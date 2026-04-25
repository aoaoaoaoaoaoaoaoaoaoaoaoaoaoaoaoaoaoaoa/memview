use super::model::{
    Bytes, LedgerState, Meminfo, Metric, ObjectKind, ObjectUsage, Pid, ProcessNode, SharedObject,
    Snapshot, TmpfsMount, TmpfsNode, TmpfsNodeKind,
};
pub use super::nav::{Hotkey, HotkeySections, Tab};
use super::probe;
use super::search::{Search, SearchDraft, SearchRole, SearchSummary};
use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use rustix::fd::OwnedFd;
use rustix::process::{Pid as KernelPid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

mod rows;
mod worker;
use rows::{build_process_rows, build_shared_rows, build_tmpfs_rows};
pub use worker::{WorkerCommand, WorkerEvent, spawn_worker};

const KILL_ARMING_DELAY: Duration = Duration::from_secs(2);
const TERMINAL_FRAME_ROWS: u16 = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessScope {
    SelfOnly,
    SelfAndChildren,
}

impl ProcessScope {
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::SelfOnly => Self::SelfAndChildren,
            Self::SelfAndChildren => Self::SelfOnly,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::SelfOnly => "self",
            Self::SelfAndChildren => "self+children",
        }
    }

    #[must_use]
    pub fn rollup(self, node: &ProcessNode) -> super::model::MemoryRollup {
        match self {
            Self::SelfOnly => node.rollup,
            Self::SelfAndChildren => node.subtree,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FlatProcessRow {
    pub index: usize,
    pub pid: Pid,
    pub depth: usize,
    pub fold: RowFold,
    pub search: SearchRole,
}

#[derive(Clone, Debug)]
pub struct FlatTmpfsRow {
    pub mount_index: usize,
    pub path: PathBuf,
    pub name: String,
    pub kind: TmpfsNodeKind,
    pub allocated: Bytes,
    pub logical: Bytes,
    pub depth: usize,
    pub fold: RowFold,
    pub search: SearchRole,
}

#[derive(Clone, Debug)]
pub struct FlatSharedRow {
    pub index: usize,
    key: (ObjectKind, String),
    pub search: SearchRole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowFold {
    Leaf,
    Expanded,
    Collapsed,
}

impl RowFold {
    #[must_use]
    fn is_collapsed(self) -> bool {
        self == Self::Collapsed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RowIndex(usize);

impl RowIndex {
    #[must_use]
    fn new(index: usize) -> Self {
        Self(index)
    }

    #[must_use]
    pub fn get(self) -> usize {
        self.0
    }
}

pub trait IdentifiedRow {
    type Key: Clone + Ord;

    fn key(&self) -> &Self::Key;
}

impl IdentifiedRow for FlatProcessRow {
    type Key = Pid;

    fn key(&self) -> &Self::Key {
        &self.pid
    }
}

impl IdentifiedRow for FlatTmpfsRow {
    type Key = PathBuf;

    fn key(&self) -> &Self::Key {
        &self.path
    }
}

impl IdentifiedRow for FlatSharedRow {
    type Key = (ObjectKind, String);

    fn key(&self) -> &Self::Key {
        &self.key
    }
}

#[derive(Clone, Debug)]
pub struct PaneRows<Row: IdentifiedRow> {
    rows: Vec<Row>,
    by_key: BTreeMap<Row::Key, RowIndex>,
    selected: Option<RowIndex>,
}

impl<Row: IdentifiedRow> Default for PaneRows<Row> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            by_key: BTreeMap::new(),
            selected: None,
        }
    }
}

impl<Row: IdentifiedRow> PaneRows<Row> {
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    #[must_use]
    pub fn selected(&self) -> Option<&Row> {
        self.selected.and_then(|index| self.rows.get(index.get()))
    }

    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected.map_or(0, RowIndex::get)
    }

    fn selected_slot(&self) -> Option<RowIndex> {
        self.selected
    }

    fn selected_key(&self) -> Option<Row::Key> {
        self.selected().map(|row| row.key().clone())
    }

    fn install(&mut self, rows: Vec<Row>) {
        self.install_prefer(rows, self.selected_key());
    }

    fn install_pinned_to_top(&mut self, rows: Vec<Row>) {
        self.install_prefer(rows, None);
    }

    fn install_prefer(&mut self, rows: Vec<Row>, preferred: Option<Row::Key>) {
        let by_key = rows
            .iter()
            .enumerate()
            .map(|(index, row)| (row.key().clone(), RowIndex::new(index)))
            .collect::<BTreeMap<_, _>>();
        let selected = preferred
            .and_then(|key| by_key.get(&key).copied())
            .or_else(|| (!rows.is_empty()).then_some(RowIndex::new(0)));

        self.rows = rows;
        self.by_key = by_key;
        self.selected = selected;
    }

    fn select_clamped(&mut self, index: RowIndex) -> bool {
        if self.rows.is_empty() {
            let changed = self.selected.is_some();
            self.selected = None;
            return changed;
        }
        let next = RowIndex::new(index.get().min(self.rows.len() - 1));
        let changed = self.selected != Some(next);
        self.selected = Some(next);
        changed
    }

    fn move_by(&mut self, delta: isize) -> bool {
        let Some(current) = self.selected else {
            return false;
        };
        if self.rows.is_empty() {
            return false;
        }
        let next = RowIndex::new(
            (current.get() as isize + delta).clamp(0, self.rows.len() as isize - 1) as usize,
        );
        let changed = current != next;
        self.selected = Some(next);
        changed
    }

    fn select_edge(&mut self, edge: RowEdge) -> bool {
        let Some(next) = edge.index(self.rows.len()) else {
            return false;
        };
        let changed = self.selected != Some(next);
        self.selected = Some(next);
        changed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RowEdge {
    First,
    Last,
}

impl RowEdge {
    #[must_use]
    fn index(self, len: usize) -> Option<RowIndex> {
        match self {
            Self::First => (len > 0).then_some(RowIndex::new(0)),
            Self::Last => len.checked_sub(1).map(RowIndex::new),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageRows(usize);

impl Default for PageRows {
    fn default() -> Self {
        Self(1)
    }
}

impl PageRows {
    #[must_use]
    fn from_terminal_height(height: u16) -> Self {
        Self(usize::from(
            height.saturating_sub(TERMINAL_FRAME_ROWS).max(1),
        ))
    }

    #[must_use]
    fn delta(self, direction: PageDirection) -> isize {
        let rows = self.0.min(isize::MAX as usize) as isize;
        match direction {
            PageDirection::Up => -rows,
            PageDirection::Down => rows,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageDirection {
    Up,
    Down,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SelectionCustody {
    #[default]
    SystemOwned,
    UserOwned,
}

impl SelectionCustody {
    #[must_use]
    fn preserves_anchor(self) -> bool {
        self == Self::UserOwned
    }

    fn seize(&mut self) {
        *self = Self::UserOwned;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeMinimis {
    threshold: Bytes,
}

impl DeMinimis {
    #[must_use]
    fn from_largest_non_root(system_total: Bytes, largest_non_root: Bytes) -> Self {
        Self {
            threshold: pct(system_total, 1).min(pct(largest_non_root, 3)),
        }
    }

    #[must_use]
    fn folds(self, value: Bytes) -> bool {
        self.threshold.0 > 0 && value < self.threshold
    }
}

fn pct(value: Bytes, percent: u64) -> Bytes {
    Bytes(((u128::from(value.0) * u128::from(percent)) / 100).min(u128::from(u64::MAX)) as u64)
}

#[derive(Debug)]
struct FoldPolicy<'a, Key> {
    collapsed: &'a BTreeSet<Key>,
    expanded: &'a BTreeSet<Key>,
    de_minimis: DeMinimis,
}

impl<Key: Ord> FoldPolicy<'_, Key> {
    #[must_use]
    fn row_fold(&self, key: &Key, depth: usize, has_children: bool, total: Bytes) -> RowFold {
        if !has_children {
            RowFold::Leaf
        } else if self.collapsed.contains(key) {
            RowFold::Collapsed
        } else if self.expanded.contains(key) {
            RowFold::Expanded
        } else if depth > 0 && self.de_minimis.folds(total) {
            RowFold::Collapsed
        } else {
            RowFold::Expanded
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum KeySequence {
    #[default]
    Root,
    G,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SequenceResolution {
    Unmatched(KeyEvent),
    Pending,
    Cancelled,
    Command(SequenceCommand),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SequenceCommand {
    FirstRow,
    LastRow,
}

impl KeySequence {
    fn resolve(&mut self, key: KeyEvent) -> SequenceResolution {
        match (*self, plain_char(key)) {
            (Self::Root, Some('g')) => {
                *self = Self::G;
                SequenceResolution::Pending
            }
            (Self::Root, Some('G')) => SequenceResolution::Command(SequenceCommand::LastRow),
            (Self::Root, _) => SequenceResolution::Unmatched(key),
            (Self::G, Some('g')) => {
                *self = Self::Root;
                SequenceResolution::Command(SequenceCommand::FirstRow)
            }
            (Self::G, _) => {
                *self = Self::Root;
                SequenceResolution::Cancelled
            }
        }
    }
}

fn plain_char(key: KeyEvent) -> Option<char> {
    if key.modifiers.intersects(
        KeyModifiers::CONTROL
            | KeyModifiers::ALT
            | KeyModifiers::SUPER
            | KeyModifiers::HYPER
            | KeyModifiers::META,
    ) {
        return None;
    }
    match key.code {
        KeyCode::Char(character) => Some(character),
        KeyCode::Esc => Some('\u{1b}'),
        _ => None,
    }
}

pub struct App {
    pub tab: Tab,
    pub metric: Metric,
    pub process_scope: ProcessScope,
    focused: bool,
    pub show_help: bool,
    pub snapshot: Option<Snapshot>,
    pub last_error: Option<String>,
    pub process_scan_started_at: Option<Instant>,
    search: Option<Search>,
    search_draft: Option<SearchDraft>,
    process_search: SearchSummary,
    tmpfs_search: SearchSummary,
    shared_search: SearchSummary,
    collapsed_processes: BTreeSet<Pid>,
    expanded_processes: BTreeSet<Pid>,
    collapsed_tmpfs: BTreeSet<PathBuf>,
    expanded_tmpfs: BTreeSet<PathBuf>,
    process_mapping_cache: BTreeMap<Pid, ProcessMappingLedger>,
    process_mapping_started_at: Option<(Pid, Instant)>,
    shared_scan_started_at: Option<Instant>,
    pub deletions: Vec<DeleteTask>,
    confirmed_deletions: BTreeSet<PathBuf>,
    pub kill_confirmation: Option<KillConfirmation>,
    inventory_warnings: Vec<String>,
    tmpfs_refresh_warnings: Vec<String>,
    process_warnings: Vec<String>,
    pending_process_scan: Option<probe::ProcessScan>,
    tmpfs_selection: SelectionCustody,
    process_rows: PaneRows<FlatProcessRow>,
    tmpfs_rows: PaneRows<FlatTmpfsRow>,
    shared_rows: PaneRows<FlatSharedRow>,
    page_rows: PageRows,
    key_sequence: KeySequence,
}

pub struct KillConfirmation {
    pub target: ProcessKillTarget,
    opened_at: Instant,
}

impl KillConfirmation {
    #[must_use]
    fn new(target: ProcessKillTarget) -> Self {
        Self {
            target,
            opened_at: Instant::now(),
        }
    }

    #[must_use]
    pub fn armed(&self) -> bool {
        self.opened_at.elapsed() >= KILL_ARMING_DELAY
    }

    #[must_use]
    pub fn lock_remaining(&self) -> Duration {
        KILL_ARMING_DELAY.saturating_sub(self.opened_at.elapsed())
    }
}

pub struct ProcessKillTarget {
    pub pid: Pid,
    pub name: String,
    pub command: String,
    pidfd: OwnedFd,
}

impl ProcessKillTarget {
    fn capture(process: &ProcessNode) -> std::result::Result<Self, String> {
        Ok(Self {
            pid: process.pid,
            name: process.name.clone(),
            command: process.command.clone(),
            pidfd: open_pidfd(process.pid)?,
        })
    }

    #[must_use]
    pub fn cli(&self) -> &str {
        if self.command.is_empty() {
            &self.name
        } else {
            &self.command
        }
    }

    fn send_sigterm(self) -> std::result::Result<(), String> {
        pidfd_send_signal(self.pidfd, Signal::TERM)
            .map_err(|error| format!("pidfd SIGTERM {}: {error}", self.pid))
    }
}

pub struct ProcessMappingLedger {
    pub pid: Pid,
    pub elapsed: Duration,
    pub cost: probe::ProcessMappingCost,
    pub objects: Vec<ObjectUsage>,
    pub mappings_state: LedgerState,
}

impl ProcessMappingLedger {
    fn install(scan: probe::ProcessMappingScan) -> Self {
        Self {
            pid: scan.pid,
            elapsed: scan.elapsed,
            cost: scan.cost,
            objects: scan.objects,
            mappings_state: scan.mappings_state,
        }
    }
}

pub struct DeleteTask {
    pub path: PathBuf,
    mount_point: PathBuf,
    result: Receiver<DeleteOutcome>,
}

enum DeleteOutcome {
    Deleted,
    Failed(String),
}

#[derive(Clone, Debug)]
enum TombstoneCoverage {
    Full,
    Mount(PathBuf),
}

impl TombstoneCoverage {
    #[must_use]
    fn covers(&self, path: &Path) -> bool {
        match self {
            Self::Full => true,
            Self::Mount(mount_point) => path.starts_with(mount_point),
        }
    }
}

impl App {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tab: Tab::Processes,
            metric: Metric::Pss,
            process_scope: ProcessScope::SelfOnly,
            focused: true,
            show_help: false,
            snapshot: None,
            last_error: None,
            process_scan_started_at: None,
            search: None,
            search_draft: None,
            process_search: SearchSummary::new(Metric::Pss.label()),
            tmpfs_search: SearchSummary::new("allocated"),
            shared_search: SearchSummary::new(Metric::Pss.label()),
            collapsed_processes: BTreeSet::new(),
            expanded_processes: BTreeSet::new(),
            collapsed_tmpfs: BTreeSet::new(),
            expanded_tmpfs: BTreeSet::new(),
            process_mapping_cache: BTreeMap::new(),
            process_mapping_started_at: None,
            shared_scan_started_at: None,
            deletions: Vec::new(),
            confirmed_deletions: BTreeSet::new(),
            kill_confirmation: None,
            inventory_warnings: Vec::new(),
            tmpfs_refresh_warnings: Vec::new(),
            process_warnings: Vec::new(),
            pending_process_scan: None,
            tmpfs_selection: SelectionCustody::default(),
            process_rows: PaneRows::default(),
            tmpfs_rows: PaneRows::default(),
            shared_rows: PaneRows::default(),
            page_rows: PageRows::default(),
            key_sequence: KeySequence::default(),
        }
    }

    pub fn set_terminal_height(&mut self, height: u16) {
        self.page_rows = PageRows::from_terminal_height(height);
    }

    pub fn start_visible_work(&mut self, commands: &Sender<WorkerCommand>) {
        self.request_current_pane(commands);
        self.sync_process_scanning(commands);
    }

    #[must_use]
    pub fn is_focused(&self) -> bool {
        self.focused
    }

    pub fn set_focused(&mut self, focused: bool, commands: &Sender<WorkerCommand>) {
        if self.focused == focused {
            return;
        }
        self.focused = focused;
        self.sync_process_scanning(commands);
    }

    pub fn apply_worker_event(&mut self, event: WorkerEvent, commands: &Sender<WorkerCommand>) {
        match event {
            WorkerEvent::InventoryReady(result) => self.apply_inventory_result(result),
            WorkerEvent::TmpfsMountReady(result) => self.apply_tmpfs_mount_result(result),
            WorkerEvent::ProcessesStarted(started) => self.process_scan_started_at = Some(started),
            WorkerEvent::ProcessesReady(result) => self.apply_process_result(result, commands),
            WorkerEvent::ProcessMappingsReady(result) => self.apply_process_mappings_result(result),
            WorkerEvent::SharedObjectsStarted(started) => {
                self.shared_scan_started_at = Some(started);
            }
            WorkerEvent::SharedObjectsReady(result) => self.apply_shared_objects_result(result),
        }
    }

    fn apply_inventory_result(&mut self, result: Result<Box<Snapshot>>) {
        match result {
            Ok(snapshot) => {
                self.last_error = None;
                self.install_inventory_snapshot(*snapshot);
            }
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn apply_tmpfs_mount_result(&mut self, result: Result<Box<probe::TmpfsMountScan>>) {
        match result {
            Ok(scan) => {
                self.last_error = None;
                self.install_tmpfs_mount_scan(*scan);
            }
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn apply_process_result(
        &mut self,
        result: Result<Box<probe::ProcessScan>>,
        commands: &Sender<WorkerCommand>,
    ) {
        self.process_scan_started_at = None;
        match result {
            Ok(scan) => {
                self.last_error = None;
                self.install_process_scan(*scan);
                self.request_selected_process_mappings(commands);
            }
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn apply_process_mappings_result(&mut self, result: Result<Box<probe::ProcessMappingScan>>) {
        match result {
            Ok(mut scan) => {
                if self
                    .process_mapping_started_at
                    .is_some_and(|(pid, _)| pid == scan.pid)
                {
                    self.process_mapping_started_at = None;
                }
                self.process_warnings.append(&mut scan.warnings);
                let ledger = ProcessMappingLedger::install(*scan);
                let _ = self.process_mapping_cache.insert(ledger.pid, ledger);
                self.last_error = None;
                self.rebuild_snapshot_warnings();
            }
            Err(error) => {
                self.process_mapping_started_at = None;
                self.last_error = Some(format!("{error:#}"));
            }
        }
    }

    fn apply_shared_objects_result(&mut self, result: Result<Box<probe::SharedObjectsScan>>) {
        self.shared_scan_started_at = None;
        match result {
            Ok(mut scan) => {
                self.last_error = None;
                self.process_warnings.append(&mut scan.warnings);
                self.install_shared_objects_scan(*scan);
            }
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn install_inventory_snapshot(&mut self, mut snapshot: Snapshot) {
        self.inventory_warnings = std::mem::take(&mut snapshot.warnings);
        self.tmpfs_refresh_warnings.clear();
        let tmpfs_fresh = !snapshot.tmpfs_mounts.is_empty();
        if let Some(current) = self.snapshot.take() {
            snapshot.process_tree = current.process_tree;
            snapshot.shared_objects = current.shared_objects;
            if snapshot.tmpfs_mounts.is_empty() {
                snapshot.tmpfs_mounts = current.tmpfs_mounts;
            }
        }
        if tmpfs_fresh {
            self.reconcile_confirmed_deletions(&snapshot.tmpfs_mounts, TombstoneCoverage::Full);
        }
        self.prune_tmpfs_tombstones(&mut snapshot.tmpfs_mounts);
        probe::rebuild_snapshot_derived(&mut snapshot);
        self.snapshot = Some(snapshot);
        self.rebuild_snapshot_warnings();
        if tmpfs_fresh {
            self.rebuild_tmpfs_rows();
        }

        if let Some(scan) = self.pending_process_scan.take() {
            self.install_process_scan(scan);
        }
        self.rebuild_shared_rows();
    }

    fn install_process_scan(&mut self, mut scan: probe::ProcessScan) {
        self.process_warnings = std::mem::take(&mut scan.warnings);
        if self.snapshot.is_none() {
            self.snapshot = Some(empty_snapshot(scan.meminfo.clone()));
        }
        let Some(snapshot) = self.snapshot.as_mut() else {
            self.pending_process_scan = Some(scan);
            return;
        };
        scan.install(snapshot);
        self.rebuild_snapshot_warnings();
        self.rebuild_process_rows();
        self.retain_live_process_mapping_cache();
    }

    fn install_shared_objects_scan(&mut self, scan: probe::SharedObjectsScan) {
        if self.snapshot.is_none() {
            self.snapshot = Some(empty_snapshot(scan.meminfo.clone()));
        }
        let Some(snapshot) = self.snapshot.as_mut() else {
            return;
        };
        snapshot.captured_at = scan.captured_at;
        snapshot.elapsed = scan.elapsed;
        snapshot.meminfo = scan.meminfo;
        snapshot.shared_objects = scan.shared_objects;
        probe::rebuild_snapshot_derived(snapshot);
        self.rebuild_snapshot_warnings();
        self.rebuild_shared_rows();
    }

    fn install_tmpfs_mount_scan(&mut self, mut scan: probe::TmpfsMountScan) {
        self.tmpfs_refresh_warnings = std::mem::take(&mut scan.warnings);
        self.reconcile_confirmed_deletions(
            std::slice::from_ref(&scan.mount),
            TombstoneCoverage::Mount(scan.mount.mount_point.clone()),
        );
        self.prune_tmpfs_tombstones(std::slice::from_mut(&mut scan.mount));
        if self.snapshot.is_none() {
            self.snapshot = Some(empty_snapshot(Meminfo::default()));
        }
        let Some(snapshot) = self.snapshot.as_mut() else {
            return;
        };

        snapshot.captured_at = scan.captured_at;
        snapshot.elapsed = scan.elapsed;
        if let Some(slot) = snapshot
            .tmpfs_mounts
            .iter_mut()
            .find(|mount| mount.mount_point == scan.mount.mount_point)
        {
            *slot = scan.mount;
        } else {
            snapshot.tmpfs_mounts.push(scan.mount);
        }
        snapshot
            .tmpfs_mounts
            .sort_by_key(|mount| std::cmp::Reverse(mount.root.allocated));
        probe::rebuild_snapshot_derived(snapshot);
        self.rebuild_snapshot_warnings();
        self.rebuild_tmpfs_rows();
    }

    fn rebuild_snapshot_warnings(&mut self) {
        let Some(snapshot) = self.snapshot.as_mut() else {
            return;
        };
        let mut warnings = Vec::with_capacity(
            self.inventory_warnings.len()
                + self.tmpfs_refresh_warnings.len()
                + self.process_warnings.len(),
        );
        warnings.extend(self.inventory_warnings.iter().cloned());
        warnings.extend(self.tmpfs_refresh_warnings.iter().cloned());
        warnings.extend(self.process_warnings.iter().cloned());
        snapshot.warnings = warnings;
    }

    fn tmpfs_tombstones(&self) -> BTreeSet<PathBuf> {
        let mut tombstones = self.confirmed_deletions.clone();
        tombstones.extend(self.deletions.iter().map(|task| task.path.clone()));
        tombstones
    }

    fn prune_tmpfs_tombstones(&self, mounts: &mut [TmpfsMount]) {
        let tombstones = self.tmpfs_tombstones();
        prune_tmpfs_tombstones(mounts, &tombstones);
    }

    fn prune_tmpfs_path(&mut self, path: &Path) {
        let mut tombstones = self.tmpfs_tombstones();
        let _ = tombstones.insert(path.to_path_buf());
        let Some(snapshot) = self.snapshot.as_mut() else {
            return;
        };
        prune_tmpfs_tombstones(&mut snapshot.tmpfs_mounts, &tombstones);
        probe::rebuild_snapshot_derived(snapshot);
        self.rebuild_tmpfs_rows();
    }

    fn reconcile_confirmed_deletions(
        &mut self,
        mounts: &[TmpfsMount],
        coverage: TombstoneCoverage,
    ) {
        self.confirmed_deletions.retain(|path| {
            if !coverage.covers(path) {
                return true;
            }
            mounts
                .iter()
                .filter(|mount| path.starts_with(&mount.mount_point))
                .any(|mount| tmpfs_tree_contains_path(&mount.root, path))
        });
    }

    pub fn poll_deletion(&mut self, commands: &Sender<WorkerCommand>) -> bool {
        let mut changed = false;
        let mut index = 0;
        while index < self.deletions.len() {
            match self.deletions[index].result.try_recv() {
                Ok(DeleteOutcome::Deleted) => {
                    let task = self.deletions.remove(index);
                    let _ = self.confirmed_deletions.insert(task.path);
                    self.last_error = None;
                    let _ = commands.send(WorkerCommand::RefreshTmpfsMount(task.mount_point));
                    changed = true;
                }
                Ok(DeleteOutcome::Failed(error)) => {
                    let task = self.deletions.remove(index);
                    let _ = self.confirmed_deletions.remove(&task.path);
                    self.last_error = Some(error);
                    let _ = commands.send(WorkerCommand::RefreshTmpfsMount(task.mount_point));
                    changed = true;
                }
                Err(TryRecvError::Empty) => index += 1,
                Err(TryRecvError::Disconnected) => {
                    let task = self.deletions.remove(index);
                    let _ = self.confirmed_deletions.remove(&task.path);
                    self.last_error = Some(format!(
                        "delete task disconnected for {}",
                        task.path.display()
                    ));
                    let _ = commands.send(WorkerCommand::RefreshTmpfsMount(task.mount_point));
                    changed = true;
                }
            }
        }
        changed
    }

    #[must_use]
    pub fn needs_periodic_redraw(&self) -> bool {
        self.focused
            && (self.kill_confirmation.is_some()
                || self.process_scan_started_at.is_some()
                || self.process_mapping_started_at.is_some()
                || self.shared_scan_started_at.is_some())
    }

    fn rebuild_filterable_rows(&mut self) {
        self.rebuild_process_rows();
        self.rebuild_tmpfs_rows();
        self.rebuild_shared_rows();
    }

    #[must_use]
    pub fn tab_labels() -> Vec<String> {
        Tab::ALL
            .iter()
            .enumerate()
            .map(|(index, tab)| format!("{} {}", index + 1, tab.title()))
            .collect()
    }

    #[must_use]
    pub fn current_time_label(&self) -> String {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return "loading".to_string();
        };
        match snapshot.captured_at.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(since_epoch) => format!("captured {}", since_epoch.as_secs()),
            Err(_) => "captured".to_string(),
        }
    }

    #[must_use]
    pub fn hotkey_sections(&self) -> HotkeySections {
        HotkeySections {
            global: super::nav::global_hotkeys(),
            pane_title: self.tab.title(),
            pane: self.tab.hotkeys(),
        }
    }

    fn rebuild_process_rows(&mut self) {
        let (rows, summary) = self.snapshot.as_ref().map_or_else(
            || (Vec::new(), SearchSummary::new(self.metric.label())),
            |snapshot| {
                build_process_rows(
                    snapshot,
                    self.metric,
                    self.process_scope,
                    &self.collapsed_processes,
                    &self.expanded_processes,
                    self.search.as_ref(),
                )
            },
        );
        self.process_search = summary;
        self.process_rows.install(rows);
    }

    fn rebuild_tmpfs_rows(&mut self) {
        let (rows, summary) = self.snapshot.as_ref().map_or_else(
            || (Vec::new(), SearchSummary::new("allocated")),
            |snapshot| {
                build_tmpfs_rows(
                    snapshot,
                    self.process_scope,
                    &self.collapsed_tmpfs,
                    &self.expanded_tmpfs,
                    self.search.as_ref(),
                )
            },
        );
        self.tmpfs_search = summary;
        if self.tmpfs_selection.preserves_anchor() {
            self.tmpfs_rows.install(rows);
        } else {
            self.tmpfs_rows.install_pinned_to_top(rows);
        }
    }

    fn rebuild_shared_rows(&mut self) {
        let (rows, summary) = self.snapshot.as_ref().map_or_else(
            || (Vec::new(), SearchSummary::new(self.metric.label())),
            |snapshot| build_shared_rows(snapshot, self.metric, self.search.as_ref()),
        );
        self.shared_search = summary;
        self.shared_rows.install(rows);
    }

    #[must_use]
    pub fn search_pattern(&self) -> Option<&str> {
        self.search.as_ref().map(Search::pattern)
    }

    #[must_use]
    pub fn search_draft(&self) -> Option<&SearchDraft> {
        self.search_draft.as_ref()
    }

    #[must_use]
    pub fn search_summary(&self) -> Option<&SearchSummary> {
        let _active = self.search.as_ref()?;
        Some(match self.tab {
            Tab::Overview => return None,
            Tab::Processes => &self.process_search,
            Tab::Tmpfs => &self.tmpfs_search,
            Tab::Shared => &self.shared_search,
        })
    }

    #[must_use]
    pub fn search_scope_label(&self) -> &'static str {
        self.process_scope.label()
    }

    #[must_use]
    pub fn deletion_count(&self) -> usize {
        self.deletions.len()
    }

    #[must_use]
    pub fn process_rows(&self) -> &[FlatProcessRow] {
        self.process_rows.rows()
    }

    #[must_use]
    pub fn tmpfs_rows(&self) -> &[FlatTmpfsRow] {
        self.tmpfs_rows.rows()
    }

    #[must_use]
    pub fn shared_rows(&self) -> &[FlatSharedRow] {
        self.shared_rows.rows()
    }

    #[must_use]
    pub fn selected_process_row(&self) -> usize {
        self.process_rows.selected_index()
    }

    #[must_use]
    pub fn selected_tmpfs_row(&self) -> usize {
        self.tmpfs_rows.selected_index()
    }

    #[must_use]
    pub fn selected_shared_row(&self) -> usize {
        self.shared_rows.selected_index()
    }

    #[must_use]
    pub fn selected_tmpfs_entry(&self) -> Option<&FlatTmpfsRow> {
        self.tmpfs_rows.selected()
    }

    #[must_use]
    pub fn selected_process(&self) -> Option<&ProcessNode> {
        let row = self.process_rows.selected()?;
        let snapshot = self.snapshot.as_ref()?;
        snapshot.process_tree.nodes.get(row.index)
    }

    #[must_use]
    pub fn selected_process_objects(&self) -> &[ObjectUsage] {
        let Some(process) = self.selected_process() else {
            return &[];
        };
        self.process_mapping_cache
            .get(&process.pid)
            .map_or(&[], |ledger| ledger.objects.as_slice())
    }

    #[must_use]
    pub fn selected_process_mapping_status(&self) -> &'static str {
        let Some(process) = self.selected_process() else {
            return "none";
        };
        if self
            .process_mapping_started_at
            .is_some_and(|(pid, _)| pid == process.pid)
        {
            return "loading";
        }
        self.process_mapping_cache
            .get(&process.pid)
            .map_or(process.mappings_state.label(), |ledger| {
                ledger.mappings_state.label()
            })
    }

    #[must_use]
    pub fn selected_process_mapping_loading(&self) -> Option<(Pid, Duration)> {
        let process = self.selected_process()?;
        let (pid, started_at) = self.process_mapping_started_at?;
        (pid == process.pid).then_some((pid, started_at.elapsed()))
    }

    #[must_use]
    pub fn selected_process_mapping_scan_label(&self) -> String {
        if let Some((pid, elapsed)) = self.selected_process_mapping_loading() {
            return format!("loading pid {pid}: {} ms", elapsed.as_millis());
        }
        let Some(process) = self.selected_process() else {
            return "none".to_string();
        };
        self.process_mapping_cache.get(&process.pid).map_or_else(
            || "not loaded".to_string(),
            |ledger| {
                format!(
                    "{} ms (mount {} read {} parse {})",
                    ledger.elapsed.as_millis(),
                    ledger.cost.mount_index.as_millis(),
                    ledger.cost.read.as_millis(),
                    ledger.cost.parse.as_millis()
                )
            },
        )
    }

    #[must_use]
    pub fn process_mapping_started_at(&self) -> Option<(Pid, Instant)> {
        self.process_mapping_started_at
    }

    #[must_use]
    pub fn shared_scan_started_at(&self) -> Option<Instant> {
        self.shared_scan_started_at
    }

    #[must_use]
    pub fn selected_tmpfs_mount(&self) -> Option<&TmpfsMount> {
        let snapshot = self.snapshot.as_ref()?;
        let row = self.tmpfs_rows.selected()?;
        snapshot.tmpfs_mounts.get(row.mount_index)
    }

    #[must_use]
    pub fn selected_shared_object(&self) -> Option<&SharedObject> {
        let row = self.shared_rows.selected()?;
        self.snapshot.as_ref()?.shared_objects.get(row.index)
    }

    pub fn handle_key(&mut self, key: KeyEvent, commands: &Sender<WorkerCommand>) -> bool {
        if self.kill_confirmation.is_some() {
            return self.handle_kill_confirmation_key(key, commands);
        }
        if self.search_draft.is_some() {
            return self.handle_search_key(key);
        }
        if self.show_help {
            return self.handle_help_key(key);
        }
        if matches!(key.code, KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL)) {
            return true;
        }

        match self.key_sequence.resolve(key) {
            SequenceResolution::Unmatched(key) => self.handle_single_key(key, commands),
            SequenceResolution::Pending | SequenceResolution::Cancelled => false,
            SequenceResolution::Command(command) => {
                self.handle_sequence_command(command, commands);
                false
            }
        }
    }

    fn handle_single_key(&mut self, key: KeyEvent, commands: &Sender<WorkerCommand>) -> bool {
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => {}
            KeyCode::Char('?') => self.show_help = !self.show_help,
            KeyCode::Char('/') => self.open_search(),
            KeyCode::Char('f') => self.clear_search(),
            KeyCode::Tab => self.select_tab(self.tab.next(), commands),
            KeyCode::BackTab => self.select_tab(self.tab.previous(), commands),
            KeyCode::Char('1') => self.select_tab(Tab::Overview, commands),
            KeyCode::Char('2') => self.select_tab(Tab::Processes, commands),
            KeyCode::Char('3') => self.select_tab(Tab::Tmpfs, commands),
            KeyCode::Char('4') => self.select_tab(Tab::Shared, commands),
            KeyCode::Char('s') => {
                self.metric = self.metric.next();
                self.rebuild_process_rows();
                self.rebuild_shared_rows();
            }
            KeyCode::Char('m') => {
                self.process_scope = self.process_scope.next();
                self.rebuild_filterable_rows();
            }
            KeyCode::Char('d') => self.delete_current_tmpfs_entry(),
            KeyCode::Char('K') => self.arm_process_kill(),
            KeyCode::Char('r') => self.refresh_current_pane(commands),
            KeyCode::Down | KeyCode::Char('j') => {
                let _ = self.move_selection_and_request_mappings(1, commands);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let _ = self.move_selection_and_request_mappings(-1, commands);
            }
            KeyCode::PageDown => {
                let _ = self.page_selection_and_request_mappings(PageDirection::Down, commands);
            }
            KeyCode::PageUp => {
                let _ = self.page_selection_and_request_mappings(PageDirection::Up, commands);
            }
            KeyCode::Left | KeyCode::Char('h') => self.collapse_current(),
            KeyCode::Right | KeyCode::Char('l') => self.expand_current(),
            KeyCode::Enter => self.toggle_current(),
            _ => {}
        }
        false
    }

    fn handle_sequence_command(
        &mut self,
        command: SequenceCommand,
        commands: &Sender<WorkerCommand>,
    ) {
        match command {
            SequenceCommand::FirstRow => {
                let _ = self.select_edge_and_request_mappings(RowEdge::First, commands);
            }
            SequenceCommand::LastRow => {
                let _ = self.select_edge_and_request_mappings(RowEdge::Last, commands);
            }
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent, commands: &Sender<WorkerCommand>) -> bool {
        if self.kill_confirmation.is_some() || self.show_help {
            return false;
        }
        self.key_sequence = KeySequence::Root;

        match mouse.kind {
            MouseEventKind::ScrollDown => self.move_selection_and_request_mappings(1, commands),
            MouseEventKind::ScrollUp => self.move_selection_and_request_mappings(-1, commands),
            MouseEventKind::ScrollLeft | MouseEventKind::ScrollRight => false,
            MouseEventKind::Down(_)
            | MouseEventKind::Up(_)
            | MouseEventKind::Drag(_)
            | MouseEventKind::Moved => false,
        }
    }

    fn select_tab(&mut self, tab: Tab, commands: &Sender<WorkerCommand>) {
        self.tab = tab;
        if tab == Tab::Tmpfs {
            self.seize_tmpfs_selection();
        }
        self.request_current_pane(commands);
        self.sync_process_scanning(commands);
    }

    fn sync_process_scanning(&self, commands: &Sender<WorkerCommand>) {
        let _ = commands.send(WorkerCommand::SetProcessScanning(
            self.focused && self.tab.drives_process_scans(),
        ));
    }

    fn request_current_pane(&mut self, commands: &Sender<WorkerCommand>) {
        match self.tab {
            Tab::Overview => {
                let _ = commands.send(WorkerCommand::RefreshInventory);
            }
            Tab::Processes => self.request_selected_process_mappings(commands),
            Tab::Tmpfs => {
                let _ = commands.send(WorkerCommand::RefreshTmpfsMounts);
            }
            Tab::Shared => {
                let _ = commands.send(WorkerCommand::RefreshSharedObjects);
            }
        }
    }

    fn request_selected_process_mappings(&mut self, commands: &Sender<WorkerCommand>) {
        if self.tab != Tab::Processes {
            return;
        }
        let Some(process) = self.selected_process() else {
            return;
        };
        if self.process_mapping_cache.contains_key(&process.pid)
            || self
                .process_mapping_started_at
                .is_some_and(|(pid, _)| pid == process.pid)
        {
            return;
        }
        let pid = process.pid;
        self.process_mapping_started_at = Some((pid, Instant::now()));
        let _ = commands.send(WorkerCommand::RefreshProcessMappings(pid));
    }

    fn retain_live_process_mapping_cache(&mut self) {
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.process_mapping_cache.clear();
            self.process_mapping_started_at = None;
            return;
        };
        let live = snapshot
            .process_tree
            .nodes
            .iter()
            .map(|node| node.pid)
            .collect::<BTreeSet<_>>();
        self.process_mapping_cache
            .retain(|pid, _ledger| live.contains(pid));
        if self
            .process_mapping_started_at
            .is_some_and(|(pid, _)| !live.contains(&pid))
        {
            self.process_mapping_started_at = None;
        }
    }

    fn refresh_current_pane(&mut self, commands: &Sender<WorkerCommand>) {
        let command = match self.tab {
            Tab::Overview => WorkerCommand::RefreshInventory,
            Tab::Processes => WorkerCommand::RefreshProcesses,
            Tab::Tmpfs => self
                .selected_tmpfs_mount()
                .map(|mount| WorkerCommand::RefreshTmpfsMount(mount.mount_point.clone()))
                .unwrap_or(WorkerCommand::RefreshTmpfsMounts),
            Tab::Shared => WorkerCommand::RefreshSharedObjects,
        };
        let _ = commands.send(command);
    }

    fn open_search(&mut self) {
        self.key_sequence = KeySequence::Root;
        self.search_draft = Some(SearchDraft::new(self.search.as_ref()));
    }

    fn clear_search(&mut self) {
        if self.search.take().is_some() {
            self.rebuild_filterable_rows();
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Esc => {
                self.search_draft = None;
                false
            }
            KeyCode::Enter => {
                self.commit_search();
                false
            }
            KeyCode::Backspace => {
                if let Some(draft) = self.search_draft.as_mut() {
                    draft.backspace();
                }
                false
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(draft) = self.search_draft.as_mut() {
                    draft.clear();
                }
                false
            }
            KeyCode::Char(character) if plain_char(key).is_some() => {
                if let Some(draft) = self.search_draft.as_mut() {
                    draft.push(character);
                }
                false
            }
            _ => false,
        }
    }

    fn commit_search(&mut self) {
        let Some(draft) = self.search_draft.take() else {
            return;
        };
        let input = draft.into_input();
        match Search::compile(input.clone()) {
            Ok(search) => {
                self.search = search;
                self.rebuild_filterable_rows();
            }
            Err(error) => {
                let mut draft = SearchDraft::from_input(input);
                draft.fail(error);
                self.search_draft = Some(draft);
            }
        }
    }

    fn handle_help_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Esc | KeyCode::Char('?') => {
                self.show_help = false;
                false
            }
            _ => false,
        }
    }

    fn handle_kill_confirmation_key(
        &mut self,
        key: KeyEvent,
        commands: &Sender<WorkerCommand>,
    ) -> bool {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Esc | KeyCode::Char('n') => {
                self.kill_confirmation = None;
                false
            }
            KeyCode::Char('y')
                if self
                    .kill_confirmation
                    .as_ref()
                    .is_some_and(KillConfirmation::armed) =>
            {
                self.confirm_process_kill(commands);
                false
            }
            _ => false,
        }
    }

    fn move_selection(&mut self, delta: isize) -> bool {
        match self.tab {
            Tab::Overview => false,
            Tab::Processes => self.process_rows.move_by(delta),
            Tab::Tmpfs => self.tmpfs_rows.move_by(delta),
            Tab::Shared => self.shared_rows.move_by(delta),
        }
    }

    fn seize_tmpfs_selection(&mut self) {
        if self.tmpfs_selection.preserves_anchor() {
            return;
        }
        let _ = self.tmpfs_rows.select_edge(RowEdge::First);
        self.tmpfs_selection.seize();
    }

    fn page_selection(&mut self, direction: PageDirection) -> bool {
        self.move_selection(self.page_rows.delta(direction))
    }

    fn move_selection_and_request_mappings(
        &mut self,
        delta: isize,
        commands: &Sender<WorkerCommand>,
    ) -> bool {
        let changed = self.move_selection(delta);
        self.request_selected_process_mappings_after(changed, commands)
    }

    fn page_selection_and_request_mappings(
        &mut self,
        direction: PageDirection,
        commands: &Sender<WorkerCommand>,
    ) -> bool {
        let changed = self.page_selection(direction);
        self.request_selected_process_mappings_after(changed, commands)
    }

    fn select_edge_and_request_mappings(
        &mut self,
        edge: RowEdge,
        commands: &Sender<WorkerCommand>,
    ) -> bool {
        let changed = self.select_edge(edge);
        self.request_selected_process_mappings_after(changed, commands)
    }

    fn request_selected_process_mappings_after(
        &mut self,
        changed: bool,
        commands: &Sender<WorkerCommand>,
    ) -> bool {
        if changed {
            self.request_selected_process_mappings(commands);
        }
        changed
    }

    fn select_edge(&mut self, edge: RowEdge) -> bool {
        match self.tab {
            Tab::Overview => false,
            Tab::Processes => self.process_rows.select_edge(edge),
            Tab::Tmpfs => self.tmpfs_rows.select_edge(edge),
            Tab::Shared => self.shared_rows.select_edge(edge),
        }
    }

    fn collapse_current(&mut self) {
        match self.tab {
            Tab::Processes => {
                let Some((pid, fold)) = self.process_rows.selected().map(|row| (row.pid, row.fold))
                else {
                    return;
                };
                if fold != RowFold::Leaf {
                    let _ = self.expanded_processes.remove(&pid);
                    let _ = self.collapsed_processes.insert(pid);
                    self.rebuild_process_rows();
                }
            }
            Tab::Tmpfs => {
                let Some((path, fold)) = self
                    .tmpfs_rows
                    .selected()
                    .map(|row| (row.path.clone(), row.fold))
                else {
                    return;
                };
                if fold != RowFold::Leaf {
                    let _ = self.expanded_tmpfs.remove(&path);
                    let _ = self.collapsed_tmpfs.insert(path);
                    self.rebuild_tmpfs_rows();
                }
            }
            Tab::Overview | Tab::Shared => {}
        }
    }

    fn expand_current(&mut self) {
        match self.tab {
            Tab::Processes => {
                if let Some((pid, fold)) =
                    self.process_rows.selected().map(|row| (row.pid, row.fold))
                    && fold != RowFold::Leaf
                {
                    let _ = self.collapsed_processes.remove(&pid);
                    let _ = self.expanded_processes.insert(pid);
                    self.rebuild_process_rows();
                }
            }
            Tab::Tmpfs => {
                if let Some((path, fold)) = self
                    .tmpfs_rows
                    .selected()
                    .map(|row| (row.path.clone(), row.fold))
                    && fold != RowFold::Leaf
                {
                    let _ = self.collapsed_tmpfs.remove(&path);
                    let _ = self.expanded_tmpfs.insert(path);
                    self.rebuild_tmpfs_rows();
                }
            }
            Tab::Overview | Tab::Shared => {}
        }
    }

    fn toggle_current(&mut self) {
        match self.tab {
            Tab::Processes => {
                let Some((pid, fold)) = self.process_rows.selected().map(|row| (row.pid, row.fold))
                else {
                    return;
                };
                match fold {
                    RowFold::Leaf => return,
                    RowFold::Collapsed => {
                        let _ = self.collapsed_processes.remove(&pid);
                        let _ = self.expanded_processes.insert(pid);
                    }
                    RowFold::Expanded => {
                        let _ = self.expanded_processes.remove(&pid);
                        let _ = self.collapsed_processes.insert(pid);
                    }
                }
                self.rebuild_process_rows();
            }
            Tab::Tmpfs => {
                let Some((path, fold)) = self
                    .tmpfs_rows
                    .selected()
                    .map(|row| (row.path.clone(), row.fold))
                else {
                    return;
                };
                match fold {
                    RowFold::Leaf => return,
                    RowFold::Collapsed => {
                        let _ = self.collapsed_tmpfs.remove(&path);
                        let _ = self.expanded_tmpfs.insert(path);
                    }
                    RowFold::Expanded => {
                        let _ = self.expanded_tmpfs.remove(&path);
                        let _ = self.collapsed_tmpfs.insert(path);
                    }
                }
                self.rebuild_tmpfs_rows();
            }
            Tab::Overview | Tab::Shared => {}
        }
    }

    fn delete_current_tmpfs_entry(&mut self) {
        if self.tab != Tab::Tmpfs {
            return;
        }
        let Some((path, kind)) = self
            .tmpfs_rows
            .selected()
            .map(|row| (row.path.clone(), row.kind))
        else {
            return;
        };
        let Some(mount_point) = self
            .selected_tmpfs_mount()
            .map(|mount| mount.mount_point.clone())
        else {
            return;
        };

        if kind == TmpfsNodeKind::Mount {
            self.last_error = Some(format!(
                "refusing to delete tmpfs mount root {}",
                path.display()
            ));
            return;
        }

        let Some(successor) = self.tmpfs_rows.selected_slot() else {
            return;
        };
        let (sender, result) = mpsc::channel();
        let task_path = path.clone();
        let _handle = thread::spawn(move || {
            let outcome = delete_tmpfs_entry(&task_path, kind)
                .map_err(|error| format!("delete {}: {error}", task_path.display()))
                .map_or_else(DeleteOutcome::Failed, |()| DeleteOutcome::Deleted);
            let _ = sender.send(outcome);
        });

        self.last_error = None;
        let _ = self.collapsed_tmpfs.remove(&path);
        let _ = self.expanded_tmpfs.remove(&path);
        self.deletions.push(DeleteTask {
            path: path.clone(),
            mount_point,
            result,
        });
        self.prune_tmpfs_path(&path);
        let _ = self.tmpfs_rows.select_clamped(successor);
    }

    fn arm_process_kill(&mut self) {
        if self.tab != Tab::Processes {
            return;
        }
        let Some(process) = self.selected_process() else {
            return;
        };

        match ProcessKillTarget::capture(process) {
            Ok(target) => {
                self.last_error = None;
                self.kill_confirmation = Some(KillConfirmation::new(target));
            }
            Err(error) => self.last_error = Some(error),
        }
    }

    fn confirm_process_kill(&mut self, commands: &Sender<WorkerCommand>) {
        let Some(confirmation) = self.kill_confirmation.take() else {
            return;
        };
        match confirmation.target.send_sigterm() {
            Ok(()) => {
                self.last_error = None;
                let _ = commands.send(WorkerCommand::RefreshProcesses);
            }
            Err(error) => self.last_error = Some(error),
        }
    }
}

fn open_pidfd(pid: Pid) -> std::result::Result<OwnedFd, String> {
    let Some(kernel_pid) = KernelPid::from_raw(pid.0) else {
        return Err(format!("cannot arm SIGTERM for invalid pid {pid}"));
    };
    pidfd_open(kernel_pid, PidfdFlags::empty())
        .map_err(|error| format!("pidfd_open {pid}: {error}"))
}

fn delete_tmpfs_entry(path: &Path, kind: TmpfsNodeKind) -> std::io::Result<()> {
    let result = match kind {
        TmpfsNodeKind::Directory => fs::remove_dir_all(path),
        TmpfsNodeKind::Mount => Ok(()),
        TmpfsNodeKind::File
        | TmpfsNodeKind::Symlink
        | TmpfsNodeKind::Socket
        | TmpfsNodeKind::Fifo
        | TmpfsNodeKind::CharDevice
        | TmpfsNodeKind::BlockDevice
        | TmpfsNodeKind::Other => fs::remove_file(path),
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TmpfsUsage {
    allocated: Bytes,
    logical: Bytes,
}

impl TmpfsUsage {
    #[must_use]
    fn from_node(node: &TmpfsNode) -> Self {
        Self {
            allocated: node.allocated,
            logical: node.logical,
        }
    }

    fn absorb(&mut self, usage: Self) {
        self.allocated += usage.allocated;
        self.logical += usage.logical;
    }
}

fn prune_tmpfs_tombstones(mounts: &mut [TmpfsMount], tombstones: &BTreeSet<PathBuf>) {
    if tombstones.is_empty() {
        return;
    }
    for mount in mounts {
        let removed = prune_tmpfs_node_children(&mut mount.root, tombstones);
        mount.root.allocated -= removed.allocated;
        mount.root.logical -= removed.logical;
    }
}

fn prune_tmpfs_node_children(node: &mut TmpfsNode, tombstones: &BTreeSet<PathBuf>) -> TmpfsUsage {
    let mut removed = TmpfsUsage::default();
    node.children.retain_mut(|child| {
        if tmpfs_path_is_tombstoned(&child.path, tombstones) {
            removed.absorb(TmpfsUsage::from_node(child));
            return false;
        }
        let child_removed = prune_tmpfs_node_children(child, tombstones);
        child.allocated -= child_removed.allocated;
        child.logical -= child_removed.logical;
        removed.absorb(child_removed);
        true
    });
    removed
}

fn tmpfs_path_is_tombstoned(path: &Path, tombstones: &BTreeSet<PathBuf>) -> bool {
    tombstones
        .iter()
        .any(|tombstone| path == tombstone || path.starts_with(tombstone))
}

fn tmpfs_tree_contains_path(node: &TmpfsNode, path: &Path) -> bool {
    node.path == path
        || (path.starts_with(&node.path)
            && node
                .children
                .iter()
                .any(|child| tmpfs_tree_contains_path(child, path)))
}

fn empty_snapshot(meminfo: Meminfo) -> Snapshot {
    let mut snapshot = Snapshot {
        captured_at: SystemTime::now(),
        elapsed: Duration::ZERO,
        meminfo,
        overview: super::model::Overview::default(),
        process_tree: super::model::ProcessTree::default(),
        shared_objects: Vec::new(),
        sysv_segments: Vec::new(),
        tmpfs_mounts: Vec::new(),
        warnings: Vec::new(),
    };
    probe::rebuild_snapshot_derived(&mut snapshot);
    snapshot
}

#[cfg(test)]
mod tests;
