use super::model::{
    BackingIdentity, Bytes, Inventory, Ledger, Meminfo, Metric, ObjectUsage, Pid, ProcessKey,
    ProcessNode, Processes, Shared, SharedObject, Tmpfs, TmpfsMount, TmpfsNode, TmpfsNodeKind,
};
use super::nav::{self, Action};
pub use super::nav::{Binding, BindingSections, Tab};
use super::probe;
use super::search::{Search, SearchDraft, SearchRole, SearchSummary};
use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use rustix::fd::OwnedFd;
use rustix::process::{Pid as KernelPid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

mod ledgers;
mod mappings;
mod rows;
mod worker;
use ledgers::Ledgers;
use mappings::MappingLedgers;
use rows::{build_process_rows, build_shared_rows, build_tmpfs_rows};
#[cfg(test)]
pub use worker::ProcessRequest;
pub use worker::{WorkerEvent, WorkerPort, spawn_worker};

const KILL_ARMING_DELAY: Duration = Duration::from_secs(2);
const TERMINAL_FRAME_ROWS: u16 = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeScope {
    SelfOnly,
    SelfAndChildren,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiState {
    pub tab: Tab,
    pub metric: Metric,
    pub tree_scope: TreeScope,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            tab: Tab::Processes,
            metric: Metric::Pss,
            tree_scope: TreeScope::SelfOnly,
        }
    }
}

impl TreeScope {
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
            Self::SelfOnly => node.rollup(),
            Self::SelfAndChildren => node.subtree,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FlatProcessRow {
    pub index: usize,
    pub key: ProcessKey,
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
    key: BackingIdentity,
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
    type Key = ProcessKey;

    fn key(&self) -> &Self::Key {
        &self.key
    }
}

impl IdentifiedRow for FlatTmpfsRow {
    type Key = PathBuf;

    fn key(&self) -> &Self::Key {
        &self.path
    }
}

impl IdentifiedRow for FlatSharedRow {
    type Key = BackingIdentity;

    fn key(&self) -> &Self::Key {
        &self.key
    }
}

#[derive(Clone, Debug)]
pub struct PaneRows<Row: IdentifiedRow> {
    rows: Vec<Row>,
    selected: Option<RowIndex>,
}

impl<Row: IdentifiedRow> Default for PaneRows<Row> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
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
        let selected = preferred
            .and_then(|key| rows.iter().position(|row| row.key() == &key))
            .map(RowIndex::new)
            .or_else(|| (!rows.is_empty()).then_some(RowIndex::new(0)));

        self.rows = rows;
        self.selected = selected;
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
    Bytes::from_wide((u128::from(value.0) * u128::from(percent)) / 100)
}

#[derive(Debug)]
struct FoldPolicy<'a, Key> {
    overrides: &'a BTreeMap<Key, FoldOverride>,
    de_minimis: DeMinimis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FoldOverride {
    Collapsed,
    Expanded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FoldMutation {
    Collapse,
    Expand,
    Toggle,
}

impl FoldMutation {
    fn apply(self, fold: RowFold) -> Option<FoldOverride> {
        match (self, fold) {
            (_, RowFold::Leaf) => None,
            (Self::Collapse, _) | (Self::Toggle, RowFold::Expanded) => {
                Some(FoldOverride::Collapsed)
            }
            (Self::Expand, _) | (Self::Toggle, RowFold::Collapsed) => Some(FoldOverride::Expanded),
        }
    }
}

enum FoldTarget {
    Process(ProcessKey),
    Tmpfs(PathBuf),
}

impl<Key: Ord> FoldPolicy<'_, Key> {
    #[must_use]
    fn row_fold(&self, key: &Key, depth: usize, has_children: bool, total: Bytes) -> RowFold {
        if has_children {
            self.overrides.get(key).map_or_else(
                || {
                    if depth > 0 && self.de_minimis.folds(total) {
                        RowFold::Collapsed
                    } else {
                        RowFold::Expanded
                    }
                },
                |override_| match override_ {
                    FoldOverride::Collapsed => RowFold::Collapsed,
                    FoldOverride::Expanded => RowFold::Expanded,
                },
            )
        } else {
            RowFold::Leaf
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
    Command(Action),
}

impl KeySequence {
    fn resolve(&mut self, key: KeyEvent) -> SequenceResolution {
        match (*self, plain_char(key)) {
            (Self::Root, Some('g')) => {
                *self = Self::G;
                SequenceResolution::Pending
            }
            (Self::Root, Some('G')) => SequenceResolution::Command(Action::LastRow),
            (Self::Root, _) => SequenceResolution::Unmatched(key),
            (Self::G, Some('g')) => {
                *self = Self::Root;
                SequenceResolution::Command(Action::FirstRow)
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
    pub tree_scope: TreeScope,
    focused: bool,
    modal: Option<Modal>,
    ledgers: Ledgers,
    pub last_error: Option<String>,
    pub process_scan_started_at: Option<Instant>,
    search: Option<Search>,
    process_search: SearchSummary,
    tmpfs_search: SearchSummary,
    shared_search: SearchSummary,
    process_folds: BTreeMap<ProcessKey, FoldOverride>,
    tmpfs_folds: BTreeMap<PathBuf, FoldOverride>,
    process_mappings: MappingLedgers,
    shared_scan_started_at: Option<Instant>,
    tmpfs_selection: SelectionCustody,
    process_rows: PaneRows<FlatProcessRow>,
    tmpfs_rows: PaneRows<FlatTmpfsRow>,
    shared_rows: PaneRows<FlatSharedRow>,
    page_rows: PageRows,
    key_sequence: KeySequence,
}

enum Modal {
    Help,
    Search(SearchDraft),
    Kill(KillConfirmation),
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
        let key = process.key();
        probe::verify_process_identity(key).map_err(|error| format!("{error:#}"))?;
        let pidfd = open_pidfd(process.pid)?;
        probe::verify_process_identity(key).map_err(|error| format!("{error:#}"))?;
        Ok(Self {
            pid: process.pid,
            name: process.name.clone(),
            command: process.command.clone(),
            pidfd,
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

impl App {
    #[must_use]
    pub fn new(state: UiState) -> Self {
        Self {
            tab: state.tab,
            metric: state.metric,
            tree_scope: state.tree_scope,
            focused: true,
            modal: None,
            ledgers: Ledgers::default(),
            last_error: None,
            process_scan_started_at: None,
            search: None,
            process_search: SearchSummary::new(state.metric.label()),
            tmpfs_search: SearchSummary::new("allocated"),
            shared_search: SearchSummary::new(state.metric.label()),
            process_folds: BTreeMap::new(),
            tmpfs_folds: BTreeMap::new(),
            process_mappings: MappingLedgers::default(),
            shared_scan_started_at: None,
            tmpfs_selection: SelectionCustody::default(),
            process_rows: PaneRows::default(),
            tmpfs_rows: PaneRows::default(),
            shared_rows: PaneRows::default(),
            page_rows: PageRows::default(),
            key_sequence: KeySequence::default(),
        }
    }

    #[must_use]
    pub fn ui_state(&self) -> UiState {
        UiState {
            tab: self.tab,
            metric: self.metric,
            tree_scope: self.tree_scope,
        }
    }

    pub fn set_terminal_height(&mut self, height: u16) {
        self.page_rows = PageRows::from_terminal_height(height);
    }

    pub fn start_visible_work(&mut self, commands: &WorkerPort) {
        self.request_current_pane(commands);
        self.sync_process_scanning(commands);
    }

    #[must_use]
    pub fn is_focused(&self) -> bool {
        self.focused
    }

    pub fn set_focused(&mut self, focused: bool, commands: &WorkerPort) {
        if self.focused == focused {
            return;
        }
        self.focused = focused;
        self.sync_process_scanning(commands);
    }

    pub fn apply_worker_event(&mut self, event: WorkerEvent, commands: &WorkerPort) {
        match event {
            WorkerEvent::InventoryReady(result) => self.apply_inventory_result(result),
            WorkerEvent::TmpfsMountReady(result) => self.apply_tmpfs_mount_result(result),
            WorkerEvent::ProcessesStarted(started) => self.process_scan_started_at = Some(started),
            WorkerEvent::ProcessesReady(result) => self.apply_process_result(result, commands),
            WorkerEvent::ProcessMappingsReady(key, result) => {
                self.apply_process_mappings_result(key, result);
            }
            WorkerEvent::SharedObjectsStarted(started) => {
                self.shared_scan_started_at = Some(started);
            }
            WorkerEvent::SharedObjectsReady(result) => self.apply_shared_objects_result(result),
        }
    }

    fn apply_inventory_result(&mut self, result: Result<Box<Ledger<Inventory>>>) {
        match result {
            Ok(ledger) => {
                self.last_error = None;
                self.install_inventory(*ledger);
            }
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn apply_tmpfs_mount_result(&mut self, result: Result<Box<Ledger<TmpfsMount>>>) {
        match result {
            Ok(ledger) => {
                self.last_error = None;
                self.install_tmpfs_mount(*ledger);
            }
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn apply_process_result(
        &mut self,
        result: Result<Box<Ledger<Processes>>>,
        commands: &WorkerPort,
    ) {
        self.process_scan_started_at = None;
        match result {
            Ok(ledger) => {
                self.last_error = None;
                self.install_processes(*ledger);
                self.request_selected_process_mappings(commands);
            }
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn apply_process_mappings_result(
        &mut self,
        key: ProcessKey,
        result: Result<Box<probe::ProcessMappingScan>>,
    ) {
        match self.process_mappings.finish(key, result) {
            Ok(()) => self.last_error = None,
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn apply_shared_objects_result(&mut self, result: Result<Box<Ledger<Shared>>>) {
        self.shared_scan_started_at = None;
        match result {
            Ok(ledger) => {
                self.last_error = None;
                self.install_shared(*ledger);
            }
            Err(error) => self.last_error = Some(format!("{error:#}")),
        }
    }

    fn install_inventory(&mut self, ledger: Ledger<Inventory>) {
        self.ledgers.install_inventory(ledger);
    }

    fn install_processes(&mut self, ledger: Ledger<Processes>) {
        self.ledgers.install_processes(ledger);
        self.rebuild_process_rows();
        self.retain_live_process_mappings();
    }

    fn install_shared(&mut self, ledger: Ledger<Shared>) {
        self.ledgers.install_shared(ledger);
        self.rebuild_shared_rows();
    }

    fn install_tmpfs_mount(&mut self, ledger: Ledger<TmpfsMount>) {
        let Ledger {
            stamp,
            value,
            warnings,
        } = ledger;

        let tmpfs = self.ledgers.tmpfs.get_or_insert_with(|| Ledger {
            stamp,
            value: Tmpfs {
                mounts: Vec::new(),
                allocated_total: Bytes::ZERO,
            },
            warnings: Vec::new(),
        });
        tmpfs.stamp = stamp;
        tmpfs.warnings = warnings;
        if let Some(slot) = tmpfs
            .value
            .mounts
            .iter_mut()
            .find(|mount| mount.mount_point == value.mount_point)
        {
            *slot = value;
        } else {
            tmpfs.value.mounts.push(value);
        }
        tmpfs
            .value
            .mounts
            .sort_by_key(|mount| std::cmp::Reverse(mount.root.allocated));
        tmpfs.value.allocated_total = tmpfs
            .value
            .mounts
            .iter()
            .map(|mount| mount.root.allocated)
            .fold(Bytes::ZERO, |total, allocated| total + allocated);
        self.rebuild_tmpfs_rows();
    }

    #[must_use]
    pub fn needs_periodic_redraw(&self) -> bool {
        self.focused
            && (self.kill_confirmation().is_some()
                || self.process_scan_started_at.is_some()
                || self.process_mappings.is_loading()
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
        let Some(stamp) = self.active_stamp() else {
            return "loading".to_string();
        };
        match (
            stamp.began_at.duration_since(SystemTime::UNIX_EPOCH),
            stamp.captured_at.duration_since(SystemTime::UNIX_EPOCH),
        ) {
            (Ok(began), Ok(captured)) => format!(
                "capture #{} {}..{} ({} ms)",
                stamp.id,
                began.as_secs(),
                captured.as_secs(),
                stamp.elapsed.as_millis()
            ),
            _ => format!("capture #{} ({} ms)", stamp.id, stamp.elapsed.as_millis()),
        }
    }

    fn active_stamp(&self) -> Option<super::model::CaptureStamp> {
        match self.tab {
            Tab::Overview => self.ledgers.inventory.as_ref().map(|ledger| ledger.stamp),
            Tab::Processes => self.ledgers.processes.as_ref().map(|ledger| ledger.stamp),
            Tab::Tmpfs => self.ledgers.tmpfs.as_ref().map(|ledger| ledger.stamp),
            Tab::Shared => self.ledgers.shared.as_ref().map(|ledger| ledger.stamp),
        }
    }

    #[must_use]
    pub fn active_ledger_ready(&self) -> bool {
        match self.tab {
            Tab::Overview => self.ledgers.inventory.is_some(),
            Tab::Processes => self.ledgers.processes.is_some(),
            Tab::Tmpfs => self.ledgers.tmpfs.is_some(),
            Tab::Shared => self.ledgers.shared.is_some(),
        }
    }

    #[must_use]
    pub fn meminfo(&self) -> Option<&Meminfo> {
        match self.tab {
            Tab::Overview | Tab::Tmpfs => self
                .ledgers
                .inventory
                .as_ref()
                .map(|ledger| &ledger.value.meminfo),
            Tab::Processes => self
                .ledgers
                .processes
                .as_ref()
                .map(|ledger| &ledger.value.meminfo),
            Tab::Shared => self
                .ledgers
                .shared
                .as_ref()
                .map(|ledger| &ledger.value.meminfo),
        }
    }

    #[must_use]
    pub fn inventory(&self) -> Option<&Inventory> {
        self.ledgers.inventory.as_ref().map(|ledger| &ledger.value)
    }

    #[must_use]
    pub fn processes(&self) -> Option<&Processes> {
        self.ledgers.process_data()
    }

    #[must_use]
    pub fn tmpfs(&self) -> Option<&Tmpfs> {
        self.ledgers.tmpfs_data()
    }

    #[must_use]
    pub fn shared(&self) -> Option<&Shared> {
        self.ledgers.shared_data()
    }

    #[must_use]
    pub fn last_capture_elapsed(&self) -> Duration {
        self.active_stamp()
            .map_or(Duration::ZERO, |stamp| stamp.elapsed)
    }

    #[must_use]
    pub fn process_capture_label(&self) -> String {
        self.ledgers.processes.as_ref().map_or_else(
            || "pending".to_string(),
            |ledger| format!("#{}", ledger.stamp.id),
        )
    }

    #[must_use]
    pub fn tmpfs_capture_label(&self) -> String {
        self.ledgers.tmpfs.as_ref().map_or_else(
            || "pending".to_string(),
            |ledger| format!("#{}", ledger.stamp.id),
        )
    }

    #[must_use]
    pub fn warnings(&self) -> Vec<&str> {
        let mut warnings = Vec::new();
        match self.tab {
            Tab::Overview => {
                if let Some(ledger) = &self.ledgers.inventory {
                    warnings.extend(ledger.warnings.iter().map(String::as_str));
                }
            }
            Tab::Processes => {
                if let Some(ledger) = &self.ledgers.processes {
                    warnings.extend(ledger.warnings.iter().map(String::as_str));
                }
            }
            Tab::Tmpfs => {
                if let Some(ledger) = &self.ledgers.tmpfs {
                    warnings.extend(ledger.warnings.iter().map(String::as_str));
                }
            }
            Tab::Shared => {
                if let Some(ledger) = &self.ledgers.shared {
                    warnings.extend(ledger.warnings.iter().map(String::as_str));
                }
            }
        }
        if self.tab == Tab::Processes {
            warnings.extend(self.process_mappings.warnings());
        }
        warnings
    }

    #[must_use]
    pub fn binding_sections(&self) -> BindingSections {
        BindingSections {
            global: nav::global_bindings(),
            pane_title: self.tab.title(),
            navigation: self.tab.navigation(),
            pane: self.tab.bindings(),
        }
    }

    fn rebuild_process_rows(&mut self) {
        let (rows, summary) = self.ledgers.process_data().map_or_else(
            || (Vec::new(), SearchSummary::new(self.metric.label())),
            |processes| {
                build_process_rows(
                    processes,
                    self.metric,
                    self.tree_scope,
                    &self.process_folds,
                    self.search.as_ref(),
                )
            },
        );
        self.process_search = summary;
        self.process_rows.install(rows);
    }

    fn rebuild_tmpfs_rows(&mut self) {
        let capacity = self
            .meminfo()
            .and_then(|meminfo| meminfo.value("MemTotal"))
            .unwrap_or(Bytes::ZERO);
        let (rows, summary) = self.ledgers.tmpfs_data().map_or_else(
            || (Vec::new(), SearchSummary::new("allocated")),
            |tmpfs| {
                build_tmpfs_rows(
                    tmpfs,
                    capacity,
                    self.tree_scope,
                    &self.tmpfs_folds,
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
        let (rows, summary) = self.ledgers.shared_data().map_or_else(
            || (Vec::new(), SearchSummary::new(self.metric.label())),
            |shared| build_shared_rows(shared, self.metric, self.search.as_ref()),
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
        match &self.modal {
            Some(Modal::Search(draft)) => Some(draft),
            Some(Modal::Help | Modal::Kill(_)) | None => None,
        }
    }

    #[must_use]
    pub fn help_open(&self) -> bool {
        matches!(self.modal, Some(Modal::Help))
    }

    #[must_use]
    pub fn kill_confirmation(&self) -> Option<&KillConfirmation> {
        match &self.modal {
            Some(Modal::Kill(confirmation)) => Some(confirmation),
            Some(Modal::Help | Modal::Search(_)) | None => None,
        }
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
        self.tree_scope.label()
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
        self.ledgers.process_data()?.tree.nodes.get(row.index)
    }

    #[must_use]
    pub fn selected_process_objects(&self) -> &[ObjectUsage] {
        let Some(process) = self.selected_process() else {
            return &[];
        };
        self.process_mappings.objects(process.key())
    }

    #[must_use]
    pub fn selected_process_mapping_status(&self) -> &'static str {
        let Some(process) = self.selected_process() else {
            return "none";
        };
        self.process_mappings
            .state(process.key(), process.mappings_state)
    }

    #[must_use]
    pub fn selected_process_mapping_loading(&self) -> Option<(Pid, Duration)> {
        let process = self.selected_process()?;
        self.process_mappings
            .loading(process.key())
            .map(|elapsed| (process.pid, elapsed))
    }

    #[must_use]
    pub fn selected_process_mapping_scan_label(&self) -> String {
        if let Some((pid, elapsed)) = self.selected_process_mapping_loading() {
            return format!("loading pid {pid}: {} ms", elapsed.as_millis());
        }
        let Some(process) = self.selected_process() else {
            return "none".to_string();
        };
        self.process_mappings.scan_label(process.key())
    }

    #[must_use]
    pub fn process_mapping_started_at(&self) -> Option<(Pid, Instant)> {
        self.process_mappings.first_loading()
    }

    #[must_use]
    pub fn shared_scan_started_at(&self) -> Option<Instant> {
        self.shared_scan_started_at
    }

    #[must_use]
    pub fn selected_tmpfs_mount(&self) -> Option<&TmpfsMount> {
        let row = self.tmpfs_rows.selected()?;
        self.ledgers.tmpfs_data()?.mounts.get(row.mount_index)
    }

    #[must_use]
    pub fn selected_shared_object(&self) -> Option<&SharedObject> {
        let row = self.shared_rows.selected()?;
        self.ledgers.shared_data()?.objects.get(row.index)
    }

    pub fn handle_key(&mut self, key: KeyEvent, commands: &WorkerPort) -> bool {
        if self.kill_confirmation().is_some() {
            return self.handle_kill_confirmation_key(key, commands);
        }
        if self.search_draft().is_some() {
            return self.handle_search_key(key);
        }
        if self.help_open() {
            return self.handle_help_key(key);
        }

        match self.key_sequence.resolve(key) {
            SequenceResolution::Unmatched(key) => self.handle_single_key(key, commands),
            SequenceResolution::Pending | SequenceResolution::Cancelled => false,
            SequenceResolution::Command(action) => self.execute(action, commands),
        }
    }

    fn handle_single_key(&mut self, key: KeyEvent, commands: &WorkerPort) -> bool {
        nav::resolve(self.tab, key).is_some_and(|action| self.execute(action, commands))
    }

    fn execute(&mut self, action: Action, commands: &WorkerPort) -> bool {
        match action {
            Action::Ignore => {}
            Action::Quit => return true,
            Action::ShowHelp => self.modal = Some(Modal::Help),
            Action::OpenSearch => self.open_search(),
            Action::ClearSearch => self.clear_search(),
            Action::NextTab => self.select_tab(self.tab.next(), commands),
            Action::PreviousTab => self.select_tab(self.tab.previous(), commands),
            Action::SelectTab(tab) => self.select_tab(tab, commands),
            Action::CycleMetric => {
                self.metric = self.metric.next();
                self.rebuild_process_rows();
                self.rebuild_shared_rows();
            }
            Action::CycleScope => {
                self.tree_scope = self.tree_scope.next();
                self.rebuild_filterable_rows();
            }
            Action::Kill => self.arm_process_kill(),
            Action::Refresh => self.refresh_current_pane(commands),
            Action::Move(delta) => {
                let _ = self.move_selection_and_request_mappings(delta, commands);
            }
            Action::PageDown => {
                let _ = self.page_selection_and_request_mappings(PageDirection::Down, commands);
            }
            Action::PageUp => {
                let _ = self.page_selection_and_request_mappings(PageDirection::Up, commands);
            }
            Action::Collapse => self.mutate_current_fold(FoldMutation::Collapse),
            Action::Expand => self.mutate_current_fold(FoldMutation::Expand),
            Action::Toggle => self.mutate_current_fold(FoldMutation::Toggle),
            Action::FirstRow => {
                let _ = self.select_edge_and_request_mappings(RowEdge::First, commands);
            }
            Action::LastRow => {
                let _ = self.select_edge_and_request_mappings(RowEdge::Last, commands);
            }
        }
        false
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent, commands: &WorkerPort) -> bool {
        if self.modal.is_some() {
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

    fn select_tab(&mut self, tab: Tab, commands: &WorkerPort) {
        self.tab = tab;
        if tab == Tab::Tmpfs {
            self.seize_tmpfs_selection();
        }
        self.request_current_pane(commands);
        self.sync_process_scanning(commands);
    }

    fn sync_process_scanning(&self, commands: &WorkerPort) {
        commands.set_process_scanning(self.focused && self.tab.drives_process_scans());
    }

    fn request_current_pane(&mut self, commands: &WorkerPort) {
        match self.tab {
            Tab::Overview => commands.refresh_inventory(),
            Tab::Processes => self.request_selected_process_mappings(commands),
            Tab::Tmpfs => commands.refresh_tmpfs(),
            Tab::Shared => commands.refresh_shared(),
        }
    }

    fn request_selected_process_mappings(&mut self, commands: &WorkerPort) {
        if self.tab != Tab::Processes {
            return;
        }
        let Some(process) = self.selected_process() else {
            return;
        };
        let key = process.key();
        if self.process_mappings.begin(key) {
            commands.refresh_process_mappings(key);
        }
    }

    fn retain_live_process_mappings(&mut self) {
        let Some(processes) = self.ledgers.process_data() else {
            self.process_mappings.clear();
            return;
        };
        let live = processes
            .tree
            .nodes
            .iter()
            .map(|node| node.key())
            .collect::<BTreeSet<_>>();
        self.process_mappings.retain(&live);
    }

    fn refresh_current_pane(&mut self, commands: &WorkerPort) {
        match self.tab {
            Tab::Overview => commands.refresh_inventory(),
            Tab::Processes => commands.refresh_processes(),
            Tab::Tmpfs => {
                if let Some(mount) = self.selected_tmpfs_mount() {
                    commands.refresh_tmpfs_mount(mount.mount_point.clone());
                } else {
                    commands.refresh_tmpfs();
                }
            }
            Tab::Shared => commands.refresh_shared(),
        }
    }

    fn open_search(&mut self) {
        self.key_sequence = KeySequence::Root;
        self.modal = Some(Modal::Search(SearchDraft::new(self.search.as_ref())));
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
                self.modal = None;
                false
            }
            KeyCode::Enter => {
                self.commit_search();
                false
            }
            KeyCode::Backspace => {
                if let Some(Modal::Search(draft)) = self.modal.as_mut() {
                    draft.backspace();
                }
                false
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(Modal::Search(draft)) = self.modal.as_mut() {
                    draft.clear();
                }
                false
            }
            KeyCode::Char(character) if plain_char(key).is_some() => {
                if let Some(Modal::Search(draft)) = self.modal.as_mut() {
                    draft.push(character);
                }
                false
            }
            _ => false,
        }
    }

    fn commit_search(&mut self) {
        let Some(Modal::Search(draft)) = self.modal.take() else {
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
                self.modal = Some(Modal::Search(draft));
            }
        }
    }

    fn handle_help_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Esc | KeyCode::Char('?') => {
                self.modal = None;
                false
            }
            _ => false,
        }
    }

    fn handle_kill_confirmation_key(&mut self, key: KeyEvent, commands: &WorkerPort) -> bool {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Esc | KeyCode::Char('n') => {
                self.modal = None;
                false
            }
            KeyCode::Char('y')
                if self
                    .kill_confirmation()
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

    fn move_selection_and_request_mappings(&mut self, delta: isize, commands: &WorkerPort) -> bool {
        let changed = self.move_selection(delta);
        self.request_selected_process_mappings_after(changed, commands)
    }

    fn page_selection_and_request_mappings(
        &mut self,
        direction: PageDirection,
        commands: &WorkerPort,
    ) -> bool {
        let changed = self.page_selection(direction);
        self.request_selected_process_mappings_after(changed, commands)
    }

    fn select_edge_and_request_mappings(&mut self, edge: RowEdge, commands: &WorkerPort) -> bool {
        let changed = self.select_edge(edge);
        self.request_selected_process_mappings_after(changed, commands)
    }

    fn request_selected_process_mappings_after(
        &mut self,
        changed: bool,
        commands: &WorkerPort,
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

    fn mutate_current_fold(&mut self, mutation: FoldMutation) {
        let target = match self.tab {
            Tab::Processes => self
                .process_rows
                .selected()
                .map(|row| (FoldTarget::Process(row.key), row.fold)),
            Tab::Tmpfs => self
                .tmpfs_rows
                .selected()
                .map(|row| (FoldTarget::Tmpfs(row.path.clone()), row.fold)),
            Tab::Overview | Tab::Shared => None,
        };
        let Some((target, override_)) = target
            .and_then(|(target, fold)| mutation.apply(fold).map(|override_| (target, override_)))
        else {
            return;
        };
        match target {
            FoldTarget::Process(key) => {
                let _ = self.process_folds.insert(key, override_);
                self.rebuild_process_rows();
            }
            FoldTarget::Tmpfs(path) => {
                let _ = self.tmpfs_folds.insert(path, override_);
                self.rebuild_tmpfs_rows();
            }
        }
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
                self.modal = Some(Modal::Kill(KillConfirmation::new(target)));
            }
            Err(error) => self.last_error = Some(error),
        }
    }

    fn confirm_process_kill(&mut self, commands: &WorkerPort) {
        let Some(Modal::Kill(confirmation)) = self.modal.take() else {
            return;
        };
        match confirmation.target.send_sigterm() {
            Ok(()) => {
                self.last_error = None;
                commands.refresh_processes();
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

#[cfg(test)]
mod tests;
