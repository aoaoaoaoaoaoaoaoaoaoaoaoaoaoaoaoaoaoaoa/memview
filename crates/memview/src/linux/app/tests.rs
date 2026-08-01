use super::super::model::{
    BackingIdentity, CaptureId, CaptureStamp, LedgerState, MemoryRollup, ObjectKind,
    ProcessCoverage, ProcessCwd, ProcessMemory, ProcessRecord, ProcessTree,
};
use super::*;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};

fn tmpfs_mount(path: &str, allocated: Bytes) -> TmpfsMount {
    TmpfsMount {
        mount_point: PathBuf::from(path),
        source: "tmpfs".to_string(),
        size_limit: None,
        root: TmpfsNode {
            path: PathBuf::from(path),
            name: path.to_string(),
            kind: TmpfsNodeKind::Mount,
            allocated,
            logical: allocated,
            children: Vec::new(),
        },
    }
}

fn tmpfs_tree(path: &str, allocated: Bytes, children: Vec<TmpfsNode>) -> TmpfsMount {
    TmpfsMount {
        mount_point: PathBuf::from(path),
        source: "tmpfs".to_string(),
        size_limit: None,
        root: TmpfsNode {
            path: PathBuf::from(path),
            name: path.to_string(),
            kind: TmpfsNodeKind::Mount,
            allocated,
            logical: allocated,
            children,
        },
    }
}

fn tmpfs_dir(path: &str, allocated: Bytes, children: Vec<TmpfsNode>) -> TmpfsNode {
    TmpfsNode {
        path: PathBuf::from(path),
        name: path.to_string(),
        kind: TmpfsNodeKind::Directory,
        allocated,
        logical: allocated,
        children,
    }
}

fn ledger<T>(value: T) -> Ledger<T> {
    Ledger {
        stamp: CaptureStamp {
            id: CaptureId(1),
            began_at: SystemTime::UNIX_EPOCH,
            captured_at: SystemTime::UNIX_EPOCH,
            elapsed: Duration::ZERO,
        },
        value,
        warnings: Vec::new(),
    }
}

fn tmpfs_ledger(mounts: Vec<TmpfsMount>) -> Ledger<Tmpfs> {
    let allocated_total = mounts
        .iter()
        .map(|mount| mount.root.allocated)
        .fold(Bytes::ZERO, |total, allocated| total + allocated);
    ledger(Tmpfs {
        mounts,
        allocated_total,
    })
}

fn process_ledger(nodes: Vec<ProcessNode>) -> Ledger<Processes> {
    ledger(Processes {
        meminfo: Meminfo::default(),
        tree: ProcessTree {
            roots: (0..nodes.len()).collect(),
            nodes,
            coverage: ProcessCoverage::default(),
        },
        totals: super::super::model::ProcessTotals::default(),
    })
}

fn process_node(pid: i32, command: &str, cwd: Option<&str>) -> ProcessNode {
    let rollup = MemoryRollup {
        pss: Bytes(1024),
        rss: Bytes(1024),
        ..MemoryRollup::default()
    };
    ProcessNode {
        process: ProcessRecord {
            pid: Pid(pid),
            start_time_ticks: pid as u64,
            ppid: None,
            name: format!("p{pid}"),
            command: command.to_string(),
            cwd: cwd.map(|path| ProcessCwd::new(PathBuf::from(path))),
            username: "test".to_string(),
            state: "S".to_string(),
            threads: 1,
            memory: ProcessMemory::Smaps(rollup),
            objects: Vec::new(),
            mappings_state: LedgerState::Deferred,
        },
        subtree: rollup,
        children: Vec::new(),
    }
}

fn regex(pattern: &str) -> Search {
    Search::compile(pattern.to_string())
        .expect("test regex compiles")
        .expect("test regex is non-empty")
}

#[test]
fn shared_rows_obey_the_selected_metric() {
    let object = |label: &str, pss: u64, rss: u64| SharedObject {
        backing: BackingIdentity::SysvTable(pss as i32),
        kind: ObjectKind::File,
        label: label.to_string(),
        rollup: MemoryRollup {
            pss: Bytes(pss),
            rss: Bytes(rss),
            ..MemoryRollup::default()
        },
        regions: 1,
        mapped_processes: 1,
        consumers: Vec::new(),
    };
    let shared = Shared {
        meminfo: Meminfo::default(),
        coverage: ProcessCoverage::default(),
        objects: vec![object("pss", 20, 10), object("rss", 10, 20)],
    };

    let (pss, _) = build_shared_rows(&shared, Metric::Pss, None);
    let (rss, _) = build_shared_rows(&shared, Metric::Rss, None);
    assert_eq!(shared.objects[pss[0].index].label, "pss");
    assert_eq!(shared.objects[rss[0].index].label, "rss");
}

fn next_process_scan_switch(commands: &Receiver<ProcessRequest>) -> bool {
    match commands.recv().expect("process scan switch command") {
        ProcessRequest::SetScanning(enabled) => enabled,
        command => unreachable!("expected process scan switch, got {command:?}"),
    }
}

#[test]
fn de_minimis_chooses_lower_threshold() {
    assert_eq!(
        DeMinimis::from_largest_non_root(Bytes(10_000), Bytes(1_000)).threshold,
        Bytes(30)
    );
    assert_eq!(
        DeMinimis::from_largest_non_root(Bytes(10_000), Bytes(100_000)).threshold,
        Bytes(100)
    );
}

#[test]
fn process_scanning_tracks_focus_and_active_tab() {
    let (commands, events) = mpsc::channel();
    let commands = WorkerPort::process_harness(commands);
    let mut app = App::new(UiState::default());

    app.set_focused(false, &commands);
    assert!(!next_process_scan_switch(&events));

    app.select_tab(Tab::Processes, &commands);
    assert!(!next_process_scan_switch(&events));

    app.set_focused(true, &commands);
    assert!(next_process_scan_switch(&events));

    app.process_scan_started_at = Some(Instant::now());
    assert!(app.needs_periodic_redraw());
    app.set_focused(false, &commands);
    assert!(!next_process_scan_switch(&events));
    assert!(!app.needs_periodic_redraw());
}

#[test]
fn fold_policy_respects_roots_leaves_and_manual_overrides() {
    let mut overrides = BTreeMap::new();
    let _ = overrides.insert(7, FoldOverride::Expanded);
    let policy = FoldPolicy {
        overrides: &overrides,
        de_minimis: DeMinimis {
            threshold: Bytes(100),
        },
    };

    assert_eq!(policy.row_fold(&1, 0, true, Bytes(1)), RowFold::Expanded);
    assert_eq!(policy.row_fold(&1, 1, false, Bytes(1)), RowFold::Leaf);
    assert_eq!(policy.row_fold(&1, 1, true, Bytes(99)), RowFold::Collapsed);
    assert_eq!(policy.row_fold(&7, 1, true, Bytes(99)), RowFold::Expanded);
}

#[test]
fn process_search_matches_cwd() {
    let mut app = App::new(UiState::default());
    app.ledgers.processes = Some(process_ledger(vec![process_node(
        42,
        "rust-analyzer",
        Some("/home/main/programming/projects/memview"),
    )]));
    app.search = Some(regex("memview"));

    app.rebuild_process_rows();

    assert_eq!(app.process_rows().len(), 1);
    assert_eq!(app.process_rows()[0].key.pid, Pid(42));
}

#[test]
fn tmpfs_background_rebuilds_stay_pinned_to_top_until_user_entry() {
    let mut app = App::new(UiState::default());
    app.ledgers.tmpfs = Some(tmpfs_ledger(vec![tmpfs_mount("/tmpfs-small", Bytes(1))]));
    app.rebuild_tmpfs_rows();
    assert_eq!(
        app.tmpfs_rows.selected().map(|row| row.path.as_path()),
        Some(Path::new("/tmpfs-small"))
    );

    app.ledgers.tmpfs = Some(tmpfs_ledger(vec![
        tmpfs_mount("/tmpfs-big", Bytes(2)),
        tmpfs_mount("/tmpfs-small", Bytes(1)),
    ]));
    app.rebuild_tmpfs_rows();
    assert_eq!(app.selected_tmpfs_row(), 0);
    assert_eq!(
        app.tmpfs_rows.selected().map(|row| row.path.as_path()),
        Some(Path::new("/tmpfs-big"))
    );
}

#[test]
fn first_tmpfs_entry_seizes_top_then_preserves_user_anchor() {
    let (processes, _requests) = mpsc::channel();
    let commands = WorkerPort::process_harness(processes);
    let mut app = App::new(UiState::default());
    app.ledgers.tmpfs = Some(tmpfs_ledger(vec![
        tmpfs_mount("/tmpfs-big", Bytes(2)),
        tmpfs_mount("/tmpfs-small", Bytes(1)),
    ]));
    app.rebuild_tmpfs_rows();
    let _ = app.tmpfs_rows.move_by(1);

    app.select_tab(Tab::Tmpfs, &commands);
    assert_eq!(app.selected_tmpfs_row(), 0);

    app.ledgers.tmpfs = Some(tmpfs_ledger(vec![
        tmpfs_mount("/tmpfs-bigger", Bytes(3)),
        tmpfs_mount("/tmpfs-big", Bytes(2)),
        tmpfs_mount("/tmpfs-small", Bytes(1)),
    ]));
    app.rebuild_tmpfs_rows();
    assert_eq!(
        app.tmpfs_rows.selected().map(|row| row.path.as_path()),
        Some(Path::new("/tmpfs-big"))
    );
}

#[test]
fn tmpfs_search_self_mode_filters_to_direct_matches_and_sums_them() {
    let mut app = App::new(UiState::default());
    app.ledgers.tmpfs = Some(tmpfs_ledger(vec![tmpfs_tree(
        "/mnt",
        Bytes(35),
        vec![
            tmpfs_dir("/mnt/batch-a", Bytes(10), Vec::new()),
            tmpfs_dir("/mnt/batch-b", Bytes(20), Vec::new()),
            tmpfs_dir("/mnt/other", Bytes(5), Vec::new()),
        ],
    )]));
    app.search = Some(regex("batch-[ab]"));
    app.rebuild_tmpfs_rows();

    assert_eq!(
        app.tmpfs_rows()
            .iter()
            .map(|row| row.path.as_path())
            .collect::<Vec<_>>(),
        vec![Path::new("/mnt/batch-b"), Path::new("/mnt/batch-a")]
    );
    assert_eq!(app.tmpfs_search.matches, 2);
    assert_eq!(app.tmpfs_search.total, Bytes(30));
}

#[test]
fn tmpfs_search_self_and_children_includes_context_parents_without_counting_them() {
    let mut app = App::new(UiState::default());
    app.tree_scope = TreeScope::SelfAndChildren;
    app.ledgers.tmpfs = Some(tmpfs_ledger(vec![tmpfs_tree(
        "/mnt",
        Bytes(35),
        vec![
            tmpfs_dir("/mnt/batch-a", Bytes(10), Vec::new()),
            tmpfs_dir("/mnt/batch-b", Bytes(20), Vec::new()),
            tmpfs_dir("/mnt/other", Bytes(5), Vec::new()),
        ],
    )]));
    app.search = Some(regex("batch-[ab]"));
    app.rebuild_tmpfs_rows();

    assert_eq!(
        app.tmpfs_rows()
            .iter()
            .map(|row| (row.path.as_path(), row.search))
            .collect::<Vec<_>>(),
        vec![
            (Path::new("/mnt"), SearchRole::Context),
            (Path::new("/mnt/batch-b"), SearchRole::Match),
            (Path::new("/mnt/batch-a"), SearchRole::Match),
        ]
    );
    assert_eq!(app.tmpfs_search.matches, 2);
    assert_eq!(app.tmpfs_search.total, Bytes(30));
}

#[test]
fn tmpfs_search_self_and_children_does_not_double_count_nested_matches() {
    let mut app = App::new(UiState::default());
    app.tree_scope = TreeScope::SelfAndChildren;
    app.ledgers.tmpfs = Some(tmpfs_ledger(vec![tmpfs_tree(
        "/batch-root",
        Bytes(30),
        vec![tmpfs_dir("/batch-root/batch-child", Bytes(10), Vec::new())],
    )]));
    app.search = Some(regex("batch"));
    app.rebuild_tmpfs_rows();

    assert_eq!(app.tmpfs_search.matches, 2);
    assert_eq!(app.tmpfs_search.total, Bytes(30));
}

#[test]
fn page_rows_match_left_table_viewport_height() {
    assert_eq!(PageRows::from_terminal_height(32), PageRows(23));
    assert_eq!(PageRows::from_terminal_height(9), PageRows(1));
    assert_eq!(PageRows::from_terminal_height(0), PageRows(1));
}

#[test]
fn page_keys_move_one_visible_pane() {
    let (processes, _requests) = mpsc::channel();
    let commands = WorkerPort::process_harness(processes);
    let mut app = App::new(UiState::default());
    app.tab = Tab::Tmpfs;
    app.set_terminal_height(12);
    app.tmpfs_rows.install(
        (0..10)
            .map(|index| FlatTmpfsRow {
                mount_index: 0,
                path: PathBuf::from(format!("/tmp/{index}")),
                name: index.to_string(),
                kind: TmpfsNodeKind::File,
                allocated: Bytes::ZERO,
                logical: Bytes::ZERO,
                depth: 0,
                fold: RowFold::Leaf,
                search: SearchRole::Ordinary,
            })
            .collect(),
    );

    let _ = app.handle_key(
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        &commands,
    );
    assert_eq!(app.selected_tmpfs_row(), 3);

    let _ = app.handle_key(
        KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
        &commands,
    );
    assert_eq!(app.selected_tmpfs_row(), 0);
}
