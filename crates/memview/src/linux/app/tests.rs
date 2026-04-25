use super::*;

#[derive(Clone, Debug)]
struct TestRow(u8);

impl IdentifiedRow for TestRow {
    type Key = u8;

    fn key(&self) -> &Self::Key {
        &self.0
    }
}

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

fn tmpfs_snapshot(mounts: Vec<TmpfsMount>) -> Snapshot {
    Snapshot {
        captured_at: SystemTime::UNIX_EPOCH,
        elapsed: Duration::ZERO,
        meminfo: Meminfo::default(),
        overview: super::super::model::Overview::default(),
        process_tree: super::super::model::ProcessTree::default(),
        shared_objects: Vec::new(),
        sysv_segments: Vec::new(),
        tmpfs_mounts: mounts,
        warnings: Vec::new(),
    }
}

fn regex(pattern: &str) -> Search {
    Search::compile(pattern.to_string())
        .expect("test regex compiles")
        .expect("test regex is non-empty")
}

fn next_process_scan_switch(commands: &Receiver<WorkerCommand>) -> bool {
    match commands.recv().expect("process scan switch command") {
        WorkerCommand::SetProcessScanning(enabled) => enabled,
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
    let mut app = App::new();

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
    let collapsed = BTreeSet::new();
    let mut expanded = BTreeSet::new();
    let _ = expanded.insert(7);
    let policy = FoldPolicy {
        collapsed: &collapsed,
        expanded: &expanded,
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
fn pane_rows_can_select_deleted_row_successor_slot() {
    let mut rows = PaneRows::default();
    rows.install(vec![TestRow(1), TestRow(2), TestRow(3)]);
    let _ = rows.move_by(1);
    let successor = rows.selected_slot().expect("selected successor row slot");

    rows.install(vec![TestRow(1), TestRow(3)]);
    let _ = rows.select_clamped(successor);
    assert_eq!(rows.selected().map(|row| row.0), Some(3));

    rows.install(vec![TestRow(1)]);
    let _ = rows.select_clamped(successor);
    assert_eq!(rows.selected().map(|row| row.0), Some(1));
}

#[test]
fn tmpfs_background_rebuilds_stay_pinned_to_top_until_user_entry() {
    let mut app = App::new();
    app.snapshot = Some(tmpfs_snapshot(vec![tmpfs_mount("/tmpfs-small", Bytes(1))]));
    app.rebuild_tmpfs_rows();
    assert_eq!(
        app.tmpfs_rows.selected().map(|row| row.path.as_path()),
        Some(Path::new("/tmpfs-small"))
    );

    app.snapshot = Some(tmpfs_snapshot(vec![
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
    let (commands, _events) = mpsc::channel();
    let mut app = App::new();
    app.snapshot = Some(tmpfs_snapshot(vec![
        tmpfs_mount("/tmpfs-big", Bytes(2)),
        tmpfs_mount("/tmpfs-small", Bytes(1)),
    ]));
    app.rebuild_tmpfs_rows();
    let _ = app.tmpfs_rows.move_by(1);

    app.select_tab(Tab::Tmpfs, &commands);
    assert_eq!(app.selected_tmpfs_row(), 0);

    app.snapshot = Some(tmpfs_snapshot(vec![
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
fn optimistic_tmpfs_delete_prunes_immediately_and_keeps_successor_slot() {
    let mut app = App::new();
    app.tab = Tab::Tmpfs;
    app.snapshot = Some(tmpfs_snapshot(vec![tmpfs_tree(
        "/proc/self/memview-delete-test",
        Bytes(30),
        vec![
            tmpfs_dir(
                "/proc/self/memview-delete-test/victim",
                Bytes(20),
                Vec::new(),
            ),
            tmpfs_dir("/proc/self/memview-delete-test/next", Bytes(10), Vec::new()),
        ],
    )]));
    app.rebuild_tmpfs_rows();
    let _ = app.tmpfs_rows.move_by(1);

    app.delete_current_tmpfs_entry();

    assert_eq!(app.deletion_count(), 1);
    assert_eq!(
        app.tmpfs_rows()
            .iter()
            .map(|row| row.path.as_path())
            .collect::<Vec<_>>(),
        vec![
            Path::new("/proc/self/memview-delete-test"),
            Path::new("/proc/self/memview-delete-test/next"),
        ]
    );
    assert_eq!(app.selected_tmpfs_row(), 1);
}

#[test]
fn confirmed_tmpfs_tombstone_prunes_stale_scan_and_clears_after_absent_scan() {
    let stale = tmpfs_tree(
        "/tmp/memview-tombstone-test",
        Bytes(30),
        vec![
            tmpfs_dir("/tmp/memview-tombstone-test/victim", Bytes(20), Vec::new()),
            tmpfs_dir("/tmp/memview-tombstone-test/next", Bytes(10), Vec::new()),
        ],
    );
    let fresh = tmpfs_tree(
        "/tmp/memview-tombstone-test",
        Bytes(10),
        vec![tmpfs_dir(
            "/tmp/memview-tombstone-test/next",
            Bytes(10),
            Vec::new(),
        )],
    );
    let victim = PathBuf::from("/tmp/memview-tombstone-test/victim");
    let mut app = App::new();
    app.snapshot = Some(tmpfs_snapshot(vec![stale.clone()]));
    let _ = app.confirmed_deletions.insert(victim.clone());

    app.install_tmpfs_mount_scan(probe::TmpfsMountScan {
        captured_at: SystemTime::UNIX_EPOCH,
        elapsed: Duration::ZERO,
        mount: stale,
        warnings: Vec::new(),
    });
    assert!(!app.tmpfs_rows().iter().any(|row| row.path == victim));
    assert!(app.confirmed_deletions.contains(&victim));

    app.install_tmpfs_mount_scan(probe::TmpfsMountScan {
        captured_at: SystemTime::UNIX_EPOCH,
        elapsed: Duration::ZERO,
        mount: fresh,
        warnings: Vec::new(),
    });
    assert!(!app.confirmed_deletions.contains(&victim));
}

#[test]
fn tmpfs_search_self_mode_filters_to_direct_matches_and_sums_them() {
    let mut app = App::new();
    app.snapshot = Some(tmpfs_snapshot(vec![tmpfs_tree(
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
    let mut app = App::new();
    app.process_scope = ProcessScope::SelfAndChildren;
    app.snapshot = Some(tmpfs_snapshot(vec![tmpfs_tree(
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
    let mut app = App::new();
    app.process_scope = ProcessScope::SelfAndChildren;
    app.snapshot = Some(tmpfs_snapshot(vec![tmpfs_tree(
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
    let (commands, _events) = mpsc::channel();
    let mut app = App::new();
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
