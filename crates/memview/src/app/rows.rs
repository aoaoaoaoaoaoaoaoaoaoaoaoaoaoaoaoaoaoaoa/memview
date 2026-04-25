use super::*;

pub(super) fn build_process_rows(
    snapshot: &Snapshot,
    metric: Metric,
    scope: ProcessScope,
    collapsed: &BTreeSet<Pid>,
    expanded: &BTreeSet<Pid>,
    search: Option<&Search>,
) -> (Vec<FlatProcessRow>, SearchSummary) {
    let mut summary = SearchSummary::new(metric.label());
    let mut rows = Vec::new();
    let roots = sorted_process_roots(snapshot, metric, scope);
    if let Some(search) = search {
        match scope {
            ProcessScope::SelfOnly => {
                for root in roots {
                    push_process_search_self(
                        root,
                        0,
                        snapshot,
                        metric,
                        search,
                        &mut rows,
                        &mut summary,
                    );
                }
            }
            ProcessScope::SelfAndChildren => {
                for root in roots {
                    let _ = push_process_search_tree(
                        root,
                        0,
                        snapshot,
                        metric,
                        search,
                        false,
                        &mut rows,
                        &mut summary,
                    );
                }
            }
        }
        return (rows, summary);
    }

    let policy = FoldPolicy {
        collapsed,
        expanded,
        de_minimis: DeMinimis::from_largest_non_root(
            snapshot.meminfo.get("MemTotal"),
            largest_process_non_root_subtree(snapshot, metric),
        ),
    };
    for root in roots {
        push_process_rows(root, 0, snapshot, metric, scope, &policy, &mut rows);
    }
    (rows, summary)
}

pub(super) fn build_tmpfs_rows(
    snapshot: &Snapshot,
    scope: ProcessScope,
    collapsed: &BTreeSet<PathBuf>,
    expanded: &BTreeSet<PathBuf>,
    search: Option<&Search>,
) -> (Vec<FlatTmpfsRow>, SearchSummary) {
    let mut summary = SearchSummary::new("allocated");
    let mut rows = Vec::new();
    if let Some(search) = search {
        match scope {
            ProcessScope::SelfOnly => {
                for (mount_index, mount) in snapshot.tmpfs_mounts.iter().enumerate() {
                    push_tmpfs_search_self(
                        mount_index,
                        &mount.root,
                        0,
                        search,
                        &mut rows,
                        &mut summary,
                    );
                }
            }
            ProcessScope::SelfAndChildren => {
                for (mount_index, mount) in snapshot.tmpfs_mounts.iter().enumerate() {
                    let _ = push_tmpfs_search_tree(
                        mount_index,
                        &mount.root,
                        0,
                        search,
                        false,
                        &mut rows,
                        &mut summary,
                    );
                }
            }
        }
        return (rows, summary);
    }

    let policy = FoldPolicy {
        collapsed,
        expanded,
        de_minimis: DeMinimis::from_largest_non_root(
            snapshot.meminfo.get("MemTotal"),
            largest_tmpfs_non_root_subtree(snapshot),
        ),
    };
    for (mount_index, mount) in snapshot.tmpfs_mounts.iter().enumerate() {
        push_tmpfs_rows(mount_index, &mount.root, 0, &policy, &mut rows);
    }
    (rows, summary)
}

pub(super) fn build_shared_rows(
    snapshot: &Snapshot,
    metric: Metric,
    search: Option<&Search>,
) -> (Vec<FlatSharedRow>, SearchSummary) {
    let mut summary = SearchSummary::new(metric.label());
    let rows = snapshot
        .shared_objects
        .iter()
        .enumerate()
        .filter_map(|(index, object)| {
            let direct = search.is_none_or(|search| shared_matches(search, object));
            if !direct {
                return None;
            }
            if search.is_some() {
                summary.strike(object.rollup.metric(metric));
            }
            Some(FlatSharedRow {
                index,
                key: (object.kind, object.label.clone()),
                search: search.map_or(SearchRole::Ordinary, |_| SearchRole::Match),
            })
        })
        .collect();
    (rows, summary)
}

fn sorted_process_roots(snapshot: &Snapshot, metric: Metric, scope: ProcessScope) -> Vec<usize> {
    let mut roots = snapshot.process_tree.roots.clone();
    roots.sort_by(|lhs, rhs| {
        process_cmp(
            &snapshot.process_tree.nodes[*lhs],
            &snapshot.process_tree.nodes[*rhs],
            metric,
            scope,
        )
    });
    roots
}

fn largest_process_non_root_subtree(snapshot: &Snapshot, metric: Metric) -> Bytes {
    snapshot
        .process_tree
        .roots
        .iter()
        .flat_map(|root| snapshot.process_tree.nodes[*root].children.iter().copied())
        .map(|child| largest_process_subtree(child, snapshot, metric))
        .max()
        .unwrap_or(Bytes::ZERO)
}

fn largest_process_subtree(index: usize, snapshot: &Snapshot, metric: Metric) -> Bytes {
    let node = &snapshot.process_tree.nodes[index];
    let child_max = node
        .children
        .iter()
        .copied()
        .map(|child| largest_process_subtree(child, snapshot, metric))
        .max()
        .unwrap_or(Bytes::ZERO);
    if node.children.is_empty() {
        child_max
    } else {
        child_max.max(node.subtree.metric(metric))
    }
}

fn push_process_rows(
    index: usize,
    depth: usize,
    snapshot: &Snapshot,
    metric: Metric,
    scope: ProcessScope,
    policy: &FoldPolicy<'_, Pid>,
    rows: &mut Vec<FlatProcessRow>,
) {
    let node = &snapshot.process_tree.nodes[index];
    let fold = policy.row_fold(
        &node.pid,
        depth,
        !node.children.is_empty(),
        node.subtree.metric(metric),
    );
    rows.push(FlatProcessRow {
        index,
        pid: node.pid,
        depth,
        fold,
        search: SearchRole::Ordinary,
    });
    if fold.is_collapsed() {
        return;
    }

    for child in sorted_process_children(node, snapshot, metric, scope) {
        push_process_rows(child, depth + 1, snapshot, metric, scope, policy, rows);
    }
}

fn sorted_process_children(
    node: &ProcessNode,
    snapshot: &Snapshot,
    metric: Metric,
    scope: ProcessScope,
) -> Vec<usize> {
    let mut children = node.children.clone();
    children.sort_by(|lhs, rhs| {
        process_cmp(
            &snapshot.process_tree.nodes[*lhs],
            &snapshot.process_tree.nodes[*rhs],
            metric,
            scope,
        )
    });
    children
}

fn push_process_search_self(
    index: usize,
    depth: usize,
    snapshot: &Snapshot,
    metric: Metric,
    search: &Search,
    rows: &mut Vec<FlatProcessRow>,
    summary: &mut SearchSummary,
) {
    let node = &snapshot.process_tree.nodes[index];
    if process_matches(search, node) {
        summary.strike(node.rollup.metric(metric));
        rows.push(FlatProcessRow {
            index,
            pid: node.pid,
            depth,
            fold: RowFold::Leaf,
            search: SearchRole::Match,
        });
    }
    for child in sorted_process_children(node, snapshot, metric, ProcessScope::SelfOnly) {
        push_process_search_self(child, depth + 1, snapshot, metric, search, rows, summary);
    }
}

fn push_process_search_tree(
    index: usize,
    depth: usize,
    snapshot: &Snapshot,
    metric: Metric,
    search: &Search,
    covered_by_match: bool,
    rows: &mut Vec<FlatProcessRow>,
    summary: &mut SearchSummary,
) -> bool {
    let node = &snapshot.process_tree.nodes[index];
    let direct = process_matches(search, node);
    let mut child_rows = Vec::new();
    let mut child_visible = false;
    let children = sorted_process_children(node, snapshot, metric, ProcessScope::SelfAndChildren);
    for child in children {
        child_visible |= push_process_search_tree(
            child,
            depth + 1,
            snapshot,
            metric,
            search,
            covered_by_match || direct,
            &mut child_rows,
            summary,
        );
    }
    if direct {
        summary.hit();
        if !covered_by_match {
            summary.attribute(node.subtree.metric(metric));
        }
    }
    let visible = direct || child_visible;
    if visible {
        rows.push(FlatProcessRow {
            index,
            pid: node.pid,
            depth,
            fold: if child_visible {
                RowFold::Expanded
            } else {
                RowFold::Leaf
            },
            search: if direct {
                SearchRole::Match
            } else {
                SearchRole::Context
            },
        });
        rows.extend(child_rows);
    }
    visible
}

fn process_matches(search: &Search, node: &ProcessNode) -> bool {
    search.matches(&node.name)
        || search.matches(&node.command)
        || search.matches(&node.username)
        || search.matches(&node.state)
        || search.matches(&node.pid.to_string())
}

fn largest_tmpfs_non_root_subtree(snapshot: &Snapshot) -> Bytes {
    snapshot
        .tmpfs_mounts
        .iter()
        .flat_map(|mount| mount.root.children.iter())
        .map(largest_tmpfs_subtree)
        .max()
        .unwrap_or(Bytes::ZERO)
}

fn largest_tmpfs_subtree(node: &TmpfsNode) -> Bytes {
    let child_max = node
        .children
        .iter()
        .map(largest_tmpfs_subtree)
        .max()
        .unwrap_or(Bytes::ZERO);
    if node.children.is_empty() {
        child_max
    } else {
        child_max.max(node.allocated)
    }
}

fn push_tmpfs_rows(
    mount_index: usize,
    node: &TmpfsNode,
    depth: usize,
    policy: &FoldPolicy<'_, PathBuf>,
    rows: &mut Vec<FlatTmpfsRow>,
) {
    let fold = policy.row_fold(&node.path, depth, !node.children.is_empty(), node.allocated);
    rows.push(FlatTmpfsRow {
        mount_index,
        path: node.path.clone(),
        name: node.name.clone(),
        kind: node.kind,
        allocated: node.allocated,
        logical: node.logical,
        depth,
        fold,
        search: SearchRole::Ordinary,
    });
    if fold.is_collapsed() {
        return;
    }

    for child in sorted_tmpfs_children(node) {
        push_tmpfs_rows(mount_index, child, depth + 1, policy, rows);
    }
}

fn push_tmpfs_search_self(
    mount_index: usize,
    node: &TmpfsNode,
    depth: usize,
    search: &Search,
    rows: &mut Vec<FlatTmpfsRow>,
    summary: &mut SearchSummary,
) {
    if tmpfs_matches(search, node) {
        summary.strike(node.allocated);
        rows.push(FlatTmpfsRow {
            mount_index,
            path: node.path.clone(),
            name: node.name.clone(),
            kind: node.kind,
            allocated: node.allocated,
            logical: node.logical,
            depth,
            fold: RowFold::Leaf,
            search: SearchRole::Match,
        });
    }
    for child in sorted_tmpfs_children(node) {
        push_tmpfs_search_self(mount_index, child, depth + 1, search, rows, summary);
    }
}

fn push_tmpfs_search_tree(
    mount_index: usize,
    node: &TmpfsNode,
    depth: usize,
    search: &Search,
    covered_by_match: bool,
    rows: &mut Vec<FlatTmpfsRow>,
    summary: &mut SearchSummary,
) -> bool {
    let direct = tmpfs_matches(search, node);
    let mut child_rows = Vec::new();
    let mut child_visible = false;
    for child in sorted_tmpfs_children(node) {
        child_visible |= push_tmpfs_search_tree(
            mount_index,
            child,
            depth + 1,
            search,
            covered_by_match || direct,
            &mut child_rows,
            summary,
        );
    }
    if direct {
        summary.hit();
        if !covered_by_match {
            summary.attribute(node.allocated);
        }
    }
    let visible = direct || child_visible;
    if visible {
        rows.push(FlatTmpfsRow {
            mount_index,
            path: node.path.clone(),
            name: node.name.clone(),
            kind: node.kind,
            allocated: node.allocated,
            logical: node.logical,
            depth,
            fold: if child_visible {
                RowFold::Expanded
            } else {
                RowFold::Leaf
            },
            search: if direct {
                SearchRole::Match
            } else {
                SearchRole::Context
            },
        });
        rows.extend(child_rows);
    }
    visible
}

fn sorted_tmpfs_children(node: &TmpfsNode) -> Vec<&'_ TmpfsNode> {
    let mut children = node.children.iter().collect::<Vec<_>>();
    children.sort_by(|lhs, rhs| {
        rhs.allocated
            .cmp(&lhs.allocated)
            .then_with(|| lhs.path.cmp(&rhs.path))
    });
    children
}

fn tmpfs_matches(search: &Search, node: &TmpfsNode) -> bool {
    search.matches(&node.name)
        || search.matches(node.kind.label())
        || search.matches(node.path.to_string_lossy().as_ref())
}

fn shared_matches(search: &Search, object: &SharedObject) -> bool {
    search.matches(&object.label) || search.matches(object.kind.label())
}

fn process_cmp(
    lhs: &ProcessNode,
    rhs: &ProcessNode,
    metric: Metric,
    scope: ProcessScope,
) -> std::cmp::Ordering {
    metric
        .cmp_rollup(scope.rollup(lhs), scope.rollup(rhs))
        .then_with(|| lhs.pid.cmp(&rhs.pid))
}
