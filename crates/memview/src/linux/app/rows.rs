use super::*;
use std::cmp::Ordering;

pub(super) fn build_process_rows(
    processes: &Processes,
    metric: Metric,
    scope: TreeScope,
    overrides: &BTreeMap<ProcessKey, FoldOverride>,
    search: Option<&Search>,
) -> (Vec<FlatProcessRow>, SearchSummary) {
    build_forest_rows(
        &ProcessForest {
            processes,
            metric,
            scope,
        },
        scope,
        overrides,
        search,
    )
}

pub(super) fn build_tmpfs_rows(
    tmpfs: &Tmpfs,
    system_total: Bytes,
    scope: TreeScope,
    overrides: &BTreeMap<PathBuf, FoldOverride>,
    search: Option<&Search>,
) -> (Vec<FlatTmpfsRow>, SearchSummary) {
    build_forest_rows(
        &TmpfsForest {
            tmpfs,
            system_total,
        },
        scope,
        overrides,
        search,
    )
}

pub(super) fn build_shared_rows(
    shared: &Shared,
    metric: Metric,
    search: Option<&Search>,
) -> (Vec<FlatSharedRow>, SearchSummary) {
    let mut summary = SearchSummary::new(metric.label());
    let mut indices = shared
        .objects
        .iter()
        .enumerate()
        .filter_map(|(index, object)| {
            search
                .is_none_or(|search| shared_matches(search, object))
                .then_some(index)
        })
        .collect::<Vec<_>>();
    indices.sort_by(|lhs, rhs| {
        let lhs = &shared.objects[*lhs];
        let rhs = &shared.objects[*rhs];
        metric
            .cmp_rollup(lhs.rollup, rhs.rollup)
            .then_with(|| lhs.kind.cmp(&rhs.kind))
            .then_with(|| lhs.label.cmp(&rhs.label))
    });
    let rows = indices
        .into_iter()
        .map(|index| {
            let object = &shared.objects[index];
            if search.is_some() {
                summary.strike(object.rollup.metric(metric));
            }
            FlatSharedRow {
                index,
                key: object.backing.clone(),
                search: search.map_or(SearchRole::Ordinary, |_| SearchRole::Match),
            }
        })
        .collect();
    (rows, summary)
}

trait Forest {
    type Handle: Copy;
    type Key: Clone + Ord;
    type Row;

    fn roots(&self) -> Vec<Self::Handle>;
    fn children(&self, handle: Self::Handle) -> Vec<Self::Handle>;
    fn key(&self, handle: Self::Handle) -> Self::Key;
    fn direct_value(&self, handle: Self::Handle) -> Bytes;
    fn total_value(&self, handle: Self::Handle) -> Bytes;
    fn matches(&self, search: &Search, handle: Self::Handle) -> bool;
    fn row(
        &self,
        handle: Self::Handle,
        depth: usize,
        fold: RowFold,
        search: SearchRole,
    ) -> Self::Row;
    fn system_total(&self) -> Bytes;
    fn summary_label(&self) -> &'static str;
}

fn build_forest_rows<F: Forest>(
    forest: &F,
    scope: TreeScope,
    overrides: &BTreeMap<F::Key, FoldOverride>,
    search: Option<&Search>,
) -> (Vec<F::Row>, SearchSummary) {
    let mut rows = Vec::new();
    let mut summary = SearchSummary::new(forest.summary_label());
    if let Some(search) = search {
        for root in forest.roots() {
            match scope {
                TreeScope::SelfOnly => {
                    push_direct_matches(forest, root, 0, search, &mut rows, &mut summary);
                }
                TreeScope::SelfAndChildren => {
                    let _ = push_contextual_matches(
                        forest,
                        root,
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
        overrides,
        de_minimis: DeMinimis::from_largest_non_root(
            forest.system_total(),
            largest_non_root_subtree(forest),
        ),
    };
    for root in forest.roots() {
        push_browse_rows(forest, root, 0, &policy, &mut rows);
    }
    (rows, summary)
}

fn push_browse_rows<F: Forest>(
    forest: &F,
    handle: F::Handle,
    depth: usize,
    policy: &FoldPolicy<'_, F::Key>,
    rows: &mut Vec<F::Row>,
) {
    let children = forest.children(handle);
    let fold = policy.row_fold(
        &forest.key(handle),
        depth,
        !children.is_empty(),
        forest.total_value(handle),
    );
    rows.push(forest.row(handle, depth, fold, SearchRole::Ordinary));
    if fold.is_collapsed() {
        return;
    }
    for child in children {
        push_browse_rows(forest, child, depth + 1, policy, rows);
    }
}

fn push_direct_matches<F: Forest>(
    forest: &F,
    handle: F::Handle,
    depth: usize,
    search: &Search,
    rows: &mut Vec<F::Row>,
    summary: &mut SearchSummary,
) {
    if forest.matches(search, handle) {
        summary.strike(forest.direct_value(handle));
        rows.push(forest.row(handle, depth, RowFold::Leaf, SearchRole::Match));
    }
    for child in forest.children(handle) {
        push_direct_matches(forest, child, depth + 1, search, rows, summary);
    }
}

fn push_contextual_matches<F: Forest>(
    forest: &F,
    handle: F::Handle,
    depth: usize,
    search: &Search,
    covered_by_match: bool,
    rows: &mut Vec<F::Row>,
    summary: &mut SearchSummary,
) -> bool {
    let direct = forest.matches(search, handle);
    let mut child_rows = Vec::new();
    let mut child_visible = false;
    for child in forest.children(handle) {
        child_visible |= push_contextual_matches(
            forest,
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
            summary.attribute(forest.total_value(handle));
        }
    }
    let visible = direct || child_visible;
    if visible {
        rows.push(forest.row(
            handle,
            depth,
            if child_visible {
                RowFold::Expanded
            } else {
                RowFold::Leaf
            },
            if direct {
                SearchRole::Match
            } else {
                SearchRole::Context
            },
        ));
        rows.extend(child_rows);
    }
    visible
}

fn largest_non_root_subtree<F: Forest>(forest: &F) -> Bytes {
    forest
        .roots()
        .into_iter()
        .flat_map(|root| forest.children(root))
        .map(|child| largest_subtree(forest, child))
        .max()
        .unwrap_or(Bytes::ZERO)
}

fn largest_subtree<F: Forest>(forest: &F, handle: F::Handle) -> Bytes {
    let children = forest.children(handle);
    let child_max = children
        .iter()
        .copied()
        .map(|child| largest_subtree(forest, child))
        .max()
        .unwrap_or(Bytes::ZERO);
    child_max.max(forest.total_value(handle))
}

struct ProcessForest<'a> {
    processes: &'a Processes,
    metric: Metric,
    scope: TreeScope,
}

impl ProcessForest<'_> {
    fn node(&self, index: usize) -> &ProcessNode {
        &self.processes.tree.nodes[index]
    }

    fn sort(&self, indices: &mut [usize]) {
        indices.sort_by(|lhs, rhs| self.compare(self.node(*lhs), self.node(*rhs)));
    }

    fn compare(&self, lhs: &ProcessNode, rhs: &ProcessNode) -> Ordering {
        self.metric
            .cmp_rollup(self.scope.rollup(lhs), self.scope.rollup(rhs))
            .then_with(|| lhs.pid.cmp(&rhs.pid))
    }
}

impl Forest for ProcessForest<'_> {
    type Handle = usize;
    type Key = ProcessKey;
    type Row = FlatProcessRow;

    fn roots(&self) -> Vec<Self::Handle> {
        let mut roots = self.processes.tree.roots.clone();
        self.sort(&mut roots);
        roots
    }

    fn children(&self, handle: Self::Handle) -> Vec<Self::Handle> {
        let mut children = self.node(handle).children.clone();
        self.sort(&mut children);
        children
    }

    fn key(&self, handle: Self::Handle) -> Self::Key {
        self.node(handle).key()
    }

    fn direct_value(&self, handle: Self::Handle) -> Bytes {
        self.node(handle).rollup().metric(self.metric)
    }

    fn total_value(&self, handle: Self::Handle) -> Bytes {
        self.node(handle).subtree.metric(self.metric)
    }

    fn matches(&self, search: &Search, handle: Self::Handle) -> bool {
        let node = self.node(handle);
        search.matches(&node.name)
            || search.matches(&node.command)
            || node
                .cwd
                .as_ref()
                .is_some_and(|cwd| search.matches(cwd.as_str()))
            || search.matches(&node.username)
            || search.matches(&node.state)
            || search.matches(&node.pid.to_string())
    }

    fn row(
        &self,
        handle: Self::Handle,
        depth: usize,
        fold: RowFold,
        search: SearchRole,
    ) -> Self::Row {
        FlatProcessRow {
            index: handle,
            key: self.node(handle).key(),
            depth,
            fold,
            search,
        }
    }

    fn system_total(&self) -> Bytes {
        self.processes
            .meminfo
            .value("MemTotal")
            .unwrap_or(Bytes::ZERO)
    }

    fn summary_label(&self) -> &'static str {
        self.metric.label()
    }
}

#[derive(Clone, Copy)]
struct TmpfsHandle<'a> {
    mount_index: usize,
    node: &'a TmpfsNode,
}

struct TmpfsForest<'a> {
    tmpfs: &'a Tmpfs,
    system_total: Bytes,
}

impl<'a> Forest for TmpfsForest<'a> {
    type Handle = TmpfsHandle<'a>;
    type Key = PathBuf;
    type Row = FlatTmpfsRow;

    fn roots(&self) -> Vec<Self::Handle> {
        self.tmpfs
            .mounts
            .iter()
            .enumerate()
            .map(|(mount_index, mount)| TmpfsHandle {
                mount_index,
                node: &mount.root,
            })
            .collect()
    }

    fn children(&self, handle: Self::Handle) -> Vec<Self::Handle> {
        let mut children = handle
            .node
            .children
            .iter()
            .map(|node| TmpfsHandle {
                mount_index: handle.mount_index,
                node,
            })
            .collect::<Vec<_>>();
        children.sort_by(|lhs, rhs| {
            rhs.node
                .allocated
                .cmp(&lhs.node.allocated)
                .then_with(|| lhs.node.path.cmp(&rhs.node.path))
        });
        children
    }

    fn key(&self, handle: Self::Handle) -> Self::Key {
        handle.node.path.clone()
    }

    fn direct_value(&self, handle: Self::Handle) -> Bytes {
        handle.node.allocated
    }

    fn total_value(&self, handle: Self::Handle) -> Bytes {
        handle.node.allocated
    }

    fn matches(&self, search: &Search, handle: Self::Handle) -> bool {
        search.matches(&handle.node.name)
            || search.matches(handle.node.kind.label())
            || search.matches(handle.node.path.to_string_lossy().as_ref())
    }

    fn row(
        &self,
        handle: Self::Handle,
        depth: usize,
        fold: RowFold,
        search: SearchRole,
    ) -> Self::Row {
        FlatTmpfsRow {
            mount_index: handle.mount_index,
            path: handle.node.path.clone(),
            name: handle.node.name.clone(),
            kind: handle.node.kind,
            allocated: handle.node.allocated,
            logical: handle.node.logical,
            depth,
            fold,
            search,
        }
    }

    fn system_total(&self) -> Bytes {
        self.system_total
    }

    fn summary_label(&self) -> &'static str {
        "allocated"
    }
}

fn shared_matches(search: &Search, object: &SharedObject) -> bool {
    search.matches(&object.label) || search.matches(object.kind.label())
}
