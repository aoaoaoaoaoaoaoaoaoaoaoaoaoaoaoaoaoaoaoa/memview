use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pid(pub i32);

impl Display for Pid {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Bytes(pub u64);

impl Bytes {
    pub const ZERO: Self = Self(0);
    const KIB: f64 = 1024.0;
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

    #[must_use]
    pub fn from_kib(kib: u64) -> Self {
        Self(kib.saturating_mul(1024))
    }

    #[must_use]
    pub fn from_blocks_512(blocks: u64) -> Self {
        Self(blocks.saturating_mul(512))
    }

    #[must_use]
    pub fn as_f64(self) -> f64 {
        self.0 as f64
    }

    #[must_use]
    pub fn pct_of(self, total: Self) -> f64 {
        if total.0 == 0 {
            0.0
        } else {
            (self.as_f64() * 100.0) / total.as_f64()
        }
    }

    #[must_use]
    pub fn human_iec(self) -> String {
        if self.0 < 1024 {
            return format!("{} B", self.0);
        }

        let mut value = self.as_f64();
        let mut unit = 0usize;
        while value >= Self::KIB && unit + 1 < Self::UNITS.len() {
            value /= Self::KIB;
            unit += 1;
        }
        format!("{value:.1} {}", Self::UNITS[unit])
    }

    #[must_use]
    pub fn human_exact(self) -> String {
        format!("{} ({})", self.human_iec(), self.0)
    }
}

impl Add for Bytes {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign for Bytes {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_add(rhs.0);
    }
}

impl Sub for Bytes {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl SubAssign for Bytes {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_sub(rhs.0);
    }
}

impl Display for Bytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.human_iec())
    }
}

macro_rules! memory_rollup_apply {
    ($lhs:expr, $rhs:expr, $op:tt) => {{
        $lhs.size $op $rhs.size;
        $lhs.rss $op $rhs.rss;
        $lhs.pss $op $rhs.pss;
        $lhs.pss_dirty $op $rhs.pss_dirty;
        $lhs.pss_anon $op $rhs.pss_anon;
        $lhs.pss_file $op $rhs.pss_file;
        $lhs.pss_shmem $op $rhs.pss_shmem;
        $lhs.shared_clean $op $rhs.shared_clean;
        $lhs.shared_dirty $op $rhs.shared_dirty;
        $lhs.private_clean $op $rhs.private_clean;
        $lhs.private_dirty $op $rhs.private_dirty;
        $lhs.referenced $op $rhs.referenced;
        $lhs.anonymous $op $rhs.anonymous;
        $lhs.lazy_free $op $rhs.lazy_free;
        $lhs.anon_huge_pages $op $rhs.anon_huge_pages;
        $lhs.shmem_pmd_mapped $op $rhs.shmem_pmd_mapped;
        $lhs.file_pmd_mapped $op $rhs.file_pmd_mapped;
        $lhs.shared_hugetlb $op $rhs.shared_hugetlb;
        $lhs.private_hugetlb $op $rhs.private_hugetlb;
        $lhs.swap $op $rhs.swap;
        $lhs.swap_pss $op $rhs.swap_pss;
        $lhs.locked $op $rhs.locked;
    }};
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryRollup {
    pub size: Bytes,
    pub rss: Bytes,
    pub pss: Bytes,
    pub pss_dirty: Bytes,
    pub pss_anon: Bytes,
    pub pss_file: Bytes,
    pub pss_shmem: Bytes,
    pub shared_clean: Bytes,
    pub shared_dirty: Bytes,
    pub private_clean: Bytes,
    pub private_dirty: Bytes,
    pub referenced: Bytes,
    pub anonymous: Bytes,
    pub lazy_free: Bytes,
    pub anon_huge_pages: Bytes,
    pub shmem_pmd_mapped: Bytes,
    pub file_pmd_mapped: Bytes,
    pub shared_hugetlb: Bytes,
    pub private_hugetlb: Bytes,
    pub swap: Bytes,
    pub swap_pss: Bytes,
    pub locked: Bytes,
}

impl MemoryRollup {
    #[must_use]
    pub fn uss(self) -> Bytes {
        self.private_clean + self.private_dirty + self.private_hugetlb
    }

    #[must_use]
    pub fn shared(self) -> Bytes {
        self.shared_clean + self.shared_dirty + self.shared_hugetlb
    }

    #[must_use]
    pub fn metric(self, metric: Metric) -> Bytes {
        match metric {
            Metric::Pss => self.pss,
            Metric::Uss => self.uss(),
            Metric::Rss => self.rss,
            Metric::SwapPss => self.swap_pss,
            Metric::Anonymous => self.pss_anon.max(self.anonymous),
            Metric::File => self.pss_file,
            Metric::Shmem => self.pss_shmem.max(self.shared()),
        }
    }
}

impl Add for MemoryRollup {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl AddAssign for MemoryRollup {
    fn add_assign(&mut self, rhs: Self) {
        memory_rollup_apply!(self, rhs, +=);
    }
}

#[derive(Clone, Debug)]
pub struct MeminfoEntry {
    pub key: String,
    pub value: Bytes,
}

#[derive(Clone, Debug, Default)]
pub struct Meminfo {
    pub entries: Vec<MeminfoEntry>,
    pub table: BTreeMap<String, Bytes>,
}

impl Meminfo {
    #[must_use]
    pub fn get(&self, key: &str) -> Bytes {
        self.table.get(key).copied().unwrap_or(Bytes::ZERO)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectKind {
    Anonymous,
    SharedAnonymous,
    Heap,
    Stack,
    File,
    Tmpfs,
    Memfd,
    SysV,
    Vdso,
    Vvar,
    Vsyscall,
    Pseudo,
}

impl ObjectKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Anonymous => "anon",
            Self::SharedAnonymous => "shmem",
            Self::Heap => "heap",
            Self::Stack => "stack",
            Self::File => "file",
            Self::Tmpfs => "tmpfs",
            Self::Memfd => "memfd",
            Self::SysV => "sysv",
            Self::Vdso => "vdso",
            Self::Vvar => "vvar",
            Self::Vsyscall => "vsyscall",
            Self::Pseudo => "pseudo",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ObjectUsage {
    pub kind: ObjectKind,
    pub label: String,
    pub rollup: MemoryRollup,
    pub regions: usize,
}

#[derive(Clone, Debug)]
pub struct ObjectConsumer {
    pub pid: Pid,
    pub name: String,
    pub command: String,
    pub rollup: MemoryRollup,
}

#[derive(Clone, Debug)]
pub struct SharedObject {
    pub kind: ObjectKind,
    pub label: String,
    pub rollup: MemoryRollup,
    pub regions: usize,
    pub mapped_processes: usize,
    pub consumers: Vec<ObjectConsumer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerState {
    Exact,
    Approximate,
    Inaccessible,
    Deferred,
}

impl LedgerState {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Approximate => "approx",
            Self::Inaccessible => "inaccessible",
            Self::Deferred => "deferred",
        }
    }

    #[must_use]
    pub fn is_inaccessible(self) -> bool {
        matches!(self, Self::Approximate | Self::Inaccessible)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessTreeStats {
    pub observed_processes: usize,
    pub inaccessible_rollups: usize,
    pub inaccessible_maps: usize,
}

#[derive(Clone, Debug)]
pub struct ProcessNode {
    pub pid: Pid,
    pub ppid: Option<Pid>,
    pub name: String,
    pub command: String,
    pub username: String,
    pub state: String,
    pub threads: u32,
    pub rollup: MemoryRollup,
    pub subtree: MemoryRollup,
    pub children: Vec<usize>,
    pub objects: Vec<ObjectUsage>,
    pub rollup_state: LedgerState,
    pub mappings_state: LedgerState,
}

impl ProcessNode {
    #[must_use]
    pub fn title(&self) -> String {
        if self.command.is_empty() {
            format!("{} [{}]", self.name, self.pid)
        } else {
            format!("{} [{}] {}", self.name, self.pid, self.command)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcessTree {
    pub roots: Vec<usize>,
    pub nodes: Vec<ProcessNode>,
    pub stats: ProcessTreeStats,
}

#[derive(Clone, Debug)]
pub struct SysvSegment {
    pub id: i32,
    pub attachments: u32,
    pub owner_uid: u32,
    pub size: Bytes,
    pub rss: Bytes,
    pub swap: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TmpfsNodeKind {
    Mount,
    Directory,
    File,
    Symlink,
    Socket,
    Fifo,
    CharDevice,
    BlockDevice,
    Other,
}

impl TmpfsNodeKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Mount => "mount",
            Self::Directory => "dir",
            Self::File => "file",
            Self::Symlink => "link",
            Self::Socket => "sock",
            Self::Fifo => "fifo",
            Self::CharDevice => "char",
            Self::BlockDevice => "block",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TmpfsNode {
    pub path: PathBuf,
    pub name: String,
    pub kind: TmpfsNodeKind,
    pub allocated: Bytes,
    pub logical: Bytes,
    pub children: Vec<TmpfsNode>,
}

#[derive(Clone, Debug)]
pub struct TmpfsMount {
    pub mount_point: PathBuf,
    pub source: String,
    pub size_limit: Option<Bytes>,
    pub root: TmpfsNode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Metric {
    Pss,
    Uss,
    Rss,
    SwapPss,
    Anonymous,
    File,
    Shmem,
}

impl Metric {
    const ALL: [Self; 7] = [
        Self::Pss,
        Self::Uss,
        Self::Rss,
        Self::SwapPss,
        Self::Anonymous,
        Self::File,
        Self::Shmem,
    ];

    #[must_use]
    pub fn next(self) -> Self {
        let index = Self::ALL
            .iter()
            .position(|metric| *metric == self)
            .unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pss => "PSS",
            Self::Uss => "USS",
            Self::Rss => "RSS",
            Self::SwapPss => "SwapPSS",
            Self::Anonymous => "Anon",
            Self::File => "File",
            Self::Shmem => "Shmem",
        }
    }

    #[must_use]
    pub fn cmp_rollup(self, lhs: MemoryRollup, rhs: MemoryRollup) -> Ordering {
        rhs.metric(self).cmp(&lhs.metric(self))
    }
}

#[derive(Clone, Debug, Default)]
pub struct Overview {
    pub process_count: usize,
    pub inaccessible_rollups: usize,
    pub inaccessible_maps: usize,
    pub process_pss_total: Bytes,
    pub process_uss_total: Bytes,
    pub process_rss_total: Bytes,
    pub process_swap_pss_total: Bytes,
    pub process_pss_anon_total: Bytes,
    pub process_pss_file_total: Bytes,
    pub process_pss_shmem_total: Bytes,
    pub tmpfs_allocated_total: Bytes,
    pub sysv_rss_total: Bytes,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub captured_at: SystemTime,
    pub elapsed: Duration,
    pub meminfo: Meminfo,
    pub overview: Overview,
    pub process_tree: ProcessTree,
    pub shared_objects: Vec<SharedObject>,
    pub sysv_segments: Vec<SysvSegment>,
    pub tmpfs_mounts: Vec<TmpfsMount>,
    pub warnings: Vec<String>,
}
