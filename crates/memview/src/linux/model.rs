use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::ops::{Add, AddAssign, Deref, Sub, SubAssign};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pid(pub i32);

impl Display for Pid {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessKey {
    pub pid: Pid,
    pub start_time_ticks: u64,
}

impl Display for ProcessKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.pid, self.start_time_ticks)
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

macro_rules! memory_rollup {
    ($($field:ident => $proc_key:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct MemoryRollup {
            $(pub $field: Bytes,)+
        }

        impl MemoryRollup {
            pub(crate) fn apply_proc_field(&mut self, key: &str, value: Bytes) {
                match key {
                    $($proc_key => self.$field = value,)+
                    _ => {}
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
                $(self.$field += rhs.$field;)+
            }
        }
    };
}

memory_rollup! {
    size => "Size",
    rss => "Rss",
    pss => "Pss",
    pss_dirty => "Pss_Dirty",
    pss_anon => "Pss_Anon",
    pss_file => "Pss_File",
    pss_shmem => "Pss_Shmem",
    shared_clean => "Shared_Clean",
    shared_dirty => "Shared_Dirty",
    private_clean => "Private_Clean",
    private_dirty => "Private_Dirty",
    referenced => "Referenced",
    anonymous => "Anonymous",
    lazy_free => "LazyFree",
    anon_huge_pages => "AnonHugePages",
    shmem_pmd_mapped => "ShmemPmdMapped",
    file_pmd_mapped => "FilePmdMapped",
    shared_hugetlb => "Shared_Hugetlb",
    private_hugetlb => "Private_Hugetlb",
    swap => "Swap",
    swap_pss => "SwapPss",
    locked => "Locked",
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

#[derive(Clone, Debug)]
pub struct MeminfoEntry {
    pub key: String,
    pub value: Bytes,
}

#[derive(Clone, Debug, Default)]
pub struct Meminfo {
    pub entries: Vec<MeminfoEntry>,
}

impl Meminfo {
    #[must_use]
    pub fn get(&self, key: &str) -> Bytes {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map_or(Bytes::ZERO, |entry| entry.value)
    }

    #[must_use]
    pub fn physical_ledger(&self) -> PhysicalMemoryLedger {
        let sum = |keys: &[&str]| {
            keys.iter()
                .map(|key| self.get(key))
                .fold(Bytes::ZERO, |total, value| total + value)
        };
        let total = self.get("MemTotal");
        let free = self.get("MemFree");
        let allocated = total - free;
        let lru = sum(&[
            "Active(anon)",
            "Inactive(anon)",
            "Active(file)",
            "Inactive(file)",
            "Unevictable",
        ]);
        let slab = self.get("Slab");
        let hugetlb = self.get("Hugetlb");
        let kernel = sum(&[
            "KernelStack",
            "ShadowCallStack",
            "PageTables",
            "SecPageTables",
            "Percpu",
            "Zswap",
            "HardwareCorrupted",
            "Unaccepted",
            "Balloon",
            "GPUActive",
            "GPUReclaim",
        ]);
        let classified = lru + slab + hugetlb + kernel;

        PhysicalMemoryLedger {
            total,
            free,
            allocated,
            lru,
            slab,
            hugetlb,
            kernel,
            direct: allocated - classified,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PhysicalMemoryLedger {
    pub total: Bytes,
    pub free: Bytes,
    pub allocated: Bytes,
    pub lru: Bytes,
    pub slab: Bytes,
    pub hugetlb: Bytes,
    pub kernel: Bytes,
    pub direct: Bytes,
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
    pub fn is_degraded(self) -> bool {
        matches!(self, Self::Approximate | Self::Inaccessible)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessTreeStats {
    pub observed_processes: usize,
    pub degraded_rollups: usize,
    pub degraded_maps: usize,
}

#[derive(Clone, Debug)]
pub struct ProcessRecord {
    pub pid: Pid,
    pub start_time_ticks: u64,
    pub ppid: Option<Pid>,
    pub name: String,
    pub command: String,
    pub cwd: Option<ProcessCwd>,
    pub username: String,
    pub state: String,
    pub threads: u32,
    pub rollup: MemoryRollup,
    pub objects: Vec<ObjectUsage>,
    pub rollup_state: LedgerState,
    pub mappings_state: LedgerState,
}

impl ProcessRecord {
    #[must_use]
    pub fn key(&self) -> ProcessKey {
        ProcessKey {
            pid: self.pid,
            start_time_ticks: self.start_time_ticks,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcessNode {
    pub process: ProcessRecord,
    pub subtree: MemoryRollup,
    pub children: Vec<usize>,
}

impl Deref for ProcessNode {
    type Target = ProcessRecord;

    fn deref(&self) -> &Self::Target {
        &self.process
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessCwd(String);

impl ProcessCwd {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self(path.display().to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ProcessCwd {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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
pub struct ProcessTotals {
    pub process_count: usize,
    pub degraded_rollups: usize,
    pub degraded_maps: usize,
    pub pss: Bytes,
    pub uss: Bytes,
    pub rss: Bytes,
    pub swap_pss: Bytes,
    pub pss_anon: Bytes,
    pub pss_file: Bytes,
    pub pss_shmem: Bytes,
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureStamp {
    pub captured_at: SystemTime,
    pub elapsed: Duration,
}

#[derive(Clone, Debug)]
pub struct Ledger<T> {
    pub stamp: CaptureStamp,
    pub value: T,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvidiaPoolSnapshot {
    pub bytes: Bytes,
    pub pool_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvidiaPoolLedger {
    Disabled,
    Exact(NvidiaPoolSnapshot),
    Inaccessible,
}

#[derive(Clone, Debug)]
pub struct Inventory {
    pub meminfo: Meminfo,
    pub sysv_segments: Vec<SysvSegment>,
    pub sysv_rss_total: Bytes,
    pub nvidia_pools: Option<NvidiaPoolLedger>,
}

#[derive(Clone, Debug)]
pub struct Processes {
    pub meminfo: Meminfo,
    pub tree: ProcessTree,
    pub totals: ProcessTotals,
}

#[derive(Clone, Debug)]
pub struct Tmpfs {
    pub mounts: Vec<TmpfsMount>,
    pub allocated_total: Bytes,
}

#[derive(Clone, Debug)]
pub struct Shared {
    pub meminfo: Meminfo,
    pub objects: Vec<SharedObject>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_ledger_leaves_direct_allocator_pages_as_an_explicit_residual() {
        let entries = [
            ("MemTotal", 1_000),
            ("MemFree", 100),
            ("Active(anon)", 200),
            ("Inactive(anon)", 100),
            ("Active(file)", 100),
            ("Inactive(file)", 90),
            ("Unevictable", 10),
            ("Slab", 100),
            ("Hugetlb", 100),
            ("KernelStack", 20),
            ("PageTables", 20),
            ("Percpu", 10),
        ]
        .into_iter()
        .map(|(key, value)| MeminfoEntry {
            key: key.to_string(),
            value: Bytes(value),
        })
        .collect();
        let ledger = Meminfo { entries }.physical_ledger();

        assert_eq!(ledger.allocated, Bytes(900));
        assert_eq!(ledger.lru, Bytes(500));
        assert_eq!(ledger.kernel, Bytes(50));
        assert_eq!(ledger.direct, Bytes(150));
    }
}
