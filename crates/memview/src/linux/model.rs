use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::ops::{Add, AddAssign, Deref};
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
        Self::from_wide(u128::from(kib) * 1024)
    }

    #[must_use]
    pub fn from_blocks_512(blocks: u64) -> Self {
        Self::from_wide(u128::from(blocks) * 512)
    }

    #[must_use]
    pub fn from_wide(bytes: u128) -> Self {
        match u64::try_from(bytes) {
            Ok(bytes) => Self(bytes),
            Err(_) => std::process::abort(),
        }
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
        match self.0.checked_add(rhs.0) {
            Some(bytes) => Self(bytes),
            None => std::process::abort(),
        }
    }
}

impl AddAssign for Bytes {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Display for Bytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.human_iec())
    }
}

macro_rules! memory_rollup {
    ($($field:ident => $proc_key:literal),+ $(,)?) => {
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
    pub fn value(&self, key: &str) -> Option<Bytes> {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.value)
    }

    #[must_use]
    pub fn physical_ledger(&self) -> Option<PhysicalMemoryLedger> {
        // /proc/meminfo is neither exhaustive nor wholly disjoint. This deliberately uses only
        // physical-state counters documented by the kernel and exposes the remainder as an
        // estimate, never as a proof of ownership. Contract:
        // https://docs.kernel.org/filesystems/proc.html#meminfo
        let sum = |keys: &[&str]| {
            keys.iter()
                .filter_map(|key| self.value(key))
                .fold(Bytes::ZERO, |total, value| total + value)
        };
        let total = self.value("MemTotal")?;
        let free = self.value("MemFree")?;
        let allocated = total.0.checked_sub(free.0).map(Bytes)?;
        let lru = sum(&[
            "Active(anon)",
            "Inactive(anon)",
            "Active(file)",
            "Inactive(file)",
            "Unevictable",
        ]);
        let slab = self.value("Slab").unwrap_or(Bytes::ZERO);
        let hugetlb = self.value("Hugetlb").unwrap_or(Bytes::ZERO);
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

        let residual = allocated.0.checked_sub(classified.0).map_or_else(
            || PhysicalResidual::Inconsistent {
                excess: Bytes(classified.0 - allocated.0),
            },
            |bytes| PhysicalResidual::Estimate(Bytes(bytes)),
        );

        Some(PhysicalMemoryLedger {
            total,
            free,
            allocated,
            lru,
            slab,
            hugetlb,
            kernel,
            residual,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalMemoryLedger {
    pub total: Bytes,
    pub free: Bytes,
    pub allocated: Bytes,
    pub lru: Bytes,
    pub slab: Bytes,
    pub hugetlb: Bytes,
    pub kernel: Bytes,
    pub residual: PhysicalResidual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalResidual {
    Estimate(Bytes),
    Inconsistent { excess: Bytes },
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BackingIdentity {
    DeviceInode {
        device_major: u32,
        device_minor: u32,
        inode: u64,
    },
    ProcessRegion {
        process: ProcessKey,
        start_address: u64,
    },
    SysvTable(i32),
}

impl Display for BackingIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceInode {
                device_major,
                device_minor,
                inode,
            } => write!(f, "{device_major:x}:{device_minor:x}:{inode}"),
            Self::ProcessRegion {
                process,
                start_address,
            } => write!(f, "{process}:{start_address:x}"),
            Self::SysvTable(id) => write!(f, "sysvipc:{id}"),
        }
    }
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
    pub backing: BackingIdentity,
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
    pub backing: BackingIdentity,
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
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatusMemory {
    pub rss: Bytes,
    pub anonymous: Bytes,
    pub file: Bytes,
    pub shmem: Bytes,
    pub swap: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessMemory {
    Smaps(MemoryRollup),
    Status(StatusMemory),
}

impl ProcessMemory {
    #[must_use]
    pub fn rollup(self) -> MemoryRollup {
        match self {
            Self::Smaps(rollup) => rollup,
            Self::Status(status) => MemoryRollup {
                rss: status.rss,
                anonymous: status.anonymous,
                swap: status.swap,
                ..MemoryRollup::default()
            },
        }
    }

    #[must_use]
    pub fn state(self) -> LedgerState {
        match self {
            Self::Smaps(_) => LedgerState::Exact,
            Self::Status(_) => LedgerState::Approximate,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessCoverage {
    pub candidates: usize,
    pub captured: usize,
    pub vanished: usize,
    pub inaccessible: usize,
    pub exact_rollups: usize,
    pub status_rollups: usize,
    pub exact_maps: usize,
    pub inaccessible_maps: usize,
    pub deferred_maps: usize,
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
    pub memory: ProcessMemory,
    pub objects: Vec<ObjectUsage>,
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

    #[must_use]
    pub fn rollup(&self) -> MemoryRollup {
        self.memory.rollup()
    }

    #[must_use]
    pub fn rollup_state(&self) -> LedgerState {
        self.memory.state()
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
    pub coverage: ProcessCoverage,
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
    pub pss: Bytes,
    pub uss: Bytes,
    pub rss: Bytes,
    pub swap_pss: Bytes,
    pub pss_anon: Bytes,
    pub pss_file: Bytes,
    pub pss_shmem: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CaptureId(pub u64);

impl Display for CaptureId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureStamp {
    pub id: CaptureId,
    pub began_at: SystemTime,
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
    Unsupported,
    Disabled,
    Exact(NvidiaPoolSnapshot),
    Inaccessible,
    Malformed,
}

#[derive(Clone, Debug)]
pub struct Inventory {
    pub meminfo: Meminfo,
    pub sysv_segments: Vec<SysvSegment>,
    pub sysv_rss_total: Bytes,
    pub nvidia_pools: NvidiaPoolLedger,
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
    pub coverage: ProcessCoverage,
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
        let ledger = Meminfo { entries }
            .physical_ledger()
            .expect("required counters exist");

        assert_eq!(ledger.allocated, Bytes(900));
        assert_eq!(ledger.lru, Bytes(500));
        assert_eq!(ledger.kernel, Bytes(50));
        assert_eq!(ledger.residual, PhysicalResidual::Estimate(Bytes(150)));
    }

    #[test]
    fn physical_ledger_fails_closed_without_required_counters() {
        let meminfo = Meminfo {
            entries: vec![MeminfoEntry {
                key: "MemTotal".to_string(),
                value: Bytes(1_000),
            }],
        };
        assert!(meminfo.physical_ledger().is_none());
    }

    #[test]
    fn physical_ledger_exposes_counter_inconsistency() {
        let entries = [("MemTotal", 1_000), ("MemFree", 500), ("Slab", 600)]
            .into_iter()
            .map(|(key, value)| MeminfoEntry {
                key: key.to_string(),
                value: Bytes(value),
            })
            .collect();
        let ledger = Meminfo { entries }
            .physical_ledger()
            .expect("required counters exist");
        assert_eq!(
            ledger.residual,
            PhysicalResidual::Inconsistent { excess: Bytes(100) }
        );
    }

    #[test]
    fn status_memory_never_masquerades_as_pss() {
        let memory = ProcessMemory::Status(StatusMemory {
            rss: Bytes(100),
            anonymous: Bytes(70),
            file: Bytes(20),
            shmem: Bytes(10),
            swap: Bytes(5),
        });
        let rollup = memory.rollup();
        assert_eq!(memory.state(), LedgerState::Approximate);
        assert_eq!(rollup.rss, Bytes(100));
        assert_eq!(rollup.pss, Bytes::ZERO);
        assert_eq!(rollup.pss_anon, Bytes::ZERO);
        assert_eq!(rollup.swap_pss, Bytes::ZERO);
    }
}
