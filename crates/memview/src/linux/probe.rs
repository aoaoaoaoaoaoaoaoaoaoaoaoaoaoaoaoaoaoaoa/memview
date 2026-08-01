use super::model::{
    BackingIdentity, Bytes, CaptureId, CaptureStamp, Inventory, Ledger, LedgerState, Meminfo,
    MeminfoEntry, MemoryRollup, Metric, NvidiaPoolLedger, NvidiaPoolSnapshot, ObjectConsumer,
    ObjectKind, ObjectUsage, Pid, ProcessCoverage, ProcessCwd, ProcessKey, ProcessMemory,
    ProcessNode, ProcessRecord, ProcessTotals, ProcessTree, Processes, Shared, SharedObject,
    StatusMemory, SysvSegment, Tmpfs, TmpfsCoverage, TmpfsMount, TmpfsNode, TmpfsNodeKind,
};
use color_eyre::eyre::{Context, Result, eyre};
use rustix::param::page_size;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant, SystemTime};
use uzers::get_user_by_uid;
use walkdir::WalkDir;

const DELETED_MAPPING_SUFFIX: &str = " (deleted)";
const NVIDIA_PARAMS: &str = "/proc/driver/nvidia/params";
const SHRINKER_ROOT: &str = "/sys/kernel/debug/shrinker";
const NVIDIA_POOL_PREFIX: &str = "nv-sysmem-alloc-node-";
static NEXT_CAPTURE_ID: AtomicU64 = AtomicU64::new(1);

fn capture_stamp(began_at: SystemTime, started: Instant) -> CaptureStamp {
    CaptureStamp {
        id: CaptureId(NEXT_CAPTURE_ID.fetch_add(1, AtomicOrdering::Relaxed)),
        began_at,
        captured_at: SystemTime::now(),
        elapsed: started.elapsed(),
    }
}

#[derive(Debug)]
pub struct ProcessMappingScan {
    pub elapsed: Duration,
    pub cost: ProcessMappingCost,
    pub key: ProcessKey,
    pub objects: Vec<ObjectUsage>,
    pub mappings_state: LedgerState,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct ProcessMappingCost {
    pub mount_index: Duration,
    pub read: Duration,
    pub parse: Duration,
}

pub fn capture_inventory() -> Result<Ledger<Inventory>> {
    let began_at = SystemTime::now();
    let started = Instant::now();
    let mut warnings = Vec::new();
    let meminfo = read_meminfo().wrap_err("failed to read /proc/meminfo")?;
    let sysv_segments =
        read_sysv_segments(&mut warnings).wrap_err("failed to read /proc/sysvipc/shm")?;
    let sysv_rss_total = sysv_segments
        .iter()
        .map(|segment| segment.rss)
        .fold(Bytes::ZERO, |total, rss| total + rss);
    let nvidia_pools = read_nvidia_pool_ledger(&mut warnings);
    Ok(Ledger {
        stamp: capture_stamp(began_at, started),
        value: Inventory {
            meminfo,
            sysv_segments,
            sysv_rss_total,
            nvidia_pools,
        },
        warnings,
    })
}

fn read_nvidia_pool_ledger(warnings: &mut Vec<String>) -> NvidiaPoolLedger {
    let params = match fs::read_to_string(NVIDIA_PARAMS) {
        Ok(params) => params,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return NvidiaPoolLedger::Unsupported;
        }
        Err(error) => {
            warnings.push(format!("NVIDIA driver parameters unavailable: {error}"));
            return NvidiaPoolLedger::Inaccessible;
        }
    };
    let mask = match nvidia_pool_mask(&params) {
        Ok(mask) => mask,
        Err(error) => {
            warnings.push(format!("NVIDIA pool configuration is malformed: {error}"));
            return NvidiaPoolLedger::Malformed;
        }
    };
    if mask == 0 {
        return NvidiaPoolLedger::Disabled;
    }

    match read_nvidia_pool_snapshot(Path::new(SHRINKER_ROOT), page_size()) {
        Ok(snapshot) => NvidiaPoolLedger::Exact(snapshot),
        Err(error) => {
            warnings.push(format!(
                "NVIDIA system page pools are enabled but their shrinker counts are unavailable: \
                 {error}. The /proc/meminfo residual estimate may include them"
            ));
            NvidiaPoolLedger::Inaccessible
        }
    }
}

fn nvidia_pool_mask(params: &str) -> Result<u64> {
    let value = params
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "EnableSystemMemoryPools").then_some(value.trim())
        })
        .ok_or_else(|| eyre!("EnableSystemMemoryPools is absent"))?;
    value
        .parse()
        .wrap_err("EnableSystemMemoryPools is not an integer")
}

fn read_nvidia_pool_snapshot(root: &Path, page_size: usize) -> Result<NvidiaPoolSnapshot> {
    // NVIDIA's open driver registers NUMA-aware shrinkers under this name and reports
    // `pages_owned`; each object is one PAGE_SIZE << order allocation. Source contract pinned at
    // 452cec62d827034798072827d3866d1881662b77:
    // https://github.com/NVIDIA/open-gpu-kernel-modules/blob/main/kernel-open/nvidia/nv-vm.c
    let mut bytes = 0u64;
    let mut pool_count = 0usize;

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let Some((node, order)) = parse_nvidia_pool_name(&entry.file_name()) else {
            continue;
        };
        let count_text = fs::read_to_string(entry.path().join("count"))?;
        let objects = parse_shrinker_node_count(&count_text, node)?;
        let pool_bytes = nvidia_pool_bytes(objects, page_size, order)?;
        bytes = bytes
            .checked_add(pool_bytes)
            .ok_or_else(|| eyre!("NVIDIA pool total overflows"))?;
        pool_count += 1;
    }

    if pool_count == 0 {
        return Err(eyre!(
            "no {NVIDIA_POOL_PREFIX}* shrinkers matched the enabled pool configuration"
        ));
    }

    Ok(NvidiaPoolSnapshot {
        bytes: Bytes(bytes),
        pool_count,
    })
}

fn parse_nvidia_pool_name(name: &OsStr) -> Option<(usize, u32)> {
    let suffix = name.to_str()?.strip_prefix(NVIDIA_POOL_PREFIX)?;
    let (node, order_and_id) = suffix.split_once("-order-")?;
    let order = order_and_id.split('-').next()?;
    Some((node.parse().ok()?, order.parse().ok()?))
}

fn parse_shrinker_node_count(text: &str, node: usize) -> Result<u64> {
    let column = node
        .checked_add(1)
        .ok_or_else(|| eyre!("NUMA node index overflows"))?;
    text.lines().try_fold(0u64, |total, line| {
        let count = line
            .split_whitespace()
            .nth(column)
            .ok_or_else(|| eyre!("shrinker count omits NUMA node {node}"))?
            .parse::<u64>()?;
        total
            .checked_add(count)
            .ok_or_else(|| eyre!("shrinker object count overflows"))
    })
}

fn nvidia_pool_bytes(objects: u64, page_size: usize, order: u32) -> Result<u64> {
    let bytes_per_object = (page_size as u64)
        .checked_shl(order)
        .ok_or_else(|| eyre!("NVIDIA pool page order {order} overflows"))?;
    objects
        .checked_mul(bytes_per_object)
        .ok_or_else(|| eyre!("NVIDIA pool byte count overflows"))
}

pub fn capture_processes() -> Result<Ledger<Processes>> {
    let began_at = SystemTime::now();
    let started = Instant::now();
    let mut warnings = Vec::new();
    let meminfo = read_meminfo().wrap_err("failed to read /proc/meminfo")?;
    let forest = scan_processes(&mut warnings).wrap_err("failed to scan /proc")?;
    let tree = build_process_tree(forest.processes, forest.coverage);
    let totals = derive_process_totals(&tree);
    Ok(Ledger {
        stamp: capture_stamp(began_at, started),
        value: Processes {
            meminfo,
            tree,
            totals,
        },
        warnings,
    })
}

pub fn capture_process_mappings(key: ProcessKey) -> Result<ProcessMappingScan> {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let pid = key.pid;
    let root = PathBuf::from("/proc").join(pid.0.to_string());
    verify_process_key(&root, key)?;
    let mount_started = Instant::now();
    let mount_index = MountIndex::read().wrap_err("failed to read /proc/self/mountinfo")?;
    let mount_index_elapsed = mount_started.elapsed();
    let read_started = Instant::now();
    let (objects, mappings_state, read_elapsed, parse_elapsed) =
        match fs::read_to_string(root.join("smaps")) {
            Ok(text) => {
                let read_elapsed = read_started.elapsed();
                let parse_started = Instant::now();
                let objects = parse_smaps(&text, &mount_index, key);
                (
                    objects,
                    LedgerState::Exact,
                    read_elapsed,
                    parse_started.elapsed(),
                )
            }
            Err(error) => {
                warnings.push(format!(
                    "selected process mappings unavailable for {pid}: {error}"
                ));
                (
                    Vec::new(),
                    LedgerState::Inaccessible,
                    read_started.elapsed(),
                    Duration::ZERO,
                )
            }
        };
    verify_process_key(&root, key)?;

    Ok(ProcessMappingScan {
        elapsed: started.elapsed(),
        cost: ProcessMappingCost {
            mount_index: mount_index_elapsed,
            read: read_elapsed,
            parse: parse_elapsed,
        },
        key,
        objects,
        mappings_state,
        warnings,
    })
}

pub fn verify_process_identity(expected: ProcessKey) -> Result<()> {
    let root = PathBuf::from("/proc").join(expected.pid.0.to_string());
    verify_process_key(&root, expected)
}

pub fn capture_shared_objects() -> Result<Ledger<Shared>> {
    let began_at = SystemTime::now();
    let started = Instant::now();
    let mut warnings = Vec::new();
    let meminfo = read_meminfo().wrap_err("failed to read /proc/meminfo")?;
    let mount_index = MountIndex::read().wrap_err("failed to read /proc/self/mountinfo")?;
    let sysv_segments =
        read_sysv_segments(&mut warnings).wrap_err("failed to read /proc/sysvipc/shm")?;
    let (objects, coverage) = scan_shared_objects(&mount_index, &sysv_segments, &mut warnings)
        .wrap_err("failed to scan shared mappings")?;

    Ok(Ledger {
        stamp: capture_stamp(began_at, started),
        value: Shared {
            meminfo,
            coverage,
            objects,
        },
        warnings,
    })
}

pub fn capture_tmpfs() -> Result<Ledger<Tmpfs>> {
    let began_at = SystemTime::now();
    let started = Instant::now();
    let mount_index = MountIndex::read().wrap_err("failed to read /proc/self/mountinfo")?;
    let discovered_mounts = mount_index.tmpfs.len();
    let infos = unique_tmpfs_infos(&mount_index);
    let mut coverage = TmpfsCoverage {
        discovered_mounts,
        unique_filesystems: infos.len(),
        ..TmpfsCoverage::default()
    };
    let mut warnings = Vec::new();
    let mut mounts = Vec::with_capacity(infos.len());
    for info in infos {
        match scan_tmpfs_mount(&info, &mut coverage) {
            Ok(mount) => mounts.push(mount),
            Err(error) => {
                coverage.inaccessible_filesystems += 1;
                warnings.push(format!(
                    "tmpfs {} was not captured: {error}",
                    info.mount_point.display()
                ));
            }
        }
    }
    coverage.captured_filesystems = mounts.len();
    mounts.sort_by_key(|mount| Reverse(mount.root.allocated));
    let allocated_total = mounts
        .iter()
        .map(|mount| mount.root.allocated)
        .fold(Bytes::ZERO, |total, allocated| total + allocated);
    if coverage.walk_errors > 0 {
        warnings.push(format!(
            "{} tmpfs entries vanished or were inaccessible during traversal",
            coverage.walk_errors
        ));
    }

    Ok(Ledger {
        stamp: capture_stamp(began_at, started),
        value: Tmpfs {
            mounts,
            allocated_total,
            coverage,
        },
        warnings,
    })
}

#[derive(Clone, Debug)]
struct MountInfo {
    mount_point: PathBuf,
    device_major: u32,
    device_minor: u32,
    fs_type: String,
    source: String,
    super_options: String,
}

#[derive(Clone, Debug, Default)]
struct MountIndex {
    tmpfs: Vec<MountInfo>,
}

#[derive(Clone, Debug)]
struct TmpfsBuilder {
    path: PathBuf,
    name: String,
    kind: TmpfsNodeKind,
    allocated: Bytes,
    logical: Bytes,
    parent: Option<usize>,
    children: Vec<usize>,
}

impl MountIndex {
    fn read() -> Result<Self> {
        let text = fs::read_to_string("/proc/self/mountinfo")?;
        let mut tmpfs_by_mountpoint = BTreeMap::new();

        for line in text.lines().filter(|line| !line.is_empty()) {
            let Some(info) = parse_mountinfo_line(line) else {
                continue;
            };
            if info.fs_type == "tmpfs" {
                let _ = tmpfs_by_mountpoint
                    .entry(info.mount_point.clone())
                    .or_insert(info);
            }
        }
        let mut tmpfs = tmpfs_by_mountpoint.into_values().collect::<Vec<_>>();
        tmpfs.sort_by_key(|info| Reverse(info.mount_point.as_os_str().len()));
        Ok(Self { tmpfs })
    }

    fn match_tmpfs_mount<'a>(&'a self, path: &Path) -> Option<&'a MountInfo> {
        self.tmpfs.iter().find(|info| {
            path == info.mount_point
                || path
                    .strip_prefix(&info.mount_point)
                    .is_ok_and(|suffix| !suffix.as_os_str().is_empty())
        })
    }
}

fn parse_mountinfo_line(line: &str) -> Option<MountInfo> {
    let (left, right) = line.split_once(" - ")?;
    let left_fields = left.split_whitespace().collect::<Vec<_>>();
    let right_fields = right.split_whitespace().collect::<Vec<_>>();
    if left_fields.len() < 5 || right_fields.len() < 3 {
        return None;
    }
    let (device_major, device_minor) = left_fields[2].split_once(':')?;
    let device_major = device_major.parse().ok()?;
    let device_minor = device_minor.parse().ok()?;

    Some(MountInfo {
        mount_point: PathBuf::from(unescape_mount_field(left_fields[4])),
        device_major,
        device_minor,
        fs_type: right_fields[0].to_string(),
        source: right_fields[1].to_string(),
        super_options: right_fields[2..].join(" "),
    })
}

fn unescape_mount_field(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let slice = &value[index + 1..index + 4];
            if let Ok(code) = u8::from_str_radix(slice, 8) {
                out.push(char::from(code));
                index += 4;
                continue;
            }
        }

        out.push(bytes[index].into());
        index += 1;
    }

    out
}

fn read_meminfo() -> Result<Meminfo> {
    let text = fs::read_to_string("/proc/meminfo")?;
    Ok(parse_meminfo(&text))
}

fn parse_meminfo(text: &str) -> Meminfo {
    #[derive(Clone, Debug)]
    struct RawEntry<'a> {
        key: &'a str,
        number: u64,
        unit: Option<&'a str>,
    }

    let raw = text
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let (key, rest) = line.split_once(':')?;
            let mut fields = rest.split_whitespace();
            Some(RawEntry {
                key: key.trim(),
                number: fields.next()?.parse().ok()?,
                unit: fields.next(),
            })
        })
        .collect::<Vec<_>>();
    let hugepage_size = raw
        .iter()
        .find(|entry| entry.key == "Hugepagesize")
        .map(|entry| Bytes::from_kib(entry.number))
        .unwrap_or(Bytes::ZERO);
    let mut entries = Vec::new();
    for entry in raw {
        let value = meminfo_value(entry.key, entry.number, entry.unit, hugepage_size);
        entries.push(MeminfoEntry {
            key: entry.key.to_string(),
            value,
        });
    }

    Meminfo { entries }
}

fn meminfo_value(key: &str, number: u64, unit: Option<&str>, hugepage_size: Bytes) -> Bytes {
    if key.starts_with("HugePages_") {
        return Bytes::from_wide(u128::from(number) * u128::from(hugepage_size.0));
    }

    match unit {
        Some("kB") => Bytes::from_kib(number),
        _ => Bytes(number),
    }
}

fn read_sysv_segments(warnings: &mut Vec<String>) -> Result<Vec<SysvSegment>> {
    let text = match fs::read_to_string("/proc/sysvipc/shm") {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Ok(Vec::new());
    };
    let columns = header.split_whitespace().collect::<Vec<_>>();
    let index = columns
        .iter()
        .enumerate()
        .map(|(position, name)| (*name, position))
        .collect::<HashMap<_, _>>();

    let mut segments = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(id) = parse_column::<i32>(&fields, &index, "shmid") else {
            warnings.push(format!("ignoring malformed sysv shm row: {line}"));
            continue;
        };

        segments.push(SysvSegment {
            id,
            attachments: parse_column::<u32>(&fields, &index, "nattch").unwrap_or(0),
            owner_uid: parse_column::<u32>(&fields, &index, "uid").unwrap_or(0),
            size: parse_column::<u64>(&fields, &index, "size")
                .map(Bytes)
                .unwrap_or(Bytes::ZERO),
            rss: parse_column::<u64>(&fields, &index, "rss")
                .map(Bytes)
                .unwrap_or(Bytes::ZERO),
            swap: parse_column::<u64>(&fields, &index, "swap")
                .map(Bytes)
                .unwrap_or(Bytes::ZERO),
        });
    }

    segments.sort_by(|lhs, rhs| rhs.rss.cmp(&lhs.rss).then_with(|| lhs.id.cmp(&rhs.id)));
    Ok(segments)
}

fn parse_column<T: std::str::FromStr>(
    fields: &[&str],
    index: &HashMap<&str, usize>,
    name: &str,
) -> Option<T> {
    let position = *index.get(name)?;
    fields.get(position)?.parse().ok()
}

fn scan_process_shells(warnings: &mut Vec<String>) -> Result<ProcessForest> {
    let mut processes = Vec::new();
    let mut usernames = BTreeMap::new();
    let mut coverage = ProcessCoverage::default();

    for entry in fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!("ignoring /proc entry: {error}"));
                continue;
            }
        };

        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        coverage.candidates += 1;

        match scan_process_shell(Pid(pid), &mut usernames) {
            Ok(Some(process)) => processes.push(process),
            Ok(None) => coverage.vanished += 1,
            Err(error) => {
                coverage.inaccessible += 1;
                warnings.push(format!("pid {pid} was not captured: {error}"));
            }
        }
    }

    coverage.captured = processes.len();
    Ok(ProcessForest {
        processes,
        coverage,
    })
}

fn scan_processes(warnings: &mut Vec<String>) -> Result<ProcessForest> {
    let mut forest = scan_process_shells(warnings)?;
    forest.processes.sort_by_key(|process| process.pid);
    finish_process_coverage(&forest.processes, &mut forest.coverage);
    Ok(forest)
}

fn scan_process_shell(
    pid: Pid,
    usernames: &mut BTreeMap<u32, String>,
) -> Result<Option<ProcessRecord>> {
    let root = PathBuf::from("/proc").join(pid.0.to_string());
    let key = match read_process_key(&root, pid) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let status_text = match fs::read_to_string(root.join("status")) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    let status = parse_status(&status_text);
    let command = read_cmdline(&root).unwrap_or_else(|| status.name.clone());
    let cwd = read_cwd(&root);
    let username = lookup_username(status.uid, usernames);
    let status_memory = StatusMemory {
        rss: status.vm_rss,
        anonymous: status.rss_anon,
        file: status.rss_file,
        shmem: status.rss_shmem,
        swap: status.vm_swap,
    };
    let memory = match fs::read_to_string(root.join("smaps_rollup")) {
        Ok(text) => ProcessMemory::Smaps(parse_rollup_kv(&text)),
        Err(_) => ProcessMemory::Status(status_memory),
    };

    if read_process_key(&root, pid)? != key {
        return Ok(None);
    }

    Ok(Some(ProcessRecord {
        pid,
        start_time_ticks: key.start_time_ticks,
        ppid: status.ppid,
        name: status.name,
        command,
        cwd,
        username,
        state: status.state,
        threads: status.threads,
        memory,
        mappings_state: LedgerState::Deferred,
    }))
}

#[derive(Clone, Debug)]
struct ProcessForest {
    processes: Vec<ProcessRecord>,
    coverage: ProcessCoverage,
}

fn finish_process_coverage(processes: &[ProcessRecord], coverage: &mut ProcessCoverage) {
    coverage.captured = processes.len();
    coverage.exact_rollups = processes
        .iter()
        .filter(|process| process.rollup_state() == LedgerState::Exact)
        .count();
    coverage.status_rollups = processes
        .iter()
        .filter(|process| process.rollup_state() == LedgerState::Approximate)
        .count();
    coverage.exact_maps = processes
        .iter()
        .filter(|process| process.mappings_state == LedgerState::Exact)
        .count();
    coverage.inaccessible_maps = processes
        .iter()
        .filter(|process| process.mappings_state == LedgerState::Inaccessible)
        .count();
    coverage.deferred_maps = processes
        .iter()
        .filter(|process| process.mappings_state == LedgerState::Deferred)
        .count();
}

#[derive(Debug)]
struct SharedProcess {
    key: ProcessKey,
    name: String,
    command: String,
    objects: Vec<ObjectUsage>,
    mappings_state: LedgerState,
    warning: Option<String>,
}

struct SharedAccumulator {
    backing: BackingIdentity,
    kind: ObjectKind,
    label: String,
    rollup: MemoryRollup,
    regions: usize,
    consumers: Vec<ObjectConsumer>,
}

fn scan_shared_objects(
    mount_index: &MountIndex,
    sysv_segments: &[SysvSegment],
    warnings: &mut Vec<String>,
) -> Result<(Vec<SharedObject>, ProcessCoverage)> {
    let mut coverage = ProcessCoverage::default();
    let mut objects = BTreeMap::<BackingIdentity, SharedAccumulator>::new();
    for entry in fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!("ignoring /proc entry: {error}"));
                continue;
            }
        };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        coverage.candidates += 1;
        match scan_shared_process(Pid(pid), mount_index) {
            Ok(Some(process)) => {
                coverage.captured += 1;
                match process.mappings_state {
                    LedgerState::Exact => coverage.exact_maps += 1,
                    LedgerState::Inaccessible => coverage.inaccessible_maps += 1,
                    LedgerState::Deferred | LedgerState::Approximate => {}
                }
                if let Some(warning) = &process.warning {
                    warnings.push(warning.clone());
                }
                absorb_shared_process(&mut objects, process);
            }
            Ok(None) => coverage.vanished += 1,
            Err(error) => {
                coverage.inaccessible += 1;
                warnings.push(format!(
                    "pid {pid} shared mappings were not captured: {error}"
                ));
            }
        }
    }
    Ok((finalize_shared_objects(objects, sysv_segments), coverage))
}

fn absorb_shared_process(
    objects: &mut BTreeMap<BackingIdentity, SharedAccumulator>,
    process: SharedProcess,
) {
    for object in process.objects {
        let entry = objects
            .entry(object.backing.clone())
            .or_insert_with(|| SharedAccumulator {
                backing: object.backing.clone(),
                kind: object.kind,
                label: object.label.clone(),
                rollup: MemoryRollup::default(),
                regions: 0,
                consumers: Vec::new(),
            });
        entry.rollup += object.rollup;
        entry.regions += object.regions;
        entry.consumers.push(ObjectConsumer {
            pid: process.key.pid,
            name: process.name.clone(),
            command: process.command.clone(),
            rollup: object.rollup,
        });
    }
}

fn scan_shared_process(pid: Pid, mount_index: &MountIndex) -> Result<Option<SharedProcess>> {
    let root = PathBuf::from("/proc").join(pid.0.to_string());
    let key = match read_process_key(&root, pid) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let name = fs::read_to_string(root.join("comm"))
        .map(|name| name.trim_end().to_string())
        .unwrap_or_else(|_| pid.to_string());
    let command = read_cmdline(&root).unwrap_or_else(|| name.clone());
    let (objects, mappings_state, warning) = match fs::read_to_string(root.join("smaps")) {
        Ok(text) => (
            parse_smaps(&text, mount_index, key),
            LedgerState::Exact,
            None,
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => (
            Vec::new(),
            LedgerState::Inaccessible,
            Some(format!("pid {pid} smaps unavailable: {error}")),
        ),
    };
    match read_process_key(&root, pid) {
        Ok(observed) if observed == key => {}
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    Ok(Some(SharedProcess {
        key,
        name,
        command,
        objects,
        mappings_state,
        warning,
    }))
}

#[derive(Clone, Debug)]
struct StatusSnapshot {
    name: String,
    ppid: Option<Pid>,
    uid: u32,
    state: String,
    threads: u32,
    vm_rss: Bytes,
    vm_swap: Bytes,
    rss_anon: Bytes,
    rss_file: Bytes,
    rss_shmem: Bytes,
}

fn parse_status(text: &str) -> StatusSnapshot {
    let mut name = String::new();
    let mut ppid = None;
    let mut uid = 0u32;
    let mut state = "?".to_string();
    let mut threads = 0u32;
    let mut vm_rss = Bytes::ZERO;
    let mut vm_swap = Bytes::ZERO;
    let mut rss_anon = Bytes::ZERO;
    let mut rss_file = Bytes::ZERO;
    let mut rss_shmem = Bytes::ZERO;

    for line in text.lines().filter(|line| !line.is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "Name" => name = value.to_string(),
            "PPid" => ppid = value.parse::<i32>().ok().map(Pid),
            "Uid" => {
                uid = value
                    .split_whitespace()
                    .next()
                    .and_then(|field| field.parse().ok())
                    .unwrap_or(0);
            }
            "State" => state = value.to_string(),
            "Threads" => threads = value.parse().unwrap_or(0),
            "VmRSS" => vm_rss = parse_status_kib(value).unwrap_or(Bytes::ZERO),
            "VmSwap" => vm_swap = parse_status_kib(value).unwrap_or(Bytes::ZERO),
            "RssAnon" => rss_anon = parse_status_kib(value).unwrap_or(Bytes::ZERO),
            "RssFile" => rss_file = parse_status_kib(value).unwrap_or(Bytes::ZERO),
            "RssShmem" => rss_shmem = parse_status_kib(value).unwrap_or(Bytes::ZERO),
            _ => {}
        }
    }

    StatusSnapshot {
        name,
        ppid,
        uid,
        state,
        threads,
        vm_rss,
        vm_swap,
        rss_anon,
        rss_file,
        rss_shmem,
    }
}

fn parse_status_kib(value: &str) -> Option<Bytes> {
    value
        .split_whitespace()
        .next()
        .and_then(|field| field.parse::<u64>().ok())
        .map(Bytes::from_kib)
}

fn read_process_key(root: &Path, pid: Pid) -> io::Result<ProcessKey> {
    let stat = fs::read_to_string(root.join("stat"))?;
    let start_time_ticks = parse_process_start_time(&stat).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed {}", root.join("stat").display()),
        )
    })?;
    Ok(ProcessKey {
        pid,
        start_time_ticks,
    })
}

fn parse_process_start_time(stat: &str) -> Option<u64> {
    stat.get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn verify_process_key(root: &Path, expected: ProcessKey) -> Result<()> {
    let observed = read_process_key(root, expected.pid)
        .wrap_err_with(|| format!("failed to identify process {}", expected.pid))?;
    if observed == expected {
        Ok(())
    } else {
        Err(eyre!(
            "process identity changed: expected {expected}, observed {observed}"
        ))
    }
}

fn read_cmdline(root: &Path) -> Option<String> {
    let bytes = fs::read(root.join("cmdline")).ok()?;
    if bytes.is_empty() {
        return None;
    }

    let parts = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn read_cwd(root: &Path) -> Option<ProcessCwd> {
    fs::read_link(root.join("cwd")).ok().map(ProcessCwd::new)
}

fn lookup_username(uid: u32, cache: &mut BTreeMap<u32, String>) -> String {
    cache
        .entry(uid)
        .or_insert_with(|| {
            get_user_by_uid(uid)
                .map(|user| String::from_utf8_lossy(user.name().as_bytes()).into_owned())
                .unwrap_or_else(|| uid.to_string())
        })
        .clone()
}

fn parse_rollup_kv(text: &str) -> MemoryRollup {
    let mut rollup = MemoryRollup::default();

    for line in text.lines().skip(1) {
        let Some((key, value)) = parse_kib_value(line) else {
            continue;
        };
        rollup.apply_proc_field(key, value);
    }

    rollup
}

fn parse_kib_value(line: &str) -> Option<(&str, Bytes)> {
    let (key, rest) = line.split_once(':')?;
    let value = rest.split_whitespace().next()?.parse::<u64>().ok()?;
    Some((key.trim(), Bytes::from_kib(value)))
}

fn parse_smaps(text: &str, mount_index: &MountIndex, process: ProcessKey) -> Vec<ObjectUsage> {
    let mut objects = BTreeMap::<BackingIdentity, ObjectUsage>::new();
    let mut current = None::<MappingAccumulator>;

    for line in text.lines() {
        if let Some(header) = parse_mapping_header(line) {
            flush_mapping(&mut current, &mut objects);
            current = Some(MappingAccumulator::new(
                classify_mapping(&header.path, mount_index),
                header.size,
                header.backing(process),
            ));
            continue;
        }

        if let Some((key, value)) = parse_kib_value(line)
            && let Some(mapping) = current.as_mut()
        {
            mapping.rollup.apply_proc_field(key, value);
        }
    }

    flush_mapping(&mut current, &mut objects);
    let mut rows = objects.into_values().collect::<Vec<_>>();
    rows.sort_by(|lhs, rhs| {
        Metric::Pss
            .cmp_rollup(lhs.rollup, rhs.rollup)
            .then_with(|| lhs.label.cmp(&rhs.label))
    });
    rows
}

fn flush_mapping(
    current: &mut Option<MappingAccumulator>,
    objects: &mut BTreeMap<BackingIdentity, ObjectUsage>,
) {
    let Some(mapping) = current.take() else {
        return;
    };

    let key = mapping.backing.clone();
    let entry = objects.entry(key).or_insert_with(|| ObjectUsage {
        backing: mapping.backing.clone(),
        kind: mapping.kind,
        label: mapping.label.clone(),
        rollup: MemoryRollup::default(),
        regions: 0,
    });
    entry.rollup += mapping.rollup;
    entry.regions += 1;
}

#[derive(Clone, Debug)]
struct MappingAccumulator {
    backing: BackingIdentity,
    kind: ObjectKind,
    label: String,
    rollup: MemoryRollup,
}

impl MappingAccumulator {
    fn new(classified: ClassifiedMapping, size: Bytes, backing: BackingIdentity) -> Self {
        Self {
            backing,
            kind: classified.kind,
            label: classified.label,
            rollup: MemoryRollup {
                size,
                ..MemoryRollup::default()
            },
        }
    }
}

#[derive(Clone, Debug)]
struct MappingHeader {
    start_address: u64,
    size: Bytes,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    path: String,
}

impl MappingHeader {
    fn backing(&self, process: ProcessKey) -> BackingIdentity {
        if self.inode == 0 {
            BackingIdentity::ProcessRegion {
                process,
                start_address: self.start_address,
            }
        } else {
            BackingIdentity::DeviceInode {
                device_major: self.device_major,
                device_minor: self.device_minor,
                inode: self.inode,
            }
        }
    }
}

fn parse_mapping_header(line: &str) -> Option<MappingHeader> {
    let mut cursor = 0usize;
    let range = take_field(line, &mut cursor)?;
    let _perms = take_field(line, &mut cursor)?;
    let _offset = take_field(line, &mut cursor)?;
    let dev = take_field(line, &mut cursor)?;
    let inode = take_field(line, &mut cursor)?.parse().ok()?;
    let path = line[cursor..].trim().to_string();

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let (device_major, device_minor) = dev.split_once(':')?;
    let device_major = u32::from_str_radix(device_major, 16).ok()?;
    let device_minor = u32::from_str_radix(device_minor, 16).ok()?;

    Some(MappingHeader {
        start_address: start,
        size: Bytes(end.saturating_sub(start)),
        device_major,
        device_minor,
        inode,
        path,
    })
}

fn take_field<'a>(line: &'a str, cursor: &mut usize) -> Option<&'a str> {
    let bytes = line.as_bytes();
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
    if *cursor >= bytes.len() {
        return None;
    }
    let start = *cursor;
    while *cursor < bytes.len() && !bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
    Some(&line[start..*cursor])
}

#[derive(Clone, Debug)]
struct ClassifiedMapping {
    kind: ObjectKind,
    label: String,
}

fn classify_mapping(path: &str, mount_index: &MountIndex) -> ClassifiedMapping {
    if path.is_empty() {
        return ClassifiedMapping {
            kind: ObjectKind::Anonymous,
            label: "<anonymous>".to_string(),
        };
    }

    let mut raw = path.to_string();
    let deleted = raw.ends_with(DELETED_MAPPING_SUFFIX);
    if deleted {
        raw.truncate(raw.len().saturating_sub(DELETED_MAPPING_SUFFIX.len()));
    }

    if raw.starts_with('[') && raw.ends_with(']') {
        let inner = &raw[1..raw.len() - 1];
        return match inner {
            "heap" => ClassifiedMapping {
                kind: ObjectKind::Heap,
                label: "[heap]".to_string(),
            },
            "vdso" => ClassifiedMapping {
                kind: ObjectKind::Vdso,
                label: "[vdso]".to_string(),
            },
            "vvar" => ClassifiedMapping {
                kind: ObjectKind::Vvar,
                label: "[vvar]".to_string(),
            },
            "vsyscall" => ClassifiedMapping {
                kind: ObjectKind::Vsyscall,
                label: "[vsyscall]".to_string(),
            },
            _ if inner.starts_with("stack") => ClassifiedMapping {
                kind: ObjectKind::Stack,
                label: raw,
            },
            _ if inner.starts_with("anon_shmem:") => ClassifiedMapping {
                kind: ObjectKind::SharedAnonymous,
                label: raw,
            },
            _ if inner.starts_with("anon:") => ClassifiedMapping {
                kind: ObjectKind::Anonymous,
                label: raw,
            },
            _ => ClassifiedMapping {
                kind: ObjectKind::Pseudo,
                label: raw,
            },
        };
    }

    if raw.starts_with("/SYSV") {
        return ClassifiedMapping {
            kind: ObjectKind::SysV,
            label: restore_deleted_suffix(raw, deleted),
        };
    }

    if raw.starts_with("/memfd:") {
        return ClassifiedMapping {
            kind: ObjectKind::Memfd,
            label: restore_deleted_suffix(raw, deleted),
        };
    }

    let path = Path::new(&raw);
    if mount_index.match_tmpfs_mount(path).is_some() {
        return ClassifiedMapping {
            kind: ObjectKind::Tmpfs,
            label: restore_deleted_suffix(raw, deleted),
        };
    }

    ClassifiedMapping {
        kind: ObjectKind::File,
        label: restore_deleted_suffix(raw, deleted),
    }
}

fn restore_deleted_suffix(raw: String, deleted: bool) -> String {
    if deleted {
        format!("{raw}{DELETED_MAPPING_SUFFIX}")
    } else {
        raw
    }
}

fn build_process_tree(processes: Vec<ProcessRecord>, coverage: ProcessCoverage) -> ProcessTree {
    let mut nodes = processes
        .into_iter()
        .map(|process| {
            let subtree = process.rollup();
            ProcessNode {
                process,
                subtree,
                children: Vec::new(),
            }
        })
        .collect::<Vec<_>>();

    let by_pid = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.pid, index))
        .collect::<BTreeMap<_, _>>();

    let mut roots = Vec::new();
    for index in 0..nodes.len() {
        let Some(ppid) = nodes[index].ppid else {
            roots.push(index);
            continue;
        };
        match by_pid.get(&ppid).copied() {
            Some(parent) if parent != index => nodes[parent].children.push(index),
            _ => roots.push(index),
        }
    }

    for root in roots.clone() {
        let _ = accumulate_subtree(root, &mut nodes);
    }

    ProcessTree {
        roots,
        nodes,
        coverage,
    }
}

fn accumulate_subtree(index: usize, nodes: &mut [ProcessNode]) -> MemoryRollup {
    let children = nodes[index].children.clone();
    let mut subtotal = nodes[index].rollup();
    for child in children {
        subtotal += accumulate_subtree(child, nodes);
    }
    nodes[index].subtree = subtotal;
    subtotal
}

fn finalize_shared_objects(
    objects: BTreeMap<BackingIdentity, SharedAccumulator>,
    sysv_segments: &[SysvSegment],
) -> Vec<SharedObject> {
    let mut rows = objects
        .into_values()
        .map(|mut acc| {
            acc.consumers.sort_by(|lhs, rhs| {
                Metric::Pss
                    .cmp_rollup(lhs.rollup, rhs.rollup)
                    .then_with(|| lhs.pid.cmp(&rhs.pid))
            });
            SharedObject {
                backing: acc.backing,
                kind: acc.kind,
                label: acc.label,
                rollup: acc.rollup,
                regions: acc.regions,
                mapped_processes: acc.consumers.len(),
                consumers: acc.consumers,
            }
        })
        .collect::<Vec<_>>();

    for segment in sysv_segments {
        rows.push(SharedObject {
            backing: BackingIdentity::SysvTable(segment.id),
            kind: ObjectKind::SysV,
            label: format!(
                "sysv:{} owner:{} attaches:{} size:{}",
                segment.id,
                segment.owner_uid,
                segment.attachments,
                segment.size.human_iec()
            ),
            rollup: MemoryRollup {
                rss: segment.rss,
                swap: segment.swap,
                ..MemoryRollup::default()
            },
            regions: 1,
            mapped_processes: segment.attachments as usize,
            consumers: Vec::new(),
        });
    }

    rows.sort_by(|lhs, rhs| {
        Metric::Pss
            .cmp_rollup(lhs.rollup, rhs.rollup)
            .then_with(|| rhs.rollup.rss.cmp(&lhs.rollup.rss))
            .then_with(|| lhs.label.cmp(&rhs.label))
    });
    rows
}

fn derive_process_totals(process_tree: &ProcessTree) -> ProcessTotals {
    let mut totals = ProcessTotals::default();

    for node in &process_tree.nodes {
        let rollup = node.rollup();
        totals.pss += rollup.pss;
        totals.uss += rollup.uss();
        totals.rss += rollup.rss;
        totals.swap_pss += rollup.swap_pss;
        totals.pss_anon += rollup.pss_anon;
        totals.pss_file += rollup.pss_file;
        totals.pss_shmem += rollup.pss_shmem;
    }

    totals
}

fn unique_tmpfs_infos(mount_index: &MountIndex) -> Vec<MountInfo> {
    let mut infos = mount_index.tmpfs.iter().collect::<Vec<_>>();
    let mut seen_devices = BTreeSet::new();
    let mut unique = Vec::new();
    infos.sort_by_key(|info| info.mount_point.as_os_str().len());

    for info in infos {
        if !seen_devices.insert((info.device_major, info.device_minor)) {
            continue;
        }
        unique.push(info.clone());
    }

    unique
}

fn scan_tmpfs_mount(info: &MountInfo, coverage: &mut TmpfsCoverage) -> Result<TmpfsMount> {
    let root_meta = fs::symlink_metadata(&info.mount_point)?;
    let mut seen_storage = BTreeSet::<(u64, u64)>::new();
    let _ = seen_storage.insert((root_meta.dev(), root_meta.ino()));
    let mut nodes = vec![TmpfsBuilder {
        path: info.mount_point.clone(),
        name: info.mount_point.display().to_string(),
        kind: TmpfsNodeKind::Mount,
        allocated: metadata_allocated(&root_meta),
        logical: metadata_logical(&root_meta),
        parent: None,
        children: Vec::new(),
    }];
    let mut ancestors = vec![0usize];

    let mut walk = WalkDir::new(&info.mount_point)
        .same_file_system(true)
        .follow_links(false)
        .into_iter();
    while let Some(entry) = walk.next() {
        let entry = if let Ok(entry) = entry {
            entry
        } else {
            coverage.walk_errors += 1;
            walk.skip_current_dir();
            continue;
        };
        let path = entry.path();
        if path == info.mount_point {
            continue;
        }

        let metadata = if let Ok(metadata) = entry.metadata() {
            metadata
        } else {
            coverage.walk_errors += 1;
            walk.skip_current_dir();
            continue;
        };

        let first_storage_name = seen_storage.insert((metadata.dev(), metadata.ino()));
        let allocated = if first_storage_name {
            metadata_allocated(&metadata)
        } else {
            Bytes::ZERO
        };
        let logical = if first_storage_name {
            metadata_logical(&metadata)
        } else {
            Bytes::ZERO
        };
        let depth = entry.depth();
        let parent = ancestors.get(depth.saturating_sub(1)).copied().unwrap_or(0);
        let index = nodes.len();
        nodes[parent].children.push(index);
        nodes.push(TmpfsBuilder {
            path: path.to_path_buf(),
            name: basename(path),
            kind: classify_tmpfs_entry(&metadata),
            allocated,
            logical,
            parent: Some(parent),
            children: Vec::new(),
        });
        ancestors.truncate(depth);
        ancestors.push(index);
    }

    for index in (1..nodes.len()).rev() {
        let parent = nodes[index].parent.unwrap_or(0);
        let allocated = nodes[index].allocated;
        let logical = nodes[index].logical;
        nodes[parent].allocated += allocated;
        nodes[parent].logical += logical;
    }

    let mut nodes = nodes.into_iter().map(Some).collect::<Vec<_>>();
    let root = materialize_tmpfs_node(0, &mut nodes)?;
    Ok(TmpfsMount {
        mount_point: info.mount_point.clone(),
        source: info.source.clone(),
        size_limit: parse_tmpfs_size_limit(&info.super_options),
        root,
    })
}

fn materialize_tmpfs_node(index: usize, nodes: &mut [Option<TmpfsBuilder>]) -> Result<TmpfsNode> {
    let builder = nodes
        .get_mut(index)
        .and_then(Option::take)
        .ok_or_else(|| eyre!("tmpfs tree lost arena node {index}"))?;

    let mut children = builder
        .children
        .iter()
        .map(|child| materialize_tmpfs_node(*child, nodes))
        .collect::<Result<Vec<_>>>()?;
    children.sort_by(|lhs, rhs| {
        rhs.allocated
            .cmp(&lhs.allocated)
            .then_with(|| lhs.path.cmp(&rhs.path))
    });

    Ok(TmpfsNode {
        path: builder.path,
        name: builder.name,
        kind: builder.kind,
        allocated: builder.allocated,
        logical: builder.logical,
        children,
    })
}

fn basename(path: &Path) -> String {
    path.file_name()
        .unwrap_or_else(|| OsStr::new("/"))
        .to_string_lossy()
        .into_owned()
}

fn metadata_allocated(metadata: &Metadata) -> Bytes {
    Bytes::from_blocks_512(metadata.blocks())
}

fn metadata_logical(metadata: &Metadata) -> Bytes {
    Bytes(metadata.size())
}

fn classify_tmpfs_entry(metadata: &Metadata) -> TmpfsNodeKind {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        TmpfsNodeKind::Directory
    } else if file_type.is_file() {
        TmpfsNodeKind::File
    } else if file_type.is_symlink() {
        TmpfsNodeKind::Symlink
    } else if file_type.is_socket() {
        TmpfsNodeKind::Socket
    } else if file_type.is_fifo() {
        TmpfsNodeKind::Fifo
    } else if file_type.is_char_device() {
        TmpfsNodeKind::CharDevice
    } else if file_type.is_block_device() {
        TmpfsNodeKind::BlockDevice
    } else {
        TmpfsNodeKind::Other
    }
}

fn parse_tmpfs_size_limit(options: &str) -> Option<Bytes> {
    options
        .split(',')
        .find_map(|option| option.strip_prefix("size=").and_then(parse_size_option))
}

fn parse_size_option(value: &str) -> Option<Bytes> {
    let trimmed = value.trim();
    let digits = trimmed
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    let suffix = &trimmed[digits.len()..];
    let number = digits.parse::<u64>().ok()?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024_u64.pow(2),
        "g" | "gb" => 1024_u64.pow(3),
        "t" | "tb" => 1024_u64.pow(4),
        "p" | "pb" => 1024_u64.pow(5),
        _ => return None,
    };
    Some(Bytes::from_wide(
        u128::from(number) * u128::from(multiplier),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nvidia_pool_parameter_and_shrinker_identity() {
        let params = "Foo: 1\nEnableSystemMemoryPools: 529\nBar: 2\n";
        assert_eq!(nvidia_pool_mask(params).ok(), Some(529));
        assert!(nvidia_pool_mask("Foo: 1\n").is_err());
        assert_eq!(
            parse_nvidia_pool_name(OsStr::new("nv-sysmem-alloc-node-3-order-9-417")),
            Some((3, 9))
        );
        assert_eq!(parse_nvidia_pool_name(OsStr::new("dentry-12")), None);
    }

    #[test]
    fn converts_nvidia_shrinker_objects_by_numa_node_and_page_order() {
        let count = "0 11 13 17\n";
        assert_eq!(parse_shrinker_node_count(count, 1).ok(), Some(13));
        assert_eq!(nvidia_pool_bytes(13, 4096, 9).ok(), Some(13 << 21));
        assert!(parse_shrinker_node_count(count, 3).is_err());
    }

    #[test]
    fn enabled_nvidia_pool_probe_rejects_an_empty_shrinker_directory() {
        let root =
            std::env::temp_dir().join(format!("memview-empty-shrinkers-{}", std::process::id()));
        fs::create_dir(&root).expect("create isolated shrinker fixture");
        let result = read_nvidia_pool_snapshot(&root, 4096);
        fs::remove_dir(&root).expect("remove isolated shrinker fixture");
        assert!(result.is_err());
    }

    #[test]
    fn parses_process_identity_after_parenthesized_command() {
        let stat = "123 (worker ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242";
        assert_eq!(parse_process_start_time(stat), Some(4242));
        assert_eq!(parse_process_start_time("123 malformed"), None);
    }

    fn scanned_process(pid: i32, pss: u64) -> ProcessRecord {
        ProcessRecord {
            pid: Pid(pid),
            start_time_ticks: pid as u64,
            ppid: None,
            name: format!("p{pid}"),
            command: format!("p{pid} --serve"),
            cwd: None,
            username: "test".to_string(),
            state: "S".to_string(),
            threads: 1,
            memory: ProcessMemory::Smaps(MemoryRollup {
                pss: Bytes(pss),
                rss: Bytes(pss),
                ..MemoryRollup::default()
            }),
            mappings_state: LedgerState::Deferred,
        }
    }

    #[test]
    fn process_coverage_preserves_every_summary_process() {
        let processes = vec![
            scanned_process(1, 9_900),
            scanned_process(2, 50),
            scanned_process(3, 50),
        ];
        let mut coverage = ProcessCoverage {
            candidates: 3,
            ..ProcessCoverage::default()
        };
        finish_process_coverage(&processes, &mut coverage);
        assert_eq!(coverage.captured, 3);
        assert_eq!(coverage.exact_rollups, 3);
        assert_eq!(coverage.deferred_maps, 3);
    }

    #[test]
    fn parses_mountinfo() {
        let line = "839 811 0:34 / /tmp rw,nosuid,nodev master:17 - tmpfs tmpfs rw,size=65909960k";
        let parsed = parse_mountinfo_line(line).expect("mountinfo");
        assert_eq!(parsed.mount_point, PathBuf::from("/tmp"));
        assert_eq!((parsed.device_major, parsed.device_minor), (0, 34));
        assert_eq!(parsed.fs_type, "tmpfs");
        assert_eq!(parsed.source, "tmpfs");
    }

    #[test]
    fn parses_mapping_header() {
        let line = "7f1230000000-7f1230001000 rw-s 00000000 00:01 42 /memfd:cache shard (deleted)";
        let parsed = parse_mapping_header(line).expect("header");
        assert_eq!(parsed.size, Bytes(0x1000));
        assert_eq!(parsed.device_major, 0);
        assert_eq!(parsed.device_minor, 1);
        assert_eq!(parsed.inode, 42);
        assert!(parsed.path.contains("/memfd:cache shard"));
    }

    #[test]
    fn shared_backing_identity_ignores_aliasing_path_labels() {
        let key = ProcessKey {
            pid: Pid(7),
            start_time_ticks: 11,
        };
        let smaps = concat!(
            "1000-2000 rw-s 00000000 00:01 42 /first-name\n",
            "Pss: 1 kB\n",
            "2000-3000 rw-s 00001000 00:01 42 /second-name\n",
            "Pss: 2 kB\n",
            "3000-4000 rw-s 00000000 00:01 43 /first-name\n",
            "Pss: 3 kB\n",
        );
        let objects = parse_smaps(smaps, &MountIndex::default(), key);
        assert_eq!(objects.len(), 2);
        assert!(objects.iter().any(|object| {
            object.regions == 2
                && object.rollup.pss == Bytes::from_kib(3)
                && matches!(
                    object.backing,
                    BackingIdentity::DeviceInode { inode: 42, .. }
                )
        }));
    }

    #[test]
    fn inode_zero_backings_remain_process_local() {
        let smaps = "1000-2000 rw-p 00000000 00:00 0\nPss: 1 kB\n";
        let first = ProcessKey {
            pid: Pid(7),
            start_time_ticks: 11,
        };
        let second = ProcessKey {
            pid: Pid(8),
            start_time_ticks: 12,
        };
        let first = parse_smaps(smaps, &MountIndex::default(), first);
        let second = parse_smaps(smaps, &MountIndex::default(), second);
        assert_ne!(first[0].backing, second[0].backing);
    }

    #[test]
    fn parses_size_option_units() {
        assert_eq!(parse_size_option("64k"), Some(Bytes(64 * 1024)));
        assert_eq!(parse_size_option("2m"), Some(Bytes(2 * 1024 * 1024)));
        assert_eq!(parse_size_option("1g"), Some(Bytes(1024 * 1024 * 1024)));
    }

    #[test]
    fn converts_meminfo_hugepage_counts_to_bytes() {
        let parsed = parse_meminfo(
            "MemTotal: 1024 kB\nHugePages_Total: 3\nHugePages_Free: 2\nHugepagesize: 2048 kB\n",
        );
        assert_eq!(parsed.value("MemTotal"), Some(Bytes(1024 * 1024)));
        assert_eq!(
            parsed.value("HugePages_Total"),
            Some(Bytes(3 * 2048 * 1024))
        );
        assert_eq!(parsed.value("HugePages_Free"), Some(Bytes(2 * 2048 * 1024)));
    }
}
