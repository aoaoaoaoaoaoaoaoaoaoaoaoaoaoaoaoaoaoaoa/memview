use super::model::{
    Bytes, LedgerState, Meminfo, MeminfoEntry, MemoryRollup, Metric, ObjectConsumer, ObjectKind,
    ObjectUsage, Overview, Pid, ProcessCwd, ProcessNode, ProcessTree, ProcessTreeStats,
    SharedObject, Snapshot, SysvSegment, TmpfsMount, TmpfsNode, TmpfsNodeKind,
};
use color_eyre::eyre::{Context, Result, eyre};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use uzers::get_user_by_uid;
use walkdir::WalkDir;

const DELETED_MAPPING_SUFFIX: &str = " (deleted)";

pub struct Capture {
    started: Instant,
    meminfo: Meminfo,
    tmpfs_mounts: Vec<TmpfsMount>,
    sysv_segments: Vec<SysvSegment>,
    warnings: Vec<String>,
}

impl Capture {
    #[must_use]
    pub fn inventory_snapshot(&self) -> Snapshot {
        let process_tree = ProcessTree::default();
        let shared_objects = fold_shared_objects(&process_tree, &self.sysv_segments);
        let overview = derive_overview(&process_tree, &self.tmpfs_mounts, &self.sysv_segments);

        Snapshot {
            captured_at: SystemTime::now(),
            elapsed: self.started.elapsed(),
            meminfo: self.meminfo.clone(),
            overview,
            process_tree,
            shared_objects,
            sysv_segments: self.sysv_segments.clone(),
            tmpfs_mounts: self.tmpfs_mounts.clone(),
            warnings: self.warnings.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ProcessScan {
    pub captured_at: SystemTime,
    pub elapsed: Duration,
    pub meminfo: Meminfo,
    pub process_tree: ProcessTree,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct ProcessMappingScan {
    pub elapsed: Duration,
    pub cost: ProcessMappingCost,
    pub pid: Pid,
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

#[derive(Debug)]
pub struct SharedObjectsScan {
    pub captured_at: SystemTime,
    pub elapsed: Duration,
    pub meminfo: Meminfo,
    pub shared_objects: Vec<SharedObject>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct TmpfsMountScan {
    pub captured_at: SystemTime,
    pub elapsed: Duration,
    pub mount: TmpfsMount,
    pub warnings: Vec<String>,
}

impl ProcessScan {
    pub fn install(self, snapshot: &mut Snapshot) {
        snapshot.captured_at = self.captured_at;
        snapshot.elapsed = self.elapsed;
        snapshot.meminfo = self.meminfo;
        snapshot.process_tree = self.process_tree;
        rebuild_snapshot_derived(snapshot);
    }
}

pub fn capture_inventory_shell() -> Result<Capture> {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let meminfo = read_meminfo().wrap_err("failed to read /proc/meminfo")?;
    let _mount_index = MountIndex::read().wrap_err("failed to read /proc/self/mountinfo")?;
    let sysv_segments =
        read_sysv_segments(&mut warnings).wrap_err("failed to read /proc/sysvipc/shm")?;

    Ok(Capture {
        started,
        meminfo,
        tmpfs_mounts: Vec::new(),
        sysv_segments,
        warnings,
    })
}

pub fn capture_processes() -> Result<ProcessScan> {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let meminfo = read_meminfo().wrap_err("failed to read /proc/meminfo")?;
    let forest = scan_processes(&mut warnings).wrap_err("failed to scan /proc")?;
    Ok(ProcessScan {
        captured_at: SystemTime::now(),
        elapsed: started.elapsed(),
        meminfo,
        process_tree: build_process_tree(forest.processes, forest.stats),
        warnings,
    })
}

pub fn capture_process_mappings(pid: Pid) -> Result<ProcessMappingScan> {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let mount_started = Instant::now();
    let mount_index = MountIndex::read().wrap_err("failed to read /proc/self/mountinfo")?;
    let mount_index_elapsed = mount_started.elapsed();
    let root = PathBuf::from("/proc").join(pid.0.to_string());
    let read_started = Instant::now();
    let (objects, mappings_state, read_elapsed, parse_elapsed) =
        match fs::read_to_string(root.join("smaps")) {
            Ok(text) => {
                let read_elapsed = read_started.elapsed();
                let parse_started = Instant::now();
                let objects = parse_smaps(&text, &mount_index);
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

    Ok(ProcessMappingScan {
        elapsed: started.elapsed(),
        cost: ProcessMappingCost {
            mount_index: mount_index_elapsed,
            read: read_elapsed,
            parse: parse_elapsed,
        },
        pid,
        objects,
        mappings_state,
        warnings,
    })
}

pub fn capture_shared_objects() -> Result<SharedObjectsScan> {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let meminfo = read_meminfo().wrap_err("failed to read /proc/meminfo")?;
    let mount_index = MountIndex::read().wrap_err("failed to read /proc/self/mountinfo")?;
    let sysv_segments =
        read_sysv_segments(&mut warnings).wrap_err("failed to read /proc/sysvipc/shm")?;
    let mut processes = scan_process_shells(&mut warnings).wrap_err("failed to scan /proc")?;
    attach_all_mapping_ledgers(&mut processes, &mount_index);
    let stats = process_stats(&processes);
    let process_tree = build_process_tree(processes, stats);

    Ok(SharedObjectsScan {
        captured_at: SystemTime::now(),
        elapsed: started.elapsed(),
        meminfo,
        shared_objects: fold_shared_objects(&process_tree, &sysv_segments),
        warnings,
    })
}

pub fn tmpfs_mount_points() -> Result<Vec<PathBuf>> {
    let mut warnings = Vec::new();
    let mount_index = MountIndex::read().wrap_err("failed to read /proc/self/mountinfo")?;
    Ok(unique_tmpfs_infos(&mount_index, &mut warnings)
        .into_iter()
        .map(|info| info.mount_point)
        .collect())
}

pub fn capture_tmpfs_mount(path: &Path) -> Result<TmpfsMountScan> {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let mount_index = MountIndex::read().wrap_err("failed to read /proc/self/mountinfo")?;
    let info = mount_index
        .match_tmpfs_mount(path)
        .cloned()
        .ok_or_else(|| eyre!("no tmpfs mount contains {}", path.display()))?;
    let mount = scan_tmpfs_mount(&info).map_err(|error| {
        warnings.push(format!(
            "tmpfs scan skipped for {}: {error}",
            info.mount_point.display()
        ));
        error
    })?;

    Ok(TmpfsMountScan {
        captured_at: SystemTime::now(),
        elapsed: started.elapsed(),
        mount,
        warnings,
    })
}

pub fn rebuild_snapshot_derived(snapshot: &mut Snapshot) {
    snapshot.overview = derive_overview(
        &snapshot.process_tree,
        &snapshot.tmpfs_mounts,
        &snapshot.sysv_segments,
    );
}

#[derive(Clone, Debug)]
struct MountInfo {
    mount_point: PathBuf,
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
    own_allocated: Bytes,
    own_logical: Bytes,
    allocated: Bytes,
    logical: Bytes,
    children: Vec<PathBuf>,
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

    Some(MountInfo {
        mount_point: PathBuf::from(unescape_mount_field(left_fields[4])),
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
    let mut table = BTreeMap::new();

    for entry in raw {
        let value = meminfo_value(entry.key, entry.number, entry.unit, hugepage_size);
        entries.push(MeminfoEntry {
            key: entry.key.to_string(),
            value,
        });
        let _ = table.insert(entry.key.to_string(), value);
    }

    Meminfo { entries, table }
}

fn meminfo_value(key: &str, number: u64, unit: Option<&str>, hugepage_size: Bytes) -> Bytes {
    if key.starts_with("HugePages_") {
        return Bytes(number.saturating_mul(hugepage_size.0));
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

#[derive(Clone, Debug)]
struct ScannedProcess {
    pid: Pid,
    ppid: Option<Pid>,
    name: String,
    command: String,
    cwd: Option<ProcessCwd>,
    username: String,
    state: String,
    threads: u32,
    rollup: MemoryRollup,
    objects: Vec<ObjectUsage>,
    rollup_state: LedgerState,
    mappings_state: LedgerState,
}

fn scan_process_shells(warnings: &mut Vec<String>) -> Result<Vec<ScannedProcess>> {
    let mut processes = Vec::new();
    let mut usernames = BTreeMap::new();

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

        match scan_process_shell(Pid(pid), &mut usernames) {
            Ok(Some(process)) => processes.push(process),
            Ok(None) => {}
            Err(error) => warnings.push(format!("ignoring pid {pid}: {error}")),
        }
    }

    Ok(processes)
}

fn scan_processes(warnings: &mut Vec<String>) -> Result<ProcessForest> {
    let mut processes = scan_process_shells(warnings)?;
    let stats = process_stats(&processes);
    processes.sort_by_key(|process| process.pid);
    Ok(ProcessForest { processes, stats })
}

fn scan_process_shell(
    pid: Pid,
    usernames: &mut BTreeMap<u32, String>,
) -> Result<Option<ScannedProcess>> {
    let root = PathBuf::from("/proc").join(pid.0.to_string());
    let status_text = match fs::read_to_string(root.join("status")) {
        Ok(text) => text,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };

    let status = parse_status(&status_text);
    let command = read_cmdline(&root).unwrap_or_else(|| status.name.clone());
    let cwd = read_cwd(&root);
    let username = lookup_username(status.uid, usernames);
    let fallback_rollup = MemoryRollup {
        rss: status.vm_rss,
        pss: status.vm_rss,
        anonymous: status.rss_anon,
        pss_anon: status.rss_anon,
        pss_file: status.rss_file,
        pss_shmem: status.rss_shmem,
        swap: status.vm_swap,
        ..MemoryRollup::default()
    };
    let (rollup, rollup_state) = match fs::read_to_string(root.join("smaps_rollup")) {
        Ok(text) => (parse_rollup_kv(&text), LedgerState::Exact),
        Err(_) => (fallback_rollup, LedgerState::Approximate),
    };

    Ok(Some(ScannedProcess {
        pid,
        ppid: status.ppid,
        name: status.name,
        command,
        cwd,
        username,
        state: status.state,
        threads: status.threads,
        rollup,
        objects: Vec::new(),
        rollup_state,
        mappings_state: LedgerState::Deferred,
    }))
}

#[derive(Clone, Debug)]
struct ProcessForest {
    processes: Vec<ScannedProcess>,
    stats: ProcessTreeStats,
}

fn process_stats(processes: &[ScannedProcess]) -> ProcessTreeStats {
    ProcessTreeStats {
        observed_processes: processes.len(),
        inaccessible_rollups: processes
            .iter()
            .filter(|process| process.rollup_state.is_inaccessible())
            .count(),
        inaccessible_maps: processes
            .iter()
            .filter(|process| process.mappings_state.is_inaccessible())
            .count(),
    }
}

fn attach_all_mapping_ledgers(processes: &mut [ScannedProcess], mount_index: &MountIndex) {
    for process in processes.iter_mut() {
        if process.rollup.rss == Bytes::ZERO && process.rollup.pss == Bytes::ZERO {
            continue;
        }
        match fs::read_to_string(
            PathBuf::from("/proc")
                .join(process.pid.0.to_string())
                .join("smaps"),
        ) {
            Ok(text) => {
                process.objects = parse_smaps(&text, mount_index);
                process.mappings_state = LedgerState::Exact;
            }
            Err(_) => process.mappings_state = LedgerState::Inaccessible,
        }
    }
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
        apply_rollup_field(&mut rollup, key, value);
    }

    rollup
}

fn parse_kib_value(line: &str) -> Option<(&str, Bytes)> {
    let (key, rest) = line.split_once(':')?;
    let value = rest.split_whitespace().next()?.parse::<u64>().ok()?;
    Some((key.trim(), Bytes::from_kib(value)))
}

fn apply_rollup_field(rollup: &mut MemoryRollup, key: &str, value: Bytes) {
    match key {
        "Size" => rollup.size = value,
        "Rss" => rollup.rss = value,
        "Pss" => rollup.pss = value,
        "Pss_Dirty" => rollup.pss_dirty = value,
        "Pss_Anon" => rollup.pss_anon = value,
        "Pss_File" => rollup.pss_file = value,
        "Pss_Shmem" => rollup.pss_shmem = value,
        "Shared_Clean" => rollup.shared_clean = value,
        "Shared_Dirty" => rollup.shared_dirty = value,
        "Private_Clean" => rollup.private_clean = value,
        "Private_Dirty" => rollup.private_dirty = value,
        "Referenced" => rollup.referenced = value,
        "Anonymous" => rollup.anonymous = value,
        "LazyFree" => rollup.lazy_free = value,
        "AnonHugePages" => rollup.anon_huge_pages = value,
        "ShmemPmdMapped" => rollup.shmem_pmd_mapped = value,
        "FilePmdMapped" => rollup.file_pmd_mapped = value,
        "Shared_Hugetlb" => rollup.shared_hugetlb = value,
        "Private_Hugetlb" => rollup.private_hugetlb = value,
        "Swap" => rollup.swap = value,
        "SwapPss" => rollup.swap_pss = value,
        "Locked" => rollup.locked = value,
        _ => {}
    }
}

fn parse_smaps(text: &str, mount_index: &MountIndex) -> Vec<ObjectUsage> {
    let mut objects = BTreeMap::<(ObjectKind, String), ObjectUsage>::new();
    let mut current = None::<MappingAccumulator>;

    for line in text.lines() {
        if let Some(header) = parse_mapping_header(line) {
            flush_mapping(&mut current, &mut objects);
            current = Some(MappingAccumulator::new(
                classify_mapping(&header.path, mount_index),
                header.size,
            ));
            continue;
        }

        if let Some((key, value)) = parse_kib_value(line)
            && let Some(mapping) = current.as_mut()
        {
            apply_rollup_field(&mut mapping.rollup, key, value);
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
    objects: &mut BTreeMap<(ObjectKind, String), ObjectUsage>,
) {
    let Some(mapping) = current.take() else {
        return;
    };

    let key = (mapping.kind, mapping.label.clone());
    let entry = objects.entry(key).or_insert_with(|| ObjectUsage {
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
    kind: ObjectKind,
    label: String,
    rollup: MemoryRollup,
}

impl MappingAccumulator {
    fn new(classified: ClassifiedMapping, size: Bytes) -> Self {
        Self {
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
    size: Bytes,
    path: String,
}

fn parse_mapping_header(line: &str) -> Option<MappingHeader> {
    let mut cursor = 0usize;
    let range = take_field(line, &mut cursor)?;
    let _perms = take_field(line, &mut cursor)?;
    let _offset = take_field(line, &mut cursor)?;
    let _dev = take_field(line, &mut cursor)?;
    let _inode = take_field(line, &mut cursor)?;
    let path = line[cursor..].trim().to_string();

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;

    Some(MappingHeader {
        size: Bytes(end.saturating_sub(start)),
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

fn build_process_tree(processes: Vec<ScannedProcess>, stats: ProcessTreeStats) -> ProcessTree {
    let mut nodes = processes
        .into_iter()
        .map(|process| ProcessNode {
            pid: process.pid,
            ppid: process.ppid,
            name: process.name,
            command: process.command,
            cwd: process.cwd,
            username: process.username,
            state: process.state,
            threads: process.threads,
            rollup: process.rollup,
            subtree: process.rollup,
            children: Vec::new(),
            objects: process.objects,
            rollup_state: process.rollup_state,
            mappings_state: process.mappings_state,
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
        stats,
    }
}

fn accumulate_subtree(index: usize, nodes: &mut [ProcessNode]) -> MemoryRollup {
    let children = nodes[index].children.clone();
    let mut subtotal = nodes[index].rollup;
    for child in children {
        subtotal += accumulate_subtree(child, nodes);
    }
    nodes[index].subtree = subtotal;
    subtotal
}

fn fold_shared_objects(
    process_tree: &ProcessTree,
    sysv_segments: &[SysvSegment],
) -> Vec<SharedObject> {
    struct Accumulator {
        kind: ObjectKind,
        label: String,
        rollup: MemoryRollup,
        regions: usize,
        consumers: Vec<ObjectConsumer>,
    }

    let mut objects = BTreeMap::<(ObjectKind, String), Accumulator>::new();

    for node in &process_tree.nodes {
        for object in &node.objects {
            let entry = objects
                .entry((object.kind, object.label.clone()))
                .or_insert_with(|| Accumulator {
                    kind: object.kind,
                    label: object.label.clone(),
                    rollup: MemoryRollup::default(),
                    regions: 0,
                    consumers: Vec::new(),
                });
            entry.rollup += object.rollup;
            entry.regions += object.regions;
            entry.consumers.push(ObjectConsumer {
                pid: node.pid,
                name: node.name.clone(),
                command: node.command.clone(),
                rollup: object.rollup,
            });
        }
    }

    let mut rows = objects
        .into_values()
        .map(|mut acc| {
            acc.consumers.sort_by(|lhs, rhs| {
                Metric::Pss
                    .cmp_rollup(lhs.rollup, rhs.rollup)
                    .then_with(|| lhs.pid.cmp(&rhs.pid))
            });
            SharedObject {
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

fn derive_overview(
    process_tree: &ProcessTree,
    tmpfs_mounts: &[TmpfsMount],
    sysv_segments: &[SysvSegment],
) -> Overview {
    let mut overview = Overview {
        process_count: process_tree.stats.observed_processes,
        inaccessible_rollups: process_tree.stats.inaccessible_rollups,
        inaccessible_maps: process_tree.stats.inaccessible_maps,
        ..Overview::default()
    };

    for node in &process_tree.nodes {
        overview.process_pss_total += node.rollup.pss;
        overview.process_uss_total += node.rollup.uss();
        overview.process_rss_total += node.rollup.rss;
        overview.process_swap_pss_total += node.rollup.swap_pss;
        overview.process_pss_anon_total += node.rollup.pss_anon;
        overview.process_pss_file_total += node.rollup.pss_file;
        overview.process_pss_shmem_total += node.rollup.pss_shmem;
    }

    for mount in tmpfs_mounts {
        overview.tmpfs_allocated_total += mount.root.allocated;
    }
    for segment in sysv_segments {
        overview.sysv_rss_total += segment.rss;
    }

    overview
}

fn unique_tmpfs_infos(mount_index: &MountIndex, warnings: &mut Vec<String>) -> Vec<MountInfo> {
    let mut infos = mount_index.tmpfs.iter().collect::<Vec<_>>();
    let mut seen_devices = BTreeSet::new();
    let mut unique = Vec::new();
    infos.sort_by_key(|info| info.mount_point.as_os_str().len());

    for info in infos {
        match fs::symlink_metadata(&info.mount_point) {
            Ok(metadata) if seen_devices.insert(metadata.dev()) => {}
            Ok(_) => continue,
            Err(error) => {
                warnings.push(format!(
                    "tmpfs scan skipped for {}: {error}",
                    info.mount_point.display()
                ));
                continue;
            }
        }

        unique.push(info.clone());
    }

    unique
}

fn scan_tmpfs_mount(info: &MountInfo) -> Result<TmpfsMount> {
    let root_meta = fs::symlink_metadata(&info.mount_point)?;
    let mut seen_storage = BTreeSet::<(u64, u64)>::new();
    let _ = seen_storage.insert((root_meta.dev(), root_meta.ino()));
    let mut nodes = BTreeMap::<PathBuf, TmpfsBuilder>::new();
    let _ = nodes.insert(
        info.mount_point.clone(),
        TmpfsBuilder {
            path: info.mount_point.clone(),
            name: info.mount_point.display().to_string(),
            kind: TmpfsNodeKind::Mount,
            own_allocated: metadata_allocated(&root_meta),
            own_logical: metadata_logical(&root_meta),
            allocated: Bytes::ZERO,
            logical: Bytes::ZERO,
            children: Vec::new(),
        },
    );

    for entry in WalkDir::new(&info.mount_point)
        .same_file_system(true)
        .follow_links(false)
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if path == info.mount_point {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        let path_buf = path.to_path_buf();
        let first_storage_name = seen_storage.insert((metadata.dev(), metadata.ino()));
        let own_allocated = if first_storage_name {
            metadata_allocated(&metadata)
        } else {
            Bytes::ZERO
        };
        let own_logical = if first_storage_name {
            metadata_logical(&metadata)
        } else {
            Bytes::ZERO
        };
        let parent = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| info.mount_point.clone());
        nodes
            .entry(parent.clone())
            .or_insert_with(|| TmpfsBuilder {
                path: parent.clone(),
                name: basename(&parent),
                kind: TmpfsNodeKind::Directory,
                own_allocated: Bytes::ZERO,
                own_logical: Bytes::ZERO,
                allocated: Bytes::ZERO,
                logical: Bytes::ZERO,
                children: Vec::new(),
            })
            .children
            .push(path_buf.clone());

        let _ = nodes.insert(
            path_buf.clone(),
            TmpfsBuilder {
                path: path_buf,
                name: basename(path),
                kind: classify_tmpfs_entry(&metadata),
                own_allocated,
                own_logical,
                allocated: Bytes::ZERO,
                logical: Bytes::ZERO,
                children: Vec::new(),
            },
        );
    }

    let mut ordered = nodes.keys().cloned().collect::<Vec<_>>();
    ordered.sort_by_key(|path| Reverse(path.components().count()));
    for path in ordered {
        let Some(node) = nodes.get_mut(&path) else {
            continue;
        };
        node.allocated += node.own_allocated;
        node.logical += node.own_logical;
        let allocated = node.allocated;
        let logical = node.logical;
        let parent = path.parent().map(Path::to_path_buf);
        if let Some(parent) = parent.and_then(|parent| nodes.get_mut(&parent)) {
            parent.allocated += allocated;
            parent.logical += logical;
        }
    }

    let root = materialize_tmpfs_node(&info.mount_point, &mut nodes);
    Ok(TmpfsMount {
        mount_point: info.mount_point.clone(),
        source: info.source.clone(),
        size_limit: parse_tmpfs_size_limit(&info.super_options),
        root,
    })
}

fn materialize_tmpfs_node(path: &Path, nodes: &mut BTreeMap<PathBuf, TmpfsBuilder>) -> TmpfsNode {
    let builder = nodes.remove(path).unwrap_or_else(|| TmpfsBuilder {
        path: path.to_path_buf(),
        name: basename(path),
        kind: TmpfsNodeKind::Other,
        own_allocated: Bytes::ZERO,
        own_logical: Bytes::ZERO,
        allocated: Bytes::ZERO,
        logical: Bytes::ZERO,
        children: Vec::new(),
    });

    let mut children = builder
        .children
        .iter()
        .map(|child| materialize_tmpfs_node(child, nodes))
        .collect::<Vec<_>>();
    children.sort_by(|lhs, rhs| {
        rhs.allocated
            .cmp(&lhs.allocated)
            .then_with(|| lhs.path.cmp(&rhs.path))
    });

    TmpfsNode {
        path: builder.path,
        name: builder.name,
        kind: builder.kind,
        allocated: builder.allocated,
        logical: builder.logical,
        children,
    }
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
    Some(Bytes(number.saturating_mul(multiplier)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanned_process(pid: i32, pss: u64) -> ScannedProcess {
        ScannedProcess {
            pid: Pid(pid),
            ppid: None,
            name: format!("p{pid}"),
            command: format!("p{pid} --serve"),
            cwd: None,
            username: "test".to_string(),
            state: "S".to_string(),
            threads: 1,
            rollup: MemoryRollup {
                pss: Bytes(pss),
                rss: Bytes(pss),
                ..MemoryRollup::default()
            },
            objects: Vec::new(),
            rollup_state: LedgerState::Exact,
            mappings_state: LedgerState::Deferred,
        }
    }

    #[test]
    fn process_stats_preserve_every_summary_process() {
        let processes = vec![
            scanned_process(1, 9_900),
            scanned_process(2, 50),
            scanned_process(3, 50),
        ];
        let stats = process_stats(&processes);
        assert_eq!(stats.observed_processes, 3);
        assert_eq!(stats.inaccessible_rollups, 0);
        assert_eq!(stats.inaccessible_maps, 0);
    }

    #[test]
    fn parses_mountinfo() {
        let line = "839 811 0:34 / /tmp rw,nosuid,nodev master:17 - tmpfs tmpfs rw,size=65909960k";
        let parsed = parse_mountinfo_line(line).expect("mountinfo");
        assert_eq!(parsed.mount_point, PathBuf::from("/tmp"));
        assert_eq!(parsed.fs_type, "tmpfs");
        assert_eq!(parsed.source, "tmpfs");
    }

    #[test]
    fn parses_mapping_header() {
        let line = "7f1230000000-7f1230001000 rw-s 00000000 00:01 42 /memfd:cache shard (deleted)";
        let parsed = parse_mapping_header(line).expect("header");
        assert_eq!(parsed.size, Bytes(0x1000));
        assert!(parsed.path.contains("/memfd:cache shard"));
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
        assert_eq!(parsed.get("MemTotal"), Bytes(1024 * 1024));
        assert_eq!(parsed.get("HugePages_Total"), Bytes(3 * 2048 * 1024));
        assert_eq!(parsed.get("HugePages_Free"), Bytes(2 * 2048 * 1024));
    }
}
