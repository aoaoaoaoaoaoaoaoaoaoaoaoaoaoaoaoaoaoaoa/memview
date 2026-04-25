use crate::model::{Pid, Snapshot};
use crate::probe;
use color_eyre::eyre::Result;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

const MIN_WORKER_REFRESH: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub enum WorkerCommand {
    RefreshInventory,
    RefreshProcesses,
    RefreshProcessMappings(Pid),
    RefreshSharedObjects,
    RefreshTmpfsMounts,
    RefreshTmpfsMount(PathBuf),
    SetProcessScanning(bool),
    Shutdown,
}

#[derive(Debug)]
pub enum WorkerEvent {
    InventoryReady(Result<Box<Snapshot>>),
    TmpfsMountReady(Result<Box<probe::TmpfsMountScan>>),
    ProcessesStarted(Instant),
    ProcessesReady(Result<Box<probe::ProcessScan>>),
    ProcessMappingsReady(Result<Box<probe::ProcessMappingScan>>),
    SharedObjectsStarted(Instant),
    SharedObjectsReady(Result<Box<probe::SharedObjectsScan>>),
}

pub fn spawn_worker(refresh_every: Duration) -> (Sender<WorkerCommand>, Receiver<WorkerEvent>) {
    let refresh_every = refresh_every.max(MIN_WORKER_REFRESH);
    let (command_tx, command_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();
    let (inventory_tx, inventory_rx) = mpsc::channel();
    let (process_tx, process_rx) = mpsc::channel();

    spawn_inventory_worker(inventory_rx, event_tx.clone());
    spawn_process_worker(refresh_every, process_rx, event_tx);

    let _handle = thread::spawn(move || {
        while let Ok(command) = command_rx.recv() {
            match command {
                WorkerCommand::RefreshInventory
                | WorkerCommand::RefreshTmpfsMounts
                | WorkerCommand::RefreshTmpfsMount(_) => {
                    let _ = inventory_tx.send(command);
                }
                WorkerCommand::RefreshProcesses
                | WorkerCommand::RefreshProcessMappings(_)
                | WorkerCommand::RefreshSharedObjects
                | WorkerCommand::SetProcessScanning(_) => {
                    let _ = process_tx.send(command);
                }
                WorkerCommand::Shutdown => {
                    let _ = inventory_tx.send(WorkerCommand::Shutdown);
                    let _ = process_tx.send(WorkerCommand::Shutdown);
                    break;
                }
            }
        }
    });

    (command_tx, event_rx)
}

fn spawn_inventory_worker(command_rx: Receiver<WorkerCommand>, event_tx: Sender<WorkerEvent>) {
    let _handle = thread::spawn(move || {
        loop {
            match command_rx.recv() {
                Ok(WorkerCommand::RefreshInventory) => {
                    if !publish_inventory_shell(&event_tx) || !publish_all_tmpfs_mounts(&event_tx) {
                        break;
                    }
                }
                Ok(WorkerCommand::RefreshTmpfsMounts) => {
                    if !publish_all_tmpfs_mounts(&event_tx) {
                        break;
                    }
                }
                Ok(WorkerCommand::RefreshTmpfsMount(path)) => {
                    if !publish_tmpfs_mount(&event_tx, &path) {
                        break;
                    }
                }
                Ok(
                    WorkerCommand::RefreshProcesses
                    | WorkerCommand::RefreshProcessMappings(_)
                    | WorkerCommand::RefreshSharedObjects
                    | WorkerCommand::SetProcessScanning(_),
                ) => {}
                Ok(WorkerCommand::Shutdown) | Err(_) => break,
            }
        }
    });
}

#[derive(Clone, Copy, Debug)]
enum ProcessWorkerFlow {
    Continue,
    Shutdown,
}

fn collect_process_command(
    command: WorkerCommand,
    active: &mut bool,
    scan_once: &mut bool,
    mapping_request: &mut Option<Pid>,
    shared_request: &mut bool,
) -> ProcessWorkerFlow {
    match command {
        WorkerCommand::SetProcessScanning(next) => *active = next,
        WorkerCommand::RefreshProcesses => *scan_once = true,
        WorkerCommand::RefreshProcessMappings(pid) => *mapping_request = Some(pid),
        WorkerCommand::RefreshSharedObjects => *shared_request = true,
        WorkerCommand::RefreshInventory
        | WorkerCommand::RefreshTmpfsMounts
        | WorkerCommand::RefreshTmpfsMount(_) => {}
        WorkerCommand::Shutdown => return ProcessWorkerFlow::Shutdown,
    }
    ProcessWorkerFlow::Continue
}

fn drain_process_commands(
    command_rx: &Receiver<WorkerCommand>,
    active: &mut bool,
    scan_once: &mut bool,
    mapping_request: &mut Option<Pid>,
    shared_request: &mut bool,
) -> ProcessWorkerFlow {
    while let Ok(command) = command_rx.try_recv() {
        if matches!(
            collect_process_command(command, active, scan_once, mapping_request, shared_request),
            ProcessWorkerFlow::Shutdown
        ) {
            return ProcessWorkerFlow::Shutdown;
        }
    }
    ProcessWorkerFlow::Continue
}

fn publish_process_mappings(event_tx: &Sender<WorkerEvent>, pid: Pid) -> ProcessWorkerFlow {
    if event_tx
        .send(WorkerEvent::ProcessMappingsReady(
            probe::capture_process_mappings(pid).map(Box::new),
        ))
        .is_err()
    {
        ProcessWorkerFlow::Shutdown
    } else {
        ProcessWorkerFlow::Continue
    }
}

fn publish_shared_objects(event_tx: &Sender<WorkerEvent>) -> ProcessWorkerFlow {
    if event_tx
        .send(WorkerEvent::SharedObjectsStarted(Instant::now()))
        .is_err()
    {
        return ProcessWorkerFlow::Shutdown;
    }
    if event_tx
        .send(WorkerEvent::SharedObjectsReady(
            probe::capture_shared_objects().map(Box::new),
        ))
        .is_err()
    {
        ProcessWorkerFlow::Shutdown
    } else {
        ProcessWorkerFlow::Continue
    }
}

fn publish_processes(event_tx: &Sender<WorkerEvent>) -> ProcessWorkerFlow {
    if event_tx
        .send(WorkerEvent::ProcessesStarted(Instant::now()))
        .is_err()
    {
        return ProcessWorkerFlow::Shutdown;
    }
    if event_tx
        .send(WorkerEvent::ProcessesReady(
            probe::capture_processes().map(Box::new),
        ))
        .is_err()
    {
        ProcessWorkerFlow::Shutdown
    } else {
        ProcessWorkerFlow::Continue
    }
}

fn wait_process_command(
    command_rx: &Receiver<WorkerCommand>,
    refresh_every: Duration,
    active: &mut bool,
    scan_once: &mut bool,
    mapping_request: &mut Option<Pid>,
    shared_request: &mut bool,
) -> ProcessWorkerFlow {
    match command_rx.recv_timeout(refresh_every) {
        Ok(command) => {
            collect_process_command(command, active, scan_once, mapping_request, shared_request)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => ProcessWorkerFlow::Continue,
        Err(mpsc::RecvTimeoutError::Disconnected) => ProcessWorkerFlow::Shutdown,
    }
}

fn publish_inventory_shell(event_tx: &Sender<WorkerEvent>) -> bool {
    event_tx
        .send(WorkerEvent::InventoryReady(
            probe::capture_inventory_shell().map(|capture| Box::new(capture.inventory_snapshot())),
        ))
        .is_ok()
}

fn publish_all_tmpfs_mounts(event_tx: &Sender<WorkerEvent>) -> bool {
    let paths = match probe::tmpfs_mount_points() {
        Ok(paths) => paths,
        Err(error) => {
            return event_tx
                .send(WorkerEvent::TmpfsMountReady(Err(error)))
                .is_ok();
        }
    };

    paths
        .into_iter()
        .all(|path| publish_tmpfs_mount(event_tx, &path))
}

fn publish_tmpfs_mount(event_tx: &Sender<WorkerEvent>, path: &Path) -> bool {
    event_tx
        .send(WorkerEvent::TmpfsMountReady(
            probe::capture_tmpfs_mount(path).map(Box::new),
        ))
        .is_ok()
}

fn spawn_process_worker(
    refresh_every: Duration,
    command_rx: Receiver<WorkerCommand>,
    event_tx: Sender<WorkerEvent>,
) {
    let _handle = thread::spawn(move || {
        let mut active = false;
        let mut scan_once = false;
        let mut mapping_request = None;
        let mut shared_request = false;

        loop {
            if !active && !scan_once && mapping_request.is_none() && !shared_request {
                match command_rx.recv() {
                    Ok(command) => {
                        if matches!(
                            collect_process_command(
                                command,
                                &mut active,
                                &mut scan_once,
                                &mut mapping_request,
                                &mut shared_request,
                            ),
                            ProcessWorkerFlow::Shutdown
                        ) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            if matches!(
                drain_process_commands(
                    &command_rx,
                    &mut active,
                    &mut scan_once,
                    &mut mapping_request,
                    &mut shared_request,
                ),
                ProcessWorkerFlow::Shutdown
            ) {
                break;
            }

            if let Some(pid) = mapping_request.take() {
                if matches!(
                    publish_process_mappings(&event_tx, pid),
                    ProcessWorkerFlow::Shutdown
                ) {
                    break;
                }
                if active
                    && !scan_once
                    && matches!(
                        wait_process_command(
                            &command_rx,
                            refresh_every,
                            &mut active,
                            &mut scan_once,
                            &mut mapping_request,
                            &mut shared_request,
                        ),
                        ProcessWorkerFlow::Shutdown
                    )
                {
                    break;
                }
                continue;
            }

            if shared_request {
                shared_request = false;
                if matches!(
                    publish_shared_objects(&event_tx),
                    ProcessWorkerFlow::Shutdown
                ) {
                    break;
                }
                if active
                    && !scan_once
                    && matches!(
                        wait_process_command(
                            &command_rx,
                            refresh_every,
                            &mut active,
                            &mut scan_once,
                            &mut mapping_request,
                            &mut shared_request,
                        ),
                        ProcessWorkerFlow::Shutdown
                    )
                {
                    break;
                }
                continue;
            }

            if !active && !scan_once {
                continue;
            }
            scan_once = false;

            if matches!(publish_processes(&event_tx), ProcessWorkerFlow::Shutdown) {
                break;
            }

            if active
                && matches!(
                    wait_process_command(
                        &command_rx,
                        refresh_every,
                        &mut active,
                        &mut scan_once,
                        &mut mapping_request,
                        &mut shared_request,
                    ),
                    ProcessWorkerFlow::Shutdown
                )
            {
                break;
            }
        }
    });
}
