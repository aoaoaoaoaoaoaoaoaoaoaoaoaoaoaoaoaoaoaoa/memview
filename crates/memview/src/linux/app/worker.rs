use super::super::model::{Inventory, Ledger, ProcessKey, Processes, Shared, TmpfsMount};
use super::super::probe;
use color_eyre::eyre::Result;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

const MIN_WORKER_REFRESH: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
enum InventoryRequest {
    Refresh,
    RefreshTmpfs,
    RefreshTmpfsMount(PathBuf),
    Shutdown,
}

#[derive(Clone, Debug)]
pub enum ProcessRequest {
    Refresh,
    RefreshMappings(ProcessKey),
    RefreshShared,
    SetScanning(bool),
    Shutdown,
}

#[derive(Clone, Debug)]
pub struct WorkerPort {
    inventory: Sender<InventoryRequest>,
    processes: Sender<ProcessRequest>,
}

impl WorkerPort {
    pub fn refresh_inventory(&self) {
        let _ = self.inventory.send(InventoryRequest::Refresh);
    }

    pub fn refresh_processes(&self) {
        let _ = self.processes.send(ProcessRequest::Refresh);
    }

    pub fn refresh_process_mappings(&self, key: ProcessKey) {
        let _ = self.processes.send(ProcessRequest::RefreshMappings(key));
    }

    pub fn refresh_shared(&self) {
        let _ = self.processes.send(ProcessRequest::RefreshShared);
    }

    pub fn refresh_tmpfs(&self) {
        let _ = self.inventory.send(InventoryRequest::RefreshTmpfs);
    }

    pub fn refresh_tmpfs_mount(&self, path: PathBuf) {
        let _ = self
            .inventory
            .send(InventoryRequest::RefreshTmpfsMount(path));
    }

    pub fn set_process_scanning(&self, active: bool) {
        let _ = self.processes.send(ProcessRequest::SetScanning(active));
    }

    pub fn shutdown(&self) {
        let _ = self.inventory.send(InventoryRequest::Shutdown);
        let _ = self.processes.send(ProcessRequest::Shutdown);
    }

    #[cfg(test)]
    pub fn process_harness(processes: Sender<ProcessRequest>) -> Self {
        let (inventory, _requests) = mpsc::channel();
        Self {
            inventory,
            processes,
        }
    }
}

#[derive(Debug)]
pub enum WorkerEvent {
    InventoryReady(Result<Box<Ledger<Inventory>>>),
    TmpfsMountReady(Result<Box<Ledger<TmpfsMount>>>),
    ProcessesStarted(Instant),
    ProcessesReady(Result<Box<Ledger<Processes>>>),
    ProcessMappingsReady(ProcessKey, Result<Box<probe::ProcessMappingScan>>),
    SharedObjectsStarted(Instant),
    SharedObjectsReady(Result<Box<Ledger<Shared>>>),
}

pub fn spawn_worker(refresh_every: Duration) -> (WorkerPort, Receiver<WorkerEvent>) {
    let (inventory_tx, inventory_rx) = mpsc::channel();
    let (process_tx, process_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    spawn_inventory_worker(inventory_rx, event_tx.clone());
    spawn_process_worker(refresh_every.max(MIN_WORKER_REFRESH), process_rx, event_tx);

    (
        WorkerPort {
            inventory: inventory_tx,
            processes: process_tx,
        },
        event_rx,
    )
}

fn spawn_inventory_worker(command_rx: Receiver<InventoryRequest>, event_tx: Sender<WorkerEvent>) {
    let _handle = thread::spawn(move || {
        while let Ok(command) = command_rx.recv() {
            let live = match command {
                InventoryRequest::Refresh => {
                    publish_inventory(&event_tx) && publish_all_tmpfs_mounts(&event_tx)
                }
                InventoryRequest::RefreshTmpfs => publish_all_tmpfs_mounts(&event_tx),
                InventoryRequest::RefreshTmpfsMount(path) => publish_tmpfs_mount(&event_tx, &path),
                InventoryRequest::Shutdown => break,
            };
            if !live {
                break;
            }
        }
    });
}

#[derive(Clone, Copy, Debug)]
enum ProcessJob {
    Mappings(ProcessKey),
    Shared,
    Processes,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Cadence {
    #[default]
    Paused,
    Scanning,
}

impl Cadence {
    fn active(self) -> bool {
        self == Self::Scanning
    }
}

#[derive(Clone, Copy, Debug, Default)]
enum DemandFlag {
    #[default]
    Idle,
    Pending,
}

impl DemandFlag {
    fn raise(&mut self) {
        *self = Self::Pending;
    }

    fn take(&mut self) -> bool {
        matches!(std::mem::take(self), Self::Pending)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum WorkerLife {
    #[default]
    Running,
    Shutdown,
}

#[derive(Debug, Default)]
struct ProcessDemand {
    cadence: Cadence,
    summary: DemandFlag,
    mappings: Option<ProcessKey>,
    shared: DemandFlag,
    life: WorkerLife,
}

impl ProcessDemand {
    fn absorb(&mut self, request: ProcessRequest) {
        match request {
            ProcessRequest::Refresh => self.summary.raise(),
            ProcessRequest::RefreshMappings(pid) => self.mappings = Some(pid),
            ProcessRequest::RefreshShared => self.shared.raise(),
            ProcessRequest::SetScanning(active) => {
                if active && !self.cadence.active() {
                    self.summary.raise();
                }
                self.cadence = if active {
                    Cadence::Scanning
                } else {
                    Cadence::Paused
                };
            }
            ProcessRequest::Shutdown => self.life = WorkerLife::Shutdown,
        }
    }

    fn pop(&mut self) -> Option<ProcessJob> {
        if let Some(pid) = self.mappings.take() {
            Some(ProcessJob::Mappings(pid))
        } else if self.shared.take() {
            Some(ProcessJob::Shared)
        } else if self.summary.take() {
            Some(ProcessJob::Processes)
        } else {
            None
        }
    }
}

fn absorb_wait(
    demand: &mut ProcessDemand,
    command_rx: &Receiver<ProcessRequest>,
    deadline: Option<Instant>,
) {
    let request = match deadline {
        None => {
            if let Ok(request) = command_rx.recv() {
                Some(request)
            } else {
                demand.life = WorkerLife::Shutdown;
                None
            }
        }
        Some(deadline) => {
            match command_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(request) => Some(request),
                Err(RecvTimeoutError::Timeout) => {
                    demand.summary.raise();
                    None
                }
                Err(RecvTimeoutError::Disconnected) => {
                    demand.life = WorkerLife::Shutdown;
                    None
                }
            }
        }
    };
    if let Some(request) = request {
        demand.absorb(request);
        while let Ok(request) = command_rx.try_recv() {
            demand.absorb(request);
        }
    }
}

fn publish_process_job(event_tx: &Sender<WorkerEvent>, job: ProcessJob) -> bool {
    match job {
        ProcessJob::Mappings(key) => event_tx
            .send(WorkerEvent::ProcessMappingsReady(
                key,
                probe::capture_process_mappings(key).map(Box::new),
            ))
            .is_ok(),
        ProcessJob::Shared => {
            event_tx
                .send(WorkerEvent::SharedObjectsStarted(Instant::now()))
                .is_ok()
                && event_tx
                    .send(WorkerEvent::SharedObjectsReady(
                        probe::capture_shared_objects().map(Box::new),
                    ))
                    .is_ok()
        }
        ProcessJob::Processes => {
            event_tx
                .send(WorkerEvent::ProcessesStarted(Instant::now()))
                .is_ok()
                && event_tx
                    .send(WorkerEvent::ProcessesReady(
                        probe::capture_processes().map(Box::new),
                    ))
                    .is_ok()
        }
    }
}

fn spawn_process_worker(
    refresh_every: Duration,
    command_rx: Receiver<ProcessRequest>,
    event_tx: Sender<WorkerEvent>,
) {
    let _handle = thread::spawn(move || {
        let mut demand = ProcessDemand::default();
        let mut deadline = None;

        loop {
            if demand.life == WorkerLife::Shutdown {
                break;
            }
            if demand.cadence.active()
                && deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                demand.summary.raise();
                deadline = None;
            }
            if let Some(job) = demand.pop() {
                if !publish_process_job(&event_tx, job) {
                    break;
                }
                deadline = demand
                    .cadence
                    .active()
                    .then(|| Instant::now() + refresh_every);
                continue;
            }

            let wait_deadline = demand.cadence.active().then_some(deadline).flatten();
            absorb_wait(&mut demand, &command_rx, wait_deadline);
        }
    });
}

fn publish_inventory(event_tx: &Sender<WorkerEvent>) -> bool {
    event_tx
        .send(WorkerEvent::InventoryReady(
            probe::capture_inventory().map(Box::new),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demand_coalesces_and_prioritizes_explicit_work() {
        let mut demand = ProcessDemand::default();
        demand.absorb(ProcessRequest::Refresh);
        demand.absorb(ProcessRequest::RefreshShared);
        let first = ProcessKey {
            pid: super::super::super::model::Pid(1),
            start_time_ticks: 10,
        };
        let second = ProcessKey {
            pid: super::super::super::model::Pid(2),
            start_time_ticks: 20,
        };
        demand.absorb(ProcessRequest::RefreshMappings(first));
        demand.absorb(ProcessRequest::RefreshMappings(second));

        assert!(matches!(demand.pop(), Some(ProcessJob::Mappings(key)) if key == second));
        assert!(matches!(demand.pop(), Some(ProcessJob::Shared)));
        assert!(matches!(demand.pop(), Some(ProcessJob::Processes)));
        assert!(demand.pop().is_none());
    }

    #[test]
    fn enabling_periodic_scanning_demands_an_immediate_summary() {
        let mut demand = ProcessDemand::default();
        demand.absorb(ProcessRequest::SetScanning(true));
        assert!(matches!(demand.pop(), Some(ProcessJob::Processes)));
        demand.absorb(ProcessRequest::SetScanning(true));
        assert!(demand.pop().is_none());
    }

    #[test]
    fn shutdown_is_absorbing() {
        let mut demand = ProcessDemand::default();
        demand.absorb(ProcessRequest::Shutdown);
        assert_eq!(demand.life, WorkerLife::Shutdown);
    }

    #[test]
    fn disconnected_timed_wait_shuts_down_instead_of_faking_a_tick() {
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        let mut demand = ProcessDemand {
            cadence: Cadence::Scanning,
            ..ProcessDemand::default()
        };
        absorb_wait(
            &mut demand,
            &receiver,
            Some(Instant::now() + Duration::from_secs(1)),
        );
        assert_eq!(demand.life, WorkerLife::Shutdown);
        assert!(demand.pop().is_none());
    }
}
