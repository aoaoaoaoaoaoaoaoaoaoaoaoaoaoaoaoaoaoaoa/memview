use super::super::model::{Inventory, Ledger, ProcessKey, Processes, Shared, Tmpfs};
use super::super::probe;
use color_eyre::eyre::Result;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

const MIN_WORKER_REFRESH: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
enum InventoryRequest {
    Refresh,
    RefreshTmpfs,
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
    inventory: Arc<(Mutex<InventoryDemand>, Condvar)>,
    processes: ProcessPort,
}

#[derive(Clone, Debug)]
enum ProcessPort {
    Live(Arc<(Mutex<ProcessDemand>, Condvar)>),
    #[cfg(test)]
    Harness(Sender<ProcessRequest>),
}

impl WorkerPort {
    pub fn refresh_inventory(&self) {
        submit_inventory(&self.inventory, InventoryRequest::Refresh);
    }

    pub fn refresh_processes(&self) {
        self.submit_process(ProcessRequest::Refresh);
    }

    pub fn refresh_process_mappings(&self, key: ProcessKey) {
        self.submit_process(ProcessRequest::RefreshMappings(key));
    }

    pub fn refresh_shared(&self) {
        self.submit_process(ProcessRequest::RefreshShared);
    }

    pub fn refresh_tmpfs(&self) {
        submit_inventory(&self.inventory, InventoryRequest::RefreshTmpfs);
    }

    pub fn set_process_scanning(&self, active: bool) {
        self.submit_process(ProcessRequest::SetScanning(active));
    }

    pub fn shutdown(&self) {
        submit_inventory(&self.inventory, InventoryRequest::Shutdown);
        self.submit_process(ProcessRequest::Shutdown);
    }

    fn submit_process(&self, request: ProcessRequest) {
        match &self.processes {
            ProcessPort::Live(mailbox) => submit_process(mailbox, request),
            #[cfg(test)]
            ProcessPort::Harness(sender) => {
                let _ = sender.send(request);
            }
        }
    }

    #[cfg(test)]
    pub fn process_harness(processes: Sender<ProcessRequest>) -> Self {
        Self {
            inventory: Arc::new((Mutex::new(InventoryDemand::default()), Condvar::new())),
            processes: ProcessPort::Harness(processes),
        }
    }
}

#[derive(Debug)]
pub enum WorkerEvent {
    InventoryReady(Result<Box<Ledger<Inventory>>>),
    TmpfsReady(Result<Box<Ledger<Tmpfs>>>),
    ProcessesStarted(Instant),
    ProcessesReady(Result<Box<Ledger<Processes>>>),
    ProcessMappingsReady(ProcessKey, Result<Box<probe::ProcessMappingScan>>),
    SharedObjectsStarted(Instant),
    SharedObjectsReady(Result<Box<Ledger<Shared>>>),
}

pub fn spawn_worker(refresh_every: Duration) -> (WorkerPort, Receiver<WorkerEvent>) {
    let inventory = Arc::new((Mutex::new(InventoryDemand::default()), Condvar::new()));
    let processes = Arc::new((Mutex::new(ProcessDemand::default()), Condvar::new()));
    let (event_tx, event_rx) = mpsc::channel();

    spawn_inventory_worker(Arc::clone(&inventory), event_tx.clone());
    spawn_process_worker(
        refresh_every.max(MIN_WORKER_REFRESH),
        Arc::clone(&processes),
        event_tx,
    );

    (
        WorkerPort {
            inventory,
            processes: ProcessPort::Live(processes),
        },
        event_rx,
    )
}

fn spawn_inventory_worker(
    mailbox: Arc<(Mutex<InventoryDemand>, Condvar)>,
    event_tx: Sender<WorkerEvent>,
) {
    let _handle = thread::spawn(move || {
        loop {
            let job = {
                let (demand_lock, wake) = &*mailbox;
                let mut demand = lock(demand_lock);
                let mut job = demand.pop();
                while demand.life == WorkerLife::Running && job.is_none() {
                    demand = match wake.wait(demand) {
                        Ok(demand) => demand,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    job = demand.pop();
                }
                if demand.life == WorkerLife::Shutdown {
                    None
                } else {
                    job
                }
            };
            let Some(job) = job else {
                break;
            };
            let live = match job {
                InventoryJob::Inventory => publish_inventory(&event_tx),
                InventoryJob::Tmpfs => publish_tmpfs(&event_tx),
            };
            if !live {
                break;
            }
        }
    });
}

#[derive(Clone, Copy, Debug)]
enum InventoryJob {
    Inventory,
    Tmpfs,
}

#[derive(Debug, Default)]
struct InventoryDemand {
    inventory: DemandFlag,
    tmpfs: DemandFlag,
    life: WorkerLife,
}

impl InventoryDemand {
    fn absorb(&mut self, request: InventoryRequest) {
        match request {
            InventoryRequest::Refresh => {
                self.inventory.raise();
                self.tmpfs.raise();
            }
            InventoryRequest::RefreshTmpfs => self.tmpfs.raise(),
            InventoryRequest::Shutdown => self.life = WorkerLife::Shutdown,
        }
    }

    fn pop(&mut self) -> Option<InventoryJob> {
        if self.inventory.take() {
            Some(InventoryJob::Inventory)
        } else if self.tmpfs.take() {
            Some(InventoryJob::Tmpfs)
        } else {
            None
        }
    }
}

fn submit_inventory(mailbox: &Arc<(Mutex<InventoryDemand>, Condvar)>, request: InventoryRequest) {
    let (demand, wake) = &**mailbox;
    lock(demand).absorb(request);
    wake.notify_one();
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

fn next_process_job(
    mailbox: &Arc<(Mutex<ProcessDemand>, Condvar)>,
    deadline: Option<Instant>,
) -> Option<ProcessJob> {
    let (demand_lock, wake) = &**mailbox;
    let mut demand = lock(demand_lock);
    loop {
        if demand.life == WorkerLife::Shutdown {
            return None;
        }
        if demand.cadence.active() && deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            demand.summary.raise();
        }
        if let Some(job) = demand.pop() {
            return Some(job);
        }

        let wait_deadline = demand.cadence.active().then_some(deadline).flatten();
        demand = if let Some(deadline) = wait_deadline {
            let timeout = deadline.saturating_duration_since(Instant::now());
            match wake.wait_timeout(demand, timeout) {
                Ok((demand, _)) => demand,
                Err(poisoned) => poisoned.into_inner().0,
            }
        } else {
            match wake.wait(demand) {
                Ok(demand) => demand,
                Err(poisoned) => poisoned.into_inner(),
            }
        };
    }
}

fn submit_process(mailbox: &Arc<(Mutex<ProcessDemand>, Condvar)>, request: ProcessRequest) {
    let (demand, wake) = &**mailbox;
    lock(demand).absorb(request);
    wake.notify_one();
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
    mailbox: Arc<(Mutex<ProcessDemand>, Condvar)>,
    event_tx: Sender<WorkerEvent>,
) {
    let _handle = thread::spawn(move || {
        let mut deadline = None;

        while let Some(job) = next_process_job(&mailbox, deadline) {
            if !publish_process_job(&event_tx, job) {
                break;
            }
            let (demand, _) = &*mailbox;
            deadline = lock(demand)
                .cadence
                .active()
                .then(|| Instant::now() + refresh_every);
        }
    });
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn publish_inventory(event_tx: &Sender<WorkerEvent>) -> bool {
    event_tx
        .send(WorkerEvent::InventoryReady(
            probe::capture_inventory().map(Box::new),
        ))
        .is_ok()
}

fn publish_tmpfs(event_tx: &Sender<WorkerEvent>) -> bool {
    event_tx
        .send(WorkerEvent::TmpfsReady(
            probe::capture_tmpfs().map(Box::new),
        ))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_demand_coalesces_full_generations() {
        let mut demand = InventoryDemand::default();
        demand.absorb(InventoryRequest::RefreshTmpfs);
        demand.absorb(InventoryRequest::Refresh);
        demand.absorb(InventoryRequest::Refresh);

        assert!(matches!(demand.pop(), Some(InventoryJob::Inventory)));
        assert!(matches!(demand.pop(), Some(InventoryJob::Tmpfs)));
        assert!(demand.pop().is_none());
    }

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
    fn mailbox_stays_constant_size_under_a_refresh_storm() {
        let mailbox = Arc::new((Mutex::new(ProcessDemand::default()), Condvar::new()));
        for _ in 0..10_000 {
            submit_process(&mailbox, ProcessRequest::Refresh);
            submit_process(&mailbox, ProcessRequest::RefreshShared);
        }
        let (demand, _) = &*mailbox;
        let mut demand = lock(demand);
        assert!(matches!(demand.pop(), Some(ProcessJob::Shared)));
        assert!(matches!(demand.pop(), Some(ProcessJob::Processes)));
        assert!(demand.pop().is_none());
    }
}
