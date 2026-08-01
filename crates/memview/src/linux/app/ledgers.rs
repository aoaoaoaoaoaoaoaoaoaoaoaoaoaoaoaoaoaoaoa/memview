use super::super::model::{CaptureStamp, Inventory, Ledger, Meminfo, Processes, Shared, Tmpfs};

#[derive(Clone, Copy, Debug)]
enum MeminfoSource {
    Inventory,
    Processes,
    Shared,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Ledgers {
    pub(super) inventory: Option<Ledger<Inventory>>,
    pub(super) processes: Option<Ledger<Processes>>,
    pub(super) tmpfs: Option<Ledger<Tmpfs>>,
    pub(super) shared: Option<Ledger<Shared>>,
    meminfo_source: Option<MeminfoSource>,
    pub(super) last_stamp: Option<CaptureStamp>,
}

impl Ledgers {
    pub(super) fn install_inventory(&mut self, ledger: Ledger<Inventory>) {
        self.last_stamp = Some(ledger.stamp);
        self.meminfo_source = Some(MeminfoSource::Inventory);
        self.inventory = Some(ledger);
    }

    pub(super) fn install_processes(&mut self, ledger: Ledger<Processes>) {
        self.last_stamp = Some(ledger.stamp);
        self.meminfo_source = Some(MeminfoSource::Processes);
        self.processes = Some(ledger);
    }

    pub(super) fn install_shared(&mut self, ledger: Ledger<Shared>) {
        self.last_stamp = Some(ledger.stamp);
        self.meminfo_source = Some(MeminfoSource::Shared);
        self.shared = Some(ledger);
    }

    pub(super) fn meminfo(&self) -> Option<&Meminfo> {
        match self.meminfo_source? {
            MeminfoSource::Inventory => self.inventory.as_ref().map(|ledger| &ledger.value.meminfo),
            MeminfoSource::Processes => self.processes.as_ref().map(|ledger| &ledger.value.meminfo),
            MeminfoSource::Shared => self.shared.as_ref().map(|ledger| &ledger.value.meminfo),
        }
    }

    pub(super) fn process_data(&self) -> Option<&Processes> {
        self.processes.as_ref().map(|ledger| &ledger.value)
    }

    pub(super) fn tmpfs_data(&self) -> Option<&Tmpfs> {
        self.tmpfs.as_ref().map(|ledger| &ledger.value)
    }

    pub(super) fn shared_data(&self) -> Option<&Shared> {
        self.shared.as_ref().map(|ledger| &ledger.value)
    }
}
