use super::super::model::{Inventory, Ledger, Processes, Shared, Tmpfs};

#[derive(Clone, Debug, Default)]
pub(super) struct Ledgers {
    pub(super) inventory: Option<Ledger<Inventory>>,
    pub(super) processes: Option<Ledger<Processes>>,
    pub(super) tmpfs: Option<Ledger<Tmpfs>>,
    pub(super) shared: Option<Ledger<Shared>>,
}

impl Ledgers {
    pub(super) fn install_inventory(&mut self, ledger: Ledger<Inventory>) {
        self.inventory = Some(ledger);
    }

    pub(super) fn install_processes(&mut self, ledger: Ledger<Processes>) {
        self.processes = Some(ledger);
    }

    pub(super) fn install_shared(&mut self, ledger: Ledger<Shared>) {
        self.shared = Some(ledger);
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
