use super::super::model::{LedgerState, ObjectUsage, Pid, ProcessKey};
use super::super::probe;
use color_eyre::eyre::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

struct MappingLedger {
    elapsed: Duration,
    cost: probe::ProcessMappingCost,
    objects: Vec<ObjectUsage>,
    state: LedgerState,
    warnings: Vec<String>,
}

impl From<probe::ProcessMappingScan> for MappingLedger {
    fn from(scan: probe::ProcessMappingScan) -> Self {
        Self {
            elapsed: scan.elapsed,
            cost: scan.cost,
            objects: scan.objects,
            state: scan.mappings_state,
            warnings: scan.warnings,
        }
    }
}

enum MappingState {
    Loading(Instant),
    Ready(MappingLedger),
}

#[derive(Default)]
pub(super) struct MappingLedgers {
    states: BTreeMap<ProcessKey, MappingState>,
}

impl MappingLedgers {
    pub(super) fn begin(&mut self, key: ProcessKey) -> bool {
        if self.states.contains_key(&key) {
            return false;
        }
        self.states
            .retain(|_, state| matches!(state, MappingState::Ready(_)));
        let _ = self
            .states
            .insert(key, MappingState::Loading(Instant::now()));
        true
    }

    pub(super) fn finish(
        &mut self,
        expected: ProcessKey,
        result: Result<Box<probe::ProcessMappingScan>>,
    ) -> Result<()> {
        match result {
            Ok(scan) => {
                let _ = self.states.remove(&expected);
                ensure!(
                    scan.key == expected,
                    "mapping worker returned {} for requested {expected}",
                    scan.key
                );
                let _ = self
                    .states
                    .insert(expected, MappingState::Ready((*scan).into()));
                Ok(())
            }
            Err(error) => {
                let _ = self.states.remove(&expected);
                Err(error)
            }
        }
    }

    pub(super) fn retain(&mut self, live: &BTreeSet<ProcessKey>) {
        self.states.retain(|key, _| live.contains(key));
    }

    pub(super) fn clear(&mut self) {
        self.states.clear();
    }

    pub(super) fn objects(&self, key: ProcessKey) -> &[ObjectUsage] {
        match self.states.get(&key) {
            Some(MappingState::Ready(ledger)) => &ledger.objects,
            Some(MappingState::Loading(_)) | None => &[],
        }
    }

    pub(super) fn state(&self, key: ProcessKey, fallback: LedgerState) -> &'static str {
        match self.states.get(&key) {
            Some(MappingState::Loading(_)) => "loading",
            Some(MappingState::Ready(ledger)) => ledger.state.label(),
            None => fallback.label(),
        }
    }

    pub(super) fn loading(&self, key: ProcessKey) -> Option<Duration> {
        match self.states.get(&key)? {
            MappingState::Loading(started) => Some(started.elapsed()),
            MappingState::Ready(_) => None,
        }
    }

    pub(super) fn scan_label(&self, key: ProcessKey) -> String {
        match self.states.get(&key) {
            Some(MappingState::Loading(started)) => {
                format!(
                    "loading pid {}: {} ms",
                    key.pid,
                    started.elapsed().as_millis()
                )
            }
            Some(MappingState::Ready(ledger)) => format!(
                "{} ms (mount {} read {} parse {})",
                ledger.elapsed.as_millis(),
                ledger.cost.mount_index.as_millis(),
                ledger.cost.read.as_millis(),
                ledger.cost.parse.as_millis()
            ),
            None => "not loaded".to_string(),
        }
    }

    pub(super) fn first_loading(&self) -> Option<(Pid, Instant)> {
        self.states.iter().find_map(|(key, state)| match state {
            MappingState::Loading(started) => Some((key.pid, *started)),
            MappingState::Ready(_) => None,
        })
    }

    pub(super) fn is_loading(&self) -> bool {
        self.first_loading().is_some()
    }

    pub(super) fn warnings(&self) -> impl Iterator<Item = &str> {
        self.states.values().flat_map(|state| match state {
            MappingState::Loading(_) => [].iter().map(String::as_str),
            MappingState::Ready(ledger) => ledger.warnings.iter().map(String::as_str),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::model::Pid;
    use super::*;

    fn key(pid: i32) -> ProcessKey {
        ProcessKey {
            pid: Pid(pid),
            start_time_ticks: pid as u64,
        }
    }

    fn scan(key: ProcessKey) -> Box<probe::ProcessMappingScan> {
        Box::new(probe::ProcessMappingScan {
            elapsed: Duration::ZERO,
            cost: probe::ProcessMappingCost {
                mount_index: Duration::ZERO,
                read: Duration::ZERO,
                parse: Duration::ZERO,
            },
            key,
            objects: Vec::new(),
            mappings_state: LedgerState::Exact,
            warnings: Vec::new(),
        })
    }

    #[test]
    fn latest_loading_request_coexists_with_an_older_result() {
        let first = key(1);
        let second = key(2);
        let mut ledgers = MappingLedgers::default();
        assert!(ledgers.begin(first));
        assert!(ledgers.begin(second));
        assert_eq!(
            ledgers.first_loading().map(|(pid, _)| pid),
            Some(second.pid)
        );

        ledgers
            .finish(first, Ok(scan(first)))
            .expect("valid result");
        assert_eq!(ledgers.state(first, LedgerState::Deferred), "exact");
        assert_eq!(ledgers.state(second, LedgerState::Deferred), "loading");
    }

    #[test]
    fn rejects_a_result_for_another_process_incarnation() {
        let mut ledgers = MappingLedgers::default();
        let expected = key(1);
        assert!(ledgers.begin(expected));
        assert!(ledgers.finish(expected, Ok(scan(key(2)))).is_err());
        assert_eq!(ledgers.state(expected, LedgerState::Deferred), "deferred");
    }
}
