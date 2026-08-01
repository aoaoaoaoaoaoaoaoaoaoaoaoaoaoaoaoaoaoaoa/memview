use super::super::model::{LedgerState, ObjectUsage, Pid, ProcessKey};
use super::super::probe;
use color_eyre::eyre::{Result, ensure};
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
    selected: Option<(ProcessKey, MappingState)>,
}

impl MappingLedgers {
    pub(super) fn begin(&mut self, key: ProcessKey) -> bool {
        if self
            .selected
            .as_ref()
            .is_some_and(|(selected, _)| *selected == key)
        {
            return false;
        }
        self.selected = Some((key, MappingState::Loading(Instant::now())));
        true
    }

    pub(super) fn finish(
        &mut self,
        expected: ProcessKey,
        result: Result<Box<probe::ProcessMappingScan>>,
    ) -> Result<()> {
        match result {
            Ok(scan) => {
                if scan.key != expected
                    && self
                        .selected
                        .as_ref()
                        .is_some_and(|(selected, _)| *selected == expected)
                {
                    self.selected = None;
                }
                ensure!(
                    scan.key == expected,
                    "mapping worker returned {} for requested {expected}",
                    scan.key
                );
                if self
                    .selected
                    .as_ref()
                    .is_some_and(|(selected, _)| *selected == expected)
                {
                    self.selected = Some((expected, MappingState::Ready((*scan).into())));
                }
                Ok(())
            }
            Err(error) => {
                if self
                    .selected
                    .as_ref()
                    .is_some_and(|(selected, _)| *selected == expected)
                {
                    self.selected = None;
                    Err(error)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub(super) fn clear(&mut self) {
        self.selected = None;
    }

    pub(super) fn objects(&self, key: ProcessKey) -> &[ObjectUsage] {
        match &self.selected {
            Some((selected, MappingState::Ready(ledger))) if *selected == key => &ledger.objects,
            Some((_, MappingState::Loading(_) | MappingState::Ready(_))) | None => &[],
        }
    }

    pub(super) fn state(&self, key: ProcessKey, fallback: LedgerState) -> &'static str {
        match &self.selected {
            Some((selected, MappingState::Loading(_))) if *selected == key => "loading",
            Some((selected, MappingState::Ready(ledger))) if *selected == key => {
                ledger.state.label()
            }
            Some((_, MappingState::Loading(_) | MappingState::Ready(_))) | None => fallback.label(),
        }
    }

    pub(super) fn loading(&self, key: ProcessKey) -> Option<Duration> {
        match self.selected.as_ref()? {
            (selected, MappingState::Loading(started)) if *selected == key => {
                Some(started.elapsed())
            }
            (_, MappingState::Loading(_) | MappingState::Ready(_)) => None,
        }
    }

    pub(super) fn scan_label(&self, key: ProcessKey) -> String {
        match &self.selected {
            Some((selected, MappingState::Loading(started))) if *selected == key => {
                format!(
                    "loading pid {}: {} ms",
                    key.pid,
                    started.elapsed().as_millis()
                )
            }
            Some((selected, MappingState::Ready(ledger))) if *selected == key => format!(
                "{} ms (mount {} read {} parse {})",
                ledger.elapsed.as_millis(),
                ledger.cost.mount_index.as_millis(),
                ledger.cost.read.as_millis(),
                ledger.cost.parse.as_millis()
            ),
            Some((_, MappingState::Loading(_) | MappingState::Ready(_))) | None => {
                "not loaded".to_string()
            }
        }
    }

    pub(super) fn first_loading(&self) -> Option<(Pid, Instant)> {
        match self.selected.as_ref()? {
            (key, MappingState::Loading(started)) => Some((key.pid, *started)),
            (_, MappingState::Ready(_)) => None,
        }
    }

    pub(super) fn is_loading(&self) -> bool {
        self.first_loading().is_some()
    }

    pub(super) fn warnings(&self) -> impl Iterator<Item = &str> {
        self.selected.iter().flat_map(|(_, state)| match state {
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
    fn latest_selection_supersedes_and_discards_an_older_result() {
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
        assert_eq!(ledgers.state(first, LedgerState::Deferred), "deferred");
        assert_eq!(ledgers.state(second, LedgerState::Deferred), "loading");
        ledgers
            .finish(second, Ok(scan(second)))
            .expect("valid result");
        assert_eq!(ledgers.state(second, LedgerState::Deferred), "exact");
    }

    #[test]
    fn rejects_a_result_for_another_process_incarnation() {
        let mut ledgers = MappingLedgers::default();
        let expected = key(1);
        assert!(ledgers.begin(expected));
        assert!(ledgers.finish(expected, Ok(scan(key(2)))).is_err());
        assert_eq!(ledgers.state(expected, LedgerState::Deferred), "deferred");
    }

    #[test]
    fn a_new_process_generation_can_refresh_the_same_selection() {
        let selected = key(1);
        let mut ledgers = MappingLedgers::default();
        assert!(ledgers.begin(selected));
        ledgers
            .finish(selected, Ok(scan(selected)))
            .expect("valid result");
        assert!(!ledgers.begin(selected));

        ledgers.clear();
        assert!(ledgers.begin(selected));
        assert!(ledgers.objects(selected).is_empty());
        assert_eq!(ledgers.state(selected, LedgerState::Deferred), "loading");
    }
}
