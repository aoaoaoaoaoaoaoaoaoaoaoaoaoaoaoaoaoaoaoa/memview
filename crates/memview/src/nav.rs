#[derive(Clone, Copy, Debug)]
pub struct Hotkey {
    pub key: &'static str,
    pub action: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub struct HotkeySections {
    pub global: &'static [Hotkey],
    pub pane_title: &'static str,
    pub pane: &'static [Hotkey],
}

const GLOBAL_HOTKEYS: &[Hotkey] = &[
    Hotkey {
        key: "1-4 / Tab",
        action: "switch pane",
    },
    Hotkey {
        key: "?",
        action: "show this help",
    },
    Hotkey {
        key: "/",
        action: "filter current ledger rows by regexp; empty search clears",
    },
    Hotkey {
        key: "f",
        action: "clear active regexp filter",
    },
    Hotkey {
        key: "Esc",
        action: "no-op at top level; close modal/help",
    },
    Hotkey {
        key: "q / Ctrl-C",
        action: "quit",
    },
];

const OVERVIEW_HOTKEYS: &[Hotkey] = &[
    Hotkey {
        key: "r",
        action: "refresh kernel counters, tmpfs mounts, and SysV shm",
    },
    Hotkey {
        key: "s",
        action: "cycle memory lens",
    },
];

const PROCESS_HOTKEYS: &[Hotkey] = &[
    Hotkey {
        key: "j/k / arrows",
        action: "move selection",
    },
    Hotkey {
        key: "gg / G",
        action: "jump to first or last row",
    },
    Hotkey {
        key: "PgUp / PgDn",
        action: "move selection by one visible pane",
    },
    Hotkey {
        key: "wheel",
        action: "move selection one row per detent",
    },
    Hotkey {
        key: "h/l / Left/Right",
        action: "collapse or expand selected process",
    },
    Hotkey {
        key: "Enter",
        action: "toggle selected process fold, including auto-folds",
    },
    Hotkey {
        key: "s",
        action: "cycle sort metric",
    },
    Hotkey {
        key: "m",
        action: "toggle self vs self+children accounting",
    },
    Hotkey {
        key: "r",
        action: "force an immediate process memory rescan",
    },
    Hotkey {
        key: "K",
        action: "confirm SIGTERM for selected process",
    },
];

const TMPFS_HOTKEYS: &[Hotkey] = &[
    Hotkey {
        key: "j/k / arrows",
        action: "move selection",
    },
    Hotkey {
        key: "gg / G",
        action: "jump to first or last row",
    },
    Hotkey {
        key: "PgUp / PgDn",
        action: "move selection by one visible pane",
    },
    Hotkey {
        key: "wheel",
        action: "move selection one row per detent",
    },
    Hotkey {
        key: "h/l / Left/Right",
        action: "collapse or expand selected entry",
    },
    Hotkey {
        key: "Enter",
        action: "toggle selected directory fold, including auto-folds",
    },
    Hotkey {
        key: "m",
        action: "toggle self vs self+children search context",
    },
    Hotkey {
        key: "r",
        action: "refresh only the selected tmpfs mount",
    },
    Hotkey {
        key: "d",
        action: "delete selected tmpfs entry recursively if directory",
    },
];

const SHARED_HOTKEYS: &[Hotkey] = &[
    Hotkey {
        key: "j/k / arrows",
        action: "move selection",
    },
    Hotkey {
        key: "gg / G",
        action: "jump to first or last row",
    },
    Hotkey {
        key: "PgUp / PgDn",
        action: "move selection by one visible pane",
    },
    Hotkey {
        key: "wheel",
        action: "move selection one row per detent",
    },
    Hotkey {
        key: "s",
        action: "cycle memory lens",
    },
    Hotkey {
        key: "m",
        action: "toggle self vs self+children search context",
    },
    Hotkey {
        key: "r",
        action: "force an immediate shared-object rescan",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tab {
    Overview,
    Processes,
    Tmpfs,
    Shared,
}

impl Tab {
    pub const ALL: [Self; 4] = [Self::Overview, Self::Processes, Self::Tmpfs, Self::Shared];

    #[must_use]
    pub fn next(self) -> Self {
        let index = Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    #[must_use]
    pub fn previous(self) -> Self {
        let index = Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0);
        Self::ALL[(index + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Processes => "Processes",
            Self::Tmpfs => "Tmpfs",
            Self::Shared => "Shared",
        }
    }

    #[must_use]
    pub fn drives_process_scans(self) -> bool {
        matches!(self, Self::Processes)
    }

    #[must_use]
    pub fn hotkeys(self) -> &'static [Hotkey] {
        match self {
            Self::Overview => OVERVIEW_HOTKEYS,
            Self::Processes => PROCESS_HOTKEYS,
            Self::Tmpfs => TMPFS_HOTKEYS,
            Self::Shared => SHARED_HOTKEYS,
        }
    }
}

#[must_use]
pub fn global_hotkeys() -> &'static [Hotkey] {
    GLOBAL_HOTKEYS
}
