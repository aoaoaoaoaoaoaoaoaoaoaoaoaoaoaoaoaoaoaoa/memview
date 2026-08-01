use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

macro_rules! tab_catalog {
    ($($variant:ident => {
        title: $title:literal,
        token: $token:literal,
        scans: $scans:literal,
        navigation: $navigation:expr,
        bindings: $bindings:expr
    }),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u8)]
        pub enum Tab {$($variant),+}

        impl Tab {
            pub const ALL: [Self; tab_catalog!(@count $($variant)+)] = [$(Self::$variant),+];

            #[must_use]
            pub fn next(self) -> Self {
                Self::ALL[(self as usize + 1) % Self::ALL.len()]
            }

            #[must_use]
            pub fn previous(self) -> Self {
                Self::ALL[(self as usize + Self::ALL.len() - 1) % Self::ALL.len()]
            }

            #[must_use]
            pub fn title(self) -> &'static str {
                match self {$(Self::$variant => $title),+}
            }

            #[must_use]
            pub fn token(self) -> &'static str {
                match self {$(Self::$variant => $token),+}
            }

            #[must_use]
            pub fn from_token(token: &str) -> Option<Self> {
                match token {$($token => Some(Self::$variant),)+ _ => None}
            }

            #[must_use]
            pub fn drives_process_scans(self) -> bool {
                match self {$(Self::$variant => $scans),+}
            }

            #[must_use]
            pub fn bindings(self) -> &'static [Binding] {
                match self {$(Self::$variant => $bindings),+}
            }

            #[must_use]
            pub fn navigation(self) -> &'static [Binding] {
                match self {$(Self::$variant => $navigation),+}
            }
        }
    };
    (@count $head:ident $($tail:ident)*) => {1usize $(+ tab_catalog!(@one $tail))*};
    (@one $variant:ident) => {1usize};
}

tab_catalog! {
    Overview => {
        title: "Overview",
        token: "overview",
        scans: false,
        navigation: &[],
        bindings: OVERVIEW_BINDINGS
    },
    Processes => {
        title: "Processes",
        token: "processes",
        scans: true,
        navigation: TREE_NAVIGATION,
        bindings: PROCESS_ACTIONS
    },
    Tmpfs => {
        title: "Tmpfs",
        token: "tmpfs",
        scans: false,
        navigation: TREE_NAVIGATION,
        bindings: TMPFS_ACTIONS
    },
    Shared => {
        title: "Shared",
        token: "shared",
        scans: false,
        navigation: FLAT_NAVIGATION,
        bindings: SHARED_ACTIONS
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Ignore,
    Quit,
    ShowHelp,
    OpenSearch,
    ClearSearch,
    NextTab,
    PreviousTab,
    SelectTab(Tab),
    CycleMetric,
    CycleScope,
    Refresh,
    Kill,
    Move(isize),
    PageUp,
    PageDown,
    Collapse,
    Expand,
    Toggle,
    FirstRow,
    LastRow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Chord {
    Char(char),
    Code(KeyCode),
    Control(char),
}

impl Chord {
    fn matches(&self, key: KeyEvent) -> bool {
        let command_modifier = key.modifiers.intersects(
            KeyModifiers::CONTROL
                | KeyModifiers::ALT
                | KeyModifiers::SUPER
                | KeyModifiers::HYPER
                | KeyModifiers::META,
        );
        match self {
            Self::Char(character) => key.code == KeyCode::Char(*character) && !command_modifier,
            Self::Code(code) => key.code == *code && !command_modifier,
            Self::Control(character) => {
                key.code == KeyCode::Char(*character)
                    && key.modifiers.contains(KeyModifiers::CONTROL)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Command {
    chord: Chord,
    action: Action,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FooterHint {
    pub key: &'static str,
    pub action: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub key: &'static str,
    pub description: &'static str,
    pub footer: Option<FooterHint>,
    commands: &'static [Command],
}

impl Binding {
    #[must_use]
    pub fn resolve(&self, key: KeyEvent) -> Option<Action> {
        self.commands
            .iter()
            .find(|command| command.chord.matches(key))
            .map(|command| command.action)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BindingSections {
    pub global: &'static [Binding],
    pub pane_title: &'static str,
    pub navigation: &'static [Binding],
    pub pane: &'static [Binding],
}

macro_rules! commands {
    ($(($chord:expr, $action:expr)),+ $(,)?) => {
        &[$(Command { chord: $chord, action: $action }),+]
    };
}

macro_rules! binding {
    ($key:literal, $description:literal, $commands:expr) => {
        Binding {
            key: $key,
            description: $description,
            footer: None,
            commands: $commands,
        }
    };
    ($key:literal, $description:literal, $footer_key:literal, $footer_action:literal, $commands:expr) => {
        Binding {
            key: $key,
            description: $description,
            footer: Some(FooterHint {
                key: $footer_key,
                action: $footer_action,
            }),
            commands: $commands,
        }
    };
}

const GLOBAL_BINDINGS: &[Binding] = &[
    binding!(
        "1-4 / Tab / Shift-Tab",
        "switch pane",
        commands![
            (Chord::Char('1'), Action::SelectTab(Tab::Overview)),
            (Chord::Char('2'), Action::SelectTab(Tab::Processes)),
            (Chord::Char('3'), Action::SelectTab(Tab::Tmpfs)),
            (Chord::Char('4'), Action::SelectTab(Tab::Shared)),
            (Chord::Code(KeyCode::Tab), Action::NextTab),
            (Chord::Code(KeyCode::BackTab), Action::PreviousTab),
        ]
    ),
    binding!(
        "?",
        "show this help",
        "?",
        "help",
        commands![(Chord::Char('?'), Action::ShowHelp)]
    ),
    binding!(
        "/",
        "filter current ledger rows by regexp; empty search clears",
        "/",
        "search",
        commands![(Chord::Char('/'), Action::OpenSearch)]
    ),
    binding!(
        "f",
        "clear active regexp filter",
        commands![(Chord::Char('f'), Action::ClearSearch)]
    ),
    binding!(
        "Esc",
        "close the active modal; no-op at top level",
        commands![(Chord::Code(KeyCode::Esc), Action::Ignore)]
    ),
    binding!(
        "q / Ctrl-C",
        "quit",
        "q",
        "quit",
        commands![
            (Chord::Char('q'), Action::Quit),
            (Chord::Control('c'), Action::Quit),
        ]
    ),
];

const OVERVIEW_BINDINGS: &[Binding] = &[
    binding!(
        "r",
        "refresh kernel counters, tmpfs mounts, and SysV shm",
        "r",
        "refresh",
        commands![(Chord::Char('r'), Action::Refresh)]
    ),
    binding!(
        "s",
        "cycle memory lens",
        "s",
        "lens",
        commands![(Chord::Char('s'), Action::CycleMetric)]
    ),
];

const TREE_NAVIGATION: &[Binding] = &[
    binding!(
        "j/k / arrows",
        "move selection",
        "j/k/Pg/wheel",
        "move",
        commands![
            (Chord::Char('j'), Action::Move(1)),
            (Chord::Code(KeyCode::Down), Action::Move(1)),
            (Chord::Char('k'), Action::Move(-1)),
            (Chord::Code(KeyCode::Up), Action::Move(-1)),
        ]
    ),
    binding!("gg / G", "jump to first or last row", "gg/G", "edge", &[]),
    binding!(
        "PgUp / PgDn",
        "move selection by one visible pane",
        commands![
            (Chord::Code(KeyCode::PageUp), Action::PageUp),
            (Chord::Code(KeyCode::PageDown), Action::PageDown),
        ]
    ),
    binding!("wheel", "move selection one row per detent", &[]),
    binding!(
        "h/l / Left/Right",
        "collapse or expand selected subtree",
        commands![
            (Chord::Char('h'), Action::Collapse),
            (Chord::Code(KeyCode::Left), Action::Collapse),
            (Chord::Char('l'), Action::Expand),
            (Chord::Code(KeyCode::Right), Action::Expand),
        ]
    ),
    binding!(
        "Enter",
        "toggle selected subtree fold, including auto-folds",
        "Enter",
        "fold",
        commands![(Chord::Code(KeyCode::Enter), Action::Toggle)]
    ),
];

const PROCESS_ACTIONS: &[Binding] = &[
    binding!(
        "s",
        "cycle sort metric",
        "s",
        "sort",
        commands![(Chord::Char('s'), Action::CycleMetric)]
    ),
    binding!(
        "m",
        "toggle self vs self+children accounting",
        "m",
        "mode",
        commands![(Chord::Char('m'), Action::CycleScope)]
    ),
    binding!(
        "r",
        "force an immediate process memory rescan",
        "r",
        "rescan",
        commands![(Chord::Char('r'), Action::Refresh)]
    ),
    binding!(
        "K",
        "confirm SIGTERM for selected process",
        "K",
        "SIGTERM",
        commands![(Chord::Char('K'), Action::Kill)]
    ),
];

const TMPFS_ACTIONS: &[Binding] = &[
    binding!(
        "m",
        "toggle self vs self+children search context",
        "m",
        "mode",
        commands![(Chord::Char('m'), Action::CycleScope)]
    ),
    binding!(
        "r",
        "replace the complete tmpfs capture generation",
        "r",
        "refresh",
        commands![(Chord::Char('r'), Action::Refresh)]
    ),
];

const FLAT_NAVIGATION: &[Binding] = &[
    binding!(
        "j/k / arrows",
        "move selection",
        "j/k/Pg/wheel",
        "move",
        commands![
            (Chord::Char('j'), Action::Move(1)),
            (Chord::Code(KeyCode::Down), Action::Move(1)),
            (Chord::Char('k'), Action::Move(-1)),
            (Chord::Code(KeyCode::Up), Action::Move(-1)),
        ]
    ),
    binding!("gg / G", "jump to first or last row", "gg/G", "edge", &[]),
    binding!(
        "PgUp / PgDn",
        "move selection by one visible pane",
        commands![
            (Chord::Code(KeyCode::PageUp), Action::PageUp),
            (Chord::Code(KeyCode::PageDown), Action::PageDown),
        ]
    ),
    binding!("wheel", "move selection one row per detent", &[]),
];

const SHARED_ACTIONS: &[Binding] = &[
    binding!(
        "s",
        "cycle memory lens",
        "s",
        "sort",
        commands![(Chord::Char('s'), Action::CycleMetric)]
    ),
    binding!(
        "r",
        "force an immediate shared-object rescan",
        "r",
        "rescan",
        commands![(Chord::Char('r'), Action::Refresh)]
    ),
];

#[must_use]
pub fn global_bindings() -> &'static [Binding] {
    GLOBAL_BINDINGS
}

#[must_use]
pub fn resolve(tab: Tab, key: KeyEvent) -> Option<Action> {
    GLOBAL_BINDINGS
        .iter()
        .chain(tab.navigation())
        .chain(tab.bindings())
        .find_map(|binding| binding.resolve(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pane_catalog_is_the_dispatch_boundary() {
        let plain = |character| KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE);
        assert_eq!(
            resolve(Tab::Processes, plain('m')),
            Some(Action::CycleScope)
        );
        assert_eq!(resolve(Tab::Shared, plain('m')), None);
        assert_eq!(resolve(Tab::Shared, plain('s')), Some(Action::CycleMetric));
        assert_eq!(resolve(Tab::Tmpfs, plain('s')), None);
    }
}
