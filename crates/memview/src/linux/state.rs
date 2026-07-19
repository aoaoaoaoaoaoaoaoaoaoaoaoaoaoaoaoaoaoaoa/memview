use super::app::{TreeScope, UiState};
use super::model::Metric;
use super::nav::Tab;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const STATE_VERSION: &str = "v1";

trait StateAtom: Copy + Sized {
    const UNKNOWN: &'static str;

    fn token(self) -> &'static str;
    fn parse(token: &str) -> Option<Self>;
}

macro_rules! state_atoms {
    ($($ty:ty, $unknown:literal => {$($variant:path = $token:literal),+ $(,)?});+ $(;)?) => {
        $(impl StateAtom for $ty {
            const UNKNOWN: &'static str = $unknown;

            fn token(self) -> &'static str {
                match self {$($variant => $token),+}
            }

            fn parse(token: &str) -> Option<Self> {
                match token {$($token => Some($variant),)+ _ => None}
            }
        })+
    };
}

state_atoms! {
    Tab, "unknown pane" => {
        Tab::Overview = "overview",
        Tab::Processes = "processes",
        Tab::Tmpfs = "tmpfs",
        Tab::Shared = "shared",
    };
    Metric, "unknown metric" => {
        Metric::Pss = "pss",
        Metric::Uss = "uss",
        Metric::Rss = "rss",
        Metric::SwapPss = "swap-pss",
        Metric::Anonymous = "anonymous",
        Metric::File = "file",
        Metric::Shmem = "shmem",
    };
    TreeScope, "unknown tree scope" => {
        TreeScope::SelfOnly = "self",
        TreeScope::SelfAndChildren = "self+children",
    };
}

pub struct UiStateStore {
    path: Option<PathBuf>,
    persisted: Option<UiState>,
    restored: UiState,
    warning: Option<String>,
}

impl UiStateStore {
    #[must_use]
    pub fn discover() -> Self {
        let Some(path) = state_path(
            env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            env::var_os("HOME").map(PathBuf::from),
        ) else {
            return Self {
                path: None,
                persisted: None,
                restored: UiState::default(),
                warning: Some(
                    "UI state disabled: neither XDG_STATE_HOME nor HOME names an absolute path"
                        .to_string(),
                ),
            };
        };
        Self::restore(path)
    }

    fn restore(path: PathBuf) -> Self {
        match fs::read_to_string(&path) {
            Ok(encoded) => match decode(&encoded) {
                Ok(restored) => Self {
                    path: Some(path),
                    persisted: Some(restored),
                    restored,
                    warning: None,
                },
                Err(problem) => Self {
                    warning: Some(format!(
                        "ignored invalid UI state at {}: {problem}",
                        path.display()
                    )),
                    path: Some(path),
                    persisted: None,
                    restored: UiState::default(),
                },
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self {
                path: Some(path),
                persisted: None,
                restored: UiState::default(),
                warning: None,
            },
            Err(error) => Self {
                warning: Some(format!(
                    "could not read UI state at {}: {error}",
                    path.display()
                )),
                path: Some(path),
                persisted: None,
                restored: UiState::default(),
            },
        }
    }

    #[must_use]
    pub fn restored(&self) -> UiState {
        self.restored
    }

    pub fn take_warning(&mut self) -> Option<String> {
        self.warning.take()
    }

    pub fn sync(&mut self, state: UiState) -> Option<String> {
        if self.persisted == Some(state) {
            return None;
        }
        let path = self.path.clone()?;
        match atomic_write(&path, encode(state).as_bytes()) {
            Ok(()) => {
                self.persisted = Some(state);
                None
            }
            Err(error) => {
                self.path = None;
                Some(format!(
                    "UI state persistence disabled after write to {} failed: {error}",
                    path.display()
                ))
            }
        }
    }
}

fn state_path(xdg_state_home: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    xdg_state_home
        .filter(|path| path.is_absolute())
        .or_else(|| {
            home.filter(|path| path.is_absolute())
                .map(|path| path.join(".local/state"))
        })
        .map(|root| root.join("memview/ui-state"))
}

fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UI state path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(".ui-state.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&staging)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&staging, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(staging);
    }
    result
}

fn encode(state: UiState) -> String {
    format!(
        "{STATE_VERSION} {} {} {}\n",
        state.tab.token(),
        state.metric.token(),
        state.tree_scope.token()
    )
}

fn decode(encoded: &str) -> Result<UiState, &'static str> {
    let mut fields = encoded.split_ascii_whitespace();
    let (Some(version), Some(tab), Some(metric), Some(scope), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err("expected four fields");
    };
    if version != STATE_VERSION {
        return Err("unsupported state version");
    }
    Ok(UiState {
        tab: decode_atom(tab)?,
        metric: decode_atom(metric)?,
        tree_scope: decode_atom(scope)?,
    })
}

fn decode_atom<T: StateAtom>(token: &str) -> Result<T, &'static str> {
    T::parse(token).ok_or(T::UNKNOWN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_spans_the_closed_ui_state_product() {
        let metrics = [
            Metric::Pss,
            Metric::Uss,
            Metric::Rss,
            Metric::SwapPss,
            Metric::Anonymous,
            Metric::File,
            Metric::Shmem,
        ];
        let scopes = [TreeScope::SelfOnly, TreeScope::SelfAndChildren];
        for tab in Tab::ALL {
            for metric in metrics {
                for tree_scope in scopes {
                    let state = UiState {
                        tab,
                        metric,
                        tree_scope,
                    };
                    assert_eq!(decode(&encode(state)), Ok(state));
                }
            }
        }
    }

    #[test]
    fn xdg_state_home_precedes_home_fallback() {
        assert_eq!(
            state_path(Some("/state".into()), Some("/home/me".into())),
            Some(PathBuf::from("/state/memview/ui-state"))
        );
        assert_eq!(
            state_path(Some("relative".into()), Some("/home/me".into())),
            Some(PathBuf::from("/home/me/.local/state/memview/ui-state"))
        );
        assert_eq!(state_path(None, Some("relative".into())), None);
    }

    #[test]
    fn malformed_state_is_rejected() {
        assert_eq!(
            decode("v2 processes pss self"),
            Err("unsupported state version")
        );
        assert_eq!(decode("v1 process pss self"), Err("unknown pane"));
        assert_eq!(decode("v1 processes pss"), Err("expected four fields"));
    }

    #[test]
    fn store_round_trips_through_an_atomic_private_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = env::temp_dir().join(format!("memview-state-test-{}", std::process::id()));
        let path = root.join("memview/ui-state");
        let _ = fs::remove_dir_all(&root);
        let state = UiState {
            tab: Tab::Shared,
            metric: Metric::Uss,
            tree_scope: TreeScope::SelfAndChildren,
        };

        let mut store = UiStateStore::restore(path.clone());
        assert_eq!(store.sync(state), None);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let restored = UiStateStore::restore(path);
        assert_eq!(restored.restored(), state);
        assert!(restored.warning.is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
