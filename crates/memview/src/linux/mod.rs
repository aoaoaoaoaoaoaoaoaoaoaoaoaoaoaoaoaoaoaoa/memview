mod app;
mod model;
mod nav;
mod probe;
mod search;
mod state;
mod ui;

use app::{App, spawn_worker};
use clap::Parser;
use color_eyre::eyre::{Result, ensure};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{
    self, DisableFocusChange, DisableMouseCapture, EnableFocusChange, EnableMouseCapture, Event,
    KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use state::UiStateStore;
use std::io::{self, IsTerminal, Stdout};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const FOCUSED_IDLE_POLL: Duration = Duration::from_millis(500);
const BACKGROUND_IDLE_POLL: Duration = Duration::from_secs(1);
const ANIMATED_REDRAW: Duration = Duration::from_millis(250);

#[derive(Debug, Parser)]
#[command(author, version, about = "ncdu-like RAM accounting for Linux /proc")]
struct Cli {
    #[arg(long, default_value_t = 5000)]
    refresh_ms: u64,
}

pub type MainResult = Result<()>;

pub fn run() -> MainResult {
    color_eyre::install()?;
    let cli = Cli::parse();
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "memview requires an interactive terminal on stdin and stdout"
    );
    let termination = TerminationFlag::install()?;
    let (commands, events) = spawn_worker(Duration::from_millis(cli.refresh_ms));
    let mut state_store = UiStateStore::discover();
    let mut terminal = TerminalGuard::enter()?;
    let mut app = App::new(state_store.restored());
    app.last_error = state_store.take_warning();
    if let Some(warning) = state_store.sync(app.ui_state()) {
        app.last_error = Some(warning);
    }
    app.set_terminal_height(terminal.height()?);
    app.start_visible_work(&commands);
    let mut dirty = true;
    let mut next_animated_redraw = Instant::now();

    let termination_signal = loop {
        if let Some(signal) = termination.pending() {
            break Some(signal);
        }
        while let Ok(event) = events.try_recv() {
            app.apply_worker_event(event, &commands);
            dirty = true;
        }

        let now = Instant::now();
        let redraw_animation = app.needs_periodic_redraw() && now >= next_animated_redraw;
        if app.is_focused() && (dirty || redraw_animation) {
            terminal.draw(|frame| ui::render(frame, &app))?;
            dirty = false;
            next_animated_redraw = Instant::now() + ANIMATED_REDRAW;
        }

        let input_ready = match event::poll(poll_timeout(&app, next_animated_redraw)) {
            Ok(input_ready) => input_ready,
            Err(_) if termination.pending().is_some() => break termination.pending(),
            Err(error) => return Err(error.into()),
        };
        if input_ready {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    let quit = app.handle_key(key, &commands);
                    if let Some(warning) = state_store.sync(app.ui_state()) {
                        app.last_error = Some(warning);
                    }
                    if quit {
                        break None;
                    }
                    dirty = true;
                }
                Event::Mouse(mouse) => {
                    if app.handle_mouse(mouse, &commands) {
                        dirty = true;
                    }
                }
                Event::Resize(_, height) => {
                    app.set_terminal_height(height);
                    dirty = true;
                }
                Event::FocusGained => {
                    app.set_focused(true, &commands);
                    dirty = true;
                }
                Event::FocusLost => {
                    app.set_focused(false, &commands);
                    dirty = false;
                }
                Event::Paste(_) => {}
            }
        }
    };

    commands.shutdown();
    drop(terminal);
    if let Some(signal) = termination_signal {
        std::process::exit(128 + signal);
    }
    Ok(())
}

struct TerminationFlag(Arc<AtomicUsize>);

impl TerminationFlag {
    fn install() -> Result<Self> {
        use signal_hook::consts::signal::{SIGHUP, SIGTERM};

        let pending = Arc::new(AtomicUsize::new(0));
        let _hangup = signal_hook::flag::register_usize(
            SIGHUP,
            Arc::clone(&pending),
            usize::try_from(SIGHUP)?,
        )?;
        let _terminate = signal_hook::flag::register_usize(
            SIGTERM,
            Arc::clone(&pending),
            usize::try_from(SIGTERM)?,
        )?;
        Ok(Self(pending))
    }

    #[must_use]
    fn pending(&self) -> Option<i32> {
        i32::try_from(self.0.load(Ordering::SeqCst))
            .ok()
            .filter(|signal| *signal != 0)
    }
}

fn poll_timeout(app: &App, next_animated_redraw: Instant) -> Duration {
    if !app.is_focused() {
        return BACKGROUND_IDLE_POLL;
    }
    if app.needs_periodic_redraw() {
        FOCUSED_IDLE_POLL.min(next_animated_redraw.saturating_duration_since(Instant::now()))
    } else {
        FOCUSED_IDLE_POLL
    }
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    _restore: TerminalState,
}

struct TerminalState;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let restore = TerminalState;
        let mut stdout = io::stdout();
        execute!(
            stdout,
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableFocusChange,
            Hide
        )?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self {
            terminal,
            _restore: restore,
        })
    }

    fn draw<F>(&mut self, draw: F) -> Result<()>
    where
        F: FnOnce(&mut ratatui::Frame<'_>),
    {
        let _ = self.terminal.draw(draw)?;
        Ok(())
    }

    fn height(&self) -> Result<u16> {
        Ok(self.terminal.size()?.height)
    }
}

impl Drop for TerminalState {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            Show,
            DisableFocusChange,
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = disable_raw_mode();
    }
}
