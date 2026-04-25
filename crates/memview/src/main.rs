#[cfg(target_os = "linux")]
mod app;
#[cfg(target_os = "linux")]
mod model;
#[cfg(target_os = "linux")]
mod nav;
#[cfg(target_os = "linux")]
mod probe;
#[cfg(target_os = "linux")]
mod search;
#[cfg(target_os = "linux")]
mod ui;

#[cfg(target_os = "linux")]
use crate::app::{App, WorkerCommand, spawn_worker};
#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use color_eyre::eyre::Result;
#[cfg(target_os = "linux")]
use crossterm::cursor::{Hide, Show};
#[cfg(target_os = "linux")]
use crossterm::event::{
    self, DisableFocusChange, DisableMouseCapture, EnableFocusChange, EnableMouseCapture, Event,
    KeyEventKind,
};
#[cfg(target_os = "linux")]
use crossterm::execute;
#[cfg(target_os = "linux")]
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
#[cfg(target_os = "linux")]
use ratatui::Terminal;
#[cfg(target_os = "linux")]
use ratatui::backend::CrosstermBackend;
#[cfg(target_os = "linux")]
use std::io::{self, Stdout};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const FOCUSED_IDLE_POLL: Duration = Duration::from_millis(500);
#[cfg(target_os = "linux")]
const BACKGROUND_IDLE_POLL: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const ANIMATED_REDRAW: Duration = Duration::from_millis(250);

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
#[command(author, version, about = "ncdu-like RAM accounting for Linux /proc")]
struct Cli {
    #[arg(long, default_value_t = 5000)]
    refresh_ms: u64,
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    let (commands, events) = spawn_worker(Duration::from_millis(cli.refresh_ms));
    let mut terminal = TerminalGuard::enter()?;
    let mut app = App::new();
    app.set_terminal_height(terminal.height()?);
    app.start_visible_work(&commands);
    let mut dirty = true;
    let mut next_animated_redraw = Instant::now();

    loop {
        while let Ok(event) = events.try_recv() {
            app.apply_worker_event(event, &commands);
            dirty = true;
        }
        if app.poll_deletion(&commands) {
            dirty = true;
        }

        let now = Instant::now();
        let redraw_animation = app.needs_periodic_redraw() && now >= next_animated_redraw;
        if app.is_focused() && (dirty || redraw_animation) {
            terminal.draw(|frame| ui::render(frame, &app))?;
            dirty = false;
            next_animated_redraw = Instant::now() + ANIMATED_REDRAW;
        }

        if event::poll(poll_timeout(&app, next_animated_redraw))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if app.handle_key(key, &commands) {
                        break;
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
    }

    let _ = commands.send(WorkerCommand::Shutdown);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("memview is not supported on this system: Linux is required.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

#[cfg(target_os = "linux")]
impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
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
        Ok(Self { terminal })
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

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            Show,
            DisableFocusChange,
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = self.terminal.show_cursor();
    }
}
