#[cfg(not(target_os = "linux"))]
compile_error!("memview is Linux-only: it reads Linux /proc, tmpfs, SysV shm, and pidfd surfaces.");

mod app;
mod model;
mod nav;
mod probe;
mod search;
mod ui;

use crate::app::{App, WorkerCommand, spawn_worker};
use clap::Parser;
use color_eyre::eyre::Result;
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
use std::io::{self, Stdout};
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
}

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
