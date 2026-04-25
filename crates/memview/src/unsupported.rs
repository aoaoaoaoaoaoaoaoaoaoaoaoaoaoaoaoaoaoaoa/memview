use std::process::ExitCode;

pub type MainResult = ExitCode;

pub fn run() -> MainResult {
    eprintln!("memview is not supported on this system: Linux is required.");
    ExitCode::FAILURE
}
