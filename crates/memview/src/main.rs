#[cfg(target_os = "linux")]
mod app;
#[cfg(target_os = "linux")]
mod linux;
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

#[cfg(not(target_os = "linux"))]
mod unsupported;

#[cfg(target_os = "linux")]
fn main() -> color_eyre::eyre::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    unsupported::run();
}
