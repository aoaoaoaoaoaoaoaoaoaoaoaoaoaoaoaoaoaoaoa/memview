#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(not(target_os = "linux"), path = "unsupported.rs")]
mod platform;

fn main() -> platform::MainResult {
    platform::run()
}
