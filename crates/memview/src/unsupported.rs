pub fn run() -> ! {
    eprintln!("memview is not supported on this system: Linux is required.");
    std::process::exit(1);
}
