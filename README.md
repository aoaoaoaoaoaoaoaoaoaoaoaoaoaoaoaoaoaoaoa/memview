# memview

`memview` is an interactive Linux terminal for investigating physical RAM through independent,
time-stamped kernel views:

- process PSS, USS, RSS, SwapPSS, and PSS categories, with explicit status-RSS fallback coverage
- tmpfs allocated blocks and logical sizes
- mapped objects and their visible process consumers, including tmpfs, memfd, SysV, files, and
  anonymous regions
- `/proc/meminfo`, SysV shm, an approximate physical-counter residual, and NVIDIA open-driver
  system page pools when shrinker debugfs is readable

These views are not one atomic partition. Procfs can race, permissions can hide tasks or mappings,
and meminfo counters can overlap or omit subsystem ownership. The UI exposes capture intervals,
coverage, warnings, and unavailable NVIDIA accounting rather than treating omissions as zero.

```bash
cargo install memview --locked
memview
```

`memview` requires interactive stdin and stdout. Process updates pause after 30 seconds without
keyboard or scroll input, or immediately when the terminal reports losing focus. A `PAUSED`
indicator shows why. Terminal focus is a conservative proxy for visibility: a visible but unfocused
window also pauses; terminals without focus reporting still pause on inactivity. Interaction resumes updates;
`r` requests an immediate refresh. Automatic scans wait at least 99 times the preceding scan's
elapsed time, targeting at most a 1% scan duty cycle. `--refresh-ms N` sets the minimum delay
(default 5000 ms), not a fixed sampling period. In-flight scans finish normally. Overview does not
walk tmpfs; that work runs only in the tmpfs pane. Press `?` for the complete, scrollable key
catalogue and accounting notes.

The only mutating action sends SIGTERM after a named, delayed confirmation through a pidfd. Reading
other users' procfs data and NVIDIA shrinker counters depends on host permissions; do not run the
whole TUI as root merely to widen accounting. Pane, metric, and tree-scope preferences persist in
`$XDG_STATE_HOME/memview/ui-state`, falling back to `~/.local/state/memview/ui-state`.

Licensed under the [MIT License](LICENSE). The generated
[`THIRD-PARTY-LICENSES.html`](crates/memview/THIRD-PARTY-LICENSES.html) records the license
disposition of the locked dependency graph.
