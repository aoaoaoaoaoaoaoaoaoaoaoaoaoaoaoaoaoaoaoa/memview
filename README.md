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

`memview` requires interactive stdin and stdout. Use `--refresh-ms N` to change the process refresh
period from its 5000 ms default. Press `?` for the complete, scrollable key catalogue and accounting
notes.

The only mutating action sends SIGTERM after a named, delayed confirmation through a pidfd. Reading
other users' procfs data and NVIDIA shrinker counters depends on host permissions; do not run the
whole TUI as root merely to widen accounting. Pane, metric, and tree-scope preferences persist in
`$XDG_STATE_HOME/memview/ui-state`, falling back to `~/.local/state/memview/ui-state`.

Licensed under the [MIT License](LICENSE). The generated
[`THIRD-PARTY-LICENSES.html`](crates/memview/THIRD-PARTY-LICENSES.html) records the license
disposition of the locked dependency graph.
