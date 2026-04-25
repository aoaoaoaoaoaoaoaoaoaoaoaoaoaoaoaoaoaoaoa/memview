# memview

`memview` is a Linux-only terminal UI for attributing RAM usage across the
surfaces that usually make totals feel impossible to reconcile: processes,
tmpfs, shared mappings, SysV shm, and kernel counters.

It is intentionally not cross-platform. The tool reads Linux `/proc`, tmpfs
mount metadata, smaps on demand, and pidfd process-control surfaces.

## Install

```bash
cargo install --path crates/memview --locked --profile release
```

## Use

```bash
memview
```

The default pane is `Processes`. Press `?` inside the TUI for global and
pane-specific controls.
