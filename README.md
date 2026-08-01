# memview

Linux-only RAM attribution TUI.

Covers processes, tmpfs, shared mappings, SysV shm, kernel counters, and physical-RAM residuals.
NVIDIA open-driver system page pools are measured through shrinker debugfs when readable and
otherwise remain visible inside the direct/unclassified residual.

```bash
cargo install memview --locked
memview
```

Press `?` for keys.
