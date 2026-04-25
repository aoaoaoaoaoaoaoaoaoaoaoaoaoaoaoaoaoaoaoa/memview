# AGENTS.md

Before meaningful Rust edits, read the [Rust Style Doctrine](/home/main/programming/projects/rust_starter/docs/rust-style-doctrine.md).
It intentionally rejects several pieces of conventional Rust advice; preserve
those inversions instead of translating them back into generic approachable
code.

Local rules:

- The only permitted child/subagent is `clippy_fixer`, and only for
  `$clippy-fix`. Do not invoke any other agent kind.
- Prefer explicit domain types, enums, newtypes, and total transforms over
  stringly state, bool flags, and ad-hoc tuples.
- Use `rust-analyzer` before textual search when you need definitions,
  references, diagnostics, or refactors.
- Default to deletion over backward-compatibility shims when the task does not
  explicitly require compatibility.
- Run `cargo fmt` after meaningful edits.
- Run `./check.py check` after meaningful local edits. Use `./check.py verify`
  for a non-mutating CI-style gate.
