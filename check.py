#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath


ROOT = Path(__file__).resolve().parent
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
DEFAULT_MAX_SOURCE_FILE_LINES = 2500
DEFAULT_SOURCE_FILE_INCLUDE = ("*.rs", "**/*.rs")
IGNORED_SOURCE_DIRS = frozenset(
    {".direnv", ".git", ".hg", ".jj", ".svn", "__pycache__", "node_modules", "target", "vendor"}
)
Command = tuple[str, ...]
CommandSequence = tuple[Command, ...]


@dataclass(frozen=True, slots=True)
class SourceFilePolicy:
    max_lines: int
    include: tuple[str, ...]
    exclude: tuple[str, ...]


def load_workspace_metadata() -> dict[str, object]:
    workspace = tomllib.loads(WORKSPACE_MANIFEST.read_text(encoding="utf-8"))
    return workspace["workspace"]["metadata"]["rust-starter"]


def load_command(value: object, *, key_path: str) -> Command:
    if not isinstance(value, list) or not value or not all(isinstance(part, str) and part for part in value):
        raise SystemExit(f"[check] invalid {key_path}: expected a non-empty string list")
    return tuple(value)


def load_command_sequence(value: object, *, key_path: str) -> CommandSequence:
    if not isinstance(value, list) or not value:
        raise SystemExit(f"[check] invalid {key_path}: expected a non-empty list of commands")

    commands: list[Command] = []
    for index, command in enumerate(value, start=1):
        commands.append(load_command(command, key_path=f"{key_path}[{index}]"))
    return tuple(commands)


def load_commands(metadata: dict[str, object]) -> dict[str, Command | CommandSequence]:
    commands: dict[str, Command | CommandSequence] = {
        "format_command": load_command(
            metadata.get("format_command"),
            key_path="workspace.metadata.rust-starter.format_command",
        ),
        "clippy_command": load_command(
            metadata.get("clippy_command"),
            key_path="workspace.metadata.rust-starter.clippy_command",
        ),
        "test_command": load_command(
            metadata.get("test_command"),
            key_path="workspace.metadata.rust-starter.test_command",
        ),
        "canonicalize_commands": load_command_sequence(
            metadata.get("canonicalize_commands"),
            key_path="workspace.metadata.rust-starter.canonicalize_commands",
        ),
    }

    raw_doc_command = metadata.get("doc_command")
    if raw_doc_command is not None:
        commands["doc_command"] = load_command(
            raw_doc_command,
            key_path="workspace.metadata.rust-starter.doc_command",
        )
    raw_install_command = metadata.get("install_command")
    if raw_install_command is not None:
        commands["install_command"] = load_command(
            raw_install_command,
            key_path="workspace.metadata.rust-starter.install_command",
        )
    return commands


def load_patterns(
    value: object,
    *,
    default: tuple[str, ...],
    key_path: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(pattern, str) and pattern for pattern in value):
        raise SystemExit(f"[check] invalid {key_path}: expected a string list")
    if not allow_empty and not value:
        raise SystemExit(f"[check] invalid {key_path}: expected at least one pattern")
    return tuple(value)


def load_source_file_policy(metadata: dict[str, object]) -> SourceFilePolicy:
    raw_policy = metadata.get("source_files")
    if raw_policy is None:
        return SourceFilePolicy(DEFAULT_MAX_SOURCE_FILE_LINES, DEFAULT_SOURCE_FILE_INCLUDE, ())
    if not isinstance(raw_policy, dict):
        raise SystemExit("[check] invalid workspace.metadata.rust-starter.source_files: expected a table")

    max_lines = raw_policy.get("max_lines", DEFAULT_MAX_SOURCE_FILE_LINES)
    if not isinstance(max_lines, int) or max_lines <= 0:
        raise SystemExit(
            "[check] invalid workspace.metadata.rust-starter.source_files.max_lines: expected a positive integer"
        )

    include = load_patterns(
        raw_policy.get("include"),
        default=DEFAULT_SOURCE_FILE_INCLUDE,
        key_path="workspace.metadata.rust-starter.source_files.include",
        allow_empty=False,
    )
    exclude = load_patterns(
        raw_policy.get("exclude"),
        default=(),
        key_path="workspace.metadata.rust-starter.source_files.exclude",
        allow_empty=True,
    )
    return SourceFilePolicy(max_lines, include, exclude)


def run(name: str, argv: Command) -> None:
    print(f"[check] {name}: {' '.join(argv)}", flush=True)
    proc = subprocess.run(argv, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def verify_python_sources() -> None:
    print("[check] python: compile check.py publish.py", flush=True)
    for path in (ROOT / "check.py", ROOT / "publish.py"):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    before = subprocess.check_output(("git", "status", "--porcelain"), cwd=ROOT)
    for argv in (("--help",), ("release", "--help")):
        subprocess.run(
            (sys.executable, str(ROOT / "publish.py"), *argv),
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )
    after = subprocess.check_output(("git", "status", "--porcelain"), cwd=ROOT)
    if before != after:
        raise SystemExit("[check] publisher inquiry mutated the worktree")


def verify_generated_licenses() -> None:
    print("[check] licenses: regenerate locked third-party notice", flush=True)
    with tempfile.TemporaryDirectory(prefix="memview-licenses-") as scratch:
        generated = Path(scratch) / "THIRD-PARTY-LICENSES.html"
        proc = subprocess.run(
            (
                "cargo",
                "about",
                "generate",
                "--locked",
                "--fail",
                "--offline",
                "-o",
                str(generated),
                "about.hbs",
            ),
            cwd=ROOT,
        )
        if proc.returncode != 0:
            raise SystemExit(proc.returncode)
        committed = ROOT / "crates/memview/THIRD-PARTY-LICENSES.html"
        if generated.read_bytes() != committed.read_bytes():
            raise SystemExit(
                "[check] THIRD-PARTY-LICENSES.html is stale; regenerate it with cargo-about"
            )


def binary_path() -> Path:
    metadata = json.loads(
        subprocess.check_output(
            ("cargo", "metadata", "--format-version", "1", "--locked", "--no-deps"),
            cwd=ROOT,
            text=True,
        )
    )
    return Path(metadata["target_directory"]) / "debug" / "memview"


def drain_pty(master: int, deadline: float) -> bytes:
    output = bytearray()
    while time.monotonic() < deadline:
        readable, _, _ = select.select((master,), (), (), 0.05)
        if not readable:
            continue
        try:
            output.extend(os.read(master, 65_536))
        except OSError:
            break
    return bytes(output)


def verify_terminal_exit(binary: Path, exit_signal: signal.Signals | None) -> None:
    master, slave = pty.openpty()
    baseline = termios.tcgetattr(slave)
    with tempfile.TemporaryDirectory(prefix="memview-state-") as state_home:
        process = subprocess.Popen(
            (str(binary), "--refresh-ms", "60000"),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env={**os.environ, "XDG_STATE_HOME": state_home},
            start_new_session=True,
        )
        output = drain_pty(master, time.monotonic() + 0.5)
        if exit_signal is None:
            os.write(master, b"q")
            expected = 0
        else:
            process.send_signal(exit_signal)
            expected = 128 + exit_signal.value
        try:
            returncode = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise SystemExit(f"[check] terminal lifecycle hung for {exit_signal or 'quit'}") from None
        output += drain_pty(master, time.monotonic() + 0.25)
    restored = termios.tcgetattr(slave)
    os.close(master)
    os.close(slave)
    if returncode != expected:
        raise SystemExit(
            f"[check] terminal lifecycle returned {returncode}, expected {expected} for "
            f"{exit_signal or 'quit'}"
        )
    if baseline != restored:
        raise SystemExit(f"[check] terminal attributes leaked after {exit_signal or 'quit'}")
    if b"\x1b[?1049h" not in output or b"\x1b[?1049l" not in output:
        raise SystemExit(f"[check] alternate-screen restoration absent for {exit_signal or 'quit'}")


def verify_terminal_lifecycle() -> None:
    run("terminal.build", ("cargo", "build", "--locked", "-p", "memview"))
    binary = binary_path()
    print("[check] terminal: non-TTY, quit, SIGHUP, SIGTERM", flush=True)
    non_tty = subprocess.run(
        (str(binary),), cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, text=True
    )
    if non_tty.returncode == 0 or "requires an interactive terminal" not in non_tty.stderr:
        raise SystemExit("[check] non-TTY invocation lacks its explicit prerequisite diagnostic")
    for exit_signal in (None, signal.SIGHUP, signal.SIGTERM):
        verify_terminal_exit(binary, exit_signal)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Thin Rust starter check runner")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("check", "verify", "deep", "fix", "canon", "install"),
        default="check",
        help=(
            "Run canonicalization plus the fast gate, run a non-mutating verification gate, "
            "include docs for the deep gate, run only canonicalization, or install locally."
        ),
    )
    return parser.parse_args()


def run_command_sequence(name: str, commands: CommandSequence) -> None:
    for index, command in enumerate(commands, start=1):
        run(f"{name}.{index}", command)


def matches_pattern(path: PurePosixPath, pattern: str) -> bool:
    if path.match(pattern):
        return True
    prefix = "**/"
    return pattern.startswith(prefix) and path.match(pattern.removeprefix(prefix))


def iter_source_files(policy: SourceFilePolicy) -> list[Path]:
    paths: list[Path] = []
    for current_root, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(name for name in dirnames if name not in IGNORED_SOURCE_DIRS)
        current = Path(current_root)
        for filename in filenames:
            path = current / filename
            relative_path = PurePosixPath(path.relative_to(ROOT).as_posix())
            if not any(matches_pattern(relative_path, pattern) for pattern in policy.include):
                continue
            if any(matches_pattern(relative_path, pattern) for pattern in policy.exclude):
                continue
            paths.append(path)
    return sorted(paths)


def line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def enforce_source_file_policy(policy: SourceFilePolicy) -> None:
    paths = iter_source_files(policy)
    print(f"[check] source-files: max {policy.max_lines} lines", flush=True)
    violations: list[tuple[str, int]] = []
    for path in paths:
        lines = line_count(path)
        if lines > policy.max_lines:
            violations.append((path.relative_to(ROOT).as_posix(), lines))
    if not violations:
        return

    print(
        f"[check] source-files: {len(violations)} file(s) exceed the configured limit",
        flush=True,
    )
    for relative_path, lines in violations:
        print(f"[check] source-files: {relative_path}: {lines} lines", flush=True)
    raise SystemExit(1)


def main() -> None:
    metadata = load_workspace_metadata()
    commands = load_commands(metadata)
    source_file_policy = load_source_file_policy(metadata)
    args = parse_args()

    if args.mode in {"fix", "canon"}:
        run_command_sequence("canonicalize", commands["canonicalize_commands"])
        return

    enforce_source_file_policy(source_file_policy)
    verify_python_sources()
    if args.mode != "verify":
        run_command_sequence("canonicalize", commands["canonicalize_commands"])

    run("fmt", commands["format_command"])
    run("clippy", commands["clippy_command"])
    run("test", commands["test_command"])

    if args.mode in {"verify", "deep", "install"} and "doc_command" in commands:
        run("doc", commands["doc_command"])
        run("audit", ("cargo", "audit"))
        verify_generated_licenses()
        verify_terminal_lifecycle()
    if args.mode == "install":
        run("install", commands["install_command"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
