#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
REGISTRY_TOKEN = Path("/home/main/security/main.token")


@dataclass(frozen=True, order=True, slots=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> Version:
        parts = raw.split(".")
        if len(parts) != 3:
            raise SystemExit(f"[publish] expected x.y.z version, got {raw!r}")
        try:
            major, minor, patch = (int(part) for part in parts)
        except ValueError as error:
            raise SystemExit(f"[publish] expected numeric x.y.z version, got {raw!r}") from error
        return cls(major, minor, patch)

    def next_patch(self) -> Version:
        return Version(self.major, self.minor, self.patch + 1)

    def tag(self) -> str:
        return f"v{self}"

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


def run(*argv: str) -> None:
    print(f"[publish] {' '.join(argv)}", flush=True)
    subprocess.run(argv, cwd=ROOT, check=True)


def output(*argv: str) -> str:
    return subprocess.check_output(argv, cwd=ROOT, text=True).strip()


def run_with_token(*argv: str) -> None:
    token = registry_token()
    print(f"[publish] {' '.join(argv)}", flush=True)
    subprocess.run(
        argv,
        cwd=ROOT,
        check=True,
        env={**dict(os.environ), "CARGO_REGISTRY_TOKEN": token},
    )


def require_clean_worktree() -> None:
    status = output("git", "status", "--porcelain")
    if status:
        print("[publish] dirty worktree; commit or stash before publishing", file=sys.stderr)
        print(status, file=sys.stderr)
        raise SystemExit(1)


def current_version() -> Version:
    workspace = tomllib.loads(WORKSPACE_MANIFEST.read_text(encoding="utf-8"))
    return Version.parse(workspace["workspace"]["package"]["version"])


def replace_workspace_version(old: Version, new: Version) -> None:
    text = WORKSPACE_MANIFEST.read_text(encoding="utf-8")
    old_line = f'version = "{old}"'
    new_line = f'version = "{new}"'
    if old_line not in text:
        raise SystemExit(f"[publish] could not find workspace {old_line}")
    WORKSPACE_MANIFEST.write_text(text.replace(old_line, new_line, 1), encoding="utf-8")


def release_tags() -> list[Version]:
    tags = output("git", "tag", "--list", "v[0-9]*")
    versions = []
    for tag in tags.splitlines():
        try:
            versions.append(Version.parse(tag.removeprefix("v")))
        except SystemExit:
            continue
    return sorted(versions)


def rev_parse(rev: str) -> str | None:
    try:
        return output("git", "rev-list", "-n", "1", rev)
    except subprocess.CalledProcessError:
        return None


def prepare_version() -> Version | None:
    version = current_version()
    tags = release_tags()
    if not tags:
        return version

    latest = tags[-1]
    head = output("git", "rev-parse", "HEAD")
    latest_commit = rev_parse(latest.tag())

    if version < latest:
        raise SystemExit(f"[publish] Cargo version {version} is behind latest tag {latest.tag()}")
    if version > latest:
        print(f"[publish] manual version bump detected: {version}", flush=True)
        return version
    if latest_commit == head:
        print(f"[publish] HEAD is already {latest.tag()}; skipping crates.io publish", flush=True)
        return None

    bumped = version.next_patch()
    print(f"[publish] autobumping {version} -> {bumped}", flush=True)
    replace_workspace_version(version, bumped)
    run("cargo", "check", "-p", "memview")
    run("git", "add", "Cargo.toml", "Cargo.lock")
    run("git", "commit", "-m", f"Release memview {bumped}")
    return bumped


def ensure_tag(version: Version) -> None:
    tag = version.tag()
    head = output("git", "rev-parse", "HEAD")
    tag_commit = rev_parse(tag)
    if tag_commit is None:
        run("git", "tag", "-a", tag, "-m", f"memview {version}")
        return
    if tag_commit != head:
        raise SystemExit(f"[publish] {tag} points at {tag_commit}, not HEAD {head}")


def registry_token() -> str:
    token = os.environ.get("CARGO_REGISTRY_TOKEN")
    if token:
        return token
    if not REGISTRY_TOKEN.is_file():
        raise SystemExit(f"[publish] missing crates.io token file: {REGISTRY_TOKEN}")
    token = REGISTRY_TOKEN.read_text(encoding="utf-8").strip()
    if not token:
        raise SystemExit(f"[publish] empty crates.io token file: {REGISTRY_TOKEN}")
    return token


def publish_crate(version: Version) -> None:
    run("./check.py", "verify")
    run("cargo", "publish", "--dry-run", "--locked", "-p", "memview")
    run_with_token("cargo", "publish", "--locked", "-p", "memview")
    ensure_tag(version)


def verify_remote(remote: str) -> None:
    head = output("git", "ls-remote", remote, "refs/heads/main").split()[0]
    local = output("git", "rev-parse", "HEAD")
    if head != local:
        raise SystemExit(f"[publish] {remote}/main is {head}, expected {local}")
    print(f"[publish] verified {remote}/main {head}", flush=True)


def main() -> None:
    require_clean_worktree()
    release = prepare_version()
    require_clean_worktree()
    if release is not None:
        publish_crate(release)
    run("./check.py", "install")
    require_clean_worktree()
    run("git", "push", "--follow-tags", "swarm", "main")
    verify_remote("swarm")
    run("git", "push", "--follow-tags", "github", "main")
    verify_remote("github")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
