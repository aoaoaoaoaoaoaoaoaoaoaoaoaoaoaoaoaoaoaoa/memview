#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
CRATES_IO_API = "https://crates.io/api/v1/crates/memview"
AUTHORITATIVE_REMOTES = ("swarm", "github")


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


def require_clean_worktree() -> None:
    status = output("git", "status", "--porcelain")
    if status:
        print("[publish] dirty worktree; commit or stash before releasing", file=sys.stderr)
        print(status, file=sys.stderr)
        raise SystemExit(1)


def current_version() -> Version:
    workspace = tomllib.loads(WORKSPACE_MANIFEST.read_text(encoding="utf-8"))
    return Version.parse(workspace["workspace"]["package"]["version"])


def replace_workspace_version(old: Version, new: Version) -> None:
    text = WORKSPACE_MANIFEST.read_text(encoding="utf-8")
    old_line = f'version = "{old}"'
    new_line = f'version = "{new}"'
    if text.count(old_line) != 1:
        raise SystemExit(f"[publish] expected one workspace {old_line}")
    WORKSPACE_MANIFEST.write_text(text.replace(old_line, new_line), encoding="utf-8")


def release_tags() -> list[Version]:
    versions = []
    for tag in output("git", "tag", "--list", "v[0-9]*").splitlines():
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


def crate_version_published(version: Version) -> bool:
    request = urllib.request.Request(
        CRATES_IO_API,
        headers={"User-Agent": "memview-publish/2.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise SystemExit(f"[publish] could not query crates.io: {error}") from error
    return any(entry.get("num") == str(version) for entry in payload.get("versions", []))


def planned_version(explicit: str | None) -> Version:
    current = current_version()
    tags = release_tags()
    latest = tags[-1] if tags else None
    head = output("git", "rev-parse", "HEAD")
    tagged_head = latest is not None and rev_parse(latest.tag()) == head

    if explicit is not None:
        planned = Version.parse(explicit)
    elif latest is None or current > latest or tagged_head:
        planned = current
    else:
        planned = current.next_patch()

    if latest is not None and planned < latest:
        raise SystemExit(f"[publish] planned {planned} is behind {latest.tag()}")
    if planned == latest and not tagged_head:
        raise SystemExit(f"[publish] {planned} is already tagged on another commit")
    return planned


def preflight_remotes() -> None:
    head = output("git", "rev-parse", "HEAD")
    for remote in AUTHORITATIVE_REMOTES:
        rows = output("git", "ls-remote", remote, "refs/heads/main").split()
        if len(rows) != 2:
            raise SystemExit(f"[publish] {remote} has no unambiguous main branch")
        remote_head = rows[0]
        if subprocess.run(
            ["git", "merge-base", "--is-ancestor", remote_head, head], cwd=ROOT
        ).returncode != 0:
            raise SystemExit(f"[publish] {remote}/main {remote_head} is not an ancestor of {head}")
        print(f"[publish] preflight {remote}/main {remote_head}", flush=True)


def prepare_release_commit(version: Version) -> None:
    current = current_version()
    if current == version:
        return
    replace_workspace_version(current, version)
    run("cargo", "check", "-p", "memview")
    run(
        "cargo",
        "about",
        "generate",
        "--locked",
        "--fail",
        "--offline",
        "-o",
        "crates/memview/THIRD-PARTY-LICENSES.html",
        "about.hbs",
    )
    run(
        "git",
        "add",
        "Cargo.toml",
        "Cargo.lock",
        "crates/memview/THIRD-PARTY-LICENSES.html",
    )
    run("git", "commit", "-m", f"Release memview {version}")


def ensure_tag(version: Version) -> None:
    tag = version.tag()
    head = output("git", "rev-parse", "HEAD")
    tagged = rev_parse(tag)
    if tagged is None:
        run("git", "tag", "-a", tag, "-m", f"memview {version}")
    elif tagged != head:
        raise SystemExit(f"[publish] {tag} points at {tagged}, not HEAD {head}")


def package_path(version: Version) -> Path:
    metadata = json.loads(output("cargo", "metadata", "--format-version", "1", "--locked"))
    return Path(metadata["target_directory"]) / "package" / f"memview-{version}.crate"


def seal_package(version: Version) -> str:
    run("cargo", "package", "--locked", "-p", "memview")
    package = package_path(version)
    head = output("git", "rev-parse", "HEAD")
    prefix = f"memview-{version}"
    with tarfile.open(package, "r:gz") as archive:
        names = set(archive.getnames())
        required = {
            f"{prefix}/.cargo_vcs_info.json",
            f"{prefix}/LICENSE",
            f"{prefix}/THIRD-PARTY-LICENSES.html",
        }
        if missing := sorted(required - names):
            raise SystemExit(f"[publish] package omits required files: {', '.join(missing)}")
        vcs_file = archive.extractfile(f"{prefix}/.cargo_vcs_info.json")
        if vcs_file is None:
            raise SystemExit("[publish] package VCS metadata is unreadable")
        vcs = json.load(vcs_file)
    if vcs.get("git", {}).get("sha1") != head or vcs.get("git", {}).get("dirty"):
        raise SystemExit(f"[publish] package provenance does not seal clean HEAD {head}")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    print(f"[publish] sealed {package} sha256={digest}", flush=True)
    return digest


def publish_source(version: Version) -> None:
    head = output("git", "rev-parse", "HEAD")
    tag = version.tag()
    for remote in AUTHORITATIVE_REMOTES:
        run("git", "push", "--atomic", remote, "main", tag)
        branch = output("git", "ls-remote", remote, "refs/heads/main").split()[0]
        peeled = output("git", "ls-remote", remote, f"refs/tags/{tag}^{{}}").split()[0]
        if branch != head or peeled != head:
            raise SystemExit(
                f"[publish] {remote} provenance mismatch: main={branch} {tag}={peeled} expected={head}"
            )
        print(f"[publish] verified {remote} main and {tag} at {head}", flush=True)


def release(explicit: str | None, install: bool) -> None:
    require_clean_worktree()
    preflight_remotes()
    version = planned_version(explicit)
    if crate_version_published(version):
        raise SystemExit(f"[publish] crates.io already contains {version}")
    prepare_release_commit(version)
    require_clean_worktree()
    run("./check.py", "verify")
    ensure_tag(version)
    seal_package(version)
    publish_source(version)
    run("cargo", "publish", "--locked", "-p", "memview")
    if install:
        run("./check.py", "install")
    print(f"[publish] released memview {version}", flush=True)


def plan(explicit: str | None) -> None:
    require_clean_worktree()
    preflight_remotes()
    version = planned_version(explicit)
    availability = "published" if crate_version_published(version) else "available"
    print(f"[publish] plan: memview {version} ({availability})", flush=True)
    print("[publish] commit/tag -> swarm -> github -> crates.io -> local install", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seal and publish a memview release after durable source provenance"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "release"):
        command = commands.add_parser(name)
        command.add_argument("--version", help="explicit x.y.z version; defaults to the next patch")
    commands.choices["release"].add_argument(
        "--no-install", action="store_true", help="skip the post-publication local install"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "plan":
        plan(args.version)
    else:
        release(args.version, not args.no_install)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
