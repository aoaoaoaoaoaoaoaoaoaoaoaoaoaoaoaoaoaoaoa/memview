#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def run(*argv: str) -> None:
    print(f"[publish] {' '.join(argv)}", flush=True)
    subprocess.run(argv, cwd=ROOT, check=True)


def output(*argv: str) -> str:
    return subprocess.check_output(argv, cwd=ROOT, text=True).strip()


def require_clean_worktree() -> None:
    status = output("git", "status", "--porcelain")
    if status:
        print("[publish] dirty worktree; commit or stash before publishing", file=sys.stderr)
        print(status, file=sys.stderr)
        raise SystemExit(1)


def sync_tracking_ref(remote: str) -> None:
    head = output("git", "ls-remote", remote, "refs/heads/main").split()[0]
    local = output("git", "rev-parse", "HEAD")
    if head != local:
        raise SystemExit(f"[publish] {remote}/main is {head}, expected {local}")
    run("git", "update-ref", f"refs/remotes/{remote}/main", head)


def main() -> None:
    require_clean_worktree()
    run("./check.py", "install")
    require_clean_worktree()
    run("git", "push", "--follow-tags", "swarm", "main")
    sync_tracking_ref("swarm")
    run("git", "push", "--follow-tags", "github", "main")
    sync_tracking_ref("github")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
