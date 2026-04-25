#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def run(*argv: str) -> None:
    print(f"[publish] {' '.join(argv)}", flush=True)
    subprocess.run(argv, cwd=ROOT, check=True)


def main() -> None:
    run("./check.py", "install")
    run("git", "push", "swarm", "main")
    run("git", "push", "github", "main")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
