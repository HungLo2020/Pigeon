#!/usr/bin/env python3
"""Start the Pigeon Tauri client against the repository's existing UI/core."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "src" / "client" / "frontend"


def require(command: str, install: str) -> None:
    if shutil.which(command) is None:
        print(f"RunClient.py: '{command}' is required. {install}", file=sys.stderr)
        raise SystemExit(2)


def run(command: list[str], environment: dict[str, str]) -> int:
    child = subprocess.Popen(command, cwd=ROOT, env=environment)
    try:
        return child.wait()
    except KeyboardInterrupt:
        print("\nStopping Pigeon client…", file=sys.stderr)
        child.terminate()
        try:
            return child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            return child.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="run Tauri in release mode")
    args = parser.parse_args()
    require("cargo", "Install Rust with: https://rustup.rs/")
    require("npm", "Install Node.js/npm, then run: npm --prefix src/client/frontend install")
    if not (FRONTEND / "node_modules").is_dir():
        print("RunClient.py: frontend dependencies are missing. Run: npm --prefix src/client/frontend install", file=sys.stderr)
        return 2

    # Tauri invokes the existing CLI core for all protocol work. Build it here
    # and pass its repository-relative output explicitly instead of requiring a
    # globally installed pigeon-client binary.
    profile = "release" if args.release else "debug"
    build = ["cargo", "build", "-p", "pigeon-client"]
    if args.release:
        build.append("--release")
    if subprocess.run(build, cwd=ROOT).returncode:
        return 1
    core_binary = ROOT / "target" / profile / "pigeon-client"
    environment = os.environ.copy()
    environment["PIGEON_CLIENT_BIN"] = str(core_binary)
    print("Starting Pigeon Tauri client")
    print(f"  Repository: {ROOT}")
    print(f"  Client core: {core_binary}")
    print("  Account state: normal Tauri application-data location (preserved between runs)")
    print("  Stop with Ctrl+C.")
    command = ["cargo", "tauri", "dev", "--config", "src/client/tauri/tauri.conf.json"]
    if args.release:
        command.append("--release")
    return run(command, environment)


if __name__ == "__main__":
    raise SystemExit(main())
