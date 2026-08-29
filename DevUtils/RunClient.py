#!/usr/bin/env python3
"""Start the Pigeon Tauri client against the repository's existing UI/core."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "src" / "client" / "frontend"
LOCAL_RELAY_CERTIFICATE = ROOT / "DevUtils" / "local-relay" / "pigeon-server-cert.der"


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
    parser.add_argument("--certificate", type=Path, help="pinned relay certificate for client-core setup and sync")
    parser.add_argument("--profile", help="isolated local runtime profile (for example: alice)")
    args = parser.parse_args()
    require("cargo", "Install Rust with: https://rustup.rs/")
    require("npm", "Install Node.js/npm, then run: npm --prefix src/client/frontend install")
    if not (FRONTEND / "node_modules").is_dir():
        print("RunClient.py: frontend dependencies are missing. Run: npm --prefix src/client/frontend install", file=sys.stderr)
        return 2

    # Build each layer first. Cargo and npm remain incremental, but this avoids
    # launching a previously built core, host, or frontend asset bundle.
    if subprocess.run(["npm", "--prefix", str(FRONTEND), "run", "build"], cwd=ROOT).returncode:
        return 1
    if subprocess.run(["cargo", "check", "-p", "pigeon-tauri"], cwd=ROOT).returncode:
        return 1
    profile = "release" if args.release else "debug"
    build = ["cargo", "build", "-p", "pigeon-client"]
    if args.release:
        build.append("--release")
    if subprocess.run(build, cwd=ROOT).returncode:
        return 1
    tauri_build = ["cargo", "build", "-p", "pigeon-tauri"]
    if args.release:
        tauri_build.append("--release")
    if subprocess.run(tauri_build, cwd=ROOT).returncode:
        return 1
    core_binary = ROOT / "target" / profile / "pigeon-client"
    environment = os.environ.copy()
    if args.profile:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", args.profile):
            print("RunClient.py: profile may contain only letters, digits, '_' and '-'.", file=sys.stderr)
            return 2
        profile_data = ROOT / "DevUtils" / "profiles" / args.profile
        profile_data.mkdir(parents=True, exist_ok=True)
        environment["XDG_DATA_HOME"] = str(profile_data)
    environment["PIGEON_CLIENT_BIN"] = str(core_binary)
    certificate = args.certificate or (LOCAL_RELAY_CERTIFICATE if LOCAL_RELAY_CERTIFICATE.exists() else None)
    if certificate is None:
        print(
            "RunClient.py: no pinned relay certificate found. Start the local relay with "
            "python3 DevUtils/RunRelay.py, or pass --certificate PATH.",
            file=sys.stderr,
        )
        return 2
    certificate = certificate.resolve()
    if not certificate.is_file():
        print(f"RunClient.py: relay certificate does not exist: {certificate}", file=sys.stderr)
        return 2
    environment["PIGEON_CERTIFICATE"] = str(certificate)
    print("Starting Pigeon Tauri client")
    print(f"  Repository: {ROOT}")
    print(f"  Client core: {core_binary}")
    print(f"  Pinned relay certificate: {certificate}")
    if args.profile:
        print(f"  Profile: {args.profile}")
        print(f"  Account state: {environment['XDG_DATA_HOME']} (preserved and isolated)")
    else:
        print("  Profile: default")
        print("  Account state: normal Tauri application-data location (preserved between runs)")
    print("  Stop with Ctrl+C.")
    command = ["cargo", "tauri", "dev", "--config", "src/client/tauri/tauri.conf.json"]
    if args.release:
        command.append("--release")
    return run(command, environment)


if __name__ == "__main__":
    raise SystemExit(main())
