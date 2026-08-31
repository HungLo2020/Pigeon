#!/usr/bin/env python3
"""Start the Pigeon Tauri client against the repository's existing UI/core."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import re
import socket
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


def daemon_running(socket_path: Path) -> bool:
    if not socket_path.exists():
        return False
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(0.2)
        client.connect(str(socket_path))
        return True
    except OSError:
        return False
    finally:
        client.close()


def start_daemon(binary: Path, environment: dict[str, str], data_dir: Path, socket_path: Path) -> bool:
    if daemon_running(socket_path):
        return True
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.Popen(
            [str(binary), "--data-dir", str(data_dir), "--socket", str(socket_path)],
            cwd=ROOT,
            env=environment,
            start_new_session=True,
        )
    except OSError as error:
        print(f"RunClient.py: could not start pigeon-client-daemon: {error}", file=sys.stderr)
        return False
    for _ in range(30):
        if daemon_running(socket_path):
            return True
        import time
        time.sleep(0.1)
    print("RunClient.py: daemon did not create its IPC socket.", file=sys.stderr)
    return False


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
    daemon_build = ["cargo", "build", "-p", "pigeon-client-daemon"]
    if args.release:
        daemon_build.append("--release")
    if subprocess.run(daemon_build, cwd=ROOT).returncode:
        return 1
    tauri_build = ["cargo", "build", "-p", "pigeon-tauri"]
    if args.release:
        tauri_build.append("--release")
    if subprocess.run(tauri_build, cwd=ROOT).returncode:
        return 1
    core_binary = ROOT / "target" / profile / "pigeon-client"
    daemon_binary = ROOT / "target" / profile / "pigeon-client-daemon"
    environment = os.environ.copy()
    profile_runtime: Path | None = None
    if args.profile:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", args.profile):
            print("RunClient.py: profile may contain only letters, digits, '_' and '-'.", file=sys.stderr)
            return 2
        profile_root = ROOT / "DevUtils" / "profiles" / args.profile
        profile_data = profile_root / "data"
        profile_runtime = profile_root / "runtime"
        profile_data.mkdir(parents=True, exist_ok=True)
        profile_runtime.mkdir(parents=True, exist_ok=True)
        profile_runtime.chmod(0o700)
        environment["XDG_DATA_HOME"] = str(profile_data)
        environment["PIGEON_DATA_DIR"] = str(profile_data / "pigeon")
    environment["PIGEON_CLIENT_BIN"] = str(core_binary)
    environment["PIGEON_CLIENT_DAEMON_BIN"] = str(daemon_binary)
    data_home = Path(environment.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    data_dir = Path(environment.get("PIGEON_DATA_DIR", str(data_home / "pigeon")))
    # Do not replace XDG_RUNTIME_DIR for a profile: GTK uses the session value
    # to find the Wayland socket.  Only Pigeon's private daemon socket needs
    # isolation, so place that one below the profile runtime directory.
    runtime_dir = profile_runtime or Path(environment.get("XDG_RUNTIME_DIR", "/tmp"))
    daemon_socket = runtime_dir / "pigeon" / "pigeon-client.sock"
    environment["PIGEON_DAEMON_SOCKET"] = str(daemon_socket)
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
    print(f"  Background daemon: {daemon_binary}")
    print(f"  Daemon IPC: {daemon_socket}")
    print(f"  Pinned relay certificate: {certificate}")
    if args.profile:
        print(f"  Profile: {args.profile}")
        print(f"  Account state: {data_dir} (preserved and isolated)")
    else:
        print("  Profile: default")
        print(f"  Account state: {data_dir} (preserved between runs)")
    print("  Stop with Ctrl+C.")
    if not start_daemon(daemon_binary, environment, data_dir, daemon_socket):
        return 1
    command = ["cargo", "tauri", "dev", "--config", "src/client/tauri/tauri.conf.json"]
    if args.release:
        command.append("--release")
    return run(command, environment)


if __name__ == "__main__":
    raise SystemExit(main())
