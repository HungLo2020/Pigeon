#!/usr/bin/env python3
"""Start a persistent local Pigeon relay from any working directory."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STATE = ROOT / "DevUtils" / "local-relay"


def require(command: str, install: str) -> None:
    if shutil.which(command) is None:
        print(f"RunRelay.py: '{command}' is required. {install}", file=sys.stderr)
        raise SystemExit(2)


def run(command: list[str]) -> int:
    child = subprocess.Popen(command, cwd=ROOT)
    try:
        return child.wait()
    except KeyboardInterrupt:
        print("\nStopping relay…", file=sys.stderr)
        child.terminate()
        try:
            return child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            return child.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1:8443", help="relay listen address")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE, help="persistent local relay files")
    args = parser.parse_args()
    require("cargo", "Install Rust with: https://rustup.rs/")

    state_dir = args.state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    database = state_dir / "pigeon-server.sqlite3"
    certificate = state_dir / "pigeon-server-cert.der"
    private_key = state_dir / "pigeon-server-key.der"
    print("Starting Pigeon local relay")
    print(f"  Relay address: {args.listen}")
    print(f"  SQLite database: {database}")
    print(f"  TLS certificate: {certificate}")
    print(f"  TLS private key: {private_key}")
    print("  Stop with Ctrl+C. State is retained for the next run.")
    build = ["cargo", "build", "-p", "pigeon-server"]
    if subprocess.run(build, cwd=ROOT).returncode:
        return 1
    # Invoke the binary Cargo just built.  This makes the launcher's freshness
    # contract explicit while retaining Cargo's normal incremental builds.
    return run([
        str(ROOT / "target" / "debug" / "pigeon-server"),
        "--listen", args.listen,
        "--database", str(database),
        "--certificate", str(certificate),
        "--private-key", str(private_key),
    ])


if __name__ == "__main__":
    raise SystemExit(main())
