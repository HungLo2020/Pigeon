#!/usr/bin/env python3
"""Configure a packaged Pigeon relay and enable its systemd service."""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_CONFIG = Path("/etc/pigeon/pigeon-server.conf")
DEFAULT_DATA_DIR = Path("/var/lib/pigeon")
SERVER = Path("/usr/bin/pigeon-server")
SERVICE = "pigeon-server.service"
ADDRESS = re.compile(r"^(?:\[[^]\s]+\]|[^:\s]+):([0-9]{1,5})$")


def require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("pigeon-setup must run as root; use sudo pigeon-setup")


def valid_address(value: str) -> str:
    match = ADDRESS.fullmatch(value.strip())
    if match is None or not 1 <= int(match.group(1)) <= 65535:
        raise ValueError("enter host:port (or [IPv6]:port) with a port from 1 to 65535")
    return value.strip()


def prompt(label: str, default: str, validator=valid_address) -> str:
    while True:
        value = input(f"{label} [{default}]: ").strip() or default
        try:
            return validator(value)
        except ValueError as error:
            print(f"Invalid value: {error}", file=sys.stderr)


def yes_no(label: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{label} [{hint}]: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer yes or no.", file=sys.stderr)


def pigeon_ids() -> tuple[int, int]:
    try:
        return pwd.getpwnam("pigeon").pw_uid, grp.getgrnam("pigeon").gr_gid
    except KeyError as error:
        raise RuntimeError("the pigeon system account is missing; reinstall pigeon-server") from error


def owned(path: Path, mode: int, uid: int, gid: int) -> None:
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def write_config(path: Path, values: dict[str, str], uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chown(path.parent, 0, gid)
    os.chmod(path.parent, 0o750)
    content = "# Managed by pigeon-setup. Values are intentionally unquoted key=value.\n" + "".join(
        f"{key}={value}\n" for key, value in values.items()
    )
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    owned(temporary_path, 0o640, uid, gid)
    temporary_path.replace(path)


def run_as_pigeon(*command: str) -> None:
    subprocess.run(["runuser", "-u", "pigeon", "--", *command], check=True)


def configure_tls(data_dir: Path, uid: int, gid: int) -> tuple[Path, Path]:
    tls_dir = data_dir / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    owned(tls_dir, 0o750, uid, gid)
    certificate = tls_dir / "pigeon-server-cert.der"
    private_key = tls_dir / "pigeon-server-key.der"
    if certificate.is_file() and private_key.is_file():
        print("Retaining existing relay TLS material; setup does not replace relay identity material.")
        return certificate, private_key
    if (data_dir / "pigeon-server.sqlite3").exists():
        raise RuntimeError(
            "existing relay database has incomplete TLS material; refusing to create a replacement "
            "identity without an explicit relay recovery/migration procedure"
        )
    generate = yes_no("Generate a new self-signed TLS certificate", True)
    if generate:
        return certificate, private_key
    source_certificate = Path(prompt("Existing TLS certificate DER path", "", lambda value: value)).expanduser()
    source_key = Path(prompt("Existing TLS private-key DER path", "", lambda value: value)).expanduser()
    if not source_certificate.is_file() or not source_key.is_file():
        raise RuntimeError("both supplied TLS DER files must exist")
    shutil.copy2(source_certificate, certificate)
    shutil.copy2(source_key, private_key)
    owned(certificate, 0o640, uid, gid)
    owned(private_key, 0o600, uid, gid)
    return certificate, private_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--force", action="store_true", help="replace an existing config, never relay state")
    parser.add_argument("--no-start", action="store_true", help="write and initialize config without enabling systemd")
    args = parser.parse_args()
    require_root()
    config = args.config.resolve()
    data_dir = args.data_dir.resolve()
    if not data_dir.is_absolute() or str(data_dir).startswith("/usr/"):
        raise RuntimeError("relay state must use an absolute non-/usr path")
    if config.exists() and not args.force:
        print(f"Existing relay configuration retained: {config}")
        print("Use --force to change configuration; it never replaces relay identity/database state.")
        if not args.no_start:
            subprocess.run(["systemctl", "enable", "--now", SERVICE], check=True)
            subprocess.run(["systemctl", "status", "--no-pager", SERVICE], check=False)
        return 0
    if config != DEFAULT_CONFIG and not args.no_start:
        raise RuntimeError("a non-default --config requires --no-start; the packaged service uses /etc/pigeon")

    uid, gid = pigeon_ids()
    data_dir.mkdir(parents=True, exist_ok=True)
    owned(data_dir, 0o750, uid, gid)
    listen = prompt("Listen address", "0.0.0.0:8443")
    public_address = prompt("Public relay address", listen)
    certificate, private_key = configure_tls(data_dir, uid, gid)
    values = {
        "listen": listen,
        "public_address": public_address,
        "database": str(data_dir / "pigeon-server.sqlite3"),
        "certificate": str(certificate),
        "private_key": str(private_key),
    }
    write_config(config, values, uid, gid)
    # Initialization is performed as the service account. It reuses an existing
    # SQLite relay identity and fails safely rather than replacing it.
    run_as_pigeon(str(SERVER), "--config", str(config), "--initialize-only")
    print(f"Relay state initialized at {data_dir}")
    print(f"Persistent configuration written to {config}")
    if args.no_start:
        print("Service was not enabled (--no-start). Start it with systemctl when ready.")
        return 0
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", SERVICE], check=True)
    subprocess.run(["systemctl", "status", "--no-pager", SERVICE], check=False)
    print("Pigeon relay is enabled for boot. Logs: journalctl -u pigeon-server -f")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, OSError) as error:
        print(f"pigeon-setup: {error}", file=sys.stderr)
        raise SystemExit(1)
