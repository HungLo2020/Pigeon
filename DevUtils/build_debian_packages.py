#!/usr/bin/env python3
"""Build independently installable Pigeon client and relay Debian packages.

The Tauri bundler owns the client application's runtime dependency metadata.
This helper repackages that output under Pigeon's stable client package name
and creates the relay package directly from the server binary. Keeping the two
steps separate prevents desktop/WebKit dependencies from reaching the relay.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
import tarfile
from io import BytesIO
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TAURI_CONFIG = ROOT / "src/client/tauri/tauri.conf.json"
CLIENT_MANIFEST = ROOT / "src/client/tauri/Cargo.toml"
SERVER_MANIFEST = ROOT / "src/server/Cargo.toml"
DEBIAN_PACKAGING = ROOT / "packaging/debian"


def run(*command: str, cwd: Path = ROOT) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def package_version() -> str:
    client = tomllib.loads(CLIENT_MANIFEST.read_text())["package"]["version"]
    server = tomllib.loads(SERVER_MANIFEST.read_text())["package"]["version"]
    tauri = json.loads(TAURI_CONFIG.read_text())["version"]
    if not isinstance(client, str) or client != server or client != tauri:
        raise RuntimeError(
            "client, server, and Tauri package versions must match before Debian packaging"
        )
    return client


def architecture() -> str:
    return subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()


def clear_previous_output(output: Path, version: str, arch: str, client: bool, server: bool) -> None:
    """Prevent a failed rebuild from leaving a same-version artifact publishable."""
    names: list[str] = []
    if client:
        names.append(f"pigeon-client_{version}_{arch}.deb")
    if server:
        names.append(f"pigeon-server_{version}_{arch}.deb")
    for name in names:
        previous = output / name
        if previous.exists():
            print(f"Removing previous package output {previous}")
            previous.unlink()


def replace_control_field(control: Path, name: str, value: str) -> None:
    lines = control.read_text().splitlines()
    prefix = f"{name}:"
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{name}: {value}"
            control.write_text("\n".join(lines) + "\n")
            return
    lines.append(f"{name}: {value}")
    control.write_text("\n".join(lines) + "\n")


def build_client(output: Path, version: str, arch: str) -> Path:
    run("npm", "run", "build", "--prefix", "src/client/frontend")
    run(
        "cargo",
        "tauri",
        "build",
        "--config",
        "src/client/tauri/tauri.conf.json",
        "--bundles",
        "deb",
        "--",
        "--locked",
    )
    candidates = sorted((ROOT / "target/release/bundle/deb").glob(f"Pigeon_{version}_*.deb"))
    if len(candidates) != 1:
        raise RuntimeError(f"expected one Tauri Debian bundle for {version}, found {candidates}")

    destination = output / f"pigeon-client_{version}_{arch}.deb"
    with tempfile.TemporaryDirectory(prefix="pigeon-client-deb-") as temporary:
        staging = Path(temporary) / "package"
        run("dpkg-deb", "--raw-extract", str(candidates[0]), str(staging))
        replace_control_field(staging / "DEBIAN/control", "Package", "pigeon-client")
        run("dpkg-deb", "--build", "--root-owner-group", str(staging), str(destination))
    return destination


def server_dependencies(binary: Path, packaging_root: Path) -> str:
    # dpkg-shlibdeps derives minimum ABI versions from Debian's symbols files.
    # It expects a source-package control file even though this helper creates
    # the binary package directly rather than through debhelper.
    debian = packaging_root / "debian"
    debian.mkdir()
    (debian / "control").write_text(
        "\n".join(
            [
                "Source: pigeon-server",
                "Section: net",
                "Priority: optional",
                "Maintainer: Pigeon <maintainers@pigeon.chat>",
                "Standards-Version: 4.7.0",
                "",
                "Package: pigeon-server",
                "Architecture: any",
                "Description: Pigeon encrypted-message relay",
                "",
            ]
        )
    )
    result = subprocess.run(
        ["dpkg-shlibdeps", "-O", f"-e{binary}"],
        cwd=packaging_root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    prefix = "shlibs:Depends="
    for line in result.stdout.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    raise RuntimeError("dpkg-shlibdeps did not return runtime dependencies")


def build_server(output: Path, version: str, arch: str) -> Path:
    run("cargo", "build", "--locked", "--release", "-p", "pigeon-server")
    binary = ROOT / "target/release/pigeon-server"
    if not binary.is_file():
        raise RuntimeError(f"server binary was not produced at {binary}")

    destination = output / f"pigeon-server_{version}_{arch}.deb"
    with tempfile.TemporaryDirectory(prefix="pigeon-server-deb-") as temporary:
        staging = Path(temporary) / "package"
        bin_dir = staging / "usr/bin"
        control_dir = staging / "DEBIAN"
        unit_dir = staging / "lib/systemd/system"
        config_dir = staging / "etc/pigeon"
        state_dir = staging / "var/lib/pigeon"
        bin_dir.mkdir(parents=True)
        control_dir.mkdir()
        unit_dir.mkdir(parents=True)
        config_dir.mkdir(parents=True)
        state_dir.mkdir(parents=True)
        bin_dir.chmod(0o755)
        control_dir.chmod(0o755)
        unit_dir.chmod(0o755)
        config_dir.chmod(0o750)
        state_dir.chmod(0o750)
        installed_binary = bin_dir / "pigeon-server"
        shutil.copy2(binary, installed_binary)
        installed_binary.chmod(0o755)
        setup = bin_dir / "pigeon-setup"
        shutil.copy2(DEBIAN_PACKAGING / "pigeon-setup.py", setup)
        setup.chmod(0o755)
        unit = unit_dir / "pigeon-server.service"
        shutil.copy2(DEBIAN_PACKAGING / "pigeon-server.service", unit)
        unit.chmod(0o644)
        for script in ("postinst", "postrm"):
            destination_script = control_dir / script
            shutil.copy2(DEBIAN_PACKAGING / script, destination_script)
            destination_script.chmod(0o755)
        dependencies = server_dependencies(installed_binary, Path(temporary))
        (control_dir / "control").write_text(
            "\n".join(
                [
                    "Package: pigeon-server",
                    f"Version: {version}",
                    f"Architecture: {arch}",
                    "Maintainer: Pigeon <maintainers@pigeon.chat>",
                    "Priority: optional",
                    "Section: net",
                    f"Depends: {dependencies}, python3",
                    "Description: Pigeon encrypted-message relay",
                    " Pigeon relay server for recent encrypted delivery and routing.",
                    "",
                ]
            )
        )
        run("dpkg-deb", "--build", "--root-owner-group", str(staging), str(destination))
    return destination


def package_listing(package: Path) -> str:
    return subprocess.check_output(["dpkg-deb", "-c", str(package)], text=True)


def package_control(package: Path) -> str:
    return subprocess.check_output(["dpkg-deb", "-I", str(package)], text=True)


def control_members(package: Path) -> set[str]:
    archive = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(package)])
    with tarfile.open(fileobj=BytesIO(archive)) as control:
        return {member.name.removeprefix("./") for member in control.getmembers()}


def validate(client: Path | None, server: Path | None) -> None:
    if client is not None:
        control = package_control(client)
        listing = package_listing(client)
        if "Package: pigeon-client" not in control or "./usr/bin/pigeon-tauri" not in listing:
            raise RuntimeError("pigeon-client package does not contain the expected Tauri application")
    if server is not None:
        control = package_control(server).lower()
        listing = package_listing(server).lower()
        scripts = control_members(server)
        forbidden = ("webkit", "gtk", "tauri", "frontend", "node_modules")
        required_files = (
            "./usr/bin/pigeon-server",
            "./usr/bin/pigeon-setup",
            "./lib/systemd/system/pigeon-server.service",
            "./etc/pigeon/",
            "./var/lib/pigeon/",
        )
        if "package: pigeon-server" not in control or any(value not in listing for value in required_files):
            raise RuntimeError("pigeon-server package does not contain the expected relay binary")
        if not {"postinst", "postrm"}.issubset(scripts):
            raise RuntimeError("pigeon-server package lacks required system-user/service maintainer scripts")
        if any(value in control or value in listing for value in forbidden):
            raise RuntimeError("pigeon-server package contains a client runtime dependency or asset")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selected = parser.add_mutually_exclusive_group()
    selected.add_argument("--client", action="store_true", help="build only pigeon-client")
    selected.add_argument("--server", action="store_true", help="build only pigeon-server")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "target/release/packages",
        help="directory for built packages (default: target/release/packages)",
    )
    args = parser.parse_args()
    version = package_version()
    arch = architecture()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build_client_package = not args.server
    build_server_package = not args.client
    clear_previous_output(output, version, arch, build_client_package, build_server_package)
    client = build_client(output, version, arch) if build_client_package else None
    server = build_server(output, version, arch) if build_server_package else None
    validate(client, server)
    for package in (client, server):
        if package is not None:
            print(f"Built and validated {package}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Debian packaging failed: {error}", file=sys.stderr)
        raise SystemExit(1)
