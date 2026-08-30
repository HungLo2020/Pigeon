"""Standard-library implementation for Pigeon's rolling Debian installers."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY = "HungLo2020/Pigeon"
RELEASE_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/tags/latest"
USER_AGENT = "pigeon-latest-installer/1"


def fail(message: str) -> RuntimeError:
    return RuntimeError(f"Pigeon installer: {message}")


def debian_architecture() -> str:
    if shutil.which("dpkg") is None:
        raise fail("dpkg is required; this installer supports Debian-family systems only")
    try:
        architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
    except subprocess.CalledProcessError as error:
        raise fail(f"could not detect Debian architecture: {error}") from error
    if not architecture:
        raise fail("dpkg returned an empty Debian architecture")
    return architecture


def release_metadata() -> dict[str, Any]:
    request = Request(
        RELEASE_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
    )
    try:
        with urlopen(request, timeout=30) as response:
            metadata = json.load(response)
    except HTTPError as error:
        raise fail(f"could not fetch rolling latest release (HTTP {error.code})") from error
    except URLError as error:
        raise fail(f"could not reach GitHub: {error.reason}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise fail(f"could not read rolling latest release metadata: {error}") from error
    if not isinstance(metadata, dict) or metadata.get("tag_name") != "latest":
        raise fail("GitHub did not return Pigeon's rolling latest release")
    if not isinstance(metadata.get("assets"), list):
        raise fail("latest release has no readable assets")
    return metadata


def selected_assets(metadata: dict[str, Any], package: str, architecture: str) -> tuple[dict[str, Any], dict[str, Any]]:
    package_pattern = re.compile(rf"^{re.escape(package)}_.+_{re.escape(architecture)}\.deb$")
    assets = metadata["assets"]
    packages = [asset for asset in assets if isinstance(asset, dict) and package_pattern.fullmatch(str(asset.get("name", "")))]
    sums = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == "SHA256SUMS"]
    if len(packages) != 1:
        available = ", ".join(str(asset.get("name", "")) for asset in assets if isinstance(asset, dict))
        raise fail(f"could not find exactly one {package} package for {architecture}; release assets: {available}")
    if len(sums) != 1:
        raise fail("latest release is missing an unambiguous SHA256SUMS asset")
    for asset in (packages[0], sums[0]):
        if not isinstance(asset.get("browser_download_url"), str):
            raise fail(f"release asset {asset.get('name')!r} has no download URL")
    return packages[0], sums[0]


def download(url: str, destination: Path) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    try:
        with urlopen(request, timeout=60) as response, destination.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
    except HTTPError as error:
        raise fail(f"download failed for {destination.name} (HTTP {error.code})") from error
    except URLError as error:
        raise fail(f"download failed for {destination.name}: {error.reason}") from error
    except OSError as error:
        raise fail(f"could not save {destination.name}: {error}") from error
    return digest.hexdigest()


def checksum_for(sums: Path, filename: str) -> str:
    expected: list[str] = []
    pattern = re.compile(r"^([0-9A-Fa-f]{64})\s+\*?(.+)$")
    try:
        lines = sums.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise fail(f"could not read SHA256SUMS: {error}") from error
    for line in lines:
        match = pattern.fullmatch(line.strip())
        if match and Path(match.group(2)).name == filename:
            expected.append(match.group(1).lower())
    if len(expected) != 1:
        raise fail(f"SHA256SUMS has no unambiguous checksum for {filename}")
    return expected[0]


def verify_and_download(package: str) -> tuple[Path, tempfile.TemporaryDirectory[str], dict[str, Any]]:
    architecture = debian_architecture()
    metadata = release_metadata()
    asset, sums_asset = selected_assets(metadata, package, architecture)
    temporary = tempfile.TemporaryDirectory(prefix="pigeon-latest-", dir="/tmp")
    try:
        directory = Path(temporary.name)
        directory.chmod(0o755)
        deb = directory / str(asset["name"])
        sums = directory / "SHA256SUMS"
        print(f"Downloading {asset['name']} from Pigeon latest ({metadata.get('target_commitish', 'unknown commit')})...")
        actual = download(str(asset["browser_download_url"]), deb)
        download(str(sums_asset["browser_download_url"]), sums)
        expected = checksum_for(sums, deb.name)
        if not hmac.compare_digest(actual, expected):
            raise fail(f"SHA-256 mismatch for {deb.name}: expected {expected}, got {actual}")
        deb.chmod(0o644)
        print(f"SHA-256 verified: {actual}")
        return deb, temporary, metadata
    except Exception:
        temporary.cleanup()
        raise


def install(package: str, server: bool) -> int:
    parser = argparse.ArgumentParser(description=f"Install Pigeon's latest {package} Debian package.")
    parser.add_argument("--verify-only", action="store_true", help="download and verify, but do not invoke apt")
    args = parser.parse_args()
    if shutil.which("apt") is None:
        raise fail("apt is required; this installer supports Debian-family systems only")
    deb, temporary, metadata = verify_and_download(package)
    try:
        if args.verify_only:
            print(f"Verified {deb.name}; apt installation skipped.")
            return 0
        print(f"Installing {deb.name} with apt (sudo may prompt for your password)...")
        subprocess.run(["sudo", "apt", "install", "--reinstall", "-y", str(deb)], check=True)
        if server:
            config = Path("/etc/pigeon/pigeon-server.conf")
            if config.exists():
                print("Existing relay configuration was retained. Check it with: systemctl status pigeon-server")
            else:
                print("Relay package installed but not configured. Next step: sudo pigeon-setup")
        print(f"Installed Pigeon {package} from latest commit {metadata.get('target_commitish', 'unknown')}.")
        return 0
    except subprocess.CalledProcessError as error:
        raise fail(f"apt failed while installing {deb.name} (exit {error.returncode})") from error
    finally:
        temporary.cleanup()
