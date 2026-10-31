#!/usr/bin/env python3
"""Build a local macOS Encrypted File Transfer application bundle."""
from __future__ import annotations

import plistlib
import shutil
import subprocess
import sys
import tempfile
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APP_NAME = "Encrypted File Transfer"
ASSET_MANIFEST = ROOT / "desktop-assets.txt"
OWNER_MARKER = ROOT / "desktop-app-owner.txt"
BUNDLE_ID = "io.github.gmperkinsmba.teleport"
LICENSE_DIR = ROOT / "third_party_licenses"
LICENSE_FALLBACKS = LICENSE_DIR / "fallback-manifest.json"
LICENSE_SUFFIXES = {"", ".txt", ".md", ".rst", ".html", ".apache", ".bsd", ".mit"}


def main() -> int:
    if sys.platform != "darwin":
        raise SystemExit("Build this native application on macOS.")
    assets = tuple(line.strip() for line in ASSET_MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip())
    if not assets or any(Path(name).name != name for name in assets):
        raise SystemExit("The desktop asset manifest must contain only simple file names.")
    for name in assets:
        asset = ROOT / name
        if asset.is_symlink() or not asset.is_file():
            raise SystemExit(f"Required app asset is missing: {name}")
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--windowed",
        "--name",
        APP_NAME,
        "--osx-bundle-identifier",
        BUNDLE_ID,
        "--hidden-import",
        "desktop_policy",
    ]
    for asset in assets:
        command.extend(("--add-data", f"{ROOT / asset}:."))
    with tempfile.TemporaryDirectory(prefix="teleport-build-") as temp_dir:
        build_root = Path(temp_dir)
        command.extend(("--workpath", str(build_root / "work"), "--specpath", str(build_root / "spec")))
        notices = build_root / "THIRD_PARTY_NOTICES.txt"
        write_notices(notices)
        command.extend(("--add-data", f"{notices}:."))
        command.extend(("--add-data", f"{OWNER_MARKER}:."))
        command.extend(("--distpath", str(build_root / "dist"), str(ROOT / "desktop.py")))
        subprocess.run(command, cwd=ROOT, check=True)
        destination = ROOT / "dist" / f"{APP_NAME}.app"
        destination.parent.mkdir(exist_ok=True)
        if destination.exists():
            if not owned_bundle(destination):
                raise SystemExit(f"Refusing to replace an app without the Encrypted File Transfer ownership marker: {destination}")
            backup_owned_bundle(destination)
        shutil.move(str(build_root / "dist" / f"{APP_NAME}.app"), str(destination))
    print(ROOT / "dist" / f"{APP_NAME}.app")
    return 0


def owned_bundle(path: Path) -> bool:
    try:
        with (path / "Contents" / "Info.plist").open("rb") as stream:
            bundle_id = plistlib.load(stream).get("CFBundleIdentifier")
        marker = (path / "Contents" / "Resources" / OWNER_MARKER.name).read_bytes()
        return bundle_id == BUNDLE_ID and marker == OWNER_MARKER.read_bytes()
    except (OSError, ValueError, plistlib.InvalidFileException):
        return False


def backup_owned_bundle(path: Path) -> Path:
    from datetime import datetime

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.previous-{stamp}")
    if backup.exists():
        raise SystemExit(f"Refusing to replace existing backup: {backup}")
    path.rename(backup)
    return backup


def write_notices(destination: Path) -> None:
    import importlib.metadata

    fallbacks = json.loads(LICENSE_FALLBACKS.read_text(encoding="utf-8"))
    fallback_by_package = {
        "pyobjc_core": "pyobjc-core-13.0-License.txt",
        "pyobjc_framework_security": "pyobjc-framework-security-13.0-License.txt",
        "pyobjc_framework_uniformtypeidentifiers": "pyobjc-framework-uniformtypeidentifiers-13.0-License.txt",
        "proxy_tools": "proxy-tools-0.1.0-LICENSE.txt",
    }
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    python_license_path = Path(sys.base_prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "LICENSE.txt"
    python_license = decode_license(python_license_path.read_bytes()) if python_license_path.is_file() else None
    if python_license is None:
        raise SystemExit("The Python runtime license text is missing or unreadable.")
    chunks = [
        "Encrypted File Transfer desktop dependencies\n\nThird-party license texts for the pinned build environment follow.\n",
        f"\n{'=' * 72}\nPython runtime {python_version}\n{'=' * 72}\n{python_license}\n",
    ]
    for distribution in sorted(importlib.metadata.distributions(), key=lambda item: (item.metadata.get("Name") or "").lower()):
        name = distribution.metadata.get("Name")
        if not name:
            continue
        chunks.append(f"\n{'=' * 72}\n{name} {distribution.version}\n{'=' * 72}\n")
        license_files = [item for item in (distribution.files or []) if is_text_license_name(Path(str(item)).name)]
        if license_files:
            copied = 0
            for item in license_files:
                try:
                    raw = distribution.locate_file(item).read_bytes()
                    text = decode_license(raw)
                    if text is None:
                        continue
                    chunks.append(f"\n--- {item} ---\n")
                    chunks.append(text)
                    copied += 1
                except OSError:
                    continue
            if copied:
                continue
        fallback_name = fallback_by_package.get(name.lower().replace("-", "_"))
        if fallback_name:
            record = fallbacks[fallback_name]
            raw = (LICENSE_DIR / fallback_name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != record["sha256"]:
                raise SystemExit(f"License fallback checksum failed for {name}.")
            text = decode_license(raw)
            if text is None:
                raise SystemExit(f"License fallback is not plain UTF-8 text for {name}.")
            chunks.append(f"\n--- source license for {name} ---\n")
            chunks.append(f"Source: {record['source_url']}\n")
            if record.get("source_archive_sha256"):
                chunks.append(f"Source archive SHA-256: {record['source_archive_sha256']}\n")
            if record.get("source_note"):
                chunks.append(f"Metadata note: {record['source_note']}\n")
            chunks.append(text)
            continue
        metadata_license = distribution.metadata.get("License") or ""
        if len(metadata_license) < 100:
            raise SystemExit(f"No readable license text was found for {name}.")
        chunks.append(f"\n--- package license metadata for {name} ---\n{metadata_license}\n")
    destination.write_text("\n".join(chunks), encoding="utf-8")


def is_text_license_name(filename: str) -> bool:
    lowered = filename.lower()
    for prefix in ("license", "copying", "notice"):
        if lowered == prefix:
            return True
        if lowered.startswith(prefix + ".") and Path(lowered).suffix in LICENSE_SUFFIXES:
            return True
    return False


def decode_license(raw: bytes) -> str | None:
    if not raw or len(raw) > 2_000_000 or b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
