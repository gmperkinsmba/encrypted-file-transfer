#!/usr/bin/env python3
"""Install only an owned Encrypted File Transfer bundle without deleting prior copies."""
from __future__ import annotations

import plistlib
import shutil
import sys
from pathlib import Path

from build_desktop import APP_NAME, BUNDLE_ID, OWNER_MARKER, backup_owned_bundle, owned_bundle


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "dist" / f"{APP_NAME}.app"
DESTINATION = Path.home() / "Applications" / f"{APP_NAME}.app"


def bundle_id(path: Path) -> str | None:
    try:
        with (path / "Contents" / "Info.plist").open("rb") as stream:
            return plistlib.load(stream).get("CFBundleIdentifier")
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None


def main() -> int:
    if sys.platform != "darwin":
        raise SystemExit("Install the native application on macOS.")
    if not owned_bundle(SOURCE):
        raise SystemExit(f"The built app is missing its expected identity and ownership marker: {SOURCE}")
    DESTINATION.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if DESTINATION.exists():
        if bundle_id(DESTINATION) != BUNDLE_ID or not owned_bundle(DESTINATION):
            raise SystemExit(f"Refusing to replace an unrelated or unmarked app: {DESTINATION}")
        backup_owned_bundle(DESTINATION)
    shutil.copytree(SOURCE, DESTINATION, symlinks=True)
    if not owned_bundle(DESTINATION):
        raise SystemExit("Installed bundle verification failed; the installed copy was left in place for review.")
    print(DESTINATION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
