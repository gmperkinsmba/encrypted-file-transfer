"""Verified, staged installation for signed macOS app bundles."""
from __future__ import annotations

import ctypes
import argparse
import datetime
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable
import unicodedata


class InstallSecurityError(RuntimeError):
    """Raised when an app bundle cannot be installed safely."""


OwnerCheck = Callable[[Path], bool]
Verifier = Callable[[Path], None]
Copier = Callable[..., object]
Rename = Callable[[Path, Path], None]


def verify_codesign(bundle: Path) -> None:
    """Require a valid strict macOS code seal; this does not prove publisher identity."""
    if sys.platform != "darwin":
        raise InstallSecurityError("App signature verification requires macOS codesign.")
    result = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "signature verification failed"
        raise InstallSecurityError(f"App signature verification failed: {detail}")


def _validate_bundle_path(bundle: Path) -> None:
    if bundle.is_symlink() or not bundle.is_dir():
        raise InstallSecurityError(f"App bundle must be a real directory: {bundle}")

    root = bundle.resolve(strict=True)
    for current, dirs, files in os.walk(bundle, followlinks=False):
        for name in (*dirs, *files):
            entry = Path(current) / name
            if not entry.is_symlink():
                continue
            target = os.readlink(entry)
            if os.path.isabs(target):
                raise InstallSecurityError(f"App bundle contains an absolute symlink: {entry}")
            try:
                resolved = entry.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, RuntimeError, ValueError):
                raise InstallSecurityError(f"App bundle symlink escapes or is broken: {entry}") from None


def _renameatx(source: Path, destination: Path, flags: int) -> None:
    if sys.platform != "darwin":
        raise InstallSecurityError("Atomic app installation requires macOS renamex_np.")
    if source.parent != destination.parent:
        raise InstallSecurityError("Staged app and destination must be on the same directory.")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renamex = libc.renamex_np
    except (OSError, AttributeError):
        raise InstallSecurityError("This macOS system does not provide renamex_np.") from None
    renamex.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    renamex.restype = ctypes.c_int
    result = renamex(os.fsencode(source), os.fsencode(destination), flags)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def _rename_exclusive(source: Path, destination: Path) -> None:
    # RENAME_EXCL | RENAME_NOFOLLOW_ANY from <sys/stdio.h>.
    _renameatx(source, destination, 0x00000004 | 0x00000010)


def _swap(source: Path, destination: Path) -> None:
    # RENAME_SWAP | RENAME_NOFOLLOW_ANY from <sys/stdio.h>.
    _renameatx(source, destination, 0x00000002 | 0x00000010)


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _remove_stage(path: Path) -> None:
    if not _lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


def install_signed_bundle(
    source: Path,
    destination: Path,
    *,
    owner_check: OwnerCheck,
    verifier: Verifier = verify_codesign,
    copier: Copier = shutil.copytree,
    rename_exclusive: Rename = _rename_exclusive,
    swap: Rename = _swap,
) -> Path | None:
    """Verify source, copy and verify a stage, then atomically install it.

    If an owned app exists, RENAME_SWAP replaces it atomically and preserves the
    old bundle under a unique sibling backup path. An unowned path is never moved.
    """
    source = Path(source)
    destination = Path(destination)
    if not owner_check(source):
        raise InstallSecurityError(f"Source app has the wrong bundle identity or owner marker: {source}")
    _validate_bundle_path(source)
    verifier(source)

    parent = destination.parent
    if parent.is_symlink():
        raise InstallSecurityError(f"Install directory must not be a symlink: {parent}")
    parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    parent = parent.resolve(strict=True)
    destination = parent / destination.name

    if _lexists(destination):
        if destination.is_symlink() or not destination.is_dir() or not owner_check(destination):
            raise InstallSecurityError(f"Refusing to replace an unrelated or symlink app: {destination}")

    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage-", dir=parent))
    backup: Path | None = None
    preserve_stage = False
    try:
        copier(source, stage, symlinks=True, dirs_exist_ok=True)
        shutil.copystat(source, stage, follow_symlinks=False)
        _validate_bundle_path(stage)
        if not owner_check(stage):
            raise InstallSecurityError(f"Staged app has the wrong bundle identity or owner marker: {stage}")
        verifier(stage)

        if _lexists(destination):
            if destination.is_symlink() or not destination.is_dir() or not owner_check(destination):
                raise InstallSecurityError(f"Destination changed to an unrelated or symlink app: {destination}")
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = parent / f".{destination.name}.previous-{stamp}-{uuid.uuid4().hex[:8]}"
            swap(stage, destination)
            try:
                rename_exclusive(stage, backup)
            except Exception as backup_error:
                try:
                    swap(stage, destination)
                except Exception as rollback_error:
                    preserve_stage = True
                    raise InstallSecurityError(
                        f"Could not save the prior app at {backup}: {backup_error}. "
                        f"It remains at {stage}; the new app remains at {destination}. "
                        f"Rollback failed: {rollback_error}"
                    ) from backup_error
                raise
        else:
            rename_exclusive(stage, destination)

        return backup
    finally:
        if not preserve_stage:
            _remove_stage(stage)


def owner_check_for(
    bundle_id: str,
    marker_file: Path | None = None,
    marker_name: str = "desktop-app-owner.txt",
) -> OwnerCheck:
    """Build an owner check for native shell installers using the same helper."""
    expected_marker = marker_file.read_bytes() if marker_file is not None else None

    def check(bundle: Path) -> bool:
        try:
            info = plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes())
            if info.get("CFBundleIdentifier") != bundle_id:
                return False
            if expected_marker is None:
                return True
            actual = (bundle / "Contents" / "Resources" / marker_name).read_bytes()
            return actual == expected_marker
        except (OSError, ValueError, plistlib.InvalidFileException):
            return False

    return check


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install a verified, signed macOS application bundle.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--owner-marker-file", type=Path)
    parser.add_argument("--owner-marker-name", default="desktop-app-owner.txt")
    args = parser.parse_args(argv)
    if sys.platform != "darwin":
        parser.error("App installation and signature checks require macOS.")
    if not args.bundle_id.strip() or any(unicodedata.category(char).startswith("C") for char in args.bundle_id):
        parser.error("Bundle identifier is invalid.")
    try:
        owner_check = owner_check_for(
            args.bundle_id,
            marker_file=args.owner_marker_file,
            marker_name=args.owner_marker_name,
        )
        backup = install_signed_bundle(args.source, args.destination, owner_check=owner_check)
    except (InstallSecurityError, OSError, ValueError) as exc:
        print(f"Install failed: {exc}", file=sys.stderr)
        return 2
    if backup is not None:
        print(f"Previous app preserved at {backup}")
    print(f"Installed {args.destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
