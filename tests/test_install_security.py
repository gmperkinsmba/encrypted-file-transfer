from __future__ import annotations

import plistlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from install_security import InstallSecurityError, install_signed_bundle, verify_codesign

FIXTURE_BUNDLE_ID = "com.example.installer-fixture"
FIXTURE_OWNER = b"installer-test-owner-v1\n"


def make_bundle(path: Path, text: str, *, owner: bool = True) -> Path:
    resources = path / "Contents" / "Resources"
    executable = path / "Contents" / "MacOS" / "Fixture"
    resources.mkdir(parents=True)
    executable.parent.mkdir(parents=True)
    (path / "Contents" / "Info.plist").write_bytes(
        plistlib.dumps({"CFBundleIdentifier": FIXTURE_BUNDLE_ID, "CFBundleExecutable": "Fixture"})
    )
    (resources / "desktop-app-owner.txt").write_bytes(
        FIXTURE_OWNER if owner else b"not this app"
    )
    executable.write_text(text, encoding="utf-8")
    executable.chmod(0o755)
    return path


def is_owned(path: Path) -> bool:
    try:
        info = plistlib.loads((path / "Contents" / "Info.plist").read_bytes())
        marker = (path / "Contents" / "Resources" / "desktop-app-owner.txt").read_bytes()
        return info.get("CFBundleIdentifier") == FIXTURE_BUNDLE_ID and marker == FIXTURE_OWNER
    except (OSError, ValueError, plistlib.InvalidFileException):
        return False


class InstallSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = make_bundle(self.root / "source.app", "new app")
        self.destination = self.root / "Applications" / "Target.app"
        self.destination.parent.mkdir()
        self.verify_calls: list[Path] = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    def verifier(self, bundle: Path) -> None:
        self.verify_calls.append(bundle)
        if (bundle / "Contents" / "Resources" / "invalid-signature-fixture").exists():
            raise InstallSecurityError("fixture signature rejected")

    @staticmethod
    def rename_exclusive(source: Path, destination: Path) -> None:
        if os.path.lexists(destination):
            raise FileExistsError(destination)
        os.rename(source, destination)

    @staticmethod
    def swap(source: Path, destination: Path) -> None:
        temporary = source.with_name(f".{source.name}.swap-test")
        os.rename(source, temporary)
        os.rename(destination, source)
        os.rename(temporary, destination)

    def install(self, **kwargs: object) -> Path | None:
        return install_signed_bundle(
            self.source,
            self.destination,
            owner_check=is_owned,
            verifier=self.verifier,
            rename_exclusive=self.rename_exclusive,
            swap=self.swap,
            **kwargs,
        )

    def test_new_install_verifies_source_and_stage(self) -> None:
        backup = self.install()
        self.assertIsNone(backup)
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "new app")
        self.assertEqual(len(self.verify_calls), 2)
        self.assertEqual(self.verify_calls[0], self.source)
        self.assertTrue(self.verify_calls[1].name.startswith(".Target.app.stage-"))
        self.assertFalse(list(self.destination.parent.glob(".Target.app.stage-*")))

    def test_existing_owned_app_is_swapped_to_backup(self) -> None:
        make_bundle(self.destination, "old app")
        backup = self.install()
        self.assertIsNotNone(backup)
        assert backup is not None
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "new app")
        self.assertEqual((backup / "Contents" / "MacOS" / "Fixture").read_text(), "old app")
        self.assertFalse(list(self.destination.parent.glob(".Target.app.stage-*")))

    def test_bad_source_signature_leaves_existing_app_untouched(self) -> None:
        make_bundle(self.destination, "old app")

        def reject_source(bundle: Path) -> None:
            raise InstallSecurityError("source rejected")

        with self.assertRaisesRegex(InstallSecurityError, "source rejected"):
            install_signed_bundle(
                self.source, self.destination, owner_check=is_owned, verifier=reject_source,
                rename_exclusive=self.rename_exclusive, swap=self.swap
            )
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "old app")
        self.assertFalse(list(self.destination.parent.glob(".Target.app.previous-*")))

    def test_bad_staged_signature_leaves_existing_app_untouched(self) -> None:
        make_bundle(self.destination, "old app")

        def reject_stage(bundle: Path) -> None:
            if bundle != self.source:
                raise InstallSecurityError("stage rejected")

        with self.assertRaisesRegex(InstallSecurityError, "stage rejected"):
            install_signed_bundle(
                self.source, self.destination, owner_check=is_owned, verifier=reject_stage,
                rename_exclusive=self.rename_exclusive, swap=self.swap
            )
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "old app")
        self.assertFalse(list(self.destination.parent.glob(".Target.app.previous-*")))
        self.assertFalse(list(self.destination.parent.glob(".Target.app.stage-*")))

    def test_copy_failure_leaves_existing_app_and_cleans_stage(self) -> None:
        make_bundle(self.destination, "old app")

        def fail_copy(source: Path, destination: Path, **kwargs: object) -> None:
            raise OSError("simulated copy failure")

        with self.assertRaisesRegex(OSError, "simulated copy failure"):
            install_signed_bundle(
                self.source,
                self.destination,
                owner_check=is_owned,
                verifier=self.verifier,
                copier=fail_copy,
                rename_exclusive=self.rename_exclusive,
                swap=self.swap,
            )
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "old app")
        self.assertFalse(list(self.destination.parent.glob(".Target.app.stage-*")))

    def test_backup_failure_rolls_back_the_atomic_swap(self) -> None:
        make_bundle(self.destination, "old app")

        def fail_backup(source: Path, destination: Path) -> None:
            if ".previous-" in destination.name:
                raise OSError("simulated backup failure")
            self.rename_exclusive(source, destination)

        with self.assertRaisesRegex(OSError, "simulated backup failure"):
            install_signed_bundle(
                self.source,
                self.destination,
                owner_check=is_owned,
                verifier=self.verifier,
                rename_exclusive=fail_backup,
                swap=self.swap,
            )
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "old app")
        self.assertFalse(list(self.destination.parent.glob(".Target.app.stage-*")))
        self.assertFalse(list(self.destination.parent.glob(".Target.app.previous-*")))

    def test_failed_backup_and_failed_rollback_preserve_old_stage_and_report_paths(self) -> None:
        make_bundle(self.destination, "old app")
        swap_calls = 0

        def fail_backup(source: Path, destination: Path) -> None:
            raise OSError("simulated backup move failure")

        def fail_rollback(source: Path, destination: Path) -> None:
            nonlocal swap_calls
            swap_calls += 1
            if swap_calls == 1:
                self.swap(source, destination)
            else:
                raise OSError("simulated rollback failure")

        with self.assertRaises(InstallSecurityError) as caught:
            install_signed_bundle(
                self.source,
                self.destination,
                owner_check=is_owned,
                verifier=self.verifier,
                rename_exclusive=fail_backup,
                swap=fail_rollback,
            )
        message = str(caught.exception)
        stages = list(self.destination.parent.glob(".Target.app.stage-*"))
        self.assertEqual(len(stages), 1)
        self.assertIn(str(stages[0]), message)
        self.assertIn(str(self.destination), message)
        self.assertIn("simulated backup move failure", message)
        self.assertIn("simulated rollback failure", message)
        self.assertEqual((stages[0] / "Contents" / "MacOS" / "Fixture").read_text(), "old app")
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "new app")

    def test_unowned_destination_is_never_moved(self) -> None:
        make_bundle(self.destination, "other app", owner=False)
        with self.assertRaisesRegex(InstallSecurityError, "unrelated"):
            self.install()
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "other app")

    def test_destination_symlink_is_rejected(self) -> None:
        outside = make_bundle(self.root / "outside.app", "other app")
        self.destination.symlink_to(outside)
        with self.assertRaisesRegex(InstallSecurityError, "symlink"):
            self.install()
        self.assertTrue(self.destination.is_symlink())

    def test_symlink_install_directory_is_rejected(self) -> None:
        real_directory = self.root / "real-apps"
        real_directory.mkdir()
        link_directory = self.root / "linked-apps"
        link_directory.symlink_to(real_directory)
        destination = link_directory / "Target.app"
        with self.assertRaisesRegex(InstallSecurityError, "Install directory must not be a symlink"):
            install_signed_bundle(
                self.source,
                destination,
                owner_check=is_owned,
                verifier=self.verifier,
                rename_exclusive=self.rename_exclusive,
                swap=self.swap,
            )
        self.assertEqual(list(real_directory.iterdir()), [])

    def test_bundle_symlink_must_stay_inside_bundle(self) -> None:
        outside = self.root / "outside-resource"
        outside.write_text("outside", encoding="utf-8")
        link = self.source / "Contents" / "Resources" / "outside-link"
        link.symlink_to(outside)
        with self.assertRaisesRegex(InstallSecurityError, "absolute|escapes"):
            install_signed_bundle(
                self.source, self.destination, owner_check=is_owned, verifier=self.verifier
            )
        self.assertFalse(self.destination.exists())

    @unittest.skipUnless(sys.platform == "darwin", "Apple code signing is available only on macOS")
    def test_real_adhoc_signed_fixture_passes_codesign_and_installs(self) -> None:
        subprocess.run(
            ["/usr/bin/codesign", "--force", "--deep", "--sign", "-", "--timestamp=none", str(self.source)],
            check=True,
            capture_output=True,
            text=True,
        )
        verify_codesign(self.source)
        backup = install_signed_bundle(self.source, self.destination, owner_check=is_owned)
        self.assertIsNone(backup)
        verify_codesign(self.destination)

    @unittest.skipUnless(sys.platform == "darwin", "Apple code signing is available only on macOS")
    def test_real_signed_existing_app_is_atomically_swapped_and_backed_up(self) -> None:
        make_bundle(self.destination, "old app")
        for bundle in (self.source, self.destination):
            subprocess.run(
                ["/usr/bin/codesign", "--force", "--deep", "--sign", "-", "--timestamp=none", str(bundle)],
                check=True,
                capture_output=True,
                text=True,
            )
            verify_codesign(bundle)
        backup = install_signed_bundle(self.source, self.destination, owner_check=is_owned)
        self.assertIsNotNone(backup)
        assert backup is not None
        verify_codesign(self.destination)
        verify_codesign(backup)
        self.assertEqual((self.destination / "Contents" / "MacOS" / "Fixture").read_text(), "new app")
        self.assertEqual((backup / "Contents" / "MacOS" / "Fixture").read_text(), "old app")


if __name__ == "__main__":
    unittest.main()
