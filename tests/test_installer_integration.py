from __future__ import annotations

import importlib
import plistlib
import tempfile
import unittest
from pathlib import Path


MODULE_NAME = (
    "install_app"
    if (Path(__file__).resolve().parents[1] / "install_app.py").is_file()
    else "install_desktop"
)


class InstallerOwnerCallbackTests(unittest.TestCase):
    def test_actual_installer_owner_callback_accepts_only_expected_fixture(self) -> None:
        installer = importlib.import_module(MODULE_NAME)
        if MODULE_NAME == "install_app":
            bundle_id = installer.PRODUCT_ID
            marker_name = "desktop-app-owner.txt"
            marker_bytes = (installer.OWNER_MARKER + "\n").encode("utf-8")
            owner_callback = installer.owned
        else:
            build = importlib.import_module("build_desktop")
            bundle_id = build.BUNDLE_ID
            marker_path = build.OWNER_MARKER
            marker_name = marker_path.name
            marker_bytes = marker_path.read_bytes()
            owner_callback = installer.owned_bundle

        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "Owned Fixture.app"
            resources = bundle / "Contents" / "Resources"
            resources.mkdir(parents=True)
            (bundle / "Contents" / "Info.plist").write_bytes(
                plistlib.dumps({"CFBundleIdentifier": bundle_id})
            )
            marker = resources / marker_name
            marker.write_bytes(marker_bytes)
            self.assertTrue(owner_callback(bundle))

            (bundle / "Contents" / "Info.plist").write_bytes(
                plistlib.dumps({"CFBundleIdentifier": "invalid.fixture"})
            )
            self.assertFalse(owner_callback(bundle))
            (bundle / "Contents" / "Info.plist").write_bytes(
                plistlib.dumps({"CFBundleIdentifier": bundle_id})
            )
            marker.write_bytes(b"wrong owner marker\n")
            self.assertFalse(owner_callback(bundle))


if __name__ == "__main__":
    unittest.main()
