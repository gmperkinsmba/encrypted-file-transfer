"""Native shell boundaries and owned ephemeral backend lifecycle."""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import plistlib

import server
from build_desktop import BUNDLE_ID, OWNER_MARKER, owned_bundle
from desktop_policy import navigation_policy


class DesktopTests(unittest.TestCase):
    def test_navigation_policy_keeps_the_webview_on_its_owned_origin(self):
        origin = "http://127.0.0.1:49125/"
        self.assertEqual(navigation_policy(origin, origin, False, False), "allow")
        self.assertEqual(navigation_policy("blob:" + origin + "download", origin, False, True), "download")
        for blocked in ("file:///etc/passwd", "javascript:alert(1)", "data:text/html,x",
                        "http://127.0.0.1:49126/", "http://127.0.0.1.evil.test:49125/"):
            self.assertEqual(navigation_policy(blocked, origin, False, False), "cancel")
        self.assertEqual(navigation_policy("https://example.com", origin, True, False), "external")
        self.assertEqual(navigation_policy("https://example.com", origin, False, False), "cancel")

    def test_ephemeral_backend_serves_ui_and_shuts_down_cleanly(self):
        with tempfile.TemporaryDirectory() as runtime:
            app = server.make_server(port=0, data_dir=Path(runtime) / "runtime")
            worker = threading.Thread(target=app.serve_forever, daemon=True)
            worker.start()
            try:
                with urlopen(f"http://127.0.0.1:{app.server_port}/?desktop=1", timeout=3) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"<h1>Teleport</h1>", response.read())
                with self.assertRaises(HTTPError) as failure:
                    urlopen(Request(f"http://127.0.0.1:{app.server_port}/", headers={"Host": "evil.test"}), timeout=3)
                self.assertEqual(failure.exception.code, 403)
                failure.exception.close()
            finally:
                app.shutdown()
                app.server_close()
                worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(app.fileno(), -1)

    def test_bundle_replacement_requires_exact_identity_and_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "Teleport.app"
            resources = bundle / "Contents" / "Resources"
            resources.mkdir(parents=True)
            (bundle / "Contents" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": BUNDLE_ID}))
            (resources / OWNER_MARKER.name).write_bytes(OWNER_MARKER.read_bytes())
            self.assertTrue(owned_bundle(bundle))
            (resources / OWNER_MARKER.name).write_text("unowned", encoding="utf-8")
            self.assertFalse(owned_bundle(bundle))


if __name__ == "__main__":
    unittest.main()
