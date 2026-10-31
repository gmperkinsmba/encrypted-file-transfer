import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

_IMPORT_RUNTIME = tempfile.TemporaryDirectory()
_SAVED_TELEPORT_DATA = os.environ.get("TELEPORT_DATA")
os.environ["TELEPORT_DATA"] = _IMPORT_RUNTIME.name
import server
import relay_core
from fake_keychain import FakeKeychain
if _SAVED_TELEPORT_DATA is None:
    os.environ.pop("TELEPORT_DATA", None)
else:
    os.environ["TELEPORT_DATA"] = _SAVED_TELEPORT_DATA


class DesktopServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.prior_server_data = server.DATA
        self.prior_data = os.environ.get("TELEPORT_DATA")
        self.runtime = Path(self.temp.name).resolve() / "runtime"
        self.keychain_patch = patch.object(relay_core, "make_secret_backend", return_value=FakeKeychain())
        self.keychain_patch.start()
        self.app = server.make_server(0, self.runtime)
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.app.server_port
        self.origin = f"http://127.0.0.1:{self.port}"
        self.host = f"127.0.0.1:{self.port}"
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/api/session", headers={"Host": self.host})
        response = conn.getresponse()
        self.token = json.loads(response.read())["token"]
        conn.close()

    def tearDown(self):
        self.app.shutdown()
        self.app.server_close()
        self.thread.join(timeout=2)
        self.keychain_patch.stop()
        server.DATA = self.prior_server_data
        if self.prior_data is None:
            os.environ.pop("TELEPORT_DATA", None)
        else:
            os.environ["TELEPORT_DATA"] = self.prior_data
        self.temp.cleanup()

    def call(self, path, method="GET", body=None, headers=None):
        request_headers = {"Host": self.host, "Origin": self.origin,
                           "Sec-Fetch-Site": "same-origin", "X-Teleport-Request": self.token}
        request_headers.update(headers or {})
        payload = body
        if isinstance(body, (dict, list)):
            payload = json.dumps(body)
            request_headers["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request(method, path, body=payload, headers=request_headers)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        try:
            return response.status, json.loads(raw)
        except Exception:
            return response.status, raw

    def test_factory_binds_loopback_dynamic_port_and_daemon_threads(self):
        self.assertEqual(self.app.server_address[0], "127.0.0.1")
        self.assertGreater(self.port, 0)
        self.assertTrue(self.app.daemon_threads)

    def test_host_origin_and_session_boundaries(self):
        status, _ = self.call("/api/relay/status", headers={"Host": "attacker.invalid"})
        self.assertEqual(status, 403)
        status, _ = self.call("/api/relay/status", headers={"Origin": "https://attacker.invalid"})
        self.assertEqual(status, 403)
        status, _ = self.call("/api/relay/status", headers={"X-Teleport-Request": "wrong"})
        self.assertEqual(status, 403)
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/api/session", headers={"Host": f"attacker.invalid:{self.port}"})
        response = conn.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("HEAD", "/", headers={"Host": f"attacker.invalid:{self.port}"})
        response = conn.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        conn.close()

    def test_settings_configure_returns_new_key_once_and_status_never_returns_secrets(self):
        payload = {"owner": "owner", "repo": "private", "channel": "team", "recipient": "Riley",
                   "auth_mode": "pat", "token": "ghp_" + "x" * 36, "pairing_key": None}
        status, configured = self.call("/api/relay/configure", method="POST", body=payload)
        self.assertEqual(status, 200)
        key = configured["pairing_key"]
        self.assertEqual(len(key), 43)
        self.assertNotIn(payload["token"], json.dumps(configured))
        status, flags = self.call("/api/relay/status")
        self.assertEqual(status, 200)
        self.assertTrue(flags["configured"])
        self.assertNotIn("token", flags)
        self.assertNotIn("pairing_key", flags)
        status, removed = self.call("/api/relay/remove-settings", method="POST", body={})
        self.assertEqual(status, 200)
        self.assertFalse(removed["configured"])

    def test_malformed_remote_payload_gets_generic_error(self):
        configured, _ = self.call("/api/relay/configure", method="POST", body={
            "owner": "owner", "repo": "private", "channel": "team", "recipient": "Riley",
            "auth_mode": "pat", "token": "ghp_" + "x" * 36, "pairing_key": None
        })
        self.assertEqual(configured, 200)
        status, result = self.call("/api/relay/receive", method="POST", body={"transfer_id": 17, "asset": None, "recipient": []})
        self.assertEqual(status, 400)
        self.assertIn("error", result)
        self.assertNotIn("Traceback", str(result))


if __name__ == "__main__":
    unittest.main()
