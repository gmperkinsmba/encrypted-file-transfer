import base64
import hashlib
import json
import os
import tempfile
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from relay_core import (API, CDN_HOST, MAX_PACKET, GitHubRelay, RelayError, Response,
                       SafeHTTP, SecretStore, build_packet, make_receipt, open_packet,
                       receipt_asset_name, safe_write_files, verify_receipt, verify_saved_files)
from remote_service import send_selected
import teleport_cli


KEY = bytes(range(32))
TRANSFER = "0123456789abcdef0123456789abcdef"


class FakeTransport:
    def __init__(self, private=True):
        self.private = private
        self.release = None
        self.assets = {}
        self.next_asset_id = 10
        self.calls = []
        self.fail_receipt_once = False
        self.store_failed_receipt_response = False

    def request(self, method, url, headers, body=None, allow_asset_redirect=False):
        self.calls.append((method, url, dict(headers), body, allow_asset_redirect))
        parsed = urlsplit(url)
        path = parsed.path
        if parsed.hostname == "uploads.github.com":
            name = dict(x.split("=", 1) for x in parsed.query.split("&") if "=" in x).get("name", "")
            name = name.replace("%2D", "-").replace("%2E", ".")
            if name in self.assets:
                return Response(422, {}, b"duplicate")
            self.assets[name] = {"id": self.next_asset_id, "data": body}
            self.next_asset_id += 1
            if name.startswith("rcpt-") and self.fail_receipt_once:
                self.fail_receipt_once = False
                if not self.store_failed_receipt_response:
                    del self.assets[name]
                return Response(500, {}, b"upload response unavailable")
            return Response(201, {}, b"{}")
        if path.rstrip("/") == "/repos/owner/private":
            return Response(200, {}, json.dumps({"private": self.private, "full_name": "owner/private"}).encode())
        if path == "/repos/owner/private/releases":
            if method == "GET":
                releases = [{**self.release, "tag_name": "teleport-private-relay"}] if self.release else []
                return Response(200, {}, json.dumps(releases).encode())
            if method == "POST":
                self.release = {"id": 7, "draft": True, "tag_name": "teleport-private-relay"}
                return Response(201, {}, json.dumps(self.release).encode())
        if path == "/repos/owner/private/releases/7/assets":
            rows = [{"name": n, "id": x["id"]} for n, x in self.assets.items()]
            query = parse_qs(parsed.query)
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["100"])[0])
            return Response(200, {}, json.dumps(rows[(page - 1) * per_page:page * per_page]).encode())
        if path.startswith("/repos/owner/private/releases/assets/") and method == "GET":
            aid = int(path.rsplit("/", 1)[-1])
            asset = next((a for a in self.assets.values() if a["id"] == aid), None)
            return Response(200, {}, asset["data"] if asset else b"")
        if path.startswith("/repos/owner/private/releases/assets/") and method == "DELETE":
            aid = int(path.rsplit("/", 1)[-1])
            for n, asset in list(self.assets.items()):
                if asset["id"] == aid:
                    del self.assets[n]
            return Response(204, {}, b"")
        return Response(404, {}, b"not found")


class CryptographyTests(unittest.TestCase):
    def test_packet_hides_metadata_and_decrypts_exact_files(self):
        packet = build_packet(KEY, TRANSFER, "李", "team-blue", int(time.time()) + 3600, [("résumé_日本.txt", b"payload")])
        self.assertNotIn("李".encode(), packet)
        self.assertNotIn("team-blue".encode(), packet)
        self.assertNotIn("résumé".encode(), packet)
        opened = open_packet(KEY, TRANSFER, packet)
        self.assertEqual(opened["recipient"], "李")
        self.assertEqual(opened["channel"], "team-blue")
        self.assertEqual(opened["files"], [("résumé_日本.txt", b"payload")])

    def test_wrong_key_tamper_and_transfer_binding_fail_closed(self):
        packet = build_packet(KEY, TRANSFER, "Riley", "blue", int(time.time()) + 3600, [("a.txt", b"x")])
        with self.assertRaises(RelayError):
            open_packet(bytes(reversed(KEY)), TRANSFER, packet)
        altered = packet[:-1] + bytes([packet[-1] ^ 1])
        with self.assertRaises(RelayError):
            open_packet(KEY, TRANSFER, altered)
        with self.assertRaises(RelayError):
            open_packet(KEY, "f" * 32, packet)

    def test_expired_duplicate_and_unsafe_manifests_rejected(self):
        with self.assertRaises(RelayError):
            build_packet(KEY, TRANSFER, "Riley", "blue", int(time.time()) - 1, [("a", b"x")])
        with self.assertRaises(RelayError):
            build_packet(KEY, TRANSFER, "Riley", "blue", int(time.time()) + 60, [("same", b"a"), ("SAME", b"b")])
        with self.assertRaises(RelayError):
            build_packet(KEY, TRANSFER, "Riley", "blue", int(time.time()) + 60, [("../escape", b"x")])

    def test_receipt_binds_packet_transfer_recipient_and_file_hashes(self):
        expires = int(time.time()) + 3600
        files = [("a.txt", b"exact")]
        packet = build_packet(KEY, TRANSFER, "Riley", "blue", expires, files)
        receipt = make_receipt(KEY, TRANSFER, packet, "Riley", "blue", expires, files)
        value = verify_receipt(KEY, TRANSFER, receipt, packet, "Riley", "blue", expires)
        self.assertEqual(value["files"][0]["sha256"], hashlib.sha256(b"exact").hexdigest())
        with self.assertRaises(RelayError):
            verify_receipt(KEY, TRANSFER, receipt, packet + b"x", "Riley", "blue", expires)
        self.assertRegex(receipt_asset_name(KEY, TRANSFER), r"^rcpt-[a-f0-9]{48}\.tpr$")


class StoreAndFileTests(unittest.TestCase):
    def test_cli_configure_accepts_hidden_shared_pairing_key(self):
        supplied = base64.urlsafe_b64encode(KEY).decode("ascii").rstrip("=")
        output = StringIO()
        with patch("teleport_cli.getpass.getpass", return_value=supplied), \
                patch("teleport_cli.configure", return_value={"pairing_key": None}) as configure_call, \
                patch("sys.stdout", output):
            result = teleport_cli.main(["configure", "--owner", "owner", "--repo", "private",
                                        "--channel", "blue", "--recipient", "Riley", "--auth", "gh"])
        self.assertEqual(result, 0)
        configure_call.assert_called_once_with("owner", "private", "blue", "Riley", "gh", None, supplied)
        self.assertNotIn(supplied, output.getvalue())

    def test_secret_store_status_is_flags_only_and_remove_works(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "private" / "settings.json"
            store = SecretStore(path)
            store.save({"owner": "owner", "repo": "private", "channel": "blue", "auth_mode": "pat",
                        "token": "ghp_" + "x" * 36, "pairing_key": base64.urlsafe_b64encode(KEY).decode().rstrip("=")})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            status = store.status()
            self.assertNotIn("token", status)
            self.assertNotIn("pairing_key", status)
            self.assertTrue(status["token_set"])
            store.remove()
            self.assertFalse(store.status()["configured"])

    def test_no_clobber_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root).resolve() / "downloads"
            result = safe_write_files(base, TRANSFER, [("safe.txt", b"verified")])
            self.assertEqual(result[0]["sha256"], hashlib.sha256(b"verified").hexdigest())
            self.assertEqual((base / TRANSFER / "safe.txt").read_bytes(), b"verified")
            with self.assertRaises(RelayError):
                safe_write_files(base, TRANSFER, [("safe.txt", b"overwrite")])
            target = Path(root) / "target"
            target.mkdir()
            link = Path(root) / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(RelayError):
                safe_write_files(link / "nested", "f" * 32, [("x", b"x")])

    def test_failure_cleanup_stays_on_open_transfer_directory_after_symlink_swap(self):
        with tempfile.TemporaryDirectory() as root:
            area = Path(root).resolve()
            destination = area / "receiver"
            destination.mkdir()
            outside = area / "synthetic-outside"
            outside.mkdir()
            marker = outside / "marker.txt"
            marker.write_text("keep", encoding="utf-8")
            transfer_dir = destination / TRANSFER
            displaced = area / "renamed-transfer-directory"
            def swap_then_fail(source, target, *args, **kwargs):
                transfer_dir.rename(displaced)
                transfer_dir.symlink_to(outside, target_is_directory=True)
                raise OSError("synthetic injected link failure")

            with patch("relay_core.os.link", side_effect=swap_then_fail):
                with self.assertRaises(RelayError):
                    safe_write_files(destination, TRANSFER, [("report.txt", b"payload")])
            self.assertTrue(marker.exists())
            self.assertTrue(transfer_dir.is_symlink())
            self.assertTrue(displaced.is_dir())
            self.assertEqual(list(displaced.iterdir()), [])

    def test_ancestor_swap_does_not_redirect_publication_or_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            area = Path(root).resolve()
            parent = area / "parent"
            parent.mkdir()
            destination = parent / "downloads"
            destination.mkdir()
            outside = area / "synthetic-outside"
            outside.mkdir()
            marker = outside / "marker.txt"
            marker.write_text("keep", encoding="utf-8")
            displaced = area / "renamed-downloads"
            transfer_dir = destination / TRANSFER

            def swap_then_fail(source, target, *args, **kwargs):
                destination.rename(displaced)
                destination.symlink_to(outside, target_is_directory=True)
                raise OSError("synthetic injected link failure")

            with patch("relay_core.os.link", side_effect=swap_then_fail):
                with self.assertRaises(RelayError):
                    safe_write_files(destination, TRANSFER, [("report.txt", b"payload")])
            self.assertTrue(marker.exists())
            self.assertTrue(destination.is_symlink())
            self.assertTrue(displaced.is_dir())
            self.assertFalse((displaced / TRANSFER).exists())

    def test_pending_verification_rejects_symlink_and_fifo_files(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root).resolve()
            folder = base / TRANSFER
            folder.mkdir()
            external = base / "outside.txt"
            external.write_text("unchanged", encoding="utf-8")
            (folder / "link.txt").symlink_to(external)
            with self.assertRaises(RelayError):
                verify_saved_files(base, TRANSFER, [("link.txt", b"unchanged")])
            (folder / "link.txt").unlink()
            os.mkfifo(folder / "pipe.txt")
            with self.assertRaises(RelayError):
                verify_saved_files(base, TRANSFER, [("pipe.txt", b"x")])
            self.assertEqual(external.read_text(encoding="utf-8"), "unchanged")

    def test_browser_send_checks_lengths_and_hash_before_network(self):
        class NotUsed:
            settings = {"recipient": "Riley"}
        raw = b"browser bytes"
        meta = {"recipient": "Riley", "hours": 24, "files": [{"name": "b.txt", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}]}
        with self.assertRaises(RelayError):
            send_selected(meta, raw + b"extra", service=NotUsed())
        meta["files"][0]["sha256"] = "0" * 64
        with self.assertRaises(RelayError):
            send_selected(meta, raw, service=NotUsed())


class RelayProtocolTests(unittest.TestCase):
    def settings(self):
        return {"owner": "owner", "repo": "private", "channel": "blue", "pairing_key": base64.urlsafe_b64encode(KEY).decode().rstrip("="), "token": "ghp_" + "x" * 36}

    def test_two_identity_send_receive_restart_duplicate_and_cleanup_after_receipt(self):
        fake = FakeTransport()
        sender = GitHubRelay(self.settings(), http=fake)
        sent = sender.send("Riley", int(time.time()) + 3600, [("a.txt", b"exact bytes")])
        packet = fake.assets[sent["asset"]]["data"]
        decoded = open_packet(KEY, sent["transfer_id"], packet)
        receiver = GitHubRelay(self.settings(), http=fake)
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root).resolve()
            dest, state = root_path / "Downloads", root_path / "runtime" / "received.json"
            result = receiver.receive(sent["transfer_id"], sent["asset"], "Riley", dest, state)
            self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(b"exact bytes").hexdigest())
            restarted = GitHubRelay(self.settings(), http=fake)
            with self.assertRaisesRegex(RelayError, "already received"):
                restarted.receive(sent["transfer_id"], sent["asset"], "Riley", dest, state)
            receipt = restarted.receipt(sent["transfer_id"], sent["asset"])
            self.assertEqual(receipt["recipient"], "Riley")
            cleaned = sender.cleanup(sent["transfer_id"], sent["asset"])
            self.assertTrue(cleaned["cleaned"])
            self.assertNotIn(sent["asset"], fake.assets)

    def test_authenticated_saved_receipt_allows_cleanup_after_expiry(self):
        fake = FakeTransport()
        sender = GitHubRelay(self.settings(), http=fake)
        expires = int(time.time()) + 2
        sent = sender.send("Riley", expires, [("a.txt", b"saved before expiry")])
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root).resolve()
            receiver = GitHubRelay(self.settings(), http=fake)
            receiver.receive(sent["transfer_id"], sent["asset"], "Riley", root_path / "Downloads", root_path / "runtime" / "state.json")
            time.sleep(max(0, expires - time.time()) + 1.1)
            self.assertTrue(sender.cleanup(sent["transfer_id"], sent["asset"])["cleaned"])

    def test_expired_transfer_without_authenticated_receipt_cannot_cleanup(self):
        fake = FakeTransport()
        sender = GitHubRelay(self.settings(), http=fake)
        sent = sender.send("Riley", int(time.time()) + 1, [("a.txt", b"no receipt")])
        time.sleep(1.1)
        with self.assertRaisesRegex(RelayError, "Verified receipt is unavailable"):
            sender.cleanup(sent["transfer_id"], sent["asset"])

    def test_public_or_mismatched_repository_denied(self):
        fake = FakeTransport(private=False)
        with self.assertRaisesRegex(RelayError, "must exist and be private"):
            GitHubRelay(self.settings(), http=fake).send("Riley", int(time.time()) + 60, [("x", b"x")])

    def test_receive_retry_after_receipt_upload_interruption_reuses_verified_saved_bytes(self):
        fake = FakeTransport()
        sender = GitHubRelay(self.settings(), http=fake)
        sent = sender.send("Riley", int(time.time()) + 3600, [("a.txt", b"survives interruption")])
        fake.fail_receipt_once = True
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root).resolve()
            dest, state = root_path / "Downloads", root_path / "runtime" / "received.json"
            receiver = GitHubRelay(self.settings(), http=fake)
            with self.assertRaises(RelayError):
                receiver.receive(sent["transfer_id"], sent["asset"], "Riley", dest, state)
            saved = dest / sent["transfer_id"] / "a.txt"
            self.assertEqual(saved.read_bytes(), b"survives interruption")
            result = GitHubRelay(self.settings(), http=fake).receive(sent["transfer_id"], sent["asset"], "Riley", dest, state)
            self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(b"survives interruption").hexdigest())
            with self.assertRaisesRegex(RelayError, "already received"):
                GitHubRelay(self.settings(), http=fake).receive(sent["transfer_id"], sent["asset"], "Riley", dest, state)

    def test_receive_recovers_when_receipt_upload_succeeds_but_response_fails(self):
        fake = FakeTransport()
        sent = GitHubRelay(self.settings(), http=fake).send("Riley", int(time.time()) + 3600, [("a.txt", b"receipt lost")])
        fake.fail_receipt_once = True
        fake.store_failed_receipt_response = True
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root).resolve()
            result = GitHubRelay(self.settings(), http=fake).receive(sent["transfer_id"], sent["asset"], "Riley", root_path / "Downloads", root_path / "runtime" / "state.json")
            self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(b"receipt lost").hexdigest())

    def test_inbox_discovers_all_matching_assets_and_persists_duplicate_state(self):
        fake = FakeTransport()
        sender = GitHubRelay(self.settings(), http=fake)
        first = sender.send("Riley", int(time.time()) + 3600, [("one.txt", b"one")])
        second = sender.send("Riley", int(time.time()) + 3600, [("two.txt", b"two")])
        sender.send("Someone else", int(time.time()) + 3600, [("private.txt", b"other recipient")])
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root).resolve()
            receiver = GitHubRelay(self.settings(), http=fake)
            result = receiver.receive_inbox_once("Riley", root_path / "Downloads", root_path / "runtime" / "history.json")
            self.assertEqual(len(result["received"]), 2)
            self.assertEqual(len(result["ignored"]), 1)
            self.assertTrue((root_path / "Downloads" / first["transfer_id"] / "one.txt").is_file())
            self.assertTrue((root_path / "Downloads" / second["transfer_id"] / "two.txt").is_file())
            again = GitHubRelay(self.settings(), http=fake).receive_inbox_once("Riley", root_path / "Downloads", root_path / "runtime" / "history.json")
            self.assertEqual(again["received"], [])
            self.assertEqual(again["ignored"], [])

    def test_inbox_reports_wrong_key_and_tampered_asset_instead_of_hiding_them(self):
        fake = FakeTransport()
        sent = GitHubRelay(self.settings(), http=fake).send("Riley", int(time.time()) + 3600, [("x.txt", b"x")])
        fake.assets[sent["asset"]]["data"] = fake.assets[sent["asset"]]["data"][:-1] + b"!"
        wrong = self.settings()
        wrong["pairing_key"] = base64.urlsafe_b64encode(bytes(reversed(KEY))).decode().rstrip("=")
        with tempfile.TemporaryDirectory() as root:
            base = Path(root).resolve()
            result = GitHubRelay(wrong, http=fake).receive_inbox_once("Riley", base / "Downloads", base / "runtime" / "history.json")
            self.assertEqual(result["received"], [])
            self.assertEqual(result["ignored"][0]["asset"], sent["asset"])
            self.assertIn("authentication", result["ignored"][0]["reason"])

    def test_asset_listing_paginates_and_stops_at_bounds(self):
        fake = FakeTransport()
        relay = GitHubRelay(self.settings(), http=fake)
        release = relay._release(create=True)
        for index in range(105):
            fake.assets[f"xfer-{index:048x}.tpx"] = {"id": index + 1000, "data": b"test"}
        self.assertEqual(len(relay._assets(release)), 105)
        with tempfile.TemporaryDirectory() as root:
            base = Path(root).resolve()
            first = relay.receive_inbox_once("Riley", base / "Downloads", base / "runtime" / "state.json")
            self.assertTrue(first["truncated"])
            self.assertEqual(len(first["ignored"]), 100)
            next_pass = GitHubRelay(self.settings(), http=fake).receive_inbox_once("Riley", base / "Downloads", base / "runtime" / "state.json")
            self.assertFalse(next_pass["truncated"])
            self.assertEqual(len(next_pass["ignored"]), 5)

    def test_configured_hosts_and_upload_tokens_are_scoped(self):
        class Capture:
            def __init__(self): self.calls = []
            def __call__(self, req):
                self.calls.append(req)
                class R:
                    status = 200
                    headers = {}
                    def read(self, n): return b"ok"
                return R()
        cap = Capture()
        transport = SafeHTTP(opener=cap)
        with self.assertRaises(RelayError):
            transport.request("GET", "https://evil.example/data", {"Authorization": "secret"})
        transport.request("GET", API + "/repos/owner/private", {"Authorization": "secret"})
        self.assertEqual(urlsplit(cap.calls[0].full_url).hostname, "api.github.com")

    def test_asset_cdn_redirect_strips_credentials_and_rejects_bad_targets(self):
        class FakeResponse:
            def __init__(self, status, headers=None, body=b""):
                self.status, self.headers, self.body = status, headers or {}, body
            def read(self, _): return self.body
        class RedirectMock:
            def __init__(self, location): self.location, self.requests = location, []
            def __call__(self, req):
                self.requests.append(req)
                if len(self.requests) == 1:
                    return FakeResponse(302, {"Location": self.location})
                return FakeResponse(200, body=b"encrypted")
        good = RedirectMock(f"https://{CDN_HOST}/signed/asset")
        result = SafeHTTP(opener=good).request("GET", API + "/repos/o/r/releases/assets/1", {"Authorization": "Bearer secret", "Cookie": "session=secret"}, allow_asset_redirect=True)
        self.assertEqual(result.body, b"encrypted")
        self.assertNotIn("Authorization", good.requests[1].headers)
        self.assertNotIn("Cookie", good.requests[1].headers)
        self.assertEqual(good.requests[1].headers, {"Accept": "application/octet-stream"})
        for target in ("https://attacker.example/x", f"https://user@{CDN_HOST}/x", f"https://{CDN_HOST}:444/x"):
            with self.subTest(target=target), self.assertRaises(RelayError):
                SafeHTTP(opener=RedirectMock(target)).request("GET", API + "/asset", {"Authorization": "Bearer x"}, allow_asset_redirect=True)
        class TwoHops:
            def __init__(self): self.calls = 0
            def __call__(self, req):
                self.calls += 1
                return FakeResponse(302, {"Location": f"https://{CDN_HOST}/second"})
        with self.assertRaises(RelayError):
            SafeHTTP(opener=TwoHops()).request("GET", API + "/asset", {}, allow_asset_redirect=True)


if __name__ == "__main__":
    unittest.main()
