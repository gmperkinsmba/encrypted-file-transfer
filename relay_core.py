"""Authenticated, encrypted GitHub private-release relay primitives.

No file bytes or user metadata are sent before AES-GCM encryption. Network
access is injected so protocol tests never contact GitHub.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keychain_store import KeychainError, MacKeychain

API = "https://api.github.com"
UPLOAD = "https://uploads.github.com"
CDN_HOST = "release-assets.githubusercontent.com"
VERSION = b"teleport-relay-v1"
MAX_PACKET = 32 * 1024 * 1024
MAX_FILES = 100
MAX_FILE = 16 * 1024 * 1024
MAX_INBOX_SCAN = 100
MAX_INBOX_BYTES = 256 * 1024 * 1024
MAX_NAME = 240
SAFE_ID = re.compile(r"^[a-f0-9]{32}$")
SAFE_ASSET = re.compile(r"^xfer-[a-f0-9]{48}\.tpx$")


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and SAFE_ID.fullmatch(value) is not None


def _valid_asset(value: object) -> bool:
    return isinstance(value, str) and SAFE_ASSET.fullmatch(value) is not None


class RelayError(Exception):
    """Safe public error; callers must not expose underlying HTTP details."""


def make_secret_backend():
    """Return the platform secret store; only macOS uses the system Keychain."""
    if sys.platform == "darwin":
        try:
            return MacKeychain()
        except KeychainError:
            raise RelayError("macOS Keychain is unavailable") from None
    return None


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise RelayError("Pairing key must contain 32 bytes")


def _valid_name(name: object) -> str:
    if not isinstance(name, str) or not name or len(name) > MAX_NAME:
        raise RelayError("Invalid file name")
    if name in (".", "..") or "/" in name or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise RelayError("File names must be safe basenames")
    return name


def build_packet(key: bytes, transfer_id: str, recipient: str, channel: str,
                 expires: int, files: list[tuple[str, bytes]]) -> bytes:
    """Encrypt a bounded set of files and all identifying metadata."""
    _validate_key(key)
    if not _valid_id(transfer_id):
        raise RelayError("Invalid transfer ID")
    if not isinstance(recipient, str) or not recipient or len(recipient) > 160 or any(ord(c) < 32 or ord(c) == 127 for c in recipient):
        raise RelayError("Invalid recipient")
    if not isinstance(channel, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", channel):
        raise RelayError("Invalid recipient or channel")
    if type(expires) is not int or expires <= int(time.time()):
        raise RelayError("Expiry must be in the future")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise RelayError("Choose 1 to 100 files")
    names: set[str] = set()
    records = []
    data = bytearray()
    for entry in files:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise RelayError("Invalid file entry")
        name, raw = entry
        name = _valid_name(name)
        if name.casefold() in names:
            raise RelayError("Duplicate file names are not allowed")
        names.add(name.casefold())
        if not isinstance(raw, bytes) or len(raw) > MAX_FILE:
            raise RelayError("File exceeds the 16 MiB limit")
        records.append({"name": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        data.extend(raw)
    payload = _json_bytes({"recipient": recipient, "channel": channel, "expires": expires,
                           "files": records, "data_length": len(data)}) + b"\n" + bytes(data)
    if len(payload) + 12 + 16 + len(VERSION) + 1 + 32 > MAX_PACKET:
        raise RelayError("Encrypted transfer exceeds 32 MiB")
    nonce = os.urandom(12)
    # Version and opaque transfer ID are the only visible authenticated fields.
    aad = VERSION + b"\0" + transfer_id.encode("ascii")
    return VERSION + b"\0" + transfer_id.encode("ascii") + nonce + AESGCM(key).encrypt(nonce, payload, aad)


def open_packet(key: bytes, transfer_id: str, packet: bytes, allow_expired: bool = False) -> dict:
    _validate_key(key)
    if not _valid_id(transfer_id) or not isinstance(packet, bytes) or len(packet) > MAX_PACKET:
        raise RelayError("Invalid encrypted transfer")
    prefix = VERSION + b"\0" + transfer_id.encode("ascii")
    if not packet.startswith(prefix) or len(packet) < len(prefix) + 28:
        raise RelayError("Invalid encrypted transfer")
    nonce = packet[len(prefix):len(prefix) + 12]
    aad = prefix
    try:
        clear = AESGCM(key).decrypt(nonce, packet[len(prefix) + 12:], aad)
        header, data = clear.split(b"\n", 1)
        meta = json.loads(header)
    except (InvalidTag, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise RelayError("Transfer authentication failed") from None
    if not isinstance(meta, dict):
        raise RelayError("Invalid encrypted transfer")
    entries = meta.get("files")
    total = meta.get("data_length")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES or type(total) is not int or total != len(data):
        raise RelayError("Invalid encrypted manifest")
    seen: set[str] = set()
    offset = 0
    decoded = []
    for item in entries:
        if not isinstance(item, dict):
            raise RelayError("Invalid encrypted manifest")
        name = _valid_name(item.get("name"))
        size, digest = item.get("size"), item.get("sha256")
        if name.casefold() in seen or type(size) is not int or size < 0 or size > MAX_FILE or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise RelayError("Invalid encrypted manifest")
        seen.add(name.casefold())
        raw = data[offset:offset + size]
        if len(raw) != size or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest):
            raise RelayError("File hash verification failed")
        decoded.append((name, raw))
        offset += size
    if offset != len(data) or not isinstance(meta.get("recipient"), str) or not isinstance(meta.get("channel"), str) or type(meta.get("expires")) is not int:
        raise RelayError("Invalid encrypted manifest")
    if not allow_expired and meta["expires"] <= int(time.time()):
        raise RelayError("Transfer expired")
    return {"recipient": meta["recipient"], "channel": meta["channel"], "expires": meta["expires"], "files": decoded}


def receipt_asset_name(key: bytes, transfer_id: str) -> str:
    _validate_key(key)
    if not _valid_id(transfer_id):
        raise RelayError("Invalid transfer ID")
    digest = hmac.new(key, b"teleport-receipt-v1\0" + transfer_id.encode("ascii"), hashlib.sha256).hexdigest()[:48]
    return f"rcpt-{digest}.tpr"


def make_receipt(key: bytes, transfer_id: str, packet: bytes, recipient: str, channel: str, expiry: int,
                 files: list[tuple[str, bytes]]) -> bytes:
    _validate_key(key)
    if not _valid_id(transfer_id):
        raise RelayError("Invalid transfer ID")
    payload = {"transfer_id": transfer_id, "packet_sha256": hashlib.sha256(packet).hexdigest(),
               "recipient": recipient, "channel": channel, "expires": expiry,
               "files": [{"name": n, "size": len(b), "sha256": hashlib.sha256(b).hexdigest()} for n, b in files]}
    nonce = os.urandom(12)
    aad = b"teleport-receipt-v1\0" + transfer_id.encode("ascii")
    return nonce + AESGCM(key).encrypt(nonce, _json_bytes(payload), aad)


def verify_receipt(key: bytes, transfer_id: str, raw: bytes, packet: bytes,
                   recipient: str, channel: str, expiry: int) -> dict:
    _validate_key(key)
    if not _valid_id(transfer_id) or not isinstance(raw, bytes) or len(raw) > 65536 or len(raw) < 28:
        raise RelayError("Invalid receipt")
    nonce, cipher = raw[:12], raw[12:]
    aad = b"teleport-receipt-v1\0" + transfer_id.encode("ascii")
    try:
        data = json.loads(AESGCM(key).decrypt(nonce, cipher, aad))
    except (InvalidTag, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise RelayError("Receipt authentication failed") from None
    expected = {"transfer_id": transfer_id, "packet_sha256": hashlib.sha256(packet).hexdigest(),
                "recipient": recipient, "channel": channel, "expires": expiry}
    if not isinstance(data, dict) or any(data.get(k) != v for k, v in expected.items()):
        raise RelayError("Receipt does not match this transfer")
    return data


def private_runtime(path: Path) -> Path:
    path = path.expanduser().absolute()
    if path.is_symlink():
        raise RelayError("Runtime directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise RelayError("Runtime directory must be a real directory")
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RelayError("Runtime directory permissions are too broad")
    return path


class SecretStore:
    """Keep macOS secrets in Keychain and non-secret settings in an atomic file."""
    SECRET_NAMES = ("token", "pairing_key")

    def __init__(self, path: Path, secret_backend=None):
        self.path = path
        private_runtime(path.parent)
        self.secret_backend = secret_backend if secret_backend is not None else make_secret_backend()
        canonical = os.path.normcase(str(path.expanduser().resolve()))
        self.scope = hashlib.sha256(os.fsencode(canonical)).hexdigest()

    def _new_secret_ref(self, name: str) -> str:
        return f"{name}-{self.scope}-{secrets.token_hex(16)}"

    def _valid_secret_ref(self, name: object, ref: object) -> bool:
        return (name in self.SECRET_NAMES and isinstance(ref, str) and
                re.fullmatch(rf"{re.escape(name)}-{self.scope}-[a-f0-9]{{32}}", ref) is not None)

    def _read_refs(self, metadata: dict) -> tuple[dict, list[str]]:
        refs = metadata.get("secret_refs", {})
        pending = metadata.get("cleanup_pending", [])
        if not isinstance(refs, dict) or any(not self._valid_secret_ref(name, ref) for name, ref in refs.items()):
            raise RelayError("Relay secret references are invalid")
        if not isinstance(pending, list) or any(not isinstance(ref, str) or
                re.fullmatch(rf"(?:token|pairing_key)-{self.scope}-[a-f0-9]{{32}}", ref) is None for ref in pending):
            raise RelayError("Relay secret references are invalid")
        if set(pending).intersection(refs.values()):
            raise RelayError("Relay secret references are invalid")
        return refs, pending

    def save(self, settings: dict) -> None:
        if not isinstance(settings, dict):
            raise RelayError("Invalid settings")
        mode = settings.get("auth_mode")
        owner, repo = settings.get("owner"), settings.get("repo")
        if mode not in ("pat", "gh") or not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", owner) or not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", repo):
            raise RelayError("Invalid relay settings")
        if not isinstance(settings.get("channel"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", settings["channel"]):
            raise RelayError("Channel must use letters, numbers, underscore, or hyphen")
        recipient = settings.get("recipient", "")
        if not isinstance(recipient, str) or len(recipient) > 160 or any(ord(ch) < 32 or ord(ch) == 127 for ch in recipient):
            raise RelayError("Invalid recipient")
        pairing_key = settings.get("pairing_key")
        if pairing_key is not None:
            if not isinstance(pairing_key, str):
                raise RelayError("Pairing key is invalid")
            try:
                decoded_key = base64.urlsafe_b64decode(pairing_key + "=" * (-len(pairing_key) % 4))
            except Exception:
                raise RelayError("Pairing key is invalid") from None
            if len(decoded_key) != 32:
                raise RelayError("Pairing key must encode 32 bytes")
        token = settings.get("token")
        if mode == "pat" and (not isinstance(token, str) or len(token) < 20 or any(ord(ch) < 33 or ord(ch) > 126 for ch in token)):
            raise RelayError("Enter a valid fine-grained token")
        if mode == "gh":
            settings = dict(settings)
            settings.pop("token", None)
        if self.secret_backend is not None:
            self._save_keychain(settings)
            return
        if self.path.is_symlink():
            raise RelayError("Settings path must not be a symlink")
        self._write_json(settings)

    def _write_json(self, settings: dict) -> None:
        if self.path.is_symlink():
            raise RelayError("Settings path must not be a symlink")
        tmp = self.path.with_name(self.path.name + "." + secrets.token_hex(8) + ".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(settings, separators=(",", ":")))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.path)
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise RelayError("Settings could not be saved") from None

    def _backend_call(self, method: str, account: str, *args):
        try:
            return getattr(self.secret_backend, method)(account, *args)
        except KeychainError:
            raise RelayError("macOS Keychain is unavailable or access was denied") from None
        except Exception:
            raise RelayError("macOS Keychain is unavailable or access was denied") from None

    def _save_keychain(self, settings: dict) -> None:
        if self.path.is_symlink():
            raise RelayError("Settings path must not be a symlink")
        previous_metadata = {}
        try:
            previous_metadata = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError):
            raise RelayError("Existing relay settings could not be read") from None
        if not isinstance(previous_metadata, dict):
            raise RelayError("Existing relay settings are invalid")
        old_refs, old_pending = self._read_refs(previous_metadata)
        desired = {
            "pairing_key": settings.get("pairing_key"),
            "token": settings.get("token") if settings.get("auth_mode") == "pat" else None,
        }
        new_refs = {}
        created = []
        committed = False
        retired = list(dict.fromkeys([*old_pending, *old_refs.values()]))
        refs = {}
        try:
            for name, value in desired.items():
                if value is not None:
                    ref = self._new_secret_ref(name)
                    self._backend_call("set", ref, value)
                    created.append(ref)
                    if self._backend_call("get", ref) != value:
                        raise RelayError("macOS Keychain secret verification failed")
                    new_refs[name] = ref
            metadata = {key: settings[key] for key in ("owner", "repo", "channel", "recipient", "auth_mode") if key in settings}
            metadata["secret_refs"] = new_refs
            pending = [ref for ref in retired if ref not in new_refs.values()]
            if pending:
                metadata["cleanup_pending"] = pending
            self._write_json(metadata)
            committed = True
        except Exception as exc:
            if not committed:
                cleanup_pending = []
                for ref in created:
                    try:
                        self._backend_call("delete", ref)
                    except RelayError:
                        cleanup_pending.append(ref)
                if cleanup_pending and previous_metadata:
                    preserved = dict(previous_metadata)
                    _, existing_pending = self._read_refs(preserved)
                    preserved["cleanup_pending"] = list(dict.fromkeys([*existing_pending, *cleanup_pending]))
                    try:
                        self._write_json(preserved)
                    except RelayError:
                        pass
                if isinstance(exc, RelayError):
                    raise
                raise RelayError("Relay settings could not be saved to macOS Keychain") from None
            raise
        cleanup_pending = []
        for ref in pending:
            try:
                self._backend_call("delete", ref)
            except RelayError:
                cleanup_pending.append(ref)
        if cleanup_pending:
            metadata["cleanup_pending"] = cleanup_pending
        else:
            metadata.pop("cleanup_pending", None)
        try:
            self._write_json(metadata)
        except RelayError:
            # The committed file still records the retired references for a later cleanup attempt.
            pass

    def load(self) -> dict:
        if self.path.is_symlink():
            raise RelayError("Settings path must not be a symlink")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise RelayError("Relay settings are not configured") from None
        if not isinstance(value, dict):
            raise RelayError("Relay settings are invalid")
        if os.name == "posix" and stat.S_IMODE(self.path.stat().st_mode) & 0o077:
            raise RelayError("Relay settings permissions are too broad")
        if self.secret_backend is not None:
            return self._load_keychain(value)
        return value

    def _load_keychain(self, value: dict) -> dict:
        refs = value.get("secret_refs")
        if refs is None:
            legacy = {name: value[name] for name in self.SECRET_NAMES if name in value}
            if not legacy:
                return value
            new_refs = {}
            created = []
            try:
                for name, secret in legacy.items():
                    if not isinstance(secret, str):
                        raise RelayError("Legacy relay settings are invalid")
                    ref = self._new_secret_ref(name)
                    self._backend_call("set", ref, secret)
                    created.append(ref)
                    if self._backend_call("get", ref) != secret:
                        raise RelayError("macOS Keychain secret verification failed")
                    new_refs[name] = ref
                metadata = dict(value)
                for name in legacy:
                    metadata.pop(name, None)
                metadata["secret_refs"] = new_refs
                self._write_json(metadata)
            except Exception:
                for ref in created:
                    try:
                        self._backend_call("delete", ref)
                    except RelayError:
                        pass
                raise RelayError("Legacy relay secrets could not be migrated; original settings were preserved") from None
            value = metadata
            refs = metadata["secret_refs"]
        refs, _ = self._read_refs(value)
        if set(refs) != set(value.get("secret_refs", {})):
            raise RelayError("Relay secret references are invalid")
        result = dict(value)
        result.pop("secret_refs", None)
        result.pop("cleanup_pending", None)
        for name in self.SECRET_NAMES:
            if name in refs:
                secret = self._backend_call("get", refs[name])
                if secret is None:
                    raise RelayError("Saved relay secrets are unavailable from macOS Keychain")
                result[name] = secret
        if result.get("auth_mode") == "pat" and not result.get("token"):
            raise RelayError("Saved relay secrets are unavailable from macOS Keychain")
        return result

    def remove(self) -> None:
        if self.secret_backend is None:
            self.path.unlink(missing_ok=True)
            return
        try:
            metadata = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError):
            raise RelayError("Relay settings could not be removed") from None
        if not isinstance(metadata, dict):
            raise RelayError("Relay settings could not be removed")
        refs, pending = self._read_refs(metadata)
        owned_refs = list(dict.fromkeys([*refs.values(), *pending]))
        try:
            if owned_refs:
                self._write_json({"secret_refs": {}, "cleanup_pending": owned_refs})
            for ref in owned_refs:
                self._backend_call("delete", ref)
            self.path.unlink(missing_ok=True)
        except Exception:
            raise RelayError("Relay settings could not be removed") from None

    def status(self) -> dict:
        try:
            s = self.load()
            flags = {"auth_mode": s.get("auth_mode"), "owner_set": bool(s.get("owner")),
                     "repo_set": bool(s.get("repo")), "channel_set": bool(s.get("channel")),
                     "pairing_key_set": bool(s.get("pairing_key")), "token_set": bool(s.get("token")) or s.get("auth_mode") == "gh",
                     "keychain_cleanup_pending": bool(json.loads(self.path.read_text(encoding="utf-8")).get("cleanup_pending", [])) if self.secret_backend is not None else False}
            flags["configured"] = all(flags[key] for key in ("owner_set", "repo_set", "channel_set", "pairing_key_set", "token_set"))
            return flags
        except RelayError as exc:
            flags = {"configured": False, "auth_mode": None, "owner_set": False, "repo_set": False,
                     "channel_set": False, "pairing_key_set": False, "token_set": False}
            if "Keychain" in str(exc):
                flags["error"] = "Saved secrets are unavailable from macOS Keychain"
            return flags


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


class SafeHTTP:
    """Minimal HTTPS transport with a single tightly-scoped asset CDN hop."""
    def __init__(self, opener: Callable | None = None):
        self.opener = opener or self._open

    @staticmethod
    def _open(request: urllib.request.Request):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            return opener.open(request, timeout=60)
        except urllib.error.HTTPError as e:
            return e

    def request(self, method: str, url: str, headers: dict[str, str], body: bytes | None = None,
                allow_asset_redirect: bool = False) -> Response:
        try:
            parsed = urllib.parse.urlsplit(url)
            parsed_port = parsed.port
        except ValueError:
            raise RelayError("Relay URL rejected") from None
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed_port not in (None, 443) or parsed.hostname not in ("api.github.com", "uploads.github.com"):
            raise RelayError("Relay URL rejected")
        if allow_asset_redirect and (method != "GET" or parsed.hostname != "api.github.com" or not re.fullmatch(r"/repos/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/releases/assets/[0-9]+", parsed.path)):
            raise RelayError("Asset redirect is not permitted for this request")
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            response = self.opener(req)
            status = getattr(response, "status", getattr(response, "code", 0))
            rh = {k.lower(): v for k, v in response.headers.items()}
            content = response.read(MAX_PACKET + 1)
        except Exception:
            raise RelayError("Relay request failed") from None
        if len(content) > MAX_PACKET:
            raise RelayError("Relay response exceeds the size limit")
        if status in (301, 302, 303, 307, 308):
            location = rh.get("location", "")
            try:
                target = urllib.parse.urlsplit(urllib.parse.urljoin(url, location))
                target_port = target.port
            except ValueError:
                raise RelayError("Relay redirect rejected") from None
            if not allow_asset_redirect or status != 302 or target.scheme != "https" or target.hostname != CDN_HOST or target_port not in (None, 443) or target.username or target.password:
                raise RelayError("Relay redirect rejected")
            # The signed asset CDN gets no API authorization, cookies, or caller headers.
            cdn_req = urllib.request.Request(urllib.parse.urlunsplit(target), headers={"Accept": "application/octet-stream"}, method="GET")
            try:
                cdn = self.opener(cdn_req)
                cstatus = getattr(cdn, "status", getattr(cdn, "code", 0))
                cbody = cdn.read(MAX_PACKET + 1)
            except Exception:
                raise RelayError("Asset download failed") from None
            if cstatus != 200 or len(cbody) > MAX_PACKET:
                raise RelayError("Asset download failed")
            return Response(cstatus, {}, cbody)
        return Response(status, rh, content)


class GitHubRelay:
    """Single private repository relay. `http` is mocked in unit tests."""
    def __init__(self, settings: dict, http: SafeHTTP | None = None, token: str | None = None):
        if not isinstance(settings, dict):
            raise RelayError("Invalid relay settings")
        self.settings = settings
        self.http = http or SafeHTTP()
        self.owner, self.repo = settings["owner"], settings["repo"]
        self.channel = settings["channel"]
        if not isinstance(self.owner, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", self.owner) or not isinstance(self.repo, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", self.repo):
            raise RelayError("Invalid relay repository")
        if not isinstance(self.channel, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", self.channel):
            raise RelayError("Invalid relay channel")
        pairing_key = settings.get("pairing_key")
        if not isinstance(pairing_key, str):
            raise RelayError("Pairing key is not configured")
        try:
            self.key = base64.urlsafe_b64decode(pairing_key + "=" * (-len(pairing_key) % 4))
        except Exception:
            raise RelayError("Pairing key is invalid") from None
        _validate_key(self.key)
        self.token = token if token is not None else settings.get("token", "")
        if not isinstance(self.token, str) or len(self.token) < 20 or any(ord(ch) < 33 or ord(ch) > 126 for ch in self.token):
            raise RelayError("Relay credentials are unavailable")

    def _api(self, method: str, path: str, body: bytes | None = None, content_type="application/json", binary=False, expected=(200, 201, 204)) -> Response:
        if (path and not path.startswith("/")) or ".." in path.split("/"):
            raise RelayError("Relay path rejected")
        url = API + f"/repos/{urllib.parse.quote(self.owner, safe='')}/{urllib.parse.quote(self.repo, safe='')}" + path
        headers = {"Authorization": f"Bearer {self.token}", "Accept": ("application/octet-stream" if binary else "application/vnd.github+json"),
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Teleport"}
        if body is not None:
            headers["Content-Type"] = content_type
        response = self.http.request(method, url, headers, body, allow_asset_redirect=binary)
        if response.status not in expected:
            raise RelayError("GitHub relay request was rejected")
        return response

    def _assert_private(self) -> None:
        data = self._api("GET", "").body
        try:
            repo = json.loads(data)
        except Exception:
            raise RelayError("Repository verification failed") from None
        if not isinstance(repo, dict) or repo.get("private") is not True or repo.get("full_name", "").casefold() != f"{self.owner}/{self.repo}".casefold():
            raise RelayError("Configured repository must exist and be private")

    def _release(self, create=False) -> dict:
        self._assert_private()
        tag = "teleport-private-relay"
        found = []
        for page in range(1, 11):
            response = self._api("GET", f"/releases?per_page=100&page={page}")
            data = json.loads(response.body)
            if not isinstance(data, list):
                raise RelayError("Relay release listing failed")
            page_found = [item for item in data if isinstance(item, dict) and item.get("tag_name") == tag]
            found.extend(page_found)
            if page_found:
                break
            if len(data) < 100:
                break
        else:
            raise RelayError("Repository release limit exceeded; relay release not found")
        if found:
            release = found[0]
            if release.get("draft") is not True or type(release.get("id")) is not int:
                raise RelayError("Relay release must be a draft")
            return release
        if not create:
            raise RelayError("Private relay release is unavailable")
        created = json.loads(self._api("POST", "/releases", _json_bytes({"tag_name": tag, "name": "Encrypted File Transfer relay", "draft": True, "prerelease": True})).body)
        if not isinstance(created, dict) or type(created.get("id")) is not int or created.get("draft") is not True or created.get("tag_name") != tag:
            raise RelayError("Could not create private relay release")
        return created

    def _upload(self, release: dict, asset_name: str, raw: bytes) -> None:
        if not _valid_asset(asset_name) and not (isinstance(asset_name, str) and re.fullmatch(r"rcpt-[a-f0-9]{48}\.tpr", asset_name)):
            raise RelayError("Asset name rejected")
        self._assert_private()
        rid = release.get("id")
        if type(rid) is not int or release.get("draft") is not True or release.get("tag_name") != "teleport-private-relay":
            raise RelayError("Invalid release")
        query = urllib.parse.urlencode({"name": asset_name})
        url = f"{UPLOAD}/repos/{urllib.parse.quote(self.owner, safe='')}/{urllib.parse.quote(self.repo, safe='')}/releases/{rid}/assets?{query}"
        result = self.http.request("POST", url, {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json", "Content-Type": "application/octet-stream", "User-Agent": "Teleport"}, raw)
        if result.status != 201:
            raise RelayError("Relay asset upload failed")

    def _assets(self, release: dict) -> list[dict]:
        self._assert_private()
        all_assets = []
        for page in range(1, 11):
            data = json.loads(self._api("GET", f"/releases/{release['id']}/assets?per_page=100&page={page}").body)
            if not isinstance(data, list):
                raise RelayError("Relay asset listing failed")
            all_assets.extend(a for a in data if isinstance(a, dict))
            if len(data) < 100:
                return all_assets
        raise RelayError("Relay asset limit exceeded; remove old transfers before continuing")

    def send(self, recipient: str, expiry: int, files: list[tuple[str, bytes]]) -> dict:
        transfer_id = secrets.token_hex(16)
        packet = build_packet(self.key, transfer_id, recipient, self.channel, expiry, files)
        release = self._release(create=True)
        asset = "xfer-" + secrets.token_hex(24) + ".tpx"
        self._upload(release, asset, packet)
        return {"transfer_id": transfer_id, "asset": asset, "expires": expiry,
                "packet_sha256": hashlib.sha256(packet).hexdigest(), "files": len(files)}

    def download(self, transfer_id: str, asset_name: str) -> bytes:
        if not _valid_id(transfer_id) or not _valid_asset(asset_name):
            raise RelayError("Transfer reference rejected")
        release = self._release(create=False)
        assets = self._assets(release)
        matches = [a for a in assets if a.get("name") == asset_name and type(a.get("id")) is int]
        if len(matches) != 1:
            raise RelayError("Transfer asset is unavailable")
        asset_id = matches[0]["id"]
        # GitHub may respond with 200 bytes or one strict signed-CDN redirect.
        response = self._api("GET", f"/releases/assets/{asset_id}", binary=True)
        return response.body

    def transfer_available(self, transfer_id: str, asset_name: str) -> bool:
        if not _valid_id(transfer_id) or not _valid_asset(asset_name):
            raise RelayError("Transfer reference rejected")
        release = self._release(create=False)
        assets = self._assets(release)
        return any(a.get("name") == asset_name for a in assets)

    def receive(self, transfer_id: str, asset_name: str, recipient: str, destination: Path,
                state_path: Path, _packet: bytes | None = None) -> dict:
        packet = _packet if _packet is not None else self.download(transfer_id, asset_name)
        decoded = open_packet(self.key, transfer_id, packet)
        if decoded["recipient"].casefold() != recipient.casefold() or decoded["channel"] != self.channel:
            raise RelayError("Transfer recipient or channel does not match")
        state = ReplayStore(state_path)
        packet_hash = hashlib.sha256(packet).hexdigest()
        if state.seen(transfer_id, packet_hash):
            raise RelayError("This transfer was already received")
        pending = state.pending(transfer_id, packet_hash)
        if pending:
            written = verify_saved_files(destination, transfer_id, decoded["files"])
        else:
            written = safe_write_files(destination, transfer_id, decoded["files"])
            state.record_pending(transfer_id, packet_hash, written)
        receipt_name = receipt_asset_name(self.key, transfer_id)
        receipt = self._existing_receipt(transfer_id, receipt_name, packet, decoded)
        if receipt is None:
            raw_receipt = make_receipt(self.key, transfer_id, packet, decoded["recipient"], decoded["channel"], decoded["expires"], decoded["files"])
            release = self._release(create=False)
            try:
                self._upload(release, receipt_name, raw_receipt)
            except RelayError:
                # An upload can succeed while its response is lost. Verify the
                # existing receipt before treating the retry as complete.
                receipt = self._existing_receipt(transfer_id, receipt_name, packet, decoded)
                if receipt is None:
                    raise
            else:
                parsed = verify_receipt(self.key, transfer_id, raw_receipt, packet,
                                        decoded["recipient"], decoded["channel"], decoded["expires"])
                expected_files = [{"name": filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                  for filename, data in decoded["files"]]
                if parsed.get("files") != expected_files:
                    raise RelayError("Receipt file list does not match the transfer")
                receipt = raw_receipt
        state.complete(transfer_id, packet_hash)
        return {"transfer_id": transfer_id, "files": written, "receipt_sha256": hashlib.sha256(receipt).hexdigest()}

    def receive_inbox_once(self, recipient: str, destination: Path, state_path: Path) -> dict:
        if not isinstance(recipient, str) or not recipient.strip() or len(recipient) > 160:
            raise RelayError("Recipient is required")
        release = self._release(create=False)
        assets = [a for a in self._assets(release) if isinstance(a.get("name"), str) and SAFE_ASSET.fullmatch(a["name"])]
        state = ReplayStore(state_path)
        received, ignored = [], []
        prefix = VERSION + b"\0"
        downloaded = 0
        examined = 0
        truncated = False
        for asset in assets:
            asset_id = asset.get("id")
            if type(asset_id) is not int:
                ignored.append({"asset": asset["name"], "reason": "invalid asset record"})
                continue
            prior = state.asset_result(asset["name"], str(asset_id))
            if prior is not None:
                continue
            # Reserve a full maximum-sized packet before starting another read.
            if examined >= MAX_INBOX_SCAN or downloaded + MAX_PACKET > MAX_INBOX_BYTES:
                truncated = True
                break
            examined += 1
            packet = self._api("GET", f"/releases/assets/{asset_id}", binary=True).body
            downloaded += len(packet)
            if not packet.startswith(prefix) or len(packet) < len(prefix) + 32:
                reason = "unrecognized encrypted packet"
                ignored.append({"asset": asset["name"], "reason": reason})
                state.record_asset(asset["name"], str(asset_id), reason)
                continue
            try:
                transfer_id = packet[len(prefix):len(prefix) + 32].decode("ascii")
                decoded = open_packet(self.key, transfer_id, packet)
            except (UnicodeDecodeError, RelayError):
                reason = "packet authentication, format, or expiry check failed"
                ignored.append({"asset": asset["name"], "reason": reason})
                state.record_asset(asset["name"], str(asset_id), reason)
                continue
            if decoded["recipient"].casefold() != recipient.strip().casefold() or decoded["channel"] != self.channel:
                reason = "not addressed to this recipient and channel"
                ignored.append({"asset": asset["name"], "reason": reason})
                state.record_asset(asset["name"], str(asset_id), reason)
                continue
            digest = hashlib.sha256(packet).hexdigest()
            if state.seen(transfer_id, digest):
                reason = "already received"
                ignored.append({"asset": asset["name"], "reason": reason})
                state.record_asset(asset["name"], str(asset_id), reason)
                continue
            received.append(self.receive(transfer_id, asset["name"], recipient, destination, state_path, _packet=packet))
            state = ReplayStore(state_path)
            state.record_asset(asset["name"], str(asset_id), "already received")
        return {"checked": len(assets), "received": received, "ignored": ignored,
                "scan_limit": MAX_INBOX_SCAN, "byte_limit": MAX_INBOX_BYTES,
                "downloaded_bytes": downloaded, "truncated": truncated}

    def watch_inbox(self, recipient: str, destination: Path, state_path: Path,
                    timeout: int = 86400, interval: int = 15, on_poll=None) -> dict:
        if type(timeout) is not int or not 1 <= timeout <= 7 * 86400 or type(interval) is not int or not 5 <= interval <= 300:
            raise RelayError("Watch timeout must be 1 second to 7 days and interval 5 to 300 seconds")
        deadline = time.monotonic() + timeout
        received, ignored = [], {}
        checked = 0
        while time.monotonic() < deadline:
            try:
                result = self.receive_inbox_once(recipient, destination, state_path)
            except RelayError as exc:
                if str(exc) != "Private relay release is unavailable":
                    raise
                result = {"checked": 0, "received": [], "ignored": []}
            checked += result["checked"]
            received.extend(result["received"])
            for item in result["ignored"]:
                ignored[item["asset"]] = item["reason"]
            if on_poll is not None:
                on_poll({"checked": result["checked"], "received": len(result["received"]), "ignored": len(result["ignored"])})
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
        return {"polls_complete": True, "checked_assets": checked, "received": received,
                "ignored": [{"asset": name, "reason": reason} for name, reason in ignored.items()]}

    def watch_receive(self, transfer_id: str, asset_name: str, recipient: str, destination: Path,
                      state_path: Path, timeout: int = 3600, interval: int = 15) -> dict:
        if type(timeout) is not int or not 1 <= timeout <= 7 * 86400 or type(interval) is not int or not 5 <= interval <= 300:
            raise RelayError("Watch timeout must be 1 second to 7 days and interval 5 to 300 seconds")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                return self.receive(transfer_id, asset_name, recipient, destination, state_path)
            except RelayError as exc:
                if str(exc) not in ("Private relay release is unavailable", "Transfer asset is unavailable"):
                    raise
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
        raise RelayError("Transfer did not arrive before the watch timeout")

    def _existing_receipt(self, transfer_id: str, name: str, packet: bytes, decoded: dict) -> bytes | None:
        release = self._release(create=False)
        assets = self._assets(release)
        found = [a for a in assets if a.get("name") == name and type(a.get("id")) is int]
        if not found:
            return None
        if len(found) != 1:
            raise RelayError("Receipt asset is ambiguous")
        response = self._api("GET", f"/releases/assets/{found[0]['id']}", binary=True)
        parsed = verify_receipt(self.key, transfer_id, response.body, packet, decoded["recipient"], decoded["channel"], decoded["expires"])
        expected_files = [{"name": filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                          for filename, data in decoded["files"]]
        if parsed.get("files") != expected_files:
            raise RelayError("Receipt file list does not match the transfer")
        return response.body

    def receipt(self, transfer_id: str, asset_name: str) -> dict:
        packet = self.download(transfer_id, asset_name)
        # Find exactly the expected asset under the same private release.
        release = self._release(create=False)
        name = receipt_asset_name(self.key, transfer_id)
        assets = self._assets(release)
        found = [a for a in assets if a.get("name") == name and type(a.get("id")) is int]
        if len(found) != 1:
            raise RelayError("Verified receipt is unavailable")
        resp = self._api("GET", f"/releases/assets/{found[0]['id']}", binary=True)
        decoded = open_packet(self.key, transfer_id, packet, allow_expired=True)
        result = verify_receipt(self.key, transfer_id, resp.body, packet, decoded["recipient"], decoded["channel"], decoded["expires"])
        expected_files = [{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in decoded["files"]]
        if result.get("files") != expected_files:
            raise RelayError("Receipt file list does not match the transfer")
        return result

    def cleanup(self, transfer_id: str, asset_name: str) -> dict:
        """Delete only this encrypted asset after its matching receipt is verified."""
        receipt = self.receipt(transfer_id, asset_name)
        release = self._release(create=False)
        assets = self._assets(release)
        match = [a for a in assets if a.get("name") == asset_name and type(a.get("id")) is int]
        if len(match) != 1:
            raise RelayError("Transfer asset is unavailable")
        self._assert_private()
        self._api("DELETE", f"/releases/assets/{match[0]['id']}", expected=(204,))
        return {"cleaned": True, "transfer_id": transfer_id, "receipt_verified": True,
                "receipt_files": len(receipt.get("files", []))}


class ReplayStore:
    def __init__(self, path: Path):
        self.path = path
        private_runtime(path.parent)
        if path.is_symlink():
            raise RelayError("Receive history path must not be a symlink")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            data = {}
        if not isinstance(data, dict):
            raise RelayError("Receive history is invalid")
        if os.name == "posix" and path.exists() and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise RelayError("Receive history permissions are too broad")
        self.data = data

    def seen(self, transfer_id: str, digest: str) -> bool:
        value = self.data.get(transfer_id)
        if isinstance(value, str):
            prior_digest, status = value, "complete"
        elif isinstance(value, dict):
            prior_digest, status = value.get("packet_sha256"), value.get("status")
        else:
            prior_digest, status = None, None
        if prior_digest is not None and prior_digest != digest:
            raise RelayError("Transfer ID was reused with different bytes")
        return status == "complete"

    def pending(self, transfer_id: str, digest: str) -> bool:
        value = self.data.get(transfer_id)
        if isinstance(value, dict) and value.get("packet_sha256") == digest and value.get("status") == "pending":
            return True
        return False

    def asset_result(self, name: str, asset_id: str) -> str | None:
        entries = self.data.get("_assets", {})
        record = entries.get(name) if isinstance(entries, dict) else None
        if isinstance(record, dict) and record.get("asset_id") == asset_id:
            return record.get("result") if isinstance(record.get("result"), str) else None
        return None

    def record_asset(self, name: str, asset_id: str, result: str) -> None:
        if not isinstance(name, str) or not re.fullmatch(r"xfer-[a-f0-9]{48}\.tpx", name) or not isinstance(asset_id, str) or not asset_id.isdigit() or not isinstance(result, str):
            raise RelayError("Invalid inbox history record")
        entries = self.data.setdefault("_assets", {})
        if not isinstance(entries, dict):
            raise RelayError("Inbox history is invalid")
        entries[name] = {"asset_id": asset_id, "result": result[:160]}
        while len(entries) > 2000:
            entries.pop(next(iter(entries)))
        self._save()

    def record_pending(self, transfer_id: str, digest: str, files: list[dict]) -> None:
        self._write(transfer_id, {"packet_sha256": digest, "status": "pending", "files": files})

    def complete(self, transfer_id: str, digest: str) -> None:
        self._write(transfer_id, {"packet_sha256": digest, "status": "complete"})

    def _write(self, transfer_id: str, record: dict) -> None:
        digest = record.get("packet_sha256")
        if not _valid_id(transfer_id) or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise RelayError("Invalid receive history record")
        self.data[transfer_id] = record
        self._save()

    def _save(self) -> None:
        tmp = self.path.with_name(self.path.name + "." + secrets.token_hex(8) + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(self.data, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


def _directory_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_safe_directory(destination: Path, create: bool) -> tuple[Path, int]:
    """Walk an absolute directory through held no-follow descriptors."""
    path = Path(os.path.normpath(str(Path(destination).expanduser().absolute())))
    flags = _directory_flags()
    try:
        current_fd = os.open(path.anchor, flags)
    except OSError:
        raise RelayError("Download folder path is missing or unsafe") from None
    try:
        for component in path.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise RelayError("Download folder is missing") from None
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                try:
                    next_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError:
                    raise RelayError("Download folder path must not contain symlinks") from None
            except OSError:
                raise RelayError("Download folder path must not contain symlinks") from None
            os.close(current_fd)
            current_fd = next_fd
        return path, current_fd
    except Exception:
        os.close(current_fd)
        raise


def _open_child_directory(parent_fd: int, name: str) -> int:
    try:
        child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError:
        raise RelayError("Pending receive folder is missing or unsafe") from None
    if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
        os.close(child_fd)
        raise RelayError("Pending receive folder is unsafe")
    return child_fd


def _read_regular_at(directory_fd: int, name: str, missing_message: str, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        file_fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        raise RelayError(missing_message) from None
    try:
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise RelayError("Pending receive file is unsafe")
        blocks = []
        total = 0
        while True:
            block = os.read(file_fd, min(1024 * 1024, max_bytes - total + 1))
            if not block:
                return b"".join(blocks)
            total += len(block)
            if total > max_bytes:
                raise RelayError("Pending receive file exceeds its expected size")
            blocks.append(block)
    finally:
        os.close(file_fd)


def verify_saved_files(destination: Path, transfer_id: str, files: list[tuple[str, bytes]]) -> list[dict]:
    if not _valid_id(transfer_id):
        raise RelayError("Invalid transfer ID")
    _, base_fd = _open_safe_directory(destination, create=False)
    try:
        folder_fd = _open_child_directory(base_fd, transfer_id)
        try:
            verified = []
            for name, expected in files:
                name = _valid_name(name)
                raw = _read_regular_at(folder_fd, name, "Pending receive file is missing or unsafe", len(expected))
                if not hmac.compare_digest(hashlib.sha256(raw).digest(), hashlib.sha256(expected).digest()):
                    raise RelayError("Pending receive file changed")
                verified.append({"name": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            return verified
        finally:
            os.close(folder_fd)
    finally:
        os.close(base_fd)


def _unlink_if_same(directory_fd: int, name: str, identity: tuple[int, int]) -> None:
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == identity:
            os.unlink(name, dir_fd=directory_fd)
    except OSError:
        pass


def safe_write_files(destination: Path, transfer_id: str, files: list[tuple[str, bytes]]) -> list[dict]:
    """Write verified basenames through held no-follow directory descriptors."""
    if not _valid_id(transfer_id):
        raise RelayError("Invalid transfer ID")
    _, base_fd = _open_safe_directory(destination, create=True)
    transfer_fd = None
    transfer_identity = None
    created: list[tuple[str, tuple[int, int]]] = []
    try:
        try:
            os.mkdir(transfer_id, mode=0o700, dir_fd=base_fd)
        except FileExistsError:
            raise RelayError("Transfer folder already exists") from None
        created_stat = os.stat(transfer_id, dir_fd=base_fd, follow_symlinks=False)
        transfer_identity = (created_stat.st_dev, created_stat.st_ino)
        transfer_fd = _open_child_directory(base_fd, transfer_id)
        opened_stat = os.fstat(transfer_fd)
        if (opened_stat.st_dev, opened_stat.st_ino) != transfer_identity:
            raise RelayError("Transfer folder changed while opening")

        results = []
        for name, raw in files:
            name = _valid_name(name)
            digest = hashlib.sha256(raw).hexdigest()
            tmp = "." + secrets.token_hex(12) + ".tmp"
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                file_fd = os.open(tmp, flags, 0o600, dir_fd=transfer_fd)
            except OSError:
                raise RelayError("Could not create a private receive file") from None
            info = os.fstat(file_fd)
            identity = (info.st_dev, info.st_ino)
            created.append((tmp, identity))
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(file_fd, view)
                    if written <= 0:
                        raise RelayError("Could not write the received file")
                    view = view[written:]
                os.fsync(file_fd)
                os.lseek(file_fd, 0, os.SEEK_SET)
                blocks = []
                while True:
                    block = os.read(file_fd, 1024 * 1024)
                    if not block:
                        break
                    blocks.append(block)
                check = b"".join(blocks)
            finally:
                os.close(file_fd)
            if not hmac.compare_digest(hashlib.sha256(check).hexdigest(), digest):
                raise RelayError("Saved file verification failed")

            # Descriptor-relative hard-link publishes atomically and never replaces.
            try:
                os.link(tmp, name, src_dir_fd=transfer_fd, dst_dir_fd=transfer_fd, follow_symlinks=False)
            except OSError:
                raise RelayError("Destination file already exists or could not be published") from None
            created.append((name, identity))
            final_bytes = _read_regular_at(transfer_fd, name, "Saved file verification failed", len(raw))
            if not hmac.compare_digest(hashlib.sha256(final_bytes).hexdigest(), digest):
                raise RelayError("Saved file verification failed")
            _unlink_if_same(transfer_fd, tmp, identity)
            created.remove((tmp, identity))
            results.append({"name": name, "size": len(raw), "sha256": digest})
        return results
    except Exception:
        if transfer_fd is not None:
            for name, identity in reversed(created):
                _unlink_if_same(transfer_fd, name, identity)
        if transfer_fd is not None and transfer_identity is not None:
            os.close(transfer_fd)
            transfer_fd = None
        if transfer_identity is not None:
            try:
                current = os.stat(transfer_id, dir_fd=base_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == transfer_identity:
                    os.rmdir(transfer_id, dir_fd=base_fd)
            except OSError:
                pass
        raise
    finally:
        if transfer_fd is not None:
            os.close(transfer_fd)
        os.close(base_fd)
