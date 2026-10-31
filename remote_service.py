"""Shared operations used by the desktop UI and `teleport` CLI."""
from __future__ import annotations

import base64
import getpass
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from relay_core import (MAX_FILE, MAX_PACKET, GitHubRelay, RelayError, SecretStore,
                        private_runtime)


def runtime_dir() -> Path:
    configured = os.environ.get("TELEPORT_DATA")
    if configured:
        path = Path(configured).expanduser()
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / "Teleport"
    else:
        path = Path.home() / ".local" / "share" / "teleport"
    product_root = Path(__file__).resolve().parent
    try:
        path.resolve().relative_to(product_root)
        raise RelayError("Runtime data must be outside the application folder")
    except ValueError:
        pass
    return private_runtime(path)


def store() -> SecretStore:
    return SecretStore(runtime_dir() / "relay-settings.json")


def gh_token() -> str:
    """Only called when the user explicitly selected `gh` authentication."""
    candidates = ("/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh")
    executable = next((candidate for candidate in candidates if os.path.isfile(candidate) and os.access(candidate, os.X_OK)), None)
    if executable is None:
        raise RelayError("GitHub CLI authentication is unavailable")
    try:
        result = subprocess.run([executable, "auth", "token", "--hostname", "github.com"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=True, timeout=10,
                                env={"PATH": os.defpath, "HOME": str(Path.home()), "LANG": "C"})
    except Exception:
        raise RelayError("GitHub CLI authentication is unavailable") from None
    token = result.stdout.decode("utf-8", "strict").strip()
    if len(token) < 20 or "\n" in token:
        raise RelayError("GitHub CLI did not return a valid token")
    return token


def relay(settings: dict | None = None, http=None) -> GitHubRelay:
    settings = settings if settings is not None else store().load()
    token = gh_token() if settings.get("auth_mode") == "gh" else settings.get("token", "")
    return GitHubRelay(settings, http=http, token=token)


def configure(owner: str, repo: str, channel: str, recipient: str,
              auth_mode: str, token: str | None = None, pairing_key: str | None = None) -> dict:
    if not all(isinstance(value, str) for value in (owner, repo, channel, recipient, auth_mode)):
        raise RelayError("Invalid relay settings")
    if auth_mode not in ("pat", "gh"):
        raise RelayError("Choose fine-grained token or explicit GitHub CLI authentication")
    if auth_mode == "pat" and not token:
        raise RelayError("Fine-grained token is required")
    generated = pairing_key is None
    key = pairing_key or base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    try:
        decoded = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
    except Exception:
        raise RelayError("Pairing key must be URL-safe base64") from None
    if len(decoded) != 32:
        raise RelayError("Pairing key must encode exactly 32 bytes")
    settings = {"owner": owner.strip(), "repo": repo.strip(), "channel": channel.strip(),
                "recipient": recipient.strip(), "auth_mode": auth_mode, "pairing_key": key}
    if auth_mode == "pat":
        settings["token"] = token
    store().save(settings)
    return {"configured": True, "pairing_key": key if generated else None, "settings": store().status()}


def remove_settings() -> dict:
    store().remove()
    return store().status()


def settings_status() -> dict:
    return store().status()


def send_paths(paths: list[str], recipient: str | None = None, hours: int = 24,
               service: GitHubRelay | None = None) -> dict:
    if not isinstance(hours, int) or not 1 <= hours <= 168:
        raise RelayError("Expiry must be 1 to 168 hours")
    settings = service.settings if service else store().load()
    receiver = recipient or settings.get("recipient", "")
    if not receiver:
        raise RelayError("Set a recipient in Settings")
    sources: list[tuple[str, bytes]] = []
    total = 0
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        try:
            if path.is_symlink() or not path.is_file():
                raise RelayError("Select regular files only")
            size = path.stat().st_size
            if size > MAX_FILE:
                raise RelayError("A selected file exceeds 16 MiB")
            total += size
            if total > MAX_PACKET - 1024:
                raise RelayError("Transfer exceeds 32 MiB")
            data = path.read_bytes()
        except OSError:
            raise RelayError("A selected file could not be read") from None
        sources.append((path.name, data))
    if not sources:
        raise RelayError("Select at least one file")
    import time
    return (service or relay()).send(receiver, int(time.time()) + hours * 3600, sources)


def send_selected(metadata: dict, payload: bytes, service: GitHubRelay | None = None) -> dict:
    """Validate a browser's length-prefixed file selection before encryption."""
    if not isinstance(metadata, dict) or not isinstance(payload, bytes) or len(payload) > MAX_PACKET:
        raise RelayError("Invalid selected files")
    entries = metadata.get("files")
    recipient, hours = metadata.get("recipient"), metadata.get("hours")
    if not isinstance(recipient, str) or not recipient.strip() or len(recipient) > 160 or type(hours) is not int or not 1 <= hours <= 168:
        raise RelayError("Enter a recipient and expiry from 1 to 168 hours")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
        raise RelayError("Choose 1 to 100 files")
    files = []
    offset = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise RelayError("Invalid selected file")
        name, size, expected = entry.get("name"), entry.get("size"), entry.get("sha256")
        if not isinstance(name, str) or type(size) is not int or size < 0 or size > MAX_FILE or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise RelayError("Invalid selected file")
        data = payload[offset:offset + size]
        if len(data) != size or not secrets.compare_digest(hashlib.sha256(data).hexdigest(), expected):
            raise RelayError("Selected file hash does not match")
        files.append((name, data))
        offset += size
    if offset != len(payload):
        raise RelayError("Selected file lengths do not match")
    import time
    active = service or relay()
    return active.send(recipient.strip(), int(time.time()) + hours * 3600, files)


def receive_once(transfer_id: str, asset_name: str, recipient: str | None = None,
                 destination: Path | None = None, service: GitHubRelay | None = None) -> dict:
    active = service or relay()
    settings = active.settings
    target = destination or (Path.home() / "Downloads" / "Teleport")
    recipient = recipient or settings.get("recipient", "")
    state = runtime_dir() / "received-transfers.json"
    return active.receive(transfer_id, asset_name, recipient, target, state)


def transfer_available(transfer_id: str, asset_name: str, service: GitHubRelay | None = None) -> bool:
    return (service or relay()).transfer_available(transfer_id, asset_name)


def watch_receive(transfer_id: str, asset_name: str, recipient: str | None = None,
                 destination: Path | None = None, timeout: int = 3600, interval: int = 15,
                 service: GitHubRelay | None = None) -> dict:
    active = service or relay()
    settings = active.settings
    target = destination or (Path.home() / "Downloads" / "Teleport")
    recipient = recipient or settings.get("recipient", "")
    state = runtime_dir() / "received-transfers.json"
    return active.watch_receive(transfer_id, asset_name, recipient, target, state, timeout, interval)


def receive_inbox_once(recipient: str | None = None, destination: Path | None = None,
                       service: GitHubRelay | None = None) -> dict:
    active = service or relay()
    target = destination or (Path.home() / "Downloads" / "Teleport")
    recipient = recipient or active.settings.get("recipient", "")
    state = runtime_dir() / "received-transfers.json"
    return active.receive_inbox_once(recipient, target, state)


def watch_inbox(timeout: int = 86400, interval: int = 15, recipient: str | None = None,
                destination: Path | None = None, on_poll=None, service: GitHubRelay | None = None) -> dict:
    active = service or relay()
    target = destination or (Path.home() / "Downloads" / "Teleport")
    recipient = recipient or active.settings.get("recipient", "")
    state = runtime_dir() / "received-transfers.json"
    return active.watch_inbox(recipient, target, state, timeout, interval, on_poll)


def check_receipt(transfer_id: str, asset_name: str, service: GitHubRelay | None = None) -> dict:
    return (service or relay()).receipt(transfer_id, asset_name)


def watch_receipt(transfer_id: str, asset_name: str, timeout: int = 3600,
                  interval: int = 15, service: GitHubRelay | None = None) -> dict:
    if type(timeout) is not int or not 1 <= timeout <= 7 * 86400 or type(interval) is not int or not 5 <= interval <= 300:
        raise RelayError("Watch timeout must be 1 second to 7 days and interval 5 to 300 seconds")
    active = service or relay()
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            return active.receipt(transfer_id, asset_name)
        except RelayError as exc:
            if str(exc) not in ("Verified receipt is unavailable", "Transfer asset is unavailable"):
                raise
            last_error = exc
            # A missing receipt is the expected polling case. Re-check at a bounded interval.
        time.sleep(min(interval, max(0, deadline - time.monotonic())))
    raise RelayError("No verified receipt arrived before the watch timeout") from last_error


def cleanup_remote(transfer_id: str, asset_name: str, service: GitHubRelay | None = None) -> dict:
    return (service or relay()).cleanup(transfer_id, asset_name)


def remove_pairing_key() -> dict:
    settings = store().load()
    settings.pop("pairing_key", None)
    store().save(settings)
    return store().status()
