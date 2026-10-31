# Teleport architecture and invariants

## First principle

Recipients check delivered bytes before Teleport removes its encrypted relay copy.

## Remote relay

- Browser UI and CLI use `remote_service.py`; `relay_core.py` owns protocol, GitHub API, cryptography, receipt, and filesystem rules.
- GitHub relay is opt-in and uses one generic draft release in the configured private repository. Only random asset names and opaque transfer IDs are visible in release metadata.
- An AES-GCM envelope authenticates protocol version and opaque transfer ID. Recipient, channel, expiry, filenames, file sizes, SHA-256 manifest, and bytes are encrypted together. Each packet has a fresh random 12-byte nonce and uses a 256-bit pairing key.
- The GitHub API and upload hosts are fixed. Repository privacy and exact full name are checked before send, list, download, and delete. A binary asset request may follow one 302 to `release-assets.githubusercontent.com` over HTTPS port 443, with all API authorization/cookies stripped and no further redirect.
- Receiver receipts authenticate transfer ID, encrypted packet digest, recipient, channel, expiry, names, sizes, and file hashes. Receiver replay state persists outside the checkout with owner-only permissions. Interrupted receipt publication resumes only after saved files are rehashed.
- Cleanup is sender initiated and requires the matching authenticated receipt. It deletes only the opaque encrypted relay asset, never the selected source files.
- The default receiver folder is `~/Downloads/Teleport/<transfer-id>/`. Paths are basenames only, transfer folders cannot already exist, symbolic links are rejected, publication is no-clobber, and bytes are hashed again after writing.

## Limits

- Up to 100 files, 16 MiB per file, 32 MiB total. Transfer payloads are binary packets, not ZIP archives.
- GitHub release listing and asset scans are paginated and bounded. Inbox discovery scans at most 100 matching transfer assets per pass and reports rejected or unrelated candidates.
- GitHub is the relay and controls availability. The implementation does not promise delivery independent of GitHub.
- The on-device adapter remains available for compatibility. It is a same-device transfer, stores bytes unencrypted, and has a separate recipient-code boundary.

## Local runtime and secrets

- macOS defaults to `~/Library/Application Support/Teleport`; `TELEPORT_DATA` can select another external runtime directory.
- Runtime directories use owner-only permissions, and settings/history files use owner-only permissions on POSIX systems. Runtime data must remain outside the application checkout.
- PAT mode stores the token privately. GitHub CLI mode invokes a fixed installed `gh auth token --hostname github.com` executable only after explicit selection. Neither mode returns credential or pairing-key values through status APIs.
- Pairing keys are shared out of band. The UI returns a newly generated key once during explicit configuration and does not store secrets in browser storage.

## Backend host boundary

- `server.make_server(port=0, data_dir=...)` binds directly to numeric `127.0.0.1`, validates exact Host and Origin boundaries, and uses an in-memory same-origin request token.
- Browser request bodies have strict size limits. The server serves only the fixed app files and explicit API routes.
- A desktop host owns backend startup and shutdown. The manual Python server is only a local preview path.
