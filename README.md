# Teleport

First principle: Recipients check delivered bytes before Teleport deletes its copy.

Teleport is a local, resumable file handoff for small teams. It accepts files selected in a browser. It stores transfer chunks and a manifest in a private runtime directory. Before it offers a receipt, it checks SHA-256 hashes. The recipient enters the handoff ID, recipient code, and expected name.

## Run

Requires Python 3. No third-party runtime dependencies.

```sh
python3 server.py
```

Open http://127.0.0.1:8311. Keep the service running for the sender and recipient. The recipient connects in a browser on the same device. Teleport sends no data over the internet. It does not encrypt files at rest or in transit. Do not use it for sensitive files.

## Resume and cleanup

If an upload stops, enter the handoff ID, recipient code, and name in the receive section. Then select the original files. Teleport checks their hashes and skips chunks already stored. The recipient downloads each file through the browser. Teleport compares the downloaded bytes and writes a receipt. After the receipt, the sender can click cleanup to delete Teleport's stored chunks. Cleanup never touches the sender's selected source files.

Transfer folders default to `~/.local/share/teleport` with owner-only directory permissions and owner-only files. Set `TELEPORT_DATA` before startup to choose another runtime folder. Keep it outside the source checkout. Transfers expire after 1 to 168 hours. This build blocks expired access. It does not automatically purge expired folders.

Settings describes the local storage boundary. This version has no external service key to configure.

## Limits

This is a local transport adapter for one device. It does not deliver files remotely. It does not provide end-to-end encryption or encrypted storage. It is not a cloud service. Each transfer can total up to 128 MiB. Files are sent in 1 MiB chunks, and each transfer can hold up to 100 files. The browser uses Web Crypto to hash each full file. Memory use can reach about twice the file size. The receipt is local JSON shown after the browser download. Keep the handoff ID and code private.

## Test

```sh
python3 -m unittest discover -s tests -v
```

## Data and license

No sample user files or personal credentials are included. Runtime files are local and untracked. Original code is MIT licensed; see `LICENSE`.
