# Encrypted File Transfer

**First principle:** Recipients check delivered bytes before the app removes its encrypted relay copy.

Send files with encryption through a private GitHub relay. Check delivery.

The app sends selected files to named recipients. It uses draft assets in a private GitHub repo. AES-GCM encrypts the file and transfer details before upload. These include names, recipient, channel, manifest, and expiry. The receiver checks and saves each file. It then sends an authenticated receipt. The sender can remove the relay asset after checking that receipt.

## Native macOS app

The native Mac app is the main way to use Encrypted File Transfer. It starts its own Python server on a temporary loopback port. A local WKWebView shows the app. It stops the server when the app closes. It does not attach to an existing server.

Build on macOS with Python 3.12.14 and Xcode command line tools. The app includes Python and its pinned packages:

```sh
python3.12 -m venv .desktop-venv
source .desktop-venv/bin/activate
python -m pip install -r requirements-desktop.lock.txt
python build_desktop.py
python install_desktop.py
```

Build creates `dist/Encrypted File Transfer.app`.

Open **Encrypted File Transfer.app** from `~/Applications` or Finder. Quit with **Encrypted File Transfer → Quit Encrypted File Transfer** or `⌘Q`. The app is not Developer ID signed or notarized. Settings, pairing key, token, and receive history stay in `~/Library/Application Support/Teleport`, outside the app and source folder. To uninstall, move `~/Applications/Encrypted File Transfer.app` to Trash. The runtime folder stores settings and receive history. Remove it to erase them. The installer will not replace unrelated or unmarked apps. It keeps an owned prior copy as a dated backup.

## Optional browser preview

The browser interface can also be previewed locally:

```sh
python3 server.py
```

Open `http://127.0.0.1:8311`. The on-device mode remains available. It is for local handoff only and does not encrypt files.

## Configure the private relay

Both people use the same private repo and channel. They share a 32-byte pairing key. The sender can leave Pairing key blank to make a new one. The app shows the new key once. Copy it and share it through a trusted channel. The recipient enters that key in Settings. Each person sets up their own GitHub sign-in.

Use a fine-grained personal access token for this repo. GitHub release uploads need Contents write access and draft release access. Both people need both permissions. The app does not need a public repo. Before each relay action, it checks the full repo name. It also checks that GitHub marks the repo as private.

You can also choose GitHub CLI sign-in. The app runs `gh auth token --hostname github.com` only in this mode. It does not read GitHub CLI credentials in token mode. Settings, token, and pairing key stay outside this checkout. The private runtime folder also keeps replay history. Settings shows only whether each item is set. Remove the pairing key or all relay settings to erase saved secrets.

## Send and receive

Select files and send them through the private relay. Give the recipient the transfer ID and asset reference. The recipient can enter them and click **Check and save once**. Or the recipient can use **Watch for delivery**. The CLI can also find matching encrypted assets:

```sh
python3 teleport_cli.py configure --owner OWNER --repo PRIVATE_REPO --channel team-transfer --recipient Riley --auth pat
python3 teleport_cli.py send ./report.pdf --hours 24
python3 teleport_cli.py inbox
python3 teleport_cli.py watch-inbox --timeout 86400 --interval 15
python3 teleport_cli.py watch TRANSFER_ID ASSET_REFERENCE --timeout 3600
python3 teleport_cli.py cleanup TRANSFER_ID ASSET_REFERENCE
python3 teleport_cli.py status
```

`configure` asks for the pairing key without showing it as you type. Leave it blank to make a key. The new key prints once. A recipient enters the key shared through a trusted channel. With `--auth pat`, the token prompt is hidden too. With `--auth gh`, the CLI uses GitHub CLI sign-in and asks only for the pairing key. `inbox` scans once. `watch-inbox` polls until its time limit or Ctrl-C. Both save checked files under `~/Downloads/Teleport/<transfer-id>/` without overwriting. The sender checks the signed receipt before cleanup. Clean up with a deliberate CLI or Settings action. It deletes only the encrypted relay asset. It never deletes the selected source file.

## Limits and security boundary

- Each file can be up to 16 MiB. A transfer can hold up to 100 files and 32 MiB total. Files stay in memory, so peak use can be several times the transfer size.
- Each remote transfer is one encrypted binary asset. The receiver does not unpack archives. It rejects unsafe names, symlinks, existing transfer folders, and changed bytes. It saves files without overwriting.
- AES-GCM uses a new random 12-byte nonce and a 256-bit pairing key. The transfer ID is hidden and authenticated. User details stay inside the encrypted data. The matching pairing key is needed to decrypt files and make a valid receipt. See the [AES-GCM API reference](https://cryptography.io/en/stable/hazmat/primitives/aead/).
- The GitHub API and upload hosts are fixed. A file download may follow one HTTPS 302 redirect to `release-assets.githubusercontent.com:443`. That request sends no API Authorization or Cookie headers. It cannot redirect again.
- GitHub private release assets carry each transfer. GitHub controls how long they stay available. The app cannot promise delivery if GitHub is down or removes an asset.
- Local-only mode stores chunks without encryption in the private runtime folder. The receiver must use the same device. This mode is not remote or encrypted.

## Test

Requires Python 3.11 or later and `cryptography` (see `requirements.txt`). No test accesses GitHub or requires real credentials.

```sh
python3 -m unittest discover -s tests -v
```

The `cryptography` dependency is distributed under Apache-2.0 OR BSD-3-Clause terms. Original Encrypted File Transfer code is MIT licensed; see `LICENSE`.
