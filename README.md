# Teleport

**First principle:** Recipients check delivered bytes before Teleport removes its encrypted relay copy.

Teleport hands selected files to a named recipient through draft release assets in a GitHub private repository. It encrypts file bytes, names, recipient, channel, manifest, and expiry with AES-GCM before upload. The receiver verifies and saves each file, then publishes an authenticated receipt. The sender can remove the relay asset after checking that receipt.

## Native macOS app

Teleport's native Mac app is the primary interface. It runs the shared Python backend on an ephemeral loopback port, opens a local-only WKWebView, and shuts down its listener when the app closes. It does not attach to an existing server.

Build on macOS with Python 3.12.14 and Xcode command line tools. The build includes Python and the pinned dependencies:

```sh
python3.12 -m venv .desktop-venv
source .desktop-venv/bin/activate
python -m pip install -r requirements-desktop.lock.txt
python build_desktop.py
python install_desktop.py
```

Launch **Teleport.app** from `~/Applications` or Finder. Quit with **Teleport → Quit Teleport** or `⌘Q`. The local build is not Developer ID signed or notarized. Runtime settings, pairing key, token, and receive history live in `~/Library/Application Support/Teleport`, outside the app and source folder. Uninstall by moving `~/Applications/Teleport.app` to Trash. Remove the runtime folder separately only if you also want to erase local settings and receive history. The install script refuses to replace an unrelated or unmarked app and keeps an owned prior copy as a timestamped backup.

## Optional browser preview

The browser interface can also be previewed locally:

```sh
python3 server.py
```

Open `http://127.0.0.1:8311`. The on-device mode remains available. It is for local handoff only and does not encrypt files.

## Configure the private relay

Both participants configure the same private repository, channel, and 32-byte pairing key. The sender can leave Pairing key blank to generate one. Teleport shows a generated key once; copy it and share it separately through a trusted channel. The recipient enters that exact key in Settings. Each participant configures their own GitHub authentication.

Use a fine-grained personal access token with access to the selected private repository. GitHub's release-asset API requires repository Contents write permission for uploads and draft release access; both participants need that permission. Teleport never needs a public repository. It checks that the configured full repository name matches and that GitHub reports it private before each relay operation.

Alternatively, select GitHub CLI authentication. Teleport invokes the installed `gh auth token --hostname github.com` command only after this mode is selected. It does not inspect GitHub CLI credentials in token mode. Settings, token, pairing key, and replay history stay outside this checkout in an owner-only runtime directory. The Settings status reveals configured flags only. Remove pairing key or Remove all relay settings to erase stored secrets.

## Send and receive

Select files in the app and send them through the private relay. Share the transfer ID and opaque asset reference with the recipient. The recipient can enter those values and click **Check and save once**, or use **Watch for delivery**. The CLI can discover matching encrypted assets automatically:

```sh
python3 teleport_cli.py configure --owner OWNER --repo PRIVATE_REPO --channel team-transfer --recipient Riley --auth pat
python3 teleport_cli.py send ./report.pdf --hours 24
python3 teleport_cli.py inbox
python3 teleport_cli.py watch-inbox --timeout 86400 --interval 15
python3 teleport_cli.py watch TRANSFER_ID ASSET_REFERENCE --timeout 3600
python3 teleport_cli.py cleanup TRANSFER_ID ASSET_REFERENCE
python3 teleport_cli.py status
```

`configure` prompts for the pairing key without echoing it; leave the prompt blank to generate a new key, which is printed once. A recipient enters the key received through a separate trusted channel. With `--auth pat`, the token prompt is hidden too. With `--auth gh`, Teleport uses GitHub CLI authentication and asks only for the pairing key. `inbox` scans once. `watch-inbox` polls continuously until its bounded timeout or Ctrl-C. Both save verified files under `~/Downloads/Teleport/<transfer-id>/` without overwriting. The sender checks a verified receiver receipt before cleanup. Cleanup is an explicit CLI command or a deliberate Settings flow action; it deletes only the encrypted relay asset. It never deletes the selected source file.

## Limits and security boundary

- Each file is limited to 16 MiB; a transfer is limited to 32 MiB and 100 files. Files are processed in memory, so peak use can be several times the transfer size.
- Each remote transfer is one binary encrypted asset. There is no archive extraction. The receiver rejects unsafe names, symlinks, existing transfer folders, and changed bytes; files are atomically published without clobbering.
- AES-GCM uses a fresh random 12-byte nonce and a 256-bit pairing key. The transfer ID is opaque and authenticated; user metadata stays inside the ciphertext. A matching pairing key is required to decrypt and publish a valid receipt. See the [AES-GCM API reference](https://cryptography.io/en/stable/hazmat/primitives/aead/).
- The GitHub API and uploads host are fixed. An asset download may follow one HTTPS 302 to `release-assets.githubusercontent.com:443`; that request carries no API Authorization or Cookie headers and cannot redirect again.
- GitHub private release assets are the relay. GitHub controls their availability and retention. Teleport does not claim a third-party-independent delivery guarantee.
- The local-only mode stores chunks unencrypted in the private runtime folder and uses the same-device receiver flow. It is not a remote or encrypted transport.

## Test

Requires Python 3.11 or later and `cryptography` (see `requirements.txt`). No test accesses GitHub or requires real credentials.

```sh
python3 -m unittest discover -s tests -v
```

The `cryptography` dependency is distributed under Apache-2.0 OR BSD-3-Clause terms. Original Teleport code is MIT licensed; see `LICENSE`.
