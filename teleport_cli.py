#!/usr/bin/env python3
"""Command-line entry point for Teleport's shared relay backend."""
import argparse
import getpass
import json
import secrets
import sys
import time

from relay_core import RelayError
from remote_service import (check_receipt, cleanup_remote, configure, receive_once,
                            receive_inbox_once, remove_pairing_key, remove_settings,
                            send_paths, settings_status, watch_inbox, watch_receive,
                            watch_receipt)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="teleport", description="Encrypted private-repository file handoff")
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("configure", help="Configure the private GitHub relay")
    setup.add_argument("--owner", required=True)
    setup.add_argument("--repo", required=True)
    setup.add_argument("--channel", required=True)
    setup.add_argument("--recipient", required=True)
    setup.add_argument("--auth", choices=("pat", "gh"), required=True)
    send = sub.add_parser("send", help="Encrypt selected files and upload a private relay asset")
    send.add_argument("files", nargs="+")
    send.add_argument("--recipient")
    send.add_argument("--hours", type=int, default=24)
    receive = sub.add_parser("receive", help="Save and verify one received transfer")
    receive.add_argument("transfer_id")
    receive.add_argument("asset_name")
    receive.add_argument("--recipient")
    receive.add_argument("--destination")
    inbox = sub.add_parser("inbox", help="Scan once and save authenticated files addressed to this recipient")
    inbox.add_argument("--recipient")
    inbox.add_argument("--destination")
    receipt = sub.add_parser("receipt", help="Check an authenticated receiver receipt")
    receipt.add_argument("transfer_id")
    receipt.add_argument("asset_name")
    watch = sub.add_parser("watch", help="Poll until the receiver publishes a verified receipt")
    watch.add_argument("transfer_id")
    watch.add_argument("asset_name")
    watch.add_argument("--timeout", type=int, default=3600)
    watch.add_argument("--interval", type=int, default=15)
    watch_in = sub.add_parser("watch-receive", help="Poll and automatically save one incoming transfer")
    watch_in.add_argument("transfer_id")
    watch_in.add_argument("asset_name")
    watch_in.add_argument("--recipient")
    watch_in.add_argument("--destination")
    watch_in.add_argument("--timeout", type=int, default=3600)
    watch_in.add_argument("--interval", type=int, default=15)
    watch_inbox_cmd = sub.add_parser("watch-inbox", help="Continuously poll and save matching incoming transfers")
    watch_inbox_cmd.add_argument("--recipient")
    watch_inbox_cmd.add_argument("--destination")
    watch_inbox_cmd.add_argument("--timeout", type=int, default=86400)
    watch_inbox_cmd.add_argument("--interval", type=int, default=15)
    cleanup = sub.add_parser("cleanup", help="Delete an asset after checking its verified receipt")
    cleanup.add_argument("transfer_id")
    cleanup.add_argument("asset_name")
    sub.add_parser("status", help="Show configured flags without secrets")
    sub.add_parser("remove-settings", help="Remove saved relay credentials and pairing key")
    sub.add_parser("remove-pairing-key", help="Remove the saved pairing key")
    args = parser.parse_args(argv)
    try:
        if args.command == "configure":
            token = getpass.getpass("Fine-grained GitHub token (input hidden): ") if args.auth == "pat" else None
            entered_key = getpass.getpass("Shared pairing key (input hidden; blank generates a new key): ")
            result = configure(args.owner, args.repo, args.channel, args.recipient, args.auth, token,
                               entered_key.strip() or None)
            if result["pairing_key"]:
                print("Pairing key (share with the receiver out of band; it will not be shown again):")
                print(result["pairing_key"])
            else:
                print("Pairing key saved; its value is not shown.")
            print("Settings saved outside the checkout.")
        elif args.command == "send":
            print(json.dumps(send_paths(args.files, args.recipient, args.hours), indent=2))
        elif args.command == "receive":
            from pathlib import Path
            dest = Path(args.destination).expanduser() if args.destination else None
            print(json.dumps(receive_once(args.transfer_id, args.asset_name, args.recipient, dest), indent=2))
        elif args.command == "inbox":
            from pathlib import Path
            dest = Path(args.destination).expanduser() if args.destination else None
            print(json.dumps(receive_inbox_once(args.recipient, dest), indent=2))
        elif args.command == "receipt":
            print(json.dumps(check_receipt(args.transfer_id, args.asset_name), indent=2))
        elif args.command == "watch":
            print(json.dumps(watch_receipt(args.transfer_id, args.asset_name, args.timeout, args.interval), indent=2))
        elif args.command == "watch-receive":
            from pathlib import Path
            dest = Path(args.destination).expanduser() if args.destination else None
            print(json.dumps(watch_receive(args.transfer_id, args.asset_name, args.recipient, dest, args.timeout, args.interval), indent=2))
        elif args.command == "watch-inbox":
            from pathlib import Path
            dest = Path(args.destination).expanduser() if args.destination else None
            def progress(result):
                print(json.dumps({"poll": result}), flush=True)
            print("Watching private relay. Press Ctrl-C to stop.", flush=True)
            try:
                result = watch_inbox(args.timeout, args.interval, args.recipient, dest, progress)
            except KeyboardInterrupt:
                print("Inbox watch stopped.", file=sys.stderr)
                return 130
            print(json.dumps(result, indent=2))
        elif args.command == "cleanup":
            print(json.dumps(cleanup_remote(args.transfer_id, args.asset_name), indent=2))
        elif args.command == "status":
            print(json.dumps(settings_status(), indent=2))
        elif args.command == "remove-settings":
            remove_settings()
            print("Saved relay settings removed.")
        elif args.command == "remove-pairing-key":
            print(json.dumps(remove_pairing_key(), indent=2))
        return 0
    except RelayError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
