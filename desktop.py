#!/usr/bin/env python3
"""Native macOS shell for Encrypted File Transfer."""
from __future__ import annotations

import threading

import server
import webview
from desktop_policy import install_policy


def run() -> None:
    app_server = server.make_server(port=0)
    worker = threading.Thread(target=app_server.serve_forever, name="teleport-http", daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{app_server.server_port}/?desktop=1"
    try:
        webview.create_window("Encrypted File Transfer", url, width=1080, height=760, min_size=(820, 600))
        install_policy(url)
        webview.start()
    finally:
        app_server.shutdown()
        app_server.server_close()
        worker.join(timeout=3)


if __name__ == "__main__":
    try:
        run()
    except Exception:
        import AppKit

        alert = AppKit.NSAlert.alloc().init()
        alert.setMessageText_("Encrypted File Transfer could not start")
        alert.setInformativeText_("The local app failed to open. Restart Encrypted File Transfer and try again.")
        alert.addButtonWithTitle_("OK")
        alert.runModal()
        raise SystemExit(1)
