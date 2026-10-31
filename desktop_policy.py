"""Navigation boundary for the pinned pywebview macOS renderer."""
from __future__ import annotations

from urllib.parse import urlsplit


def local_url(url: str, origin: str) -> bool:
    """Match scheme, host and port without accepting credentials or lookalikes."""
    try:
        candidate, allowed = urlsplit(url), urlsplit(origin)
        return (
            candidate.scheme == allowed.scheme == "http"
            and candidate.hostname == allowed.hostname == "127.0.0.1"
            and candidate.port == allowed.port
            and candidate.username is None
            and candidate.password is None
        )
    except ValueError:
        return False


def navigation_policy(url: str, origin: str, activated: bool, download: bool) -> str:
    """Only a deliberate link may leave the app; local exports may download."""
    if local_url(url, origin):
        return "download" if download else "allow"
    if url.startswith("blob:") and local_url(url[5:], origin) and download:
        return "download"
    try:
        parsed = urlsplit(url)
        if activated and parsed.scheme in ("https", "http") and parsed.hostname and not parsed.username and not parsed.password:
            return "external"
    except ValueError:
        pass
    return "cancel"


def install_policy(origin: str) -> None:
    """Install before creating the Cocoa view. No Python methods enter JS."""
    import AppKit
    import Foundation
    import WebKit
    import webview
    from webview.platforms.cocoa import BrowserView

    parent = BrowserView.BrowserDelegate

    def open_external(url: str) -> None:
        AppKit.NSWorkspace.sharedWorkspace().openURL_(Foundation.NSURL.URLWithString_(url))

    class LocalOnlyBrowserDelegate(parent):
        def webView_decidePolicyForNavigationAction_decisionHandler_(self, view, action, handler):
            url = str(action.request().URL().absoluteString())
            activated = action.navigationType() == WebKit.WKNavigationTypeLinkActivated
            download = bool(action.shouldPerformDownload())
            choice = navigation_policy(url, origin, activated, download)
            if choice == "allow":
                handler(WebKit.WKNavigationActionPolicyAllow)
            elif choice == "download":
                handler(WebKit.WKNavigationActionPolicyDownload)
            else:
                handler(WebKit.WKNavigationActionPolicyCancel)
                if choice == "external":
                    open_external(url)

        def webView_createWebViewWithConfiguration_forNavigationAction_windowFeatures_(self, view, config, action, features):
            url = str(action.request().URL().absoluteString())
            activated = action.navigationType() == WebKit.WKNavigationTypeLinkActivated
            choice = navigation_policy(url, origin, activated, False)
            if activated and choice == "allow":
                view.loadRequest_(action.request())
            elif choice == "external":
                open_external(url)
            return None

    BrowserView.BrowserDelegate = LocalOnlyBrowserDelegate
    webview.settings["ALLOW_DOWNLOADS"] = True
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False
