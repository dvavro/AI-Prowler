"""Shared helpers for tests/gui_hr_e2e (sandbox HR browser suite)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

# Throwaway sandbox-only credentials: key -> (name, token, role, email)
USERS = {
    "owner":   ("ZTEST Owner",   "ZTEST_HRGUI_OWNER_TOKEN_0001",   "owner",   "owner+hrtest@example.com"),
    "manager": ("ZTEST Manager", "ZTEST_HRGUI_MANAGER_TOKEN_0002", "manager", "manager+hrtest@example.com"),
    "anna":    ("ZTEST Anna",    "ZTEST_HRGUI_ANNA_TOKEN_0003",    "staff",   "anna+hrtest@example.com"),
    "ben":     ("ZTEST Ben",     "ZTEST_HRGUI_BEN_TOKEN_0004",     "staff",   "ben+hrtest@example.com"),
    "cara":    ("ZTEST Cara",    "ZTEST_HRGUI_CARA_TOKEN_0005",    "staff",   "cara+hrtest@example.com"),
}
# Text that must never show on a screen
BAD_TEXT = ("undefined", "NaN", "[object Object]", "coming in Week", "Lorem ipsum", "Traceback")


def http(method, url, token=None, payload=None, headers=None, timeout=15):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(body) if body.strip().startswith(("{", "[")) else body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body
    except Exception as e:
        return 0, str(e)


class Watch:
    """JS errors seen by one page, plus any request the server refused as not
    signed in (401) - a 401 sends HR Admin back to its sign-in screen."""
    def __init__(self, page, label):
        self.errors, self.refused = [], []
        page.on("pageerror", lambda e: self.errors.append(f"{label} pageerror: {e}"))
        page.on("console", lambda m: self.errors.append(f"{label} console: {m.text}")
                if m.type == "error" and "favicon" not in m.text and "status of 4" not in m.text else None)
        page.on("response", lambda r: self.refused.append(f"{r.status} {r.request.method} {r.url}")
                if r.status in (401, 403) and "/hr-api/" in r.url else None)


def new_page(browser, label, width=1280, height=900):
    ctx = browser.new_context(viewport={"width": width, "height": height}, service_workers="block",
                              timezone_id="America/New_York")
    page = ctx.new_page()
    return ctx, page, Watch(page, label)


def sign_in_admin(page, sb, who="manager"):
    page.goto(f"{sb.base}/hr_admin/")
    page.fill("#auth-name", USERS[who][0])
    page.fill("#auth-token", USERS[who][1])
    page.click("button.auth-btn")
    page.wait_for_selector("#app", state="visible", timeout=20000)
    page.wait_for_timeout(1500)


def sign_in_portal(page, sb, who):
    page.add_init_script("try{localStorage.setItem('hr_gs_seen','1')}catch(e){}")
    page.goto(f"{sb.base}/hr_portal/")
    page.fill("#login-name", USERS[who][0])
    page.fill("#login-pass", USERS[who][1])
    page.click("#login-btn")
    page.wait_for_function("() => typeof authState !== 'undefined' && authState && authState.session", timeout=20000)
    page.wait_for_timeout(2000)


def visible_text(page, selector):
    try:
        return page.inner_text(selector, timeout=5000)
    except Exception:
        return ""


def bad_words(text):
    return [w for w in BAD_TEXT if w in text]
