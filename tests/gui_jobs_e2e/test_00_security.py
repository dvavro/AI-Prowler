"""SEC-01..SEC-07, SEC-10 (spec §6.13) — run FIRST. Talks to the public
address with plain HTTP outside the browser (what a stranger could do), plus
the browser login. Read-only (only check_ai_prowler_status). Never logs the token."""
import json

import pytest

from api import http

STATUS = {"tool": "check_ai_prowler_status", "args": {}}


def _req(origin, method, path, body=None, token=None):
    return http(method, origin + path, body, token=token, timeout=30)


@pytest.fixture(scope="module")
def origin(api):
    return api.origin


def test_SEC_01_pwa_token_hands_out_no_token(origin):
    s, b = _req(origin, "GET", "/pwa-token")
    assert s == 200
    d = json.loads(b)
    assert d.get("token") == "" and d.get("mode") == "personal"


def test_SEC_02_api_without_token_is_refused(origin):
    assert _req(origin, "POST", "/pwa-api", STATUS)[0] == 401


def test_SEC_03_api_with_wrong_token_is_refused(origin):
    assert _req(origin, "POST", "/pwa-api", STATUS, token="wrong-" + "x" * 24)[0] == 401


def test_SEC_04_photo_upload_without_token_is_refused(origin):
    assert _req(origin, "POST", "/photos/upload", {"job_id": "ZTEST", "photos": []})[0] == 401


def test_SEC_05_login_check_is_done_by_the_server(origin, token):
    assert _req(origin, "POST", "/pwa-verify", {"token": "wrong-" + "x" * 24})[0] == 401
    assert _req(origin, "POST", "/pwa-verify", {"token": token})[0] == 200


def test_SEC_06_api_with_right_token_works(origin, token):
    s, b = _req(origin, "POST", "/pwa-api", STATUS, token=token)
    assert s == 200 and json.loads(b).get("ok") is True


@pytest.mark.no_login
def test_SEC_07_login_screen_never_receives_the_real_token(page, app_url, token):
    from app import JobsApp
    seen = []
    page.on("response", lambda r: seen.append(r) if "/pwa-token" in r.url else None)
    a = JobsApp(page, app_url).open_login_screen()
    a.login("definitely-wrong-token")
    from playwright.sync_api import expect
    expect(a.auth_error()).to_be_visible()
    assert a.saved_auth() is None
    for r in seen:
        assert token not in r.text(), "the real token reached the browser"
    assert page.evaluate("() => BEARER_TOKEN") == ""


@pytest.mark.parametrize("path", ["/jobs/../remote/index.html", "/jobs/..%2F..%2Fconfig.json",
                                  "/jobs/%2E%2E/ai_prowler_mcp.py", "/jobs/..%5C..%5Cconfig.json"])
def test_SEC_10_static_files_never_serve_private_files(origin, path):
    # Cloudflare may normalise '..' away and serve a PUBLIC page (e.g. /remote/) —
    # fine. What must never come back is a private file: config/token or source.
    s, b = _req(origin, "GET", path)
    for secret in ('"remote_token"', '"tunnel_domain"', "#!/usr/bin/env python3", "def _pwa_personal_auth"):
        assert secret not in b, f"{path} -> HTTP {s} leaked private content ('{secret}')"
