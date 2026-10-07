"""SECURITY FIX 2026-09-25 — personal-mode PWA authentication.

Found: in personal mode
  * /pwa-token handed the owner's Bearer Token (config.json remote_token) to
    ANY caller, no auth;
  * the Jobs PWA and the Remote PWA "logged in" by comparing the typed token
    against that downloaded copy in the browser;
  * /pwa-api (read/change/delete jobs & customers, send SMS/email) and
    /photos/upload required no token at all.
On the public tunnel URL anyone who knew the address could do all of that.

Fixed: /pwa-token never returns the token; /pwa-verify checks a typed token on
the server; /pwa-api and /photos/upload require a valid Bearer token
(_access_tokens, the same set /remote-api and /mcp use); both PWAs verify on
the server and send the token on every request. Also: the static-file and
Remote-upload "inside this folder" checks were prefix matches (…\\jobs_old
passed for …\\jobs; a writable …\\proj allowed …\\project2) — now
_path_is_inside().

These are source-level guards (the personal router is built inside the
server-start function and can't be instantiated here); the live check is in
the Jobs E2E suite (spec §6.13, SEC-*).
"""
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SRC = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
JOBS = (ROOT / "jobs" / "index.html").read_text(encoding="utf-8")
REMOTE = (ROOT / "remote" / "index.html").read_text(encoding="utf-8")

PERSONAL = SRC[SRC.index("class _RouterASGI:"):]          # personal-mode router onward
SERVER = SRC[:SRC.index("class _RouterASGI:")]


def _block(text, start_marker, length=2500):
    i = text.index(start_marker)
    return text[i:i + length]


# ── server: personal mode ────────────────────────────────────────────────────
def test_pwa_token_never_returns_the_token():
    blk = _block(PERSONAL, 'if path == "/pwa-token":', 1600)
    blk = blk[:blk.index("# ── end PWA token endpoint")]
    assert "remote_token" not in blk, "/pwa-token must never read or return the Bearer Token"
    assert '"token":      ""' in blk


def test_pwa_verify_checks_on_the_server_and_refuses_with_401():
    blk = _block(PERSONAL, 'if path == "/pwa-verify" and method == "POST":', 2000)
    assert "_access_tokens" in blk
    assert "401" in blk and "sleep(" in blk                    # refuses, slowed down


def test_pwa_api_requires_a_token_before_doing_anything():
    blk = _block(PERSONAL, 'if path == "/pwa-api":', 300)
    assert "if not await _pwa_personal_auth(scope, send):" in blk


def test_photo_upload_requires_a_token_before_reading_the_body():
    blk = _block(PERSONAL, 'if path == "/photos/upload":', 300)
    assert "if not await _pwa_personal_auth(scope, send):" in blk


def test_auth_helper_uses_the_same_token_set_as_remote_api_and_mcp():
    helper = _block(SRC, "async def _pwa_personal_auth(scope, send) -> bool:", 1200)
    assert "_tok in _access_tokens" in helper and "401" in helper


def test_no_personal_endpoint_is_documented_as_no_auth_any_more():
    for marker in ("PWA API endpoint — no auth required", "PWA photo upload endpoint — no auth required",
                   "PWA token endpoint — no auth required"):
        assert marker not in SRC


def test_server_mode_endpoints_still_require_their_own_login():
    # unchanged by this fix, asserted so it stays that way
    api = _block(SERVER, 'if path == "/pwa-api" and method == "POST":', 600)
    assert "_bearer_from_scope(scope)" in api and "401" in api
    tok = _block(SERVER, 'if path == "/pwa-token":', 200)
    assert '"token": ""' in tok


# ── Jobs PWA ────────────────────────────────────────────────────────────────
def test_jobs_pwa_never_takes_the_token_from_the_server():
    fn = JOBS[JOBS.index("async function loadBearerToken()"):JOBS.index("function _withAuth(")]
    assert not re.search(r"BEARER_TOKEN\s*=[^=]", fn), "loadBearerToken must never set BEARER_TOKEN"
    assert "data.token" not in fn


def test_jobs_pwa_login_is_verified_by_the_server():
    assert "entered !== BEARER_TOKEN" not in JOBS
    assert "'/pwa-verify'" in JOBS


def test_jobs_pwa_sends_the_token_on_every_request():
    mcp = JOBS[JOBS.index("async function mcpCall("):JOBS.index("async function mcpCall(") + 400]
    assert "_withAuth(" in mcp
    assert "const uploadHeaders = _withAuth(" in JOBS
    helper = JOBS[JOBS.index("function _withAuth("):JOBS.index("function _withAuth(") + 300]
    assert "BEARER_TOKEN" in helper and "ACCESS_TOKEN" in helper


# ── Remote PWA ──────────────────────────────────────────────────────────────
def test_remote_pwa_never_takes_the_token_from_the_server():
    assert "BEARER = d.token" not in REMOTE


def test_remote_pwa_login_and_resume_are_verified_by_the_server():
    assert "async function verifyToken(" in REMOTE and "'/pwa-verify'" in REMOTE
    do_auth = REMOTE[REMOTE.index("async function doAuth()"):REMOTE.index("async function doAuth()") + 500]
    assert "verifyToken(v)" in do_auth and "v !== BEARER" not in do_auth
    init = REMOTE[REMOTE.index("// ── Init ──"):REMOTE.index("// ── Init ──") + 700]
    assert "await verifyToken(s.token)" in init and "s.token === BEARER" not in init
    # NOTE: the separate "re-enter your token to confirm" prompt before sensitive
    # actions (raAttempts) still compares against BEARER — fine: BEARER now only
    # ever holds a token the server already verified at login, and the action it
    # guards is itself checked by /remote-api on the server.


# ── "inside this folder" checks ─────────────────────────────────────────────
def test_folder_checks_use_real_containment_not_prefix_matching():
    assert "_path_is_inside(file_path, _pwa_root)" in SRC               # personal /jobs
    assert "_path_is_inside(_srv_file_path, _srv_pwa_root)" in SRC      # server /jobs
    assert "_path_is_inside(_file6, _remote_root)" in SRC               # /remote static
    assert "_path_is_inside(_up_dir_abs, w)" in SRC                     # /remote/upload writable dirs
    assert "abspath(file_path).startswith(" not in SRC
    assert "_up_dir_abs.lower().startswith(" not in SRC


@pytest.fixture(scope="module")
def inside():
    import ai_prowler_mcp as ap
    return ap._path_is_inside


def test_path_is_inside_basics(inside, tmp_path):
    root = tmp_path / "jobs"
    root.mkdir()
    assert inside(root, root)
    assert inside(root / "index.html", root)
    assert inside(root / "a" / "b.js", root)
    assert not inside(tmp_path / "jobs_old" / "secret.txt", root)       # the prefix bug
    assert not inside(root / ".." / "config.json", root)                # traversal
    assert not inside(tmp_path, root)


@pytest.mark.skipif(os.name != "nt", reason="Windows drive/case semantics")
def test_path_is_inside_windows_edges(inside, tmp_path):
    root = tmp_path / "Proj"
    root.mkdir()
    assert inside(str(root).upper() + "\\x.txt", root)                  # case-insensitive
    other = "D:\\x" if str(tmp_path)[:1].upper() != "D" else "E:\\x"
    assert not inside(other, root)                                      # different drive → never inside
