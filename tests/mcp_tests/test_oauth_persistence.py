"""
OAuth sign-ins survive an AI-Prowler restart (2026-10-28).

Bug: the access tokens ai_prowler_mcp.py handed to claude.ai lived only in
memory and no refresh token was ever issued, so every restart signed the
Claude connector out (mcp_server.log 2026-10-28 14:45:01 / 15:04:19 "AUTH FAIL:
no valid Bearer token for POST /mcp"). oauth_store.py now keeps hashed tokens
with their expiry in ~/.ai-prowler and both modes use it.

A "restart" here is exactly what happens at start-up: a brand-new OAuthStore
reading the same file.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import oauth_store as OS
from oauth_store import OAuthStore, exchange_token, token_hash

SRC = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
PERSONAL = SRC[SRC.index("def _run_http("):]
SERVER = SRC[SRC.index("def _run_server_mode("):SRC.index("def _run_http(")]


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def path(tmp_path):
    return tmp_path / "oauth_tokens.json"


@pytest.fixture
def clock():
    return Clock()


def restart(path, clock, binding="owner-hash"):
    return OAuthStore(path, binding=binding, clock=clock)


def _pkce():
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _sign_in(store, client_id="cid-1"):
    """The real /token code path: /authorize code + PKCE S256 -> tokens."""
    verifier, challenge = _pkce()
    codes = {"code-1": {"redirect_uri": "https://claude.ai/cb", "code_challenge": challenge,
                        "code_challenge_method": "S256", "client_id": client_id}}
    status, body = exchange_token(store, {"grant_type": "authorization_code", "code": "code-1",
                                          "code_verifier": verifier, "client_id": client_id}, codes)
    assert status == 200, body
    assert codes == {}                       # one-time code used up
    return body


# ── the three asked-for cases ────────────────────────────────────────────────

def test_token_issued_before_restart_is_accepted_after(path, clock):
    tok = _sign_in(restart(path, clock))
    after = restart(path, clock)
    assert tok["access_token"] in after
    assert after.check_access(tok["access_token"]) == {}


def test_expired_token_is_refused(path, clock):
    tok = _sign_in(restart(path, clock))
    clock.t += OS.ACCESS_TTL_SECS + 1
    after = restart(path, clock)
    assert tok["access_token"] not in after
    # and it's pruned from the file, not kept forever
    assert token_hash(tok["access_token"]) not in json.loads(path.read_text())["access"]


def test_revoked_token_is_refused(path, clock):
    s = restart(path, clock)
    tok = _sign_in(s)
    assert s.revoke(tok["access_token"]) is True
    assert tok["access_token"] not in s
    after = restart(path, clock)
    assert tok["access_token"] not in after
    # revoking the access token ends the whole sign-in: its refresh token too
    status, _ = exchange_token(after, {"grant_type": "refresh_token",
                                       "refresh_token": tok["refresh_token"]}, {})
    assert status == 400


# ── refresh across a restart ─────────────────────────────────────────────────

def test_refresh_token_works_across_a_restart(path, clock):
    tok = _sign_in(restart(path, clock))
    clock.t += OS.ACCESS_TTL_SECS + 10       # access token expired while "down"
    after = restart(path, clock)
    assert tok["access_token"] not in after
    status, new = exchange_token(after, {"grant_type": "refresh_token",
                                         "refresh_token": tok["refresh_token"],
                                         "client_id": "cid-1"}, {})
    assert status == 200, new
    assert new["access_token"] != tok["access_token"]
    assert new["refresh_token"] != tok["refresh_token"]      # rotated
    assert new["expires_in"] == OS.ACCESS_TTL_SECS
    assert new["access_token"] in restart(path, clock)


def test_rotated_refresh_token_has_only_a_short_grace(path, clock):
    s = restart(path, clock)
    tok = _sign_in(s)
    st1, _ = exchange_token(s, {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, {})
    st2, _ = exchange_token(s, {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, {})
    assert (st1, st2) == (200, 200)          # lost-response retry still works
    clock.t += OS.REFRESH_GRACE_SECS + 1
    st3, body = exchange_token(restart(path, clock),
                               {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, {})
    assert st3 == 400 and body["error"] == "invalid_grant"


def test_refresh_refused_for_other_client_or_after_expiry(path, clock):
    s = restart(path, clock)
    tok = _sign_in(s, client_id="cid-1")
    st, _ = exchange_token(s, {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                               "client_id": "someone-else"}, {})
    assert st == 400
    clock.t += OS.REFRESH_TTL_SECS + 1
    st, _ = exchange_token(restart(path, clock), {"grant_type": "refresh_token",
                                                  "refresh_token": tok["refresh_token"]}, {})
    assert st == 400


def test_refresh_veto_revokes_the_sign_in(path, clock):
    """Server mode: refresh is refused (and the sign-in ended) once the user is gone."""
    s = restart(path, clock)
    verifier, challenge = _pkce()
    codes = {"c": {"code_challenge": challenge, "code_challenge_method": "S256", "user_token": "U1"}}
    st, tok = exchange_token(s, {"grant_type": "authorization_code", "code": "c", "code_verifier": verifier},
                             codes, grant_data=lambda d: {"user_hash": token_hash(d["user_token"])})
    assert st == 200
    assert s.check_access(tok["access_token"]) == {"user_hash": token_hash("U1")}
    st, _ = exchange_token(s, {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]},
                           {}, validate_refresh=lambda d: False)
    assert st == 400
    assert tok["access_token"] not in s


# ── /token edge cases (unchanged behaviour) ──────────────────────────────────

def test_pkce_mismatch_and_bad_grants(path, clock):
    s = restart(path, clock)
    _, challenge = _pkce()
    codes = {"c": {"code_challenge": challenge, "code_challenge_method": "S256"}}
    st, body = exchange_token(s, {"grant_type": "authorization_code", "code": "c", "code_verifier": "wrong"}, codes)
    assert st == 400 and body["error_description"] == "PKCE mismatch"
    assert exchange_token(s, {"grant_type": "authorization_code", "code": "nope"}, {})[0] == 400
    assert exchange_token(s, {"grant_type": "password"}, {})[1] == {"error": "unsupported_grant_type"}
    assert exchange_token(s, {"grant_type": "refresh_token", "refresh_token": ""}, {})[0] == 400


# ── what's on disk ───────────────────────────────────────────────────────────

def test_file_holds_hashes_never_raw_tokens(path, clock):
    tok = _sign_in(restart(path, clock))
    text = path.read_text(encoding="utf-8")
    assert tok["access_token"] not in text and tok["refresh_token"] not in text
    data = json.loads(text)
    assert token_hash(tok["access_token"]) in data["access"]
    assert token_hash(tok["refresh_token"]) in data["refresh"]
    assert all("exp" in v for v in data["access"].values())
    assert "owner-hash" == data["binding"]


def test_file_is_written_safely(path, clock):
    assert OS.atomic_write_json.__module__ == "safe_save"
    _sign_in(restart(path, clock))
    assert [p.name for p in path.parent.iterdir()] == [path.name]     # no temp files left


def test_registered_clients_survive_a_restart(path, clock):
    rec = restart(path, clock).register_client({"client_name": "Claude",
                                                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]})
    assert "refresh_token" in rec["grant_types"]
    again = restart(path, clock).get_client(rec["client_id"])
    assert again["client_name"] == "Claude"
    assert again["redirect_uris"] == ["https://claude.ai/api/mcp/auth_callback"]


def test_changing_the_owner_token_signs_everyone_out(path, clock):
    tok = _sign_in(restart(path, clock, binding="old-owner"))
    after = restart(path, clock, binding="new-owner")
    assert tok["access_token"] not in after
    st, _ = exchange_token(after, {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, {})
    assert st == 400


def test_unreadable_file_starts_empty_instead_of_crashing(path, clock):
    path.write_text("{ not json", encoding="utf-8")
    s = restart(path, clock)
    assert s.counts() == {"clients": 0, "access": 0, "refresh": 0}
    _sign_in(s)                                   # and it recovers on the next save
    assert json.loads(path.read_text())["access"]


# ── wiring in ai_prowler_mcp.py ──────────────────────────────────────────────

def test_personal_mode_uses_the_persistent_store():
    assert 'oauth_tokens.json"' in PERSONAL
    assert "binding=_oauth_hash(token)" in PERSONAL
    assert "_access_tokens = _AccessTokenSet()" in PERSONAL
    assert "_access_tokens: set = set()" not in PERSONAL
    tok_ep = PERSONAL[PERSONAL.index("async def token_endpoint"):][:900]
    assert "_oauth_exchange(_oauth_store" in tok_ep
    assert "31536000" not in tok_ep
    assert 'Route("/revoke"' in PERSONAL
    assert '"grant_types_supported": ["authorization_code", "refresh_token"]' in PERSONAL


def test_server_mode_uses_the_persistent_store():
    assert 'oauth_tokens_server.json"' in SERVER
    assert "_srv_oauth_exchange(" in SERVER
    assert "_srv_oauth_resolve(tok, _live_users)" in SERVER
    assert '"grant_types_supported": ["authorization_code", "refresh_token"]' in SERVER
    assert 'path == "/revoke"' in SERVER
    assert '"expires_in":   31536000' not in SERVER
