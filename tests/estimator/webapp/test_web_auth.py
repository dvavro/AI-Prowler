"""Sign-in rules for the Estimator Web App (design spec "Hosting and access", "Deployment modes").

Personal mode on the same PC opens with no login; office network, Remote Access
and Server mode always need a login; writes need the anti-CSRF header.
"""
import time

import pytest

from estimator.api import auth


# ---------------------------------------------------------------- same PC, Personal mode

def test_same_pc_personal_opens_without_login(call):
    r = call("GET", "/estimator-api/me")
    assert r.status == 200, r.body
    me = r.json()["me"]
    assert (me["role"], me["user_id"], me["mode"], me["signed_in_by"]) == ("owner", "owner", "personal", "same_pc")
    assert me["can_sign_out"] is False


@pytest.mark.parametrize("header", ["X-Forwarded-For", "CF-Connecting-IP", "Cf-Ray", "X-Real-IP", "Forwarded",
                                   "X-Forwarded-Host", "True-Client-IP"])
def test_tunnel_or_proxy_traffic_is_never_same_pc(call, header):
    """Remote Access (cloudflared) connects from localhost; its headers must force a login."""
    r = call("GET", "/estimator-api/me", headers={header: "203.0.113.9"})
    assert r.status == 401 and r.json()["error"] == "login_required"


@pytest.mark.parametrize("host", ["evil.example.com", "evil.example.com:8770", "192.168.1.20:8770", ""])
def test_dns_rebinding_host_is_not_same_pc(call, host):
    r = call("GET", "/estimator-api/me", headers={"Host": host})
    assert r.status == 401


@pytest.mark.parametrize("host", ["localhost", "localhost:8770", "127.0.0.1:8770", "[::1]:8770"])
def test_local_host_names_are_same_pc(call, host):
    assert call("GET", "/estimator-api/me", headers={"Host": host}).status == 200


def test_another_pc_on_the_network_must_sign_in(call):
    assert call("GET", "/estimator-api/me", ip="192.168.1.44").status == 401


def test_server_mode_needs_login_even_on_the_server_pc(call):
    auth.configure(mode="server")
    assert call("GET", "/estimator-api/me").status == 401


def test_env_switches_to_server_mode(call, monkeypatch):
    monkeypatch.setenv("ESTIMATOR_MODE", "server")
    assert call("GET", "/estimator-api/me").status == 401


def test_health_needs_no_login(call):
    auth.configure(mode="server")
    r = call("GET", "/estimator-api/health", ip="10.0.0.9")
    assert r.status == 200 and r.json()["mode"] == "server"


# ---------------------------------------------------------------- Personal mode login (remote / office)

def test_personal_login_with_owner_password_then_cookie_and_bearer(call, monkeypatch):
    monkeypatch.setenv("ESTIMATOR_OWNER_PASSWORD", "s3cret-token")
    r = call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "s3cret-token"}, ip="10.0.0.5")
    assert r.status == 200, r.body
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and cookie.startswith("est_session=")
    token = r.json()["token"]
    assert r.json()["me"]["signed_in_by"] == "session" and r.json()["me"]["can_sign_out"] is True

    via_cookie = call("GET", "/estimator-api/me", ip="10.0.0.5", headers={"Cookie": f"a=1; est_session={token}"})
    assert via_cookie.status == 200
    via_bearer = call("GET", "/estimator-api/me", ip="10.0.0.5", headers={"Authorization": f"Bearer {token}"})
    assert via_bearer.status == 200


def test_owner_password_falls_back_to_ai_prowler_remote_token(call):
    auth._config_files()[0].write_text('{"remote_token": "tok-from-ai-prowler"}', encoding="utf-8")
    r = call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "tok-from-ai-prowler"},
             ip="10.0.0.5")
    assert r.status == 200


def test_no_owner_password_anywhere_means_nobody_signs_in(call):
    r = call("POST", "/estimator-api/auth/login", {"username": "owner", "password": ""}, ip="10.0.0.5")
    assert r.status == 400
    r = call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "anything"}, ip="10.0.0.5")
    assert r.status == 401 and r.json()["error"] == "bad_login"


def test_wrong_password_and_lockout(call, monkeypatch):
    monkeypatch.setenv("ESTIMATOR_OWNER_PASSWORD", "right")
    for _ in range(auth.LOGIN_MAX_FAILS):
        r = call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "wrong"}, ip="10.0.0.5")
        assert r.status == 401
    r = call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "right"}, ip="10.0.0.5")
    assert r.status == 429 and r.json()["error"] == "locked"
    # another address is not locked out
    assert call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "right"},
                ip="10.0.0.6").status == 200


def test_lockout_ends_after_the_window(call, monkeypatch):
    monkeypatch.setenv("ESTIMATOR_OWNER_PASSWORD", "right")
    for _ in range(auth.LOGIN_MAX_FAILS):
        call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "x"}, ip="10.0.0.5")
    real = time.time
    monkeypatch.setattr(auth.time, "time", lambda: real() + auth.LOGIN_LOCK_SECONDS + 1)
    assert call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "right"},
                ip="10.0.0.5").status == 200


def test_logout_ends_the_session(call, monkeypatch):
    monkeypatch.setenv("ESTIMATOR_OWNER_PASSWORD", "pw")
    tok = call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "pw"}, ip="10.0.0.5").json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = call("POST", "/estimator-api/auth/logout", {}, headers=h, ip="10.0.0.5")
    assert r.status == 200 and "Max-Age=0" in r.headers["Set-Cookie"]
    assert call("GET", "/estimator-api/me", headers=h, ip="10.0.0.5").status == 401


def test_session_expires_when_idle(call, session_for, monkeypatch):
    h = session_for("estimator")
    assert call("GET", "/estimator-api/me", headers=h, ip="10.0.0.5").status == 200
    real = time.time
    monkeypatch.setattr(auth.time, "time", lambda: real() + auth.SESSION_TTL_SECONDS + 5)
    assert call("GET", "/estimator-api/me", headers=h, ip="10.0.0.5").status == 401


def test_made_up_token_is_refused(call):
    auth.configure(mode="server")
    assert call("GET", "/estimator-api/me", headers={"Authorization": "Bearer nope"}).status == 401


# ---------------------------------------------------------------- Server mode login

def test_server_mode_without_accounts_connected_says_so(call):
    auth.configure(mode="server")
    r = call("POST", "/estimator-api/auth/login", {"username": "maria", "password": "pw"})
    assert r.status == 503 and r.json()["error"] == "not_configured"


def test_server_mode_login_uses_ai_prowler_accounts(call):
    users = {("maria", "pw1"): {"user_id": "maria", "role": "estimator", "name": "Maria"},
             ("fred", "pw2"): {"user_id": "fred", "role": "field", "name": "Fred", "company_id": "acme"}}
    auth.configure(mode="server", verifier=lambda u, p: users.get((u, p)))
    r = call("POST", "/estimator-api/auth/login", {"username": "maria", "password": "pw1"})
    me = r.json()["me"]
    assert (me["user_id"], me["role"], me["name"], me["mode"]) == ("maria", "estimator", "Maria", "server")
    r = call("POST", "/estimator-api/auth/login", {"username": "fred", "password": "pw2"})
    assert r.json()["me"]["company_id"] == "acme"
    assert call("POST", "/estimator-api/auth/login", {"username": "maria", "password": "bad"}).status == 401


def test_unknown_role_from_accounts_is_refused(call):
    auth.configure(mode="server", verifier=lambda u, p: {"user_id": u, "role": "superuser"})
    r = call("POST", "/estimator-api/auth/login", {"username": "x", "password": "y"})
    assert r.status == 403 and auth.session_count() == 0


def test_a_broken_verifier_never_lets_anyone_in(call):
    def boom(u, p):
        raise RuntimeError("accounts database offline")
    auth.configure(mode="server", verifier=boom)
    assert call("POST", "/estimator-api/auth/login", {"username": "x", "password": "y"}).status == 401
    assert auth.session_count() == 0


# ---------------------------------------------------------------- CSRF

def test_writes_without_the_app_header_are_refused(call, db):
    r = call("POST", "/estimator-api/estimates", {"title": "Sneaky"}, write_header=False)
    assert r.status == 403 and r.json()["error"] == "csrf"
    assert db.execute("SELECT COUNT(*) FROM estimates").fetchone()[0] == 0


def test_login_also_needs_the_app_header(call, monkeypatch):
    monkeypatch.setenv("ESTIMATOR_OWNER_PASSWORD", "pw")
    r = call("POST", "/estimator-api/auth/login", {"username": "owner", "password": "pw"}, write_header=False)
    assert r.status == 403 and auth.session_count() == 0


def test_cookie_is_secure_over_https(monkeypatch):
    monkeypatch.setenv("ESTIMATOR_OWNER_PASSWORD", "pw")
    from estimator.api import router
    req = router.Request("POST", "/estimator-api/auth/login",
                         {"Host": "est.example.com", "X-Estimator-Request": "1"},
                         b'{"username":"owner","password":"pw"}', "10.0.0.5", secure=True)
    assert "; Secure" in router.route(req).headers["Set-Cookie"]
