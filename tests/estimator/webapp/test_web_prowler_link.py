"""Coder 2 Sprint 1: the web app hooked into AI-Prowler (estimator/api/prowler_link.py,
the hook in ai_prowler_mcp.py, and install_estimator.py adding it to an installed copy)."""
import importlib.util
import sys
from pathlib import Path

import pytest

from estimator.api import auth, prowler_link, server

ROOT = Path(__file__).resolve().parents[3]

# A users.json like AI-Prowler's: the key is the user's access token.
USERS = {"company_id": "acme-roofing", "users": {
    "tok-owner": {"name": "Dana Owner", "role": "owner"},
    "tok-mgr": {"name": "Mo Manager", "role": "manager"},
    "tok-staff": {"name": "Sue Staff", "role": "staff"},
    "tok-crew": {"name": "Cal Crew", "role": "field_crew"},
    "tok-est": {"name": "Eve Estimator", "role": "staff", "estimator_role": "estimator"},
    "tok-out": {"name": "Nora None", "role": "manager", "estimator_role": "none"},
    "tok-gone": {"name": "Gus Gone", "role": "owner", "status": "revoked"},
}}


def _resolve(data, token):
    """Same contract as ai_prowler_mcp._resolve_user: active users only, adds a stable id."""
    entry = (data or {}).get("users", {}).get(token)
    if not isinstance(entry, dict) or entry.get("status", "active") != "active":
        return None
    u = dict(entry)
    u["id"] = u["name"].lower().replace(" ", "-")
    return u


@pytest.fixture
def verify():
    return prowler_link.make_server_verifier(lambda: USERS, _resolve)


# ------------------------------------------------------------------ role mapping

@pytest.mark.parametrize("prowler_role, expected", [
    ("owner", "owner"), ("manager", "office"), ("staff", "office"), ("field_crew", "field"), ("bogus", "")])
def test_ai_prowler_roles_map_to_least_access(prowler_role, expected):
    assert prowler_link.estimator_role({"role": prowler_role}) == expected


def test_estimator_role_override_and_opt_out():
    assert prowler_link.estimator_role({"role": "staff", "estimator_role": "Reviewer"}) == "reviewer"
    assert prowler_link.estimator_role({"role": "owner", "estimator_role": "none"}) == ""
    # An unknown override is ignored, not trusted.
    assert prowler_link.estimator_role({"role": "field_crew", "estimator_role": "admin"}) == "field"


# ------------------------------------------------------------------ Server-mode verifier

def test_verifier_accepts_name_plus_token(verify):
    who = verify("dana owner", "tok-owner")
    assert who == {"user_id": "dana-owner", "role": "owner", "name": "Dana Owner", "company_id": "acme-roofing"}
    assert verify("Cal Crew", "tok-crew")["role"] == "field"
    assert verify("Eve Estimator", "tok-est")["role"] == "estimator"


@pytest.mark.parametrize("name, token", [
    ("Dana Owner", "wrong"),          # bad password
    ("Mo Manager", "tok-owner"),      # someone else's password
    ("", "tok-owner"),                # no name
    ("Dana Owner", ""),               # no password
    ("Gus Gone", "tok-gone"),         # revoked in AI-Prowler
    ("Nora None", "tok-out"),         # kept out of the Estimator
])
def test_verifier_rejects(verify, name, token):
    assert verify(name, token) is None


def test_users_json_is_read_at_each_sign_in():
    data = {"company_id": "c1", "users": {"t": {"name": "Pat", "role": "owner"}}}
    v = prowler_link.make_server_verifier(lambda: data, _resolve)
    assert v("Pat", "t")
    data["users"]["t"]["status"] = "suspended"          # revoked while signed out
    assert v("Pat", "t") is None


def test_server_login_end_to_end_through_the_router(call, verify):
    auth.configure(mode="server", verifier=verify)
    r = call("POST", "/estimator-api/auth/login", {"username": "Cal Crew", "password": "tok-crew"})
    assert r.status == 200
    s = next(iter(auth._sessions.values()))
    assert s["ctx"] == {"company_id": "acme-roofing", "user_id": "cal-crew", "role": "field", "mode": "server"}
    bad = call("POST", "/estimator-api/auth/login", {"username": "Cal Crew", "password": "nope"})
    assert bad.status == 401
    # Server mode: no free pass on this PC.
    assert call("GET", "/estimator-api/me").status == 401


def test_broken_account_lookup_never_lets_anyone_in():
    def boom():
        raise OSError("users.json locked")
    auth.configure(mode="server", verifier=prowler_link.make_server_verifier(boom, _resolve))
    with pytest.raises(auth.LoginError) as e:
        auth.login("Dana Owner", "tok-owner", "10.0.0.5")
    assert e.value.code == "bad_login"


# ------------------------------------------------------------------ when it starts

def test_never_starts_outside_ai_prowlers_http_server():
    assert prowler_link.should_start(False)[0] is False


def test_never_starts_under_pytest():
    ok, why = prowler_link.should_start(True)
    assert ok is False and "pytest" in why


def test_should_start_when_not_testing(monkeypatch):
    monkeypatch.delitem(sys.modules, "pytest", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("ESTIMATOR_WEB", raising=False)
    assert prowler_link.should_start(True) == (True, "")
    monkeypatch.setenv("ESTIMATOR_WEB", "off")
    assert prowler_link.should_start(True)[0] is False


def test_start_from_ai_prowler_configures_and_starts(monkeypatch, verify):
    monkeypatch.setattr(prowler_link, "should_start", lambda _h: (True, ""))
    monkeypatch.setattr(server, "start_with_ai_prowler", lambda: "http://localhost:8770/estimator/")
    url = prowler_link.start_from_ai_prowler(is_http_server=True, server_mode=True,
                                             load_users=lambda: USERS, resolve_user=_resolve)
    assert url == "http://localhost:8770/estimator/"
    assert auth.mode() == "server"
    assert auth.login("Mo Manager", "tok-mgr", "10.0.0.9")[1].ctx.role == "office"


def test_start_from_ai_prowler_personal_mode(monkeypatch):
    monkeypatch.setattr(prowler_link, "should_start", lambda _h: (True, ""))
    monkeypatch.setattr(server, "start_with_ai_prowler", lambda: "u")
    assert prowler_link.start_from_ai_prowler(is_http_server=True, server_mode=False) == "u"
    assert auth.mode() == "personal"


def test_start_from_ai_prowler_never_raises(monkeypatch):
    monkeypatch.setattr(prowler_link, "should_start", lambda _h: (True, ""))

    def boom():
        raise RuntimeError("no")
    monkeypatch.setattr(server, "start_with_ai_prowler", boom)
    assert prowler_link.start_from_ai_prowler(is_http_server=True, server_mode=False) == ""
    # Server mode without the account lookup: refuses to start rather than run unprotected.
    assert prowler_link.start_from_ai_prowler(is_http_server=True, server_mode=True) == ""
    assert not server.running()


def test_under_pytest_nothing_starts():
    assert prowler_link.start_from_ai_prowler(is_http_server=True, server_mode=False) == ""
    assert not server.running()


# ------------------------------------------------------------------ the hook in AI-Prowler and the installer

def _installer():
    spec = importlib.util.spec_from_file_location("install_estimator_under_test", ROOT / "install_estimator.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_dev_ai_prowler_mcp_has_the_same_web_hook_as_the_installer():
    text = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    inst = _installer()
    assert inst.WEB_HOOK.strip() in text
    # Right after the tools hook, and before anything else uses the Estimator.
    assert text.index("_register_estimator(mcp)") < text.index("_start_estimator_web(")
    # The names it uses are defined in AI-Prowler.
    for name in ("_IS_HTTP_SERVER =", "_IS_SERVER_MODE:", "def _load_users(", "def _resolve_user("):
        assert name in text


FAKE = "import x\nmcp.tool = _counting_mcp_tool\nrest = 1\n"


def test_installer_adds_both_hooks_to_a_fresh_copy():
    inst = _installer()
    out, added, err = inst.add_hooks(FAKE)
    assert err == "" and added == ["tools", "web app"]
    assert out.index("_register_estimator") < out.index("_start_estimator_web") < out.index("rest = 1")
    compile(out, "ai_prowler_mcp.py", "exec")


def test_installer_adds_only_the_web_hook_to_an_older_install():
    inst = _installer()
    older, _, _ = inst.add_hooks(FAKE)
    older = older.replace(inst.WEB_HOOK, "")
    out, added, err = inst.add_hooks(older)
    assert err == "" and added == ["web app"]
    assert out.count("_start_estimator_web(") == 1


def test_installer_is_idempotent_and_reports_a_missing_anchor():
    inst = _installer()
    once, _, _ = inst.add_hooks(FAKE)
    again, added, err = inst.add_hooks(once)
    assert again == once and added == [] and err == ""
    _, added, err = inst.add_hooks("nothing here\n")
    assert added == [] and "Couldn't find" in err
