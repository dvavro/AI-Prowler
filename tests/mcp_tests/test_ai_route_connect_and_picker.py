"""
tests/mcp_tests/test_ai_route_connect_and_picker.py
==============================================
AI Route start/end picker + per-user Claude connection (server mode), 2026-09-19.

Covers, with no real Claude CLI, browser, network, or Scheduled Task involved:
  A. cli_signin_relay parsing helpers (URL rejoin, token extract, invalid-code)
  B. cli_signin_relay session flow with a fake console
  C. per-user token store + the AI Routing wrapper's use of it
  D. get_route_start_options (whose home address the picker offers)
  E. start_ai_routing: explicit start/end choice, token requirement, crew scope,
     one-run-at-a-time
  F. the four "Connect your Claude account" tools + audit-log redaction
  G. static checks: Jobs app picker/connect UI, allowlists, Admin tab fields

NOT covered here (needs a real sign-in / real Task Scheduler): the success path
with a real Claude code, and the AUTH_EXPIRED handling inside the background
worker.

Run with:
    run_tests.bat tests\\mcp\\test_ai_route_connect_and_picker.py -v
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

TOKEN = "sk-ant-oat01-" + "Ab3-_" * 18          # 103 chars, realistic shape
STATE = "K5MPGaG5IP0IXWQqQYfyR5boyYcyRoEO3Xugajc7M1o"   # 43 chars, like a real one
URL = ("https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"
       "&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"
       "&scope=user%3Ainference&code_challenge=LYeHoMKX-boAggGh25YiET9Y0tKpWSpRJiXY_SW1HSM"
       f"&code_challenge_method=S256&state={STATE}")
# What the CLI really writes (probe, 2026-09-19): the URL wrapped one character
# early, then the paste prompt.
SCREEN = ("Welcome to Claude Code v2.1.220\n\n Browser didn't open? Use the url below to sign in (c to copy)\n\n"
          + URL[:-1] + "\n" + URL[-1] + "\n\n Paste code here if prompted >")
INVALID = ("\nWelcome to Claude Code v2.1.220\n\n OAuth error: Invalid code. Please make sure "
           "the full code was copied\n\n\n Press Enter to retry.\n")
GOOD_CODE = "abcDEF123456-_xyz#" + "q" * 20


# ══════════════════════════════════════════════════════════════════════════
# A. parsing helpers
# ══════════════════════════════════════════════════════════════════════════

import cli_signin_relay as relay          # noqa: E402


def test_url_wrapped_across_lines_is_rejoined():
    assert relay.parse_signin_url(SCREEN) == URL


def test_url_is_none_until_the_paste_prompt_is_drawn():
    assert relay.parse_signin_url(SCREEN.split("Paste code")[0]) is None


def test_url_none_when_state_is_truncated():
    cut = ("Use the url below to sign in\n\n" + URL[:URL.index("state=") + 16]
           + "\n\n Paste code here if prompted >")
    assert relay.parse_signin_url(cut) is None


def test_url_uses_the_last_redraw():
    older = SCREEN.replace("LYeHoMKX", "OLDOLDOL")
    assert relay.parse_signin_url(older + "\n" + SCREEN) == URL


def test_url_ignores_ansi_codes():
    ansi = "\x1b[2K\x1b[1G" + SCREEN.replace("Paste code", "\x1b[0mPaste code")
    assert relay.parse_signin_url(relay.clean_output(ansi)) == URL


def test_extract_token_plain():
    assert relay.extract_token(f"Your token:\n{TOKEN}\nStore it safely") == TOKEN


def test_extract_token_rejoins_a_wrapped_token():
    cut = TOKEN[:60] + "\n" + TOKEN[60:]
    assert relay.extract_token(f"Your token:\n{cut}\n\nStore it safely") == TOKEN


def test_extract_token_none_when_absent():
    assert relay.extract_token(INVALID) is None


def test_looks_invalid():
    assert relay.looks_invalid(INVALID)
    assert not relay.looks_invalid(SCREEN)


@pytest.mark.parametrize("bad", ["", "short", "has space in it 1234567", "x" * 401, "semi;colon;1234567"])
def test_code_format_rejects_junk(bad):
    assert not relay._CODE_OK.fullmatch(bad)


def test_code_format_accepts_real_looking_code():
    assert relay._CODE_OK.fullmatch(GOOD_CODE)


# ══════════════════════════════════════════════════════════════════════════
# B. relay session flow (fake console)
# ══════════════════════════════════════════════════════════════════════════

class FakeProc:
    pid = 4242

    def __init__(self):
        self.finished = False

    def poll(self):
        return 0 if self.finished else None


@pytest.fixture
def tqa(tmp_path, monkeypatch):
    import task_queue_automation as t
    monkeypatch.setattr(t, "AI_PROWLER_HOME", tmp_path / "home")
    monkeypatch.setattr(t, "AI_ROUTING_USER_TOKEN_DIR", tmp_path / "tokens")
    monkeypatch.setattr(t, "_get_claude_exe", lambda: "claude")
    # never really run icacls in a test
    monkeypatch.setattr(t.subprocess, "run", lambda *a, **k: MagicMock(returncode=0))
    return t


@pytest.fixture
def fake(tqa, monkeypatch):
    """Fake console: spawn writes SCREEN; inject calls are recorded and each
    can append to the output file, like the real CLI reacting to typed text."""
    real_sleep = time.sleep
    monkeypatch.setattr(relay.time, "sleep", lambda s: real_sleep(0.005))
    monkeypatch.setattr(relay, "START_TIMEOUT_SEC", 0.3)
    monkeypatch.setattr(relay, "SUBMIT_TIMEOUT_SEC", 0.3)
    state = {"spawns": 0, "injected": [], "kills": [], "screen": SCREEN,
             "on_inject": lambda text, out: None, "proc": None}

    def spawn(bat, env):
        state["spawns"] += 1
        state["env"] = env
        (Path(bat).parent / "out.txt").write_text(state["screen"], encoding="utf-8")
        state["proc"] = FakeProc()
        return state["proc"]

    def inject(pid, text):
        state["injected"].append(text)
        out = next(iter(relay._SESSIONS.values()))["out"]
        state["on_inject"](text, out)
        return True, ""

    monkeypatch.setattr(relay, "_spawn_console", spawn)
    monkeypatch.setattr(relay, "_inject", inject)
    monkeypatch.setattr(relay, "_kill_tree", lambda pid: state["kills"].append(pid))
    yield state
    for slug in list(relay._SESSIONS):
        relay._end(slug)


def _append(out, text):
    with open(out, "ab") as f:
        f.write(text.encode("utf-8"))


def test_start_login_returns_the_signin_url(fake):
    ok, url = relay.start_login("jake-r")
    assert ok and url == URL


def test_browser_is_disabled_so_nothing_opens_on_the_server_desktop(fake):
    relay.start_login("jake-r")
    assert fake["env"]["BROWSER"].endswith("noop_browser.bat")


def test_start_login_twice_reuses_the_session(fake):
    relay.start_login("jake-r")
    ok, url = relay.start_login("jake-r")
    assert ok and url == URL and fake["spawns"] == 1


def test_start_login_fails_cleanly_when_cli_never_prints_a_url(fake):
    fake["screen"] = "Welcome to Claude Code\n"
    ok, msg = relay.start_login("jake-r")
    assert not ok and "didn't start" in msg
    assert relay.pending_count() == 0


def test_max_pending_sign_ins(fake, monkeypatch):
    monkeypatch.setattr(relay, "MAX_PENDING", 2)
    assert relay.start_login("user-a")[0]
    assert relay.start_login("user-b")[0]
    ok, msg = relay.start_login("user-c")
    assert not ok and "try again" in msg


def test_submit_without_a_session(fake):
    res = relay.submit_code("jake-r", GOOD_CODE)
    assert res["status"] == "no_session"


def test_submit_junk_code_is_not_typed_into_the_console(fake):
    relay.start_login("jake-r")
    res = relay.submit_code("jake-r", "nope")
    assert res["status"] == "invalid_code" and fake["injected"] == []


def test_wrong_code_reports_invalid_and_presses_enter_to_retry(fake):
    fake["on_inject"] = lambda text, out: _append(out, INVALID) if text else None
    relay.start_login("jake-r")
    res = relay.submit_code("jake-r", GOOD_CODE)
    assert res["status"] == "invalid_code"
    assert fake["injected"] == [GOOD_CODE, ""]          # the code, then Enter = retry
    assert relay.login_pending("jake-r")                 # still there for another try


def test_good_code_saves_the_token_and_cleans_up(fake, tqa):
    fake["on_inject"] = lambda text, out: _append(out, f"\nYour token:\n{TOKEN}\n")
    relay.start_login("jake-r")
    folder = next(iter(relay._SESSIONS.values()))["dir"]
    res = relay.submit_code("jake-r", GOOD_CODE)
    assert res["status"] == "connected" and res["token"] == TOKEN
    assert tqa.has_user_oauth_token("jake-r")
    assert tqa.user_oauth_token_path("jake-r").read_text(encoding="utf-8") == TOKEN
    assert relay.pending_count() == 0
    assert not folder.exists()                            # temp folder held the token: gone
    assert fake["kills"]


def test_no_answer_times_out_without_ending_the_session(fake):
    relay.start_login("jake-r")
    res = relay.submit_code("jake-r", GOOD_CODE)
    assert res["status"] == "timeout" and relay.login_pending("jake-r")


def test_console_that_dies_before_answering_is_a_timeout_not_a_crash(fake):
    def die(text, out):
        fake["proc"].finished = True
    fake["on_inject"] = die
    relay.start_login("jake-r")
    res = relay.submit_code("jake-r", GOOD_CODE)
    assert res["status"] in ("timeout", "no_session")


def test_expired_session_is_reported_and_cleaned(fake, monkeypatch):
    relay.start_login("jake-r")
    next(iter(relay._SESSIONS.values()))["expires"] = time.time() - 1
    assert relay.submit_code("jake-r", GOOD_CODE)["status"] == "no_session"
    assert relay.pending_count() == 0


def test_cancel_ends_the_session(fake):
    relay.start_login("jake-r")
    relay.cancel_login("jake-r")
    assert relay.pending_count() == 0 and fake["kills"]


def test_users_do_not_share_sessions(fake):
    relay.start_login("user-a")
    assert not relay.login_pending("user-b")
    assert relay.submit_code("user-b", GOOD_CODE)["status"] == "no_session"


# ══════════════════════════════════════════════════════════════════════════
# C. per-user token store + wrapper
# ══════════════════════════════════════════════════════════════════════════

def test_save_and_read_back_a_user_token(tqa):
    p = tqa.save_user_oauth_token("jake-r", TOKEN)
    assert p.read_text(encoding="utf-8") == TOKEN
    assert tqa.has_user_oauth_token("jake-r")
    assert not tqa.has_user_oauth_token("someone-else")


@pytest.mark.parametrize("bad", ["", "   ", "not-a-token", "sk-ant-api03-" + "x" * 40, "sk-ant-oat"])
def test_bad_tokens_are_rejected_and_nothing_is_written(tqa, bad):
    with pytest.raises(ValueError):
        tqa.save_user_oauth_token("jake-r", bad)
    assert not tqa.has_user_oauth_token("jake-r")


def test_token_id_cannot_escape_the_token_folder(tqa, tmp_path):
    p = tqa.save_user_oauth_token("../../evil", TOKEN)
    assert p.parent == tmp_path / "tokens"
    assert ".." not in p.name and "/" not in p.name and "\\" not in p.name


def test_no_user_id_no_token(tqa):
    with pytest.raises(ValueError):
        tqa.save_user_oauth_token("", TOKEN)
    assert tqa.user_oauth_token_path("!!!") is None


def test_delete_user_token(tqa):
    tqa.save_user_oauth_token("jake-r", TOKEN)
    assert tqa.delete_user_oauth_token("jake-r") is True
    assert tqa.delete_user_oauth_token("jake-r") is False
    assert not tqa.has_user_oauth_token("jake-r")


def test_a_corrupt_token_file_counts_as_not_connected(tqa):
    p = tqa.save_user_oauth_token("jake-r", TOKEN)
    p.write_text("garbage", encoding="utf-8")
    assert not tqa.has_user_oauth_token("jake-r")


def test_wrapper_reads_the_users_own_token_file(tqa, tmp_path):
    tok = tmp_path / "tokens" / "jake-r.txt"
    bat = tqa.build_ai_routing_wrapper_content("prompt", "mcp.json", "tools", oauth_token_path=tok)
    assert f'set /p CLAUDE_CODE_OAUTH_TOKEN=<"{tok}"' in bat
    assert str(tqa.OAUTH_TOKEN_PLAIN_PATH) not in bat        # never the host's shared token
    assert "ANTHROPIC_API_KEY" not in bat
    assert TOKEN not in bat


def test_wrapper_default_is_unchanged_shared_token(tqa):
    bat = tqa.build_ai_routing_wrapper_content("prompt", "mcp.json", "tools")
    assert str(tqa.OAUTH_TOKEN_PLAIN_PATH) in bat


# ══════════════════════════════════════════════════════════════════════════
# MCP-layer fixtures
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _ctx(user):
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _user(uid="jake-r", name="Jake R", role="field_crew", email="jake@example.com", home=""):
    return {"id": uid, "name": name, "role": role, "status": "active", "email": email,
            "home_address": home, "scopes": []}


@pytest.fixture
def as_user(monkeypatch, mcp_mod):
    def _set(user):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        return _ctx(user) if user else None
    return _set


# ══════════════════════════════════════════════════════════════════════════
# D. get_route_start_options
# ══════════════════════════════════════════════════════════════════════════

def _parse_opts(text):
    return (re.search(r"HOME_ADDRESS: (.*)", text).group(1),
            re.search(r"HOME_LABEL: (.*)", text).group(1))


def test_personal_mode_offers_the_owner_address_from_settings(mcp_mod, as_user, monkeypatch):
    ctx = as_user(None)
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "1 Main St", "city": "New Smyrna Beach", "state": "FL", "zip": "32168"})
    addr, label = _parse_opts(mcp_mod.get_route_start_options(ctx=ctx))
    assert addr == "1 Main St, New Smyrna Beach FL 32168" and "Settings" in label


def test_personal_mode_with_no_address_configured(mcp_mod, as_user, monkeypatch):
    ctx = as_user(None)
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "", "city": "", "state": "", "zip": ""})
    assert _parse_opts(mcp_mod.get_route_start_options(ctx=ctx))[0] == ""


def test_server_field_crew_gets_their_own_address(mcp_mod, as_user):
    ctx = as_user(_user(home="9 Palm Ave, Edgewater FL"))
    addr, label = _parse_opts(mcp_mod.get_route_start_options(ctx=ctx))
    assert addr == "9 Palm Ave, Edgewater FL" and "Jake R" in label


def test_server_never_falls_back_to_the_host_owners_address(mcp_mod, as_user, monkeypatch):
    ctx = as_user(_user(home=""))
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "OWNER HOME", "city": "", "state": "", "zip": ""})
    assert _parse_opts(mcp_mod.get_route_start_options(ctx=ctx))[0] == ""


def test_staff_can_look_up_a_crew_members_address(mcp_mod, as_user, monkeypatch):
    ctx = as_user(_user("dave", "Dave O", "owner", home="Dave's House"))
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: {"users": {
        "tok1": {"name": "Sam Crew", "role": "field_crew", "status": "active", "home_address": "5 Oak St"},
        "tok2": {"name": "Sam Crew", "role": "field_crew", "status": "suspended", "home_address": "OLD"}}})
    addr, label = _parse_opts(mcp_mod.get_route_start_options(crew="sam crew", ctx=ctx))
    assert addr == "5 Oak St" and "Sam Crew" in label


def test_lookup_of_an_unknown_crew_member_is_empty_not_the_callers_home(mcp_mod, as_user, monkeypatch):
    ctx = as_user(_user("dave", "Dave O", "owner", home="Dave's House"))
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: {"users": {}})
    assert _parse_opts(mcp_mod.get_route_start_options(crew="Nobody", ctx=ctx))[0] == ""


def test_field_crew_cannot_read_a_colleagues_address(mcp_mod, as_user, monkeypatch):
    ctx = as_user(_user(home="MY HOME"))
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: {"users": {
        "t": {"name": "Sam Crew", "role": "field_crew", "status": "active", "home_address": "SAMS HOME"}}})
    assert _parse_opts(mcp_mod.get_route_start_options(crew="Sam Crew", ctx=ctx))[0] == "MY HOME"


# ══════════════════════════════════════════════════════════════════════════
# E. start_ai_routing
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def routing(mcp_mod, tqa, monkeypatch):
    """No real CLI/Task Scheduler/thread: records what would have been started."""
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa, "ai_routing_task_exists", lambda: True)
    started = []

    class FakeThread:
        def __init__(self, target=None, args=(), daemon=None):
            started.append(args)

        def start(self):
            pass
    monkeypatch.setattr(mcp_mod.threading, "Thread", FakeThread)
    mcp_mod._AI_ROUTING_JOBS.clear()
    import db_route_ops
    monkeypatch.setattr(db_route_ops, "_geocode", lambda addr: (29.1, -81.0))
    yield started
    mcp_mod._AI_ROUTING_JOBS.clear()


def _run(mcp_mod, ctx=None, **kw):
    args = dict(route_date="2026-09-22", crew="", origin_lat="", origin_lon="", origin_choice="")
    args.update(kw)
    return mcp_mod.start_ai_routing(ctx=ctx, **args)


def test_no_start_end_choice_starts_a_run_with_no_origin(mcp_mod, as_user, routing):
    # 2026-09-21: blank choice = "do what Route Today does" — the run starts, and
    # its apply_route_order call carries no coordinates, so Settings decide by mode.
    out = _run(mcp_mod, as_user(None))
    assert out.startswith("⏳ RUNNING") and len(routing) == 1
    prompt = routing[0][1]
    assert "origin_lat" not in prompt and "origin_lon" not in prompt
    assert "apply_route_order(" in prompt


@pytest.mark.parametrize("choice", ["maybe", "HOMEISH", "gps home"])
def test_unknown_choice_is_refused(mcp_mod, as_user, routing, choice):
    out = _run(mcp_mod, as_user(None), origin_choice=choice)
    assert "Unknown start/end choice" in out and "Nothing was started" in out
    assert routing == []


@pytest.mark.parametrize("lat,lon", [("", ""), ("29.0", ""), ("abc", "def"), ("95", "0"), ("0", "181"), ("nan", "nan")])
def test_gps_choice_needs_valid_coordinates(mcp_mod, as_user, routing, lat, lon):
    out = _run(mcp_mod, as_user(None), origin_choice="gps", origin_lat=lat, origin_lon=lon)
    assert "Current location isn't available" in out and routing == []


def test_gps_choice_passes_the_coordinates_into_the_run(mcp_mod, as_user, routing):
    out = _run(mcp_mod, as_user(None), origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    assert out.startswith("⏳ RUNNING")
    prompt = routing[0][1]
    assert 'origin_lat="29.0"' in prompt and 'origin_lon="-80.9"' in prompt


def test_gps_choice_is_case_insensitive(mcp_mod, as_user, routing):
    out = _run(mcp_mod, as_user(None), origin_choice=" GPS ", origin_lat="29.0", origin_lon="-80.9")
    assert out.startswith("⏳ RUNNING")


def test_personal_home_choice_geocodes_the_settings_address(mcp_mod, as_user, routing, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "1 Main St", "city": "NSB", "state": "FL", "zip": "32168"})
    out = _run(mcp_mod, as_user(None), origin_choice="home")
    assert out.startswith("⏳ RUNNING")
    prompt = routing[0][1]
    assert 'origin_lat="29.1"' in prompt and 'origin_lon="-81.0"' in prompt


def test_home_choice_with_no_address_points_to_settings(mcp_mod, as_user, routing, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "", "city": "", "state": "", "zip": ""})
    out = _run(mcp_mod, as_user(None), origin_choice="home")
    assert "isn't set yet" in out and "Settings tab" in out and routing == []


def test_home_address_that_cannot_be_found_is_refused(mcp_mod, as_user, routing, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "Nowhere Rd", "city": "", "state": "", "zip": ""})
    import db_route_ops
    monkeypatch.setattr(db_route_ops, "_geocode", lambda addr: None)
    out = _run(mcp_mod, as_user(None), origin_choice="home")
    assert "Couldn't find" in out and routing == []


def test_the_choice_is_never_remembered_between_calls(mcp_mod, as_user, routing):
    ctx = as_user(None)
    assert _run(mcp_mod, ctx, origin_choice="gps", origin_lat="29.0", origin_lon="-80.9").startswith("⏳")
    mcp_mod._AI_ROUTING_JOBS.clear()
    # A later call with no choice must NOT reuse the earlier GPS point — it
    # starts a run with no origin at all (Settings decide, like Route Today).
    assert _run(mcp_mod, ctx).startswith("⏳")
    assert "origin_lat" not in routing[-1][1]


def test_server_user_without_a_token_is_sent_to_connect(mcp_mod, as_user, routing):
    ctx = as_user(_user())
    out = _run(mcp_mod, ctx, origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    assert "NO_CLI_TOKEN" in out and routing == []


def test_server_run_uses_the_callers_own_token_file(mcp_mod, as_user, routing, tqa):
    tqa.save_user_oauth_token("jake-r", TOKEN)
    ctx = as_user(_user())
    out = _run(mcp_mod, ctx, origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    assert out.startswith("⏳ RUNNING")
    assert routing[0][3] == tqa.user_oauth_token_path("jake-r")


def test_personal_run_uses_the_shared_token(mcp_mod, as_user, routing):
    _run(mcp_mod, as_user(None), origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    assert routing[0][3] is None


def test_field_crew_is_forced_onto_their_own_crew(mcp_mod, as_user, routing, tqa):
    tqa.save_user_oauth_token("jake-r", TOKEN)
    ctx = as_user(_user())
    _run(mcp_mod, ctx, crew="Somebody Else", origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    prompt = routing[0][1]
    assert 'crew="Jake R"' in prompt and "Somebody Else" not in prompt


def test_owner_may_route_another_crew(mcp_mod, as_user, routing, tqa):
    tqa.save_user_oauth_token("dave", TOKEN)
    ctx = as_user(_user("dave", "Dave O", "owner"))
    _run(mcp_mod, ctx, crew="Sam Crew", origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    assert 'crew="Sam Crew"' in routing[0][1]


def test_server_home_choice_uses_the_routed_crew_members_address(mcp_mod, as_user, routing, tqa, monkeypatch):
    tqa.save_user_oauth_token("dave", TOKEN)
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: {"users": {
        "t": {"name": "Sam Crew", "role": "field_crew", "status": "active", "home_address": "5 Oak St"}}})
    seen = []
    import db_route_ops
    monkeypatch.setattr(db_route_ops, "_geocode", lambda addr: seen.append(addr) or (29.1, -81.0))
    ctx = as_user(_user("dave", "Dave O", "owner", home="Daves House"))
    _run(mcp_mod, ctx, crew="Sam Crew", origin_choice="home")
    assert seen == ["5 Oak St"]


def test_server_home_choice_with_no_address_points_to_the_admin_tab(mcp_mod, as_user, routing, tqa):
    tqa.save_user_oauth_token("jake-r", TOKEN)
    out = _run(mcp_mod, as_user(_user(home="")), origin_choice="home")
    assert "Admin tab" in out and routing == []


def test_same_date_and_crew_returns_the_running_job(mcp_mod, as_user, routing):
    ctx = as_user(None)
    first = _run(mcp_mod, ctx, origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    second = _run(mcp_mod, ctx, origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    assert "already in flight" in second and len(routing) == 1
    assert re.search(r"job_id=(\w+)", first).group(1) in second


def test_only_one_run_at_a_time_across_dates_and_users(mcp_mod, as_user, routing, tqa):
    tqa.save_user_oauth_token("jake-r", TOKEN)
    tqa.save_user_oauth_token("sam-c", TOKEN)
    assert _run(mcp_mod, as_user(_user()), origin_choice="gps", origin_lat="29.0", origin_lon="-80.9").startswith("⏳")
    other = _run(mcp_mod, as_user(_user("sam-c", "Sam C")), route_date="2026-09-23",
                 origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    assert "already in progress" in other and len(routing) == 1


def test_a_finished_run_does_not_block_the_next_one(mcp_mod, as_user, routing):
    ctx = as_user(None)
    _run(mcp_mod, ctx, origin_choice="gps", origin_lat="29.0", origin_lon="-80.9")
    for job in mcp_mod._AI_ROUTING_JOBS.values():
        job["status"] = "done"
    assert _run(mcp_mod, ctx, route_date="2026-09-23", origin_choice="gps",
                origin_lat="29.0", origin_lon="-80.9").startswith("⏳")


# ══════════════════════════════════════════════════════════════════════════
# F. Connect-your-Claude-account tools + audit redaction
# ══════════════════════════════════════════════════════════════════════════

def test_all_connect_tools_refuse_in_personal_mode(mcp_mod, as_user):
    ctx = as_user(None)
    for out in (mcp_mod.start_cli_signin(ctx=ctx), mcp_mod.submit_cli_signin_code(code=GOOD_CODE, ctx=ctx),
                mcp_mod.cancel_cli_signin(ctx=ctx), mcp_mod.save_my_cli_token(token=TOKEN, ctx=ctx)):
        assert out.startswith("❌") and "multi-user servers" in out


def test_start_signin_returns_the_link(mcp_mod, as_user, monkeypatch):
    seen = []
    monkeypatch.setattr(relay, "start_login", lambda uid: seen.append(uid) or (True, URL))
    assert mcp_mod.start_cli_signin(ctx=as_user(_user())) == f"SIGNIN_URL: {URL}"
    assert seen == ["jake-r"]


def test_start_signin_failure_is_a_clear_error(mcp_mod, as_user, monkeypatch):
    monkeypatch.setattr(relay, "start_login", lambda uid: (False, "busy right now"))
    assert mcp_mod.start_cli_signin(ctx=as_user(_user())) == "❌ busy right now"


def _connected(monkeypatch):
    monkeypatch.setattr(relay, "submit_code",
                        lambda uid, code: {"status": "connected", "message": "Connected.", "token": TOKEN})


def test_connected_emails_the_user_a_copy_but_never_returns_the_token(mcp_mod, as_user, monkeypatch):
    _connected(monkeypatch)
    sent = []
    monkeypatch.setattr(mcp_mod, "_send_smtp", lambda to, subj, body, **k: sent.append((to, subj, body)) or (True, "ok"))
    out = mcp_mod.submit_cli_signin_code(code=GOOD_CODE, ctx=as_user(_user()))
    assert out.startswith("CONNECTED") and "emailed" in out
    assert TOKEN not in out and GOOD_CODE not in out
    assert sent[0][0] == "jake@example.com" and TOKEN in sent[0][2]


def test_connected_without_an_email_address_still_connects(mcp_mod, as_user, monkeypatch):
    _connected(monkeypatch)
    monkeypatch.setattr(mcp_mod, "_send_smtp", lambda *a, **k: pytest.fail("must not email"))
    out = mcp_mod.submit_cli_signin_code(code=GOOD_CODE, ctx=as_user(_user(email="")))
    assert out.startswith("CONNECTED") and "no email address" in out


def test_connected_survives_an_email_failure(mcp_mod, as_user, monkeypatch):
    _connected(monkeypatch)
    monkeypatch.setattr(mcp_mod, "_send_smtp", lambda *a, **k: (False, "SMTP not configured"))
    out = mcp_mod.submit_cli_signin_code(code=GOOD_CODE, ctx=as_user(_user()))
    assert out.startswith("CONNECTED") and "couldn't be emailed" in out and TOKEN not in out


def test_connected_survives_the_mailer_raising(mcp_mod, as_user, monkeypatch):
    _connected(monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("smtp exploded")
    monkeypatch.setattr(mcp_mod, "_send_smtp", boom)
    assert mcp_mod.submit_cli_signin_code(code=GOOD_CODE, ctx=as_user(_user())).startswith("CONNECTED")


def test_invalid_code_is_reported_for_retry(mcp_mod, as_user, monkeypatch):
    monkeypatch.setattr(relay, "submit_code", lambda uid, code: {"status": "invalid_code", "message": "Paste it again."})
    assert mcp_mod.submit_cli_signin_code(code="x" * 12, ctx=as_user(_user())) == "INVALID_CODE: Paste it again."


def test_expired_signin_is_a_plain_error(mcp_mod, as_user, monkeypatch):
    monkeypatch.setattr(relay, "submit_code", lambda uid, code: {"status": "no_session", "message": "expired"})
    assert mcp_mod.submit_cli_signin_code(code=GOOD_CODE, ctx=as_user(_user())).startswith("❌")


def test_cancel_signin(mcp_mod, as_user, monkeypatch):
    seen = []
    monkeypatch.setattr(relay, "cancel_login", lambda uid: seen.append(uid))
    assert mcp_mod.cancel_cli_signin(ctx=as_user(_user())).startswith("✅") and seen == ["jake-r"]


def test_save_my_token_saves_for_the_caller_only(mcp_mod, as_user, tqa):
    assert mcp_mod.save_my_cli_token(token=TOKEN, ctx=as_user(_user())) == "CONNECTED"
    assert tqa.has_user_oauth_token("jake-r") and not tqa.has_user_oauth_token("sam-c")


def test_save_my_token_rejects_a_bad_value(mcp_mod, as_user, tqa):
    out = mcp_mod.save_my_cli_token(token="hello", ctx=as_user(_user()))
    assert out.startswith("❌") and not tqa.has_user_oauth_token("jake-r")


def test_credentials_never_reach_the_audit_log(mcp_mod, monkeypatch, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(mcp_mod, "_AUDIT_LOG_PATH", log)
    mcp_mod._append_audit_log("save_my_cli_token", {"token": TOKEN, "ctx": None}, ok=True)
    mcp_mod._append_audit_log("submit_cli_signin_code", {"code": GOOD_CODE, "ctx": None}, ok=True)
    text = log.read_text(encoding="utf-8")
    assert TOKEN not in text and GOOD_CODE not in text and text.count("<redacted>") == 2
    assert "save_my_cli_token" in text and "submit_cli_signin_code" in text   # call itself still logged


def test_redaction_does_not_blank_other_tools_arguments(mcp_mod, monkeypatch, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(mcp_mod, "_AUDIT_LOG_PATH", log)
    mcp_mod._append_audit_log("get_route_start_options", {"crew": "Sam Crew", "ctx": None}, ok=True)
    assert "Sam Crew" in log.read_text(encoding="utf-8")


def test_credentials_are_redacted_on_the_failure_path_too(mcp_mod, monkeypatch, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(mcp_mod, "_AUDIT_LOG_PATH", log)
    mcp_mod._append_audit_log("save_my_cli_token", {"token": TOKEN}, ok=False, error="boom")
    assert TOKEN not in log.read_text(encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════
# G. static checks — Jobs app, allowlists, Admin tab
# ══════════════════════════════════════════════════════════════════════════

_HTML = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
_MCP = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
_GUI = (_SRC / "rag_gui.py").read_text(encoding="utf-8")


def _fn(name):
    m = re.search(rf"(?:async )?function {name}\(.*?\n}}\n", _HTML, re.S)
    assert m, f"{name} not found in jobs/index.html"
    return m.group(0)


def test_run_ai_routing_no_longer_uses_a_plain_confirm():
    assert "confirm(" not in _fn("runAiRouting")


def test_run_ai_routing_does_not_ask_where_the_day_starts():
    # 2026-09-21: no start/end question any more — a tap goes straight to running.
    body = _fn("runAiRouting")
    assert "_aiRoutePickOrigin(" not in body and "_aiRouteSheet(" not in body


def test_run_ai_routing_sends_no_origin_so_settings_decide_by_mode():
    # Same data as Route Today: no origin_choice / coordinates, so the server's
    # apply_route_order resolves start/end from Settings (Jobs Only -> home,
    # Company Location -> Start/End Address).
    body = _fn("runAiRouting")
    assert "origin_choice" not in body and "origin_lat" not in body and "origin_lon" not in body
    assert "var params = { route_date: date, crew: crew };" in body


def test_run_ai_routing_reconnects_then_retries_on_no_token():
    body = _fn("runAiRouting")
    assert "NO_CLI_TOKEN" in body and "_aiRouteConnect()" in body
    assert body.count("mcpCall('start_ai_routing', params)") == 2


def test_the_start_end_choice_is_never_stored():
    picker = _fn("_aiRoutePickOrigin") + _fn("runAiRouting")
    assert "localStorage.setItem('aiRoutingOrigin" not in picker
    assert not re.search(r"localStorage\.setItem\([^)]*(origin|pick|choice)", picker, re.I)


def test_picker_has_nothing_preselected_and_disables_unavailable_options():
    body = _fn("_aiRoutePickOrigin") + _fn("_aiRouteOption")
    assert "checked" not in body.replace("input[name=aiRouteOrigin]:checked", "")
    assert "disabled" in body and 'id="aoGo" disabled' in body


def test_picker_points_users_at_the_right_place_when_home_is_unset():
    body = _fn("_aiRoutePickOrigin")
    assert "Admin tab" in body and "Settings tab" in body


def test_connect_flow_offers_both_paths_and_the_personal_warning():
    body = _fn("_aiRouteConnect")
    assert "AI-Prowler Personal" in body and "Links & Analysis" in body
    assert "save_my_cli_token" in body and "start_cli_signin" in body
    assert "submit_cli_signin_code" in body and "cancel_cli_signin" in body
    assert "sign your Personal version out" in body


def test_connect_flow_only_links_to_claude_dot_com():
    assert "indexOf('https://claude.com/') !== 0" in _fn("_aiRouteConnect")


def test_connect_flow_masks_the_pasted_key():
    assert 'id="acKey" type="password"' in _fn("_aiRouteConnect")


def test_connect_ui_escapes_server_text():
    assert "escapeHtml(text)" in _fn("_aiRouteNote")


def _server_allowlist():
    i = _MCP.index("_srv_pa_allowed = {")
    return _MCP[i:_MCP.index("}", i)]


def _personal_allowlist():
    i = _MCP.index("_allowed_tools = {", _MCP.index("start_ai_routing", _MCP.index("_srv_pa_allowed = {")))
    return _MCP[i:_MCP.index("}", i)]


@pytest.mark.parametrize("tool", ["start_ai_routing", "poll_ai_routing", "get_route_start_options",
                                  "start_cli_signin", "submit_cli_signin_code",
                                  "cancel_cli_signin", "save_my_cli_token"])
def test_server_pwa_allowlist_has_the_tool(tool):
    assert f'"{tool}"' in _server_allowlist()


def test_personal_pwa_allowlist_has_the_picker_tool_but_not_the_connect_tools():
    block = _personal_allowlist()
    assert '"get_route_start_options"' in block and '"start_ai_routing"' in block
    for tool in ("start_cli_signin", "submit_cli_signin_code", "cancel_cli_signin", "save_my_cli_token"):
        assert f'"{tool}"' not in block


def test_admin_dialog_has_a_home_address_field_saved_on_add_and_edit():
    assert 'text="Home address:"' in _GUI
    assert '"home_address": fields.get("home_address", "")' in _GUI          # add
    assert 'u["home_address"] = fields.get("home_address", "")' in _GUI      # edit (can clear)


def test_admin_tab_has_the_ai_route_token_button_and_columns():
    assert "_admin_set_ai_route_token" in _GUI and "🤖 AI Route Token" in _GUI
    assert "'home', 'airoute'" in _GUI


def test_admin_tab_never_shows_the_address_or_token_in_the_table():
    row = _GUI[_GUI.index("home_flag ="):_GUI.index("seat, status, tok_display))")]
    assert 'home_flag = "✓" if' in row and "ai_flag" in row
    assert "home_address\"]" not in row.split("self._admin_tree.insert")[1]


def test_connect_tools_are_registered_as_real_tools():
    for tool in ("start_cli_signin", "submit_cli_signin_code", "cancel_cli_signin", "save_my_cli_token"):
        assert re.search(rf"@mcp\.tool\(\)\ndef {tool}\(", _MCP), tool
