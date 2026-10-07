"""
tests/mcp_tests/test_admin_ai_route_runner.py
========================================
Server-mode AI Route runner setup (Admin tab) + the Personal Links & Analysis
Copy / Email Token buttons, 2026-09-19.

A server has no Links & Analysis or Small Business tab (both hidden in server
mode), so the one-time setup for AI Routing — install the Claude Code CLI,
register the dedicated on-demand Scheduled Task — lives in an "AI Route runner"
panel on the Admin tab. These tests call the panel's methods on a fake `self`
(no Tk window, no real installer, no UAC prompt, no Scheduled Task).

The Personal Copy / Email Token buttons are closures inside a very large GUI
builder and can't be called directly, so they get source-level checks only.

Run with:
    run_tests.bat tests\\mcp\\test_admin_ai_route_runner.py -v
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_GUI = (_SRC / "rag_gui.py").read_text(encoding="utf-8")
TOKEN = "sk-ant-oat01-" + "Ab3-_" * 18


# ══════════════════════════════════════════════════════════════════════════
# fakes
# ══════════════════════════════════════════════════════════════════════════

class _Var:
    def __init__(self):
        self.value = None

    def set(self, v):
        self.value = v


class _Btn:
    def __init__(self):
        self.calls = []

    def state(self, spec):
        self.calls.append(list(spec))

    @property
    def disabled(self):
        return bool(self.calls) and self.calls[-1] == ["disabled"]


@pytest.fixture(scope="module")
def GUI():
    try:
        import rag_gui
    except Exception as exc:  # pragma: no cover - environment without Tk etc.
        pytest.skip(f"rag_gui not importable here: {exc}")
    return rag_gui.RAGGui


@pytest.fixture
def tqa(monkeypatch):
    import task_queue_automation as t
    monkeypatch.setattr(t, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(t, "ai_routing_task_exists", lambda: True)
    monkeypatch.setattr(t, "has_user_oauth_token", lambda uid: False)
    return t


def _fake(GUI, users=None, gate=True):
    """A stand-in for the RAGGui instance carrying just what the methods touch."""
    refreshed = []
    me = SimpleNamespace(
        _admin_ai_route_var=_Var(), _admin_ai_cli_btn=_Btn(), _admin_ai_runner_btn=_Btn(),
        _admin_load_users=lambda: {"users": users or {}},
        _admin_user_slug=GUI._admin_user_slug,
        _admin_ai_token_key=GUI._admin_ai_token_key,
        _admin_gate=lambda: gate,
        root=SimpleNamespace(after=lambda ms, fn: fn()),   # run "after" callbacks immediately
        refreshed=refreshed,
    )
    me._admin_ai_route_refresh_status = lambda: (refreshed.append(1),
                                                 GUI._admin_ai_route_refresh_status(me))
    return me


@pytest.fixture
def sync_threads(monkeypatch):
    """Run background-thread targets inline so a test can assert on the result."""
    import threading

    class Inline:
        def __init__(self, target=None, daemon=None, **k):
            self.target = target

        def start(self):
            self.target()
    monkeypatch.setattr(threading, "Thread", Inline)


@pytest.fixture
def boxes(monkeypatch):
    import tkinter.messagebox as mb
    rec = SimpleNamespace(info=[], warn=[], error=[])
    monkeypatch.setattr(mb, "showinfo", lambda *a, **k: rec.info.append(a))
    monkeypatch.setattr(mb, "showwarning", lambda *a, **k: rec.warn.append(a))
    monkeypatch.setattr(mb, "showerror", lambda *a, **k: rec.error.append(a))
    return rec


def _users():
    return {
        "t1": {"name": "Jake R", "status": "active"},
        "t2": {"name": "Sam Crew", "status": "active"},
        "t3": {"name": "Old Timer", "status": "suspended"},
    }


# ══════════════════════════════════════════════════════════════════════════
# status panel
# ══════════════════════════════════════════════════════════════════════════

def test_status_when_everything_is_ready(GUI, tqa, monkeypatch):
    monkeypatch.setattr(tqa, "has_user_oauth_token", lambda uid: uid == "jake-r")
    me = _fake(GUI, _users())
    GUI._admin_ai_route_refresh_status(me)
    text = me._admin_ai_route_var.value
    assert "✅ Claude Code CLI: installed" in text and "✅ On-demand runner: set up" in text
    assert "1 of 2" in text                       # suspended user not counted
    assert "AI Routing is ready" in text
    assert me._admin_ai_cli_btn.disabled          # nothing left to install


def test_status_when_nothing_is_set_up(GUI, tqa, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: False)
    monkeypatch.setattr(tqa, "ai_routing_task_exists", lambda: False)
    me = _fake(GUI, _users())
    GUI._admin_ai_route_refresh_status(me)
    text = me._admin_ai_route_var.value
    assert "❌ Claude Code CLI: not installed" in text and "❌ On-demand runner: not set up yet" in text
    assert "AI Routing is ready" not in text
    assert not me._admin_ai_cli_btn.disabled      # install button is available


def test_status_reports_a_failed_check_instead_of_crashing(GUI, tqa, monkeypatch):
    def boom():
        raise OSError("schtasks missing")
    monkeypatch.setattr(tqa, "ai_routing_task_exists", boom)
    me = _fake(GUI, _users())
    GUI._admin_ai_route_refresh_status(me)
    assert "Could not check AI Route setup" in me._admin_ai_route_var.value


def test_status_is_a_noop_before_the_panel_exists(GUI):
    GUI._admin_ai_route_refresh_status(SimpleNamespace())      # no _admin_ai_route_var: must not raise


def test_R048_token_key_is_the_user_id_like_the_server(GUI):
    # The server looks a token up by user["id"] (start_ai_routing, the Jobs app's
    # connect screen). A user renamed after creation keeps their id.
    assert GUI._admin_ai_token_key({"id": "jake-r", "name": "Jacob Rivers"}) == "jake-r"


def test_R048_token_key_falls_back_to_the_name_slug(GUI):
    assert GUI._admin_ai_token_key({"name": "Jake R"}) == "jake-r"
    assert GUI._admin_ai_token_key({"id": "  ", "name": "Jake R"}) == "jake-r"
    assert GUI._admin_ai_token_key(None) == "unknown-user"


def test_R048_connected_count_uses_the_user_id(GUI, tqa, monkeypatch):
    monkeypatch.setattr(tqa, "has_user_oauth_token", lambda uid: uid == "jake-r")
    users = {"t1": {"id": "jake-r", "name": "Jacob Rivers", "status": "active"}}   # renamed
    me = _fake(GUI, users)
    GUI._admin_ai_route_refresh_status(me)
    assert "1 of 1" in me._admin_ai_route_var.value


def test_R048_every_admin_token_lookup_uses_the_same_key():
    # Table column, runner panel count and the token dialog all go through one helper.
    import re
    assert len(re.findall(r"has_user_oauth_token\(\s*self\._admin_ai_token_key\(u\)", _GUI)) == 2
    assert "slug = self._admin_ai_token_key(u)" in _GUI
    assert "has_user_oauth_token(\n                    self._admin_user_slug" not in _GUI


def test_status_never_shows_addresses_or_tokens(GUI, tqa):
    users = {"t": {"name": "Jake R", "status": "active", "home_address": "9 SECRET LANE"}}
    me = _fake(GUI, users)
    GUI._admin_ai_route_refresh_status(me)
    assert "SECRET" not in me._admin_ai_route_var.value


# ══════════════════════════════════════════════════════════════════════════
# install CLI button
# ══════════════════════════════════════════════════════════════════════════

def test_install_cli_success(GUI, tqa, sync_threads, boxes, monkeypatch):
    calls = []
    monkeypatch.setattr(tqa, "install_claude_code_cli", lambda: calls.append(1) or (True, "Installed successfully."))
    me = _fake(GUI)
    GUI._admin_ai_route_install_cli(me)
    assert calls == [1] and me.refreshed and boxes.info == [("Claude Code CLI", "Installed successfully.")]
    assert me._admin_ai_cli_btn.calls[0] == ["disabled"]        # disabled while it runs


def test_install_cli_failure_is_shown_as_an_error(GUI, tqa, sync_threads, boxes, monkeypatch):
    monkeypatch.setattr(tqa, "install_claude_code_cli", lambda: (False, "Install timed out after 120s"))
    me = _fake(GUI)
    GUI._admin_ai_route_install_cli(me)
    assert boxes.error == [("Claude Code CLI", "Install timed out after 120s")] and not boxes.info


def test_install_cli_exception_is_shown_not_raised(GUI, tqa, sync_threads, boxes, monkeypatch):
    def boom():
        raise RuntimeError("no network")
    monkeypatch.setattr(tqa, "install_claude_code_cli", boom)
    GUI._admin_ai_route_install_cli(_fake(GUI))
    assert boxes.error and "no network" in boxes.error[0][1]


def test_install_cli_needs_the_admin_gate(GUI, tqa, sync_threads, boxes, monkeypatch):
    monkeypatch.setattr(tqa, "install_claude_code_cli", lambda: pytest.fail("must not install"))
    me = _fake(GUI, gate=False)
    GUI._admin_ai_route_install_cli(me)
    assert not me._admin_ai_cli_btn.calls and not boxes.info and not boxes.error


def test_install_runs_off_the_ui_thread(GUI):
    src = _GUI[_GUI.index("def _admin_ai_route_install_cli"):_GUI.index("def _admin_ai_route_setup_runner")]
    assert "threading.Thread(target=_work, daemon=True).start()" in src and "self.root.after(0" in src


# ══════════════════════════════════════════════════════════════════════════
# set up runner button
# ══════════════════════════════════════════════════════════════════════════

def test_setup_runner_success(GUI, tqa, sync_threads, boxes, monkeypatch):
    monkeypatch.setattr(tqa, "install_ai_routing_task", lambda: (True, "ok"))
    me = _fake(GUI)
    GUI._admin_ai_route_setup_runner(me)
    assert boxes.info == [("AI Route Runner", "The AI Route runner is set up.")]
    assert me._admin_ai_runner_btn.calls == [["disabled"], ["!disabled"]] and me.refreshed


def test_setup_runner_with_a_side_issue_warns(GUI, tqa, sync_threads, boxes, monkeypatch):
    monkeypatch.setattr(tqa, "install_ai_routing_task", lambda: (True, "ok (batch logon right grant had an issue: x)"))
    GUI._admin_ai_route_setup_runner(_fake(GUI))
    assert boxes.warn and "batch logon right" in boxes.warn[0][1] and not boxes.info


def test_setup_runner_failure_reenables_the_button(GUI, tqa, sync_threads, boxes, monkeypatch):
    monkeypatch.setattr(tqa, "install_ai_routing_task", lambda: (False, "UAC declined"))
    me = _fake(GUI)
    GUI._admin_ai_route_setup_runner(me)
    assert boxes.error and "UAC declined" in boxes.error[0][1]
    assert not me._admin_ai_runner_btn.disabled                 # can try again


def test_setup_runner_exception_is_shown_not_raised(GUI, tqa, sync_threads, boxes, monkeypatch):
    def boom():
        raise RuntimeError("powershell missing")
    monkeypatch.setattr(tqa, "install_ai_routing_task", boom)
    me = _fake(GUI)
    GUI._admin_ai_route_setup_runner(me)
    assert boxes.error and not me._admin_ai_runner_btn.disabled


def test_setup_runner_needs_the_admin_gate(GUI, tqa, sync_threads, boxes, monkeypatch):
    monkeypatch.setattr(tqa, "install_ai_routing_task", lambda: pytest.fail("must not register"))
    me = _fake(GUI, gate=False)
    GUI._admin_ai_route_setup_runner(me)
    assert not me._admin_ai_runner_btn.calls


def test_setup_runner_runs_off_the_ui_thread():
    src = _GUI[_GUI.index("def _admin_ai_route_setup_runner"):_GUI.index("@staticmethod\n    def _admin_user_slug")]
    assert "threading.Thread(target=_work, daemon=True).start()" in src


# ══════════════════════════════════════════════════════════════════════════
# panel wiring (source-level)
# ══════════════════════════════════════════════════════════════════════════

def test_admin_tab_has_the_runner_panel_with_its_buttons():
    for needle in ("AI Route runner (one-time server setup)", "⬇ Install Claude Code CLI",
                   "🔧 Set Up AI Route Runner", "_admin_ai_route_install_cli",
                   "_admin_ai_route_setup_runner", "_admin_ai_route_refresh_status"):
        assert needle in _GUI, needle


def test_table_refresh_updates_the_runner_status():
    body = _GUI[_GUI.index("def _admin_refresh_table"):_GUI.index("# Seat summary strip")]
    assert "self._admin_ai_route_refresh_status()" in body


def test_runner_panel_is_built_before_the_first_table_refresh():
    build = _GUI[_GUI.index("ai_lf = ttk.LabelFrame"):]
    assert build.index("self._admin_ai_route_var = tk.StringVar") < build.index("self._admin_refresh_table()")


# ══════════════════════════════════════════════════════════════════════════
# start_ai_routing: server-mode "not set up" messages point at the Admin tab
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


def _run(mcp_mod, ctx):
    return mcp_mod.start_ai_routing(route_date="2026-09-22", crew="", origin_lat="29.0",
                                    origin_lon="-80.9", origin_choice="gps", ctx=ctx)


SERVER_USER = {"id": "jake-r", "name": "Jake R", "role": "field_crew", "status": "active"}


def test_server_message_when_cli_missing_points_to_the_admin_tab(mcp_mod, tqa, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: SERVER_USER)
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: False)
    out = _run(mcp_mod, _ctx(SERVER_USER))
    assert "Admin tab" in out and "Install Claude Code CLI" in out
    assert "Links & Analysis" not in out and "Small Business" not in out


def test_server_message_when_runner_missing_points_to_the_admin_tab(mcp_mod, tqa, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: SERVER_USER)
    monkeypatch.setattr(tqa, "ai_routing_task_exists", lambda: False)
    out = _run(mcp_mod, _ctx(SERVER_USER))
    assert "Admin tab" in out and "Set Up AI Route Runner" in out and "Small Business" not in out


def test_personal_messages_are_unchanged(mcp_mod, tqa, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: False)
    assert "Links & Analysis tab" in _run(mcp_mod, None)
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa, "ai_routing_task_exists", lambda: False)
    assert "Small Business tab" in _run(mcp_mod, None)


def test_setup_problems_are_reported_before_the_missing_token(mcp_mod, tqa, monkeypatch):
    """No runner AND no token: the admin-only setup is the blocker to name —
    sending the user through 'Connect your Claude account' would be pointless."""
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: SERVER_USER)
    monkeypatch.setattr(tqa, "ai_routing_task_exists", lambda: False)
    out = _run(mcp_mod, _ctx(SERVER_USER))
    assert "NO_CLI_TOKEN" not in out


# ══════════════════════════════════════════════════════════════════════════
# Personal: Links & Analysis Copy / Email Token buttons (source-level)
# ══════════════════════════════════════════════════════════════════════════

_LA = _GUI[_GUI.index("def _tqa_copy_token"):_GUI.index("def _tqa_on_auth_change")]


def test_copy_and_email_buttons_exist_next_to_get_renew():
    assert 'text="📋 Copy Token"' in _LA and 'text="✉ Email Token to Me"' in _LA
    assert _LA.index("_tqa_btn_get_token = ttk.Button") < _LA.index("_tqa_btn_copy_token = ttk.Button")


def test_copy_and_email_are_shown_only_on_the_oauth_path():
    relayout = _LA[_LA.index("def _tqa_relayout_buttons"):_LA.index("def _tqa_on_auth_change") if "def _tqa_on_auth_change" in _LA else None]
    shown = relayout[relayout.index("if not is_api_key:"):relayout.index("_tqa_btn_test.pack")]
    assert "_tqa_btn_copy_token.pack" in shown and "_tqa_btn_email_token.pack" in shown
    forgot = relayout[:relayout.index("if not is_api_key:")]
    assert "_tqa_btn_copy_token" in forgot and "_tqa_btn_email_token" in forgot


def test_copy_reads_the_saved_token_and_handles_none():
    body = _LA[_LA.index("def _tqa_copy_token"):_LA.index("def _tqa_email_token")]
    assert "_tqa.load_oauth_token()" in body and "clipboard_append(tok)" in body
    assert "No Token Yet" in body and body.index("No Token Yet") < body.index("clipboard_append")


def test_email_asks_before_sending_and_needs_an_address():
    body = _LA[_LA.index("def _tqa_email_token"):_LA.index("_tqa_btn_row = tk.Frame")]
    assert "askyesno" in body and "isn't encrypted" in body
    assert "Email Not Set Up" in body and '"@" not in _to' in body
    assert body.index("askyesno") < body.index("_send_smtp(")


def test_email_goes_only_to_the_installs_own_configured_address():
    body = _LA[_LA.index("def _tqa_email_token"):_LA.index("_tqa_btn_row = tk.Frame")]
    assert '_ecfg.get("default_to")' in body and "_send_smtp(_to," in body


def test_email_never_puts_the_token_in_the_subject_or_a_message_box():
    body = _LA[_LA.index("def _tqa_email_token"):_LA.index("_tqa_btn_row = tk.Frame")]
    assert '"Your AI-Prowler Claude token"' in body
    for line in body.splitlines():
        if "messagebox." in line:
            assert "tok" not in line.replace("Token", "")
