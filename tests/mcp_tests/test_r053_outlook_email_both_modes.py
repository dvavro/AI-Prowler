"""
R-053 (2026-09-28): server-mode Settings → Email Configuration had no Outlook
support — no detection/status, no "Send via" Outlook/SMTP checkboxes, no
Check/Refresh Outlook button, no account picker, and Save / Test Connection
forced SMTP. The send path itself (_send_smtp) already honoured an Outlook
backend in both modes, and the HTTP MCP server runs as a child of the GUI in
the same desktop session, so there was no reason to withhold it.

Fix: the email section is the same in both modes (only intro text differs).
Guard added with it: in server mode send_email ignores from_account, so a
signed-in employee can't send from another mailbox in the server's Outlook
profile — every user sends from the company account chosen in Settings.
list_outlook_accounts / configure_email stay personal-only (an employee must
not list or change the company account from Claude).

Run: run_tests.bat tests\\mcp\\test_r053_outlook_email_both_modes.py -v
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def _email_section():
    src = (_SRC / "rag_gui.py").read_text(encoding="utf-8")
    i = src.index("# ── Email Configuration ──")
    j = src.index("# ── SMS / Text Messaging", i)
    return src[i:j]


def test_email_section_has_no_personal_only_gates():
    sec = _email_section()
    assert "if not _settings_is_server_mode" not in sec
    assert "not _settings_is_server_mode and" not in sec


def test_save_and_test_no_longer_force_smtp_in_server_mode():
    sec = _email_section()
    assert "using_ol   = False" not in sec
    assert "using_ol   = _outlook_cb_var.get()" in sec


def test_outlook_controls_built_for_both_modes():
    sec = _email_section()
    assert "_show_outlook_ui = True" in sec
    assert "if _show_outlook_ui:" in sec
    for s in ("🔍 Check for Outlook", "Microsoft Outlook  (no password needed)",
              "_refresh_ol_accounts()", "Default account:"):
        assert s in sec, s


def test_R054_page_load_never_launches_outlook():
    """R-054 (found live 2026-09-28): opening AI-Prowler on the server popped
    Outlook 2016's "Welcome to Outlook" setup wizard — the page-load account
    refresh fell back to Dispatch("Outlook.Application"), which STARTS Outlook,
    on a PC where Classic Outlook is installed but has no mail profile."""
    sec = _email_section()
    assert "def _refresh_ol_accounts(allow_launch: bool = True):" in sec
    assert "_refresh_ol_accounts(allow_launch=False)" in sec
    # every bare call (no argument) must be the explicit Check/Refresh click
    bare = sec.count("_refresh_ol_accounts()")
    check = sec[sec.index("def _check_outlook_now"):sec.index("_chk_ol_btn = ttk.Button")]
    assert bare == check.count("_refresh_ol_accounts()") == 1
    # the no-launch return comes BEFORE Dispatch inside the worker
    w = sec[sec.index("def _worker():"):]
    assert w.index("if not allow_launch:") < w.index('_wc2.Dispatch("Outlook.Application")')


def test_R054_saved_outlook_account_kept_when_outlook_not_running():
    sec = _email_section()
    assert "if saved_user and uses_ol and saved_user not in current_accts:" in sec


def test_server_intro_text_mentions_company_account_and_reply_to():
    sec = _email_section()
    assert "Server mode: this is the company's sending account" in sec
    assert "Reply-To" in sec


# ── send_email from_account in server mode ───────────────────────────────────

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


CFG = {"backend": "outlook", "username": "company@biz.com", "from_name": "Biz"}


def _send(mcp_mod, user):
    with patch.object(mcp_mod, "_email_config_load", return_value=CFG), \
         patch.object(mcp_mod, "_current_user", return_value=user), \
         patch.object(mcp_mod, "_send_email_cap", return_value=(True, "")), \
         patch.object(mcp_mod, "_send_smtp", return_value=(True, "✅ sent")) as m:
        mcp_mod.send_email(to="vicki@example.com", subject="s", body="b",
                           from_account="owner.private@biz.com", ctx=None)
    return m.call_args.kwargs


@pytest.mark.parametrize("role", ["owner", "manager", "staff", "field_crew"])
def test_server_mode_ignores_from_account(role, mcp_mod):
    kw = _send(mcp_mod, {"id": "u", "name": "Sam Crew", "role": role,
                         "email": "sam@example.com"})
    assert kw["from_account_override"] is None
    assert "sam@example.com" in (kw["reply_to"] or "")


def test_personal_mode_still_honours_from_account(mcp_mod):
    kw = _send(mcp_mod, None)
    assert kw["from_account_override"] == "owner.private@biz.com"


def test_send_path_routes_outlook_backend_regardless_of_mode(mcp_mod):
    with patch.object(mcp_mod, "_email_config_load", return_value=CFG), \
         patch.object(mcp_mod, "_send_via_outlook", return_value=(True, "✅ via Outlook")) as ol:
        ok, msg = mcp_mod._send_smtp("x@example.com", "s", "b",
                                     reply_to="Sam <sam@example.com>")
    assert ok and "Outlook" in msg
    assert ol.call_args.kwargs["reply_to"] == "Sam <sam@example.com>"
    assert ol.call_args.kwargs["from_account_email"] == "company@biz.com"


def test_claude_side_outlook_config_tools_stay_personal_only(mcp_mod):
    assert "list_outlook_accounts" in mcp_mod._TIER_A_SUPPRESSED
    assert "configure_email" in mcp_mod._TIER_A_SUPPRESSED
