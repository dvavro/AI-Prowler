"""Service Desk settings on AI-Prowler's Small Business tab (2026-10-30).

desk_gui_settings.py: the "🤖 Service Desk Agent & settings" section — "(not enabled)"
and nothing else until Service Desk is switched on; then General / Data & backups /
Team (server) / Agent tabs with a remembered Show/Hide switch. On a server the app has
no Settings tab (desk/index.html).

Run: run_tests.bat tests\\unit\\test_desk_gui_settings.py
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_gui_agent  # noqa: E402
import desk_gui_links  # noqa: E402
import desk_gui_settings as dgs  # noqa: E402


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    return path


@pytest.fixture
def state(tmp_path, monkeypatch):
    d = tmp_path / "state"
    d.mkdir()
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(d))
    return d


# ── switched on? remembered show/hide ────────────────────────────────────────

@pytest.mark.parametrize("on,text,color", [(True, "(enabled)", dgs.GREEN), (False, "(not enabled)", dgs.GREY)])
def test_section_status_follows_the_service_desk_switch(monkeypatch, on, text, color):
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda cfg=None: on)
    assert dgs.section_status() == {"enabled": on, "text": text, "color": color}


def test_header_shows_the_agent_and_practice_mode_as_saved(db):
    """David 2026-10-31: the Service Desk Agent & settings header should show practice mode."""
    assert dgs.agent_status(db)["text"] == "· 🤖 agent off"
    desk_db.set_setting(db, "agent_enabled", True, edition="solo")          # practice is the default
    a = dgs.agent_status(db)
    assert a["text"] == "· 🤖 agent on — practice mode · 📅 booking off" and a["practice"]
    desk_db.set_setting(db, "agent_shadow", False, edition="solo")
    desk_db.set_setting(db, "agent_bk_enabled", True, edition="solo")
    a = dgs.agent_status(db)
    assert a["text"] == "· 🤖 agent on · 📅 booking on — practice mode" and a["color"] == dgs.GREEN


def test_show_hide_is_remembered(state):
    assert dgs.load_show() is True                     # default: shown
    dgs.save_show(False)
    assert dgs.load_show() is False and (state / dgs.STATE_FILE).exists()
    dgs.save_show(True)
    assert dgs.load_show() is True


# ── ⚙ General ────────────────────────────────────────────────────────────────

def test_general_rows_match_the_app():
    solo = [k for k, _ in dgs.general_rows("solo")]
    biz = [k for k, _ in dgs.general_rows("business")]
    assert "own_tickets" in solo and "own_tickets" not in biz
    assert set(biz) == set(solo) - {"own_tickets"}
    html = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    for k, label, _ in dgs.GENERAL_ROWS:                 # same words as the app's Settings tab
        assert f"'{k}'" in html and label.split(" (")[0].replace("'", "\\'") in html, k


def test_general_saves(db):
    assert dgs.set_one(db, "csat_enabled", False, "business") == (True, "Saved.")
    assert dgs.set_one(db, "sms_new_request_mode", "ask", "business")[0]
    assert not dgs.set_one(db, "sms_new_request_mode", "shout", "business")[0]
    assert dgs.save_auto_close(db, "5", "solo")[0] and not dgs.save_auto_close(db, "61", "solo")[0]
    assert not dgs.save_auto_close(db, "soon", "solo")[0]
    assert dgs.save_alerts(db, " me@x.com ", "386-555-0100", "solo")[0]
    s = desk_db.get_settings(db)
    assert (s["csat_enabled"], s["sms_new_request_mode"], s["auto_close_days"], s["alert_email"]) == \
        (False, "ask", 5, "me@x.com")


# ── can AI-Prowler email / text? (2026-10-30) ───────────────────────────────

def test_gui_channels_reads_the_real_setup(state, monkeypatch):
    import json as _json
    import sms_backends
    assert dgs.gui_channels() == {"email": False, "sms": False}             # nothing set up
    (state / "email_config.json").write_text(_json.dumps({"smtp_host": "smtp.x.com", "username": "a"}),
                                             encoding="utf-8")
    assert dgs.gui_channels()["email"] is True                               # was always "no email" before
    (state / "email_config.json").write_text(_json.dumps({"backend": "outlook", "username": "a"}),
                                             encoding="utf-8")
    assert dgs.gui_channels()["email"] is True

    class OK:
        def validate_config(self):
            return True, ""
    monkeypatch.setattr(sms_backends, "get_sms_backend", lambda cfg: OK())
    monkeypatch.setattr(sms_backends, "load_sms_config", lambda: {})
    import tool_config_store as tcs
    monkeypatch.setattr(tcs, "group_enabled", lambda mode, group: group != "sms_whatsapp")
    assert dgs.gui_channels()["sms"] is False                                # provider OK but switched off
    monkeypatch.setattr(tcs, "group_enabled", lambda mode, group: True)
    assert dgs.gui_channels()["sms"] is True


def test_texting_note_only_when_texts_cannot_go_out():
    assert dgs.sms_note({"email": True, "sms": False}) == dgs.SMS_NOTE
    assert dgs.sms_note({"email": True, "sms": True}) == ""
    assert "SMS & WhatsApp" in dgs.SMS_NOTE and "email and phone notification" in dgs.SMS_NOTE
    assert dgs.portal_note({"email": True, "sms": True}).startswith("Customers can get their code")
    assert dgs.portal_note({"email": False, "sms": False}).startswith("Set up email")
    html = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    assert "r[0] === 'sms_fallback_default' && !pc.sms" in html and 'id="smsNote"' in html


# ── 💾 Data & backups ────────────────────────────────────────────────────────

def test_export_then_dry_run_import(db, tmp_path):
    desk_db.create_ticket(db, title="Streaky windows", kind="internal", edition="solo")
    name = dgs.export_name(db, "json", "solo")
    dest = tmp_path / name
    dgs.export_to(db, "json", str(dest), "solo")
    assert dest.stat().st_size > 0
    xl = tmp_path / "t.xlsx"
    dgs.export_to(db, "xlsx", str(xl), "solo")
    assert xl.read_bytes()[:2] == b"PK"
    r = dgs.import_file(db, str(dest), "solo", dry_run=True)
    assert dgs.import_summary(r).startswith("Dry run")


def test_backups_list_copy_and_settings(db, tmp_path):
    b = dgs.backup_now(db)
    rows = dgs.backup_rows(db)
    assert rows and rows[0][0] == b["name"] and "KB" in rows[0][1]
    out = tmp_path / "copy.zip"
    dgs.copy_backup(db, b["name"], str(out))
    assert out.read_bytes()[:2] == b"PK"
    ok, msg = dgs.save_backup_settings(db, {"backup_enabled": False, "backup_frequency": "weekly",
                                            "backup_hour": "3", "backup_keep_daily": "x"}, "solo")
    assert not ok and "whole number" in msg
    s = desk_db.get_settings(db)
    assert (s["backup_enabled"], s["backup_frequency"], s["backup_hour"]) == (False, "weekly", 3)


# ── where backups live (David 2026-10-30) ────────────────────────────────────

def test_backup_folder_can_move_and_takes_the_backups_with_it(db, tmp_path):
    import desk_backup
    std = desk_backup.default_backup_dir(db)
    assert desk_backup.backup_dir(db) == std
    b1 = dgs.backup_now(db)
    new = tmp_path / "elsewhere" / "Service Desk backups"
    r = desk_backup.set_backup_folder(db, str(new), edition="solo")
    assert r == {"folder": str(new), "moved": 1, "standard": False}
    assert desk_backup.backup_dir(db) == new and (new / b1["name"]).exists() and not (std / b1["name"]).exists()
    import datetime
    b2 = desk_backup.backup_now(db, "manual", now=datetime.datetime.now() + datetime.timedelta(minutes=1))
    assert (new / b2["name"]).exists()
    assert [n for n, _ in dgs.backup_rows(db)] == [b2["name"], b1["name"]]      # list reads the new place
    r = desk_backup.set_backup_folder(db, "", edition="solo")                   # back to the standard place
    assert r["standard"] and r["moved"] == 2 and desk_backup.backup_dir(db) == std
    with pytest.raises(desk_db.DeskError, match="full folder path"):
        desk_backup.set_backup_folder(db, "relative\\folder", edition="solo")


def test_full_restore_keeps_the_current_backup_folder(db, tmp_path):
    import desk_backup
    b = dgs.backup_now(db)                                    # its database copy says "standard place"
    new = tmp_path / "nas"
    desk_backup.set_backup_folder(db, str(new), edition="solo")
    out = desk_backup.restore(db, b["name"], edition="solo", confirm=True)
    assert out["restored"] == "all"
    assert desk_backup.backup_dir(db) == new                  # not switched back by the restore
    assert any(n == b["name"] for n, _ in dgs.backup_rows(db))


def test_backup_folder_is_set_only_in_ai_prowler(db):
    import desk_http as h
    import desk_tools as dt
    st, ct, out = h.route("POST", "/desk-api/settings", query={}, body=b'{"key": "backup_dir", "value": "C:\\\\x"}',
                          content_type="application/json", actor=None, edition="solo", db_path=db, services={})
    assert st == 403 and b"AI-Prowler on this PC" in out
    assert dt.tickets_settings(db, None, "solo", setting="backup_dir", value="C:\\x").startswith("🔒")
    assert desk_db.get_settings(db)["backup_dir"] == ""
    st, ct, out = h.route("GET", "/desk-api/backups", query={}, body=b"", content_type="", actor=None,
                          edition="solo", db_path=db, services={})
    import json as _json
    d = _json.loads(out)
    assert d["folder"].endswith("backups") and "backup_keep_monthly" in d["help"]


def test_backup_help_explains_every_setting():
    import desk_backup
    H = desk_backup.BACKUP_HELP
    for k in ("backup_frequency", "backup_hour", "backup_keep_daily", "backup_keep_weekly", "backup_keep_monthly",
              "retention", "backup_attachments", "backup_second_dir", "backup_dir"):
        assert len(H[k]) > 30, k
    assert "Sundays" in H["backup_frequency"] and "about a year" in H["backup_keep_monthly"]
    assert "30 days" in H["retention"]
    html = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    assert 'id="bkFolder"' in html and 'id="bkKeepHelp"' in html and "H.backup_keep_daily" in html
    src = (ROOT / "desk_gui_settings.py").read_text(encoding="utf-8")
    assert "set_backup_folder" in src and 'H["retention"]' in src and "Open folder" in src


# ── 👥 Team ─────────────────────────────────────────────────────────────────

def test_team_queue_rule_type(db):
    dgs.save_queue(db, "field", "Field crew", "cris, sam", "business")
    dgs.save_rule(db, "r1", "keyword", "gutter", "queue", "field", "10", "business")
    dgs.save_type(db, "redo", "Re-do", "field", "business")
    t = dgs.team(db)
    assert [q["queue_id"] for q in t["queues"]] == ["field"] and t["queues"][0]["members"] == ["cris", "sam"]
    assert t["rules"][0]["action"] == {"queue": "field"}
    assert any(y["type_id"] == "redo" for y in t["types"])
    dgs.delete_rule(db, "r1", "business")
    dgs.delete_queue(db, "field", "business")
    assert not dgs.team(db)["queues"] and not dgs.team(db)["rules"]


# ── the app: no Settings tab on a server ────────────────────────────────────

def test_app_settings_tab_is_personal_only():
    html = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    assert "$('#tabSettings').classList.toggle('hide', a.role !== 'owner' || S.me.edition !== 'solo');" in html
    assert "AI-Prowler → 🏢 Small Business tab → Service Desk settings" in html
    gui = (ROOT / "rag_gui.py").read_text(encoding="utf-8")
    assert "_dgs.build_section(self, banner)" in gui


# ── the section, built for real ─────────────────────────────────────────────

class _App:
    pass


@pytest.fixture(scope="module")
def tkroot():
    """One Tk window for every window test in this file (Windows often refuses a second
    or third Tk root in one run, which silently skipped tests)."""
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    app = _App()
    app.root, app.status_var = root, tk.StringVar(value="Ready")
    yield tk, root, app
    root.destroy()


def test_not_enabled_shows_only_the_name(tkroot, monkeypatch, state):
    tk, root, app = tkroot
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda cfg=None: False)
    frame = tk.Frame(root)
    out = dgs.build_section(app, frame)
    assert out["status"].cget("text") == "(not enabled)" and str(out["status"].cget("foreground")) == dgs.GREY
    assert "notebook" not in out
    body = out["frame"].winfo_children()[0]
    texts = [w.cget("text") for w in body.winfo_children()]
    assert len(texts) == 1 and "Service Desk (tickets)" in texts[0]


@pytest.mark.parametrize("edition,tabs", [("business", ["⚙ General", "💾 Data & backups", "👥 Team", "🌐 Web forms",
                                                       "🤖 Agent"]),
                                          ("solo", ["⚙ General", "💾 Data & backups", "🌐 Web forms", "🤖 Agent"])])
def test_enabled_shows_everything_and_remembers_hide(tkroot, monkeypatch, state, db, edition, tabs):
    tk, root, app = tkroot
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda cfg=None: True)
    monkeypatch.setattr(desk_gui_agent, "db_and_edition", lambda: (db, edition))
    frame = tk.Frame(root)
    out = dgs.build_section(app, frame)
    assert out["status"].cget("text") == "(enabled)" and str(out["status"].cget("foreground")) == dgs.GREEN
    nb = out["notebook"]
    assert [nb.tab(t, "text") for t in nb.tabs()] == tabs
    assert out["content"].winfo_manager() == "pack"              # shown
    out["show"].set(False)
    assert out["content"].winfo_manager() == "" and dgs.load_show() is False
    out["show"].set(True)
    assert out["content"].winfo_manager() == "pack" and dgs.load_show() is True


def test_switching_on_later_rebuilds(tkroot, monkeypatch, state, db):
    tk, root, app = tkroot
    on = {"v": False}
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda cfg=None: on["v"])
    monkeypatch.setattr(desk_gui_agent, "db_and_edition", lambda: (db, "solo"))
    out = dgs.build_section(app, tk.Frame(root))
    assert "notebook" not in out
    on["v"] = True
    out["rebuild"]()                                             # what showing the tab does
    assert out["status"].cget("text") == "(enabled)" and "notebook" in out
