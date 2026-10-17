"""
HR apps — AI-Prowler SERVER only, one switch (David, 2026-10-11).

Jamie's HR Admin + HR Portal apps run only on an AI-Prowler server, OFF until
the owner turns them on in Settings → MCP Tool Configuration ("HR apps (HR
Admin + HR Portal)" — one switch for both apps and all 20 hr_* tools).
HR Admin signs in with an AI-Prowler account (owners/managers); HR Portal with
the AI-Prowler account HR linked to the employee record. The original /hr/ app
is retired (its /hr -> /hr_admin/ redirect was removed 2026-10-16).

Behaviour is tested where it can run without a live server (the switch, the
HR API's link rules); the HTTP handler's wiring is checked in the source and
proved live by tests\\gui_jobs_e2e_server\\test_srv_hr_apps.py (David, Vicki,
Samual).

Run: run_tests.bat tests\\mcp_tests\\test_hr_server_only.py -v
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
MCP = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
GUI = (ROOT / "rag_gui.py").read_text(encoding="utf-8")
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
PORTAL = (ROOT / "hr_portal" / "index.html").read_text(encoding="utf-8")


def _block(start_marker: str, end_marker: str, which: int = 0) -> str:
    starts = [m.start() for m in re.finditer(re.escape(start_marker), MCP)]
    s = starts[which]
    return MCP[s:MCP.index(end_marker, s)]


SERVER_HR = _block("# \u2500\u2500 HR apps \u2014 HR Admin + HR Portal, AI-Prowler SERVER only",
                   "# \u2500\u2500 end HR REST API")
PERSONAL_HR = _block("# \u2500\u2500 HR apps \u2014 AI-Prowler SERVER only (2026-10-11",
                     "# \u2500\u2500 end HR REST API")


# ── catalog / tool registration ──────────────────────────────────────────────
def test_catalog_hr_tools_are_server_only_and_switchable():
    import mcp_tool_catalog as cat
    hr = [n for n in cat.tools_in_category("hr")]
    assert len(hr) == 20, hr
    for n in hr:
        assert set(cat.modes_of(n)) == {"server"}, (n, cat.modes_of(n))
        assert not cat.is_locked(n), n
    assert not cat.category_is_locked("hr")
    meta = next(c for c in cat.CATEGORY_ORDER if c.key == "hr")
    assert "HR Admin" in meta.label and "HR Portal" in meta.label


def test_personal_mode_never_registers_hr_tools():
    import ai_prowler_mcp as ap
    assert len(ap._HR_TOOLS) == 20
    assert ap._HR_TOOLS <= ap._PERSONAL_MODE_SUPPRESSED
    import mcp_tool_catalog as cat
    assert set(cat.tools_in_category("hr")) == set(ap._HR_TOOLS)


def test_server_hr_tools_follow_the_switch_at_start_up():
    i = MCP.index("if _IS_SERVER_MODE and not _hr_apps_switch_on():")
    assert "_USER_DISABLED_TOOLS = _USER_DISABLED_TOOLS | _HR_TOOLS" in MCP[i:i + 300]


def test_hr_scheduler_only_on_a_server_with_hr_on():
    i = MCP.index("import hr_scheduler as _hr_sched")
    assert "if _IS_SERVER_MODE and _hr_apps_switch_on():" in MCP[i - 400:i]


# ── the switch (tool_config_store) ───────────────────────────────────────────
@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    import tool_config_store as tcs
    return tcs, tmp_path


def test_switch_defaults_off_and_round_trips(store):
    tcs, d = store
    assert tcs.hr_apps_enabled() is False                         # no file at all
    (d / "config.json").write_text('{"mode": "server", "remote_token": "x"}', encoding="utf-8")
    before = (d / "config.json").read_bytes()
    tcs.save_disabled_tools(["send_sms"], "server")
    assert tcs.hr_apps_enabled() is False                         # saved list, no choice yet
    tcs.set_hr_apps_enabled(True)
    assert tcs.hr_apps_enabled() is True
    assert tcs.load_tool_config()["server"]["disabled_tools"] == ["send_sms"], "the switch dropped the list"
    tcs.save_disabled_tools([], "server")
    assert tcs.hr_apps_enabled() is True, "saving the tool list dropped the HR switch"
    tcs.set_hr_apps_enabled(False)
    assert tcs.hr_apps_enabled() is False
    assert (d / "config.json").read_bytes() == before, "config.json was touched"


def test_switch_ignores_anything_but_true(store):
    tcs, d = store
    for val in ('"yes"', "1", "null"):
        (d / "tool_config.json").write_text('{"schema_version": 1, "hr_apps_enabled": %s}' % val,
                                            encoding="utf-8")
        assert tcs.hr_apps_enabled() is False, val


@pytest.mark.parametrize("server,switch,off", [(False, True, True), (True, False, True), (True, True, False)])
def test_hr_apps_turned_off(monkeypatch, server, switch, off):
    import ai_prowler_mcp as ap
    monkeypatch.setattr(ap, "_IS_SERVER_MODE", server)
    monkeypatch.setattr(ap, "_hr_apps_switch_on", lambda: switch)
    assert ap._hr_apps_turned_off() is off


# ── the HR API's link rules (real _hr_api_route) ─────────────────────────────
@pytest.fixture()
def hr_db(tmp_path, monkeypatch):
    import ai_prowler_mcp as ap
    monkeypatch.setattr(ap, "_HR_DB_PATH", str(tmp_path / "hr_db.json"))   # data root = tmp_path
    ap._hr_save_db({"config": {}, "employees": [        # 2026-10-16: real per-folder storage
        {"id": "EMP-00001", "first_name": "ZTEST", "last_name": "One", "status": "Active"},
        {"id": "EMP-00002", "first_name": "ZTEST", "last_name": "Two", "status": "Active"}],
        "tasks": [], "documents": [], "audit_log": []})
    return ap


def _patch(ap, emp, body, role="admin"):
    st, _ct, b = ap._hr_api_route("PATCH", f"/employees/{emp}", {}, body, {"role": role})
    return st, json.loads(b)


def test_link_rules(hr_db):
    ap = hr_db
    st, r = _patch(ap, "EMP-00001", {"aiprowler_user_id": "samual-cronin", "aiprowler_user_name": "Samual Cronin"})
    assert st == 200 and r["employee"]["aiprowler_user_id"] == "samual-cronin", r
    st, r = _patch(ap, "EMP-00002", {"aiprowler_user_id": "samual-cronin"})
    assert st == 409 and r["error"] == "already_linked", r                # one account, one employee
    st, r = _patch(ap, "EMP-00002", {"aiprowler_user_id": "bad id!"})
    assert st == 400, r
    st, r = _patch(ap, "EMP-00001", {"aiprowler_user_id": ""})
    assert st == 200 and r["employee"]["aiprowler_user_id"] == "" and r["employee"]["aiprowler_user_name"] == ""
    st, r = _patch(ap, "EMP-00002", {"aiprowler_user_id": "samual-cronin"})
    assert st == 200, "free again after unlinking"
    st, r = _patch(ap, "EMP-00001", {"aiprowler_user_id": "x"}, role="employee")
    assert st == 403, "employees can't link accounts"


# ── HTTP handler wiring (proved live by test_srv_hr_apps.py) ─────────────────
def test_server_block_switch_redirect_and_path_guard():
    b = SERVER_HR
    assert b.index("if _hr_apps_turned_off():") < b.index("_hrs_app = "), "switch checked first"
    assert "if not _path_is_inside(_hrs_fp, _hrs_root):" in b
    # 2026-10-16: the old /hr/ and /employee/ addresses and their redirects are gone
    assert 'path == "/hr"' not in b and '"/hr/"' not in b
    assert 'path == "/employee"' not in b and '"/employee/"' not in b
    assert '[b"location", b"/hr_admin/"]' not in b and '[b"location", b"/hr_portal/"]' not in b


def test_server_block_sign_ins():
    b = SERVER_HR
    i = b.index('if _hrsrv_subpath in ("/auth/login", "/auth/aiprowler") and method == "POST":')
    signin = b[i:i + 6000]      # 2026-10-16: grew with the "not an employee" check
    assert "_resolve_user(_hot_reload_users(users_data), _hrl_tok)" in signin
    assert '.strip().lower() != _hrl_name.lower()' in signin, "name must match the token's user"
    assert 'get("can_manage_hr")' in signin and '"not_hr_admin"' in signin
    assert "_srv_pwa_last_used[_hrl_access]" in signin, "HR Admin sessions use the idle timeout"
    # 2026-10-16: any active Admin-tab user may sign in — the employee record
    # is found, linked or created for them (no more "not_linked" refusal).
    assert "_hr_portal_employee_for_user(_hrl_user, _hrl_db)" in signin and '"not_linked"' not in signin
    assert '_hrl_email = "aiprowler:" + str(_hrl_user.get("id"))' in signin


def test_server_block_rechecks_the_link_every_request():
    b = SERVER_HR
    assert '_hrsrv_sess_email.startswith("aiprowler:")' in b
    assert '_hrsrv_emp_rec.get("aiprowler_user_id") != _hrsrv_sess_email[len("aiprowler:"):]' in b


def test_server_block_user_picker_admin_only_no_tokens():
    b = SERVER_HR
    i = b.index('if _hrsrv_subpath == "/aiprowler-users" and method == "GET":')
    pick = b[i:i + 1200]
    assert 'if _hrsrv_auth.get("role") != "admin":' in pick
    assert '{"id": _hru_u.get("id"), "name": _hru_u.get("name", ""),' in pick
    assert "token" not in pick.split("_hru_list.append(")[1].split(")")[0]


def test_personal_block_answers_server_only():
    b = PERSONAL_HR
    assert 'path.startswith(("/hr_admin", "/hr_portal", "/hr-api"))' in b
    assert 'path == "/hr"' not in b and '"/hr/"' not in b
    assert "_HR_SERVER_ONLY_MESSAGE" in b and "_access_tokens" not in b, "no personal HR sign-in left"


# ── the two apps ─────────────────────────────────────────────────────────────
def test_old_hr_app_is_gone_and_hr_admin_moved_off_it():
    assert not (ROOT / "hr").exists()
    assert "'/hr/" not in ADMIN and '"/hr/' not in ADMIN
    assert "navigator.serviceWorker.register('/hr_admin/sw.js')" in ADMIN
    man = json.loads((ROOT / "hr_admin" / "manifest.json").read_text(encoding="utf-8"))
    assert man["start_url"] == "/hr_admin/" and man["scope"] == "/hr_admin/"
    sw = (ROOT / "hr_admin" / "sw.js").read_text(encoding="utf-8")
    assert "'/hr/" not in sw and "if (e.request.url.indexOf('/hr-api') === -1) {" in sw


def test_hr_admin_signs_in_with_an_ai_prowler_account():
    assert 'id="auth-name"' in ADMIN and 'id="auth-token"' in ADMIN
    i = ADMIN.index("async function loginAdmin()")
    fn = ADMIN[i:ADMIN.index("\n}\n", i)]
    assert "`${API_BASE}/auth/login`" in fn and "JSON.stringify({ name, token })" in fn
    assert "data.access_token" in fn
    j = ADMIN.index("function logout()")
    assert "fetch('/pwa-logout'" in ADMIN[j:j + 400]


def test_hr_admin_links_an_ai_prowler_login():
    assert 'id="info-aiprowler"' in ADMIN and "editEmpAiProwlerLogin()" in ADMIN
    i = ADMIN.index("async function editEmpAiProwlerLogin()")
    assert "apiGet('/aiprowler-users')" in ADMIN[i:i + 800]
    j = ADMIN.index("async function saveEmpAiProwlerLogin(")
    assert "aiprowler_user_id: val" in ADMIN[j:j + 900]


def test_hr_portal_signs_in_with_an_ai_prowler_account():
    assert 'id="login-name"' in PORTAL and 'id="login-email"' not in PORTAL
    i = PORTAL.index("async function doLogin()")
    fn = PORTAL[i:PORTAL.index("async function fetchMyProfile()", i)]
    assert "`${API}/hr-api/auth/aiprowler`" in fn and "JSON.stringify({ name, token })" in fn
    assert "/hr-api/auth/employee" not in fn


# ── desktop + deployment ─────────────────────────────────────────────────────
def test_gui_hr_sections_server_only_and_panel_switch():
    for frame in ("hr_admin_lf", "hr_portal_lf", "backup_lf"):
        i = GUI.index(f"{frame}.pack(")
        assert "if self._is_business_server_mode():" in GUI[i - 200:i], frame
    assert '_tool_cfg_data.get("hr_apps_enabled") is not True' in GUI
    assert "_tcs.set_hr_apps_enabled(_hr_on)" in GUI


def test_installer_ships_hr_runtime_files_only():
    iss = (ROOT / "AI-Prowler-Setup.iss").read_text(encoding="utf-8", errors="replace")
    for f in ("hr_scheduler.py", "hr_state_rules.json", "hr_task_templates.json", "hr_forms_library.json"):
        assert f'Source: "{f}"' in iss, f
    for f in ("hr_admin\\index.html", "hr_admin\\sw.js", "hr_portal\\index.html", "hr_portal\\docs\\*.html"):
        assert f'Source: "{f}"' in iss, f
    hr_sources = [l for l in iss.split("; HR apps (2026-10-11")[1].split("; ---")[0].splitlines()
                  if l.startswith("Source:")]
    assert len(hr_sources) == 15, hr_sources
    # the HR Portal links its install manifest employee_manifest.json — it ships
    assert any("hr_portal\\employee_manifest.json" in l for l in hr_sources)
    for dev in ("issue_jamie_token", "deploy_all", "fix_pay_page", "employee_index", ".docx", "test_"):
        assert not any(dev in l for l in hr_sources), dev


def test_update_install_scripts_ship_hr_to_server_only():
    # 2026-10-14 (David): update_install.bat / update_install_server.bat live in
    # his ADMIN folder, not the repo -- this check runs only where they're present.
    srv_p, per_p = ROOT / "update_install_server.bat", ROOT / "update_install.bat"
    if not (srv_p.exists() and per_p.exists()):
        pytest.skip("update_install*.bat are kept outside the repo (ADMIN folder)")
    srv = srv_p.read_text(encoding="utf-8", errors="replace")
    per = per_p.read_text(encoding="utf-8", errors="replace")
    for f in ("hr_scheduler.py", "hr_state_rules.json", "hr_task_templates.json", "hr_forms_library.json"):
        assert f in srv, f
    assert "HR_ADMIN_FILES=index.html manifest.json sw.js" in srv
    assert "employee_manifest.json" in srv
    assert "hr_admin" not in per and "hr_portal" not in per, "personal update must not ship HR"
