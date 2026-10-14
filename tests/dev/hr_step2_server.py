"""HR server-only conversion, step 2 (2026-10-11, David) — ai_prowler_mcp.py.

  a. hr_* tools never registered in PERSONAL mode (_PERSONAL_MODE_SUPPRESSED)
  b. SERVER mode: hr_* tools registered only while the HR apps switch is on
     (tool_config_store.hr_apps_enabled(), default off); _hr_apps_turned_off()
     re-reads it per request so the web apps follow the switch at once
  c. personal HTTP handler: every HR route answers "server only" (404)
  d. server HTTP handler: HR block rebuilt — switch check, /hr -> /hr_admin/
     redirect, folder-boundary path guards, AI-Prowler sign-in for HR Admin
     (/hr-api/auth/login) and HR Portal (/hr-api/auth/aiprowler), the
     employee <-> AI-Prowler-user link checked on every portal request, and
     /hr-api/aiprowler-users for HR Admin's link picker
Checks every anchor before writing. ASCII output."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
F = REPO / "ai_prowler_mcp.py"
raw = F.read_bytes().decode("utf-8")
NL = "\r\n" if "\r\n" in raw else "\n"
src = raw.replace("\r\n", "\n")

HR_TOOLS = ["hr_backup_now", "hr_complete_task", "hr_create_employee", "hr_get_backup_settings",
            "hr_get_employee", "hr_get_form", "hr_get_report", "hr_get_setup_status",
            "hr_get_state_rules", "hr_get_task_digest", "hr_initiate_termination", "hr_list_backups",
            "hr_list_documents", "hr_list_employees", "hr_list_tasks", "hr_restore_employee",
            "hr_send_notification", "hr_set_backup_settings", "hr_update_employee", "hr_verify_document"]
for t in HR_TOOLS:
    assert f"def {t}(" in src, t

# ── a. personal-mode suppression ────────────────────────────────────────────
old_a = '''_PERSONAL_MODE_SUPPRESSED: frozenset = frozenset({
    "check_sms_replies",
})'''
new_a = '''# The HR apps' tools (2026-10-11, David): HR Admin / HR Portal are AI-Prowler
# SERVER only, so none of the hr_* tools exists on a personal install.
_HR_TOOLS: frozenset = frozenset({
''' + "".join(f'    "{t}",\n' for t in HR_TOOLS) + '''})

_PERSONAL_MODE_SUPPRESSED: frozenset = frozenset({
    "check_sms_replies",
}) | _HR_TOOLS'''
assert src.count(old_a) == 1
src = src.replace(old_a, new_a)

# ── b. server: the HR switch ────────────────────────────────────────────────
old_b = '''_USER_TOOL_CONFIG = _load_user_tool_config()
_USER_DISABLED_TOOLS: frozenset = _USER_TOOL_CONFIG[
    "server" if _IS_SERVER_MODE else "personal"
]
'''
new_b = old_b + '''

# ── HR apps switch (2026-10-11, David) ──────────────────────────────────────
# HR Admin + HR Portal (and the hr_* tools) are SERVER only and OFF until the
# owner ticks "HR apps (HR Admin + HR Portal)" in Settings → MCP Tool
# Configuration. Tools: decided at start-up like every other panel choice
# (restart to apply). Web apps: _hr_apps_turned_off() re-reads the switch on
# every request, so turning HR off closes both apps immediately.
def _hr_apps_switch_on() -> bool:
    try:
        import tool_config_store as _tcs_hr
        return bool(_tcs_hr.hr_apps_enabled())
    except Exception as _e:
        _log.warning("HR apps switch unreadable (%s) — treating HR as off.", _e)
        return False


def _hr_apps_turned_off() -> bool:
    """True when the HR web apps / API must refuse: always on a personal
    install, and on a server until the owner switches HR on."""
    return (not _IS_SERVER_MODE) or (not _hr_apps_switch_on())


_HR_APPS_OFF_MESSAGE = (
    "The HR apps are turned off on this AI-Prowler server — the owner can turn "
    "them on in Settings → MCP Tool Configuration (HR apps)."
)
_HR_SERVER_ONLY_MESSAGE = (
    "The HR apps (HR Admin and HR Portal) are available on an AI-Prowler "
    "server only."
)

if _IS_SERVER_MODE and not _hr_apps_switch_on():
    _USER_DISABLED_TOOLS = _USER_DISABLED_TOOLS | _HR_TOOLS
    _log.info("HR apps are switched off — %d hr_* tool(s) not registered.", len(_HR_TOOLS))
'''
assert src.count(old_b) == 1
src = src.replace(old_b, new_b)

# ── c/d. the two HTTP handlers' HR blocks ───────────────────────────────────
START = "# \u2500\u2500 HR Admin PWA \u2014 static file server, no auth required"
END = "# \u2500\u2500 end HR REST API"
lines = src.split("\n")
starts = [i for i, l in enumerate(lines) if l.strip().startswith(START)]
ends = [i for i, l in enumerate(lines) if l.strip().startswith(END)]
assert len(starts) == 2 and len(ends) == 2, (starts, ends)
(s_srv, s_per), (e_srv, e_per) = starts, ends
assert s_srv < e_srv < s_per < e_per
srv_block = "\n".join(lines[s_srv:e_srv + 1])
per_block = "\n".join(lines[s_per:e_per + 1])
assert "_srv_access_tokens" in srv_block and "_srv_access_tokens" not in per_block
assert "_access_tokens" in per_block

I12 = " " * 12
personal_new = '''            # ── HR apps — AI-Prowler SERVER only (2026-10-11, David) ───────────
            # HR Admin / HR Portal / the HR API do not exist on a personal
            # install (the old /hr/ app is retired everywhere). Previously any
            # personal token counted as HR admin here.
            if path == "/hr" or path.startswith(("/hr/", "/hr_admin", "/hr_portal", "/hr-api")):
                if path.startswith("/hr-api"):
                    await send({"type": "http.response.start", "status": 404,
                                "headers": [[b"content-type", b"application/json"],
                                            [b"cache-control", b"no-store"]]})
                    await send({"type": "http.response.body", "more_body": False,
                                "body": json.dumps({"ok": False, "error": "hr_server_only",
                                                    "message": _HR_SERVER_ONLY_MESSAGE}).encode()})
                else:
                    await send({"type": "http.response.start", "status": 404,
                                "headers": [[b"content-type", b"text/plain; charset=utf-8"],
                                            [b"cache-control", b"no-store"]]})
                    await send({"type": "http.response.body", "more_body": False,
                                "body": _HR_SERVER_ONLY_MESSAGE.encode("utf-8")})
                return
            # ── end HR REST API (personal: server-only notice) ─────────────────'''

server_new = r'''            # ── HR apps — HR Admin + HR Portal, AI-Prowler SERVER only ─────────
            # (2026-10-11, David) One switch (Settings → MCP Tool Configuration
            # → "HR apps (HR Admin + HR Portal)", default OFF) opens or closes
            # both apps and the HR API. The old /hr/ app is retired: /hr and
            # /hr/... redirect to /hr_admin/. Static files are served with a
            # folder-boundary check (the old /hr route had none).
            #   HR Admin  — owners/managers (can_manage_hr): POST /hr-api/auth/login
            #               {name, token} -> an access token (same idle timeout and
            #               /pwa-logout as the Jobs app, but works with Jobs off)
            #   HR Portal — any AI-Prowler user LINKED to an employee record
            #               (employee.aiprowler_user_id, set in HR Admin):
            #               POST /hr-api/auth/aiprowler {name, token} -> employee
            #               session; the link is re-checked on every request
            if path == "/hr" or path.startswith(("/hr/", "/hr_admin", "/hr_portal", "/hr-api")):
                if _hr_apps_turned_off():
                    if path.startswith("/hr-api"):
                        await _send_json(send, 403, {"ok": False, "error": "hr_apps_off",
                                                     "message": _HR_APPS_OFF_MESSAGE})
                    else:
                        await _send_text(send, 404, _HR_APPS_OFF_MESSAGE)
                    return

                if path == "/hr" or path.startswith("/hr/"):
                    await send({"type": "http.response.start", "status": 302,
                                "headers": [[b"location", b"/hr_admin/"],
                                            [b"cache-control", b"no-store"]]})
                    await send({"type": "http.response.body", "body": b""})
                    return

                if path.startswith(("/hr_admin", "/hr_portal")):
                    import mimetypes as _hrs_mt, os as _hrs_os
                    _hrs_app = "hr_admin" if path.startswith("/hr_admin") else "hr_portal"
                    _hrs_root = _hrs_os.path.join(
                        _hrs_os.path.dirname(_hrs_os.path.abspath(__file__)), _hrs_app)
                    _hrs_rel = path[len("/" + _hrs_app):].lstrip("/") or "index.html"
                    _hrs_fp = _hrs_os.path.join(_hrs_root, _hrs_rel)
                    if not _path_is_inside(_hrs_fp, _hrs_root):
                        await _send_text(send, 403, "Forbidden")
                        return
                    if not _hrs_os.path.isfile(_hrs_fp):
                        _hrs_fp = _hrs_os.path.join(_hrs_root, "index.html")
                        _hrs_rel = "index.html"
                        if not _hrs_os.path.isfile(_hrs_fp):
                            await _send_text(send, 404, "Not Found")
                            return
                    try:
                        with open(_hrs_fp, "rb") as _hrs_f:
                            _hrs_body = _hrs_f.read()
                    except Exception as _hrs_e:
                        _log.error("HR app (%s): file read error for %s — %s", _hrs_app, _hrs_fp, _hrs_e)
                        await _send_text(send, 500, "Internal Server Error")
                        return
                    _hrs_body = _patch_sw_cache_version(_hrs_rel, _hrs_root, _hrs_body)
                    _hrs_ct = (_hrs_mt.guess_type(_hrs_fp)[0] or "application/octet-stream").encode()
                    await send({"type": "http.response.start", "status": 200,
                                "headers": [[b"content-type", _hrs_ct],
                                            [b"content-length", str(len(_hrs_body)).encode()],
                                            [b"cache-control", b"no-cache"]]})
                    await send({"type": "http.response.body", "body": _hrs_body})
                    return

                # ── /hr-api/* ────────────────────────────────────────────────
                import urllib.parse as _hrsrv_up
                import json as _hrsrv_json
                _hrsrv_subpath = path[len("/hr-api"):] or "/"
                _hrsrv_qs = dict(_hrsrv_up.parse_qsl(scope.get("query_string", b"").decode()))
                _hrsrv_body_bytes = await _read_body(receive)
                try:
                    _hrsrv_body_json = _hrsrv_json.loads(_hrsrv_body_bytes) if _hrsrv_body_bytes else {}
                except Exception:
                    _hrsrv_body_json = {}

                # AI-Prowler sign-in (HR Admin and HR Portal) — same name + token
                # check as the Jobs app's /pwa-login.
                if _hrsrv_subpath in ("/auth/login", "/auth/aiprowler") and method == "POST":
                    _hrl_name = str((_hrsrv_body_json or {}).get("name", "")).strip()
                    _hrl_tok = str((_hrsrv_body_json or {}).get("token", "")).strip()
                    _hrl_err = "Name or password not recognized."
                    _hrl_user = (_resolve_user(_hot_reload_users(users_data), _hrl_tok)
                                 if _hrl_name and _hrl_tok else None)
                    if (_hrl_user is None or
                            (_hrl_user.get("name", "") or "").strip().lower() != _hrl_name.lower()):
                        await _send_json(send, 401, {"ok": False, "error": "invalid_credentials",
                                                     "message": _hrl_err})
                        return
                    if _hrsrv_subpath == "/auth/login":
                        if not _role_caps(_hrl_user.get("role")).get("can_manage_hr"):
                            await _send_json(send, 403, {"ok": False, "error": "not_hr_admin",
                                                         "message": "HR Admin is for owners and managers. "
                                                                    "Employees use the HR Portal."})
                            return
                        _hrl_access = _srv_secrets.token_urlsafe(48)
                        _srv_access_tokens[_hrl_access] = _hrl_tok
                        _srv_pwa_last_used[_hrl_access] = _srv_time.time()   # R-043 idle timeout
                        _log.info("HR Admin sign-in: user=%s role=%s", _hrl_user.get("id"), _hrl_user.get("role"))
                        await _send_json(send, 200, {"ok": True, "access_token": _hrl_access,
                                                     "name": _hrl_user.get("name", ""),
                                                     "role": _hrl_user.get("role", "")})
                        return
                    _hrl_db = _hr_load_db()
                    _hrl_emp = next((e for e in _hrl_db.get("employees", [])
                                     if e.get("aiprowler_user_id") == _hrl_user.get("id")
                                     and e.get("status") != "Terminated"), None)
                    if _hrl_emp is None:
                        await _send_json(send, 403, {"ok": False, "error": "not_linked",
                                                     "message": "Your AI-Prowler account isn't linked to an "
                                                                "employee record yet — ask HR to link it in HR Admin."})
                        return
                    _hrl_email = "aiprowler:" + str(_hrl_user.get("id"))
                    _hrl_sig = _hr_sign_session(_hrl_emp["id"], _hrl_email, _hr_session_secret(_hrl_db))
                    _log.info("HR Portal sign-in: user=%s employee=%s", _hrl_user.get("id"), _hrl_emp["id"])
                    await _send_json(send, 200, {"ok": True, "session": {
                        "employee_id": _hrl_emp["id"],
                        "name": f"{_hrl_emp.get('first_name', '')} {_hrl_emp.get('last_name', '')}".strip(),
                        "email": _hrl_email, "sig": _hrl_sig}})
                    return

                # Who is calling: an HR admin (owner/manager access token) or a
                # signed-in employee (HR Portal session).
                _hrsrv_auth = {"role": None}
                _hrsrv_tok = _bearer_from_scope(scope)
                _hrsrv_resolved_user = None
                if _hrsrv_tok and _hrsrv_tok in _srv_access_tokens:
                    _hrsrv_raw_tok = _srv_raw_token_for(_hrsrv_tok)  # R-043 idle timeout
                    _hrsrv_resolved_user = (_resolve_user(_hot_reload_users(users_data), _hrsrv_raw_tok)
                                            if _hrsrv_raw_tok else None)
                if _hrsrv_resolved_user and _role_caps(_hrsrv_resolved_user.get("role")).get("can_manage_hr"):
                    _hrsrv_auth = {"role": "admin", "user_id": _hrsrv_resolved_user.get("id")}
                else:
                    _hrsrv_emp_sess_hdr = ""
                    for _hrsrv_hk, _hrsrv_hv in scope.get("headers", []):
                        if _hrsrv_hk.lower() == b"x-employee-session":
                            _hrsrv_emp_sess_hdr = _hrsrv_hv.decode("utf-8", "replace")
                            break
                    if _hrsrv_emp_sess_hdr:
                        _hrsrv_db_peek = _hr_load_db()
                        _hrsrv_emp_id = _hr_verify_employee_session(_hrsrv_emp_sess_hdr, _hrsrv_db_peek)
                        if _hrsrv_emp_id:
                            # An AI-Prowler sign-in session is only good while the
                            # employee is still linked to that same user.
                            try:
                                _hrsrv_sess_email = str(_hrsrv_json.loads(_hrsrv_emp_sess_hdr).get("email", ""))
                            except Exception:
                                _hrsrv_sess_email = ""
                            if _hrsrv_sess_email.startswith("aiprowler:"):
                                _hrsrv_emp_rec = next((e for e in _hrsrv_db_peek.get("employees", [])
                                                       if e.get("id") == _hrsrv_emp_id), {}) or {}
                                if (_hrsrv_emp_rec.get("aiprowler_user_id") != _hrsrv_sess_email[len("aiprowler:"):]
                                        or _hrsrv_emp_rec.get("status") == "Terminated"):
                                    _hrsrv_emp_id = None
                        if _hrsrv_emp_id:
                            _hrsrv_auth = {"role": "employee", "employee_id": _hrsrv_emp_id}

                # HR Admin's "AI-Prowler login" picker: the server's users
                # (id, name, role only — never a token). HR admins only.
                if _hrsrv_subpath == "/aiprowler-users" and method == "GET":
                    if _hrsrv_auth.get("role") != "admin":
                        await _send_json(send, 403, {"error": "admin_only"})
                        return
                    _hru_data = _hot_reload_users(users_data) or {}
                    _hru_list = []
                    for _hru_tok in (_hru_data.get("users") or {}):
                        _hru_u = _resolve_user(_hru_data, _hru_tok)
                        if _hru_u:
                            _hru_list.append({"id": _hru_u.get("id"), "name": _hru_u.get("name", ""),
                                              "role": _hru_u.get("role", "")})
                    _hru_list.sort(key=lambda u: (u["name"] or "").lower())
                    await _send_json(send, 200, {"users": _hru_list})
                    return

                # documents/upload -- multipart, bypasses the JSON dispatcher
                if _hrsrv_subpath == "/documents/upload" and method == "POST":
                    _hrsrv_ctype_hdr = ""
                    for _hrsrv_hk2, _hrsrv_hv2 in scope.get("headers", []):
                        if _hrsrv_hk2.lower() == b"content-type":
                            _hrsrv_ctype_hdr = _hrsrv_hv2.decode(errors="replace")
                            break
                    _hrsrv_status, _hrsrv_ctype2, _hrsrv_resp_body = _hr_handle_document_upload(
                        _hrsrv_body_bytes, _hrsrv_ctype_hdr, _hrsrv_auth)
                else:
                    _hrsrv_status, _hrsrv_ctype2, _hrsrv_resp_body = _hr_api_route(
                        method, _hrsrv_subpath, _hrsrv_qs, _hrsrv_body_json, _hrsrv_auth)
                await send({"type": "http.response.start", "status": _hrsrv_status,
                            "headers": [[b"content-type", _hrsrv_ctype2],
                                        [b"content-length", str(len(_hrsrv_resp_body)).encode()],
                                        [b"cache-control", b"no-store"]]})
                await send({"type": "http.response.body", "body": _hrsrv_resp_body})
                return
            # ── end HR REST API ───────────────────────────────────────────────'''

new_lines = lines[:s_srv] + server_new.split("\n") + lines[e_srv + 1:s_per] + \
    personal_new.split("\n") + lines[e_per + 1:]
out = "\n".join(new_lines)
compile(out, "ai_prowler_mcp.py", "exec")
F.write_bytes(out.replace("\n", NL).encode("utf-8"))
print(f"server HR block: lines {s_srv + 1}-{e_srv + 1} replaced ({e_srv - s_srv + 1} -> {len(server_new.splitlines())} lines)")
print(f"personal HR block: lines {s_per + 1}-{e_per + 1} replaced ({e_per - s_per + 1} -> {len(personal_new.splitlines())} lines)")
print("hr_* tools: personal-suppressed; server gated by the HR switch")
