"""Server E2E — the HR apps (HR Admin + HR Portal), AI-Prowler SERVER only.
David 2026-10-11: "use David Vavro, Vicki Vavro, Samual Cronin as the users to
test the HR app in the multi user configuration like it was designed for".

Needs the HR apps switched ON on the server (Settings → MCP Tool Configuration
→ "HR apps (HR Admin + HR Portal)" → Save). Otherwise every test is skipped
with that instruction.

  HR-01  /hr (the retired original app) redirects to /hr_admin/
  HR-02  HR Admin / HR Portal static files can't be escaped with ../
  HR-03  HR Admin sign-in rules (API): owner + manager get in; field crew is
         refused ("HR Admin is for owners and managers"); a wrong token is refused
  HR-04  HR Admin in the browser: David and Vicki sign in with name + token,
         Samual is refused on the sign-in screen
  HR-05  The "AI-Prowler login" link: David opens a ZTEST employee's 🔗 picker in
         HR Admin, links Samual's account and saves; one account can't be
         linked to two employees
  HR-06  HR Portal in the browser: Samual signs in with HIS AI-Prowler account
         and lands in the portal as the linked employee; Vicki (not linked) is
         refused with "isn't linked … ask HR"
  HR-07  Unlinking ends it: Samual's portal session stops working at once
  HR-08  All three at the same time (2026-10-12, David): David and Vicki both
         signed in to HR Admin and Samual to the HR Portal, three windows open
         together; David links Samual, Vicki sees it after a refresh, Samual
         signs in while both admins stay signed in, all three sessions valid

Test data: one employee "ZTEST E2E Portal" (email ztest+hrtest@example.com — the
address Jamie's /test/cleanup also recognises), deleted at the end even if a
step fails. Nothing else on the server is touched.

Run (human mode): run_tests_gui_jobs_e2e.bat --server --human -k test_srv_hr_apps
"""
import json
import urllib.error
import urllib.request

import pytest
from playwright.sync_api import expect

from app import type_text

ZT_EMAIL = "ztest+hrtest@example.com"
CTX = {"viewport": {"width": 900, "height": 860}, "service_workers": "block"}


# ── tiny HTTP helper (no redirects followed) ─────────────────────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _http(method, url, body=None, headers=None):
    # Cloudflare answers "403 error code: 1010" to Python's default User-Agent —
    # use the suite's own (tests/gui_jobs_e2e/api.py USER_AGENT). Found 2026-10-12.
    from api import USER_AGENT
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT,
                                          **(headers or {})})
    try:
        with _OPENER.open(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def _json(text):
    try:
        return json.loads(text)
    except ValueError:
        return {}


# ── fixtures ─────────────────────────────────────────────────────────────────
def _by_role(srv, *roles):
    return next(u for u in srv["users"].values() if u.role in roles)


@pytest.fixture(scope="module")
def hr(srv):
    """Skips the module unless the HR apps are switched on; returns helpers."""
    o = srv["origin"]
    st, _, body = _http("GET", o + "/hr-api/config")
    if st == 403 and _json(body).get("error") == "hr_apps_off":
        pytest.skip("The HR apps are switched OFF on the server — turn them on in Settings → "
                    "MCP Tool Configuration → 'HR apps (HR Admin + HR Portal)' → Save, then re-run.")
    if st == 404 and "server only" in body:
        pytest.exit(f"{o} answered as a personal install — the HR apps are server only.", returncode=4)
    owner, manager = _by_role(srv, "owner"), _by_role(srv, "manager")
    crew = _by_role(srv, "field_crew", "staff")

    def admin_login(u):
        return _http("POST", o + "/hr-api/auth/login", {"name": u.name, "token": u.token})

    st, _, b = admin_login(owner)
    assert st == 200, f"owner HR Admin sign-in failed: HTTP {st} {b[:200]}"
    tok = _json(b)["access_token"]

    def api(method, path, body=None, headers=None):
        st, _, txt = _http(method, o + "/hr-api" + path, body,
                           {"Authorization": f"Bearer {tok}", **(headers or {})})
        return st, _json(txt)

    return {"origin": o, "owner": owner, "manager": manager, "crew": crew,
            "admin_login": admin_login, "api": api}


@pytest.fixture
def zt_employee(hr):
    """One ZTEST employee, always deleted afterwards."""
    st, r = hr["api"]("POST", "/employees", {
        "personal": {"first_name": "ZTEST E2E", "last_name": "Portal", "personal_email": ZT_EMAIL},
        "employment": {"title": "ZTEST E2E", "department": "ZTEST"},
        "compensation": {"pay_type": "hourly", "pay_rate": 0}})
    assert st == 200 and r.get("id"), f"couldn't create the ZTEST employee: {st} {r}"
    emp_id = r["id"]
    yield emp_id
    st, r = hr["api"]("DELETE", f"/employees/{emp_id}")
    assert st in (200, 404), f"ZTEST employee {emp_id} not deleted: {st} {r}"


def _crew_user_id(hr):
    st, r = hr["api"]("GET", "/aiprowler-users")
    assert st == 200, r
    u = next((x for x in r["users"] if x["name"].lower() == hr["crew"].name.lower()), None)
    assert u, f"{hr['crew'].name} not in the AI-Prowler user list"
    assert all(set(x) == {"id", "name", "role"} for x in r["users"]), "the picker list must never carry tokens"
    return u["id"]


@pytest.fixture
def page_for(browser):
    ctxs = []

    def make():
        ctx = browser.new_context(**CTX)
        ctxs.append(ctx)
        pg = ctx.new_page()
        pg.set_default_timeout(20_000)
        return pg
    yield make
    for c in ctxs:
        try:
            c.close()
        except Exception:
            pass


def _admin_sign_in(page, origin, user):
    page.goto(origin + "/hr_admin/")
    expect(page.locator("#auth-name")).to_be_visible()
    type_text(page, page.locator("#auth-name"), user.name)
    type_text(page, page.locator("#auth-token"), user.token)
    page.get_by_role("button", name="Sign In as HR Admin").click()


def _portal_sign_in(page, origin, user):
    page.goto(origin + "/hr_portal/")
    expect(page.locator("#login-name")).to_be_visible()
    type_text(page, page.locator("#login-name"), user.name)
    type_text(page, page.locator("#login-pass"), user.token)
    page.locator("#login-btn").click()


# ── tests ────────────────────────────────────────────────────────────────────
def test_HR_01_old_hr_app_redirects_to_hr_admin(hr):
    for p in ("/hr", "/hr/", "/hr/index.html"):
        st, h, _ = _http("GET", hr["origin"] + p)
        loc = {k.lower(): v for k, v in h.items()}.get("location", "")
        assert st == 302 and loc.endswith("/hr_admin/"), f"{p}: HTTP {st} location={loc!r}"


def test_HR_02_static_files_cannot_be_escaped(hr):
    for p in ("/hr_admin/..%2F..%2Fai_prowler_mcp.py", "/hr_portal/..%2F..%2Fconfig.json",
              "/hr_admin/%2e%2e/%2e%2e/ai_prowler_mcp.py"):
        st, _, body = _http("GET", hr["origin"] + p)
        assert "def " not in body[:4000] and '"remote_token"' not in body, f"{p} leaked a file (HTTP {st})"


def test_HR_03_admin_sign_in_rules(hr):
    for u in (hr["owner"], hr["manager"]):
        st, _, b = hr["admin_login"](u)
        assert st == 200 and _json(b).get("access_token"), f"{u.name}: HTTP {st} {b[:160]}"
    st, _, b = hr["admin_login"](hr["crew"])
    assert st == 403 and _json(b).get("error") == "not_hr_admin", f"{hr['crew'].name}: HTTP {st} {b[:160]}"
    st, _, b = _http("POST", hr["origin"] + "/hr-api/auth/login",
                     {"name": hr["owner"].name, "token": "ZTEST-not-a-real-token"})
    assert st == 401, f"wrong token: HTTP {st}"


def test_HR_04_hr_admin_sign_in_in_the_browser(hr, page_for):
    for u in (hr["owner"], hr["manager"]):
        pg = page_for()
        _admin_sign_in(pg, hr["origin"], u)
        expect(pg.locator("#auth-screen")).to_be_hidden(timeout=30_000)
    pg = page_for()
    _admin_sign_in(pg, hr["origin"], hr["crew"])
    expect(pg.locator("#auth-error")).to_contain_text("owners and managers", timeout=20_000)
    expect(pg.locator("#auth-screen")).to_be_visible()


def test_HR_05_link_an_ai_prowler_login_in_hr_admin(hr, page_for, zt_employee):
    crew_id = _crew_user_id(hr)
    pg = page_for()
    _admin_sign_in(pg, hr["origin"], hr["owner"])
    expect(pg.locator("#auth-screen")).to_be_hidden(timeout=30_000)
    # open the ZTEST employee's record and its 🔗 AI-Prowler login picker
    # (a server whose HR setup was never finished may show the setup wizard and
    # have no employees loaded yet — only wait for the app state to exist)
    pg.wait_for_function("() => typeof state === 'object' && Array.isArray(state.employees)", timeout=30_000)
    # 2026-10-12: a server whose HR "Company Setup" was never finished shows the
    # setup wizard over everything. Don't fill in the company's real HR setup
    # with test data — set the wizard aside in THIS window only (nothing is
    # saved) so the employee picker can be used.
    pg.evaluate("() => { const w = document.getElementById('setup-wizard'); "
                "if (w) w.classList.add('hidden'), w.style.display = 'none'; }")
    pg.evaluate("(id) => { state.currentEmpId = id; if (!state.employees.find(e => e.id === id)) "
                "state.employees.push({id, first_name: 'ZTEST E2E', last_name: 'Portal'}); }", zt_employee)
    pg.evaluate("() => editEmpAiProwlerLogin()")
    sel = pg.locator("#aiprowler-user-select")
    expect(sel).to_be_visible()
    sel.select_option(crew_id)
    pg.locator("#aiprowler-link-save").click()
    expect(pg.locator("#aiprowler-user-select")).to_be_hidden(timeout=20_000)
    st, r = hr["api"]("GET", f"/employees/{zt_employee}")
    emp = r.get("employee", r)
    assert emp.get("aiprowler_user_id") == crew_id, f"link not saved: {emp.get('aiprowler_user_id')!r}"
    # one AI-Prowler account, one employee
    st2, r2 = hr["api"]("POST", "/employees", {"personal": {"first_name": "ZTEST E2E", "last_name": "Second",
                                                             "personal_email": "ztest2+hrtest@example.com"}})
    try:
        st3, r3 = hr["api"]("PATCH", f"/employees/{r2['id']}", {"aiprowler_user_id": crew_id})
        assert st3 == 409 and r3.get("error") == "already_linked", (st3, r3)
    finally:
        hr["api"]("DELETE", f"/employees/{r2['id']}")


def test_HR_06_portal_sign_in_with_ai_prowler_account(hr, page_for, zt_employee):
    crew_id = _crew_user_id(hr)
    st, r = hr["api"]("PATCH", f"/employees/{zt_employee}",
                      {"aiprowler_user_id": crew_id, "aiprowler_user_name": hr["crew"].name})
    assert st == 200, r
    pg = page_for()
    _portal_sign_in(pg, hr["origin"], hr["crew"])
    expect(pg.locator("#login-screen")).to_be_hidden(timeout=30_000)
    sess = pg.evaluate("() => JSON.parse(localStorage.getItem('hr_portal_session') || '{}')")
    assert (sess.get("session") or {}).get("employee_id") == zt_employee, sess
    # Vicki has no linked employee record → refused on the sign-in screen
    pg2 = page_for()
    _portal_sign_in(pg2, hr["origin"], hr["manager"])
    expect(pg2.locator("#login-err")).to_contain_text("isn't linked", timeout=20_000)


def test_HR_07_unlinking_ends_the_portal_session(hr, zt_employee):
    crew_id = _crew_user_id(hr)
    st, r = hr["api"]("PATCH", f"/employees/{zt_employee}", {"aiprowler_user_id": crew_id})
    assert st == 200, r
    st, _, b = _http("POST", hr["origin"] + "/hr-api/auth/aiprowler",
                     {"name": hr["crew"].name, "token": hr["crew"].token})
    assert st == 200, b[:200]
    sess = json.dumps(_json(b)["session"])
    st, _, _ = _http("GET", hr["origin"] + f"/hr-api/employees/{zt_employee}", headers={"X-Employee-Session": sess})
    assert st == 200, f"linked session refused: HTTP {st}"
    st, r = hr["api"]("PATCH", f"/employees/{zt_employee}", {"aiprowler_user_id": ""})
    assert st == 200, r
    st, _, _ = _http("GET", hr["origin"] + f"/hr-api/employees/{zt_employee}", headers={"X-Employee-Session": sess})
    assert st in (401, 403), f"the session still works after unlinking: HTTP {st}"


def test_HR_08_three_users_at_the_same_time(hr, page_for, zt_employee):
    """David + Vicki in HR Admin and Samual in the HR Portal, all at once."""
    o, crew_id = hr["origin"], _crew_user_id(hr)
    david, vicki = page_for(), page_for()
    _admin_sign_in(david, o, hr["owner"])
    _admin_sign_in(vicki, o, hr["manager"])
    for pg in (david, vicki):
        expect(pg.locator("#auth-screen")).to_be_hidden(timeout=30_000)
        pg.wait_for_function("() => typeof state === 'object' && Array.isArray(state.employees)", timeout=30_000)

    # David links Samual's AI-Prowler login (through his window's own session)
    st = david.evaluate("""async ([id, uid, name]) => {
        const r = await apiFetch(`/employees/${id}`, {method: 'PATCH',
            body: JSON.stringify({aiprowler_user_id: uid, aiprowler_user_name: name})});
        return r.status; }""", [zt_employee, crew_id, hr["crew"].name])
    assert st == 200, f"David's link failed in his HR Admin window: HTTP {st}"

    # Vicki — signed in at the same time — sees the link after a refresh
    linked = vicki.evaluate("""async (id) => {
        const d = await apiGet(`/employees/${id}`); const e = d.employee || d;
        return e.aiprowler_user_id || ''; }""", zt_employee)
    assert linked == crew_id, f"Vicki doesn't see David's change: {linked!r}"

    # Samual signs in to the HR Portal while both admins are signed in
    samual = page_for()
    _portal_sign_in(samual, o, hr["crew"])
    expect(samual.locator("#login-screen")).to_be_hidden(timeout=30_000)

    # all three sessions still good, side by side
    for who, pg in (("David", david), ("Vicki", vicki)):
        st = pg.evaluate("async () => (await apiFetch('/config')).status")
        assert st == 200, f"{who}'s HR Admin session stopped working: HTTP {st}"
    sess = samual.evaluate("() => JSON.parse(localStorage.getItem('hr_portal_session') || '{}').session")
    assert sess and sess.get("employee_id") == zt_employee, sess
    st, _, _ = _http("GET", o + f"/hr-api/employees/{zt_employee}",
                     headers={"X-Employee-Session": json.dumps(sess)})
    assert st == 200, f"Samual's portal session refused: HTTP {st}"
