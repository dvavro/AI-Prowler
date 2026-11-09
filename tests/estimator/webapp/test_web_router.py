"""JSON API on the shared service layer: projects, roles, company scoping, errors, live updates, static files."""
import json

import pytest

from estimator.api import router


def _create(call, title="Miller – 123 Main St", headers=None, **extra):
    return call("POST", "/estimator-api/estimates", {"title": title, **extra}, headers=headers)


# ---------------------------------------------------------------- projects through the service layer

def test_create_list_and_open_a_project(call):
    r = _create(call, address="123 Main St", due_date="2026-12-01")
    assert r.status == 201, r.body
    est = r.json()
    assert est["title"] == "Miller – 123 Main St" and est["status"] == "draft" and est["rev"] >= 1
    assert est["address"] == "123 Main St" and est["created_by"] == "owner"

    listing = call("GET", "/estimator-api/estimates").json()
    assert [e["id"] for e in listing["estimates"]] == [est["id"]]
    one = call("GET", f"/estimator-api/estimates/{est['id']}")
    assert one.status == 200 and one.json()["id"] == est["id"]
    evs = call("GET", f"/estimator-api/estimates/{est['id']}/events").json()["events"]
    assert evs[0]["action"] == "estimate_created" and evs[0]["actor"] == "owner"


def test_web_app_and_chat_see_the_same_project(call):
    """A project made in the web app is what the MCP tool returns, and the other way round."""
    from estimator.mcp_tools import est_tools
    eid = _create(call, "From the web").json()["id"]
    from_chat = json.loads(est_tools.est_get_estimate(eid))
    assert from_chat["title"] == "From the web"
    made_in_chat = json.loads(est_tools.est_create_estimate(title="From chat"))
    assert call("GET", f"/estimator-api/estimates/{made_in_chat['id']}").json()["title"] == "From chat"


@pytest.mark.parametrize("body,code", [({"title": ""}, 400), ({"title": "   "}, 400), ({"title": "x" * 201}, 400),
                                       ({"title": "ok", "address": "a" * 501}, 400)])
def test_bad_project_input(call, body, code):
    assert call("POST", "/estimator-api/estimates", body).status == code


def test_bad_json_and_huge_bodies(call):
    assert call("POST", "/estimator-api/estimates", raw=b"{not json").json()["error"] == "invalid_input"
    assert call("POST", "/estimator-api/estimates", raw=b"[1,2]").status == 400
    r = call("POST", "/estimator-api/estimates", raw=b'{"title":"' + b"a" * (router.MAX_JSON_BODY + 10) + b'"}')
    assert r.status == 413


def test_status_filter_and_bad_limit(call):
    _create(call)
    assert call("GET", "/estimator-api/estimates?status=draft").json()["count"] == 1
    assert call("GET", "/estimator-api/estimates?status=won").json()["count"] == 0
    assert call("GET", "/estimator-api/estimates?status=bogus").status == 400
    assert call("GET", "/estimator-api/estimates?limit=abc").status == 400


def test_unknown_things_are_404(call):
    assert call("GET", "/estimator-api/estimates/999").json()["error"] == "not_found"
    assert call("GET", "/estimator-api/nope").status == 404
    assert call("DELETE", "/estimator-api/estimates").status == 404
    assert call("GET", "/somewhere-else").status == 404


# ---------------------------------------------------------------- roles (Server mode users)

def test_reviewer_cannot_create_projects(call, session_for):
    r = _create(call, headers=session_for("reviewer"))
    assert r.status == 403 and r.json()["error"] == "permission_denied"


@pytest.mark.parametrize("role", ["office", "field", "estimator"])
def test_quoting_roles_can_create_projects(call, session_for, role):
    assert _create(call, headers=session_for(role)).status == 201


def test_company_scoping(call, session_for):
    eid = _create(call, headers=session_for("owner", "ann", company="acme")).json()["id"]
    other = session_for("owner", "bob", company="globex")
    assert call("GET", f"/estimator-api/estimates/{eid}", headers=other).status == 404
    assert call("GET", "/estimator-api/estimates", headers=other).json()["count"] == 0
    assert call("GET", "/estimator-api/dashboard", headers=other).json()["total"] == 0


def test_field_staff_never_get_costs_or_margins(call, session_for, db, ctx_for):
    from estimator.estimating import service
    owner = ctx_for("owner", "owner", "default")
    est = service.create_estimate(db, owner, "Patio")
    service.add_line_item(db, owner, est["id"], est["rev"], kind="material", description="Pavers", quantity="100",
                          unit="sf", unit_cost_cents=450)
    full = call("GET", f"/estimator-api/estimates/{est['id']}").json()
    assert full["sections"][0]["lines"][0]["unit_cost_cents"] == 450

    field = call("GET", f"/estimator-api/estimates/{est['id']}", headers=session_for("field")).json()
    text = json.dumps(field).lower()
    for word in router.MARGIN_WORDS:
        assert f'"{word}' not in text and f'_{word}' not in text, word
    assert "calc" not in field["sections"][0]["lines"][0]
    assert field["sections"][0]["lines"][0]["description"] == "Pavers"
    evs = call("GET", f"/estimator-api/estimates/{est['id']}/events", headers=session_for("field")).json()["events"]
    assert evs and all("after_json" not in e for e in evs)


def test_redact_is_recursive_and_leaves_others_alone():
    data = {"total_cents": 5, "cost_cents": 3, "lines": [{"unit_cost_cents": 1, "qty": 2, "calc": {}}],
            "markups": {"profit_pct": 1}}
    assert router.redact(data, True) is data
    assert router.redact(data, False) == {"total_cents": 5, "lines": [{"qty": 2}]}


# ---------------------------------------------------------------- menu and permissions

SPEC_MENU = ["Dashboard", "Projects", "Plans", "Takeoffs", "Reviews", "Estimates", "Bids", "Price Book",
             "Symbol Library", "Agents", "Reports", "Settings", "Help"]


def test_owner_sees_the_whole_menu_in_spec_order(call):
    me = call("GET", "/estimator-api/me").json()["me"]
    assert [s["label"] for s in me["menu"]] == SPEC_MENU
    assert me["permissions"]["settings"] is True


def test_field_menu_hides_money_and_admin_screens(call, session_for):
    me = call("GET", "/estimator-api/me", headers=session_for("field")).json()["me"]
    ids = [s["id"] for s in me["menu"]]
    for hidden in ("price_book", "agents", "settings", "takeoffs"):
        assert hidden not in ids
    for shown in ("dashboard", "projects", "reviews", "help", "bids"):     # field sends quotes (2026-11-08)
        assert shown in ids
    assert me["permissions"]["see_margins"] is False and me["permissions"]["approve"] is False


def test_every_role_has_a_menu_and_permissions(call, session_for):
    from estimator.context import ROLES
    for role in ROLES:
        me = call("GET", "/estimator-api/me", headers=session_for(role)).json()["me"]
        assert me["menu"][0]["id"] == "dashboard" and me["menu"][-1]["id"] == "help"
        assert set(me["permissions"]) == {"create_estimate", "edit_estimate", "see_margins", "edit_margins",
                                          "approve", "send_bids", "settings", "upload_plans", "quick_estimate"}


# ---------------------------------------------------------------- dashboard

def test_dashboard_counts_and_setup(call, session_for):
    _create(call, "A")
    _create(call, "B")
    d = call("GET", "/estimator-api/dashboard").json()
    assert d["total"] == 2 and d["counts"] == {"draft": 2} and len(d["recent"]) == 2
    assert d["setup"]["total"] == 10                      # owner sees the setup checklist
    assert call("GET", "/estimator-api/dashboard", headers=session_for("estimator")).json()["setup"] is None


# ---------------------------------------------------------------- live updates

def test_updates_feed_sees_changes_from_chat_and_agents(call, db, ctx_for):
    from estimator.context import RequestContext
    from estimator.estimating import service
    start = call("GET", "/estimator-api/updates").json()
    assert start["events"] == [] and isinstance(start["cursor"], int)

    service.create_estimate(db, RequestContext(agent="agent:director"), "Made by the Director")
    service.create_estimate(db, ctx_for("owner", "zed", "elsewhere"), "Another company")
    u = call("GET", f"/estimator-api/updates?since={start['cursor']}").json()
    assert [(e["actor"], e["action"]) for e in u["events"]] == [("agent:director", "estimate_created")]
    assert u["cursor"] > start["cursor"]
    assert "after_json" not in u["events"][0]                # pointers only; the page re-reads
    assert call("GET", f"/estimator-api/updates?since={u['cursor']}").json()["events"] == []


def test_updates_are_batched(call, db, ctx_for, monkeypatch):
    from estimator.api import live
    from estimator.estimating import service
    monkeypatch.setattr(live, "MAX_BATCH", 2)
    for i in range(3):
        service.create_estimate(db, ctx_for(), f"E{i}")
    u = call("GET", "/estimator-api/updates?since=0").json()
    assert len(u["events"]) == 2 and u["more"] is True
    u2 = call("GET", f"/estimator-api/updates?since={u['cursor']}").json()
    assert len(u2["events"]) == 1 and u2["more"] is False


def test_sse_message_format():
    from estimator.api import live
    msg = live.sse_message({"id": 7, "action": "estimate_created"}).decode()
    assert msg.startswith("id: 7\nevent: change\ndata: {") and msg.endswith("\n\n")
    assert live.sse_comment().decode() == ": ping\n\n"
    assert live.parse_cursor("12") == 12 and live.parse_cursor("-1") is None and live.parse_cursor("x") is None


# ---------------------------------------------------------------- failures never leak internals

def test_server_errors_are_generic(call):
    def broken():
        raise RuntimeError("secret path C:\\Users\\david\\estimator.db")
    req = router.Request("GET", "/estimator-api/dashboard", {"Host": "localhost"}, b"", "127.0.0.1")
    r = router.route(req, open_db=broken)
    assert r.status == 500 and b"secret" not in r.body and r.json()["error"] == "server_error"


# ---------------------------------------------------------------- static files

def test_app_page_and_files(call):
    r = call("GET", "/estimator")
    assert r.status == 301 and r.headers["Location"] == "/estimator/"
    page = call("GET", "/estimator/")
    assert page.status == 200 and page.content_type.startswith("text/html")
    assert b'src="app.js"' in page.body and b"<script>" not in page.body     # no inline script (CSP)
    assert "default-src 'self'" in page.headers["Content-Security-Policy"]
    # Sprint 3: framed only by its own site (the Jobs app's Estimates tab), never by another site.
    assert page.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "frame-ancestors 'self'" in page.headers["Content-Security-Policy"]
    assert call("GET", "/estimator/app.js").content_type.startswith("text/javascript")
    assert call("GET", "/estimator/app.css").content_type.startswith("text/css")
    assert call("GET", "/estimator/plans").body == page.body                # deep link falls back to the app


@pytest.mark.parametrize("path", ["/estimator/../config.py", "/estimator/..%2Fconfig.py", "/estimator/../../VERSION",
                                  "/estimator/missing.js", "/estimator/app.py"])
def test_no_files_outside_the_web_folder(call, path):
    assert call("GET", path).status == 404


def test_web_app_is_self_contained():
    """Spec: no CDN, no web fonts - it must work with no internet."""
    for f in router.WEB_DIR.iterdir():
        if f.suffix.lower() in (".png", ".ico", ".jpg"):          # Sprint 11: the app icons are pictures, not code
            continue
        text = f.read_text(encoding="utf-8").lower()
        # Sprint 7: the SVG namespace (document.createElementNS) is a name, not something downloaded.
        text = text.replace('"http://www.w3.org/2000/svg"', "")
        for bad in ("http://", "https://", "//cdn", "fonts.googleapis", "innerhtml"):
            assert bad not in text, (f.name, bad)
