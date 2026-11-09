"""Coder 2 Sprint 17: Reports (win/loss, takeoff, plan revisions overlay, actuals, exports), Settings
(owner only), and the full Price Book (history, markups, import column mapping).

Every money or settings change asks first, exactly like the MCP tools; costs are only shown to the
roles that open the screen. The revision overlay is Coder 1's plan_compare_revisions behind the
Reports screen; the web app draws it over the sheets (reports.js).
"""
from datetime import date
from pathlib import Path

import pytest

from estimator.api import nav
from estimator.context import personal_context
from estimator.drawing_model import store
from estimator.estimating import quick, service
from estimator.learning import history
from estimator.modules.registry import ModuleRegistry
from estimator.takeoff import measurements as m

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
HELP = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "help" / "guides"

CTX = personal_context()
REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
KEY = "pw_driveway_sqft"
CSV = "Item Code,Description,Unit,Unit Price\npw_driveway_sqft,Driveway,sqft,0.19\nbogus,Nothing like this,ea,5\n"
TOTALS = {"unchanged": 6, "moved": 1, "changed": 1, "removed": 1, "added": 3}


def _roof(db, status="won", answers=ROOF):
    e = service.create_estimate(db, CTX, "roof")
    e = quick.answer(db, CTX, e["id"], "roofing", answers, e["rev"], REG)
    if status != "draft":
        e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
        if status != "approved":
            e = service.set_status(db, CTX, e["id"], e["rev"], status)
    return service.get_estimate(db, CTX, e["id"])


def _line(est, key):
    return next(ln for s in est["sections"] for ln in s["lines"] if ln["price_key"] == key)


def pt(x, y):
    return {"type": "point", "points": [[x, y]]}


def poly(x0, y0, x1, y1):
    return {"type": "polygon", "points": [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]}


def PLAN(rev="A", image=None):
    """Rev A, or Rev B with: outlet 3 moved, slab bigger, the GFI removed, a new floor box, D1's size changed,
    a revision cloud, and a new sheet."""
    b = rev == "B"
    outlets = [{"viewport": "plan", "kind": "symbol", "label": "OUTLET", "block_name": "DUPLEX", "source": "cad",
                "geometry": pt(12 if (b and i == 3) else 2 + i, 3)} for i in range(5)]
    objs = outlets + [
        {"viewport": "plan", "kind": "polygon", "label": "SLAB", "source": "cad",
         "geometry": poly(1, 1, 7 if b else 6, 5)},                               # 20 x 16 ft -> 24 x 16 ft
        {"viewport": "plan", "kind": "polygon", "label": "PORCH", "source": "cad", "geometry": poly(8, 1, 10, 5)},
        {"viewport": "plan", "kind": "opening", "tag": "D1", "label": "door", "source": "cad", "geometry": pt(10, 12)},
    ]
    if not b:
        objs.append({"viewport": "plan", "kind": "symbol", "label": "GFI", "block_name": "GFI", "source": "cad",
                     "geometry": pt(5, 8)})
    else:
        objs += [{"viewport": "plan", "kind": "symbol", "label": "FLOOR BOX", "block_name": "FBOX", "source": "cad",
                  "geometry": pt(15, 15)},
                 {"viewport": "plan", "kind": "polyline", "label": "REV CLOUD", "layer": "REVISION", "source": "cad",
                  "geometry": {"type": "polyline", "points": [[11, 2], [13, 2], [13, 4]]}}]
    sheets = [{"page_no": 1, "sheet_no": "E-101", "title": "POWER PLAN", "discipline": "electrical",
               "units": "paper_in", "width": 36, "height": 24, "image_path": image,
               "viewports": [{"key": "plan", "label": "POWER PLAN", "scale_note": "1/4\" = 1'-0\""}],
               "objects": objs,
               "schedules": [{"schedule_type": "door", "rows": [
                   {"mark": "D1", "fields": {"size": "3'-0\" x 7'-0\"" if b else "3'-0\" x 6'-8\""}}]}]}]
    if b:
        sheets.append({"page_no": 2, "sheet_no": "E-102", "title": "LIGHTING", "discipline": "electrical",
                       "units": "paper_in", "width": 36, "height": 24,
                       "viewports": [{"key": "p", "label": "LIGHTING", "scale_note": "1/4\" = 1'-0\""}],
                       "objects": [{"viewport": "p", "kind": "symbol", "label": "CAN", "source": "cad",
                                    "geometry": pt(3, 3)}]})
    return {"sheets": sheets}


def _pdf(path: Path, pages: int, note: str = "") -> str:
    body = b"".join(b"%d 0 obj << /Type /Page >> endobj\n" % (i + 3) for i in range(pages))
    path.write_bytes(b"%PDF-1.7\n1 0 obj << /Type /Pages >> endobj\n" + body + note.encode() + b"\n%%EOF\n")
    return str(path)


def _ids(conn, ctx, ps):
    out = {}
    for o in store.objects(conn, ctx, plan_set_id=ps)["objects"]:
        out.setdefault(o["label"] if o["kind"] != "opening" else o["tag"], []).append(o["id"])
    return out


@pytest.fixture
def revs(db, tmp_path):
    est = service.create_estimate(db, CTX, "Lopez remodel")["id"]
    a = store.upload(db, CTX, est, _pdf(tmp_path / "revA.pdf", 1, "A"), confirm=True)["plan_set_id"]
    store.save_results(db, CTX, a, PLAN("A"), "fake")
    o = _ids(db, CTX, a)
    keep = m.propose(db, CTX, est, "roofing", o["OUTLET"][:3], kind="count", label="outlets 1-3",
                     confirm=True)["proposed"][0]["id"]
    moved = m.propose(db, CTX, est, "roofing", o["OUTLET"][2:5], kind="count", label="outlets 3-5",
                      confirm=True)["proposed"][0]["id"]
    slab = m.propose(db, CTX, est, "roofing", o["SLAB"], feeds="roof_area_sqft", confirm=True)["proposed"][0]["id"]
    gfi = m.propose(db, CTX, est, "roofing", o["GFI"], kind="count", label="gfi", confirm=True)["proposed"][0]["id"]
    porch = m.propose(db, CTX, est, "roofing", o["PORCH"], kind="area", label="porch", confirm=True)["proposed"][0]["id"]
    typed = m.manual(db, CTX, est, "roofing", feeds="ridge_lf", qty="20", unit="lf", confirm=True)["measurement"]["id"]
    m.confirm_measurements(db, CTX, [keep, slab, porch], confirm=True)
    b = store.upload(db, CTX, est, _pdf(tmp_path / "revB.pdf", 2, "B"), supersedes_plan_set_id=a,
                     confirm=True)["plan_set_id"]
    store.save_results(db, CTX, b, PLAN("B"), "fake")
    db.commit()
    return {"est": est, "a": a, "b": b, "o": o, "keep": keep, "moved": moved, "slab": slab, "gfi": gfi,
            "porch": porch, "typed": typed}


# ------------------------------------------------------------------ win / loss

def test_summary_starts_empty(call):                                            # C2S17-W01
    b = call("GET", f"{API}/reports/summary").json()
    assert b["by_status"] == {} and b["total"] == 0 and b["won"] == 0 and b["lost"] == 0
    assert b["win_rate"] is None and b["won_cents"] == 0 and b["lost_cents"] == 0
    assert b["open_bids_cents"] == 0 and b["by_trade"] == [] and len(b["by_month"]) == 12
    assert "No won or lost estimates yet" in b["note"]
    assert all(set(m) == {"month", "won", "lost", "won_cents", "lost_cents", "win_rate"}
               for m in b["by_month"])


def test_summary_counts_won_lost_and_approved(db, call):                         # C2S17-W02
    _roof(db, "won")
    _roof(db, "lost")
    _roof(db, "approved")
    db.commit()
    b = call("GET", f"{API}/reports/summary").json()
    assert b["by_status"] == {"won": 1, "lost": 1, "approved": 1} and b["total"] == 3
    assert (b["won"], b["lost"], b["win_rate"]) == (1, 1, 0.5) and b["note"] is None
    assert 0 < b["won_cents"] == b["lost_cents"] and b["open_bids_cents"] == 0
    trade = b["by_trade"]
    assert len(trade) == 1 and trade[0]["module_id"] == "roofing"
    assert (trade[0]["won"], trade[0]["lost"]) == (1, 1) and trade[0]["win_rate"] == 0.5
    month = next(x for x in b["by_month"] if x["month"] == date.today().strftime("%Y-%m"))
    assert (month["won"], month["lost"], month["win_rate"]) == (1, 1, 0.5)


def test_summary_months_window(call):                                           # C2S17-W03
    assert len(call("GET", f"{API}/reports/summary?months=3").json()["by_month"]) == 3
    assert len(call("GET", f"{API}/reports/summary?months=60").json()["by_month"]) == 60
    for bad in ("0", "61", "abc"):
        r = call("GET", f"{API}/reports/summary?months={bad}")
        assert r.status == 400, bad


# ------------------------------------------------------------------ takeoff report

def test_takeoff_report_lists_measurements_by_trade(db, call, revs):            # C2S17-W04
    b = call("GET", f"{API}/reports/takeoff/{revs['est']}").json()
    assert b["estimate_id"] == revs["est"] and b["estimate_title"] == "Lopez remodel"
    assert b["status"] == "draft" and b["rejected"] == []
    assert b["totals"] == {"measurements": 6, "approved": 3, "waiting": 3,
                           "remeasure": 0, "raster": 0, "rejected": 0}
    assert len(b["trades"]) == 1
    t = b["trades"][0]
    assert t["module_id"] == "roofing" and (t["approved"], t["waiting"]) == (3, 3)
    assert len(t["measurements"]) == 6 and len(t["questions"]) == 6
    outlets = next(q for q in t["questions"] if q["label"] == "outlets 1-3")
    assert outlets["approved_qty"] == 3.0 and outlets["waiting_qty"] == 0.0
    slab = next(q for q in t["questions"] if q["feeds"] == "roof_area_sqft")
    assert slab["approved_qty"] > 0
    assert "3 measurement(s) still wait for approval" in " ".join(b["notes"])


def test_takeoff_report_unknown_estimate_is_404(call):                          # C2S17-W05
    r = call("GET", f"{API}/reports/takeoff/999999")
    assert r.status == 404 and r.json()["error"] == "not_found"


# ------------------------------------------------------------------ actuals

def test_actuals_open_to_the_roles_that_see_margins(call, session_for):         # C2S17-W06
    for h in (None, session_for("reviewer"), session_for("office")):
        b = call("GET", f"{API}/reports/actuals", headers=h).json()
        assert b["jobs_with_actuals"] == 0 and "No job costs recorded yet" in b["note"]


def test_actuals_refuses_field_and_a_role_without_margins(call, session_for, monkeypatch):  # C2S17-W07
    r = call("GET", f"{API}/reports/actuals", headers=session_for("field"))
    assert r.status == 403 and "can't open reports" in r.json()["message"]
    real = nav.permissions
    monkeypatch.setattr(nav, "permissions", lambda role: {**real(role), "see_margins": False})
    r = call("GET", f"{API}/reports/actuals", headers=session_for("reviewer"))
    assert r.status == 403 and "can't see costs" in r.json()["message"]


def test_actuals_for_one_estimate(db, call):                                    # C2S17-W08
    est = _roof(db, "won")
    db.commit()
    b = call("GET", f"{API}/reports/actuals?estimate_id={est['id']}").json()
    assert b["estimate_id"] == est["id"] and b["title"] == "roof"
    assert isinstance(b["lines"], list) and len(b["lines"]) > 0
    assert b["flagged"] == 0


# ------------------------------------------------------------------ export and files

def test_export_csv_downloads(call):                                            # C2S17-W09
    done = call("POST", f"{API}/reports/export", {"format": "csv"}).json()
    assert done["file"].endswith(".csv") and done["format"] == "csv"
    assert done["url"] == f"{API}/reports/files/{done['file']}"
    r = call("GET", done["url"])
    assert r.status == 200 and r.content_type.startswith("text/csv")
    assert "attachment" in r.headers.get("Content-Disposition", "")
    assert done["file"] in r.headers["Content-Disposition"]
    assert len(r.body) > 0


def test_export_bad_format(call):                                               # C2S17-W10
    r = call("POST", f"{API}/reports/export", {"format": "pdf"})
    assert r.status == 400 and "format must be csv or xlsx" in r.json()["message"]


def test_export_files_refuse_traversal(call):                                   # C2S17-W11
    for name in ("..", "..%2F..%2Fsecret.csv", "nope.csv", "x.txt", ".csv"):
        assert call("GET", f"{API}/reports/files/{name}").status == 404, name
    r = call("GET", f"{API}/reports/files/nope.csv")
    assert r.json()["error"] == "not_found" and "no such export" in r.json()["message"]


def test_reports_posts_need_the_app_header(call):                               # C2S17-W12
    r = call("POST", f"{API}/reports/export", {"format": "csv"}, write_header=False)
    assert r.status == 403 and r.json()["error"] == "csrf"


# ------------------------------------------------------------------ plan revisions

def test_revisions_list_shows_uncompared_set(db, call, revs):                   # C2S17-W13
    b = call("GET", f"{API}/reports/revisions").json()
    assert b["reports"] == [] and b["can_compare"] is True
    assert len(b["not_compared"]) == 1
    w = b["not_compared"][0]
    assert w["new_plan_set_id"] == revs["b"] and w["old_plan_set_id"] == revs["a"]
    assert w["estimate_id"] == revs["est"] and w["estimate_title"] == "Lopez remodel"
    assert (w["from_rev"], w["to_rev"]) == ("A", "B") and w["ready"] is True
    assert w["why_not"] is None and w["name"] == "revB.pdf"
    mine = call("GET", f"{API}/reports/revisions?estimate_id={revs['est']}").json()
    assert len(mine["not_compared"]) == 1
    other = call("GET", f"{API}/reports/revisions?estimate_id=999999").json()
    assert other["reports"] == [] and other["not_compared"] == []


def test_revision_compare_asks_first_then_saves(db, call, revs):                # C2S17-W14
    ask = call("POST", f"{API}/reports/revisions", {"new_plan_set_id": revs["b"]}).json()
    assert ask["needs_confirmation"] is True and "confirm=true" not in ask["question"]
    assert "Save the revision report" in ask["question"]
    assert ask["totals"] == TOTALS and ask["carry"] == 2 and ask["flag"] == 3
    assert call("GET", f"{API}/reports/revisions").json()["reports"] == []   # nothing saved yet
    done = call("POST", f"{API}/reports/revisions",
                {"new_plan_set_id": revs["b"], "confirm": True}).json()
    assert isinstance(done["report_id"], int) and done["report_id"] > 0
    assert done["old_plan_set_id"] == revs["a"] and done["new_plan_set_id"] == revs["b"]
    assert done["totals"] == TOTALS
    listed = call("GET", f"{API}/reports/revisions").json()
    assert len(listed["reports"]) == 1 and listed["not_compared"] == []
    rep = listed["reports"][0]
    assert rep["report_id"] == done["report_id"] and rep["flagged"] == 3 and rep["carried"] == 2
    assert "Rev 1" in rep["said"] and "3 added" in rep["said"]
    detail = call("GET", f"{API}/reports/revisions/{done['report_id']}").json()
    assert (detail["from_rev"], detail["to_rev"]) == ("A", "B")
    assert detail["old_name"] == "revA.pdf" and detail["new_name"] == "revB.pdf"
    assert detail["totals"] == TOTALS and len(detail["flagged"]) == 3
    assert all(f["still_flagged"] is True and isinstance(f["why"], list) for f in detail["flagged"])
    sheet = detail["sheets"][0]
    assert sheet["sheet_no"] == "E-101" and sheet["old_sheet"]["width"] == "36"
    assert sheet["new_sheet"]["width"] == "36" and sheet["moved"] == 1
    assert sheet["removed"] == 1 and sheet["added"] == 2
    takeoff = call("GET", f"{API}/reports/takeoff/{revs['est']}").json()
    assert takeoff["totals"]["remeasure"] == 3


def test_revision_compare_bad_input(call):                                      # C2S17-W15
    r = call("POST", f"{API}/reports/revisions", {})
    assert r.status == 400 and "give the new plan set" in r.json()["message"]
    r = call("POST", f"{API}/reports/revisions", {"new_plan_set_id": 999999})
    assert r.status == 404
    r = call("GET", f"{API}/reports/revisions/999999")
    assert r.status == 404 and "not found" in r.json()["message"]


def test_revision_compare_is_owner_or_estimator_only(db, call, revs, session_for):  # C2S17-W16
    for role in ("reviewer", "field"):
        r = call("POST", f"{API}/reports/revisions", {"new_plan_set_id": revs["b"]},
                 headers=session_for(role))
        assert r.status == 403 and r.json()["error"] == "permission_denied", role
    ask = call("POST", f"{API}/reports/revisions", {"new_plan_set_id": revs["b"]},
               headers=session_for("estimator")).json()
    assert ask["needs_confirmation"] is True and ask["totals"] == TOTALS


# ------------------------------------------------------------------ settings

def test_settings_reads_everything(call):                                       # C2S17-W17
    s = call("GET", f"{API}/settings").json()
    assert set(s["company_profile"]) == {"name", "address", "phone", "license_no", "logo_path"}
    assert s["tax"] == {"tax_pct": "0", "taxable_kinds": ["material"], "tax_base": "cost"}
    assert s["markups"]["overhead_pct"] == "0" and s["markups"]["profit_pct"] == "0"
    assert s["markups"]["labor_burden_pct"] == "0" and s["markups"]["minimum_charge_cents"] is None
    assert s["markups"]["round_to_cents"] is None
    assert isinstance(s["labor_rates"], list) and s["labor_rates"]
    assert all(p["kind"] == "labor" for p in s["labor_rates"])
    assert s["bid_template"]["price_detail"] == "lines" and "lines" in s["bid_template"]["price_details"]
    assert set(s["approvals"]) == {"review_required_over_cents", "quick_send_limit_cents",
                                   "follow_up_days", "review_reminder_days", "auto_expire_bids"}
    assert isinstance(s["ai_privacy"], dict) and isinstance(s["roles"], list) and len(s["roles"]) == 5
    assert "Settings" in next(r["screens"] for r in s["roles"] if r["role"] == "owner")
    assert isinstance(s["roles_note"], str) and s["mode"] == "personal"
    assert s["backups"] == [] and s["backup_count"] == 0
    assert isinstance(s["samples_in_use"], int) and s["setup"]["done"] <= s["setup"]["total"]
    assert s["kinds"] == ["material", "labor", "equipment", "sub", "other"]


@pytest.mark.parametrize("role", ["reviewer", "estimator", "office", "field"])
def test_settings_is_owner_only(call, session_for, role):                       # C2S17-W18
    h = session_for(role)
    r = call("GET", f"{API}/settings", headers=h)
    assert r.status == 403 and "only the owner can open Settings" in r.json()["message"]
    r = call("POST", f"{API}/settings/tax", {"data": {"tax_pct": "7"}}, headers=h)
    assert r.status == 403
    me = call("GET", f"{API}/me", headers=h).json()["me"]
    assert "settings" not in [s["id"] for s in me["menu"]]
    assert me["permissions"]["settings"] is False


def test_settings_company_profile_asks_first_then_saves(call):                  # C2S17-W19
    body = {"data": {"name": "Acme Estimating LLC", "phone": "555-0100"}}
    ask = call("POST", f"{API}/settings/company_profile", body).json()
    assert ask["needs_confirmation"] is True and "confirm=true" not in ask["question"]
    assert ask["changes"] == ["name: (blank) → Acme Estimating LLC",
                              "phone: (blank) → 555-0100"]
    assert call("GET", f"{API}/settings").json()["company_profile"]["name"] is None
    done = call("POST", f"{API}/settings/company_profile", {**body, "confirm": True}).json()
    assert done["saved"] is True and done["section"] == "company_profile"
    prof = done["settings"]["company_profile"]
    assert prof["name"] == "Acme Estimating LLC" and prof["phone"] == "555-0100"


def test_settings_tax_asks_first_then_saves(call):                              # C2S17-W20
    ask = call("POST", f"{API}/settings/tax", {"data": {"tax_pct": "7"}}).json()
    assert ask["needs_confirmation"] is True
    assert ask["changes"] == ["tax: 0 → 7"]
    done = call("POST", f"{API}/settings/tax", {"data": {"tax_pct": "7"}, "confirm": True}).json()
    assert done["saved"] is True and done["settings"]["tax"]["tax_pct"] == "7"
    for body, words in (({"tax_pct": "101"}, "between 0 and 100"),
                        ({"tax_pct": "lots"}, "must be a percent"),
                        ({"tax_base": "mars"}, "cost or price"),
                        ({"taxable_kinds": ["gold"]}, "taxable kinds are among")):
        r = call("POST", f"{API}/settings/tax", {"data": body})
        assert r.status == 400 and words in r.json()["message"], body


def test_settings_unknown_section_and_no_change(call):                          # C2S17-W21
    r = call("POST", f"{API}/settings/nope", {"data": {}})
    assert r.status == 404 and "no settings section 'nope'" in r.json()["message"]
    for body in ({"data": {}}, {"data": {"tax_pct": "0"}}):
        r = call("POST", f"{API}/settings/tax", body)
        assert r.status == 400 and "nothing changed" in r.json()["message"], body


def test_settings_backup_asks_first(call):                                     # C2S17-W22
    ask = call("POST", f"{API}/settings/backup", {}).json()
    assert ask["needs_confirmation"] is True and ask.get("changes") == []
    assert ask["question"] == "Back up the Estimator database now? The newest 30 backups are kept."


def test_settings_audit_lists_changes(db, call):                                # C2S17-W23
    service.create_estimate(db, CTX, "Audit roof")
    db.commit()
    b = call("GET", f"{API}/settings/audit").json()
    assert b["count"] == 1 and b["actions"] == ["estimate_created"]
    ev = b["events"][0]
    assert ev["action"] == "estimate_created" and ev["estimate_title"] == "Audit roof"
    assert ev["actor"] and ev["at"] and "Audit roof" in (ev["detail"] or "")
    assert len(call("GET", f"{API}/settings/audit?limit=1").json()["events"]) == 1
    assert call("GET", f"{API}/settings/audit?action=prices_changed").json()["count"] == 0
    assert call("GET", f"{API}/settings/audit?limit=abc").status == 400
    assert call("GET", f"{API}/settings/audit?estimate_id=abc").status == 400


def test_settings_labor_rate_round_trip(call):                                  # C2S17-W24
    labor = call("GET", f"{API}/settings").json()["labor_rates"]
    assert labor
    key, cur = labor[0]["price_key"], labor[0]["cost_cents"]
    new = f"{(cur + 100) / 100:.2f}"
    ask = call("POST", f"{API}/settings/labor_rates", {"data": {"prices": {key: new}}}).json()
    assert ask["needs_confirmation"] is True
    assert ask["changes"][0]["price_key"] == key and ask["changes"][0]["new_cents"] == cur + 100
    done = call("POST", f"{API}/settings/labor_rates",
                {"data": {"prices": {key: new}}, "confirm": True}).json()
    assert done["section"] == "labor_rates" and done["changed"][0]["new_cents"] == cur + 100
    after = call("GET", f"{API}/settings").json()["labor_rates"]
    assert next(p for p in after if p["price_key"] == key)["cost_cents"] == cur + 100
    r = call("POST", f"{API}/settings/labor_rates", {"data": {"prices": {KEY: "1"}}})
    assert r.status == 400 and "these aren't labor rates" in r.json()["message"]


# ------------------------------------------------------------------ full price book

def test_price_history_before_and_after_a_change(call):                         # C2S17-W25
    b = call("GET", f"{API}/price-book/history/{KEY}").json()
    assert b["price_key"] == KEY and b["history"] == [] and b["jobs"] is None
    assert b["note"] == "Not saved yet: the trade's sample price is used until you set your own."
    done = call("POST", f"{API}/price-book", {"prices": {KEY: "0.25"}, "confirm": True}).json()
    assert done["changed"][0]["new_cents"] == 25
    b = call("GET", f"{API}/price-book/history/{KEY}").json()
    assert b["note"] is None and len(b["history"]) == 1
    assert b["history"][0]["cost_cents"] == 25 and b["history"][0]["sample"] is False
    r = call("GET", f"{API}/price-book/history/no_such_price")
    assert r.status == 404 and "no price called" in r.json()["message"]


def test_price_book_markups_follow_settings(call, session_for):                 # C2S17-W26
    b = call("GET", f"{API}/price-book/markups").json()
    assert b["overhead_pct"] == "0" and b["profit_pct"] == "0"
    assert b["labor_burden_pct"] == "0" and b["tax_pct"] == "0"
    assert b["taxable_kinds"] == ["material"] and b["tax_base"] == "cost"
    assert b["minimum_charge_cents"] is None and b["can_change"] is True
    est = call("GET", f"{API}/price-book/markups", headers=session_for("estimator")).json()
    assert est["can_change"] is False
    assert call("GET", f"{API}/price-book/markups", headers=session_for("field")).status == 403
    call("POST", f"{API}/settings/tax", {"data": {"tax_pct": "7"}, "confirm": True})
    assert call("GET", f"{API}/price-book/markups").json()["tax_pct"] == "7"


def test_import_preview_guesses_the_columns(call):                              # C2S17-W27
    b = call("POST", f"{API}/price-book/import/preview", {"csv_text": CSV}).json()
    assert b["columns"] == ["Item Code", "Description", "Unit", "Unit Price"]
    assert b["fields"] == ["price_key", "cost", "description", "unit", "kind", "supplier"]
    assert b["mapping"]["price_key"] == "Item Code" and b["mapping"]["cost"] == "Unit Price"
    assert b["mapping"]["description"] == "Description" and b["mapping"]["unit"] == "Unit"
    assert b["rows"][0] == {"Item Code": "pw_driveway_sqft", "Description": "Driveway",
                            "Unit": "sqft", "Unit Price": "0.19"}
    assert b["row_count"] == 2
    r = call("POST", f"{API}/price-book/import/preview", {"csv_text": "  "})
    assert r.status == 400 and "paste the price list" in r.json()["message"]


def test_import_preview_mapping_round_trip(call):                               # C2S17-W28
    preview = call("POST", f"{API}/price-book/import/preview", {"csv_text": CSV}).json()
    ask = call("POST", f"{API}/price-book/import",
               {"csv_text": CSV, "mapping": preview["mapping"]}).json()
    assert ask["needs_confirmation"] is True and ask["updates"] == 1 and ask["skipped"] == 1
    done = call("POST", f"{API}/price-book/import",
                {"csv_text": CSV, "mapping": preview["mapping"], "confirm": True}).json()
    assert done["saved"] == 1
    book = call("GET", f"{API}/price-book?module_id=pressure_washing").json()
    p = next(x for x in book["prices"] if x["price_key"] == KEY)
    assert p["cost_cents"] == 19 and p["sample"] is False


def test_price_history_shows_what_jobs_paid(db, call):                          # C2S17-W29
    est = _roof(db)
    shingles = _line(est, "rf_arch_sq")
    history.record_actuals(db, CTX, est["id"], [
        {"line_id": shingles["id"], "cost": "3,300.00", "quantity": "24"},
        {"price_key": "rf_permit_ea", "cost": "$350"},
        {"kind": "labor", "cost": "3500", "hours": "48"},
        {"total": "8600"}], note="Garcia roof")
    db.commit()
    b = call("GET", f"{API}/price-book/history/rf_arch_sq").json()
    assert b["jobs"] is not None and b["jobs"]["jobs_with_actuals"]
    assert isinstance(b["suggestions"], list)


# ------------------------------------------------------------------ menu, pages, guides

def test_reports_and_settings_are_ready_in_the_menu(call, session_for):         # C2S17-W30
    assert next(s for s in nav.SCREENS if s["id"] == "reports")["status"] == "ready"
    assert next(s for s in nav.SCREENS if s["id"] == "reports")["sprint"] == 17
    assert next(s for s in nav.SCREENS if s["id"] == "settings")["status"] == "ready"
    assert next(s for s in nav.PAGES if s["id"] == "revision")["from"] == "reports"
    assert nav.can_open("office", "reports") and not nav.can_open("field", "reports")
    assert nav.can_open("owner", "settings") and not nav.can_open("estimator", "settings")
    me = call("GET", f"{API}/me").json()["me"]
    by_id = {s["id"]: s for s in me["menu"]}
    assert by_id["reports"]["status"] == "ready" and by_id["settings"]["status"] == "ready"
    for role in ("estimator", "reviewer", "office"):
        ids = [s["id"] for s in call("GET", f"{API}/me", headers=session_for(role)).json()["me"]["menu"]]
        assert "reports" in ids and "settings" not in ids, role
    field_ids = [s["id"] for s in call("GET", f"{API}/me", headers=session_for("field")).json()["me"]["menu"]]
    assert "reports" not in field_ids and "settings" not in field_ids


def test_reports_settings_and_revision_pages_are_wired():                       # C2S17-W31
    reports = (WEB / "reports.js").read_text(encoding="utf-8")
    for part in ("SCREENS.reports = renderReports", "PAGES.revision = renderRevision",
                 "rev-overlay", '"rev-svg"', "No revision reports yet.",
                 "/reports/revisions/", "/reports/summary", "/reports/takeoff/",
                 "/reports/actuals", "/reports/export"):
        assert part in reports, part
    settings = (WEB / "settings.js").read_text(encoding="utf-8")
    for part in ("SCREENS.settings = renderSettings", "/settings/audit", "/settings/backup",
                 '"company_profile"'):
        assert part in settings, part
    app = (WEB / "app.js").read_text(encoding="utf-8")
    for part in ('page: "revision"', '"/price-book/history/"', '"/price-book/import/preview"',
                 '"/price-book/markups"', '"#/revisions/"'):
        assert part in app, part
    index = (WEB / "index.html").read_text(encoding="utf-8")
    assert '<script src="reports.js"' in index and '<script src="settings.js"' in index


def test_guides_cover_reports_settings_and_revisions():                         # C2S17-W32
    reports = (HELP / "use_reports.md").read_text(encoding="utf-8")
    assert "# Use the reports" in reports and "Win / loss" in reports
    assert "Takeoff report" in reports and "Plan revisions" in reports
    settings = (HELP / "change_your_settings.md").read_text(encoding="utf-8")
    assert "# Change your settings" in settings and "owner only" in settings
    assert "Back up now" in settings and "Audit log" in settings
    revisions = (HELP / "compare_plan_revisions.md").read_text(encoding="utf-8")
    assert "# Compare plan revisions" in revisions and "green boxes are new" in revisions
    assert "Owners and estimators compare" in revisions
