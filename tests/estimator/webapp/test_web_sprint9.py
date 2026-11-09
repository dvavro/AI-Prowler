"""Coder 2 Sprint 9: schedules and legends on the plan set page - rows linked to the plans' tags, corrections that ask
first, and the symbol dictionary the plan engine reads from the legends."""
import sys
from pathlib import Path

import pytest

from estimator.api import router
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf, title_block  # noqa: E402

API = "/estimator-api"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def _page(sheet_no, title, texts, lines=()):
    return {"w": 36, "h": 24, "texts": title_block(sheet_no, title) + list(texts), "lines": list(lines)}


SCHEDULE = [(20, 2.0, 12, "DOOR SCHEDULE"), (20, 2.5, 8, "MARK"), (21.5, 2.5, 8, "SIZE"), (23, 2.5, 8, "TYPE"),
            (20, 2.8, 8, "D1"), (21.5, 2.8, 8, "3070"), (23, 2.8, 8, "A"),
            (20, 3.1, 8, "D2"), (21.5, 3.1, 8, "2868"), (23, 3.1, 8, "B"),
            (20, 3.4, 8, "D4"), (21.5, 3.4, 8, "2668"), (23, 3.4, 8, "B")]
LEGEND = [(4, 4, 12, "ELECTRICAL LEGEND"), (4, 4.5, 9, "GFI"), (5, 4.5, 9, "DUPLEX RECEPTACLE, GFCI"),
          (4, 4.8, 9, "XQ"), (5, 4.8, 9, "SPECIAL DEVICE")]
PLAN = [(4, 21, 14, "FLOOR PLAN"), (4, 21.35, 9, 'SCALE: 1/4" = 1\'-0"'),
        (6, 10, 9, "D1"), (8, 10, 9, "D2"), (10, 10, 9, "D3")]


@pytest.fixture
def plan_set(db, tmp_path, call):
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    pdf = make_pdf(tmp_path / "smith plans.pdf", [_page("A-601", "SCHEDULES", SCHEDULE),
                                                  _page("E-001", "ELECTRICAL NOTES", LEGEND),
                                                  _page("A-101", "FIRST FLOOR PLAN", PLAN)])
    ps = store.upload(db, ctx, est["id"], str(pdf), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    return ps


def test_schedules_with_rows_linked_to_plan_tags(call, plan_set):                    # C2S9-W01
    r = call("GET", f"{API}/plan-sets/{plan_set}/schedules").json()
    assert r["count"] == 1 and r["can_edit"] is True
    sc = r["schedules"][0]
    assert (sc["sheet_no"], sc["schedule_type"], sc["title"]) == ("A-601", "door", "DOOR SCHEDULE")
    links = {row["mark"]: len(row["linked_object_ids"]) for row in sc["rows"]}
    assert links == {"D1": 1, "D2": 1, "D4": 0} and sc["unlinked_marks"] == ["D4"]
    assert call("GET", f"{API}/plan-sets/{plan_set}/schedules?type=window").json()["count"] == 0


def test_correcting_a_row_asks_first_then_relinks(call, plan_set):                   # C2S9-W02
    sc = call("GET", f"{API}/plan-sets/{plan_set}/schedules").json()["schedules"][0]
    d4 = next(r for r in sc["rows"] if r["mark"] == "D4")
    ask = call("POST", f"{API}/schedule-rows/{d4['id']}", {"mark": "D3", "fields": {"SIZE": "2868"}}).json()
    assert ask["needs_confirmation"] is True and ask["question"]
    done = call("POST", f"{API}/schedule-rows/{d4['id']}", {"mark": "D3", "fields": {"SIZE": "2868"},
                                                         "confirm": True}).json()
    assert done["row"]["mark"] == "D3" and len(done["row"]["linked_object_ids"]) == 1
    assert done["row"]["fields"]["SIZE"] == "2868" and done["row"]["reviewed_by"]
    for body in ({"fields": "SIZE=1"}, {"mark": 5}):
        assert call("POST", f"{API}/schedule-rows/{d4['id']}", body).status == 400


def test_legends_and_the_symbol_dictionary(call, plan_set):                          # C2S9-W03
    r = call("GET", f"{API}/plan-sets/{plan_set}/legends").json()
    assert [(lg["title"], lg["sheet_no"], lg["discipline"]) for lg in r["legends"]] == [
        ("ELECTRICAL LEGEND", "E-001", "electrical")]
    d = {e["description"]: e for e in r["symbol_dictionary"]}
    assert d["DUPLEX RECEPTACLE, GFCI"]["item_type"] == "duplex_receptacle_gfci" and d["DUPLEX RECEPTACLE, GFCI"]["code"] == "GFI"
    assert d["SPECIAL DEVICE"]["needs_confirming"] is True and d["SPECIAL DEVICE"]["item_type"] is None
    assert "template" not in d["SPECIAL DEVICE"]                                   # file names stay on the server


def test_roles_and_errors(call, plan_set, session_for):                              # C2S9-W04
    sc = call("GET", f"{API}/plan-sets/{plan_set}/schedules").json()["schedules"][0]
    row = sc["rows"][0]["id"]
    for role in ("reviewer", "field"):                        # look, but not correct
        h = session_for(role)
        got = call("GET", f"{API}/plan-sets/{plan_set}/schedules", headers=h).json()
        assert got["can_edit"] is False and got["count"] == 1
        assert call("GET", f"{API}/plan-sets/{plan_set}/legends", headers=h).status == 200
        assert call("POST", f"{API}/schedule-rows/{row}", {"mark": "X", "confirm": True}, headers=h).status == 403
    assert call("GET", f"{API}/plan-sets/{plan_set}/schedules", headers=session_for("office")).status == 403
    assert call("GET", f"{API}/plan-sets/{plan_set}/legends", headers=session_for("owner", company="acme")).status == 404
    assert call("GET", f"{API}/plan-sets/999/schedules").status == 404
    assert call("POST", f"{API}/schedule-rows/999", {"mark": "X", "confirm": True}).status == 404
    assert call("POST", f"{API}/schedule-rows/{row}", {"mark": "X", "confirm": True}, write_header=False).status == 403


def test_plan_set_page_shows_schedules_and_legends():                                # C2S9-W05
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for needle in ("/schedules", "/legends", "/schedule-rows/", "planTables", "scheduleCard", "Correct…",
                   "Not found on the plans", "needs a person", "symbol_dictionary"):
        assert needle in js, needle
    assert "innerHTML" not in js and "setAttribute(\"style\"" not in js
