"""LLM takeoff through the API: which agent starts, the fail-fast cases, and rerun.

The runner processes are faked (their commands are recorded, nothing runs) and the
provider is faked - no real LLM calls, no token cost. The sheet has no slab outline
(the NSB situation): an empty calibrated viewport, so geometry finds nothing.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from estimator import config
from estimator.agents import providers, roles
from estimator.api import autorun_api
from estimator.context import personal_context
from estimator.estimating import service

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
CTX = personal_context()
NOW = "2026-11-12T10:00:00+00:00"
PAPER_W = 547 / 84.3225      # 45'-7" at the live slab's scale
PAPER_H = 559 / 84.3225      # 46'-7"


def _walls(db, vp, sheet, rects):
    for (x1, y1, x2, y2) in rects.values():
        for (ax, ay), (bx, by) in [((x1, y1), (x2, y1)), ((x2, y1), (x2, y2)),
                                   ((x2, y2), (x1, y2)), ((x1, y2), (x1, y1))]:
            db.execute("INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind,"
                       " geometry_json, source) VALUES ('default', ?, ?, 'wall', ?, 'cad')",
                       (sheet, vp, json.dumps({"type": "line", "points": [[ax, ay], [bx, by]]})))


class _FakePopen:
    calls = []

    def __init__(self, cmd, **kw):
        _FakePopen.calls.append((cmd, kw))
        self.pid = 1234
        self.returncode = None

    def poll(self):
        return None


@pytest.fixture
def agent_spawns(monkeypatch):
    _FakePopen.calls.clear()
    monkeypatch.setattr(autorun_api, "_playwright_available", lambda: True)
    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    return _FakePopen


class _FakeProvider:
    """Ready (or not) on demand. The API never calls the LLM itself - the runner does."""

    def __init__(self):
        self.keys = {"claude_api": True, "grok_api": True}

    def ready(self, provider):
        return (True, "") if self.keys.get(provider) else (False, "no API key saved")

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3"}[provider]

    def ask(self, *a, **kw):
        raise AssertionError("the API must not call the LLM")

    def ask_vision(self, *a, **kw):
        raise AssertionError("the API must not call the LLM")

    def cost(self, model, usage):
        return 0.0


@pytest.fixture
def fake():
    f = _FakeProvider()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


@pytest.fixture
def empty(db):
    """An estimate with one sheet and one calibrated viewport - and no slab outline."""
    est = service.create_estimate(db, CTX, "Shed slab")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    sheet = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                       " VALUES ('default', ?, 1, 'S-1', 'FOUNDATION PLAN')", (ps,)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Foundation plan', '84.3225', 0)", (sheet,)).lastrowid
    return {"est": est, "sheet": sheet, "vp": vp}


@pytest.fixture
def slab(empty, db):
    """The empty viewport, plus a drawn slab rectangle geometry finds."""
    _walls(db, empty["vp"], empty["sheet"], {"slab": (2, 2, 2 + PAPER_W, 2 + PAPER_H)})
    return empty


def _body(seed):
    return {"estimate_id": seed["est"], "sheet_id": seed["sheet"], "viewport_id": seed["vp"],
            "module_id": "concrete"}


def _on(db, **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api", **extra}, confirm=True)


def _measurement(db, est, sheet, vp, **kw):
    vals = {"module_id": "concrete", "kind": "area", "qty": "2123.42", "unit": "sqft",
            "proposed_by": "llm-takeoff", "status": "proposed", "calc": None, "label": "Slab (AI)"}
    vals.update(kw)
    return db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, sheet_id, viewport_id, kind, label,"
        " qty, unit, source_object_ids, calc_json, method, status, proposed_by, created_at, updated_at)"
        " VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, 'ai', ?, ?, ?, ?)",
        (est, vals["module_id"], sheet, vp, vals["kind"], vals["label"], vals["qty"], vals["unit"],
         json.dumps(vals["calc"]) if vals["calc"] is not None else None,
         vals["status"], vals["proposed_by"], NOW, NOW)).lastrowid


# ---------------------------------------------------------------- which agent starts

def test_no_candidates_llm_on_starts_the_llm_runner(call, db, empty, agent_spawns, fake):
    _on(db)
    r = call("POST", f"{API}/auto-run", _body(empty))
    assert r.status == 200, r.json()
    assert r.json()["status"] == "running"
    assert len(agent_spawns.calls) == 1
    cmd, kw = agent_spawns.calls[0]
    assert cmd[0] == sys.executable
    assert cmd[1:3] == ["-m", "estimator.agents.llm_takeoff_runner"]
    assert "--base" not in cmd and "--headed" not in cmd          # no browser, no HTTP
    assert cmd[cmd.index("--db") + 1] == str(config.db_path())
    assert cmd[cmd.index("--run-id") + 1] == str(r.json()["run_id"])
    assert "creationflags" in kw or "start_new_session" in kw     # detached from the server
    assert kw["stdout"] == subprocess.DEVNULL


def test_no_candidates_llm_off_fails_fast_saying_the_ai_did_not_run(call, db, empty, agent_spawns, fake):
    """The NSB situation: no outline and LLM takeoff off - the run fails at once saying the AI
    did not run (it used to start the geometric agent, which failed with 'no slab outline'
    and looked like the AI had run and failed). Nothing spawns: no browser, no LLM, no cost."""
    r = call("POST", f"{API}/auto-run", _body(empty))
    assert r.status == 200, r.json()
    assert r.json()["status"] == "failed"
    assert "did not run" in r.json()["error"] and "AI measuring is off" in r.json()["error"]
    assert "AI agents" in r.json()["error"]                     # where to turn it on
    assert agent_spawns.calls == []
    row = db.execute("SELECT status, error FROM auto_runs WHERE id = ?", (r.json()["run_id"],)).fetchone()
    assert row["status"] == "failed" and "did not run" in row["error"]


def test_candidates_llm_on_sends_the_sheet_to_the_ai(call, db, slab, agent_spawns, fake):
    """2026-11-15 (David): AI Auto Measure/Count - with LLM takeoff on and its key ready, the sheet goes to the AI (after
    calibrating) even when the drawing has outlines."""
    _on(db)
    r = call("POST", f"{API}/auto-run", _body(slab))
    assert r.status == 200, r.json()
    assert r.json()["status"] == "running"
    assert len(agent_spawns.calls) == 1
    assert agent_spawns.calls[0][0][1:3] == ["-m", "estimator.agents.llm_takeoff_runner"]


def test_candidates_llm_off_uses_the_drawing(call, db, slab, agent_spawns, fake):
    r = call("POST", f"{API}/auto-run", _body(slab))
    assert r.status == 200, r.json()
    assert r.json()["status"] == "running"
    assert agent_spawns.calls[0][0][1:3] == ["-m", "estimator.agents.concrete_autorun"]


def test_llm_on_but_no_key_fails_fast_without_spawning(call, db, empty, agent_spawns, fake):
    fake.keys["claude_api"] = False
    _on(db)
    r = call("POST", f"{API}/auto-run", _body(empty))
    assert r.status == 200, r.json()
    assert r.json()["status"] == "failed"
    assert "isn't ready" in r.json()["error"] and "no API key" in r.json()["error"]
    assert agent_spawns.calls == []
    row = db.execute("SELECT status, error FROM auto_runs WHERE id = ?", (r.json()["run_id"],)).fetchone()
    assert row["status"] == "failed" and "isn't ready" in row["error"]


def test_llm_on_but_budget_used_up_fails_fast_without_spawning(call, db, empty, agent_spawns, fake):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    r = call("POST", f"{API}/auto-run", _body(empty))
    assert r.status == 200, r.json()
    assert r.json()["status"] == "failed" and "budget" in r.json()["error"]
    assert agent_spawns.calls == []


# ---------------------------------------------------------------- candidates endpoint reports the fallback

def test_candidates_endpoint_reports_llm_takeoff(call, db, empty, fake):
    got = call("GET", f"{API}/viewports/{empty['vp']}/slab-candidates").json()
    assert got["candidates"] == []
    assert got["llm_takeoff"] == {"enabled": False, "ready": False, "provider": None,
                                  "provider_label": None}
    _on(db)
    got = call("GET", f"{API}/viewports/{empty['vp']}/slab-candidates").json()
    assert got["llm_takeoff"] == {"enabled": True, "ready": True, "provider": "claude_api",
                                  "provider_label": "Claude API key"}


# ---------------------------------------------------------------- rerun + the run's source

def test_rerun_deletes_the_llm_measurements_too(call, db, empty, agent_spawns, fake):
    _on(db)
    old = autorun_api.create_run(db, CTX, empty["est"], empty["sheet"], empty["vp"], "concrete", [])
    autorun_api.update_run(db, old, status="done", step="done")
    gone = _measurement(db, empty["est"], empty["sheet"], empty["vp"],
                        calc={"source": "llm", "auto_run_id": old, "candidate_id": "llm"})
    kept_approved = _measurement(db, empty["est"], empty["sheet"], empty["vp"], status="approved",
                                 calc={"source": "llm", "auto_run_id": old, "candidate_id": "llm"})
    kept_human = _measurement(db, empty["est"], empty["sheet"], empty["vp"], proposed_by="owner",
                              calc=None)
    r = call("POST", f"{API}/auto-run/{old}/rerun", {})
    assert r.status == 200, r.json()
    assert r.json()["status"] == "running" and r.json()["run_id"] != old
    assert agent_spawns.calls[0][0][1:3] == ["-m", "estimator.agents.llm_takeoff_runner"]
    left = {x[0] for x in db.execute("SELECT id FROM measurements")}
    assert gone not in left and {kept_approved, kept_human} <= left


def test_get_run_reports_the_source(call, db, empty):
    geo = autorun_api.create_run(db, CTX, empty["est"], empty["sheet"], empty["vp"], "concrete",
                                 [{"id": "c1", "label": "12 x 10"}])
    llm = autorun_api.create_run(db, CTX, empty["est"], empty["sheet"], empty["vp"], "concrete",
                                 [{"id": "llm", "source": "llm", "label": "45'-7\" x 46'-7\" (read by the AI)"}])
    assert call("GET", f"{API}/auto-run/{geo}").json()["run"]["source"] == "geometry"
    assert call("GET", f"{API}/auto-run/{llm}").json()["run"]["source"] == "llm"


# ---------------------------------------------------------------- AI Auto Measure/Count on the sheets that are ON (2026-11-15)

def _off(db, sheet):
    from estimator.takeoff import sheet_trades
    sheet_trades.set_active(db, CTX, sheet, "concrete", False)


def _second_sheet(db, seed, title, image=None):
    ps = db.execute("SELECT plan_set_id FROM sheets WHERE id = ?", (seed["sheet"],)).fetchone()[0]
    sheet = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                       " VALUES ('default', ?, 2, 'A-1', ?, ?)", (ps, title, image)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, is_nts) VALUES ('default', ?, ?, 1)",
                    (sheet, title)).lastrowid
    return sheet, vp


def test_auto_run_skips_a_switched_off_sheet_and_measures_the_one_that_is_on(call, db, empty, agent_spawns, fake,
                                                                              tmp_path):
    """David's NSB case: elevations switched off, the foundation sheet on. Asking from an elevation (or with no sheet)
    measures the foundation sheet, on the slab plan's view."""
    img = tmp_path / "s.png"
    img.write_bytes(b"png")
    db.execute("UPDATE sheets SET image_path = ? WHERE id = ?", (str(img), empty["sheet"]))
    elev, elev_vp = _second_sheet(db, empty, "LEFT SIDE ELEVATION", str(img))
    _off(db, elev)
    _on(db)
    r = call("POST", f"{API}/auto-run", {"estimate_id": empty["est"], "sheet_id": elev, "viewport_id": elev_vp,
                                         "module_id": "concrete"})
    assert r.status == 200, r.json()
    row = db.execute("SELECT sheet_id, viewport_id FROM auto_runs WHERE id = ?", (r.json()["run_id"],)).fetchone()
    assert (row["sheet_id"], row["viewport_id"]) == (empty["sheet"], empty["vp"])
    r = call("POST", f"{API}/auto-run", {"estimate_id": empty["est"], "module_id": "concrete"})
    assert r.status in (200, 400), r.json()          # 400 only because the first run is still going
    # Every sheet off: refused, saying so.
    _off(db, empty["sheet"])
    db.execute("UPDATE auto_runs SET status = 'done'")
    r = call("POST", f"{API}/auto-run", {"estimate_id": empty["est"], "module_id": "concrete"})
    assert r.status == 400 and "switched off for Concrete" in r.json()["message"]


def test_finished_run_lists_its_measurements_and_the_concrete_volume(call, db, empty):
    run = autorun_api.create_run(db, CTX, empty["est"], empty["sheet"], empty["vp"], "concrete", [])
    calc = {"source": "llm", "auto_run_id": run, "candidate_id": "llm", "footer_size": "12x20"}
    a = _measurement(db, empty["est"], empty["sheet"], empty["vp"], qty="2123.42", calc=calc)
    db.execute("UPDATE measurements SET feeds = 'area_sqft' WHERE id = ?", (a,))
    f = _measurement(db, empty["est"], empty["sheet"], empty["vp"], kind="length", label="Footer (AI)", qty="184.33",
                     unit="lf", calc=calc)
    db.execute("UPDATE measurements SET feeds = 'footing_lf' WHERE id = ?", (f,))
    autorun_api.update_run(db, run, status="done", step="done", measurement_ids=[a, f])
    res = call("GET", f"{API}/auto-run/{run}").json()["run"]["results"]
    assert [x["label"] for x in res["lines"]] == ["Slab (AI)", "Footer (AI)"]
    c = res["concrete"]
    # 2026-11-15: a run from before the footer detail was read: the footer size note 12x20 is 12 wide, 20 overall.
    # The slab runs to the outside edge, so only 20 - 4 = 16 in of footer is below it: 12 x 16 = 192 sq in, along the
    # middle line 184.33 - 4 x 1 = 180.33 lf -> 180.33 x 192 / 144 / 27 = 8.91 cu yd. Slab 2123.42 x 4 / 12 / 27 = 26.22.
    assert c["slab_cuyd"] == "26.22" and c["footer_cuyd"] == "8.91" and c["total_cuyd"] == "35.13"
    assert c["with_waste_cuyd"] == "36.89" and c["footer_size"] == "12x20" and c["thickness_in"] == "4.00"
    assert c["footer_below_slab_in"] == "16" and c["footer_section_sqin"] == "192" and c["footer_lf"] == "180.33"
    assert "footer size 12x20" in c["footer_from"]["outside_in"]
    steps = {s["what"]: s for s in c["steps"]}
    assert steps["Footer depth below the slab"]["formula"] == "20 in - 4 in slab"
    assert steps["Footer cross-section"]["formula"] == "12 in x 16 in"
    assert steps["Footer length (middle line)"]["result"] == "180.33 lf"
    assert steps["Footer concrete"]["formula"] == "180.33 lf x 192 sq in ÷ 144 ÷ 27"
    assert steps["Footer concrete"]["result"] == "8.91 cu yd"
    assert steps["Slab concrete"]["formula"] == "2,123.42 sq ft x 4 in ÷ 12 ÷ 27"
    assert steps["Total concrete"]["formula"] == "26.22 + 8.91" and steps["Order with waste"]["result"] == "36.89 cu yd"
    # A thickness read off the plan is used instead of the default, and says so.
    db.execute("UPDATE measurements SET calc_json = json_set(calc_json, '$.slab_thickness', '6\"') WHERE id = ?", (a,))
    c6 = call("GET", f"{API}/auto-run/{run}").json()["run"]["results"]["concrete"]
    assert c6["thickness_in"] == "6.00" and "6\"" in c6["thickness_from"] and c6["slab_cuyd"] == "39.32"
    assert c6["footer_below_slab_in"] == "14"                    # the thicker slab covers more of the footer
    db.execute("UPDATE measurements SET calc_json = json_remove(calc_json, '$.slab_thickness') WHERE id = ?", (a,))
    # A person corrects the footer (David's NSB detail: 22 in outside face, a 4 x 2 in ledge): asks first, then the
    # footer length and volume are worked out again, and a cross-section measurement is added for the price.
    ask = call("POST", f"{API}/auto-run/{run}/footer", {"section": {"outside_in": 22, "ledge_w_in": 4, "ledge_d_in": 2}})
    assert ask.json()["needs_confirmation"] and "208 sq in" in ask.json()["question"]
    done = call("POST", f"{API}/auto-run/{run}/footer",
                {"section": {"outside_in": 22, "ledge_w_in": 4, "ledge_d_in": 2}, "confirm": True}).json()
    c2 = done["results"]["concrete"]
    assert c2["footer_section_sqin"] == "208" and c2["footer_cuyd"] == "9.65" and c2["total_cuyd"] == "35.87"
    assert c2["footer_from"]["outside_in"] == "entered by a person"
    assert db.execute("SELECT qty FROM measurements WHERE id = ?", (f,)).fetchone()[0] == "180.33"
    sec_m = db.execute("SELECT qty, unit FROM measurements WHERE estimate_id = ? AND feeds = 'footing_section_sqft'",
                       (empty["est"],)).fetchone()
    assert (sec_m[0], sec_m[1]) == ("1.4444", "sqft/lf")
    bad = call("POST", f"{API}/auto-run/{run}/footer", {"section": {"outside_in": 2}, "confirm": True})
    assert bad.status == 400 and "at least the slab thickness" in bad.json()["message"]
    # A running run has no results yet.
    other = autorun_api.create_run(db, CTX, empty["est"], empty["sheet"], empty["vp"], "concrete", [])
    assert call("GET", f"{API}/auto-run/{other}").json()["run"]["results"] is None


def test_review_data_has_the_projects_picked_trades_and_sheet_switches(call, db, empty):
    """Blueprint Review knows a trade picked for the project before it is priced, and which sheets are off."""
    from estimator.director import engine
    engine.set_project_trades(db, CTX, empty["est"], ["concrete"])
    elev, _ = _second_sheet(db, empty, "RIGHT SIDE ELEVATION")
    _off(db, elev)
    d = call("GET", f"{API}/estimates/{empty['est']}/takeoff").json()
    assert [t["module_id"] for t in d["trades"]] == ["concrete"]
    off = {s["id"]: s["inactive_trades"] for s in d["sheets"]}
    assert off[elev] == ["concrete"] and off[empty["sheet"]] == []


# ---------------------------------------------------------------- the page says the AI didn't run

def test_blueprint_review_points_at_the_llm_switch_when_takeoff_is_off():
    """The candidates line when LLM takeoff is off: it says the AI didn't run and where the switch is - AI-Prowler's
    Estimator tab → AI agents since 2026-11-13 (the agents' settings live on the desktop) - instead of only
    suggesting manual measuring. The on / not-ready lines stay as they were."""
    review = (WEB / "review.js").read_text(encoding="utf-8")
    for needle in ("didn't run because AI measuring is off",
                   "Turn it on in AI-Prowler's 🏗 Estimator tab → 🤖 AI agents (AI measuring → Suggest)",
                   "the AI will read the plan instead when you run it (AI measuring is on)",
                   "AI measuring is on, but the AI isn't ready"):
        assert needle in review, needle
