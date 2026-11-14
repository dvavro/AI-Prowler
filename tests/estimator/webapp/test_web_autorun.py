"""Concrete auto-run Phase 1: slab candidates, run start/status/rerun, retarget and mark-agent, through the API."""
import json
import subprocess
import sys

import pytest

from estimator import config
from estimator.api import autorun_api
from estimator.context import personal_context
from estimator.estimating import service
from estimator.takeoff import slab_find

API = "/estimator-api"
NOW = "2026-11-12T10:00:00+00:00"
PAPER_W = 547 / 84.3225      # 45'-7" at the live slab's scale (the plan's ~6.49" is 45'-7 1/2")
PAPER_H = 559 / 84.3225      # 46'-7"


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
    """Playwright is installed and the agent process is faked (its command is recorded, nothing runs)."""
    _FakePopen.calls.clear()
    monkeypatch.setattr(autorun_api, "_playwright_available", lambda: True)
    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    return _FakePopen


@pytest.fixture
def no_playwright(monkeypatch):
    _FakePopen.calls.clear()
    monkeypatch.setattr(autorun_api, "_playwright_available", lambda: False)
    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    return _FakePopen


def _walls(db, vp, sheet, rects):
    ids = {}
    for name, (x1, y1, x2, y2) in rects.items():
        got = []
        for (ax, ay), (bx, by) in [((x1, y1), (x2, y1)), ((x2, y1), (x2, y2)),
                                   ((x2, y2), (x1, y2)), ((x1, y2), (x1, y1))]:
            got.append(db.execute(
                "INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json, source)"
                " VALUES ('default', ?, ?, 'wall', ?, 'cad')",
                (sheet, vp, json.dumps({"type": "line", "points": [[ax, ay], [bx, by]]}))).lastrowid)
        ids[name] = got
    return ids


@pytest.fixture
def slab(db):
    """An estimate with one sheet and one calibrated viewport: a 12 x 10 ft-paper outer rectangle
    (candidate c1) and the 45'-7\" x 46'-7\" shed slab inside it (candidate c2)."""
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Shed slab")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    sheet = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no)"
                       " VALUES ('default', ?, 1, 'A-101')", (ps,)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Foundation plan', '84.3225', 0)", (sheet,)).lastrowid
    ids = _walls(db, vp, sheet, {"outer": (0, 0, 12, 10), "slab": (2, 2, 2 + PAPER_W, 2 + PAPER_H)})
    return {"est": est, "sheet": sheet, "vp": vp, "wall_ids": ids}


def _measurement(db, est, sheet, vp, **kw):
    vals = {"module_id": "concrete", "kind": "area", "qty": "2124.62", "unit": "sqft",
            "proposed_by": "owner", "status": "proposed", "calc": None, "label": "Slab"}
    vals.update(kw)
    return db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, sheet_id, viewport_id, kind, label,"
        " qty, unit, source_object_ids, calc_json, method, status, proposed_by, created_at, updated_at)"
        " VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, 'cad', ?, ?, ?, ?)",
        (est, vals["module_id"], sheet, vp, vals["kind"], vals["label"], vals["qty"], vals["unit"],
         json.dumps(vals["calc"]) if vals["calc"] is not None else None,
         vals["status"], vals["proposed_by"], NOW, NOW)).lastrowid


def _run(db, slab, status="done"):
    ctx = personal_context()
    found = slab_find.find_slab_candidates(db, "default", slab["vp"])
    rid = autorun_api.create_run(db, ctx, slab["est"], slab["sheet"], slab["vp"], "concrete",
                                 found["candidates"])
    if status != "running":
        autorun_api.update_run(db, rid, status=status, step=status)
    return rid


# ---------------------------------------------------------------- candidates

def test_candidates_endpoint(call, slab):                                                     # AR-A01
    r = call("GET", f"{API}/viewports/{slab['vp']}/slab-candidates")
    assert r.status == 200, r.json()
    got = r.json()
    assert got["calibrated"] is True and got["scale_ratio"] == 84.3225
    assert [c["id"] for c in got["candidates"]] == ["c1", "c2"]       # biggest first
    assert got["candidates"][1]["label"] == "45'-7\" x 46'-7\""
    assert got["candidates"][1]["object_ids"] == slab["wall_ids"]["slab"]


def test_candidates_endpoint_missing_viewport_is_404(call):                                   # AR-A02
    assert call("GET", f"{API}/viewports/9999/slab-candidates").status == 404


def test_candidates_endpoint_unscaled_viewport(call, db, slab):                               # AR-A03
    vp2 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'NTS detail', NULL, 1)", (slab["sheet"],)).lastrowid
    _walls(db, vp2, slab["sheet"], {"slab": (2, 2, 2 + PAPER_W, 2 + PAPER_H)})
    got = call("GET", f"{API}/viewports/{vp2}/slab-candidates").json()
    assert got["calibrated"] is False and got["candidates"][0]["area_sqft"] is None
    assert got["candidates"][0]["area"] == pytest.approx(PAPER_W * PAPER_H)


# ---------------------------------------------------------------- start + status

def test_start_run_spawns_the_agent_detached(call, db, slab, agent_spawns):                   # AR-A04
    r = call("POST", f"{API}/auto-run", {"estimate_id": slab["est"], "sheet_id": slab["sheet"],
                                         "viewport_id": slab["vp"], "module_id": "concrete"})
    assert r.status == 200, r.json()
    assert r.json()["status"] == "running"
    run_id = r.json()["run_id"]
    assert len(agent_spawns.calls) == 1
    cmd, kw = agent_spawns.calls[0]
    assert cmd[0] == sys.executable
    assert cmd[1:3] == ["-m", "estimator.agents.concrete_autorun"]
    assert cmd[cmd.index("--base") + 1] == "http://localhost:8770"
    assert cmd[cmd.index("--db") + 1] == str(config.db_path())
    assert cmd[cmd.index("--run-id") + 1] == str(run_id)
    assert cmd[-1] == "--headed"
    assert "creationflags" in kw or "start_new_session" in kw       # detached from the server
    assert kw["stdout"] == subprocess.DEVNULL
    row = db.execute("SELECT status, step, candidates_json FROM auto_runs WHERE id = ?",
                     (run_id,)).fetchone()
    assert row["status"] == "running" and row["step"] == "starting"
    assert [c["id"] for c in json.loads(row["candidates_json"])] == ["c1", "c2"]


def test_start_run_without_playwright_marks_the_run_failed(call, db, slab, no_playwright):    # AR-A05
    r = call("POST", f"{API}/auto-run", {"estimate_id": slab["est"], "sheet_id": slab["sheet"],
                                         "viewport_id": slab["vp"], "module_id": "concrete"})
    assert r.status == 200, r.json()
    assert r.json()["status"] == "failed" and "playwright install chromium" in r.json()["error"]
    assert no_playwright.calls == []                                            # nothing spawned
    row = db.execute("SELECT status, error FROM auto_runs WHERE id = ?",
                     (r.json()["run_id"],)).fetchone()
    assert row["status"] == "failed" and "playwright install chromium" in row["error"]


def test_start_run_rejects_other_modules_and_bad_ids(call, slab):                             # AR-A06
    base = {"estimate_id": slab["est"], "sheet_id": slab["sheet"], "viewport_id": slab["vp"]}
    assert call("POST", f"{API}/auto-run", {**base, "module_id": "roofing"}).status == 400
    assert call("POST", f"{API}/auto-run", {**base, "module_id": "concrete",
                                            "estimate_id": 9999}).status == 404
    assert call("POST", f"{API}/auto-run", {"module_id": "concrete"}).status == 400


def test_start_run_refuses_a_second_running_run(call, slab, agent_spawns):                    # AR-A07
    body = {"estimate_id": slab["est"], "sheet_id": slab["sheet"], "viewport_id": slab["vp"],
            "module_id": "concrete"}
    assert call("POST", f"{API}/auto-run", body).status == 200
    assert call("POST", f"{API}/auto-run", body).status == 400
    assert len(agent_spawns.calls) == 1


def test_get_run(call, db, slab):                                                             # AR-A08
    rid = _run(db, slab)
    got = call("GET", f"{API}/auto-run/{rid}").json()["run"]
    assert got["id"] == rid and got["status"] == "done"
    assert got["estimate_id"] == slab["est"] and got["module_id"] == "concrete"
    assert [c["id"] for c in got["candidates"]] == ["c1", "c2"] and got["measurement_ids"] == []
    assert call("GET", f"{API}/auto-run/9999").status == 404


# ---------------------------------------------------------------- rerun

def test_rerun_deletes_only_its_proposed_agent_measurements(call, db, slab, agent_spawns):    # AR-A09
    old = _run(db, slab)
    other = _run(db, slab)
    gone = _measurement(db, slab["est"], slab["sheet"], slab["vp"], proposed_by="concrete-agent",
                        calc={"auto_run_id": old, "candidate_id": "c2"})
    kept_approved = _measurement(db, slab["est"], slab["sheet"], slab["vp"],
                                 proposed_by="concrete-agent", status="approved",
                                 calc={"auto_run_id": old, "candidate_id": "c2"})
    kept_other_run = _measurement(db, slab["est"], slab["sheet"], slab["vp"],
                                  proposed_by="concrete-agent",
                                  calc={"auto_run_id": other, "candidate_id": "c2"})
    kept_human = _measurement(db, slab["est"], slab["sheet"], slab["vp"])
    r = call("POST", f"{API}/auto-run/{old}/rerun", {})
    assert r.status == 200, r.json()
    assert r.json()["status"] == "running" and r.json()["run_id"] != old
    assert agent_spawns.calls[0][0][agent_spawns.calls[0][0].index("--run-id") + 1] == str(r.json()["run_id"])
    left = {x[0] for x in db.execute("SELECT id FROM measurements")}
    assert gone not in left and {kept_approved, kept_other_run, kept_human} <= left


def test_rerun_refuses_a_running_run(call, db, slab):                                         # AR-A10
    rid = _run(db, slab, status="running")
    assert call("POST", f"{API}/auto-run/{rid}/rerun", {}).status == 400


# ---------------------------------------------------------------- retarget

def test_retarget_recomputes_from_the_other_candidate(call, db, slab):                        # AR-A11
    rid = _run(db, slab)
    mid = _measurement(db, slab["est"], slab["sheet"], slab["vp"], proposed_by="concrete-agent",
                       calc={"auto_run_id": rid, "candidate_id": "c2"})
    ask = call("POST", f"{API}/measurements/{mid}/retarget", {"candidate_id": "c1"})
    assert ask.status == 200 and ask.json()["needs_confirmation"] is True, ask.json()
    assert db.execute("SELECT qty FROM measurements WHERE id = ?", (mid,)).fetchone()["qty"] == "2124.62"
    done = call("POST", f"{API}/measurements/{mid}/retarget", {"candidate_id": "c1", "confirm": True})
    assert done.status == 200, done.json()
    m = done.json()["measurement"]
    assert m["qty"] == str(round(12 * 10 * (84.3225 / 12) ** 2, 2)) and m["unit"] == "sqft"
    row = db.execute("SELECT source_object_ids, geometry_json, calc_json FROM measurements WHERE id = ?",
                     (mid,)).fetchone()
    assert json.loads(row["source_object_ids"]) == slab["wall_ids"]["outer"]
    assert json.loads(row["geometry_json"]) == {"type": "polygon",
                                                "points": [[0, 0], [12, 0], [12, 10], [0, 10]]}
    assert json.loads(row["calc_json"])["candidate_id"] == "c1"


def test_retarget_rejects_non_agent_approved_and_unknown(call, db, slab):                     # AR-A12
    rid = _run(db, slab)
    human = _measurement(db, slab["est"], slab["sheet"], slab["vp"])
    assert call("POST", f"{API}/measurements/{human}/retarget",
                {"candidate_id": "c1", "confirm": True}).status == 400
    approved = _measurement(db, slab["est"], slab["sheet"], slab["vp"], proposed_by="concrete-agent",
                            status="approved", calc={"auto_run_id": rid, "candidate_id": "c2"})
    assert call("POST", f"{API}/measurements/{approved}/retarget",
                {"candidate_id": "c1", "confirm": True}).status == 400
    agent = _measurement(db, slab["est"], slab["sheet"], slab["vp"], proposed_by="concrete-agent",
                         calc={"auto_run_id": rid, "candidate_id": "c2"})
    assert call("POST", f"{API}/measurements/{agent}/retarget",
                {"candidate_id": "c9", "confirm": True}).status == 400


# ---------------------------------------------------------------- mark-agent

def test_mark_agent_stamps_the_measurement_and_the_run(call, db, slab):                       # AR-A13
    rid = _run(db, slab)
    mid = _measurement(db, slab["est"], slab["sheet"], slab["vp"])
    r = call("POST", f"{API}/measurements/{mid}/mark-agent",
             {"auto_run_id": rid, "candidate_id": "c2"})
    assert r.status == 200, r.json()
    assert r.json()["measurement"]["proposed_by"] == "concrete-agent"
    row = db.execute("SELECT proposed_by, calc_json FROM measurements WHERE id = ?", (mid,)).fetchone()
    assert row["proposed_by"] == "concrete-agent"
    assert json.loads(row["calc_json"]) == {"auto_run_id": rid, "candidate_id": "c2"}
    run = db.execute("SELECT measurement_ids_json FROM auto_runs WHERE id = ?", (rid,)).fetchone()
    assert json.loads(run["measurement_ids_json"]) == [mid]


def test_mark_agent_rejects_bad_candidate_and_approved(call, db, slab):                       # AR-A14
    rid = _run(db, slab)
    mid = _measurement(db, slab["est"], slab["sheet"], slab["vp"])
    assert call("POST", f"{API}/measurements/{mid}/mark-agent",
                {"auto_run_id": rid, "candidate_id": "c9"}).status == 400
    approved = _measurement(db, slab["est"], slab["sheet"], slab["vp"], status="approved")
    assert call("POST", f"{API}/measurements/{approved}/mark-agent",
                {"auto_run_id": rid, "candidate_id": "c2"}).status == 400


# ---------------------------------------------------------------- the agent's own calibration (2026-11-13)

def _calibrated(db, vp, by="owner", at="2099-01-01T00:00:00+00:00", method="calibration"):
    db.execute("UPDATE viewports SET scale_method = ?, scale_set_by = ?, scale_set_at = ? WHERE id = ?",
               (method, by, at, vp))


def test_agent_calibration_is_stamped_as_the_agents(call, db, slab):                          # AR-A19
    rid = _run(db, slab)
    _calibrated(db, slab["vp"])                         # the Calibrate tool records the signed-in person
    r = call("POST", f"{API}/viewports/{slab['vp']}/mark-agent", {"auto_run_id": rid})
    assert r.status == 200, r.json()
    assert r.json()["scale_set_by"] == "concrete-agent"
    assert db.execute("SELECT scale_set_by FROM viewports WHERE id = ?",
                      (slab["vp"],)).fetchone()["scale_set_by"] == "concrete-agent"
    scale = call("GET", f"{API}/auto-run/{rid}").json()["run"]["scale"]
    assert scale["by_agent"] is True and scale["during_run"] is True and scale["method"] == "calibration"


def test_mark_agent_scale_refuses_an_older_calibration_or_another_view(call, db, slab):      # AR-A20
    rid = _run(db, slab)
    _calibrated(db, slab["vp"], at="2026-11-11T18:29:19+00:00")    # a person calibrated before the run
    assert call("POST", f"{API}/viewports/{slab['vp']}/mark-agent", {"auto_run_id": rid}).status == 400
    assert db.execute("SELECT scale_set_by FROM viewports WHERE id = ?",
                      (slab["vp"],)).fetchone()["scale_set_by"] == "owner"
    _calibrated(db, slab["vp"], method="note")                     # a plan note, not a calibration
    assert call("POST", f"{API}/viewports/{slab['vp']}/mark-agent", {"auto_run_id": rid}).status == 400
    other = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                       " VALUES ('default', ?, 'Detail', '12', 0)", (slab["sheet"],)).lastrowid
    _calibrated(db, other)
    assert call("POST", f"{API}/viewports/{other}/mark-agent", {"auto_run_id": rid}).status == 400


def test_run_says_whose_scale_it_measured_with(call, db, slab):                               # AR-A21
    rid = _run(db, slab)
    _calibrated(db, slab["vp"], at="2026-11-11T18:29:19+00:00")
    scale = call("GET", f"{API}/auto-run/{rid}").json()["run"]["scale"]
    assert scale["set_by"] == "owner" and scale["by_agent"] is False and scale["during_run"] is False
    assert scale["set_at"].startswith("2026-11-11") and float(scale["scale_ratio"]) == 84.3225
    db.execute("UPDATE viewports SET scale_ratio = NULL WHERE id = ?", (slab["vp"],))
    assert call("GET", f"{API}/auto-run/{rid}").json()["run"]["scale"] is None


def test_reviewer_cannot_stamp_a_calibration(call, db, slab, session_for):                    # AR-A22
    rid = _run(db, slab)
    _calibrated(db, slab["vp"])
    assert call("POST", f"{API}/viewports/{slab['vp']}/mark-agent", {"auto_run_id": rid},
                headers=session_for("reviewer")).status == 403


def test_auto_calibrate_route(call, db, slab, session_for):                                    # AR-A23
    """The fixture's view already has a scale: replacing it asks first; with no written dimensions and AI takeoff
    off, the answer is "manual calibration required" with the reason and how - and the view says so."""
    r = call("POST", f"{API}/viewports/{slab['vp']}/auto-calibrate", {})
    assert r.status == 200 and r.json()["needs_confirmation"] is True and "already has a scale" in r.json()["question"]
    got = call("POST", f"{API}/viewports/{slab['vp']}/auto-calibrate", {"confirm": True}).json()
    assert got["status"] == "manual_required" and "AI takeoff is off" in got["reason"] and "Calibrate" in got["how"]
    vp = call("GET", f"{API}/sheets/{slab['sheet']}").json()["viewports"][0]
    assert vp["auto_calibration"]["status"] == "manual_required"
    assert call("POST", f"{API}/viewports/{slab['vp']}/auto-calibrate", {"confirm": True},
                headers=session_for("reviewer")).status == 403
    assert call("POST", f"{API}/viewports/9999/auto-calibrate", {"confirm": True}).status == 404


# ---------------------------------------------------------------- roles

def test_reviewer_reads_but_cannot_start(call, slab, session_for):                            # AR-A15
    assert call("GET", f"{API}/viewports/{slab['vp']}/slab-candidates",
                headers=session_for("reviewer")).status == 200
    assert call("POST", f"{API}/auto-run",
                {"estimate_id": slab["est"], "sheet_id": slab["sheet"], "viewport_id": slab["vp"],
                 "module_id": "concrete"}, headers=session_for("reviewer")).status == 403
    assert call("GET", f"{API}/viewports/{slab['vp']}/slab-candidates",
                headers=session_for("field")).status == 403


# ---------------------------------------------------------------- list rows carry the calc (UI follow-up)

def test_list_rows_carry_calc_with_auto_run_and_candidate(call, db, slab):                    # AR-A17
    rid = _run(db, slab)
    mid = _measurement(db, slab["est"], slab["sheet"], slab["vp"], proposed_by="concrete-agent",
                       calc={"auto_run_id": rid, "candidate_id": "c2"})
    rows = call("GET", f"{API}/estimates/{slab['est']}/takeoff").json()["takeoff"]["measurements"]
    row = next(r for r in rows if r["id"] == mid)
    assert row["proposed_by"] == "concrete-agent"
    assert row["calc"] == {"auto_run_id": rid, "candidate_id": "c2"}   # the list can name the outline now


def test_drawn_save_then_mark_agent_keeps_calc_and_adds_run_keys(call, db, slab):             # AR-A18
    """The agent's real path: it draws in the page (manual() seeds calc with how/qty/scale),
    then mark-agent merges auto_run_id/candidate_id in - the provenance stays, the run keys land."""
    rid = _run(db, slab)
    saved = call("POST", f"{API}/estimates/{slab['est']}/measurements",
                 {"module_id": "concrete", "viewport_id": slab["vp"], "label": "Slab",
                  "geometry": {"type": "polygon",
                               "points": [[2, 2], [2 + PAPER_W, 2],
                                          [2 + PAPER_W, 2 + PAPER_H], [2, 2 + PAPER_H]]},
                  "confirm": True})
    assert saved.status == 200, saved.json()
    mid = saved.json()["measurement"]["id"]
    assert saved.json()["measurement"]["kind"] == "area"
    assert abs(float(saved.json()["measurement"]["qty"])
               - PAPER_W * PAPER_H * (84.3225 / 12) ** 2) < 0.01
    r = call("POST", f"{API}/measurements/{mid}/mark-agent",
             {"auto_run_id": rid, "candidate_id": "c2"})
    assert r.status == 200, r.json()
    calc = r.json()["measurement"]["calc"]
    assert calc["auto_run_id"] == rid and calc["candidate_id"] == "c2"
    assert calc["scale_ratio"] == "84.3225" and "how" in calc       # manual()'s calc survives the merge
    assert r.json()["measurement"]["proposed_by"] == "concrete-agent"


# ---------------------------------------------------------------- update_run (the agent's way back)

def test_update_run_reports_progress_and_finish(db, slab):                                    # AR-A16
    rid = _run(db, slab, status="running")
    got = autorun_api.update_run(db, rid, step="measuring", candidate_id="c2")
    assert got["step"] == "measuring" and got["candidate_id"] == "c2" and got["status"] == "running"
    got = autorun_api.update_run(db, rid, status="done", step="done", measurement_ids=[7])
    assert got["status"] == "done" and got["measurement_ids"] == [7]
    with pytest.raises(Exception, match="not found"):
        autorun_api.update_run(db, 9999, step="x")
