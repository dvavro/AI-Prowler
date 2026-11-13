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
    assert "did not run" in r.json()["error"] and "LLM takeoff is off" in r.json()["error"]
    assert "AI agents" in r.json()["error"]                     # where to turn it on
    assert agent_spawns.calls == []
    row = db.execute("SELECT status, error FROM auto_runs WHERE id = ?", (r.json()["run_id"],)).fetchone()
    assert row["status"] == "failed" and "did not run" in row["error"]


def test_candidates_llm_on_still_uses_the_drawing(call, db, slab, agent_spawns, fake):
    _on(db)
    r = call("POST", f"{API}/auto-run", _body(slab))
    assert r.status == 200, r.json()
    assert r.json()["status"] == "running"
    assert len(agent_spawns.calls) == 1
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


# ---------------------------------------------------------------- the page says the AI didn't run

def test_blueprint_review_points_at_the_llm_switch_when_takeoff_is_off():
    """The candidates line when LLM takeoff is off: it says the AI didn't run and links
    to the Agents page, instead of only suggesting manual measuring. The on / not-ready
    lines stay as they were."""
    review = (WEB / "review.js").read_text(encoding="utf-8")
    for needle in ("didn't run because LLM takeoff is off", 'href: "#/agents"',
                   "Turn it on in 🤖 AI agents",
                   "the AI will read the plan instead when you run it (LLM takeoff is on)",
                   "LLM takeoff is on, but the AI isn't ready"):
        assert needle in review, needle
