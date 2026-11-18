"""LLM-assisted insulation takeoff: parsing, the measurements, the run, the results.

A fake provider stands in for Claude and Grok: no real API calls, no token cost.
Every test runs against a throwaway data folder (conftest.py) with fixture plan
sheets - never the live NSB plan or the live database.
"""
import json

import pytest

from estimator.agents import providers, roles
from estimator.api import autorun_api
from estimator.context import personal_context
from estimator.estimating import service
from estimator.takeoff import llm_insulation as li
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

CTX = personal_context()
NOW = "2026-11-12T10:00:00+00:00"

ROOMS = [{"name": "Living", "width_ft": "30'-0\"", "length_ft": "20'-0\""}]   # 600.00 sq ft
WALL_RUNS = [{"name": "North wall", "length_ft": "40'-0\"", "height_ft": "8'-0\""},
             {"name": "South wall", "length_ft": "40'-0\"", "height_ft": "8'-0\""}]   # 320 + 320 = 640.00 sq ft


class FakeVisionProvider:
    """Answers like Claude or Grok would. replies[provider] is a list of vision texts
    (or exceptions) used in order. ask() must never be called - the LLM takeoff reads
    pictures, it doesn't chat."""

    def __init__(self):
        self.keys = {"claude_api": True, "grok_api": True}
        self.replies = {"claude_api": [], "grok_api": []}
        self.calls = []

    def ready(self, provider):
        return (True, "") if self.keys.get(provider) else (False, "no API key saved")

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3"}[provider]

    def ask(self, provider, system, user, model=""):
        raise AssertionError("the LLM takeoff must use ask_vision, not ask")

    def ask_vision(self, provider, system, user, images, model=""):
        self.calls.append({"provider": provider, "system": system, "user": user,
                           "images": images, "model": model})
        r = self.replies[provider].pop(0) if self.replies[provider] else "{}"
        if isinstance(r, Exception):
            raise r
        return r, {"input": 3000, "output": 200}

    def cost(self, model, usage):           # $2 / $10 per 1M tokens, like Sonnet
        return round((usage["input"] * 2 + usage["output"] * 10) / 1_000_000, 5)


@pytest.fixture
def fake():
    f = FakeVisionProvider()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


def _png(path, w=400, h=300):
    from PIL import Image
    Image.new("RGB", (w, h), "white").save(path, "PNG")
    return str(path)


@pytest.fixture
def plans(db, tmp_path):
    """An estimate with one plan set: a single insulation sheet (A-501) with a
    rendered image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Insulation job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "a501.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'A-501', 'WALL SECTIONS', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Wall sections', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "insulation", [])


EVIDENCE = {"attic_sqft": "Living 30 x 20 on the floor plan",
            "wall_sqft": "North and South walls 40 x 8 on the wall sections"}


def _reading(sheet_id, **over):
    out = {"insulation_sheet_id": sheet_id,
           "rooms": [dict(r) for r in ROOMS], "wall_runs": [dict(r) for r in WALL_RUNS],
           "confidence": 0.9, "notes": "dimensions clear on the plan", "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return li.parse_insulation_reading(_reading(sheet_id, **over), sheet_id)


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_insulation_reading_full():
    got = li.parse_insulation_reading(_reading(4), 4)
    assert got == {"insulation_sheet_id": 4,
                   "rooms": [dict(r) for r in ROOMS],
                   "wall_runs": [dict(r) for r in WALL_RUNS],
                   "evidence": dict(EVIDENCE), "confidence": 0.9, "notes": "dimensions clear on the plan"}


def test_parse_insulation_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, confidence=None, evidence=None, rooms=None, wall_runs=None) + "\n```"
    got = li.parse_insulation_reading(text, 4)
    assert got["confidence"] is None and got["rooms"] == [] and got["wall_runs"] == []
    assert got["evidence"]["attic_sqft"] == ""
    # no wall runs and no evidence: the reading says the plan doesn't dimension the walls
    assert got["evidence"]["wall_sqft"] == "the plan doesn't dimension the walls"


def test_parse_insulation_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        li.parse_insulation_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        li.parse_insulation_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        li.parse_insulation_reading('{not json}', 4)


@pytest.mark.parametrize("rooms,match", [
    ("nope", "rooms"), (["nope"], "rooms\\[0\\]"),
    ([{"name": "Living"}], "width_ft"),
    ([{"name": "Living", "width_ft": "30'-0\""}], "length_ft"),
    ([{"name": "Living", "width_ft": "", "length_ft": "20'-0\""}], "width_ft"),
])
def test_parse_insulation_reading_rejects_bad_rooms(rooms, match):
    """Every defect names the field, so the AI Log says which dimension was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=match):
        li.parse_insulation_reading(_reading(4, rooms=rooms), 4)


@pytest.mark.parametrize("runs,match", [
    ("nope", "wall_runs"), (["nope"], "wall_runs\\[0\\]"),
    ([{"name": "North wall"}], "length_ft"),
    ([{"name": "North wall", "length_ft": "40'-0\""}], "height_ft"),
    ([{"name": "North wall", "length_ft": "", "height_ft": "8'-0\""}], "length_ft"),
    ([{"name": "North wall", "length_ft": "40'-0\"", "height_ft": 8}], "height_ft"),
    ([{"name": 5, "length_ft": "40'-0\"", "height_ft": "8'-0\""}], "name"),
])
def test_parse_insulation_reading_rejects_bad_wall_runs(runs, match):
    """Every defect names the field, so the AI Log says which wall run was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=match):
        li.parse_insulation_reading(_reading(4, wall_runs=runs), 4)


def test_parse_insulation_reading_empty_wall_runs_says_the_plan_doesnt_dimension_the_walls():
    ev = {"attic_sqft": "Living 30 x 20", "wall_sqft": ""}
    got = li.parse_insulation_reading(_reading(4, wall_runs=[], evidence=ev), 4)
    assert got["wall_runs"] == []
    assert got["evidence"]["wall_sqft"] == "the plan doesn't dimension the walls"
    # ... but the AI's own words stand when it wrote some
    ev2 = {"attic_sqft": "Living 30 x 20", "wall_sqft": "no wall sections on this sheet"}
    got2 = li.parse_insulation_reading(_reading(4, wall_runs=[], evidence=ev2), 4)
    assert got2["evidence"]["wall_sqft"] == "no wall sections on this sheet"


def test_parse_insulation_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = li.parse_insulation_reading(_reading(9), 4)
    assert got["insulation_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_insulation_classification():
    assert li.parse_insulation_classification('{"insulation_sheet_id": 4, "notes": "sections"}',
                                              [4, 5]) == (4, "sections")
    assert li.parse_insulation_classification('{"insulation_sheet_id": null, "notes": "none"}',
                                              [4, 5])[0] is None
    assert li.parse_insulation_classification('{"insulation_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        li.parse_insulation_classification("nope", [4])


# ------------------------------------------------------------------ the quantities (the app's maths)

def test_quantities_from_reading_works_out_both_areas():
    assert li.quantities_from_reading(_parsed(4))["values"] == {
        "attic_sqft": "600.00", "wall_sqft": "640.00"}
    # feet and inches: a 10'-6" x 8'-0" wall run is 84.00 sq ft
    runs = [{"name": "West wall", "length_ft": "10'-6\"", "height_ft": "8'-0\""}]
    assert li.quantities_from_reading(_parsed(4, wall_runs=runs))["values"]["wall_sqft"] == "84.00"
    # no dimensions: no areas
    assert li.quantities_from_reading(_parsed(4, rooms=[], wall_runs=[]))["values"] == {
        "attic_sqft": "0.00", "wall_sqft": "0.00"}
    assert li.quantities_from_reading(_parsed(4, rooms=None, wall_runs=None))["values"] == {
        "attic_sqft": "0.00", "wall_sqft": "0.00"}


@pytest.mark.parametrize("over,match", [
    ({"rooms": [{"name": "Living", "width_ft": "wide", "length_ft": "20'-0\""}]}, "width"),
    ({"rooms": [{"name": "Living", "width_ft": "30'-0\"", "length_ft": "long"}]}, "length"),
    ({"wall_runs": [{"name": "North wall", "length_ft": "long", "height_ft": "8'-0\""}]}, "length"),
    ({"wall_runs": [{"name": "North wall", "length_ft": "40'-0\"", "height_ft": "tall"}]}, "height"),
])
def test_quantities_from_reading_rejects_an_unparseable_dimension(over, match):
    """A dimension that isn't a length fails loudly, naming the side - never guessed at."""
    with pytest.raises(lt.LlmTakeoffError, match=match):
        li.quantities_from_reading(_parsed(4, **over))


# ------------------------------------------------------------------ the measurements

def test_create_measurements_proposes_one_per_nonzero_area(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = li.quantities_from_reading(reading)
    assert quantities == {"values": {"attic_sqft": "600.00", "wall_sqft": "640.00"}}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", li.SPEC)
    assert len(ids) == 2
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["attic_sqft", "wall_sqft"]
    for r in rows:
        assert r["module_id"] == "insulation" and r["kind"] == "area" and r["unit"] == "sqft"
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == li.LABELS[r["feeds"]] + " (AI)"
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["insulation_sheet_id"] == plans["s1"]
        assert calc["values"]["attic_sqft"] == "600.00" and calc["values"]["wall_sqft"] == "640.00"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "dimensions clear on the plan"
    assert [r["qty"] for r in rows] == ["600.00", "640.00"]


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], rooms=[], wall_runs=[])
    quantities = li.quantities_from_reading(reading)
    assert quantities["values"] == {"attic_sqft": "0.00", "wall_sqft": "0.00"}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", li.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_insulation_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                     # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "insulation sheet" in fake.calls[0]["system"].lower()
    assert "evidence" in fake.calls[0]["user"] and "wall_runs" in fake.calls[0]["user"]
    assert steps == ["finding the insulation sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == {"attic_sqft": "600.00", "wall_sqft": "640.00"}
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm",
                                "values": {"attic_sqft": "600.00", "wall_sqft": "640.00"},
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "dimensions clear on the plan", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the Insulation quantities on sheet %d (600.00 sq ft of attic,"
                              " 640.00 sq ft of open wall); measurements %s"
                              % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 2
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_insulation_rules_settle_on_the_insulation_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a101.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                     # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second wall-sections sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "a502.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'A-502', 'WALL SECTIONS', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'A-101', 'FLOOR PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_insulation_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"insulation_sheet_id": s2, "notes": "the sections are on A-502"}),
        _reading(s2),
    ]
    out = li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                     # classify, then the read
    assert len(fake.calls[0]["images"]) == 2        # thumbnails of both wall-sections sheets
    assert "wall sections" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 2


def test_run_llm_insulation_fails_when_the_ai_cannot_find_the_insulation_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"insulation_sheet_id": None, "notes": "no sections seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the insulation sheet"):
        li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_insulation_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "LLM takeoff is off" in str(exc.value) and "read the Insulation plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_insulation_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_insulation_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'insulation', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Insulation"):
        li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_insulation_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_insulation_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], wall_runs=[
        {"name": "North wall", "length_ft": "40'-0\""}])]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="height_ft"):
        li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_insulation_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_insulation_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = li.run_llm_insulation(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = li.insulation_results(db, CTX, row)
    assert len(got["lines"]) == 2
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["attic_sqft"] == {"id": out["measurement_ids"][0], "label": "Attic area (blown-in) (AI)",
                                      "feeds": "attic_sqft", "qty": "600.00", "unit": "sqft",
                                      "status": "proposed", "how": EVIDENCE["attic_sqft"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(li.ALL_IDS)            # both questions, zeros included
    assert items["attic_sqft"] == {"feeds": "attic_sqft", "label": "Attic area (blown-in)",
                                   "qty": "600.00", "unit": "sqft", "evidence": EVIDENCE["attic_sqft"]}
    assert items["wall_sqft"] == {"feeds": "wall_sqft", "label": "Open wall area (batts)",
                                  "qty": "640.00", "unit": "sqft", "evidence": EVIDENCE["wall_sqft"]}
    assert got["quantities"]["trade"] == "insulation" and got["quantities"]["label"] == "Insulation"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "dimensions clear on the plan"


def test_insulation_results_all_zero_counts(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm", "values": {"attic_sqft": "0.00", "wall_sqft": "0.00"},
            "evidence": dict(EVIDENCE), "confidence": 0.8, "notes": "empty plan",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = li.insulation_results(db, CTX, row)
    assert got["lines"] == []
    assert all(c["qty"] == "0.00" for c in got["quantities"]["items"])
    assert got["quantities"]["items"][0]["evidence"] == EVIDENCE["attic_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_insulation_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert li.insulation_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_insulation_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], wall_runs=[])    # the plan doesn't dimension the walls: no wall row
    ids = lq.create_measurements(db, CTX, run, reading, li.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", li.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = li.insulation_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["attic_sqft"]["qty"] == "600.00" and items["wall_sqft"]["qty"] == 0
    assert items["attic_sqft"]["evidence"] == EVIDENCE["attic_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
