"""LLM-assisted demolition takeoff: parsing, the quantity measurements, the run, the results.

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
from estimator.takeoff import llm_demolition as ld
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

CTX = personal_context()
NOW = "2026-11-12T10:00:00+00:00"


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
    """An estimate with one plan set: a single demolition sheet (D-101) with a rendered
    image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Demolition job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "d101.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'D-101', 'DEMOLITION PLAN', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Demolition plan', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "demolition", [])


# Kitchen 12 x 14.5 = 174.00, living room 20 x 15 = 300.00: interior and flooring 474.00.
ROOMS = [{"name": "Kitchen", "width_ft": "12'-0\"", "length_ft": "14'-6\""},
         {"name": "Living room", "width_ft": "20'-0\"", "length_ft": "15'-0\""}]
# 14.5 + 10 = 24.50 lf of walls, 10.00 lf of cabinets, 3 fixtures.
WALL_RUNS = [{"name": "Kitchen north wall", "length_ft": "14'-6\""},
             {"name": "Living room wall", "length_ft": "10'-0\""}]
CABINET_RUNS = [{"name": "Kitchen base cabinets", "length_ft": "10'-0\""}]
CONCRETE_AREAS = [{"name": "Patio slab", "width_ft": "10'-0\"", "length_ft": "12'-0\""}]

EVIDENCE = {"interior_sqft": "kitchen and living room marked for demo, 12 x 14.5 and 20 x 15",
            "walls_lf": "two wall runs marked for removal, 14.5 ft and 10 ft",
            "cabinets_lf": "kitchen base cabinets marked for removal, 10 ft",
            "fixtures": "3 fixtures marked for removal: 2 toilets, 1 tub",
            "flooring_sqft": "flooring torn out in the same demoed rooms",
            "concrete_sqft": "patio slab marked for breakout, 10 x 12",
            "structure_sqft": "no structure marked for demolition"}


def _reading(sheet_id, **over):
    out = {"demolition_sheet_id": sheet_id, "rooms": ROOMS, "wall_runs": WALL_RUNS,
           "cabinet_runs": CABINET_RUNS, "fixtures": 3, "concrete_areas": CONCRETE_AREAS,
           "structure_areas": [],
           "confidence": 0.9, "notes": "demo areas clear on the plan", "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return ld.parse_demolition_reading(_reading(sheet_id, **over), sheet_id)


VALUES = {"interior_sqft": "474.00", "walls_lf": "24.50", "cabinets_lf": "10.00", "fixtures": 3,
          "flooring_sqft": "474.00", "concrete_sqft": "120.00", "structure_sqft": "0.00"}


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_demolition_reading_full():
    got = ld.parse_demolition_reading(_reading(4), 4)
    assert got == {"demolition_sheet_id": 4, "rooms": ROOMS, "wall_runs": WALL_RUNS,
                   "cabinet_runs": CABINET_RUNS, "counts": {"fixtures": 3},
                   "concrete_areas": CONCRETE_AREAS, "structure_areas": [],
                   "evidence": dict(EVIDENCE), "confidence": 0.9, "notes": "demo areas clear on the plan"}


def test_parse_demolition_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, rooms=None, wall_runs=None, cabinet_runs=None,
                                  concrete_areas=None, structure_areas=None,
                                  confidence=None, evidence=None) + "\n```"
    got = ld.parse_demolition_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in ld.QUESTION_IDS}
    assert got["rooms"] == [] and got["wall_runs"] == [] and got["concrete_areas"] == []
    assert got["counts"]["fixtures"] == 3


def test_parse_demolition_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ld.parse_demolition_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ld.parse_demolition_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        ld.parse_demolition_reading('{not json}', 4)


@pytest.mark.parametrize("bad", [None, -1, 2.5, "3", True])
def test_parse_demolition_reading_rejects_bad_counts(bad):
    """Every defect names the field, so the AI Log says which count was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match="fixtures"):
        ld.parse_demolition_reading(_reading(4, fixtures=bad), 4)


@pytest.mark.parametrize("over,field", [
    ({"rooms": [{"name": "Kitchen", "width_ft": "12 ft", "length_ft": "14'-6\""}]}, "Kitchen width"),
    ({"rooms": [{"name": "Kitchen", "width_ft": "12'-0\"", "length_ft": "about 14 feet"}]},
     "Kitchen length"),
    ({"wall_runs": [{"name": "North wall", "length_ft": "10"}]}, "North wall length"),
    ({"cabinet_runs": [{"name": "Base cabinets", "length_ft": "ten feet"}]}, "Base cabinets length"),
    ({"concrete_areas": [{"name": "Slab", "width_ft": "wide", "length_ft": "12'-0\""}]}, "Slab width"),
    ({"structure_areas": [{"name": "Shed", "width_ft": "8'-0\"", "length_ft": "0"}]}, "Shed length"),
])
def test_parse_demolition_reading_rejects_bad_dimensions(over, field):
    """A dimension the AI hedged on rejects the whole answer, naming the field."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        ld.parse_demolition_reading(_reading(4, **over), 4)


def test_parse_demolition_reading_rejects_bad_shapes():
    with pytest.raises(lt.LlmTakeoffError, match="rooms"):
        ld.parse_demolition_reading(_reading(4, rooms={"name": "Kitchen"}), 4)
    with pytest.raises(lt.LlmTakeoffError, match="wall_runs"):
        ld.parse_demolition_reading(_reading(4, wall_runs=["14'-6\""]), 4)
    with pytest.raises(lt.LlmTakeoffError, match="length_ft"):
        ld.parse_demolition_reading(_reading(4, cabinet_runs=[{"name": "Base cabinets"}]), 4)
    with pytest.raises(lt.LlmTakeoffError, match="concrete_areas"):
        ld.parse_demolition_reading(_reading(4, concrete_areas=[{"name": "Slab", "width_ft": "10'-0\""}]), 4)


def test_parse_demolition_reading_rejects_missing_count():
    d = json.loads(_reading(4))
    del d["fixtures"]
    with pytest.raises(lt.LlmTakeoffError, match="fixtures"):
        ld.parse_demolition_reading(json.dumps(d), 4)


def test_parse_demolition_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = ld.parse_demolition_reading(_reading(9), 4)
    assert got["demolition_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_demolition_classification():
    assert ld.parse_demolition_classification('{"demolition_sheet_id": 4, "notes": "demo notes"}', [4, 5]) == (4, "demo notes")
    assert ld.parse_demolition_classification('{"demolition_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert ld.parse_demolition_classification('{"demolition_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ld.parse_demolition_classification("nope", [4])


# ------------------------------------------------------------------ the quantities: the app's maths

def test_quantities_from_reading_maths():
    """Areas and lengths come from the printed dimensions, to 0.01 - the AI never computes."""
    reading = _parsed(4, rooms=[{"name": "Den", "width_ft": "10'-0\"", "length_ft": "6'-8\""},
                                {"name": "Hall", "width_ft": "5'-0\"", "length_ft": "4'-0\""}],
                      wall_runs=[{"name": "Run A", "length_ft": "18'-3 1/2\""}],
                      cabinet_runs=[], fixtures=0,
                      concrete_areas=[{"name": "Slab", "width_ft": "6'-0\"", "length_ft": "6'-0\""}],
                      structure_areas=[])
    # den 10 x 6.666.. = 66.67, hall 20.00: interior and flooring 86.67;
    # run A 219.5 in = 18.29 lf; slab 36.00.
    assert ld.quantities_from_reading(reading) == {"values": {
        "interior_sqft": "86.67", "walls_lf": "18.29", "cabinets_lf": "0.00", "fixtures": 0,
        "flooring_sqft": "86.67", "concrete_sqft": "36.00", "structure_sqft": "0.00"}}


def test_quantities_from_reading_all_empty():
    reading = _parsed(4, rooms=[], wall_runs=[], cabinet_runs=[], fixtures=0,
                      concrete_areas=[], structure_areas=[])
    assert ld.quantities_from_reading(reading) == {"values": {
        "interior_sqft": "0.00", "walls_lf": "0.00", "cabinets_lf": "0.00", "fixtures": 0,
        "flooring_sqft": "0.00", "concrete_sqft": "0.00", "structure_sqft": "0.00"}}


# ------------------------------------------------------------------ the quantity measurements

def test_create_measurements_proposes_one_per_nonzero_quantity(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = ld.quantities_from_reading(reading)
    assert quantities == {"values": dict(VALUES)}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", ld.SPEC)
    assert len(ids) == 6                              # structure_sqft is 0: no row
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["interior_sqft", "walls_lf", "cabinets_lf", "fixtures",
                                          "flooring_sqft", "concrete_sqft"]
    kinds = {"interior_sqft": ("area", "sqft"), "walls_lf": ("length", "lf"),
             "cabinets_lf": ("length", "lf"), "fixtures": ("count", "ea"),
             "flooring_sqft": ("area", "sqft"), "concrete_sqft": ("area", "sqft")}
    for r in rows:
        assert r["module_id"] == "demolition" and (r["kind"], r["unit"]) == kinds[r["feeds"]]
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == ld.LABELS[r["feeds"]] + " (AI)"
        assert r["qty"] == str(VALUES[r["feeds"]])
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["demolition_sheet_id"] == plans["s1"]
        assert calc["values"]["interior_sqft"] == "474.00" and calc["values"]["fixtures"] == "3"
        assert calc["values"]["structure_sqft"] == "0.00"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "demo areas clear on the plan"


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], rooms=[], wall_runs=[], cabinet_runs=[], fixtures=0,
                      concrete_areas=[], structure_areas=[])
    quantities = ld.quantities_from_reading(reading)
    assert quantities["values"] == {"interior_sqft": "0.00", "walls_lf": "0.00", "cabinets_lf": "0.00",
                                    "fixtures": 0, "flooring_sqft": "0.00", "concrete_sqft": "0.00",
                                    "structure_sqft": "0.00"}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", ld.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_demolition_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "demolition" in fake.calls[0]["system"].lower()
    assert "marked for removal" in fake.calls[0]["user"] and "never null" in fake.calls[0]["user"]
    assert "never compute" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert steps == ["finding the demolition sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == dict(VALUES)
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm", "values": dict(VALUES),
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "demo areas clear on the plan", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the Demolition quantities on sheet %d (474.00 sq ft of interior to demo,"
                              " 24.50 lf of walls to remove, 10.00 lf of cabinets to remove, 3 fixtures to remove,"
                              " 474.00 sq ft of flooring to tear out, 120.00 sq ft of concrete to break out);"
                              " measurements %s" % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 6
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_demolition_rules_settle_on_the_demolition_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a101.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second demolition sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "d102.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'D-102', 'DEMOLITION PLAN', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'A-101', 'FLOOR PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_demolition_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"demolition_sheet_id": s2, "notes": "the demo notes are on D-102"}),
        _reading(s2),
    ]
    out = ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                       # classify, then the read
    assert len(fake.calls[0]["images"]) == 2          # thumbnails of both demolition sheets
    assert "demolition plan" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 6


def test_run_llm_demolition_fails_when_the_ai_cannot_find_the_demolition_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"demolition_sheet_id": None, "notes": "no demo notes seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the demolition sheet"):
        ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_demolition_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "LLM takeoff is off" in str(exc.value) and "read the Demolition plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_demolition_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_demolition_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'demolition', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Demolition"):
        ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_demolition_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_demolition_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], fixtures=2.5)]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="fixtures"):
        ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_demolition_bad_dimension_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(
        plans["s1"], rooms=[{"name": "Kitchen", "width_ft": "12 ft", "length_ft": "14'-6\""}])]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="Kitchen width"):
        ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_demolition_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_demolition_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = ld.run_llm_demolition(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = ld.demolition_results(db, CTX, row)
    assert len(got["lines"]) == 6
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["interior_sqft"] == {"id": out["measurement_ids"][0], "label": "Interior area to demo (AI)",
                                          "feeds": "interior_sqft", "qty": "474.00", "unit": "sqft",
                                          "status": "proposed", "how": EVIDENCE["interior_sqft"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(ld.QUESTION_IDS)        # all seven questions, zeros included
    assert items["interior_sqft"] == {"feeds": "interior_sqft", "label": "Interior area to demo",
                                      "qty": "474.00", "unit": "sqft", "evidence": EVIDENCE["interior_sqft"]}
    assert items["fixtures"] == {"feeds": "fixtures", "label": "Fixtures to remove (toilets, tubs, sinks)",
                                 "qty": 3, "unit": "ea", "evidence": EVIDENCE["fixtures"]}
    assert items["structure_sqft"] == {"feeds": "structure_sqft",
                                       "label": "Shed, carport or small structure footprint",
                                       "qty": "0.00", "unit": "sqft",
                                       "evidence": EVIDENCE["structure_sqft"]}   # zero: the candidate's evidence
    assert got["quantities"]["trade"] == "demolition" and got["quantities"]["label"] == "Demolition"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "demo areas clear on the plan"


def test_demolition_results_all_zero_quantities(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm",
            "values": {"interior_sqft": "0.00", "walls_lf": "0.00", "cabinets_lf": "0.00", "fixtures": 0,
                       "flooring_sqft": "0.00", "concrete_sqft": "0.00", "structure_sqft": "0.00"},
            "evidence": dict(EVIDENCE), "confidence": 0.8, "notes": "nothing marked",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = ld.demolition_results(db, CTX, row)
    assert got["lines"] == []
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["interior_sqft"]["qty"] == "0.00" and items["fixtures"]["qty"] == 0
    assert items["structure_sqft"]["qty"] == "0.00"
    assert got["quantities"]["items"][0]["evidence"] == EVIDENCE["interior_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_demolition_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert ld.demolition_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_demolition_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    ids = lq.create_measurements(db, CTX, run, reading, ld.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", ld.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = ld.demolition_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["interior_sqft"]["qty"] == "474.00" and items["fixtures"]["qty"] == 3
    assert items["structure_sqft"]["qty"] == 0       # no row, no candidate: the plain zero
    assert items["interior_sqft"]["evidence"] == EVIDENCE["interior_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
