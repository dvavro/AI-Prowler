"""LLM-assisted siding takeoff: parsing, the quantity measurements, the run, the results.

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
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_siding as ls
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
    """An estimate with one plan set: a single elevations sheet (A-201) with a rendered
    image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Siding job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "a201.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'A-201', 'ELEVATIONS', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Elevations', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "siding", [])


# Front and rear 40 x 9 = 360.00 each, sides 30 x 9 = 270.00 each: wall 1260.00,
# eaves 40 + 40 + 30 + 30 = 140.00 lf.
ELEVATIONS = [{"name": "Front", "width_ft": "40'-0\"", "height_ft": "9'-0\""},
              {"name": "Rear", "width_ft": "40'-0\"", "height_ft": "9'-0\""},
              {"name": "Left", "width_ft": "30'-0\"", "height_ft": "9'-0\""},
              {"name": "Right", "width_ft": "30'-0\"", "height_ft": "9'-0\""}]

EVIDENCE = {"wall_sqft": "four elevations, 40 x 9 front and rear, 30 x 9 both sides",
            "openings": "12 windows and doors in those walls",
            "outside_corners": "4 outside corners, one at each corner of the house",
            "inside_corners": "2 inside corners at the rear porch",
            "eave_lf": "the eaves run the full width of each elevation shown"}


def _reading(sheet_id, **over):
    out = {"siding_sheet_id": sheet_id, "elevations": ELEVATIONS, "openings": 12,
           "outside_corners": 4, "inside_corners": 2,
           "confidence": 0.9, "notes": "elevations clear on the plan", "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return ls.parse_siding_reading(_reading(sheet_id, **over), sheet_id)


VALUES = {"wall_sqft": "1260.00", "openings": 12, "outside_corners": 4, "inside_corners": 2,
          "eave_lf": "140.00"}


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_siding_reading_full():
    got = ls.parse_siding_reading(_reading(4), 4)
    assert got == {"siding_sheet_id": 4, "elevations": ELEVATIONS,
                   "counts": {"openings": 12, "outside_corners": 4, "inside_corners": 2},
                   "evidence": dict(EVIDENCE), "confidence": 0.9, "notes": "elevations clear on the plan"}


def test_parse_siding_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, elevations=None, confidence=None, evidence=None) + "\n```"
    got = ls.parse_siding_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in ls.QUESTION_IDS}
    assert got["elevations"] == [] and got["counts"]["openings"] == 12


def test_parse_siding_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ls.parse_siding_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ls.parse_siding_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        ls.parse_siding_reading('{not json}', 4)


@pytest.mark.parametrize("field,bad", [
    ("openings", None), ("outside_corners", -1), ("inside_corners", 2.5),
    ("openings", "12"), ("outside_corners", True), ("inside_corners", 1.0),
])
def test_parse_siding_reading_rejects_bad_counts(field, bad):
    """Every defect names the field, so the AI Log says which count was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        ls.parse_siding_reading(_reading(4, **{field: bad}), 4)


@pytest.mark.parametrize("over,field", [
    ({"elevations": [{"name": "Front", "width_ft": "40 ft", "height_ft": "9'-0\""}]}, "Front width"),
    ({"elevations": [{"name": "Rear", "width_ft": "40'-0\"", "height_ft": "nine feet"}]}, "Rear height"),
])
def test_parse_siding_reading_rejects_bad_dimensions(over, field):
    """A dimension the AI hedged on rejects the whole answer, naming the field."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        ls.parse_siding_reading(_reading(4, **over), 4)


def test_parse_siding_reading_rejects_bad_shapes():
    with pytest.raises(lt.LlmTakeoffError, match="elevations"):
        ls.parse_siding_reading(_reading(4, elevations={"name": "Front"}), 4)
    with pytest.raises(lt.LlmTakeoffError, match="elevations"):
        ls.parse_siding_reading(_reading(4, elevations=["40'-0\" x 9'-0\""]), 4)
    with pytest.raises(lt.LlmTakeoffError, match="height_ft"):
        ls.parse_siding_reading(_reading(4, elevations=[{"name": "Front", "width_ft": "40'-0\""}]), 4)


def test_parse_siding_reading_rejects_missing_count():
    d = json.loads(_reading(4))
    del d["inside_corners"]
    with pytest.raises(lt.LlmTakeoffError, match="inside_corners"):
        ls.parse_siding_reading(json.dumps(d), 4)


def test_parse_siding_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = ls.parse_siding_reading(_reading(9), 4)
    assert got["siding_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_siding_classification():
    assert ls.parse_siding_classification('{"siding_sheet_id": 4, "notes": "elevations"}', [4, 5]) == (4, "elevations")
    assert ls.parse_siding_classification('{"siding_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert ls.parse_siding_classification('{"siding_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ls.parse_siding_classification("nope", [4])


# ------------------------------------------------------------------ the quantities: the app's maths

def test_quantities_from_reading_maths():
    """Areas and lengths come from the printed dimensions, to 0.01 - the AI never computes."""
    reading = _parsed(4, elevations=[{"name": "Gable", "width_ft": "20'-0\"", "height_ft": "6'-8\""}],
                      openings=0, outside_corners=0, inside_corners=0)
    # gable 20 x 6.666.. = 133.33; eaves 20.00 lf.
    assert ls.quantities_from_reading(reading) == {"values": {
        "wall_sqft": "133.33", "openings": 0, "outside_corners": 0, "inside_corners": 0,
        "eave_lf": "20.00"}}


def test_quantities_from_reading_all_empty():
    reading = _parsed(4, elevations=[], openings=0, outside_corners=0, inside_corners=0)
    assert ls.quantities_from_reading(reading) == {"values": {
        "wall_sqft": "0.00", "openings": 0, "outside_corners": 0, "inside_corners": 0,
        "eave_lf": "0.00"}}


# ------------------------------------------------------------------ the quantity measurements

def test_create_measurements_proposes_one_per_nonzero_quantity(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = ls.quantities_from_reading(reading)
    assert quantities == {"values": dict(VALUES)}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", ls.SPEC)
    assert len(ids) == 5
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["wall_sqft", "openings", "outside_corners",
                                          "inside_corners", "eave_lf"]
    kinds = {"wall_sqft": ("area", "sqft"), "openings": ("count", "ea"),
             "outside_corners": ("count", "ea"), "inside_corners": ("count", "ea"),
             "eave_lf": ("length", "lf")}
    for r in rows:
        assert r["module_id"] == "siding" and (r["kind"], r["unit"]) == kinds[r["feeds"]]
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == ls.LABELS[r["feeds"]] + " (AI)"
        assert r["qty"] == str(VALUES[r["feeds"]])
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["siding_sheet_id"] == plans["s1"]
        assert calc["values"]["wall_sqft"] == "1260.00" and calc["values"]["openings"] == "12"
        assert calc["values"]["eave_lf"] == "140.00"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "elevations clear on the plan"


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], elevations=[], openings=0, outside_corners=0, inside_corners=0)
    quantities = ls.quantities_from_reading(reading)
    assert quantities["values"] == {"wall_sqft": "0.00", "openings": 0, "outside_corners": 0,
                                    "inside_corners": 0, "eave_lf": "0.00"}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", ls.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_siding_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "elevations" in fake.calls[0]["system"].lower()
    assert "eaves run the full width" in fake.calls[0]["user"] and "never null" in fake.calls[0]["user"]
    assert "never compute" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert steps == ["finding the elevations sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == dict(VALUES)
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm", "values": dict(VALUES),
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "elevations clear on the plan", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the Siding quantities on sheet %d (1260.00 sq ft of outside wall,"
                              " 12 openings, 4 outside corners, 2 inside corners, 140.00 lf of eaves);"
                              " measurements %s" % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 5
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_siding_rules_settle_on_the_elevations_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a101.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second elevations sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "a202.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'A-202', 'ELEVATIONS', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'A-101', 'FLOOR PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_siding_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"siding_sheet_id": s2, "notes": "the elevations are on A-202"}),
        _reading(s2),
    ]
    out = ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                       # classify, then the read
    assert len(fake.calls[0]["images"]) == 2          # thumbnails of both elevations sheets
    assert "elevations" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 5


def test_run_llm_siding_fails_when_the_ai_cannot_find_the_elevations_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"siding_sheet_id": None, "notes": "no elevations seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the elevations sheet"):
        ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_siding_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "AI measuring is off" in str(exc.value) and "read the Siding plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_siding_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_siding_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'siding', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Siding"):
        ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_siding_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_siding_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], openings=2.5)]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="openings"):
        ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_siding_bad_dimension_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(
        plans["s1"], elevations=[{"name": "Front", "width_ft": "40 ft", "height_ft": "9'-0\""}])]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="Front width"):
        ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_siding_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_siding_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = ls.run_llm_siding(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = ls.siding_results(db, CTX, row)
    assert len(got["lines"]) == 5
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["wall_sqft"] == {"id": out["measurement_ids"][0], "label": "Outside wall area (all sides) (AI)",
                                     "feeds": "wall_sqft", "qty": "1260.00", "unit": "sqft",
                                     "status": "proposed", "how": EVIDENCE["wall_sqft"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(ls.QUESTION_IDS)         # all five questions, zeros included
    assert items["wall_sqft"] == {"feeds": "wall_sqft", "label": "Outside wall area (all sides)",
                                  "qty": "1260.00", "unit": "sqft", "evidence": EVIDENCE["wall_sqft"]}
    assert items["openings"] == {"feeds": "openings", "label": "Windows and doors in those walls",
                                 "qty": 12, "unit": "ea", "evidence": EVIDENCE["openings"]}
    assert items["eave_lf"] == {"feeds": "eave_lf", "label": "Eaves (soffit and fascia)",
                                "qty": "140.00", "unit": "lf", "evidence": EVIDENCE["eave_lf"]}
    assert got["quantities"]["trade"] == "siding" and got["quantities"]["label"] == "Siding"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "elevations clear on the plan"


def test_siding_results_all_zero_quantities(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm",
            "values": {"wall_sqft": "0.00", "openings": 0, "outside_corners": 0, "inside_corners": 0,
                       "eave_lf": "0.00"},
            "evidence": dict(EVIDENCE), "confidence": 0.8, "notes": "empty plan",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = ls.siding_results(db, CTX, row)
    assert got["lines"] == []
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["wall_sqft"]["qty"] == "0.00" and items["openings"]["qty"] == 0
    assert items["eave_lf"]["qty"] == "0.00"
    assert got["quantities"]["items"][0]["evidence"] == EVIDENCE["wall_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_siding_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert ls.siding_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_siding_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], inside_corners=0)
    ids = lq.create_measurements(db, CTX, run, reading, ls.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", ls.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = ls.siding_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["wall_sqft"]["qty"] == "1260.00" and items["openings"]["qty"] == 12
    assert items["inside_corners"]["qty"] == 0        # no row, no candidate: the plain zero
    assert items["wall_sqft"]["evidence"] == EVIDENCE["wall_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
