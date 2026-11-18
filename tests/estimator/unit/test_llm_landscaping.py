"""LLM-assisted landscaping takeoff: parsing, the quantity measurements, the run, the results.

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
from estimator.takeoff import llm_landscaping as ll
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
    """An estimate with one plan set: a single landscape sheet (L-1) with a rendered
    image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Landscaping job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "l1.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'L-1', 'LANDSCAPE PLAN', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Landscape plan', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "landscaping", [])


# sod 20x30 (600) + 10x15.5 (155) = 755; rock printed 450; pavers 12x14 = 168;
# edging 85 + 40.5 = 125.50 lf; no clear or turf zones.
ZONES = [{"name": "Front lawn", "material": "sod", "width_ft": "20'-0\"", "length_ft": "30'-0\""},
         {"name": "Side strip", "material": "sod", "width_ft": "10'-0\"", "length_ft": "15'-6\""},
         {"name": "Backyard rock", "material": "rock", "area_sqft": 450},
         {"name": "Patio", "material": "pavers", "width_ft": "12'-0\"", "length_ft": "14'-0\""}]

EDGING_RUNS = [{"length_ft": "85'-0\""}, {"length_ft": "40'-6\""}]

EVIDENCE = {"clear_sqft": "no clearing shown - the yard is bare dirt",
            "sod_sqft": "front lawn and side strip, dimensioned on the planting plan",
            "turf_sqft": "no artificial turf shown",
            "rock_sqft": "backyard rock area printed as 450 sq ft",
            "pavers_sqft": "patio, dimensioned on the plan",
            "shrubs": "12 shrub symbols on the planting plan",
            "trees": "3 tree symbols",
            "drip_zones": "2 drip zones on the irrigation legend",
            "sprinkler_zones": "1 sprinkler zone on the irrigation legend",
            "edging_lf": "edging runs 85'-0\" + 40'-6\" around the beds"}


def _reading(sheet_id, **over):
    out = {"landscaping_sheet_id": sheet_id, "zones": [dict(z) for z in ZONES],
           "shrubs": 12, "trees": 3, "drip_zones": 2, "sprinkler_zones": 1,
           "edging_runs": [dict(r) for r in EDGING_RUNS],
           "confidence": 0.9, "notes": "landscape areas clear on the plan", "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return ll.parse_landscaping_reading(_reading(sheet_id, **over), sheet_id)


VALUES = {"clear_sqft": "0.00", "sod_sqft": "755.00", "turf_sqft": "0.00", "rock_sqft": "450.00",
          "pavers_sqft": "168.00", "shrubs": 12, "trees": 3, "drip_zones": 2, "sprinkler_zones": 1,
          "edging_lf": "125.50"}


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_landscaping_reading_full():
    got = ll.parse_landscaping_reading(_reading(4), 4)
    assert got == {"landscaping_sheet_id": 4,
                   "zones": [{"name": "Front lawn", "material": "sod",
                              "width_ft": "20'-0\"", "length_ft": "30'-0\""},
                             {"name": "Side strip", "material": "sod",
                              "width_ft": "10'-0\"", "length_ft": "15'-6\""},
                             {"name": "Backyard rock", "material": "rock", "area_sqft": "450"},
                             {"name": "Patio", "material": "pavers",
                              "width_ft": "12'-0\"", "length_ft": "14'-0\""}],
                   "counts": {"shrubs": 12, "trees": 3, "drip_zones": 2, "sprinkler_zones": 1},
                   "edging_runs": [{"name": "", "length_ft": "85'-0\""}, {"name": "", "length_ft": "40'-6\""}],
                   "evidence": dict(EVIDENCE), "confidence": 0.9, "notes": "landscape areas clear on the plan"}


def test_parse_landscaping_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, confidence=None, evidence=None) + "\n```"
    got = ll.parse_landscaping_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in ll.IDS}
    assert got["counts"]["shrubs"] == 12


def test_parse_landscaping_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ll.parse_landscaping_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ll.parse_landscaping_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        ll.parse_landscaping_reading('{not json}', 4)


@pytest.mark.parametrize("field,bad", [
    ("shrubs", None), ("trees", -1), ("drip_zones", 2.5), ("sprinkler_zones", "3"), ("shrubs", True),
])
def test_parse_landscaping_reading_rejects_bad_counts(field, bad):
    """Every defect names the field, so the AI Log says which count was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        ll.parse_landscaping_reading(_reading(4, **{field: bad}), 4)


def test_parse_landscaping_reading_rejects_missing_count():
    d = json.loads(_reading(4))
    del d["trees"]
    with pytest.raises(lt.LlmTakeoffError, match="trees"):
        ll.parse_landscaping_reading(json.dumps(d), 4)


def test_parse_landscaping_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = ll.parse_landscaping_reading(_reading(9), 4)
    assert got["landscaping_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_landscaping_classification():
    assert ll.parse_landscaping_classification('{"landscaping_sheet_id": 4, "notes": "planting"}', [4, 5]) == (4, "planting")
    assert ll.parse_landscaping_classification('{"landscaping_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert ll.parse_landscaping_classification('{"landscaping_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        ll.parse_landscaping_classification("nope", [4])


# ------------------------------------------------------------------ the zone rules

def _zeroed(**over):
    """A reading with no counts and no edging, so one zone rule can be checked alone."""
    base = {"zones": [], "shrubs": 0, "trees": 0, "drip_zones": 0, "sprinkler_zones": 0,
            "edging_runs": []}
    base.update(over)
    return _parsed(4, **base)


def test_zones_printed_area_used_as_is():
    reading = _zeroed(zones=[{"material": "rock", "area_sqft": 450}])
    values = ll.quantities_from_reading(reading)["values"]
    assert values["rock_sqft"] == "450.00"
    assert values["sod_sqft"] == "0.00"


def test_zones_printed_area_wins_over_dimensions():
    """A zone with both a printed area and dimensions uses the printed area, not 20x30."""
    reading = _zeroed(zones=[{"material": "sod", "area_sqft": 100,
                              "width_ft": "20'-0\"", "length_ft": "30'-0\""}])
    assert ll.quantities_from_reading(reading)["values"]["sod_sqft"] == "100.00"


def test_zones_null_area_uses_dimensions():
    reading = _zeroed(zones=[{"material": "turf", "area_sqft": None,
                              "width_ft": "10'-0\"", "length_ft": "10'-0\""}])
    assert ll.quantities_from_reading(reading)["values"]["turf_sqft"] == "100.00"


def test_zones_reject_bad_material():
    with pytest.raises(lt.LlmTakeoffError, match="material"):
        _zeroed(zones=[{"material": "grass", "width_ft": "10'-0\"", "length_ft": "10'-0\""}])


def test_zones_reject_missing_material():
    with pytest.raises(lt.LlmTakeoffError, match="material"):
        _zeroed(zones=[{"width_ft": "10'-0\"", "length_ft": "10'-0\""}])


def test_zones_reject_zone_with_neither_area_nor_dimensions():
    """A zone with no printed area and no dimensions names the zone and the missing side."""
    with pytest.raises(lt.LlmTakeoffError, match=r"zones\[0\] width_ft"):
        _zeroed(zones=[{"material": "sod"}])


def test_zones_reject_negative_area():
    with pytest.raises(lt.LlmTakeoffError, match="area_sqft"):
        _zeroed(zones=[{"material": "rock", "area_sqft": -5}])


def test_zones_reject_text_area():
    with pytest.raises(lt.LlmTakeoffError, match="area_sqft"):
        _zeroed(zones=[{"material": "rock", "area_sqft": "450"}])


def test_zones_reject_bad_dimension():
    with pytest.raises(lt.LlmTakeoffError, match=r"zones\[0\] width"):
        _zeroed(zones=[{"material": "sod", "width_ft": "wide", "length_ft": "30'-0\""}])


def test_zones_reject_zones_not_a_list():
    with pytest.raises(lt.LlmTakeoffError, match="zones"):
        _zeroed(zones={"material": "sod"})


def test_parse_landscaping_reading_rejects_bad_edging_run():
    with pytest.raises(lt.LlmTakeoffError, match="edging_runs"):
        ll.parse_landscaping_reading(_reading(4, edging_runs=[{"length_ft": "long"}]), 4)


# ------------------------------------------------------------------ the app's maths (never the AI's)

def test_quantities_sum_zones_per_material():
    """Sod 20x30 (600) + 10x10 (100) is 700; turf's printed 250.5 is used as-is."""
    reading = _zeroed(zones=[{"material": "sod", "width_ft": "20'-0\"", "length_ft": "30'-0\""},
                             {"material": "sod", "width_ft": "10'-0\"", "length_ft": "10'-0\""},
                             {"material": "turf", "area_sqft": 250.5}])
    values = ll.quantities_from_reading(reading)["values"]
    assert values["sod_sqft"] == "700.00" and values["turf_sqft"] == "250.50"
    assert values["clear_sqft"] == "0.00" and values["rock_sqft"] == "0.00"


def test_quantities_edging_adds_the_runs_up():
    """45'-7\" + 10'-5\" is 672 inches, 56 ft exactly - the app's maths, not the AI's."""
    reading = _zeroed(edging_runs=[{"length_ft": "45'-7\""}, {"length_ft": "10'-5\""}])
    assert ll.quantities_from_reading(reading)["values"]["edging_lf"] == "56.00"


def test_quantities_empty_is_zero():
    reading = _zeroed()
    assert ll.quantities_from_reading(reading)["values"] == {
        "clear_sqft": "0.00", "sod_sqft": "0.00", "turf_sqft": "0.00", "rock_sqft": "0.00",
        "pavers_sqft": "0.00", "shrubs": 0, "trees": 0, "drip_zones": 0, "sprinkler_zones": 0,
        "edging_lf": "0.00"}


# ------------------------------------------------------------------ the quantity measurements

KIND_UNIT = {"clear_sqft": ("area", "sqft"), "sod_sqft": ("area", "sqft"), "turf_sqft": ("area", "sqft"),
             "rock_sqft": ("area", "sqft"), "pavers_sqft": ("area", "sqft"),
             "shrubs": ("count", "ea"), "trees": ("count", "ea"),
             "drip_zones": ("count", "ea"), "sprinkler_zones": ("count", "ea"),
             "edging_lf": ("length", "lf")}


def test_create_measurements_proposes_one_per_nonzero_quantity(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = ll.quantities_from_reading(reading)
    assert quantities == {"values": dict(VALUES)}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", ll.SPEC)
    assert len(ids) == 8                              # clear_sqft and turf_sqft are 0: no rows
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["sod_sqft", "rock_sqft", "pavers_sqft", "shrubs", "trees",
                                          "drip_zones", "sprinkler_zones", "edging_lf"]
    for r in rows:
        kind, unit = KIND_UNIT[r["feeds"]]
        assert r["module_id"] == "landscaping" and r["kind"] == kind and r["unit"] == unit
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == ll.LABELS[r["feeds"]] + " (AI)"
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["landscaping_sheet_id"] == plans["s1"]
        assert calc["values"]["sod_sqft"] == "755.00" and calc["values"]["clear_sqft"] == "0.00"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "landscape areas clear on the plan"


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], zones=[], shrubs=0, trees=0, drip_zones=0, sprinkler_zones=0,
                      edging_runs=[])
    quantities = ll.quantities_from_reading(reading)
    assert quantities["values"] == {"clear_sqft": "0.00", "sod_sqft": "0.00", "turf_sqft": "0.00",
                                    "rock_sqft": "0.00", "pavers_sqft": "0.00", "shrubs": 0, "trees": 0,
                                    "drip_zones": 0, "sprinkler_zones": 0, "edging_lf": "0.00"}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", ll.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_landscaping_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "landscape areas" in fake.calls[0]["system"].lower()
    assert "never null" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert steps == ["finding the landscape sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == dict(VALUES)
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm", "values": dict(VALUES),
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "landscape areas clear on the plan", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the Landscaping quantities on sheet %d (755.00 sq ft of sod,"
                              " 450.00 sq ft of rock, 168.00 sq ft of pavers, 12 shrubs, 3 trees,"
                              " 2 drip zones, 1 sprinkler zones, 125.50 lf of edging);"
                              " measurements %s" % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 8
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_landscaping_rules_settle_on_the_landscape_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a101.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second landscape sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "l2.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'L-2', 'LANDSCAPE PLAN', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'A-101', 'FLOOR PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_landscaping_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"landscaping_sheet_id": s2, "notes": "the planting is on L-2"}),
        _reading(s2),
    ]
    out = ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                       # classify, then the read
    assert len(fake.calls[0]["images"]) == 2          # thumbnails of both landscape sheets
    assert "landscape plan" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 8


def test_run_llm_landscaping_fails_when_the_ai_cannot_find_the_landscape_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"landscaping_sheet_id": None, "notes": "no planting seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the landscape sheet"):
        ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_landscaping_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "LLM takeoff is off" in str(exc.value) and "read the Landscaping plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_landscaping_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_landscaping_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'landscaping', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Landscaping"):
        ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_landscaping_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_landscaping_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], shrubs=2.5)]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="shrubs"):
        ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_landscaping_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_landscaping_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = ll.run_llm_landscaping(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = ll.landscaping_results(db, CTX, row)
    assert len(got["lines"]) == 8
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["sod_sqft"] == {"id": out["measurement_ids"][0], "label": "Sod (AI)",
                                    "feeds": "sod_sqft", "qty": "755.00", "unit": "sqft", "status": "proposed",
                                    "how": EVIDENCE["sod_sqft"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(ll.IDS)                    # all ten questions, zeros included
    assert items["sod_sqft"] == {"feeds": "sod_sqft", "label": "Sod", "qty": "755.00",
                                 "unit": "sqft", "evidence": EVIDENCE["sod_sqft"]}
    assert items["clear_sqft"] == {"feeds": "clear_sqft",
                                   "label": "Area to clear and haul (old grass, rock, weeds)",
                                   "qty": "0.00", "unit": "sqft",
                                   "evidence": EVIDENCE["clear_sqft"]}   # zero: the candidate's evidence
    assert items["edging_lf"] == {"feeds": "edging_lf", "label": "Landscape edging or curbing",
                                  "qty": "125.50", "unit": "lf", "evidence": EVIDENCE["edging_lf"]}
    assert got["quantities"]["trade"] == "landscaping" and got["quantities"]["label"] == "Landscaping"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "landscape areas clear on the plan"


def test_landscaping_results_all_zero_quantities(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm",
            "values": {"clear_sqft": "0.00", "sod_sqft": "0.00", "turf_sqft": "0.00",
                       "rock_sqft": "0.00", "pavers_sqft": "0.00", "shrubs": 0, "trees": 0,
                       "drip_zones": 0, "sprinkler_zones": 0, "edging_lf": "0.00"},
            "evidence": dict(EVIDENCE), "confidence": 0.8, "notes": "empty plan",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = ll.landscaping_results(db, CTX, row)
    assert got["lines"] == []
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["sod_sqft"]["qty"] == "0.00" and items["edging_lf"]["qty"] == "0.00"
    assert items["shrubs"]["qty"] == 0 and items["trees"]["qty"] == 0
    assert got["quantities"]["items"][0]["evidence"] == EVIDENCE["clear_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_landscaping_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert ll.landscaping_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_landscaping_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    ids = lq.create_measurements(db, CTX, run, reading, ll.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", ll.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = ll.landscaping_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["sod_sqft"]["qty"] == "755.00" and items["shrubs"]["qty"] == 12
    assert items["clear_sqft"]["qty"] == 0 and items["turf_sqft"]["qty"] == 0   # no rows: zero
    assert items["sod_sqft"]["evidence"] == EVIDENCE["sod_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
