"""LLM-assisted painting takeoff: parsing, the quantity measurements, the run, the results.

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
from estimator.takeoff import llm_painting as lpa
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
    """An estimate with one plan set: a single finish sheet (A-101) with a rendered
    image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Painting job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "a101.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'A-101', 'FINISH PLAN', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Finish plan', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "painting", [])


# Living 14.5x18 = 261 sq ft, 65 lf; Bedroom 12x12 = 144 sq ft, 48 lf:
# ceiling 405.00, trim 113.00. Front + rear 40x9 = 360 each: exterior 720.00.
ROOMS = [{"name": "Living room", "width_ft": "14'-6\"", "length_ft": "18'-0\""},
         {"name": "Bedroom", "width_ft": "12'-0\"", "length_ft": "12'-0\""}]

ELEVATIONS = [{"name": "Front", "width_ft": "40'-0\"", "height_ft": "9'-0\""},
              {"name": "Rear", "width_ft": "40'-0\"", "height_ft": "9'-0\""}]

EVIDENCE = {"ceiling_sqft": "room dimensions from the finish schedule",
            "exterior_sqft": "front and rear elevations, 40 ft wide by 9 ft high",
            "trim_lf": "room perimeters from the finish schedule",
            "doors": "8 door symbols on the floor plan"}


def _reading(sheet_id, **over):
    out = {"painting_sheet_id": sheet_id, "rooms": [dict(r) for r in ROOMS],
           "elevations": [dict(e) for e in ELEVATIONS], "doors": 8,
           "confidence": 0.9, "notes": "rooms and elevations clear on the finish sheet",
           "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return lpa.parse_painting_reading(_reading(sheet_id, **over), sheet_id)


VALUES = {"ceiling_sqft": "405.00", "exterior_sqft": "720.00", "trim_lf": "113.00", "doors": 8}


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_painting_reading_full():
    got = lpa.parse_painting_reading(_reading(4), 4)
    assert got == {"painting_sheet_id": 4,
                   "rooms": [{"name": "Living room", "width_ft": "14'-6\"", "length_ft": "18'-0\""},
                             {"name": "Bedroom", "width_ft": "12'-0\"", "length_ft": "12'-0\""}],
                   "elevations": [{"name": "Front", "width_ft": "40'-0\"", "height_ft": "9'-0\""},
                                  {"name": "Rear", "width_ft": "40'-0\"", "height_ft": "9'-0\""}],
                   "counts": {"doors": 8},
                   "evidence": dict(EVIDENCE), "confidence": 0.9,
                   "notes": "rooms and elevations clear on the finish sheet"}


def test_parse_painting_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, confidence=None, evidence=None) + "\n```"
    got = lpa.parse_painting_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in lpa.IDS}
    assert got["counts"]["doors"] == 8


def test_parse_painting_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lpa.parse_painting_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lpa.parse_painting_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        lpa.parse_painting_reading('{not json}', 4)


@pytest.mark.parametrize("field,bad", [
    ("doors", None), ("doors", -1), ("doors", 2.5), ("doors", "3"), ("doors", True),
])
def test_parse_painting_reading_rejects_bad_counts(field, bad):
    """Every defect names the field, so the AI Log says which count was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        lpa.parse_painting_reading(_reading(4, **{field: bad}), 4)


def test_parse_painting_reading_rejects_missing_count():
    d = json.loads(_reading(4))
    del d["doors"]
    with pytest.raises(lt.LlmTakeoffError, match="doors"):
        lpa.parse_painting_reading(json.dumps(d), 4)


def test_parse_painting_reading_rejects_bad_room_dimension():
    with pytest.raises(lt.LlmTakeoffError, match="width"):
        lpa.parse_painting_reading(_reading(4, rooms=[{"name": "Living room", "width_ft": "big",
                                                       "length_ft": "18'-0\""}]), 4)


def test_parse_painting_reading_rejects_room_missing_length():
    with pytest.raises(lt.LlmTakeoffError, match="length_ft"):
        lpa.parse_painting_reading(_reading(4, rooms=[{"name": "Living room",
                                                       "width_ft": "14'-6\""}]), 4)


def test_parse_painting_reading_rejects_rooms_not_a_list():
    with pytest.raises(lt.LlmTakeoffError, match="rooms"):
        lpa.parse_painting_reading(_reading(4, rooms="14x18"), 4)


def test_parse_painting_reading_rejects_bad_elevation_dimension():
    with pytest.raises(lt.LlmTakeoffError, match=r"elevations\[0\] height"):
        lpa.parse_painting_reading(_reading(4, elevations=[{"width_ft": "40'-0\"",
                                                            "height_ft": "tall"}]), 4)


def test_parse_painting_reading_rejects_elevation_missing_height():
    with pytest.raises(lt.LlmTakeoffError, match="height_ft"):
        lpa.parse_painting_reading(_reading(4, elevations=[{"width_ft": "40'-0\""}]), 4)


def test_parse_painting_reading_rejects_elevations_not_a_list():
    with pytest.raises(lt.LlmTakeoffError, match="elevations"):
        lpa.parse_painting_reading(_reading(4, elevations="40x9"), 4)


def test_parse_painting_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = lpa.parse_painting_reading(_reading(9), 4)
    assert got["painting_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_painting_classification():
    assert lpa.parse_painting_classification('{"painting_sheet_id": 4, "notes": "finishes"}', [4, 5]) == (4, "finishes")
    assert lpa.parse_painting_classification('{"painting_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert lpa.parse_painting_classification('{"painting_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lpa.parse_painting_classification("nope", [4])


# ------------------------------------------------------------------ the app's maths (never the AI's)

def test_quantities_rooms_area_and_perimeter():
    """One 10'-6\" x 10'-6\" room: 10.5 x 10.5 = 110.25 sq ft, (10.5 + 10.5) x 2 = 42 lf."""
    reading = _parsed(4, rooms=[{"name": "Den", "width_ft": "10'-6\"", "length_ft": "10'-6\""}],
                      elevations=[], doors=0)
    values = lpa.quantities_from_reading(reading)["values"]
    assert values["ceiling_sqft"] == "110.25" and values["trim_lf"] == "42.00"
    assert values["exterior_sqft"] == "0.00"


def test_quantities_fractional_inches():
    """45'-7\" x 46'-7\" is 547 x 559 inches: 305773 sq in / 144 = 2123.42 sq ft,
    (547 + 559) x 2 / 12 = 184.33 lf."""
    reading = _parsed(4, rooms=[{"name": "Slab", "width_ft": "45'-7\"", "length_ft": "46'-7\""}],
                      elevations=[], doors=0)
    values = lpa.quantities_from_reading(reading)["values"]
    assert values["ceiling_sqft"] == "2123.42" and values["trim_lf"] == "184.33"


def test_quantities_elevations_area():
    """One 40'-0\" x 9'-0\" elevation is 360 sq ft."""
    reading = _parsed(4, rooms=[], elevations=[{"name": "Front", "width_ft": "40'-0\"",
                                                "height_ft": "9'-0\""}], doors=0)
    values = lpa.quantities_from_reading(reading)["values"]
    assert values["exterior_sqft"] == "360.00"
    assert values["ceiling_sqft"] == "0.00" and values["trim_lf"] == "0.00"


def test_quantities_empty_is_zero():
    reading = _parsed(4, rooms=[], elevations=[], doors=0)
    assert lpa.quantities_from_reading(reading) == {
        "values": {"ceiling_sqft": "0.00", "exterior_sqft": "0.00", "trim_lf": "0.00", "doors": 0}}


# ------------------------------------------------------------------ the quantity measurements

KIND_UNIT = {"ceiling_sqft": ("area", "sqft"), "exterior_sqft": ("area", "sqft"),
             "trim_lf": ("length", "lf"), "doors": ("count", "ea")}


def test_create_measurements_proposes_one_per_nonzero_quantity(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = lpa.quantities_from_reading(reading)
    assert quantities == {"values": dict(VALUES)}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", lpa.SPEC)
    assert len(ids) == 4
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["ceiling_sqft", "exterior_sqft", "trim_lf", "doors"]
    for r in rows:
        kind, unit = KIND_UNIT[r["feeds"]]
        assert r["module_id"] == "painting" and r["kind"] == kind and r["unit"] == unit
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == lpa.LABELS[r["feeds"]] + " (AI)"
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["painting_sheet_id"] == plans["s1"]
        assert calc["values"]["ceiling_sqft"] == "405.00" and calc["values"]["doors"] == "8"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "rooms and elevations clear on the finish sheet"


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], rooms=[], elevations=[], doors=0)
    quantities = lpa.quantities_from_reading(reading)
    assert quantities["values"] == {"ceiling_sqft": "0.00", "exterior_sqft": "0.00",
                                    "trim_lf": "0.00", "doors": 0}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", lpa.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_painting_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "areas to paint" in fake.calls[0]["system"].lower()
    assert "never null" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert steps == ["finding the finish sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == dict(VALUES)
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm", "values": dict(VALUES),
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "rooms and elevations clear on the finish sheet",
                                "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the Painting quantities on sheet %d (405.00 sq ft of ceiling,"
                              " 720.00 sq ft of exterior wall, 113.00 lf of trim, 8 doors);"
                              " measurements %s" % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 4
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_painting_rules_settle_on_the_finish_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "s1.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'S-1', 'FOUNDATION PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second finish sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "a102.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'A-102', 'FINISH PLAN', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'S-1', 'FOUNDATION PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Foundation plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_painting_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"painting_sheet_id": s2, "notes": "the finishes are on A-102"}),
        _reading(s2),
    ]
    out = lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                       # classify, then the read
    assert len(fake.calls[0]["images"]) == 2          # thumbnails of both finish sheets
    assert "finishes" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 4


def test_run_llm_painting_fails_when_the_ai_cannot_find_the_finish_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"painting_sheet_id": None, "notes": "no finishes seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the finish sheet"):
        lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_painting_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "LLM takeoff is off" in str(exc.value) and "read the Painting plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_painting_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_painting_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'painting', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Painting"):
        lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_painting_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_painting_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], doors=2.5)]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="doors"):
        lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_painting_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_painting_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lpa.run_llm_painting(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = lpa.painting_results(db, CTX, row)
    assert len(got["lines"]) == 4
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["ceiling_sqft"] == {"id": out["measurement_ids"][0], "label": "Ceiling area (AI)",
                                        "feeds": "ceiling_sqft", "qty": "405.00", "unit": "sqft",
                                        "status": "proposed", "how": EVIDENCE["ceiling_sqft"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(lpa.IDS)                   # all four questions, zeros included
    assert items["ceiling_sqft"] == {"feeds": "ceiling_sqft", "label": "Ceiling area", "qty": "405.00",
                                     "unit": "sqft", "evidence": EVIDENCE["ceiling_sqft"]}
    assert items["doors"] == {"feeds": "doors", "label": "Doors (both sides)", "qty": 8,
                              "unit": "ea", "evidence": EVIDENCE["doors"]}
    assert got["quantities"]["trade"] == "painting" and got["quantities"]["label"] == "Painting"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "rooms and elevations clear on the finish sheet"


def test_painting_results_all_zero_quantities(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm",
            "values": {"ceiling_sqft": "0.00", "exterior_sqft": "0.00", "trim_lf": "0.00", "doors": 0},
            "evidence": dict(EVIDENCE), "confidence": 0.8, "notes": "empty plan",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = lpa.painting_results(db, CTX, row)
    assert got["lines"] == []
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["ceiling_sqft"]["qty"] == "0.00" and items["trim_lf"]["qty"] == "0.00"
    assert items["doors"]["qty"] == 0
    assert got["quantities"]["items"][0]["evidence"] == EVIDENCE["ceiling_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_painting_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert lpa.painting_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_painting_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], doors=0)
    ids = lq.create_measurements(db, CTX, run, reading, lpa.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", lpa.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = lpa.painting_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["ceiling_sqft"]["qty"] == "405.00" and items["trim_lf"]["qty"] == "113.00"
    assert items["doors"]["qty"] == 0                   # no row: the quantity is zero
    assert items["ceiling_sqft"]["evidence"] == EVIDENCE["ceiling_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
