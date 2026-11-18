"""LLM-assisted drywall takeoff: parsing, the quantity measurements, the run, the results.

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
from estimator.takeoff import llm_drywall as lw
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
    """An estimate with one plan set: a single floor plan sheet (A-101) with a rendered
    image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Drywall job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "a101.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'A-101', 'FLOOR PLAN', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Floor plan', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "drywall", [])


# Living room 14 x 20 = 280.00, bedroom 12 x 12 = 144.00: ceiling 424.00.
ROOMS = [{"name": "Living room", "width_ft": "14'-0\"", "length_ft": "20'-0\""},
         {"name": "Bedroom", "width_ft": "12'-0\"", "length_ft": "12'-0\""}]
# Window 3 x 4 = 12.00, door 3 x 6.666.. = 20.00: openings 32.00.
OPENINGS = [{"name": "Window W-1", "width_ft": "3'-0\"", "height_ft": "4'-0\""},
            {"name": "Door D-1", "width_ft": "3'-0\"", "height_ft": "6'-8\""}]

EVIDENCE = {"ceiling_sqft": "living room and bedroom, 14 x 20 and 12 x 12",
            "openings_sqft": "schedule: W-1 3 x 4, D-1 3 x 6-8"}


def _reading(sheet_id, **over):
    out = {"drywall_sheet_id": sheet_id, "rooms": ROOMS, "openings": OPENINGS,
           "confidence": 0.9, "notes": "rooms and schedule clear on the plan",
           "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return lw.parse_drywall_reading(_reading(sheet_id, **over), sheet_id)


VALUES = {"ceiling_sqft": "424.00", "openings_sqft": "32.00"}


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_drywall_reading_full():
    got = lw.parse_drywall_reading(_reading(4), 4)
    assert got == {"drywall_sheet_id": 4, "rooms": ROOMS, "openings": OPENINGS,
                   "evidence": dict(EVIDENCE), "confidence": 0.9,
                   "notes": "rooms and schedule clear on the plan"}


def test_parse_drywall_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, rooms=None, openings=None,
                                  confidence=None, evidence=None) + "\n```"
    got = lw.parse_drywall_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in lw.QUESTION_IDS}
    assert got["rooms"] == [] and got["openings"] == []


def test_parse_drywall_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lw.parse_drywall_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lw.parse_drywall_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        lw.parse_drywall_reading('{not json}', 4)


@pytest.mark.parametrize("over,field", [
    ({"rooms": [{"name": "Living room", "width_ft": "14 ft", "length_ft": "20'-0\""}]},
     "Living room width"),
    ({"rooms": [{"name": "Living room", "width_ft": "14'-0\"", "length_ft": "twenty feet"}]},
     "Living room length"),
    ({"openings": [{"name": "Window W-1", "width_ft": "3", "height_ft": "4'-0\""}]},
     "Window W-1 width"),
    ({"openings": [{"name": "Door D-1", "width_ft": "3'-0\"", "height_ft": "tall"}]},
     "Door D-1 height"),
])
def test_parse_drywall_reading_rejects_bad_dimensions(over, field):
    """A dimension the AI hedged on rejects the whole answer, naming the field."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        lw.parse_drywall_reading(_reading(4, **over), 4)


def test_parse_drywall_reading_rejects_bad_shapes():
    with pytest.raises(lt.LlmTakeoffError, match="rooms"):
        lw.parse_drywall_reading(_reading(4, rooms={"name": "Living room"}), 4)
    with pytest.raises(lt.LlmTakeoffError, match="openings"):
        lw.parse_drywall_reading(_reading(4, openings=["3'-0\" x 4'-0\""]), 4)
    with pytest.raises(lt.LlmTakeoffError, match="height_ft"):
        lw.parse_drywall_reading(_reading(4, openings=[{"name": "Window W-1", "width_ft": "3'-0\""}]), 4)
    with pytest.raises(lt.LlmTakeoffError, match="length_ft"):
        lw.parse_drywall_reading(_reading(4, rooms=[{"name": "Bedroom", "width_ft": "12'-0\""}]), 4)


def test_parse_drywall_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = lw.parse_drywall_reading(_reading(9), 4)
    assert got["drywall_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_drywall_classification():
    assert lw.parse_drywall_classification('{"drywall_sheet_id": 4, "notes": "floor plan"}', [4, 5]) == (4, "floor plan")
    assert lw.parse_drywall_classification('{"drywall_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert lw.parse_drywall_classification('{"drywall_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lw.parse_drywall_classification("nope", [4])


# ------------------------------------------------------------------ the quantities: the app's maths

def test_quantities_from_reading_maths():
    """Areas come from the printed dimensions, to 0.01 - the AI never computes."""
    reading = _parsed(4, rooms=[{"name": "Den", "width_ft": "10'-0\"", "length_ft": "6'-8\""}],
                      openings=[{"name": "Window", "width_ft": "2'-6\"", "height_ft": "6'-8\""}])
    # den 10 x 6.666.. = 66.67; window 2.5 x 6.666.. = 16.67.
    assert lw.quantities_from_reading(reading) == {"values": {"ceiling_sqft": "66.67",
                                                              "openings_sqft": "16.67"}}


def test_quantities_from_reading_no_schedule_is_zero():
    """No window or door schedule on the plan: the openings area is 0.00."""
    reading = _parsed(4, openings=[],
                      evidence={"ceiling_sqft": EVIDENCE["ceiling_sqft"],
                                "openings_sqft": "no schedule on the plan"})
    assert lw.quantities_from_reading(reading) == {"values": {"ceiling_sqft": "424.00",
                                                              "openings_sqft": "0.00"}}
    assert reading["evidence"]["openings_sqft"] == "no schedule on the plan"


def test_quantities_from_reading_all_empty():
    reading = _parsed(4, rooms=[], openings=[])
    assert lw.quantities_from_reading(reading) == {"values": {"ceiling_sqft": "0.00",
                                                              "openings_sqft": "0.00"}}


# ------------------------------------------------------------------ the quantity measurements

def test_create_measurements_proposes_one_per_nonzero_quantity(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = lw.quantities_from_reading(reading)
    assert quantities == {"values": dict(VALUES)}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", lw.SPEC)
    assert len(ids) == 2
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["ceiling_sqft", "openings_sqft"]
    for r in rows:
        assert r["module_id"] == "drywall" and r["kind"] == "area" and r["unit"] == "sqft"
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == lw.LABELS[r["feeds"]] + " (AI)"
        assert r["qty"] == VALUES[r["feeds"]]
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["drywall_sheet_id"] == plans["s1"]
        assert calc["values"]["ceiling_sqft"] == "424.00" and calc["values"]["openings_sqft"] == "32.00"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "rooms and schedule clear on the plan"


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], rooms=[], openings=[])
    quantities = lw.quantities_from_reading(reading)
    assert quantities["values"] == {"ceiling_sqft": "0.00", "openings_sqft": "0.00"}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", lw.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_drywall_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "floor plan" in fake.calls[0]["system"].lower()
    assert "window and door schedule" in fake.calls[0]["user"] and "never null" in fake.calls[0]["user"]
    assert "never compute" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert steps == ["finding the drywall sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == dict(VALUES)
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm", "values": dict(VALUES),
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "rooms and schedule clear on the plan", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the Drywall quantities on sheet %d (424.00 sq ft of ceiling,"
                              " 32.00 sq ft of openings); measurements %s"
                              % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 2
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_drywall_rules_settle_on_the_drywall_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a201.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-201', 'ELEVATIONS', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second floor plan sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "a102.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'A-102', 'FLOOR PLAN', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'A-201', 'ELEVATIONS')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Elevations', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_drywall_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"drywall_sheet_id": s2, "notes": "the rooms are dimensioned on A-102"}),
        _reading(s2),
    ]
    out = lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                       # classify, then the read
    assert len(fake.calls[0]["images"]) == 2          # thumbnails of both floor plan sheets
    assert "floor plan" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 2


def test_run_llm_drywall_fails_when_the_ai_cannot_find_the_drywall_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"drywall_sheet_id": None, "notes": "no floor plan seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the drywall sheet"):
        lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_drywall_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "LLM takeoff is off" in str(exc.value) and "read the Drywall plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_drywall_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_drywall_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'drywall', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Drywall"):
        lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_drywall_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_drywall_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(
        plans["s1"], openings=[{"name": "Window W-1", "width_ft": "3", "height_ft": "4'-0\""}])]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="Window W-1 width"):
        lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_drywall_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_drywall_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lw.run_llm_drywall(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = lw.drywall_results(db, CTX, row)
    assert len(got["lines"]) == 2
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["ceiling_sqft"] == {"id": out["measurement_ids"][0], "label": "Ceiling area (AI)",
                                         "feeds": "ceiling_sqft", "qty": "424.00", "unit": "sqft",
                                         "status": "proposed", "how": EVIDENCE["ceiling_sqft"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(lw.QUESTION_IDS)         # both questions, zeros included
    assert items["ceiling_sqft"] == {"feeds": "ceiling_sqft", "label": "Ceiling area",
                                     "qty": "424.00", "unit": "sqft", "evidence": EVIDENCE["ceiling_sqft"]}
    assert items["openings_sqft"] == {"feeds": "openings_sqft", "label": "Door and window area to leave out",
                                      "qty": "32.00", "unit": "sqft", "evidence": EVIDENCE["openings_sqft"]}
    assert got["quantities"]["trade"] == "drywall" and got["quantities"]["label"] == "Drywall"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "rooms and schedule clear on the plan"


def test_drywall_results_all_zero_quantities(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm", "values": {"ceiling_sqft": "0.00", "openings_sqft": "0.00"},
            "evidence": {"ceiling_sqft": "no rooms dimensioned",
                         "openings_sqft": "no schedule on the plan"},
            "confidence": 0.8, "notes": "empty plan", "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = lw.drywall_results(db, CTX, row)
    assert got["lines"] == []
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["ceiling_sqft"]["qty"] == "0.00" and items["openings_sqft"]["qty"] == "0.00"
    assert items["openings_sqft"]["evidence"] == "no schedule on the plan"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_drywall_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert lw.drywall_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_drywall_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], openings=[],
                      evidence={"ceiling_sqft": EVIDENCE["ceiling_sqft"],
                                "openings_sqft": "no schedule on the plan"})
    ids = lq.create_measurements(db, CTX, run, reading, lw.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", lw.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = lw.drywall_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["ceiling_sqft"]["qty"] == "424.00" and items["openings_sqft"]["qty"] == 0
    assert items["ceiling_sqft"]["evidence"] == EVIDENCE["ceiling_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
