"""LLM-assisted HVAC takeoff: parsing, the quantity measurements, the run, the results.

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
from estimator.takeoff import llm_hvac as lh
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
    """An estimate with one plan set: a single mechanical sheet (M-1) with a rendered
    image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "HVAC job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "m1.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'M-1', 'MECHANICAL PLAN', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Mechanical plan', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "hvac", [])


ROOMS = [{"name": "Living room", "width_ft": "14'-6\"", "length_ft": "18'-0\""},
         {"name": "Bedroom", "width_ft": "12'-0\"", "length_ft": "14'-0\""}]

EVIDENCE = {"conditioned_sqft": "Living room 14'-6\" x 18'-0\" and Bedroom 12'-0\" x 14'-0\"",
            "zones": "3 mini-split heads in the bedrooms and living room",
            "registers": "8 supply registers on the duct layout",
            "returns": "2 return grilles in the hallway",
            "thermostats": "no thermostats shown"}


def _reading(sheet_id, **over):
    out = {"hvac_sheet_id": sheet_id, "zones": 3, "registers": 8, "returns": 2, "thermostats": 0,
           "rooms": [dict(r) for r in ROOMS],
           "confidence": 0.9, "notes": "mechanical plan clear", "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return lh.parse_hvac_reading(_reading(sheet_id, **over), sheet_id)


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_hvac_reading_full():
    got = lh.parse_hvac_reading(_reading(4), 4)
    assert got == {"hvac_sheet_id": 4,
                   "counts": {"zones": 3, "registers": 8, "returns": 2, "thermostats": 0},
                   "rooms": [dict(r) for r in ROOMS],
                   "evidence": dict(EVIDENCE), "confidence": 0.9, "notes": "mechanical plan clear"}


def test_parse_hvac_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, confidence=None, evidence=None) + "\n```"
    got = lh.parse_hvac_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in lh.ALL_IDS}
    assert got["counts"]["zones"] == 3 and len(got["rooms"]) == 2


def test_parse_hvac_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lh.parse_hvac_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lh.parse_hvac_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        lh.parse_hvac_reading('{not json}', 4)


@pytest.mark.parametrize("field,bad", [
    ("zones", None), ("registers", -1), ("returns", 2.5), ("thermostats", "2"), ("zones", True),
])
def test_parse_hvac_reading_rejects_bad_counts(field, bad):
    """Every defect names the field, so the AI Log says which count was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        lh.parse_hvac_reading(_reading(4, **{field: bad}), 4)


def test_parse_hvac_reading_rejects_missing_count():
    d = json.loads(_reading(4))
    del d["registers"]
    with pytest.raises(lt.LlmTakeoffError, match="registers"):
        lh.parse_hvac_reading(json.dumps(d), 4)


def test_parse_hvac_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = lh.parse_hvac_reading(_reading(9), 4)
    assert got["hvac_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_hvac_reading_no_rooms_means_no_conditioned_area():
    d = json.loads(_reading(4))
    del d["rooms"]
    assert lh.parse_hvac_reading(json.dumps(d), 4)["rooms"] == []
    assert lh.parse_hvac_reading(_reading(4, rooms=None), 4)["rooms"] == []
    assert lh.parse_hvac_reading(_reading(4, rooms=[]), 4)["rooms"] == []


@pytest.mark.parametrize("bad", [
    "Living room", 42, [{"name": "Living room", "length_ft": "18'-0\""}],
    [{"name": "Living room", "width_ft": 14, "length_ft": "18'-0\""}],
    [{"name": 7, "width_ft": "14'-6\"", "length_ft": "18'-0\""}], ["not a room"],
])
def test_parse_hvac_reading_rejects_bad_rooms(bad):
    """Every defect names the rooms list, so the AI Log says what was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match="rooms"):
        lh.parse_hvac_reading(_reading(4, rooms=bad), 4)


def test_parse_hvac_classification():
    assert lh.parse_hvac_classification('{"hvac_sheet_id": 4, "notes": "ducts"}', [4, 5]) == (4, "ducts")
    assert lh.parse_hvac_classification('{"hvac_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert lh.parse_hvac_classification('{"hvac_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lh.parse_hvac_classification("nope", [4])


# ------------------------------------------------------------------ the app's maths (never the AI's)

def test_quantities_from_reading_rooms_maths():
    one = _parsed(4, rooms=[{"name": "Living room", "width_ft": "14'-6\"", "length_ft": "18'-0\""}])
    assert lh.quantities_from_reading(one)["values"]["conditioned_sqft"] == "261.00"
    two = _parsed(4)
    assert lh.quantities_from_reading(two)["values"] == {"conditioned_sqft": "429.00", "zones": 3,
                                                         "registers": 8, "returns": 2,
                                                         "thermostats": 0}
    none = _parsed(4, rooms=[])
    assert lh.quantities_from_reading(none)["values"]["conditioned_sqft"] == "0.00"


def test_quantities_from_reading_rejects_an_unparseable_dimension():
    bad = _parsed(4, rooms=[{"name": "Living room", "width_ft": "14.5", "length_ft": "18'-0\""}])
    with pytest.raises(lt.LlmTakeoffError, match="Living room"):
        lh.quantities_from_reading(bad)


# ------------------------------------------------------------------ the quantity measurements

def test_create_measurements_proposes_one_per_nonzero_quantity(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = lh.quantities_from_reading(reading)
    assert quantities == {"values": {"conditioned_sqft": "429.00", "zones": 3, "registers": 8,
                                     "returns": 2, "thermostats": 0}}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", lh.SPEC)
    assert len(ids) == 4                              # thermostats is 0: no row
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["conditioned_sqft", "zones", "registers", "returns"]
    kinds = {"conditioned_sqft": ("area", "sqft"), "zones": ("count", "ea"),
             "registers": ("count", "ea"), "returns": ("count", "ea")}
    for r in rows:
        assert r["module_id"] == "hvac" and (r["kind"], r["unit"]) == kinds[r["feeds"]]
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == lh.LABELS[r["feeds"]] + " (AI)"
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["hvac_sheet_id"] == plans["s1"]
        assert calc["values"]["conditioned_sqft"] == "429.00" and calc["values"]["thermostats"] == "0"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "mechanical plan clear"


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], rooms=[], zones=0, registers=0, returns=0, thermostats=0)
    quantities = lh.quantities_from_reading(reading)
    assert quantities["values"] == {"conditioned_sqft": "0.00", "zones": 0, "registers": 0,
                                    "returns": 0, "thermostats": 0}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", lh.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_hvac_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "mechanical plan" in fake.calls[0]["system"].lower()
    assert "never null" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert steps == ["finding the mechanical sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == {"conditioned_sqft": "429.00", "zones": 3, "registers": 8,
                                           "returns": 2, "thermostats": 0}
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm",
                                "values": {"conditioned_sqft": "429.00", "zones": 3, "registers": 8,
                                           "returns": 2, "thermostats": 0},
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "mechanical plan clear", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the HVAC quantities on sheet %d (429.00 sq ft conditioned,"
                              " 3 mini-split heads, 8 supply registers, 2 return grilles);"
                              " measurements %s" % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 4
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_hvac_rules_settle_on_the_mechanical_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a101.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second mechanical sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "m2.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'M-2', 'MECHANICAL PLAN', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'S-1', 'FOUNDATION PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Foundation plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_hvac_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"hvac_sheet_id": s2, "notes": "the ducts are on M-2"}),
        _reading(s2),
    ]
    out = lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                       # classify, then the read
    assert len(fake.calls[0]["images"]) == 2          # thumbnails of both mechanical sheets
    assert "mechanical plan" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 4


def test_run_llm_hvac_fails_when_the_ai_cannot_find_the_mechanical_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"hvac_sheet_id": None, "notes": "no ducts seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the mechanical sheet"):
        lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_hvac_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "LLM takeoff is off" in str(exc.value) and "read the HVAC plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_hvac_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_hvac_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'hvac', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for HVAC"):
        lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_hvac_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_hvac_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], registers=2.5)]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="registers"):
        lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_hvac_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_hvac_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lh.run_llm_hvac(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = lh.hvac_results(db, CTX, row)
    assert len(got["lines"]) == 4
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["conditioned_sqft"] == {"id": out["measurement_ids"][0],
                                            "label": "Area to heat and cool (AI)",
                                            "feeds": "conditioned_sqft", "qty": "429.00",
                                            "unit": "sqft", "status": "proposed",
                                            "how": EVIDENCE["conditioned_sqft"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(lh.ALL_IDS)              # all five questions, zeros included
    assert items["conditioned_sqft"] == {"feeds": "conditioned_sqft", "label": "Area to heat and cool",
                                         "qty": "429.00", "unit": "sqft",
                                         "evidence": EVIDENCE["conditioned_sqft"]}
    assert items["thermostats"] == {"feeds": "thermostats", "label": "Thermostats", "qty": 0,
                                    "unit": "ea",
                                    "evidence": EVIDENCE["thermostats"]}   # zero: the candidate's evidence
    assert got["quantities"]["trade"] == "hvac" and got["quantities"]["label"] == "HVAC"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "mechanical plan clear"


def test_hvac_results_all_zero_quantities(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm",
            "values": {"conditioned_sqft": "0.00", "zones": 0, "registers": 0, "returns": 0,
                       "thermostats": 0},
            "evidence": dict(EVIDENCE), "confidence": 0.8, "notes": "empty plan",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = lh.hvac_results(db, CTX, row)
    assert got["lines"] == []
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["conditioned_sqft"]["qty"] == "0.00"
    assert all(items[f]["qty"] == 0 for f in lh.COUNT_IDS)
    assert got["quantities"]["items"][0]["evidence"] == EVIDENCE["conditioned_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_hvac_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert lh.hvac_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_hvac_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    ids = lq.create_measurements(db, CTX, run, reading, lh.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", lh.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = lh.hvac_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["conditioned_sqft"]["qty"] == "429.00" and items["thermostats"]["qty"] == 0
    assert items["conditioned_sqft"]["evidence"] == EVIDENCE["conditioned_sqft"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
