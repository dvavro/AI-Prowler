"""LLM-assisted plumbing takeoff: parsing, the count measurements, the run, the results.

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
from estimator.takeoff import llm_plumbing as lp
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
    """An estimate with one plan set: a single plumbing sheet (P-1) with a rendered
    image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Plumbing job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "p1.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'P-1', 'PLUMBING PLAN', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Plumbing plan', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "plumbing", [])


EVIDENCE = {"toilets": "2 water closets in the bathrooms",
            "sinks": "3 lavatories in the bathrooms",
            "kitchen_sinks": "1 kitchen sink",
            "showers": "2 tub/shower combinations",
            "dishwashers": "1 dishwasher hookup in the kitchen",
            "washers": "1 washer box in the laundry",
            "hose_bibs": "no hose bibs shown"}


def _reading(sheet_id, **over):
    out = {"plumbing_sheet_id": sheet_id, "toilets": 2, "sinks": 3, "kitchen_sinks": 1, "showers": 2,
           "dishwashers": 1, "washers": 1, "hose_bibs": 0,
           "confidence": 0.9, "notes": "fixtures clear on the plan", "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return lp.parse_plumbing_reading(_reading(sheet_id, **over), sheet_id)


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_plumbing_reading_full():
    got = lp.parse_plumbing_reading(_reading(4), 4)
    assert got == {"plumbing_sheet_id": 4,
                   "counts": {"toilets": 2, "sinks": 3, "kitchen_sinks": 1, "showers": 2,
                              "dishwashers": 1, "washers": 1, "hose_bibs": 0},
                   "evidence": dict(EVIDENCE), "confidence": 0.9, "notes": "fixtures clear on the plan"}


def test_parse_plumbing_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, confidence=None, evidence=None) + "\n```"
    got = lp.parse_plumbing_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in lp.COUNT_IDS}
    assert got["counts"]["toilets"] == 2


def test_parse_plumbing_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lp.parse_plumbing_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lp.parse_plumbing_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        lp.parse_plumbing_reading('{not json}', 4)


@pytest.mark.parametrize("field,bad", [
    ("toilets", None), ("sinks", -1), ("kitchen_sinks", 2.5), ("showers", "3"), ("dishwashers", True),
    ("washers", None), ("hose_bibs", 1.0),
])
def test_parse_plumbing_reading_rejects_bad_counts(field, bad):
    """Every defect names the field, so the AI Log says which count was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        lp.parse_plumbing_reading(_reading(4, **{field: bad}), 4)


def test_parse_plumbing_reading_rejects_missing_count():
    d = json.loads(_reading(4))
    del d["showers"]
    with pytest.raises(lt.LlmTakeoffError, match="showers"):
        lp.parse_plumbing_reading(json.dumps(d), 4)


def test_parse_plumbing_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = lp.parse_plumbing_reading(_reading(9), 4)
    assert got["plumbing_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_plumbing_classification():
    assert lp.parse_plumbing_classification('{"plumbing_sheet_id": 4, "notes": "fixtures"}', [4, 5]) == (4, "fixtures")
    assert lp.parse_plumbing_classification('{"plumbing_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert lp.parse_plumbing_classification('{"plumbing_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lp.parse_plumbing_classification("nope", [4])


# ------------------------------------------------------------------ the count measurements

def test_create_measurements_proposes_one_per_nonzero_count(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = lp.quantities_from_reading(reading)
    assert quantities == {"values": {"toilets": 2, "sinks": 3, "kitchen_sinks": 1, "showers": 2,
                                     "dishwashers": 1, "washers": 1, "hose_bibs": 0}}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", lp.SPEC)
    assert len(ids) == 6                              # hose_bibs is 0: no row
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["toilets", "sinks", "kitchen_sinks", "showers",
                                          "dishwashers", "washers"]
    for r in rows:
        assert r["module_id"] == "plumbing" and r["kind"] == "count" and r["unit"] == "ea"
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == lp.LABELS[r["feeds"]] + " (AI)"
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["plumbing_sheet_id"] == plans["s1"]
        assert calc["values"]["toilets"] == "2" and calc["values"]["hose_bibs"] == "0"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "fixtures clear on the plan"


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], toilets=0, sinks=0, kitchen_sinks=0, showers=0,
                      dishwashers=0, washers=0, hose_bibs=0)
    quantities = lp.quantities_from_reading(reading)
    assert quantities["values"] == {f: 0 for f in lp.COUNT_IDS}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", lp.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_plumbing_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "count the fixtures" in fake.calls[0]["system"].lower()
    assert "never null" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert steps == ["finding the plumbing sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == {"toilets": 2, "sinks": 3, "kitchen_sinks": 1, "showers": 2,
                                           "dishwashers": 1, "washers": 1, "hose_bibs": 0}
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm",
                                "values": {"toilets": 2, "sinks": 3, "kitchen_sinks": 1, "showers": 2,
                                           "dishwashers": 1, "washers": 1, "hose_bibs": 0},
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "fixtures clear on the plan", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the Plumbing quantities on sheet %d (2 toilets, 3 bathroom sinks,"
                              " 1 kitchen or bar sinks, 2 showers and tubs, 1 dishwashers, 1 washer boxes);"
                              " measurements %s" % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 6
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_plumbing_rules_settle_on_the_plumbing_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a101.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second plumbing sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "p2.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'P-2', 'PLUMBING PLAN', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'A-101', 'FLOOR PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_plumbing_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"plumbing_sheet_id": s2, "notes": "the fixtures are on P-2"}),
        _reading(s2),
    ]
    out = lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                       # classify, then the read
    assert len(fake.calls[0]["images"]) == 2          # thumbnails of both plumbing sheets
    assert "plumbing plan" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 6


def test_run_llm_plumbing_fails_when_the_ai_cannot_find_the_plumbing_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"plumbing_sheet_id": None, "notes": "no fixtures seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the plumbing sheet"):
        lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_plumbing_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "AI measuring is off" in str(exc.value) and "read the Plumbing plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_plumbing_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_plumbing_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'plumbing', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Plumbing"):
        lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_plumbing_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_plumbing_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], showers=2.5)]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="showers"):
        lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_plumbing_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_plumbing_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lp.run_llm_plumbing(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = lp.plumbing_results(db, CTX, row)
    assert len(got["lines"]) == 6
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["toilets"] == {"id": out["measurement_ids"][0], "label": "Toilets (AI)",
                                   "feeds": "toilets", "qty": "2", "unit": "ea", "status": "proposed",
                                   "how": EVIDENCE["toilets"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(lp.COUNT_IDS)            # all seven questions, zeros included
    assert items["toilets"] == {"feeds": "toilets", "label": "Toilets", "qty": 2, "unit": "ea",
                                "evidence": EVIDENCE["toilets"]}
    assert items["hose_bibs"] == {"feeds": "hose_bibs", "label": "Hose bibs", "qty": 0, "unit": "ea",
                                  "evidence": EVIDENCE["hose_bibs"]}   # zero: the candidate's evidence
    assert got["quantities"]["trade"] == "plumbing" and got["quantities"]["label"] == "Plumbing"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "fixtures clear on the plan"


def test_plumbing_results_all_zero_counts(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm", "values": {f: 0 for f in lp.COUNT_IDS},
            "evidence": dict(EVIDENCE), "confidence": 0.8, "notes": "empty plan",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = lp.plumbing_results(db, CTX, row)
    assert got["lines"] == []
    assert all(c["qty"] == 0 for c in got["quantities"]["items"])
    assert got["quantities"]["items"][0]["evidence"] == EVIDENCE["toilets"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_plumbing_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert lp.plumbing_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_plumbing_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    ids = lq.create_measurements(db, CTX, run, reading, lp.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", lp.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = lp.plumbing_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["toilets"]["qty"] == 2 and items["hose_bibs"]["qty"] == 0
    assert items["toilets"]["evidence"] == EVIDENCE["toilets"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
