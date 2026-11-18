"""LLM-assisted windows and doors takeoff: parsing, the count measurements, the run, the results.

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
from estimator.takeoff import llm_takeoff as lt
from estimator.takeoff import llm_windows_doors as lw

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
    """An estimate with one plan set: a single window and door sheet (A-601) with a
    rendered image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Windows job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "a601.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'A-601', 'WINDOW SCHEDULE', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Window schedule', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "windows_doors", [])


EVIDENCE = {"windows_small": "6 windows under 15 sq ft on the schedule",
            "windows_large": "2 windows 15 sq ft and over on the schedule",
            "patio_doors": "1 patio slider on the schedule",
            "exterior_doors": "2 exterior doors on the schedule",
            "interior_doors": "5 interior doors on the schedule",
            "garage_doors": "no garage doors shown"}


def _reading(sheet_id, **over):
    out = {"windows_doors_sheet_id": sheet_id, "windows_small": 6, "windows_large": 2, "patio_doors": 1,
           "exterior_doors": 2, "interior_doors": 5, "garage_doors": 0,
           "confidence": 0.9, "notes": "schedule clear on the sheet", "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return lw.parse_windows_doors_reading(_reading(sheet_id, **over), sheet_id)


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_windows_doors_reading_full():
    got = lw.parse_windows_doors_reading(_reading(4), 4)
    assert got == {"windows_doors_sheet_id": 4,
                   "counts": {"windows_small": 6, "windows_large": 2, "patio_doors": 1,
                              "exterior_doors": 2, "interior_doors": 5, "garage_doors": 0},
                   "evidence": dict(EVIDENCE), "confidence": 0.9, "notes": "schedule clear on the sheet"}


def test_parse_windows_doors_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, confidence=None, evidence=None) + "\n```"
    got = lw.parse_windows_doors_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in lw.COUNT_IDS}
    assert got["counts"]["windows_small"] == 6


def test_parse_windows_doors_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lw.parse_windows_doors_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lw.parse_windows_doors_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        lw.parse_windows_doors_reading('{not json}', 4)


@pytest.mark.parametrize("field,bad", [
    ("windows_small", None), ("windows_large", -1), ("patio_doors", 2.5), ("exterior_doors", "2"),
    ("interior_doors", True), ("garage_doors", 1.0),
])
def test_parse_windows_doors_reading_rejects_bad_counts(field, bad):
    """Every defect names the field, so the AI Log says which count was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        lw.parse_windows_doors_reading(_reading(4, **{field: bad}), 4)


def test_parse_windows_doors_reading_rejects_missing_count():
    d = json.loads(_reading(4))
    del d["patio_doors"]
    with pytest.raises(lt.LlmTakeoffError, match="patio_doors"):
        lw.parse_windows_doors_reading(json.dumps(d), 4)


def test_parse_windows_doors_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = lw.parse_windows_doors_reading(_reading(9), 4)
    assert got["windows_doors_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_windows_doors_classification():
    assert lw.parse_windows_doors_classification('{"windows_doors_sheet_id": 4, "notes": "schedule"}',
                                                 [4, 5]) == (4, "schedule")
    assert lw.parse_windows_doors_classification('{"windows_doors_sheet_id": null, "notes": "none"}',
                                                 [4, 5])[0] is None
    assert lw.parse_windows_doors_classification('{"windows_doors_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lw.parse_windows_doors_classification("nope", [4])


# ------------------------------------------------------------------ the count measurements

def test_create_measurements_proposes_one_per_nonzero_count(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = lw.quantities_from_reading(reading)
    assert quantities == {"values": {"windows_small": 6, "windows_large": 2, "patio_doors": 1,
                                     "exterior_doors": 2, "interior_doors": 5, "garage_doors": 0}}
    ids = lq.create_measurements(db, CTX, run, reading, quantities, "claude_api",
                                 "claude-sonnet-5-5", lw.SPEC)
    assert len(ids) == 5                            # garage_doors is 0: no row
    rows = db.execute("SELECT * FROM measurements WHERE estimate_id = ? ORDER BY id",
                      (plans["est"],)).fetchall()
    assert [r["feeds"] for r in rows] == ["windows_small", "windows_large", "patio_doors",
                                          "exterior_doors", "interior_doors"]
    for r in rows:
        assert r["module_id"] == "windows_doors" and r["kind"] == "count" and r["unit"] == "ea"
        assert r["status"] == "proposed" and r["proposed_by"] == "llm-takeoff"
        assert r["label"] == lw.LABELS[r["feeds"]] + " (AI)"
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["windows_doors_sheet_id"] == plans["s1"]
        assert calc["values"]["windows_small"] == "6" and calc["values"]["garage_doors"] == "0"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "schedule clear on the sheet"


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], windows_small=0, windows_large=0, patio_doors=0,
                      exterior_doors=0, interior_doors=0, garage_doors=0)
    quantities = lw.quantities_from_reading(reading)
    assert quantities["values"] == {f: 0 for f in lw.COUNT_IDS}
    assert lq.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m", lw.SPEC) == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_windows_doors_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                     # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "count the windows" in fake.calls[0]["system"].lower()
    assert "never null" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert "3 ft doors" in fake.calls[0]["user"]    # the size-split fallback is in the prompt
    assert steps == ["finding the window and door sheet", "reading the plan with the AI",
                     "working out the quantities"]
    assert out["quantities"]["values"] == {"windows_small": 6, "windows_large": 2, "patio_doors": 1,
                                           "exterior_doors": 2, "interior_doors": 5, "garage_doors": 0}
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm",
                                "values": {"windows_small": 6, "windows_large": 2, "patio_doors": 1,
                                           "exterior_doors": 2, "interior_doors": 5, "garage_doors": 0},
                                "evidence": dict(EVIDENCE), "confidence": 0.9,
                                "notes": "schedule clear on the sheet", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("read the Windows and Doors quantities on sheet %d (6 small windows,"
                              " 2 large windows, 1 patio doors, 2 exterior doors, 5 interior doors);"
                              " measurements %s" % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 5
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_windows_doors_rules_settle_on_the_window_and_door_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a101.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                     # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second window schedule with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "a602.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'A-602', 'WINDOW SCHEDULE', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'A-101', 'FLOOR PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_windows_doors_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"windows_doors_sheet_id": s2, "notes": "the schedule is on A-602"}),
        _reading(s2),
    ]
    out = lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                     # classify, then the read
    assert len(fake.calls[0]["images"]) == 2        # thumbnails of both window schedules
    assert "window and door schedule" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 5


def test_run_llm_windows_doors_fails_when_the_ai_cannot_find_the_window_and_door_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"windows_doors_sheet_id": None, "notes": "no schedule seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the window and door sheet"):
        lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_windows_doors_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "LLM takeoff is off" in str(exc.value) and "read the Windows and Doors plan" in str(exc.value)
    assert fake.calls == []


def test_run_llm_windows_doors_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_windows_doors_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'windows_doors', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Windows and Doors"):
        lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_windows_doors_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_windows_doors_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], windows_large=2.5)]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="windows_large"):
        lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_windows_doors_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_windows_doors_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lw.run_llm_windows_doors(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = lw.windows_doors_results(db, CTX, row)
    assert len(got["lines"]) == 5
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["windows_small"] == {"id": out["measurement_ids"][0], "label": "Windows under 15 sq ft (AI)",
                                         "feeds": "windows_small", "qty": "6", "unit": "ea", "status": "proposed",
                                         "how": EVIDENCE["windows_small"]}
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert set(items) == set(lw.COUNT_IDS)          # all six questions, zeros included
    assert items["windows_small"] == {"feeds": "windows_small", "label": "Windows under 15 sq ft",
                                      "qty": 6, "unit": "ea", "evidence": EVIDENCE["windows_small"]}
    assert items["garage_doors"] == {"feeds": "garage_doors", "label": "Garage doors", "qty": 0, "unit": "ea",
                                     "evidence": EVIDENCE["garage_doors"]}   # zero: the candidate's evidence
    assert got["quantities"]["trade"] == "windows_doors" and got["quantities"]["label"] == "Windows and Doors"
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.9
    assert got["quantities"]["notes"] == "schedule clear on the sheet"


def test_windows_doors_results_all_zero_counts(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm", "values": {f: 0 for f in lw.COUNT_IDS},
            "evidence": dict(EVIDENCE), "confidence": 0.8, "notes": "empty plan",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = lw.windows_doors_results(db, CTX, row)
    assert got["lines"] == []
    assert all(c["qty"] == 0 for c in got["quantities"]["items"])
    assert got["quantities"]["items"][0]["evidence"] == EVIDENCE["windows_small"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] == 0.8


def test_windows_doors_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert lw.windows_doors_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_windows_doors_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    ids = lq.create_measurements(db, CTX, run, reading, lw.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5", lw.SPEC)
    row = _finish_run(db, rid, None, ids)
    got = lw.windows_doors_results(db, CTX, row)
    items = {c["feeds"]: c for c in got["quantities"]["items"]}
    assert items["windows_small"]["qty"] == 6 and items["garage_doors"]["qty"] == 0
    assert items["windows_small"]["evidence"] == EVIDENCE["windows_small"]
    assert got["quantities"]["sheet_id"] == plans["s1"]
    assert got["quantities"]["confidence"] is None and got["quantities"]["notes"] == ""
