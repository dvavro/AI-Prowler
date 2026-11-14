"""LLM-assisted takeoff: parsing, the app's maths, the setting, and the fallback run.

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
    """An estimate with one plan set: sheet 1 is the foundation plan (S-1), sheet 2
    an architectural floor plan (A-101). Both have rendered images; the foundation
    viewport has the live slab's scale but no slab outline (the NSB situation)."""
    est = service.create_estimate(db, CTX, "Shed slab")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "s1.png")
    img2 = _png(tmp_path / "a101.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'S-1', 'FOUNDATION PLAN', ?)", (ps, img1)).lastrowid
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (ps, img2)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Foundation plan', '84.3225', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "s2": s2, "vp": vp}


def test_slab_measurements_go_on_the_foundation_view_not_the_footer_detail(db, plans):
    """2026-11-13: a sheet can now hold the footer detail and the foundation plan as separate views."""
    s2 = plans["s2"]
    detail = db.execute("INSERT INTO viewports (company_id, sheet_id, label, bbox_json, is_nts)"
                        " VALUES ('default', ?, '12X20 MONO. FOOTER DETAIL', '[3.6, 0.25, 8.0, 5.1]', 1)",
                        (s2,)).lastrowid
    plan = db.execute("INSERT INTO viewports (company_id, sheet_id, label, bbox_json, is_nts)"
                      " VALUES ('default', ?, 'FOUNDATION PLAN', '[7.5, 2.9, 14.6, 10.75]', 1)", (s2,)).lastrowid
    assert lt._slab_viewport(db, s2) == plan
    db.execute("UPDATE viewports SET label = NULL WHERE id = ?", (plan,))       # no title: the biggest view
    assert lt._slab_viewport(db, s2) == plan
    db.execute("DELETE FROM viewports WHERE id = ?", (plan,))
    assert lt._slab_viewport(db, s2) == detail
    db.execute("DELETE FROM viewports WHERE id = ?", (detail,))
    assert lt._slab_viewport(db, s2) is None


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "concrete", [])


def _reading(sheet_id, **over):
    out = {"foundation_sheet_id": sheet_id, "slab_width_ft": "45'-7\"", "slab_length_ft": "46'-7\"",
           "footer_size": "12x20", "footer_bar": "#5", "confidence": 0.9,
           "notes": "dimensions clear on the plan"}
    out.update(over)
    return json.dumps(out)


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_reading_full():
    got = lt.parse_reading(_reading(4), 4)
    assert got == {"foundation_sheet_id": 4, "slab_width_ft": "45'-7\"", "slab_length_ft": "46'-7\"",
                   "footer_size": "12x20", "footer_bar": "#5", "confidence": 0.9,
                   "notes": "dimensions clear on the plan"}


def test_parse_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, footer_size=None, footer_bar=None, confidence=None) + "\n```"
    got = lt.parse_reading(text, 4)
    assert got["footer_size"] is None and got["footer_bar"] is None and got["confidence"] is None
    assert got["slab_width_ft"] == "45'-7\""


def test_parse_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lt.parse_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lt.parse_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        lt.parse_reading('{not json}', 4)
    with pytest.raises(lt.LlmTakeoffError, match="not text"):
        lt.parse_reading('{"slab_width_ft": 45}', 4)


def test_parse_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = lt.parse_reading(_reading(9), 4)
    assert got["foundation_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_classification():
    assert lt.parse_classification('{"foundation_sheet_id": 4, "notes": "footings"}', [4, 5]) == (4, "footings")
    assert lt.parse_classification('{"foundation_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert lt.parse_classification('{"foundation_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lt.parse_classification("nope", [4])


# ------------------------------------------------------------------ the app's maths

def test_quantities_45_7_x_46_7():
    q = lt.quantities_from_reading({"slab_width_ft": "45'-7\"", "slab_length_ft": "46'-7\""})
    assert q["area_sqft"] == "2123.42" and q["perimeter_lf"] == "184.33"
    assert q["width_ft"] == "45.58" and q["height_ft"] == "46.58"


def test_quantities_missing_or_unreadable_dimension_fails_loud():
    with pytest.raises(lt.LlmTakeoffError, match="couldn't read the slab length"):
        lt.quantities_from_reading({"slab_width_ft": "45'-7\"", "slab_length_ft": None})
    with pytest.raises(lt.LlmTakeoffError, match="couldn't read the slab width and length"):
        lt.quantities_from_reading({"slab_width_ft": None, "slab_length_ft": None})
    with pytest.raises(lt.LlmTakeoffError, match="isn't a length"):
        lt.quantities_from_reading({"slab_width_ft": "about 45 feet", "slab_length_ft": "46'-7\""})


# ------------------------------------------------------------------ the setting

def test_llm_setting_off_by_default(db):
    s = lt.llm_setting(db, "default")
    assert s == {"enabled": False, "provider": None, "provider_label": None, "model": None,
                 "ready": False, "why_not": "", "fallback_provider": None}


def test_llm_setting_on_with_provider_and_model(db, fake):
    _on(db, model="claude-opus-5-5", fallback_provider="grok_api")
    s = lt.llm_setting(db, "default")
    assert s["enabled"] is True and s["provider"] == "claude_api"
    assert s["model"] == "claude-opus-5-5" and s["ready"] is True
    assert s["fallback_provider"] == "grok_api"


def test_llm_setting_not_ready_without_a_key(db, fake):
    fake.keys["claude_api"] = False
    _on(db)
    s = lt.llm_setting(db, "default")
    assert s["enabled"] is True and s["ready"] is False and "no API key" in s["why_not"]


def test_llm_takeoff_role_starts_off_and_works_now(db):
    ov = roles.overview(db, "default")
    mine = next(r for r in ov["roles"] if r["role"] == "llm_takeoff")
    assert mine["provider"] == "off" and mine["works_now"] is True
    assert "API key" in mine["does"] and "budget" in mine["does"]


# ------------------------------------------------------------------ picking the foundation sheet

def test_pick_foundation_sheets_scores_titles_and_prefixes(db, plans):
    ranked = lt.pick_foundation_sheets(db, "default", plans["ps"], plans["s1"])
    assert [s["id"] for s in ranked] == [plans["s1"], plans["s2"]]   # S-1 FOUNDATION PLAN first
    assert ranked[0]["score"] > ranked[1]["score"]


def test_pick_foundation_sheets_skips_sheets_without_images(db, plans):
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
               " VALUES ('default', ?, 3, 'S-2', 'FOUNDATION DETAILS')", (plans["ps"],))
    ranked = lt.pick_foundation_sheets(db, "default", plans["ps"])
    assert all(s["image_path"] for s in ranked)


# ------------------------------------------------------------------ the whole fallback

def test_run_llm_takeoff_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert steps == ["finding the foundation sheet", "reading the plan with the AI", "measuring"]
    assert out["quantities"]["area_sqft"] == "2123.42" and out["quantities"]["perimeter_lf"] == "184.33"
    assert out["foundation_sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"]["id"] == "llm" and out["candidate"]["source"] == "llm"
    assert out["candidate"]["label"] == "45'-7\" x 46'-7\" (read by the AI)"
    rows = [dict(r) for r in db.execute("SELECT * FROM measurements WHERE estimate_id = ?"
                                        " ORDER BY id", (plans["est"],))]
    assert len(rows) == 3
    by_feeds = {r["feeds"]: r for r in rows}
    assert (by_feeds["area_sqft"]["qty"], by_feeds["area_sqft"]["unit"]) == ("2123.42", "sqft")
    assert (by_feeds["footing_lf"]["qty"], by_feeds["footing_lf"]["unit"]) == ("184.33", "lf")
    assert (by_feeds["perimeter_lf"]["qty"], by_feeds["perimeter_lf"]["unit"]) == ("184.33", "lf")
    for r in rows:
        assert r["proposed_by"] == "llm-takeoff" and r["method"] == "ai"
        assert r["status"] == "proposed" and r["locked"] == 0
        assert r["sheet_id"] == plans["s1"] and r["viewport_id"] == plans["vp"]
        assert r["confidence"] == "0.9"
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["slab_width"] == "45'-7\"" and calc["slab_length"] == "46'-7\""
        assert calc["footer_size"] == "12x20" and calc["footer_bar"] == "#5"
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
    assert [m for m in out["measurement_ids"]] == [r["id"] for r in rows]
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1                                  # the read image, logged like every AI send


def _run_on_arch(db, plans):
    """A run started on the architectural sheet, so the sheet the run started on
    doesn't settle the foundation question - the two foundation sheets tie."""
    vp2 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (plans["s2"],)).lastrowid
    return _run(db, plans, sheet=plans["s2"], vp=vp2)


def test_run_llm_takeoff_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    # A second foundation sheet with the same title score: the rules can't settle it.
    img3 = _png(tmp_path / "s2.png")
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 3, 'S-2', 'FOUNDATION PLAN', ?)", (plans["ps"], img3)).lastrowid
    fake.replies["claude_api"] = [
        json.dumps({"foundation_sheet_id": s3, "notes": "the slab is on S-2"}),
        _reading(s3),
    ]
    rid = _run_on_arch(db, plans)
    out = lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2
    assert len(fake.calls[0]["images"]) == 3          # thumbnails of all three sheets
    assert all(im["media_type"] == "image/png" for im in fake.calls[0]["images"])
    assert out["foundation_sheet_id"] == s3
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 3


def test_run_llm_takeoff_fails_when_the_ai_cannot_find_the_foundation(db, fake, plans, tmp_path):
    _on(db)
    img3 = _png(tmp_path / "s2.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 3, 'S-2', 'FOUNDATION PLAN', ?)", (plans["ps"], img3))
    fake.replies["claude_api"] = [json.dumps({"foundation_sheet_id": None, "notes": "no footings seen"})]
    rid = _run_on_arch(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the foundation plan"):
        lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_takeoff_fails_when_a_dimension_cannot_be_read(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], slab_length_ft=None,
                                           notes="the length dimension is cut off")]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't read the slab length"):
        lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_takeoff_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="LLM takeoff is off"):
        lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_takeoff_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_takeoff_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


def test_run_llm_takeoff_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


# ------------------------------------------------------------------ the runner process

def _file_db(tmp_path, plans_seed=True):
    """A real estimator.db file (the runner opens it by path), seeded like `plans`."""
    from estimator.database import open_database
    path = tmp_path / "estimator.db"
    conn = open_database(path)
    est = service.create_estimate(conn, CTX, "Shed slab")["id"]
    ps = conn.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                      " file_size, sha256, status, uploaded_by, created_at)"
                      " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                      (est, NOW)).lastrowid
    img1 = _png(tmp_path / "s1.png")
    s1 = conn.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                      " VALUES ('default', ?, 1, 'S-1', 'FOUNDATION PLAN', ?)", (ps, img1)).lastrowid
    vp = conn.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                      " VALUES ('default', ?, 'Foundation plan', '84.3225', 0)", (s1,)).lastrowid
    rid = autorun_api.create_run(conn, CTX, est, s1, vp, "concrete", [])
    conn.close()
    return path, {"est": est, "ps": ps, "s1": s1, "vp": vp, "run": rid}


def test_runner_marks_the_run_done(tmp_path, fake):
    from estimator.agents.llm_takeoff_runner import LlmTakeoffRun
    path, seed = _file_db(tmp_path)
    fake.replies["claude_api"] = [_reading(seed["s1"])]
    from estimator.database import open_database
    conn = open_database(path)
    _on(conn)
    conn.close()
    assert LlmTakeoffRun(db_path=str(path), run_id=seed["run"]).run() == 0
    conn = open_database(path)
    row = conn.execute("SELECT * FROM auto_runs WHERE id = ?", (seed["run"],)).fetchone()
    assert row["status"] == "done" and row["candidate_id"] == "llm"
    cands = json.loads(row["candidates_json"])
    assert len(cands) == 1 and cands[0]["source"] == "llm"
    assert cands[0]["area_sqft"] == 2123.42 and cands[0]["foundation_sheet_id"] == seed["s1"]
    assert len(json.loads(row["measurement_ids_json"])) == 3
    conn.close()


def test_runner_marks_the_run_failed_when_off(tmp_path, fake):
    from estimator.agents.llm_takeoff_runner import LlmTakeoffRun
    path, seed = _file_db(tmp_path)
    assert LlmTakeoffRun(db_path=str(path), run_id=seed["run"]).run() == 1
    assert fake.calls == []
    from estimator.database import open_database
    conn = open_database(path)
    row = conn.execute("SELECT status, error FROM auto_runs WHERE id = ?", (seed["run"],)).fetchone()
    assert row["status"] == "failed" and "LLM takeoff is off" in row["error"]
    conn.close()
