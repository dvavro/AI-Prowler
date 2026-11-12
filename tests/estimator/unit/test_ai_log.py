"""The AI Log: every LLM call the Estimator makes, what was sent and what came back.

A fake provider stands in for Claude and Grok: no real API calls, no token cost.
Every test runs against a throwaway data folder (conftest.py) - never the live
database. Covers the table (migration 22), the module, the LLM takeoff logging
and the agent queue logging.
"""
import json
from pathlib import Path

import pytest

from estimator import config
from estimator.agents import ai_log, providers, queue, roles
from estimator.api import autorun_api
from estimator.context import RequestContext, personal_context
from estimator.director import engine
from estimator.errors import NotFound, PermissionDenied
from estimator.estimating import service
from estimator.modules.registry import ModuleRegistry
from estimator.takeoff import llm_takeoff as lt

CTX = personal_context()
REVIEWER = RequestContext(user_id="rita", role="reviewer")
NOW = "2026-11-12T10:00:00+00:00"
REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


class FakeProvider:
    """Answers like Claude or Grok would. replies[provider] is a list of texts
    (or exceptions) used in order, for both ask() and ask_vision()."""

    def __init__(self):
        self.keys = {"claude_api": True, "grok_api": True}
        self.replies = {"claude_api": [], "grok_api": []}
        self.calls = []

    def ready(self, provider):
        return (True, "") if self.keys.get(provider) else (False, "no API key saved")

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3"}[provider]

    def _reply(self, provider):
        r = self.replies[provider].pop(0) if self.replies[provider] else "{}"
        if isinstance(r, Exception):
            raise r
        return r

    def ask(self, provider, system, user, model=""):
        self.calls.append({"provider": provider, "system": system, "user": user, "model": model})
        return self._reply(provider), {"input": 2000, "output": 500}

    def ask_vision(self, provider, system, user, images, model=""):
        self.calls.append({"provider": provider, "system": system, "user": user,
                           "images": images, "model": model})
        return self._reply(provider), {"input": 3000, "output": 200}

    def cost(self, model, usage):           # $2 / $10 per 1M tokens, like Sonnet
        return round((usage["input"] * 2 + usage["output"] * 10) / 1_000_000, 5)


@pytest.fixture
def fake():
    f = FakeProvider()
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


def _on_llm(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _on_role(db, role, provider="claude_api", **extra):
    return roles.update_role(db, CTX, role, {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "concrete", [])


def _run_on_arch(db, plans):
    """A run started on the architectural sheet, so the sheet the run started on
    doesn't settle the foundation question - the two foundation sheets tie."""
    vp2 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (plans["s2"],)).lastrowid
    return _run(db, plans, sheet=plans["s2"], vp=vp2)


def _reading(sheet_id, **over):
    out = {"foundation_sheet_id": sheet_id, "slab_width_ft": "45'-7\"", "slab_length_ft": "46'-7\"",
           "footer_size": "12x20", "footer_bar": "#5", "confidence": 0.9,
           "notes": "dimensions clear on the plan"}
    out.update(over)
    return json.dumps(out)


def _review_job(db):
    return engine.start(db, CTX, "replace the roof", answers=ROOF, registry=REG)


def say(*actions, summary="ok"):
    return json.dumps({"actions": list(actions), "summary": summary})


def _rows(db):
    return [dict(r) for r in db.execute("SELECT * FROM ai_log ORDER BY id")]


# ------------------------------------------------------------------ the table (migration 22)


def test_ai_log_table_has_every_field(db):
    cols = {r[1] for r in db.execute("PRAGMA table_info(ai_log)")}
    assert {"id", "company_id", "created_at", "provider", "model", "role", "purpose",
            "auto_run_id", "task_id", "estimate_id", "system_prompt", "user_prompt",
            "images_json", "response_text", "parsed_json", "input_tokens", "output_tokens",
            "cost_micros", "duration_ms", "ok", "error"} <= cols
    idx = {r[1] for r in db.execute("PRAGMA index_list(ai_log)")}
    assert {"ix_ai_log_company", "ix_ai_log_run"} <= idx


def test_ai_log_has_no_key_column(db):
    """No API key or credential can ever be logged: the table has nowhere to put one."""
    cols = [r[1].lower() for r in db.execute("PRAGMA table_info(ai_log)")]
    assert not [c for c in cols if any(w in c for w in ("key", "secret", "password", "credential"))]
    assert [c for c in cols if "token" in c] == ["input_tokens", "output_tokens"]   # usage counts, not credentials


# ------------------------------------------------------------------ record / list / detail


def test_record_and_read_round_trip(db, fake):
    img = {"ai_send_log_id": 7, "sheet_id": 3, "sheet_no": "S-1", "kind": "full_sheet",
           "file_path": "/data/x.png", "width_px": 400, "height_px": 300, "extra": "dropped"}
    eid = ai_log.record(db, CTX, provider="claude_api", model="claude-sonnet-5-5",
                        role="llm_takeoff", purpose="LLM takeoff: read the slab dimensions",
                        system_prompt="You read plans.", user_prompt="Read this slab.",
                        images=[img], auto_run_id=5, estimate_id=2,
                        response_text='{"slab_width_ft": "45\'-7\\""}',
                        parsed={"slab_width_ft": "45'-7\""}, usage={"input": 3000, "output": 200},
                        duration_ms=1234)
    got = ai_log.get_entry(db, CTX, eid)["entry"]
    assert got["provider"] == "claude_api" and got["model"] == "claude-sonnet-5-5"
    assert got["role"] == "llm_takeoff" and got["purpose"] == "LLM takeoff: read the slab dimensions"
    assert got["auto_run_id"] == 5 and got["estimate_id"] == 2 and got["task_id"] is None
    assert got["system_prompt"] == "You read plans." and got["user_prompt"] == "Read this slab."
    assert got["response_text"] == '{"slab_width_ft": "45\'-7\\""}'
    assert got["parsed"] == {"slab_width_ft": "45'-7\""}
    assert (got["input_tokens"], got["output_tokens"]) == (3000, 200)
    assert got["cost_micros"] == 8000 and got["cost_cents"] == 0.8   # 3,000 x $2 + 200 x $10 per 1M
    assert got["duration_ms"] == 1234 and got["ok"] is True and got["error"] is None
    assert got["image_count"] == 1
    assert got["images"][0]["image_url"] == f"/ai-log/{eid}/image/0"
    assert "file_path" not in got["images"][0]                      # the browser never sees the path
    assert "extra" not in got["images"][0]                          # only the known keys are stored
    assert got["images"][0]["ai_send_log_id"] == 7 and got["images"][0]["sheet_no"] == "S-1"

    listed = ai_log.list_entries(db, CTX)["entries"]
    assert len(listed) == 1 and listed[0]["id"] == eid
    assert listed[0]["image_count"] == 1 and listed[0]["cost_cents"] == 0.8
    # The list carries no prompts or replies - the detail call has those.
    assert not {"system_prompt", "user_prompt", "response_text", "parsed", "images"} & set(listed[0])


def test_list_entries_filters_and_pagination(db, fake):
    for i, (run, role) in enumerate([(5, "llm_takeoff"), (5, "llm_takeoff"), (6, "reviewer")]):
        ai_log.record(db, CTX, provider="claude_api", model="m", role=role, purpose=f"call {i}",
                      system_prompt="s", user_prompt="u", auto_run_id=run, task_id=9 if role == "reviewer" else None)
    all_ = ai_log.list_entries(db, CTX)
    assert all_["total"] == 3 and [e["purpose"] for e in all_["entries"]] == ["call 2", "call 1", "call 0"]
    assert ai_log.list_entries(db, CTX, auto_run_id=5)["total"] == 2
    assert ai_log.list_entries(db, CTX, role="reviewer")["total"] == 1
    assert ai_log.list_entries(db, CTX, task_id=9)["entries"][0]["purpose"] == "call 2"
    page = ai_log.list_entries(db, CTX, limit=2)
    assert len(page["entries"]) == 2 and page["total"] == 3 and page["limit"] == 2
    page2 = ai_log.list_entries(db, CTX, limit=2, offset=2)
    assert [e["purpose"] for e in page2["entries"]] == ["call 0"]


def test_set_parsed_and_set_error(db, fake):
    eid = ai_log.record(db, CTX, provider="claude_api", model="m", role="reviewer",
                        purpose="Reviewer agent, task 1", system_prompt="s", user_prompt="u",
                        response_text="not json", usage={"input": 10, "output": 5})
    ai_log.set_parsed(db, "default", eid, {"actions": []})
    assert ai_log.get_entry(db, CTX, eid)["entry"]["parsed"] == {"actions": []}
    ai_log.set_error(db, "default", eid, "the AI didn't answer with JSON")
    got = ai_log.get_entry(db, CTX, eid)["entry"]
    assert got["ok"] is False and "didn't answer with JSON" in got["error"]
    assert got["response_text"] == "not json"                       # the raw reply stays to look at


def test_only_owner_and_estimators_can_read(db, fake):
    eid = ai_log.record(db, CTX, provider="claude_api", model="m", role="reviewer",
                        purpose="p", system_prompt="s", user_prompt="u")
    for ctx in (REVIEWER, RequestContext(user_id="o", role="office"), RequestContext(user_id="f", role="field")):
        with pytest.raises(PermissionDenied):
            ai_log.list_entries(db, ctx)
        with pytest.raises(PermissionDenied):
            ai_log.get_entry(db, ctx, eid)
        with pytest.raises(PermissionDenied):
            ai_log.image_file(db, ctx, eid, 0)
    assert ai_log.list_entries(db, RequestContext(user_id="e", role="estimator"))["total"] == 1


def test_missing_entry_and_image_raise_not_found(db):
    with pytest.raises(NotFound):
        ai_log.get_entry(db, CTX, 999)
    with pytest.raises(NotFound):
        ai_log.image_file(db, CTX, 999, 0)
    eid = ai_log.record(db, CTX, provider="claude_api", model="m", role="reviewer",
                        purpose="p", system_prompt="s", user_prompt="u")
    with pytest.raises(NotFound):
        ai_log.image_file(db, CTX, eid, 0)                          # no images on this entry


def test_image_file_serves_only_pictures_inside_the_data_folder(db, tmp_path):
    inside = _png(config.data_dir() / "sent.png")
    outside = _png(tmp_path / "outside.png")
    eid = ai_log.record(db, CTX, provider="claude_api", model="m", role="llm_takeoff",
                        purpose="p", system_prompt="s", user_prompt="u",
                        images=[{"file_path": inside, "sheet_id": 1},
                                {"file_path": outside, "sheet_id": 1},
                                {"file_path": str(config.data_dir() / "gone.png"), "sheet_id": 1}])
    assert ai_log.image_file(db, CTX, eid, 0) == Path(inside)
    with pytest.raises(NotFound):
        ai_log.image_file(db, CTX, eid, 1)                          # outside the data folder
    with pytest.raises(NotFound):
        ai_log.image_file(db, CTX, eid, 2)                          # file deleted since


# ------------------------------------------------------------------ the LLM takeoff writes it


def test_llm_takeoff_read_call_is_logged(db, fake, plans):
    _on_llm(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["quantities"]["area_sqft"] == "2123.42"
    rows = _rows(db)
    assert len(rows) == 1                       # the sheet rules settle it: no classify call
    r = rows[0]
    assert r["provider"] == "claude_api" and r["model"] == "claude-sonnet-5-5"
    assert r["role"] == "llm_takeoff" and r["purpose"] == "LLM takeoff: read the slab dimensions"
    assert r["auto_run_id"] == rid and r["estimate_id"] == plans["est"] and r["task_id"] is None
    assert "Read the slab's overall dimensions" in r["user_prompt"]
    assert r["system_prompt"] and r["response_text"] == _reading(plans["s1"])
    assert json.loads(r["parsed_json"])["slab_width_ft"] == "45'-7\""
    assert (r["input_tokens"], r["output_tokens"]) == (3000, 200) and r["cost_micros"] == 8000
    assert r["duration_ms"] is not None and r["duration_ms"] >= 0
    assert r["ok"] == 1 and r["error"] is None
    images = json.loads(r["images_json"])
    assert len(images) == 1
    img = images[0]
    assert img["sheet_id"] == plans["s1"] and img["sheet_no"] == "S-1" and img["kind"] == "full_sheet"
    assert (img["width_px"], img["height_px"]) == (400, 300) and "sent_max_px" not in img
    assert Path(img["file_path"]).is_file()                       # the sent image is still on disk
    assert db.execute("SELECT COUNT(*) FROM ai_send_log WHERE id = ?",
                      (img["ai_send_log_id"],)).fetchone()[0] == 1


def test_llm_takeoff_classify_and_read_are_both_logged(db, fake, plans, tmp_path):
    _on_llm(db)
    img3 = _png(tmp_path / "s2.png")
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 3, 'S-2', 'FOUNDATION PLAN', ?)", (plans["ps"], img3)).lastrowid
    fake.replies["claude_api"] = [
        json.dumps({"foundation_sheet_id": s3, "notes": "the slab is on S-2"}),
        _reading(s3),
    ]
    rid = _run_on_arch(db, plans)
    out = lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["foundation_sheet_id"] == s3
    rows = _rows(db)
    assert len(rows) == 2
    classify, read = rows
    assert classify["purpose"] == "LLM takeoff: find the foundation sheet"
    assert json.loads(classify["parsed_json"]) == {"foundation_sheet_id": s3, "notes": "the slab is on S-2"}
    thumbs = json.loads(classify["images_json"])
    assert len(thumbs) == 3                                        # thumbnails of all three sheets
    assert all(t["sent_max_px"] == 768 for t in thumbs)            # sent downscaled, stored full-size
    assert read["purpose"] == "LLM takeoff: read the slab dimensions"
    assert json.loads(read["images_json"])[0]["sheet_no"] == "S-2"
    assert all(r["auto_run_id"] == rid and r["ok"] == 1 for r in rows)
    listed = ai_log.list_entries(db, CTX, auto_run_id=rid)["entries"]
    assert [e["purpose"] for e in listed] == [read["purpose"], classify["purpose"]]   # newest first


def test_llm_takeoff_failed_call_is_logged(db, fake, plans):
    _on_llm(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api"                           # the run still succeeds
    rows = _rows(db)
    assert len(rows) == 2
    failed, good = rows
    assert failed["provider"] == "claude_api" and failed["ok"] == 0
    assert failed["error"] == "Claude is down" and failed["response_text"] is None
    assert (failed["input_tokens"], failed["output_tokens"], failed["cost_micros"]) == (0, 0, 0)
    assert "Read the slab's overall dimensions" in failed["user_prompt"]   # what was sent stays
    assert len(json.loads(failed["images_json"])) == 1
    assert good["provider"] == "grok_api" and good["ok"] == 1 and good["model"] == "grok-4.3"
    assert failed["auto_run_id"] == good["auto_run_id"] == rid


def test_llm_takeoff_parse_failure_is_logged(db, fake, plans):
    _on_llm(db)
    fake.replies["claude_api"] = ["no json here"]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    rows = _rows(db)
    assert len(rows) == 1
    assert rows[0]["ok"] == 0 and "didn't answer with JSON" in rows[0]["error"]
    assert rows[0]["response_text"] == "no json here"              # the raw reply stays to look at
    assert rows[0]["parsed_json"] is None and rows[0]["auto_run_id"] == rid
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_llm_takeoff_dimension_failure_keeps_the_row_ok(db, fake, plans):
    """The AI answered; the app couldn't use the answer (a dimension was null).
    The call itself was fine, so the row stays ok - with the parsed reading."""
    _on_llm(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], slab_length_ft=None,
                                           notes="the length dimension is cut off")]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't read the slab length"):
        lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    rows = _rows(db)
    assert len(rows) == 1 and rows[0]["ok"] == 1 and rows[0]["error"] is None
    assert json.loads(rows[0]["parsed_json"])["slab_length_ft"] is None


def test_llm_takeoff_off_logs_nothing(db, fake, plans):
    """The NSB situation: LLM takeoff off means no call and no row - the empty
    log is itself the answer to 'did the AI run?'."""
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="LLM takeoff is off"):
        lt.run_llm_takeoff(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == [] and _rows(db) == []


# ------------------------------------------------------------------ the agent queue writes it


def test_queue_reviewer_call_is_logged(db, fake):
    _on_role(db, "reviewer")
    r = _review_job(db)
    reply = say({"action": "review_note", "body": "Check the pitch on sheet A3."},
                {"action": "flag", "message": "Sample prices still in use", "severity": "warning"})
    fake.replies["claude_api"] = [reply]
    out = queue.run(db, CTX)
    assert out["ran"][0]["state"] == "done"
    rows = _rows(db)
    assert len(rows) == 1
    row = rows[0]
    tid = out["ran"][0]["task_id"]
    assert row["provider"] == "claude_api" and row["model"] == "claude-sonnet-5-5"
    assert row["role"] == "reviewer" and row["purpose"] == f"Reviewer agent, task {tid}"
    assert row["task_id"] == tid and row["estimate_id"] == r["estimate"]["id"]
    assert row["auto_run_id"] is None and row["ok"] == 1
    assert "Reviewer" in row["system_prompt"] and "replace the roof" in row["user_prompt"]
    assert row["response_text"] == reply
    assert [a["action"] for a in json.loads(row["parsed_json"])["actions"]] == ["review_note", "flag"]
    assert (row["input_tokens"], row["output_tokens"]) == (2000, 500)
    assert row["cost_micros"] == 9000                              # 2,000 x $2 + 500 x $10 per 1M
    assert json.loads(row["images_json"]) == []                    # a text call sends no images


def test_queue_failed_call_is_logged(db, fake):
    _on_role(db, "reviewer", fallback_provider="grok_api")
    _review_job(db)
    fake.replies["claude_api"] = [providers.ProviderError("HTTP 529: overloaded")]
    fake.replies["grok_api"] = [say({"action": "review_note", "body": "Looks complete."})]
    out = queue.run(db, CTX)
    assert out["ran"][0]["provider"] == "grok_api" and out["ran"][0]["state"] == "done"
    rows = _rows(db)
    assert len(rows) == 2
    failed, good = rows
    assert failed["provider"] == "claude_api" and failed["ok"] == 0
    assert "overloaded" in failed["error"] and failed["response_text"] is None
    assert good["provider"] == "grok_api" and good["ok"] == 1


def test_queue_parse_failure_is_logged(db, fake):
    _on_role(db, "reviewer")
    _review_job(db)
    fake.replies["claude_api"] = ["I think it's fine!"]
    out = queue.run(db, CTX)
    assert out["ran"][0]["state"] == "queued"                      # it will retry
    rows = _rows(db)
    assert len(rows) == 1 and rows[0]["ok"] == 0 and rows[0]["error"]
    assert rows[0]["response_text"] == "I think it's fine!"
