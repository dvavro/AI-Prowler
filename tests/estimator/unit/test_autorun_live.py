"""AI Auto Measure/Count shows what the AI is doing while its answer streams in (2026-11-21, David: "show only its latest
sentence, trimmed, plus the progress counts, and this also happens for all trades").

- The stream readers report {phase, thought, item, thinking_chars, answer_chars} to the thread's progress callback.
- The runner keeps it on the run row (auto_runs.live_json, migration 31); it's cleared when a step starts and when
  the run ends; the run's status shows it while the run is going.
- The page shows the latest sentence and the counts, and only gives up after 10 minutes with no news.
"""
import json

import desk_agent_providers as prov
from estimator.agents.concrete_autorun import RunStore
from estimator.api import autorun_api, router
from estimator.context import personal_context
from estimator.estimating import service


def _sse(events):
    out = []
    for name, data in events:
        out += [f"event: {name}\n", f"data: {json.dumps(data)}\n", "\n"]
    return out


def _delta(i, kind, text):
    key = "text" if kind == "text_delta" else "thinking"
    return ("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": kind, key: text}})


STREAM = [("message_start", {"type": "message_start", "message": {"content": [], "usage": {"input_tokens": 10}}}),
          ("ping", {"type": "ping"}),
          ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking"}}),
          _delta(0, "thinking_delta", "Looking at the legend first. Now counting the duplex outlets on the ground "),
          _delta(0, "thinking_delta", "floor. The kitchen has six GFCI outlets"),
          ("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
          _delta(1, "text_delta", '{\n  "outlets": 41,\n'),
          _delta(1, "text_delta", '  "gfci": 12,\n  "lights'),
          ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 9}}),
          ("message_stop", {"type": "message_stop"})]


def test_latest_sentence_and_item_are_short_and_readable():                          # AL-01
    assert prov.latest_sentence("First thought. Second, longer thought about outlets. And a half") \
        == "Second, longer thought about outlets."
    assert prov.latest_sentence("Just one unfinished thought") == "Just one unfinished thought"
    long = "word " * 80
    assert len(prov.latest_sentence(long)) <= prov.THOUGHT_MAX and prov.latest_sentence(long).endswith("…")
    assert prov.latest_item('{\n  "outlets": 41,\n  "gfci": 12,\n  "lig') == "gfci: 12"
    assert prov.latest_sentence("") == "" and prov.latest_item("") == ""


def test_the_stream_reports_its_progress(monkeypatch):                               # AL-02
    seen = []
    monkeypatch.setattr(prov, "PROGRESS_EVERY", 0)
    prov.set_progress(seen.append)
    try:
        msg = prov._read_claude_stream(_sse(STREAM))
    finally:
        prov.set_progress(None)
    assert msg["content"][1]["text"].startswith('{\n  "outlets": 41')
    thinking = [s for s in seen if s["phase"] == "thinking" and s["thought"]]
    assert thinking[-1]["thought"] == "Now counting the duplex outlets on the ground floor."
    writing = [s for s in seen if s["phase"] == "writing"]
    assert writing[-1]["item"] == "gfci: 12" and writing[-1]["answer_chars"] > 20
    assert writing[-1]["thinking_chars"] > 50
    # Nothing set = nothing reported, and the same answer.
    assert prov._read_claude_stream(_sse(STREAM)) == msg


def test_a_broken_watcher_never_breaks_the_call(monkeypatch):                         # AL-03
    monkeypatch.setattr(prov, "PROGRESS_EVERY", 0)

    def boom(_info):
        raise RuntimeError("watcher down")

    prov.set_progress(boom)
    try:
        assert prov._read_claude_stream(_sse(STREAM))["stop_reason"] == "end_turn"
    finally:
        prov.set_progress(None)


def test_grok_and_muse_report_their_reasoning_too(monkeypatch):                      # AL-04
    seen = []
    monkeypatch.setattr(prov, "PROGRESS_EVERY", 0)
    prov.set_progress(seen.append)
    try:
        prov._read_openai_stream([
            'data: {"choices":[{"delta":{"reasoning_content":"Reading the panel schedule. Next the lights"}}]}\n',
            'data: {"choices":[{"delta":{"content":"{\\"a\\": 1}"},"finish_reason":"stop"}]}\n', "data: [DONE]\n"])
    finally:
        prov.set_progress(None)
    assert any(s["thought"] == "Reading the panel schedule." for s in seen)
    assert seen[-1]["phase"] == "writing"


def test_the_run_row_keeps_it_and_the_status_shows_it(db, estimator_sandbox):        # AL-05
    from estimator import config
    e = service.create_estimate(db, personal_context(), "Live")
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                    " sha256, status, uploaded_by, created_at) VALUES ('default', ?, '', 'h.dxf', 'dxf', 1, 'x',"
                    " 'processed', 'owner', '2026-11-21')", (e["id"],)).lastrowid
    sheet = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                       " VALUES ('default', ?, 1, 'E-1', 'ELECTRICAL', '')", (ps,)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Plan', '48', 0)", (sheet,)).lastrowid
    rid = db.execute("INSERT INTO auto_runs (company_id, estimate_id, sheet_id, viewport_id, module_id, status, step,"
                     " created_by, created_at, updated_at) VALUES ('default', ?, ?, ?, 'electrical', 'running',"
                     " 'reading the plan with the AI', 'owner', '2026-11-21', '2026-11-21')",
                     (e["id"], sheet, vp)).lastrowid
    db.commit()
    store = RunStore(str(config.db_path()))
    try:
        store.update(rid, live={"phase": "thinking", "thought": "Counting outlets.", "thinking_chars": 400,
                                "answer_chars": 0})
        row = db.execute("SELECT * FROM auto_runs WHERE id = ?", (rid,)).fetchone()
        shaped = autorun_api._shape_run(row)
        assert shaped["live"]["thought"] == "Counting outlets." and shaped["live"]["thinking_chars"] == 400
        store.update(rid, step="counting the devices")                   # leaves live alone
        assert db.execute("SELECT live_json FROM auto_runs WHERE id = ?", (rid,)).fetchone()[0]
        store.update(rid, status="done", live=None)                      # cleared at the end
        row = db.execute("SELECT * FROM auto_runs WHERE id = ?", (rid,)).fetchone()
        assert row["live_json"] is None and autorun_api._shape_run(row)["live"] is None
    finally:
        store.close()


def test_the_runner_switches_progress_on_and_clears_it(monkeypatch):                  # AL-06
    from estimator.agents import llm_takeoff_runner as runner
    src = open(runner.__file__, encoding="utf-8").read()
    assert "providers.set_progress(self.set_live)" in src and "providers.set_progress(None)" in src
    assert 'step=step, live=None' in src and src.count("live=None") >= 3
    from estimator.agents import providers

    class Host:
        got = None

        def set_progress(self, cb):
            Host.got = cb

    monkeypatch.setattr(providers, "_host", lambda: Host())
    providers.set_progress(print)
    assert Host.got is print
    monkeypatch.setattr(providers, "_host", lambda: object())           # a host without streaming: no error
    providers.set_progress(print)


def test_the_page_shows_it_and_waits_for_news():                                      # AL-07
    js = (router.WEB_DIR / "review.js").read_text(encoding="utf-8")
    for needed in ("function autoLiveLine(", "autoLiveLine(AUTO.live)", "AUTO.live = run.live || null",
                   "AUTO.lastNews", "AUTO_MAX_MS", "The AI is thinking it through", "The AI is writing its answer",
                   "no news for 10 minutes"):
        assert needed in js, needed
    assert "Date.now() - AUTO.startedAt > AUTO_TIMEOUT_MS)" not in js        # no longer 10 minutes from the start


def test_the_wiring_stage_says_each_step(monkeypatch):                                 # AL-08
    from estimator.takeoff import wiring_run
    src = open(wiring_run.__file__, encoding="utf-8").read()
    for needed in ("on_step=None", 'say("wiring: reading the panel schedule',
                   'say(f"wiring: {routed} circuits routed', 'say(f"wiring: proposing the cable lengths'):
        assert needed in src, needed
