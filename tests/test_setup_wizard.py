"""Unit tests for the Setup Center logic (setup_wizard.py, SETUP_CENTER_SPEC.md §7).
No window is opened — only the registry, choices, dependencies and progress.

Run: run_tests.bat tests\\test_setup_wizard.py   (or: python -m pytest tests\\test_setup_wizard.py)
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import setup_wizard as sw   # noqa: E402


# ── registry integrity ──────────────────────────────────────────────────────
def test_module_ids_unique_and_requires_resolve():
    ids = [m.id for m in sw.MODULES]
    assert len(ids) == len(set(ids)), "duplicate module ids"
    for m in sw.MODULES:
        for r in m.requires:
            assert r in sw.BY_ID, f"{m.id} requires unknown {r}"


def test_no_dependency_cycles():
    def walk(mid, seen):
        assert mid not in seen, f"cycle through {mid}"
        for r in sw.BY_ID[mid].requires:
            walk(r, seen | {mid})
    for m in sw.MODULES:
        walk(m.id, set())


def test_requirements_come_before_what_needs_them():
    pos = {m.id: i for i, m in enumerate(sw.MODULES)}
    for m in sw.MODULES:
        for r in m.requires:
            assert pos[r] < pos[m.id], f"{r} should be listed before {m.id}"


def test_every_service_maps_to_real_modules_and_every_module_is_reachable():
    reachable = set()
    for sid, label, mods in sw.SERVICES:
        assert label.strip()
        for mid in mods:
            assert mid in sw.BY_ID, f"service {sid} lists unknown module {mid}"
        reachable.update(m.id for m in sw.modules_for([sid]))
    assert reachable == set(sw.BY_ID), f"never offered: {set(sw.BY_ID) - reachable}"


def test_modules_needing_setup_point_at_a_tab_and_info_cards_dont():
    for m in sw.MODULES:
        if m.info_only:
            assert not m.tab
        else:
            assert m.tab, f"{m.id} has no tab to open"
        assert m.minutes > 0 and m.why.strip()


def test_server_card_says_it_is_installed_by_the_it_team():
    m = sw.BY_ID["server_info"]
    assert m.info_only and "IT team" in m.why


def test_connect_ai_card_names_claude_grok_and_muse():
    t = sw.BY_ID["connect_ai"].title
    assert all(n in t for n in ("Claude", "Grok", "Muse"))


# ── choices → plan (with dependencies) ──────────────────────────────────────
def test_routes_pulls_in_jobs_and_phone_access():
    ids = [m.id for m in sw.modules_for(["routes"])]
    assert ids == ["remote", "jobs", "routes"], ids
    assert set(sw.added_by_requirement(["routes"])) == {"remote", "jobs"}


def test_payments_pulls_in_email_and_jobs():
    ids = {m.id for m in sw.modules_for(["business"])}
    assert {"jobs", "payments", "email", "remote"} <= ids


def test_plan_keeps_spec_order():
    ids = [m.id for m in sw.modules_for(sw.SERVICE_IDS)]
    assert ids == [m.id for m in sw.MODULES]


def test_nothing_added_for_a_self_contained_choice():
    assert sw.added_by_requirement(["email"]) == []


# ── progress file ────────────────────────────────────────────────────────────
@pytest.fixture
def prog(tmp_path, monkeypatch):
    # Isolate every live "already done?" check from the real PC's settings
    # (this PC really has email set up, tasks, learnings, a Watchdog…).
    monkeypatch.setattr(sw, "_tracked_paths", lambda: [])        # "nothing indexed" unless a test says so
    monkeypatch.setattr(sw, "email_configured", lambda: False)
    monkeypatch.setattr(sw, "watchdog_running", lambda: False)
    monkeypatch.setattr(sw, "schedule_task_exists", lambda: False)
    empty = __import__("types").SimpleNamespace(load_custom_tasks=lambda: [],
                                                get_learning_stats=lambda: {"active": 0})
    monkeypatch.setitem(sys.modules, "custom_tasks_manager", empty)
    monkeypatch.setitem(sys.modules, "self_learning", empty)
    return sw.Progress.load(tmp_path / "setup_progress.json")


def test_new_user_defaults(prog):
    assert prog.services == [] and prog.states == {} and not prog.picked
    assert [m.id for m in prog.plan()] == [m.id for m in sw.modules_for(sw.DEFAULT_SERVICES)]
    assert sw.is_first_launch(prog)


def test_choose_saves_and_reloads(prog):
    prog.choose(["phone", "files", "not-a-service"])
    again = sw.Progress.load(prog.path)
    assert again.picked and again.services == ["files", "phone"]      # known ids only, in SERVICES order
    assert not sw.is_first_launch(again)


def test_states_saved_and_bad_values_dropped(prog):
    prog.set_state("email", sw.SKIPPED)
    raw = json.loads(prog.path.read_text(encoding="utf-8"))
    raw["states"]["nope"] = "done"
    raw["states"]["index"] = "weird"
    prog.path.write_text(json.dumps(raw), encoding="utf-8")
    again = sw.Progress.load(prog.path)
    assert again.states == {"email": sw.SKIPPED}


def test_corrupt_file_starts_fresh(tmp_path):
    p = tmp_path / "setup_progress.json"
    p.write_text("{not json", encoding="utf-8")
    assert sw.Progress.load(p).states == {}


def test_add_service_is_idempotent(prog):
    prog.add_service("email")
    prog.add_service("email")
    assert prog.services == ["email"]


def test_detected_done_beats_saved_state(prog, monkeypatch):
    prog.set_state("index", sw.NOT_STARTED)
    monkeypatch.setattr(sw, "_tracked_paths", lambda: [r"C:\Docs"])
    assert prog.state(sw.BY_ID["index"]) == sw.DONE
    assert not sw.is_first_launch(prog), "someone with indexed folders isn't a first-time user"


def test_counts_skip_counts_as_finished_and_info_cards_dont_count(prog):
    prog.choose(["email", "team"])
    assert prog.counts() == (0, 1)                               # server_info card not counted
    prog.set_state("email", sw.SKIPPED)
    assert prog.counts() == (1, 1) and prog.all_finished()


def test_tracked_paths_reads_the_real_file_format(tmp_path, monkeypatch):
    monkeypatch.setattr(sw.Path, "home", lambda: tmp_path)
    monkeypatch.delitem(sys.modules, "rag_preprocessor", raising=False)
    (tmp_path / ".rag_auto_update_dirs.json").write_text(json.dumps({"directories": [r"C:\A", ""]}))
    assert sw._tracked_paths() == [r"C:\A"]


# ── order + "Index your first folder" (David 2026-09-30) ────────────────────
def test_index_is_first_and_connect_ai_second():
    assert [m.id for m in sw.MODULES[:2]] == ["index", "connect_ai"]
    assert [m.id for m in sw.modules_for(["files"])][:2] == ["index", "connect_ai"]


def test_is_tracked_matches_the_file_or_a_parent_folder(monkeypatch):
    monkeypatch.setattr(sw, "_tracked_paths", lambda: [r"C:\Users\x\Documents\AI-Prowler"])
    assert sw.is_tracked(r"C:\Users\x\Documents\AI-Prowler\COMPLETE_USER_GUIDE.md")
    assert sw.is_tracked(r"c:\users\x\documents\ai-prowler")                  # case-insensitive on Windows
    assert not sw.is_tracked(r"C:\Users\x\Documents\AI-Prowler-Other\a.md")  # sibling prefix ≠ inside
    monkeypatch.setattr(sw, "_tracked_paths", lambda: [r"C:\Guide\COMPLETE_USER_GUIDE.md"])
    assert sw.is_tracked(r"C:\Guide\COMPLETE_USER_GUIDE.md")


def test_find_user_guide_prefers_documents_copy(tmp_path, monkeypatch):
    docs = tmp_path / "Documents" / "AI-Prowler" / sw.GUIDE_NAME
    inst = tmp_path / "install" / sw.GUIDE_NAME
    monkeypatch.setattr(sw, "guide_candidates", lambda: [docs, inst])
    assert sw.find_user_guide() is None
    inst.parent.mkdir(parents=True)
    inst.write_text("x")
    assert sw.find_user_guide() == inst
    docs.parent.mkdir(parents=True)
    docs.write_text("x")
    assert sw.find_user_guide() == docs


@pytest.mark.parametrize("info,state", [
    ({}, "missing"),
    ({"ready": False, "detail": "Tesseract binary not found on this system"}, "missing"),
    ({"ready": True, "missing_langs": ["spa"], "detail": "missing language pack(s): spa"}, "partial"),
    ({"ready": True, "missing_langs": [], "detail": "Tesseract 5.4.0 ready (eng+spa)"}, "ready"),
])
def test_ocr_summary(info, state):
    assert sw.ocr_summary(info)[0] == state


@pytest.fixture(scope="module")
def tkroot():
    """One hidden Tk window shared by the flow tests (Tk won't always build a
    second root in the same process after the first is destroyed)."""
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    yield root
    root.destroy()


def _pump(root, until, seconds):
    import time
    end = time.time() + seconds
    while not until() and time.time() < end:
        root.update()
        time.sleep(0.01)


def test_index_flow_self_repairs_ocr_then_indexes_the_guide(tmp_path, monkeypatch, tkroot):
    """Simulated run: OCR missing → the flow calls the app's repair → OCR ready
    → the guide goes through the Index Docs queue + Start → tracked → done."""
    from tkinter import ttk
    root = tkroot
    guide = tmp_path / sw.GUIDE_NAME
    guide.write_text("# guide")
    tracked = []
    monkeypatch.setattr(sw, "guide_candidates", lambda: [guide])
    monkeypatch.setattr(sw, "_tracked_paths", lambda: list(tracked))
    monkeypatch.setattr(sw.IndexFirstFolderFlow, "POLL_MS", 20)
    calls = []

    class FakeApp:
        notebook = ttk.Notebook(root)
        _index_queue = []
        _index_running = False
        ocr_ok = False

        def _check_ocr_ready(self):
            return ({"ready": True, "missing_langs": [], "detail": "Tesseract 5.4.0 ready (eng+spa)"}
                    if FakeApp.ocr_ok else {"ready": False, "detail": "Tesseract binary not found"})

        def _install_or_repair_ocr(self):
            calls.append("repair")
            root.after(60, lambda: setattr(FakeApp, "ocr_ok", True))

        def _queue_add_paths(self, paths):
            calls.append(("queue", paths))
            self._index_queue.extend(paths)

        def start_indexing(self):
            calls.append("start")
            FakeApp._index_running = True

            def finish():
                tracked.extend(self._index_queue)          # the worker tracks what it indexed
                FakeApp._index_running = False
            root.after(80, finish)

    FakeApp.notebook.add(ttk.Frame(FakeApp.notebook), text="📚 Index Docs")
    prog = sw.Progress(path=tmp_path / "p.json", picked=True)
    prog.choose(["files"])
    panel = sw.SetupCenterPanel(ttk.Frame(root), FakeApp(), progress=prog)
    flow = sw.IndexFirstFolderFlow(panel)
    _pump(root, lambda: prog.states.get("index") == sw.DONE, 10)
    flow.win.destroy()
    assert calls and calls[0] == "repair", calls
    assert ("queue", [str(guide)]) in calls and "start" in calls
    assert prog.states.get("index") == sw.DONE
    assert sw.is_tracked(guide)


def test_index_flow_never_starts_the_users_own_queue(tmp_path, monkeypatch, tkroot):
    from tkinter import ttk
    root = tkroot
    guide = tmp_path / sw.GUIDE_NAME
    guide.write_text("# guide")
    monkeypatch.setattr(sw, "guide_candidates", lambda: [guide])
    monkeypatch.setattr(sw, "_tracked_paths", lambda: [])
    started = []

    class FakeApp:
        notebook = ttk.Notebook(root)
        _index_queue = [r"C:\Users\x\MyOwnFolder"]          # the user already queued something
        _index_running = False

        def _check_ocr_ready(self):
            return {"ready": True, "missing_langs": [], "detail": "ready"}

        def _queue_add_paths(self, paths):
            self._index_queue.extend(paths)

        def start_indexing(self):
            started.append(1)

    prog = sw.Progress(path=tmp_path / "p.json", picked=True)
    panel = sw.SetupCenterPanel(ttk.Frame(root), FakeApp(), progress=prog)
    flow = sw.IndexFirstFolderFlow(panel)
    _pump(root, lambda: str(guide) in FakeApp._index_queue, 5)
    _pump(root, lambda: False, 0.5)                      # let it settle — it must NOT press Start
    flow.win.destroy()
    assert str(guide) in FakeApp._index_queue, "the guide wasn't added to the queue"
    assert not started, "the flow pressed Start with the user's own folders in the queue"


# ── "Connect your AI" — Claude · Grok · Muse (2026-09-30) ───────────────────
TOKEN = "Sup3r-Secret-Bearer-Token-9f8e7d"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    """A config.json like AI-Prowler writes: domain + Bearer Token."""
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"tunnel_domain": "https://ap-test-123.ai-prowler.com/",
                             "remote_token": TOKEN}), encoding="utf-8")
    monkeypatch.setattr(sw, "CONFIG_PATH", p)
    return p


def test_urls_come_from_the_configured_domain(cfg):
    assert sw.tunnel_domain() == "ap-test-123.ai-prowler.com"
    assert sw.mcp_url() == "https://ap-test-123.ai-prowler.com/mcp"
    assert sw.connect_page_url() == "https://ap-test-123.ai-prowler.com/connect"
    assert sw.bearer_token() == TOKEN


def test_no_domain_means_no_urls(tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "CONFIG_PATH", tmp_path / "missing.json")
    assert sw.tunnel_domain() == "" and sw.mcp_url() == "" and sw.connect_page_url() == ""


def test_the_token_is_never_in_the_page_the_email_or_the_muse_message(cfg):
    url = sw.mcp_url()
    for text in (sw.connect_page_html(url), sw.email_link(url), sw.muse_message(url)):
        assert TOKEN not in text, "the Bearer Token leaked"
    assert url in sw.connect_page_html(url)
    from urllib.parse import unquote
    assert url in unquote(sw.email_link(url)), "the connector URL isn't in the email body"


def test_phone_page_has_every_ai_and_copy_email_buttons(cfg):
    page = sw.connect_page_html(sw.mcp_url())
    for a in sw.AI_APPS:
        assert a["name"] in page and a["connect_url"] in page
    assert "Copy URL" in page and "Email it to me" in page and "Copy message" in page
    assert sw.CONNECTOR_NAME in page and 'name="viewport"' in page


def test_phone_page_escapes_the_url():
    page = sw.connect_page_html('https://x.example/mcp"><script>alert(1)</script>')
    assert "<script>alert(1)</script>" not in page


def test_ai_links_and_methods():
    assert sw.AI_BY_ID["grok"]["connect_url"] == "https://grok.com/connectors"
    assert sw.AI_BY_ID["claude"]["connect_url"].startswith("https://claude.ai/customize/connectors")
    assert sw.AI_BY_ID["muse"].get("message"), "Muse uses the message method until its menu works"
    for a in sw.AI_APPS:
        assert any(sw.CONNECTOR_NAME in s for s in a["steps"]) or a.get("message")
    msg = sw.muse_message("https://h/mcp")
    assert "https://h/mcp" in msg and sw.CONNECTOR_NAME in msg


def test_qr_code_encodes_the_connect_page(cfg):
    pytest.importorskip("segno")
    png = sw.qr_png(sw.connect_page_url())
    assert png and png[:8] == b"\x89PNG\r\n\x1a\n"
    assert sw.qr_png("") is None


def test_open_ai_connector_refuses_without_phone_access(tmp_path, monkeypatch, tkroot):
    monkeypatch.setattr(sw, "CONFIG_PATH", tmp_path / "missing.json")
    shown, opened = [], []
    import tkinter.messagebox as mb
    import webbrowser
    monkeypatch.setattr(mb, "showwarning", lambda *a, **k: shown.append(a[0]))
    monkeypatch.setattr(mb, "showinfo", lambda *a, **k: shown.append(a[0]))
    monkeypatch.setattr(webbrowser, "open", lambda u: opened.append(u))
    assert sw.open_ai_connector(tkroot, "grok") is False
    assert shown == ["Set up phone access first"] and not opened


@pytest.mark.parametrize("ai", ["claude", "grok", "muse"])
def test_open_ai_connector_copies_and_opens(cfg, monkeypatch, tkroot, ai):
    shown, opened = [], []
    import tkinter.messagebox as mb
    import webbrowser
    monkeypatch.setattr(mb, "showinfo", lambda *a, **k: shown.append(a[1]))
    monkeypatch.setattr(webbrowser, "open", lambda u: opened.append(u))
    assert sw.open_ai_connector(tkroot, ai) is True
    clip = tkroot.clipboard_get()
    url = sw.mcp_url()
    assert (clip == sw.muse_message(url)) if ai == "muse" else (clip == url)
    assert TOKEN not in clip and TOKEN not in shown[0]
    assert opened == [sw.AI_BY_ID[ai]["connect_url"]]


@pytest.mark.parametrize("with_domain", [True, False])
def test_connect_window_draws(tmp_path, monkeypatch, tkroot, cfg, with_domain):
    from tkinter import ttk
    if not with_domain:
        monkeypatch.setattr(sw, "CONFIG_PATH", tmp_path / "missing.json")

    class FakeApp:
        notebook = ttk.Notebook(tkroot)
        root = tkroot
    prog = sw.Progress(path=tmp_path / "p.json", picked=True)
    panel = sw.SetupCenterPanel(ttk.Frame(tkroot), FakeApp(), progress=prog)
    flow = sw.ConnectAIFlow(panel.frame, FakeApp(), panel)
    tkroot.update_idletasks()
    texts = []

    def walk(w):
        for c in w.winfo_children():
            try:
                texts.append(str(c.cget("text")))
            except Exception:
                pass
            walk(c)
    walk(flow.win)
    joined = " | ".join(texts)
    for name in ("Claude", "Grok", "Muse"):
        assert f"Connect {name}" in joined
    if with_domain:
        assert "Copy URL" in joined and "Email it to me" in joined
    else:
        assert "Phone access isn't set up yet" in joined
    assert TOKEN not in joined
    flow._done()
    assert prog.states.get("connect_ai") == sw.DONE


# ── "Keep your index up to date" (Watchdog + nightly Windows task) ──────────
@pytest.mark.parametrize("t,ok", [("02:00", True), ("23:59", True), ("7:05", True),
                                  ("24:00", False), ("12:7", False), ("noon", False), ("", False)])
def test_valid_hhmm(t, ok):
    assert sw.valid_hhmm(t) is ok


@pytest.mark.parametrize("watch,task,done", [(True, False, True), (False, True, True),
                                             (False, False, False)])
def test_auto_index_done_when_either_is_on(monkeypatch, watch, task, done):
    monkeypatch.setattr(sw, "watchdog_running", lambda: watch)
    monkeypatch.setattr(sw, "schedule_task_exists", lambda: task)
    assert bool(sw.detect_auto_index()) is done


def _auto_flow(tkroot, tmp_path, monkeypatch, watch_on=False, task_on=False):
    from tkinter import ttk
    state = {"watch": watch_on, "task": task_on}
    monkeypatch.setattr(sw, "watchdog_running", lambda: state["watch"])
    monkeypatch.setattr(sw, "schedule_task_exists", lambda: state["task"])
    calls = []

    class FakeApp:
        notebook = ttk.Notebook(tkroot)

        def _watchdog_toggle(self):
            calls.append("watchdog")
            state["watch"] = not state["watch"]

        def set_schedule(self, t, days):
            calls.append(("schedule", t, tuple(days)))
            state["task"] = True
    prog = sw.Progress(path=tmp_path / "p.json", picked=True)
    panel = sw.SetupCenterPanel(ttk.Frame(tkroot), FakeApp(), progress=prog)
    return sw.AutoIndexFlow(panel), prog, calls


def test_auto_index_turns_both_on_and_marks_done(tkroot, tmp_path, monkeypatch):
    flow, prog, calls = _auto_flow(tkroot, tmp_path, monkeypatch)
    flow.apply()
    flow._verify()                                   # (normally 2.5 s later)
    assert calls == ["watchdog", ("schedule", "02:00", tuple(sw.ALL_DAYS))]
    assert prog.states.get("auto_index") == sw.DONE
    flow.win.destroy()


def test_auto_index_never_stops_a_running_watchdog(tkroot, tmp_path, monkeypatch):
    flow, prog, calls = _auto_flow(tkroot, tmp_path, monkeypatch, watch_on=True)
    flow.nightly.set(False)
    flow.apply()
    assert "watchdog" not in calls, "toggling a running Watchdog would STOP it"
    flow.win.destroy()


@pytest.mark.parametrize("bad", ["25:00", "noon"])
def test_auto_index_bad_time_changes_nothing(tkroot, tmp_path, monkeypatch, bad):
    flow, prog, calls = _auto_flow(tkroot, tmp_path, monkeypatch)
    flow.time.set(bad)
    flow.apply()
    assert calls == [] and "HH:MM" in flow.msg.cget("text")
    flow.win.destroy()


def test_auto_index_nothing_ticked(tkroot, tmp_path, monkeypatch):
    flow, prog, calls = _auto_flow(tkroot, tmp_path, monkeypatch)
    flow.watch.set(False)
    flow.nightly.set(False)
    flow.apply()
    assert calls == [] and "at least one" in flow.msg.cget("text")
    flow.win.destroy()


# ── Phase 3: Links & Analysis · Learnings · Email ───────────────────────────
import datetime as _dt
import types as _types


def test_dates_for_templates():
    wed = _dt.date(2026, 9, 30)                                  # a Wednesday
    assert sw.next_weekday(wed, 0) == _dt.date(2026, 10, 5)      # next Monday
    assert sw.next_weekday(_dt.date(2026, 10, 5), 0) == _dt.date(2026, 10, 12)   # "after today"
    assert sw.first_of_next_month(wed) == _dt.date(2026, 10, 1)
    assert sw.first_of_next_month(_dt.date(2026, 12, 15)) == _dt.date(2027, 1, 1)


def test_template_args_learnings_always_email_only_if_asked():
    tpl = sw.ANALYSIS_TEMPLATES[0]
    a = sw.template_task_args(tpl, _dt.date(2026, 9, 30), email_on=False)
    assert a["output_learnings"] is True and a["output_email"] is False
    assert a["first_due"] == "2026-10-05" and a["schedule_day_of_week"] == 0
    monthly = next(t for t in sw.ANALYSIS_TEMPLATES if t["schedule"] == "monthly")
    m = sw.template_task_args(monthly, _dt.date(2026, 9, 30), email_on=True)
    assert m["first_due"] == "2026-10-01" and m["output_email"] is True and "schedule_day_of_week" not in m


def test_templates_pass_the_real_task_validation():
    """The real custom_tasks_manager.create_task only validates + builds the
    dict (the caller saves) — so this checks our templates without saving."""
    ctm = pytest.importorskip("custom_tasks_manager")
    for tpl in sw.ANALYSIS_TEMPLATES:
        t = ctm.create_task(**sw.template_task_args(tpl, _dt.date.today(), email_on=False))
        assert t["label"] == tpl["label"] and t["schedule"] == tpl["schedule"]


@pytest.mark.parametrize("cfg,ok", [({"smtp_host": "smtp.gmail.com"}, True), ({"backend": "outlook"}, True),
                                    ({"smtp_host": ""}, False), (None, False)])
def test_email_configured(tmp_path, monkeypatch, cfg, ok):
    p = tmp_path / "email_config.json"
    if cfg is not None:
        p.write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.setattr(sw, "EMAIL_CONFIG_PATH", p)
    assert sw.email_configured() is ok


def _panel(tkroot, tmp_path, services=("files",)):
    from tkinter import ttk

    class FakeApp:
        notebook = ttk.Notebook(tkroot)
    prog = sw.Progress(path=tmp_path / "p.json", picked=True)
    prog.choose(list(services))
    return sw.SetupCenterPanel(ttk.Frame(tkroot), FakeApp(), progress=prog), prog


@pytest.fixture
def fake_tasks(monkeypatch):
    store = {"tasks": [{"label": "Weekly summary of my new documents"}], "saved": 0}
    fake = _types.SimpleNamespace(
        load_custom_tasks=lambda: list(store["tasks"]),
        create_task=lambda **kw: dict(kw, task_id="custom_x"),
        save_custom_tasks=lambda tasks: (store.update(tasks=tasks, saved=store["saved"] + 1), True)[1])
    monkeypatch.setitem(sys.modules, "custom_tasks_manager", fake)
    return store


def test_links_adds_chosen_and_skips_ones_already_there(tkroot, tmp_path, monkeypatch, fake_tasks):
    monkeypatch.setattr(sw, "email_configured", lambda: False)
    panel, prog = _panel(tkroot, tmp_path, services=("files", "analyses", "business"))
    flow = sw.LinksFlow(panel)
    assert {t["id"] for t in flow.templates} == {t["id"] for t in sw.ANALYSIS_TEMPLATES}
    for v in flow.vars.values():
        v.set(True)
    flow.add()
    labels = [t["label"] for t in fake_tasks["tasks"]]
    assert labels.count("Weekly summary of my new documents") == 1, "added a duplicate"
    assert "Overdue invoices check" in labels and "Monthly business review" in labels
    assert flow.win.winfo_exists(), "finishing the step closed its own window (panel redraw bug)"
    assert "Already there" in flow.msg.cget("text")
    assert prog.states.get("links") == sw.DONE
    flow.win.destroy()


def test_links_hides_business_templates_without_the_business_choice(tkroot, tmp_path, monkeypatch, fake_tasks):
    monkeypatch.setattr(sw, "email_configured", lambda: False)
    panel, _ = _panel(tkroot, tmp_path, services=("files", "analyses"))
    flow = sw.LinksFlow(panel)
    assert [t["id"] for t in flow.templates] == ["weekly_docs"]
    flow.win.destroy()


def test_links_nothing_ticked_adds_nothing(tkroot, tmp_path, monkeypatch, fake_tasks):
    monkeypatch.setattr(sw, "email_configured", lambda: False)
    panel, prog = _panel(tkroot, tmp_path)
    flow = sw.LinksFlow(panel)
    for v in flow.vars.values():
        v.set(False)
    flow.add()
    assert fake_tasks["saved"] == 0 and "at least one" in flow.msg.cget("text")
    flow.win.destroy()


def test_learnings_saves_an_example(tkroot, tmp_path, monkeypatch):
    saved = []
    monkeypatch.setitem(sys.modules, "self_learning",
                        _types.SimpleNamespace(record_learning=lambda **kw: saved.append(kw) or kw))
    panel, prog = _panel(tkroot, tmp_path)
    flow = sw.LearningsFlow(panel)
    flow.save()                                                   # empty → refused
    assert not saved and "Fill in both" in flow.msg.cget("text")
    title, content = sw.LEARNING_EXAMPLES[0]
    flow._fill(title, content)
    flow.save()
    assert saved and saved[0]["title"] == title and saved[0]["content"] == content
    assert prog.states.get("learnings") == sw.DONE
    flow.win.destroy()


def test_email_flow_marks_done_only_when_configured(tkroot, tmp_path, monkeypatch):
    state = {"ok": False}
    monkeypatch.setattr(sw, "email_configured", lambda: state["ok"])
    panel, prog = _panel(tkroot, tmp_path, services=("email",))
    flow = sw.EmailFlow(panel)
    assert prog.states.get("email") != sw.DONE
    state["ok"] = True
    flow.check()
    assert prog.states.get("email") == sw.DONE
    flow.win.destroy()


# ── Phase 4: Phone access · Remote app on your phone ────────────────────────
def test_autostart_script_matches_the_installer():
    s = sw.autostart_script(Path(r"C:\Program Files\AI-Prowler"), "david")
    for part in ('/SC ONLOGON', '/TN "AI-Prowler-AutoStart"', '/RL HIGHEST', '/DELAY 0001:00',
                 '/RU "david"', r'C:\Program Files\AI-Prowler\RAG_RUN.bat', "/F"):
        assert part in s, part


def test_power_status_shape_is_readonly_and_complete():
    ps = sw.power_status()                                      # read-only queries on this PC
    assert set(ps) == {k for k, _ in sw.POWER_CHECKS}
    assert all(isinstance(ok, bool) and isinstance(d, str) for ok, d in ps.values())


def test_remote_seen_on_phone(tmp_path, monkeypatch):
    p = tmp_path / "remote_app_seen.json"
    monkeypatch.setattr(sw, "REMOTE_SEEN_PATH", p)
    assert sw.remote_seen_on_phone() is False
    p.write_text(json.dumps({"last_at": 1, "last_was_phone": False}))
    assert sw.remote_seen_on_phone() is False                   # desktop browser only
    p.write_text(json.dumps({"phone_seen": True, "first_phone_at": 2}))
    assert sw.remote_seen_on_phone() is True


def test_detect_remote_needs_domain_and_token(cfg, tmp_path, monkeypatch):
    assert sw.detect_remote() is True
    assert sw.remote_app_url() == "https://ap-test-123.ai-prowler.com/remote/"
    monkeypatch.setattr(sw, "CONFIG_PATH", tmp_path / "missing.json")
    assert sw.detect_remote() is False and sw.remote_app_url() == ""


def _remote_flow(tkroot, tmp_path, monkeypatch, link_ok, power_ok=False, auto=False):
    from tkinter import ttk
    monkeypatch.setattr(sw, "link_reachable", lambda d=None, timeout=15: link_ok)
    monkeypatch.setattr(sw, "power_status", lambda: {k: (power_ok, "") for k, _ in sw.POWER_CHECKS})
    monkeypatch.setattr(sw, "autostart_task_exists", lambda: auto)
    applied = []

    class FakeApp:
        notebook = ttk.Notebook(tkroot)

        def _apply_power_settings(self):
            applied.append(1)
    prog = sw.Progress(path=tmp_path / "p.json", picked=True)
    prog.choose(["phone"])
    panel = sw.SetupCenterPanel(ttk.Frame(tkroot), FakeApp(), progress=prog)
    return sw.RemoteFlow(panel), prog, applied


def test_phone_access_done_when_link_answers_and_token_set(cfg, tkroot, tmp_path, monkeypatch):
    flow, prog, _ = _remote_flow(tkroot, tmp_path, monkeypatch, link_ok=True)
    _pump(tkroot, lambda: prog.states.get("remote") == sw.DONE, 5)
    assert prog.states.get("remote") == sw.DONE
    assert flow.rows["power"][0].cget("text") == "❌" and flow.rows["autostart"][0].cget("text") == "❌"
    flow.win.destroy()


def test_phone_access_not_done_when_link_silent(cfg, tkroot, tmp_path, monkeypatch):
    flow, prog, _ = _remote_flow(tkroot, tmp_path, monkeypatch, link_ok=False, power_ok=True, auto=True)
    _pump(tkroot, lambda: flow.rows["link"][0].cget("text") == "❌" and
          "isn't answering" in flow.rows["link"][1].cget("text"), 5)
    assert prog.states.get("remote") != sw.DONE
    assert flow.rows["power"][0].cget("text") == "✅" and flow.rows["autostart"][0].cget("text") == "✅"
    flow.win.destroy()


def test_phone_access_power_fix_uses_the_settings_tab_script(cfg, tkroot, tmp_path, monkeypatch):
    flow, prog, applied = _remote_flow(tkroot, tmp_path, monkeypatch, link_ok=True)
    flow.apply_power()
    assert applied == [1], "didn't run the Settings tab's own Apply Power Settings"
    flow.win.destroy()


def test_remote_app_step_waits_for_a_phone(cfg, tkroot, tmp_path, monkeypatch):
    seen = tmp_path / "remote_app_seen.json"
    monkeypatch.setattr(sw, "REMOTE_SEEN_PATH", seen)
    monkeypatch.setattr(sw.RemotePwaFlow, "POLL_MS", 30)
    panel, prog = _panel(tkroot, tmp_path, services=("phone",))
    flow = sw.RemotePwaFlow(panel)
    _pump(tkroot, lambda: False, 0.3)
    assert prog.states.get("remote_pwa") != sw.DONE and "Waiting" in flow.wait_lbl.cget("text")
    seen.write_text(json.dumps({"phone_seen": True}))
    _pump(tkroot, lambda: prog.states.get("remote_pwa") == sw.DONE, 3)
    assert prog.states.get("remote_pwa") == sw.DONE
    flow.win.destroy()


def test_remote_app_step_without_phone_access(tkroot, tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "CONFIG_PATH", tmp_path / "missing.json")
    panel, prog = _panel(tkroot, tmp_path, services=("phone",))
    flow = sw.RemotePwaFlow(panel)
    texts = [str(c.cget("text")) for c in flow.body.winfo_children() if hasattr(c, "cget")
             and "text" in c.keys()]
    assert any("Set up Phone access first" in t for t in texts)
    flow.win.destroy()


# ── Shared QR window (Settings: Remote Control URL · Small Business: Jobs App URL) ─
def test_app_urls(cfg):
    assert sw.jobs_app_url() == "https://ap-test-123.ai-prowler.com/jobs/"
    assert sw.remote_app_url() == "https://ap-test-123.ai-prowler.com/remote/"


def test_qr_window_refuses_without_a_link(tkroot, monkeypatch):
    shown = []
    import tkinter.messagebox as mb
    monkeypatch.setattr(mb, "showwarning", lambda *a, **k: shown.append(a[0]))
    assert sw.show_qr_window(tkroot, "Remote app", "") is False
    assert shown == ["No link yet"]


def test_qr_window_shows_the_link_and_never_the_token(cfg, tkroot):
    pytest.importorskip("segno")
    before = set(tkroot.winfo_children())
    assert sw.show_qr_window(tkroot, "Jobs app — scan with your phone", sw.jobs_app_url(), "Crew") is True
    win = next(w for w in tkroot.winfo_children() if w not in before)
    texts = []

    def walk(w):
        for c in w.winfo_children():
            try:
                texts.append(str(c.cget("text")))
            except Exception:
                pass
            if c.winfo_class() in ("TEntry", "Entry"):
                texts.append(c.get())
            walk(c)
    walk(win)
    joined = " | ".join(texts)
    assert sw.jobs_app_url() in joined and "Add to Home Screen" in joined
    assert TOKEN not in joined
    win.destroy()


# ── Phase 5: Jobs app ───────────────────────────────────────────────────────
@pytest.mark.parametrize("given,stored", [("7", "0.07"), ("7%", "0.07"), ("6.5", "0.065"),
                                          ("0.07", "0.07"), ("0", "0"), ("", "")])
def test_tax_to_store(given, stored):
    assert sw.tax_to_store(given) == stored


@pytest.mark.parametrize("bad", ["abc", "150", "-3"])
def test_tax_to_store_refuses_nonsense(bad):
    with pytest.raises(ValueError):
        sw.tax_to_store(bad)


def test_tax_to_show():
    assert sw.tax_to_show("0.07") == "7" and sw.tax_to_show("0.065") == "6.5" and sw.tax_to_show("7%") == "7"


def test_parse_customers_csv_maps_columns_and_skips_nameless():
    text = ("\ufeffFull Name,Business,Mobile,E-mail,Address,Town,State,Postal Code,Notes\n"
            "Jane Smith,,386-555-0101,jane@x.com,42 Beach Dr,New Smyrna Beach,FL,32168,vip\n"
            ",Blue Wave Cafe,386-555-0102,,1 Main St,Daytona,FL,32114,\n"
            ",,386-555-0103,nobody@x.com,,,,,no name here\n")
    rows, skipped = sw.parse_customers_csv(text)
    assert skipped == 1 and len(rows) == 2
    jane, cafe = rows
    assert jane["First Name"] == "Jane" and jane["Last Name"] == "Smith"
    assert jane["Phone"] == "386-555-0101" and jane["Email"] == "jane@x.com"
    assert jane["Street Address"] == "42 Beach Dr" and jane["City"] == "New Smyrna Beach"
    assert jane["ZIP"] == "32168" and "Notes" not in jane
    assert cafe["Company Name"] == "Blue Wave Cafe" and "First Name" not in cafe
    assert all(r["Status Active/Inactive"] == "Active" for r in rows)


@pytest.fixture
def jobdb(tmp_path, monkeypatch):
    """A throw-away job database (settings + customers) in a temp state dir."""
    import sqlite3
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    # Isolate the real per-user phone/skip files: detect_jobs() reads
    # JOBS_SEEN_PATH and JOBS_SKIPS_PATH, which on a dev machine reflect
    # what the user actually clicked. Point them at tmp files so jobs tests
    # are hermetic.
    monkeypatch.setattr(sw, "JOBS_SEEN_PATH", tmp_path / "jobs_app_seen.json")
    monkeypatch.setattr(sw, "JOBS_SKIPS_PATH", tmp_path / "jobs_section_skips.json")
    p = tmp_path / "ai_prowler_jobs.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, notes TEXT)")
    con.execute("CREATE TABLE customers (customer_id TEXT, company_name TEXT, first_name TEXT, "
                "last_name TEXT, phone TEXT)")
    con.execute("INSERT INTO settings VALUES ('Tax Rate', '0.07', '')")
    con.commit()
    con.close()
    calls = []

    def fake_tool(name, **kw):                       # stands in for AI-Prowler's own tools
        calls.append((name, kw))
        con = sqlite3.connect(p)
        try:
            if name == "update_job_spreadsheet":
                con.execute("UPDATE settings SET value=? WHERE key=?", (kw["updates"]["Value"], kw["job_identifier"]))
            elif name == "create_setting":
                con.execute("INSERT INTO settings (key, value) VALUES (?, ?)",
                            (kw["updates"]["Setting"], kw["updates"]["Value"]))
            elif name == "create_customer":
                u = kw["updates"]
                con.execute("INSERT INTO customers VALUES ('CUST-1', ?, ?, ?, ?)",
                            (u.get("Company Name", ""), u.get("First Name", ""), u.get("Last Name", ""),
                             u.get("Phone", "")))
            con.commit()
        finally:
            con.close()
        return "✅ done"
    monkeypatch.setattr(sw, "_tool", fake_tool)
    return p, calls


def test_job_db_reads(jobdb):
    p, _ = jobdb
    assert sw.job_db_path() == p
    assert sw.read_settings(["Tax Rate", "Business Name"]) == {"Tax Rate": "0.07", "Business Name": ""}
    assert sw.customer_count() == 0 and sw.setting_exists("tax rate") and not sw.setting_exists("Business Name")
    assert sw.detect_jobs() is False


def test_save_setting_updates_existing_or_creates_new(jobdb):
    p, calls = jobdb
    sw.save_setting("Tax Rate", "0.065")
    sw.save_setting("Business Name", "Vavro Window Cleaning")
    assert [c[0] for c in calls] == ["update_job_spreadsheet", "create_setting"]
    assert calls[0][1]["sheet_name"] == "Settings" and calls[0][1]["id_column"] == "Setting"
    assert sw.read_settings(["Tax Rate", "Business Name"]) == {"Tax Rate": "0.065",
                                                               "Business Name": "Vavro Window Cleaning"}


def _jobs_flow(tkroot, tmp_path, monkeypatch, cfg_domain=True):
    from tkinter import ttk
    monkeypatch.setattr(sw.JobsFlow, "POLL_MS", 30)
    monkeypatch.setattr(sw, "JOBS_SEEN_PATH", tmp_path / "jobs_app_seen.json")
    monkeypatch.setattr(sw, "JOBS_SKIPS_PATH", tmp_path / "jobs_section_skips.json")
    if not cfg_domain:
        monkeypatch.setattr(sw, "CONFIG_PATH", tmp_path / "missing.json")
    panel, prog = _panel(tkroot, tmp_path, services=("business",))
    return sw.JobsFlow(panel), prog


def test_jobs_business_details_save_only_changes_and_convert_tax(cfg, jobdb, tkroot, tmp_path, monkeypatch):
    p, calls = jobdb
    flow, prog = _jobs_flow(tkroot, tmp_path, monkeypatch)
    assert flow.biz_vars["Tax Rate"].get() == "7"                # shown as a percent
    flow.save_business()
    assert "business name" in flow.msg.cget("text").lower() and not calls     # name required
    flow.biz_vars["Business Name"].set("Vavro Window Cleaning")
    flow.biz_vars["Tax Rate"].set("6.5")
    flow.save_business()
    keys = [c[1].get("job_identifier") or c[1]["updates"].get("Setting") for c in calls]
    assert sorted(keys) == ["Business Name", "Tax Rate"], "saved fields that didn't change"
    assert sw.read_settings(["Tax Rate"])["Tax Rate"] == "0.065"
    flow.biz_vars["Tax Rate"].set("lots")
    flow.save_business()
    assert "percent" in flow.msg.cget("text")
    flow.win.destroy()


def test_jobs_done_after_name_and_first_customer(cfg, jobdb, tkroot, tmp_path, monkeypatch):
    flow, prog = _jobs_flow(tkroot, tmp_path, monkeypatch)
    flow.add_one()
    assert "company or a name" in flow.msg.cget("text")
    flow.biz_vars["Business Name"].set("Vavro Window Cleaning")
    flow.save_business()
    assert prog.states.get("jobs") != sw.DONE                    # no customer yet
    flow.cust_vars["First Name"].set("Jane")
    flow.cust_vars["Phone"].set("386-555-0101")
    flow.add_one()
    assert sw.customer_count() == 1
    assert prog.states.get("jobs") != sw.DONE                    # phone app not seen yet
    (tmp_path / "jobs_app_seen.json").write_text(json.dumps({"phone_seen": True}))
    flow._refresh()
    assert prog.states.get("jobs") == sw.DONE                    # phone + name + customer
    assert flow.cust_vars["First Name"].get() == "", "form not cleared after adding"
    assert "1 customer" in flow.count_lbl.cget("text")
    flow.win.destroy()


def test_jobs_section_skips_allow_green_with_phone(cfg, jobdb, tkroot, tmp_path, monkeypatch):
    flow, prog = _jobs_flow(tkroot, tmp_path, monkeypatch)
    (tmp_path / "jobs_app_seen.json").write_text(json.dumps({"phone_seen": True}))
    flow._refresh()
    assert prog.states.get("jobs") != sw.DONE                    # sections 1+2 still open
    flow.skip_business()
    assert "Database tab" in flow.biz_note.cget("text")
    assert prog.states.get("jobs") != sw.DONE                    # customers still open
    flow.skip_customers()
    assert "Database tab" in flow.cust_note.cget("text")
    assert prog.states.get("jobs") == sw.DONE                    # skips do not block green
    assert sw.detect_jobs()
    flow.win.destroy()

def test_jobs_csv_import(cfg, jobdb, tkroot, tmp_path, monkeypatch):
    p, calls = jobdb
    csvf = tmp_path / "customers.csv"
    csvf.write_text("Name,Phone\nJane Smith,1\nBob Lee,2\n,3\n", encoding="utf-8")
    import tkinter.filedialog as fd
    import tkinter.messagebox as mb
    monkeypatch.setattr(fd, "askopenfilename", lambda **k: str(csvf))
    asked = []
    monkeypatch.setattr(mb, "askyesno", lambda *a, **k: asked.append(a[1]) or True)
    flow, prog = _jobs_flow(tkroot, tmp_path, monkeypatch)
    flow.import_csv()
    assert asked and "Import 2 customers" in asked[0] and "1 row" in asked[0]
    assert sw.customer_count() == 2 and "Imported 2" in flow.msg.cget("text")
    flow.win.destroy()


def test_jobs_phone_wait_and_qr(cfg, jobdb, tkroot, tmp_path, monkeypatch):
    flow, prog = _jobs_flow(tkroot, tmp_path, monkeypatch)
    assert flow.url == "https://ap-test-123.ai-prowler.com/jobs/"
    _pump(tkroot, lambda: False, 0.2)
    assert "Waiting" in flow.phone_lbl.cget("text")
    (tmp_path / "jobs_app_seen.json").write_text(json.dumps({"phone_seen": True}))
    _pump(tkroot, lambda: "✅" in flow.phone_lbl.cget("text"), 3)
    assert "✅" in flow.phone_lbl.cget("text")
    flow.win.destroy()


def test_jobs_without_phone_access(jobdb, tkroot, tmp_path, monkeypatch):
    flow, prog = _jobs_flow(tkroot, tmp_path, monkeypatch, cfg_domain=False)
    assert flow.url == "" and flow.phone_lbl is None
    flow.win.destroy()


# ── Phase 5: Payment links ──────────────────────────────────────────────────
def _paycfg(tmp_path, monkeypatch, **kw):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(kw), encoding="utf-8")
    monkeypatch.setattr(sw, "CONFIG_PATH", p)
    return p


@pytest.mark.parametrize("cfg,stripe,square,done", [
    ({}, "", "", False),
    ({"stripe_secret_key": "sk_test_x"}, "automatic", "", True),
    ({"stripe_payment_url": "https://buy.stripe.com/x"}, "fixed link", "", True),
    ({"square_access_token": "t"}, "", "incomplete", False),              # Location ID missing
    ({"square_access_token": "t", "square_location_id": "L"}, "", "automatic", True),
    ({"square_payment_url": "https://square.link/x"}, "", "fixed link", True),
])
def test_payment_status(tmp_path, monkeypatch, cfg, stripe, square, done):
    _paycfg(tmp_path, monkeypatch, **cfg)
    s = sw.payment_status()
    assert (s["stripe"], s["square"]) == (stripe, square)
    assert s["email_on"] is True and s["sms_on"] is False                 # the server's defaults
    assert sw.detect_payments() is done


def test_test_link_uses_ai_prowlers_own_checkout_for_one_dollar(monkeypatch):
    made = []
    fake = _types.SimpleNamespace(
        _load_payment_settings=lambda: {"stripe_secret_key": "sk_test_x", "square_access_token": "t",
                                        "square_location_id": "L"},
        _create_stripe_checkout_url=lambda key, amt, desc, ref: made.append(("stripe", key, amt)) or "https://s/x",
        _create_square_checkout_url=lambda tok, loc, amt, desc, ref: made.append(("square", tok, loc, amt)) or "")
    monkeypatch.setitem(sys.modules, "ai_prowler_mcp", fake)
    assert sw.make_test_payment_link("stripe") == "https://s/x"
    assert sw.make_test_payment_link("square") == ""                      # provider said no → ''
    assert made == [("stripe", "sk_test_x", 1.0), ("square", "t", "L", 1.0)]


def test_payments_flow_test_buttons_and_never_writes_config(tkroot, tmp_path, monkeypatch):
    p = _paycfg(tmp_path, monkeypatch, stripe_secret_key="sk_test_x", square_payment_url="https://square.link/x")
    before = p.read_bytes()
    opened = []
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda u: opened.append(u))
    monkeypatch.setattr(sw, "make_test_payment_link", lambda prov: f"https://{prov}.test/checkout")
    panel, prog = _panel(tkroot, tmp_path, services=("business",))
    flow = sw.PaymentsFlow(panel)
    buttons = [w.cget("text") for w in flow.test_row.winfo_children()]
    assert buttons == ["🧪 Make a $1 Stripe test link"], "test button only for exact-amount providers"
    assert prog.states.get("payments") == sw.DONE
    flow.test("stripe")
    _pump(tkroot, lambda: bool(opened), 3)
    assert opened == ["https://stripe.test/checkout"] and "Nothing is charged" in flow.msg.cget("text")
    assert p.read_bytes() == before, "the Setup Center changed the payment settings"
    flow.win.destroy()


def test_payments_flow_not_set_up(tkroot, tmp_path, monkeypatch):
    _paycfg(tmp_path, monkeypatch)
    panel, prog = _panel(tkroot, tmp_path, services=("business",))
    flow = sw.PaymentsFlow(panel)
    assert prog.states.get("payments") != sw.DONE and "Not set up yet" in flow.msg.cget("text")
    assert not flow.test_row.winfo_children()
    flow.win.destroy()


# ── Phase 6: Crew routes ────────────────────────────────────────────────────
def test_home_address(tmp_path, monkeypatch):
    _paycfg(tmp_path, monkeypatch)
    assert sw.home_address() == ""
    _paycfg(tmp_path, monkeypatch, owner_street="12 Ocean Ave", owner_city="New Smyrna Beach",
            owner_state="FL", owner_zip="32168")
    assert sw.home_address() == "12 Ocean Ave, New Smyrna Beach, FL 32168"


@pytest.mark.parametrize("mode,addr,home,ok", [
    ("Jobs Only", {}, "", False),
    ("Jobs Only", {}, "x", True),
    ("Company Location", {}, "x", False),                    # home doesn't count in this mode
    ("Company Location", {"Start/End Street Address": "1 Shop Rd", "Start/End City": "Edgewater"}, "", True),
])
def test_route_origin_ok(monkeypatch, mode, addr, home, ok):
    monkeypatch.setattr(sw, "home_address", lambda: home)
    s = {k: "" for k in sw.ROUTE_KEYS}
    s.update({"Route Origin Mode": mode, "Email Route On Build": "Disabled", **addr})
    assert sw.route_origin_ok(s)[0] is ok


def _routes_flow(tkroot, tmp_path, monkeypatch, ai=None, home=""):
    monkeypatch.setattr(sw, "home_address", lambda: home)
    monkeypatch.setattr(sw, "ai_routing_status",
                        lambda: ai or {"cli": True, "token": "ok", "detail": ""})
    panel, prog = _panel(tkroot, tmp_path, services=("routes",))
    return sw.RoutesFlow(panel), prog


def test_routes_defaults_shown_from_the_database(jobdb, tkroot, tmp_path, monkeypatch):
    flow, prog = _routes_flow(tkroot, tmp_path, monkeypatch)
    assert flow.mode.get() == "Jobs Only" and flow.email_on.get() is False     # the server's defaults
    assert "❌" in flow.origin_lbl.cget("text")                                 # no home address
    flow.win.destroy()


def test_routes_company_location_saves_only_changes_and_marks_done(jobdb, tkroot, tmp_path, monkeypatch):
    p, calls = jobdb
    flow, prog = _routes_flow(tkroot, tmp_path, monkeypatch)
    flow.mode.set("Company Location")
    flow._mode_changed()
    flow.addr_vars["Start/End Street Address"].set("1 Shop Rd")
    flow.addr_vars["Start/End City"].set("Edgewater")
    flow.save()
    saved = {c[1].get("job_identifier") or c[1]["updates"]["Setting"] for c in calls}
    assert saved == {"Route Origin Mode", "Start/End Street Address", "Start/End City"}, saved
    assert sw.read_settings(["Route Origin Mode"])["Route Origin Mode"] == "Company Location"
    assert prog.states.get("routes") == sw.DONE and "✅" in flow.origin_lbl.cget("text")
    flow.win.destroy()


def test_routes_jobs_only_needs_home_address_and_never_writes_it(jobdb, tkroot, tmp_path, monkeypatch):
    p, calls = jobdb
    cfg = _paycfg(tmp_path, monkeypatch)
    before = cfg.read_bytes()
    flow, prog = _routes_flow(tkroot, tmp_path, monkeypatch, home="")
    flow.email_on.set(True)
    flow.save()
    assert [c[1]["updates"].get("Setting") or c[1].get("job_identifier") for c in calls] == ["Email Route On Build"]
    assert prog.states.get("routes") != sw.DONE and "Still needed" in flow.msg.cget("text")
    assert cfg.read_bytes() == before, "the routes step wrote the home address / config"
    flow.win.destroy()


def test_routes_jobs_only_done_with_home_address(jobdb, tkroot, tmp_path, monkeypatch):
    flow, prog = _routes_flow(tkroot, tmp_path, monkeypatch, home="12 Ocean Ave, NSB, FL 32168")
    flow.save()
    assert prog.states.get("routes") == sw.DONE
    flow.win.destroy()


@pytest.mark.parametrize("ai,buttons", [
    ({"cli": True, "token": "ok", "detail": ""}, []),
    ({"cli": False, "token": "no_credentials", "detail": ""},
     ["Install Claude Code", "🔑 Get / Renew Token (Links & Analysis)"]),
    ({"cli": True, "token": "expiring_soon", "detail": ""}, ["🔑 Get / Renew Token (Links & Analysis)"]),
])
def test_routes_ai_status_and_fixes(jobdb, tkroot, tmp_path, monkeypatch, ai, buttons):
    flow, prog = _routes_flow(tkroot, tmp_path, monkeypatch, ai=ai)
    _pump(tkroot, lambda: "Checking" not in flow.ai_lbl.cget("text"), 3)
    assert [w.cget("text") for w in flow.ai_fix.winfo_children()] == buttons
    flow.win.destroy()


# ── Collapsible panel + colour lights (David 2026-10-01) ────────────────────
@pytest.fixture
def fake_states(monkeypatch):
    """Drive every step's state directly; no partly-done settings."""
    states = {}
    monkeypatch.setattr(sw.Progress, "state", lambda self, m: states.get(m.id, sw.NOT_STARTED))
    monkeypatch.setattr(sw, "PARTIAL", {})
    return states


def test_core_steps_are_the_files_choice():
    assert set(sw.CORE_IDS) == {"index", "connect_ai", "auto_index", "learnings"}


def test_overall_light_requirement_never_red(tmp_path, fake_states):
    # "business" pulls Email in as a requirement of Payment links — the user
    # never chose "Send emails and reports", so Email must not turn it red.
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["business"])                               # jobs, payments + remote, email
    assert p.overall_light() == sw.YELLOW                # not red: email is a requirement, not chosen
    fake_states.update(remote=sw.DONE, jobs=sw.DONE, payments=sw.DONE)
    assert p.overall_light() == sw.YELLOW                # email (requirement) still to do
    fake_states["email"] = sw.DONE
    assert p.overall_light() == sw.GREEN


def test_overall_light_chosen_non_core_is_yellow(tmp_path, fake_states):
    # "analyses" is chosen, but Links & Analysis is not a core step — yellow, never red.
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["analyses"])                               # links + index (requirement)
    assert p.overall_light() == sw.YELLOW
    fake_states.update(links=sw.DONE, index=sw.DONE)
    assert p.overall_light() == sw.GREEN


def test_step_lights(tmp_path, fake_states, monkeypatch):
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    fake_states.update(index=sw.DONE, email=sw.SKIPPED, links=sw.IN_PROGRESS)
    L = lambda mid: p.light(sw.BY_ID[mid])
    assert (L("index"), L("email"), L("links"), L("learnings")) == (sw.GREEN, sw.GREY, sw.YELLOW, sw.RED)
    monkeypatch.setattr(sw, "PARTIAL", {"jobs": lambda: True})       # half-configured → yellow
    assert L("jobs") == sw.YELLOW and L("routes") == sw.RED


def test_overall_light_only_counts_chosen_steps(tmp_path, fake_states):
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["files"])                                  # index, connect_ai, auto_index, learnings
    fake_states.update(index=sw.DONE, connect_ai=sw.DONE, auto_index=sw.DONE)
    assert p.overall_light() == sw.RED                   # learnings (chosen, core) not done
    fake_states["learnings"] = sw.DONE
    assert p.overall_light() == sw.GREEN, "email / links weren't chosen — they must not keep it red"


def test_overall_light_yellow_until_later_chosen_steps_done(tmp_path, fake_states):
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["files", "routes"])                        # + remote, jobs, routes
    fake_states.update({m: sw.DONE for m in ("index", "connect_ai", "auto_index", "learnings")})
    assert p.overall_light() == sw.YELLOW
    fake_states.update(remote=sw.DONE, jobs=sw.DONE)
    assert p.overall_light() == sw.YELLOW                # routes still to do
    fake_states["routes"] = sw.SKIPPED                   # skipped = decided
    assert p.overall_light() == sw.GREEN


def test_collapsed_default_and_remembered(tmp_path, fake_states):
    path = tmp_path / "p.json"
    p = sw.Progress(path=path, picked=True)
    p.choose(["email"])
    assert p.is_collapsed() is False                     # something to do → open
    fake_states["email"] = sw.DONE
    assert p.is_collapsed() is True                      # all done → folded by default
    p.set_collapsed(False)                               # the user's own choice wins…
    assert sw.Progress.load(path).collapsed is False     # …and is remembered
    assert sw.Progress.load(path).is_collapsed() is False


def test_panel_folds_and_shows_the_lights(tkroot, tmp_path, fake_states):
    from tkinter import ttk

    class FakeApp:
        notebook = ttk.Notebook(tkroot)
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["files"])
    fake_states.update(index=sw.DONE, connect_ai=sw.IN_PROGRESS)
    panel = sw.SetupCenterPanel(ttk.Frame(tkroot), FakeApp(), progress=p)
    assert panel.expanded and panel.toggle_btn.cget("text").startswith("▾")
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.RED]
    rows = [r for f in panel.frame.winfo_children() for r in f.winfo_children() if hasattr(r, "light")]
    assert [r.light for r in rows] == [sw.GREEN, sw.YELLOW, sw.RED, sw.RED]   # index, connect, auto, learnings
    panel._toggle(False)                                  # ▸ fold
    assert not panel.expanded and panel.toggle_btn.cget("text").startswith("▸")
    assert not [r for f in panel.frame.winfo_children() for r in f.winfo_children() if hasattr(r, "light")]
    assert panel.light_lbl.winfo_exists(), "the light must stay visible when folded"
    assert sw.Progress.load(tmp_path / "p.json").collapsed is True
    fake_states.update(connect_ai=sw.DONE, auto_index=sw.DONE, learnings=sw.DONE)
    panel.render()
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.GREEN] and "all set" in panel.count_lbl.cget("text")


# ── Changing the answers changes the lights (David 2026-10-01) ──────────────
def _answer_picker(panel, tkroot, tick=(), untick=()):
    """Open the real "What do you want AI-Prowler to do?" window, change the
    ticks like a person would, and press Save."""
    before = set(panel.frame.winfo_children())
    panel.open_picker()
    win = next(w for w in panel.frame.winfo_children() if w not in before)
    win.grab_release()
    boxes = {}

    def walk(w):
        for c in w.winfo_children():
            if c.winfo_class() == "TCheckbutton":
                boxes[c.cget("text")] = c
            walk(c)
    walk(win)
    labels = {sid: label for sid, label, _ in sw.SERVICES}
    for sid in tick:
        if not tkroot.globalgetvar(boxes[labels[sid]].cget("variable")):
            boxes[labels[sid]].invoke()
    for sid in untick:
        if tkroot.globalgetvar(boxes[labels[sid]].cget("variable")):
            boxes[labels[sid]].invoke()
    save = []

    def find_save(w):
        for c in w.winfo_children():
            if c.winfo_class() == "TButton" and c.cget("text") == "Save":
                save.append(c)
            find_save(c)
    find_save(win)
    save[0].invoke()
    tkroot.update()


def _row_lights(panel):
    return {r.mid: r.light for f in panel.frame.winfo_children() for r in f.winfo_children()
            if hasattr(r, "light")}


@pytest.fixture
def lit_panel(tkroot, tmp_path, fake_states, monkeypatch):
    """A panel whose 'files' steps are all done; nothing else is."""
    from tkinter import ttk
    _orig_row = sw.SetupCenterPanel._row

    def tagged_row(self, parent, m):                       # remember which step each row is
        _orig_row(self, parent, m)
        last = parent.winfo_children()[-1]
        last.mid = m.id
    monkeypatch.setattr(sw.SetupCenterPanel, "_row", tagged_row)

    class FakeApp:
        notebook = ttk.Notebook(tkroot)
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["files"])
    fake_states.update({m: sw.DONE for m in ("index", "connect_ai", "auto_index", "learnings")})
    return sw.SetupCenterPanel(ttk.Frame(tkroot), FakeApp(), progress=p), p


def test_lights_follow_new_answers_add_a_service(lit_panel, tkroot):
    panel, p = lit_panel
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.GREEN]          # only "files" chosen, all done
    _answer_picker(panel, tkroot, tick=["routes"])                          # now also crew routes
    assert p.services == ["files", "routes"]
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.YELLOW], "new later steps must turn it yellow"
    lights = _row_lights(panel)
    assert lights["routes"] == sw.RED and lights["jobs"] == sw.RED and lights["remote"] == sw.RED
    assert lights["index"] == sw.GREEN


def test_lights_follow_new_answers_remove_a_service(lit_panel, tkroot, fake_states):
    panel, p = lit_panel
    _answer_picker(panel, tkroot, tick=["email"])
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.YELLOW]          # email chosen, not done
    assert "email" in _row_lights(panel)
    _answer_picker(panel, tkroot, untick=["email"])                         # changed their mind
    assert p.services == ["files"] and "email" not in _row_lights(panel)
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.GREEN], "an un-chosen step must stop counting"


def test_lights_follow_new_answers_core_not_chosen_never_red(lit_panel, tkroot, fake_states):
    panel, p = lit_panel
    fake_states.update(learnings=sw.NOT_STARTED)
    panel.render()
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.RED]             # a chosen core step undone
    _answer_picker(panel, tkroot, tick=["email"], untick=["files"])         # files no longer wanted
    assert p.services == ["email"]
    assert panel.light_lbl.cget("fg") != sw.LIGHT_COLOR[sw.RED], "un-chosen core steps must never keep it red"
    assert "learnings" not in _row_lights(panel)


def test_add_more_button_updates_lights(lit_panel, tkroot):
    panel, p = lit_panel
    panel._add("phone")                                                     # ➕ Add more → Phone access
    assert "phone" in p.services
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.YELLOW]
    assert {"remote", "remote_pwa"} <= set(_row_lights(panel))


def test_lights_update_while_folded(lit_panel, tkroot):
    panel, p = lit_panel
    panel._toggle(False)
    _answer_picker(panel, tkroot, tick=["routes"])           # "➕ Add a service" from the folded header
    assert panel.light_lbl.cget("fg") == sw.LIGHT_COLOR[sw.YELLOW]
