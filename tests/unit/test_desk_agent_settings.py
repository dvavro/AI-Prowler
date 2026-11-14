"""Service Desk Agent settings + its virtual-assistant persona (2026-10-29).

desk_agent_settings.py, the /desk-api/agent and /support-api/agent routes, the
app's Settings → 🤖 Agent card and AI-Prowler's Business-tab panel (desk_gui_agent).

Run: run_tests.bat tests\\unit\\test_desk_agent_settings.py
"""
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_agent_settings as das  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import desk_http as h  # noqa: E402
import desk_portal  # noqa: E402

OWNER = {"id": "dave", "role": "owner"}
MANAGER = {"id": "mgr", "role": "manager"}
CUSTOMER = {"id": "c1", "role": "customer", "contact_id": "C-0001"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    return path


def picture(fmt="PNG", size=(640, 480), color=(30, 120, 200)) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, fmt)
    return buf.getvalue()


def call(db, method, path, body=None, *, actor=None, edition="solo", raw=None,
         ctype="application/json", services=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    st, ct, out = h.route(method, path, query={}, body=data, content_type=ctype, actor=actor,
                          edition=edition, db_path=db, services=services or {"business": "Blue Wave"})
    return st, ct, (json.loads(out) if ct == b"application/json" else out)


def multipart(name, data):
    b = "----agentboundary"
    body = (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n').encode() + data + f"\r\n--{b}--\r\n".encode()
    return body, f"multipart/form-data; boundary={b}"


# ── defaults and validation ──────────────────────────────────────────────────

def test_defaults_are_safe_and_in_the_desk_settings(db):
    s = desk_db.get_settings(db)
    assert s["agent_enabled"] is False and s["agent_shadow"] is True
    assert s["agent_provider"] == "chat_only"
    assert all(s[f"agent_stage_{k}"] == "suggest" for k, _ in das.STAGES)
    assert s["agent_label"] == "Virtual assistant" and s["agent_photo"] == ""
    assert s["agent_hours"] == [0, 24]                       # any time by default


def test_no_reply_delay_or_overnight_wait():
    # David 2026-10-30: replies go out as soon as they're approved, at any hour.
    assert not any("delay" in k for k in das.DEFAULTS)
    assert not hasattr(das, "send_after") and not hasattr(das, "reply_delay_seconds")


@pytest.mark.parametrize("key,value", [
    ("agent_label", "Office manager"),           # not an assistant label
    ("agent_label", ""),
    ("agent_provider", "muse_api"),
    ("agent_stage_intake", "always"),
    ("agent_reply_delay_min", 2),                # removed 2026-10-30
    ("agent_name", "Sam <script>"),
    ("agent_name", "x" * (das.NAME_MAX + 1)),
    ("agent_hours", [20, 7]),
    ("agent_hours", [7, 25]),
    ("agent_max_items", 0),
    ("agent_photo", "C:/Windows/evil.jpg"),
], ids=lambda v: str(v)[:20])
def test_bad_values_are_refused(db, key, value):
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(db, key, value, edition="solo")


def test_good_values_save_and_names_are_trimmed(db):
    desk_db.set_setting(db, "agent_name", "  Sam  ", edition="solo")
    desk_db.set_setting(db, "agent_label", "AI assistant", edition="solo")
    desk_db.set_setting(db, "agent_hours", [8, 18], edition="solo")
    s = desk_db.get_settings(db)
    assert (s["agent_name"], s["agent_label"], s["agent_hours"]) == ("Sam", "AI assistant", [8, 18])


def test_only_the_owner_changes_agent_settings(db):
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(db, "agent_enabled", True, actor=MANAGER, edition="business")


# ── the persona always says it's an assistant ────────────────────────────────

def test_persona_always_carries_the_assistant_label():
    p = das.persona({"agent_name": "Sam", "agent_label": "Virtual assistant"}, "Blue Wave")
    assert p["display"] == "Sam · Virtual assistant"
    assert p["signature"] == "— Sam (virtual assistant), Blue Wave"
    assert das.persona({}, "")["display"] == "Virtual assistant"
    # a label that isn't on the list (hand-edited DB) falls back to the default
    assert das.persona({"agent_name": "Sam", "agent_label": "Owner"})["display"] == "Sam · Virtual assistant"
    assert das.persona({"agent_reply_signoff": "Team BW"}, "Blue Wave")["signature"].endswith("Team BW")


def test_prompt_tells_the_agent_to_be_honest_about_being_an_assistant():
    t = das.prompt_identity({"agent_name": "Sam"}, "Blue Wave")
    assert "not a person" in t and "Never say or suggest you are a human" in t
    assert "virtual assistant" in t and "someone from the team" in t
    assert "— Sam (virtual assistant), Blue Wave" in t


# ── the photo ────────────────────────────────────────────────────────────────

def test_photo_is_square_small_jpeg_without_exif():
    from PIL import Image
    src = Image.new("RGB", (900, 400), (200, 50, 50))
    ex = Image.Exif()
    ex[0x010F] = "PhoneMaker"                                 # camera make
    buf = io.BytesIO()
    src.save(buf, "JPEG", exif=ex.tobytes())
    out = Image.open(io.BytesIO(das.make_avatar(buf.getvalue())))
    assert out.format == "JPEG" and out.size == (das.PHOTO_SIDE, das.PHOTO_SIDE)
    assert not out.getexif()


@pytest.mark.parametrize("kind", ["empty", "not_a_picture", "too_big"])
def test_bad_photos_are_refused(kind):
    # built inside the test: an 8 MB parameter becomes a 32 MB test id
    data = {"empty": b"", "not_a_picture": b"not a picture",
            "too_big": b"\x00" * (das.PHOTO_MAX_BYTES + 1)}[kind]
    with pytest.raises(ValueError):
        das.make_avatar(data)


def test_set_and_clear_photo(db):
    das.set_photo(db, picture(), edition="solo")
    assert desk_db.get_settings(db)["agent_photo"] == das.PHOTO_REL
    assert das.photo_bytes(db)[:3] == b"\xff\xd8\xff"
    das.clear_photo(db, edition="solo")
    assert das.photo_bytes(db) is None and desk_db.get_settings(db)["agent_photo"] == ""
    with pytest.raises(desk_db.DeskError):
        das.set_photo(db, picture(), actor=MANAGER, edition="business")


# ── the app's API ────────────────────────────────────────────────────────────

def test_agent_settings_route_for_the_team(db):
    desk_db.set_setting(db, "agent_name", "Sam", edition="solo")
    st, _, d = call(db, "GET", "/desk-api/agent")
    assert st == 200 and d["persona"]["display"] == "Sam · Virtual assistant"
    assert d["persona"]["signature"] == "— Sam (virtual assistant), Blue Wave"
    assert set(d["settings"]) == set(das.DEFAULTS)
    assert d["options"]["labels"] == list(das.LABELS)
    assert "not a person" in d["prompt_identity"]
    assert call(db, "GET", "/desk-api/agent", actor=CUSTOMER)[0] == 404


def test_photo_upload_fetch_and_delete_over_the_api(db):
    body, ct = multipart("me.png", picture())
    st, _, d = call(db, "POST", "/desk-api/agent/photo", raw=body, ctype=ct)
    assert st == 200 and d["persona"]["photo"] is True
    st, ct2, img = call(db, "GET", "/desk-api/agent/photo")
    assert st == 200 and ct2 == b"image/jpeg" and img[:3] == b"\xff\xd8\xff"
    body, ct = multipart("me.png", picture())
    assert call(db, "POST", "/desk-api/agent/photo", raw=body, ctype=ct,
                actor=MANAGER, edition="business")[0] == 403
    assert call(db, "POST", "/desk-api/agent/photo/delete", {})[0] == 200
    assert call(db, "GET", "/desk-api/agent/photo")[0] == 404


def test_customers_see_the_name_label_and_photo(db):
    desk_db.set_setting(db, "agent_name", "Sam", edition="solo")
    das.set_photo(db, picture(), edition="solo")
    st, ct, out = desk_portal.route("GET", "/support-api/agent", query={}, body=b"", content_type="",
                                    ip="1.2.3.4", db_path=db, edition="solo", business="Blue Wave")
    d = json.loads(out)
    assert st == 200 and d["display"] == "Sam · Virtual assistant" and d["photo_url"].startswith(
        "/support-api/agent/photo")
    # nothing internal; ask_who (anyone / verified / ticket) tells the page whether and how to show the Ask chat
    assert set(d) == {"ok", "enabled", "name", "label", "display", "photo_url", "ask_who"}
    assert d["ask_who"] == "anyone"
    st, ct, img = desk_portal.route("GET", "/support-api/agent/photo", query={}, body=b"", content_type="",
                                    ip="1.2.3.4", db_path=db, edition="solo")
    assert st == 200 and ct == b"image/jpeg"


# ── AI-Prowler Business tab (desk_gui_agent) ─────────────────────────────────

def test_gui_save_writes_everything_valid(db):
    ok, msg = dga.save(db, {"agent_enabled": True, "agent_shadow": True, "agent_name": "Sam",
                            "agent_label": "Virtual assistant", "agent_provider": "grok_api",
                            "agent_stage_intake": "auto", "agent_hours": ["8", "19"],
                            "agent_monthly_budget_usd": "25", "agent_wait_hours": "6"}, edition="solo")
    assert ok, msg
    s = dga.load(db)
    assert (s["agent_provider"], s["agent_stage_intake"], s["agent_hours"], s["agent_wait_hours"]) == \
        ("grok_api", "auto", [8, 19], 6)


def test_gui_save_reports_problems_and_keeps_old_values(db):
    ok, msg = dga.save(db, {"agent_hours": ["20", "7"], "agent_name": "Sam!!",
                            "agent_wait_hours": "soon"}, edition="solo")
    assert not ok and "agent_hours" in msg and "whole number" in msg and "letters" in msg
    s = dga.load(db)
    assert (s["agent_hours"], s["agent_name"], s["agent_wait_hours"]) == ([0, 24], "", 4)


def test_every_agent_setting_has_help_for_claude_muse_grok(db):
    import desk_tools
    assert set(das.DEFAULTS) <= set(desk_tools.SETTING_HELP)
    assert not any("delay" in k for k in desk_tools.SETTING_HELP)
    out = desk_tools.tickets_settings(db, None, "solo", setting="agent_name", value="Sam")
    assert "✅ Saved." in out and "agent_name = Sam" in out and "virtual assistant" in out.lower()


def test_app_card_and_gui_panel_are_wired():
    html = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    assert "async function renderAgentSection()" in html and "await renderAgentSection();" in html
    for needle in ("/desk-api/agent/photo", "agent_hours", "agent_label", "function renderAgentFlow(",
                   'id="agFlow"', "o.stage_help[k]", "o.practice_help", "o.signoff_help"):
        assert needle in html, needle
    assert "agent_reply_delay" not in html and "agDMin" not in html      # delay removed 2026-10-30
    gui = (ROOT / "rag_gui.py").read_text(encoding="utf-8")
    assert "_dgs.build_section(self, banner)" in gui            # 2026-10-30: inside the Service Desk section
    assert 'desk_gui_agent.build_agent_settings(app, tabs["agent"], on_saved=' in \
        (ROOT / "desk_gui_settings.py").read_text(encoding="utf-8")
    assert "delay" not in (ROOT / "desk_gui_agent.py").read_text(encoding="utf-8").lower()


# ── Claude CLI runner: removed everywhere (David 2026-11-01, "Remove CLI everywhere") ─────────

def test_an_old_saved_cli_value_uses_the_saved_key(db, monkeypatch):
    """F-26: an install still holding claude_code showed "runner removed" and never ran, with its API keys saved."""
    import sqlite3
    import json as _json
    import desk_agent_providers as prov
    desk_db.set_setting(db, "agent_provider", "claude_api", edition="solo")
    conn = sqlite3.connect(db)
    conn.execute("UPDATE desk_settings SET value = ? WHERE key = 'agent_provider'", (_json.dumps("claude_code"),))
    conn.commit()
    conn.close()
    for saved, want in (({"claude_api"}, "claude_api"), ({"grok_api"}, "grok_api"), ({"claude_api", "grok_api"}, "claude_api"), (set(), "chat_only")):
        monkeypatch.setattr(prov, "_key", lambda p, s=saved: "k" if p in s else "")
        assert desk_db.get_settings(db)["agent_provider"] == want
        for ed in ("solo", "business"):
            assert das.effective_provider({"agent_provider": "claude_code"}, ed) == want
            assert das.effective_provider(desk_db.get_settings(db), ed) == want
    monkeypatch.setattr(prov, "_key", lambda p: "k" if p == "claude_api" else "")
    assert prov.ready(desk_db.get_settings(db)["agent_provider"], "solo") == (True, "")


def test_claude_cli_runner_is_removed(db, monkeypatch):
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "_key", lambda p: "")
    for ed in ("solo", "business"):
        with pytest.raises(desk_db.DeskError, match="removed"):
            desk_db.set_setting(db, "agent_provider", "claude_code", edition=ed)
        assert "claude_code" not in [p for p, _ in das.providers_for(ed)]
        # a value saved earlier, with no key saved, runs nothing
        assert das.effective_provider({"agent_provider": "claude_code"}, ed) == "chat_only"
    st, _, d = call(db, "GET", "/desk-api/agent", actor=OWNER, edition="business")
    assert d["settings"]["agent_provider"] == "chat_only"
    assert "claude_code" not in [p for p, _ in d["options"]["providers"]]
    ok, msg = dga.save(db, {"agent_provider": "claude_code"}, edition="solo")
    assert not ok and "removed" in msg


# ── help text and the flow diagram (David 2026-10-30) ───────────────────────

def test_every_stage_and_mode_has_plain_help():
    assert set(das.STAGE_HELP) == {k for k, _ in das.STAGES} == set(das.STAGE_SHORT)
    assert set(das.MODE_HELP) == set(das.STAGE_MODES)
    assert all(len(t) > 40 for t in das.STAGE_HELP.values())
    assert "business name" in das.SIGNOFF_HELP and "Nothing is changed" in das.PRACTICE_HELP
    o = das.ui_options("solo")
    assert o["stage_help"] == das.STAGE_HELP and o["practice_help"] and o["signoff_help"]


def _modes(f):
    return {p["id"]: p["mode"] for p in f["steps"]}


def test_flow_agent_off_lights_nothing():
    f = das.flow(dict(das.DEFAULTS), "solo")
    assert set(_modes(f).values()) == {"inactive"}
    assert not any(s["lit"] for s in f["states"]) and f["summary"].startswith("Agent is off")


def test_flow_agent_on_with_practice_mode():
    s = dict(das.DEFAULTS, agent_enabled=True, agent_shadow=True, agent_stage_learn="off")
    f = das.flow(s, "business")
    m = _modes(f)
    assert m["learn"] == "off" and all(m[k] == "practice" for k in ("intake", "first_reply",
                                                                     "resolution", "follow_through"))
    lit = {st["id"] for st in f["states"] if st["lit"]}
    assert lit == {"Open", "Assigned", "In Progress", "On Hold", "Fixed"}          # not Closed: Learn is off
    assert "Practice mode is ON" in f["summary"] and "nothing is sent to customers" in f["summary"]


# David 2026-10-30 (screenshots): "I don't see the states turn green when selected on" — each
# step is now coloured by its own choice, practice adds a ring, states take their step's colour.
G, A, P, GREY = "#16a34a", "#d97706", "#7c3aed", "#9ca3af"


@pytest.mark.parametrize("practice", [False, True], ids=["live", "practice"])
@pytest.mark.parametrize("choice,color,word", [("auto", G, "automatic"), ("suggest", A, "waits for OK"),
                                                ("off", GREY, "off")])
def test_every_choice_shows_its_own_colour(practice, choice, color, word):
    s = dict(das.DEFAULTS, agent_enabled=True, agent_shadow=practice,
             **{f"agent_stage_{k}": choice for k, _ in das.STAGES})
    f = das.flow(s, "business")
    for p in f["steps"]:
        assert (p["color"], p["word"], p["chosen"]) == (color, word, choice), p["id"]
        assert p["practice"] is (practice and choice != "off")                 # ring only when it runs
        assert p["tint"] == das.MODE_TINTS[color]
    for e in (e for e in f["edges"] if e["kind"] == "step"):
        assert e["color"] == color and e["dash"] is (choice == "off")
    lit = [st for st in f["states"] if st["lit"]]
    if choice == "off":
        assert not lit
    else:
        assert {st["id"] for st in lit} == {"Open", "Assigned", "In Progress", "On Hold", "Fixed", "Closed"}
        assert all(st["color"] == color and st["tint"] == das.MODE_TINTS[color] for st in lit)


def test_state_takes_the_strongest_colour_and_agent_off_keeps_the_choices_faint():
    s = dict(das.DEFAULTS, agent_enabled=True, agent_shadow=False, agent_stage_follow_through="suggest",
             agent_stage_learn="auto", agent_stage_intake="auto")
    states = {st["id"]: st for st in das.flow(s, "business")["states"]}
    assert states["Open"]["color"] == G and states["Closed"]["color"] == G and states["Fixed"]["color"] == A
    # Vicki 2026-10-31: with the agent off, turning a step to Auto must still show green — faint and
    # dashed (mode "inactive"), with no state lit and a summary of what will run once it's on.
    off = das.flow(dict(s, agent_enabled=False), "business")
    steps = {p["id"]: p for p in off["steps"]}
    assert steps["learn"]["color"] == G and steps["follow_through"]["color"] == A
    assert all(p["mode"] == "inactive" for p in off["steps"]) and not any(st["lit"] for st in off["states"])
    assert steps["learn"]["word"] == "automatic" and "Agent is off" in off["summary"]
    assert "Does on its own" in off["summary"] and "Learn" in off["summary"]
    assert all(e["dash"] for e in off["edges"] if e["kind"] == "step")


def test_app_diagram_reads_in_dark_and_light_themes():
    html = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    fn = html[html.index("function renderAgentFlow("):html.index("// ── Settings → Data")]
    assert "var(--card" not in fn and "#eef2ff" not in fn            # the white boxes (screenshot 2)
    assert 'fill="currentColor"' in fn                               # text follows the theme
    assert "fill-opacity=\"${st.lit ? 0.22 : 0}\"" in fn and "st.color" in fn
    assert "p.practice" in fn and "stroke-dasharray=\"5 3\"" in fn   # the practice ring


def test_tk_diagram_fits_and_dropdowns_clear():
    """One Tk window for all the checks (Windows often refuses a 2nd/3rd Tk root in one run)."""
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    try:
        for scale in (1.0, 1.25, 1.5, 2.0):
            _check_tk_scale(tk, root, scale)
        _check_dropdown_clears(tk, root)
    finally:
        root.destroy()


def _check_tk_scale(tk, root, scale):
    w, h = round((das.FLOW_W + 2 * dga.PAD) * scale), round((das.FLOW_H + 2 * dga.PAD) * scale)
    c = tk.Canvas(root, width=w, height=h)
    s = dict(das.DEFAULTS, agent_enabled=True, agent_shadow=True, agent_stage_intake="auto")
    tips = {}
    dga.draw_flow(c, das.flow(s, "business"), tips, scale)
    for i in c.find_all():
        x1, y1, x2, y2 = c.bbox(i)
        assert x1 >= -2 and y1 >= -2 and x2 <= w + 2 and y2 <= h + 2, (scale, c.type(i), c.bbox(i))
    texts = [i for i in c.find_all() if c.type(i) == "text"]
    assert all(str(c.itemcget(i, "font")).split()[1].startswith("-") for i in texts)   # pixel-sized
    assert "practice" in [c.itemcget(i, "text") for i in texts] and tips
    # each step's label stays inside its own box (the overflow in David's screenshot)
    for p in das.flow(s, "business")["steps"]:
        t = next(i for i in texts if c.itemcget(i, "text") == p["label"])
        bx1, _, bx2, _ = c.bbox(t)
        assert bx1 >= (p["x"] + dga.PAD) * scale - 1 and bx2 <= (p["x"] + p["w"] + dga.PAD) * scale + 1, \
            (scale, p["label"])
    c.destroy()


def _check_dropdown_clears(tk, root):
    """David: "when I select Auto … the Auto stays selected in a dark color"."""
    from tkinter import ttk
    # 2026-11-02: the variable must belong to THIS window — without master= it joined a window an
    # earlier test left open (full run only), the drop-down showed blank, and nothing could be selected
    var = tk.StringVar(root, value="Suggest")
    cb = dga.calm(ttk.Combobox(root, textvariable=var, state="readonly", values=["Off", "Suggest", "Auto"]))
    cb.pack()
    root.update()
    var.set("Auto")
    cb.selection_range(0, "end")
    assert cb.selection_present()
    cb.event_generate("<<ComboboxSelected>>")
    root.update()
    assert not cb.selection_present()
    cb.destroy()


def test_flow_live_mix_of_auto_suggest_off():
    s = dict(das.DEFAULTS, agent_enabled=True, agent_shadow=False, agent_stage_intake="auto",
             agent_stage_first_reply="suggest", agent_stage_resolution="off",
             agent_stage_follow_through="off", agent_stage_learn="off")
    f = das.flow(s, "business")
    assert _modes(f)["intake"] == "auto" and _modes(f)["first_reply"] == "suggest"
    assert f["summary"] == ("Does on its own: Intake. Waits for your OK: First reply. "
                            "Off: Resolution help, Follow-through, Learn.")
    dashed = [e for e in f["edges"] if e["kind"] == "step" and e["dash"]]
    assert len(dashed) == 4                     # resolution, learn, and follow-through's two arrows
    labels = {st["id"]: st["label"] for st in f["states"]}
    assert labels["Assigned"] == "Assigned" and das.flow(s, "solo")["states"][1]["label"] == "Assigned (you)"


def test_flow_boxes_fit_the_drawing():
    f = das.flow(dict(das.DEFAULTS, agent_enabled=True), "solo")
    for b in f["states"] + f["steps"]:
        assert 0 <= b["x"] and b["x"] + b["w"] <= f["w"] and 0 <= b["y"] and b["y"] + b["h"] <= f["h"], b["id"]


def test_gui_panel_builds_and_redraws_live(db, monkeypatch):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()

    class App:
        pass
    app = App(); app.root = root; app.status_var = tk.StringVar(value="Ready")
    monkeypatch.setattr(dga, "db_and_edition", lambda: (db, "business"))
    try:
        frame = tk.Frame(root)
        v = dga.build_agent_settings(app, frame)
        assert v and "claude_code" not in str(v["agent_provider"].get())
        canvas = next(w for w in frame.winfo_children()[1].winfo_children()[1].winfo_children()
                      if isinstance(w, tk.Canvas))
        assert len(canvas.find_all()) > 20
        v["agent_enabled"].set(True)            # live redraw, nothing saved yet
        v["agent_shadow"].set(False)
        v["agent_stage_intake"].set(das.STAGE_MODE_LABELS["auto"])
        root.update_idletasks()
        assert desk_db.get_settings(db)["agent_enabled"] is False
        texts = [canvas.itemcget(i, "text") for i in canvas.find_all() if canvas.type(i) == "text"]
        assert "automatic" in texts
    finally:
        root.destroy()
