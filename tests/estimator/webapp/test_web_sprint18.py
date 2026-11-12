"""Coder 2 Sprint 18: guided tours, the help panel, contextual help ("?") and empty states.

A tour is data in tour.js (plus the phone tour in mobile.js); progress is per user
(GET/POST /help/tours/progress) and the practice tour walks the practice project
(GET /help/practice). The first open of a screen auto-starts its tour unless the
user finished or skipped it; Skip saves skipped, Finish saves completed, closing
with X saves nothing.

NOTE on wiring: the API tests below go through router.route(), the way the web app
calls it. The Sprint 18 delegation (tours_api) must be reachable from route() —
if GET /help/tours/progress answers 404, the delegation never runs.
"""
import re
from pathlib import Path

import pytest

from estimator import practice
from estimator.api import nav, tours_api
from estimator.context import personal_context
from estimator.modules.registry import ModuleRegistry

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
HELP = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "help" / "guides"

CTX = personal_context()
REG = ModuleRegistry().load()


def _web_text():
    parts = [(WEB / name).read_text(encoding="utf-8") for name in sorted(p.name for p in WEB.glob("*.js"))]
    parts.append((WEB / "index.html").read_text(encoding="utf-8"))
    return "\n".join(parts)


def _tour_block():
    tour = (WEB / "tour.js").read_text(encoding="utf-8")
    m = re.search(r"const TOURS = \[(.*?)\n\];", tour, re.S)
    assert m, "TOURS array not found in tour.js"
    return m.group(1)


def _tour_ids():
    ids = re.findall(r'\{ id: "([^"]+)"', _tour_block())
    mobile = (WEB / "mobile.js").read_text(encoding="utf-8")
    m = re.search(r'const MREV_TOUR = \{ id: "([^"]+)"', mobile)
    assert m, "MREV_TOUR not found in mobile.js"
    return ids + [m.group(1)]


_STEP = re.compile(
    r'\{ sel: "((?:[^"\\]|\\.)*)"(?:, go: "((?:[^"\\]|\\.)*)")?,\s*title: "((?:[^"\\]|\\.)*)",\s*body: "((?:[^"\\]|\\.)*)"\s*\}'
)


def _steps():
    """Every tour step (tour.js TOURS + mobile.js MREV_TOUR) as (sel, go, title, body)."""
    found = _STEP.findall(_tour_block())
    found += _STEP.findall((WEB / "mobile.js").read_text(encoding="utf-8"))
    return [(s.replace('\\"', '"'), (g or "").replace('\\"', '"'),
             t.replace('\\"', '"'), b.replace('\\"', '"')) for s, g, t, b in found]


# ------------------------------------------------------------------ tour progress API


def test_progress_starts_empty(call):                                     # C2S18-W01
    # 2026-11-12: "auto" says whether tours start on their own (on until the user turns them off).
    assert call("GET", f"{API}/help/tours/progress").json() == {"ok": True, "tours": {}, "auto": True}


def test_help_progress_table_exists(db):                                  # C2S18-W02
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='help_progress'").fetchone()
    assert row is not None
    assert "PRIMARY KEY (user_id, tour_id)" in row[0]
    assert "status" in row[0] and "updated_at" in row[0]


def test_progress_round_trip(call):                                       # C2S18-W03
    done = call("POST", f"{API}/help/tours/progress", {"tour_id": "dashboard", "status": "completed"}).json()
    assert done == {"ok": True, "tour_id": "dashboard", "status": "completed"}
    assert call("GET", f"{API}/help/tours/progress").json()["tours"] == {"dashboard": "completed"}
    call("POST", f"{API}/help/tours/progress", {"tour_id": "dashboard", "status": "skipped"})
    assert call("GET", f"{API}/help/tours/progress").json()["tours"] == {"dashboard": "skipped"}
    call("POST", f"{API}/help/tours/progress", {"tour_id": "dashboard", "status": "not_started"})
    assert call("GET", f"{API}/help/tours/progress").json()["tours"] == {"dashboard": "not_started"}


def test_progress_is_per_user(call, session_for):                         # C2S18-W04
    alice = session_for("owner", user="alice")
    bob = session_for("owner", user="bob")
    call("POST", f"{API}/help/tours/progress", {"tour_id": "dashboard", "status": "completed"}, headers=alice)
    assert call("GET", f"{API}/help/tours/progress", headers=alice).json()["tours"] == {"dashboard": "completed"}
    assert call("GET", f"{API}/help/tours/progress", headers=bob).json()["tours"] == {}
    call("POST", f"{API}/help/tours/progress", {"tour_id": "projects", "status": "skipped"}, headers=bob)
    assert call("GET", f"{API}/help/tours/progress", headers=alice).json()["tours"] == {"dashboard": "completed"}
    assert call("GET", f"{API}/help/tours/progress", headers=bob).json()["tours"] == {"projects": "skipped"}


def test_progress_unknown_tour_is_404(call):                              # C2S18-W05
    r = call("POST", f"{API}/help/tours/progress", {"tour_id": "nope", "status": "completed"})
    assert r.status == 404 and "no such tour: nope" in r.json()["message"]
    r = call("POST", f"{API}/help/tours/progress", {"status": "completed"})
    assert r.status == 404 and "no such tour: (missing)" in r.json()["message"]
    assert call("GET", f"{API}/help/tours/progress").json()["tours"] == {}   # nothing saved


def test_progress_bad_status_is_400(call):                               # C2S18-W06
    for body in ({"tour_id": "dashboard", "status": "done"},
                 {"tour_id": "dashboard", "status": "DONE"},
                 {"tour_id": "dashboard"}):
        r = call("POST", f"{API}/help/tours/progress", body)
        assert r.status == 400 and "status must be not_started, completed or skipped" in r.json()["message"], body
    assert call("GET", f"{API}/help/tours/progress").json()["tours"] == {}


def test_progress_post_needs_the_app_header(call):                       # C2S18-W07
    r = call("POST", f"{API}/help/tours/progress",
             {"tour_id": "dashboard", "status": "completed"}, write_header=False)
    assert r.status == 403 and r.json()["error"] == "csrf"


@pytest.mark.parametrize("role", nav.ALL)
def test_progress_open_to_every_role(call, session_for, role):            # C2S18-W08
    assert call("GET", f"{API}/help/tours/progress", headers=session_for(role)).status == 200


def test_practice_returns_null_without_a_practice_project(call):         # C2S18-W09
    assert call("GET", f"{API}/help/practice").json() == {"ok": True, "estimate_id": None, "title": None}


def test_practice_returns_the_practice_project(db, call):                # C2S18-W10
    made = practice.create(db, CTX, REG)
    assert made["created"] is True and made["title"] == "Practice: Garcia house"
    db.commit()
    b = call("GET", f"{API}/help/practice").json()
    assert b["estimate_id"] == made["estimate_id"] and b["title"] == "Practice: Garcia house"


# ------------------------------------------------------------------ tour data


def test_tour_ids_match_the_api():                                        # C2S18-W11
    ids = _tour_ids()
    assert len(ids) == 27 and len(set(ids)) == 27
    assert set(ids) == set(tours_api.TOUR_IDS)
    assert "practice" in ids and "mobile" in ids


def test_every_tour_step_names_a_real_control():                          # C2S18-W12
    src = _web_text()
    steps = _steps()
    assert len(steps) == 87
    screens = {s["id"] for s in nav.SCREENS}
    for sel, _go, title, body in steps:
        assert title.strip() and body.strip(), sel
        if sel.startswith("#") and " " not in sel and "[" not in sel:
            ident = sel[1:]
            assert f'id: "{ident}"' in src or f'id="{ident}"' in src, sel
        elif sel.startswith("."):
            assert re.search(r'class:\s*"[^"]*\b' + re.escape(sel[1:]) + r'\b', src), sel
        elif sel.startswith("#nav a["):
            m = re.match(r'#nav a\[data-screen="([^"]+)"\]', sel)
            assert m, sel
            assert 'id="nav"' in src and '"data-screen": s.id' in src, sel
            assert m.group(1) in screens, sel
        else:
            raise AssertionError(f"unhandled selector shape: {sel}")


def test_practice_tour_walks_across_screens():                           # C2S18-W13
    steps = _steps()
    gos = [go for _sel, go, _t, _b in steps if go]
    assert len(gos) == 9   # 8 practice steps + the phone tour's first step
    # The phone tour's "#/m/reviews" is the only go that is not the practice tour's.
    practice_gos = [g for g in gos if g != "#/m/reviews"]
    assert len(practice_gos) == 8
    bases = {g.split("{practice}")[0] for g in practice_gos}
    assert bases == {"#/projects/", "#/takeoffs/", "#/reviews", "#/estimates/", "#/bids"}


def test_tour_engine_auto_starts_and_marks_progress():                   # C2S18-W14
    tour = (WEB / "tour.js").read_text(encoding="utf-8")
    assert "async function maybeStartTour" in tour
    assert "if (prog[id]) return;" in tour                     # finished or skipped: no auto-start
    assert 'tourSaveProgress(id, "skipped")' in tour           # Skip saves skipped
    assert 'tourSaveProgress(id, "completed")' in tour         # Finish saves completed
    close = tour.split("function tourClose()")[1].split("function ")[0]
    assert "tourSaveProgress" not in close                     # X saves nothing
    assert "translateX(-50%)" in tour                          # centred when a step has no control
    assert "r.top - h - 10" in tour                            # flips above when no room below
    assert "maybeStartTour()" in (WEB / "app.js").read_text(encoding="utf-8")   # route hook


# ------------------------------------------------------------------ help panel, "?", Help screen


def test_help_link_opens_the_panel_not_a_link():                         # C2S18-W15
    app = (WEB / "app.js").read_text(encoding="utf-8")
    link = app.split("function helpLink(screenId)")[1].split("function ")[0]
    assert 'el("button", { class: "button help-link"' in link
    assert "openHelpPanel(screenId)" in link
    assert 'go("#/help?screen=" + screenId)' in link              # fallback when tour.js failed
    assert "href" not in link                                     # a button, not a navigation link
    for screen in ("dashboard", "projects", "project"):
        assert f'helpLink("{screen}")' in app, screen


def test_help_panel_has_search_replay_and_close():                       # C2S18-W16
    tour = (WEB / "tour.js").read_text(encoding="utf-8")
    for part in ('id: "help-panel"', 'id: "help-panel-find"', 'id: "help-panel-replay"',
                 "Open the full Help screen", '"Escape"', '"hashchange"',
                 '"↻ Replay the " + tour.title + " tour"', '"▶ Practice project tour"',
                 "/help/guides?screen="):
        assert part in tour, part


def test_help_screen_lists_tours_with_replay():                          # C2S18-W17
    app = (WEB / "app.js").read_text(encoding="utf-8")
    for part in ("TOUR_IDS", "tourReplayBtn", '"Guided tours"', 'id: "help-tours"',
                 "tourLoadProgress", "A tour runs the first time you open its screen"):
        assert part in app, part


# ------------------------------------------------------------------ guides


def test_new_guides_cover_dashboard_and_projects():                      # C2S18-W18
    dash = (HELP / "use_the_dashboard.md").read_text(encoding="utf-8")
    assert "# Use the dashboard" in dash and "<!-- screen: dashboard;" in dash
    assert "Quick estimate" in dash and "Jobs board" in dash and "Needs attention" in dash
    assert len(re.findall(r"^\d+\. ", dash, re.M)) >= 5
    proj = (HELP / "manage_your_projects.md").read_text(encoding="utf-8")
    assert "# Manage your projects" in proj and "<!-- screen: projects;" in proj
    assert "Create project" in proj and "Filter by status" in proj
    assert len(re.findall(r"^\d+\. ", proj, re.M)) >= 5


def test_new_guides_are_served_for_their_screens(call):                 # C2S18-W19
    dash = call("GET", f"{API}/help/guides?screen=dashboard").json()["guides"]
    assert {g["id"] for g in dash} == {"use_the_dashboard", "start_with_the_director"}   # 2026-11-12: the Director
    proj = call("GET", f"{API}/help/guides?screen=projects").json()["guides"]
    assert {g["id"] for g in proj} == {"manage_your_projects"}
    one = call("GET", f"{API}/help/guides/use_the_dashboard").json()["guide"]
    assert one["title"].startswith("Use the dashboard") and one["steps"] >= 5 and "<!--" not in one["text"]


# ------------------------------------------------------------------ empty states, script order


def test_empty_states_name_the_next_step():                              # C2S18-W20
    cases = [
        ("review.js", ["takeoffs-empty", "No plans or measurements yet.", "Open Projects", "#/projects"]),
        ("verify.js", ["agents-empty", "No takeoff agents yet.", "Ask your AI to set up the trades"]),
        ("estimates.js", ["estimates-empty", "No estimates", "Create one from Projects"]),
        ("app.js", ["No trades priced yet.", "Open the estimate", "start a quick estimate",
                    "No projects yet — create one to start."]),
    ]
    for name, parts in cases:
        text = (WEB / name).read_text(encoding="utf-8")
        for part in parts:
            assert part in text, (name, part)


def test_tour_script_loads_last():                                       # C2S18-W21
    index = (WEB / "index.html").read_text(encoding="utf-8")
    at = {name: index.index(f'<script src="{name}"') for name in
          ("app.js", "review.js", "estimates.js", "verify.js", "quantities.js",
           "mobile.js", "reports.js", "settings.js", "tour.js")}
    assert at["app.js"] < at["mobile.js"] < at["tour.js"]
    assert at["reports.js"] < at["tour.js"] and at["settings.js"] < at["tour.js"]
    assert at["tour.js"] == max(at.values())
