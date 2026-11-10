# Sprint 18 — Coder 2 (David) test plan: Guided tours, help panel, contextual help and empty states

**Scope:** The Coder 2 Sprint 18 row is "Guided tours, help panel, contextual help and empty states". Spec: How-to-use guide and guided tour (the tour engine, the 27 tours, per-user progress in the DB schema `help_progress`), and Screens and controls (the "?" on each screen, the Help screen, empty states with a next step). The tour content itself is Coder 2's; the practice project it walks is Coder 1's `est_sample_project` ("Practice: Garcia house").

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat                 every Estimator test
deploy_to_install.bat                   then restart AI-Prowler
```

- **New database migration 18** — `help_progress` (user_id, tour_id, status, updated_at; PRIMARY KEY (user_id, tour_id); index on user_id). One row per user per tour; a tour never touched is simply absent, which the web app reads as not_started.
- **New files** (`estimator/ui/web/tour.js`, `estimator/api/tours_api.py`, the guides `use_the_dashboard.md` and `manage_your_projects.md`, plus the wiring in `estimator/ui/web/app.js` and `estimator/ui/web/mobile.js` and the `tour.js` script tag in `index.html`) are in `AI-Prowler-Setup.iss`.
- **⚠ Known wiring fault (found while writing these tests, not fixed here):** the tours delegation in `estimator/api/router.py` (the Sprint 18 block at lines 473–476) sits *inside* the `if settings_api.handles(sub):` block, after its unconditional `return` — so it is dead code and `GET /help/tours/progress`, `POST /help/tours/progress` and `GET /help/practice` all answer 404 through the router. The API tests below (W01, W03–W10) go through `router.route()` on purpose, so they fail until the block is dedented to the top level of `_api_data`, beside the Reports/Settings blocks. The web app hides the fault today only because `tourLoadProgress` and `tourSaveProgress` swallow errors (progress reads as empty, saves are best-effort) — with the fault in place every tour auto-starts on every open and Skip/Finish never sticks.
- **Phase 8 gate:** Sprint 18 is the "Guided tours" item in the Phase 8 gate (spec: "Guided tours"). The gate closes when the tours are checked in the browser (M1–M6), the help panel and replay pass (M4–M5), the role gates hold (M8), and the automated suite is green — which needs the wiring fault above fixed first. No phase gate has passed yet — G0 still waits on David's code review of the Coder 2 track — so this sprint's evidence feeds the gate rather than closing it.

## What was built

**Guided tours** (`estimator/ui/web/tour.js`, loaded last in `index.html`, after `app.js`, the screen scripts and `mobile.js`):
- A tour is data: `{id, title, steps: [{sel, title, body, go}]}`. `sel` names a control that really exists on that screen; a step whose control is not there (role-gated, empty list) is skipped. `go` navigates first — the practice tour walks across screens. 26 tours in `TOURS` plus the phone tour (`MREV_TOUR` in `mobile.js`, picked up by `tour.js`): 27 in all, the same list as `TOUR_IDS` in `tours_api.py`.
- The pop-up anchors under its control, flips above it when there is no room below, and centres when a step has no control. Back / Next / Finish, Skip tour, and X. After a tour-driven navigation it waits up to 3 s for the step's control to appear, then skips the step.
- **First open auto-starts** (`maybeStartTour`, called by `route()` after each screen renders): the screen's tour starts unless the user already finished or skipped it. Skip saves `skipped`, Finish saves `completed`, closing with X saves nothing.
- **Practice tour** (`practice`): with a practice project it walks end to end — project page, upload plans, Blueprint Review scale and counts, Reviews, approve, price, send — across 8 steps. With no practice project yet it shows one step telling the user how to make it, and saves nothing.

**Tour progress API** (`estimator/api/tours_api.py` — every role reads and writes only its own rows):
- `GET /help/tours/progress` — `{tours: {tour_id: status}}` for this user.
- `POST /help/tours/progress {tour_id, status}` — marks one tour `completed`, `skipped`, or `not_started` (reset). An unknown tour is 404 ("no such tour"); a bad status is 400. Writes need the app header (403 csrf without it), like every other write.
- `GET /help/practice` — `{estimate_id, title}` of "Practice: Garcia house" if it exists, else `{estimate_id: null, title: null}`.

**Help panel and "?"** (`helpLink` in `app.js`, `openHelpPanel` in `tour.js`): the "?" on each screen is a button, not a link — it opens a slide-over with that screen's guides (searchable) plus a "Replay the … tour" button, and on the dashboard a "Practice project tour" button. Escape closes it, changing the hash closes it, and "Open the full Help screen" goes to `#/help`. If `tour.js` failed to load, the "?" falls back to `#/help?screen=<screen>`. `#/help` stays the full-page route, and the Help screen lists every tour with its done/skipped state and a Replay button.

**Guides:** "Use the dashboard" (screen: dashboard) and "Manage your projects" (screen: projects) — 5 steps each, naming the real buttons.

**Empty states:** an empty list shows a `card empty` with what to do next, not a blank page — takeoffs ("No plans or measurements yet." → Open Projects), agents ("No takeoff agents yet." → ask your AI to set up the trades), estimates ("No estimates yet." → Create one from Projects), the project page ("No trades priced yet." → Open the estimate / start a quick estimate), the projects list ("No projects yet — create one to start.").

## Automated tests

`tests/estimator/webapp/test_web_sprint18.py` (21 tests; the W08 role test runs once per role, so 25 cases):

| ID | Test | Checks |
| --- | --- | --- |
| C2S18-W01 | test_progress_starts_empty | No rows yet: `{"tours": {}}` |
| C2S18-W02 | test_help_progress_table_exists | Migration 18: the table, PRIMARY KEY (user_id, tour_id), status and updated_at |
| C2S18-W03 | test_progress_round_trip | completed → skipped → not_started, each read back |
| C2S18-W04 | test_progress_is_per_user | Alice's rows are invisible to Bob and vice versa |
| C2S18-W05 | test_progress_unknown_tour_is_404 | An unknown tour and a missing tour_id are 404 "no such tour"; nothing saved |
| C2S18-W06 | test_progress_bad_status_is_400 | "done", "DONE" and a missing status are 400; nothing saved |
| C2S18-W07 | test_progress_post_needs_the_app_header | A progress POST without the app header is 403 csrf |
| C2S18-W08 | test_progress_open_to_every_role (×5 roles) | Owner, estimator, reviewer, office, field all get 200 |
| C2S18-W09 | test_practice_returns_null_without_a_practice_project | No practice project: estimate_id and title are null |
| C2S18-W10 | test_practice_returns_the_practice_project | Seeded with `practice.create`: the id and "Practice: Garcia house" |
| C2S18-W11 | test_tour_ids_match_the_api | 27 tour ids in tour.js + mobile.js, no duplicates, the same set as `tours_api.TOUR_IDS` |
| C2S18-W12 | test_every_tour_step_names_a_real_control | All 87 steps: a title and body, and every selector names a real id/class (or nav link) in the web app |
| C2S18-W13 | test_practice_tour_walks_across_screens | 8 practice steps across the project page, takeoffs, reviews, estimate and bids; the phone tour's first step navigates to #/m/reviews |
| C2S18-W14 | test_tour_engine_auto_starts_and_marks_progress | Auto-start gate (finished/skipped → no start), Skip saves skipped, Finish saves completed, X saves nothing, pop-up centres/flips, route hook in app.js |
| C2S18-W15 | test_help_link_opens_the_panel_not_a_link | "?" is a button opening the panel (fallback to #/help?screen=), on dashboard, projects and the project page |
| C2S18-W16 | test_help_panel_has_search_replay_and_close | Panel, search box, replay area, "Open the full Help screen", Escape and hash-change close, Replay and Practice-project buttons, guides fetched per screen |
| C2S18-W17 | test_help_screen_lists_tours_with_replay | Help screen lists every tour with Replay and its done/skipped state |
| C2S18-W18 | test_new_guides_cover_dashboard_and_projects | Both guides exist with their titles, screen tags, 5 steps, and the real button names |
| C2S18-W19 | test_new_guides_are_served_for_their_screens | ?screen=dashboard/projects return only the new guide; opening one gives its steps, no front-matter in the text |
| C2S18-W20 | test_empty_states_name_the_next_step | Takeoffs, agents, estimates, project page (and projects list) name what to do next |
| C2S18-W21 | test_tour_script_loads_last | tour.js loads after app.js, mobile.js, reports.js and settings.js |

The API tests (W01, W03–W10) fail while the router wiring fault above stands — that is the point: they prove the endpoints are reachable, not just implemented.

## Manual checks (Tester 2)

| # | Check | Expected |
| --- | --- | --- |
| M1 | Open each screen for the first time as a fresh user (clear tour progress first) | Its tour starts on its own; opening it again does not restart it; after Skip or Finish it never auto-starts again |
| M2 | Run a tour on a small screen (narrow browser window, then a phone-width one) | The pop-up sits under its control, flips above it near the bottom, and never runs off the right edge; the centred step (no control) sits in view |
| M3 | Seed the practice project, then start the practice tour from the dashboard help panel | It walks project page → upload → Blueprint Review → Reviews → approve → estimate → bids without getting stuck; each step points at the real control; finishing marks the practice tour completed |
| M4 | "?" on the dashboard, a project page, and Blueprint Review; type in the panel search; press Escape; change the hash | The panel shows that screen's guides; the search narrows them; Escape and navigating away both close it; "Open the full Help screen" lands on #/help for that screen |
| M5 | Help screen: replay a finished tour, replay a skipped tour, replay the practice tour | Each replay runs from the start; the done/skipped state shows beside each tour; the practice replay starts on the practice project |
| M6 | On a phone (or a phone-width browser): open Reviews from the Jobs app, then replay the mobile tour from Help | The first step lands on #/m/reviews; Approve / Take out / Skip point at the real phone buttons; swiping still works after the tour closes |
| M7 | Empty states: a company with no projects, no estimates, no agents, and a project with no plans | Each empty list says what to do next and the link goes there (Open Projects, Create one from Projects, Open the estimate); nothing shows a blank page |
| M8 | Role gates in the browser: sign in as estimator, reviewer, office and field | The "?" opens the panel on every screen each role can open; a role-gated step (e.g. a button the role cannot see) is skipped, not stuck; tour progress is per user — a second user starts every tour fresh |

## Known limits

- The tour pop-up is positioned by viewport math, not by the test suite: anchoring on odd screen sizes and on scroll is a manual check (M2).
- First-open auto-start, the practice tour's cross-screen walk, and the panel's open/close are browser behaviour — the automated tests pin the wiring and the data, Tester 2 checks the behaviour (M1, M3–M6).
- Tour progress is per user: a tour one user finished still auto-starts for the next user. That is the design (progress is keyed by user_id), not a bug.
- The practice tour needs the practice project to exist; without it the tour shows the one "make the practice project" step and saves nothing.
- The revision overlay's cloud/delta marks and the paste-only Price Book import are still open from Sprint 17 — untouched by this sprint.
