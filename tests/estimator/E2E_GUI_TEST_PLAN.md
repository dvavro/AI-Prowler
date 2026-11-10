# Estimator E2E GUI Test Plan — Playwright, human mode (Coder 2)

## Purpose

Drive the Estimator web app in a real browser the way a person would — click,
type, navigate, upload a drawing, watch the takeoff appear — and use that to
check the Manual checks (M1–M8) from the Coder 2 sprint test plans
(Sprints 10–19). This is the Estimator equivalent of the Jobs App E2E suite
(`tests/JOBS_APP_E2E_TEST_SPEC.md`): headed/human mode is a first-class way
to run it, selectors live in page objects, and the run is reproducible by
someone else from this doc alone.

## How to run

```bat
run_tests_estimator.bat browser            headless, all browser tests (existing + E2E)
run_tests_estimator.bat browser --human    visible browser, slowed down, to watch it like a person
run_tests_estimator.bat browser -k E2E_S17    only the Sprint 17 E2E tests
```

- The browser track sets `ESTIMATOR_BROWSER=1` and targets
  `tests\estimator\browser`. Without it every test in that folder is
  **skipped** (`tests/estimator/browser/conftest.py:21-27`), so the normal
  Estimator suite never opens a browser and stays fast.
- Browser: Playwright's bundled Chromium (`pw.chromium.launch`), headless by
  default; `--human` (`ESTIMATOR_BROWSER_HUMAN=1`) is headed with
  `slow_mo=250` and key-by-key typing (`browser_helpers.type_in`, 60 ms/key).
  This differs from Jobs on purpose: Jobs drives the system Edge channel
  because David watches in his own browser; Estimator keeps bundled Chromium
  so the run is reproducible anywhere.
- Playwright is not a declared dependency (same as Jobs): it is installed on
  demand (`pip install playwright; python -m playwright install chromium`).
  A missing Playwright/Chromium skips the browser track cleanly instead of
  failing it.

## Harness (reuse, do not rebuild)

`tests/estimator/browser/conftest.py` already provides everything:

- `site` fixture: the Estimator web server for that test, on a free port
  (`server.start(port=0)`), `RUN_INLINE=True` so plan processing runs
  synchronously in the test thread. Base URL is
  `http://localhost:<port>/estimator/`; tests navigate with
  `page.goto(page.base + "#/…")` (hash routing).
- `page` fixture: 1400×950 viewport, 15 s default timeout. `phone` fixture:
  390×844, touch, mobile, `device_scale_factor=2` (Sprint 13).
- Teardown guard: any `pageerror`, console error, or HTTP ≥400 fails the
  test — a test that passes has a clean console.
- `browser_helpers.py`: `type_in(page, selector, text)` and
  `answer_yes(page, prefix)`.

New E2E tests live in `tests/estimator/browser/test_e2e_sprintNN.py` and reuse
these fixtures. Shared E2E helpers (role sign-in, common seeds) go in
`tests/estimator/browser/e2e_helpers.py`. Selectors live in the test files'
page-object helpers, `data-testid` first where hooks exist, stable `#id`
second — never bare text where an id exists.

## Sandbox — no real data, ever

- Every test gets the usual throwaway data folder
  (`tests/estimator/conftest.py`: `tmp_path/"estimator_data"`,
  `ESTIMATOR_DATA_DIR` set to it, `ESTIMATOR_PDF_BROWSER=none`,
  `ESTIMATOR_WATCHER=off`). The live `estimator.db` is never touched and no
  real customer or plan-set data is ever loaded.
- Seeded drawings are **generated in code**, never real plans. For any test
  that uploads a drawing and takes off from it, prefer the real fixture
  drawings in `tests/estimator/browser/fixtures/` (Smith Residence, A-101;
  see `fixtures/README.md` for the verified takeoff numbers — Rev A PDF:
  5 rooms / 1048.25 sqft, 28 walls / 434.00 ft, 4 symbols; Rev B PDF: 5 rooms
  / 1048.17 sqft, 5 symbols, 1 revision mark; DXF: 5 rooms / 1120.00 sqft,
  8 walls / 214.00 ft). Upload them through the GUI file input
  (`set_input_files`) and assert the README numbers. Regenerate them with
  `coder2_scratch/make_fixtures.py`. Small synthetic PDFs are still fine
  where only a renderable page is needed: `tests/estimator/plan_engine/pdfmaker.py`
  (`make_pdf`, `title_block`) plus the Sprint 10/12/14/15/16 plan-engine
  helpers (`legend`, `plan`, `shape`, `HOUSE`, `NAMES`, `SCHEDULES`, `page`).
  A drawing is exercised for real: upload it in the browser (or seed it with
  `store.upload` + `engine.start(..., confirm=True)` and drive the resulting
  takeoff/measurements in the UI) — the deterministic plan engine runs, not
  an agent.
- Hand-built drawing models (no PDF geometry) use the webapp pattern:
  `store.save_results(db, CTX, plan_set_id, PLAN, "fake")` — see
  `tests/estimator/webapp/test_web_sprint17.py:55-123` (`PLAN(rev)`, `revs`
  fixture, Rev A vs Rev B with a REV CLOUD polyline). The practice project
  comes from `practice.create()` ("Practice: Garcia house" — no plans, so
  plan-dependent tour steps are skipped by the engine; seed a plan set onto
  it when a walk needs plans).
- Measurements are proposed directly with
  `estimator.takeoff.measurements.propose/manual` (Sprint 13 pattern), never
  through an agent.

## No API keys — zero tokens, by construction

- No API key is configured anywhere in the E2E environment: no
  `ANTHROPIC_API_KEY` / `GROK_API_KEY`, no `~/.ai-prowler/agent_*_api_key.txt`
  in the sandbox, and the tests never set one.
- This cannot cost tokens even by accident, verified at three layers:
  the Estimator Runner has no key concept at all (`runner.start_run` only
  inserts queued DB rows and waits for a human/chat submission);
  the agents queue calls `providers.ready()` before any `ask()` and stays
  `queued` when no provider is ready (`estimator/agents/queue.py:267-322`);
  the AI-Prowler Task Queue refuses in `why_not_ready()` before any network
  (`task_queue_automation.py:716-735`).
- The five checks that need a live AI chat stay **manual** (see the table):
  S10 M7, S11 M7, S12 M7, S15 M6, S16 M5. Their underlying tools are already
  unit/API-tested; the browser E2E suite does not re-prove them.

## Coverage — 73 M-checks (S10: 7, S11–18: 8 each, S19: 2)

**AUTO** = automated by the E2E test named. **AUTO\*** = automated with the
stated precondition. **MANUAL** = stays manual, with the reason. A MANUAL
check whose seeded mechanics are already engine-tested is marked as such;
the E2E suite does not re-prove engine accuracy, it proves the browser flow.

### Sprint 10 — Symbol Recognition Engine v1, Jobs board

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 real electrical plan, counts close to hand count | MANUAL — accuracy vs a hand count on a real plan needs human eyes; counts-table mechanics covered by M5 | — |
| M2 GFI/WP codes counted as GFCI/weatherproof | MANUAL — real-plan code reading; seeded equivalent engine-tested (C2S10-E02/E05) | — |
| M3 real DXF, blocks named, doors/furniture left alone | MANUAL — real-DXF accuracy; seeded DXF equivalent not yet a browser test | — |
| M4 scanned plan with legend | MANUAL — real-scan accuracy; seeded raster equivalent engine-tested (C2S10-E09) | — |
| M5 counts table; symbols in trade layer | AUTO | `test_E2E_S10_M5_counts_table_and_layers` |
| M6 Jobs board plan-takeoff job; progress line, links work (owner + field) | AUTO | `test_E2E_S10_M6_jobs_board_links` |
| M7 ask Claude "how many GFCI outlets?" | MANUAL — live Claude via `symbol_detections_list`; tool unit-tested (C2S10-E13) | — |

### Sprint 11 — Visual verification, company library, Agents screen

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 Reviews, least-sure-first, thumbnails readable | AUTO* — ordering + thumbnail-load assertions; thumbnail *legibility* stays human eyes | `test_E2E_S11_M1_reviews_ordering` |
| M2 relabel unknown, every match changes, counts follow | AUTO | `test_E2E_S11_M2_relabel_all_matches` |
| M3 second plan set, same architect; learned symbol found from company library | AUTO | `test_E2E_S11_M3_learned_symbol_second_set` |
| M4 Find similar on a symbol the legend missed | AUTO | `test_E2E_S11_M4_find_similar` |
| M5 Symbol Library export, import on another PC | AUTO* — export→import into a second company on one PC; literal "another PC" is manual | `test_E2E_S11_M5_library_export_import` |
| M6 Agents: trade off, start run, skipped with warning | AUTO — listing assertion only; no key needed unless a task executes | `test_E2E_S11_M6_agent_trade_off_run_skipped` |
| M7 ask Claude "those three are floor boxes" | MANUAL — live Claude via `symbol_detection_review` | — |
| M8 phone, field role: Reviews opens, thumbnails show, no action buttons | AUTO* — needs the role sign-in fixture (see below) | `test_E2E_S11_M8_phone_field_reviews_readonly` |

### Sprint 12 — Wall-and-room model; electrical/plumbing libraries

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 real house plan set, rooms/areas match written areas | MANUAL — real-plan accuracy; seeded equivalent browser-tested (B07) | — |
| M2 reflected ceiling plan + electrical sheets, floor area not doubled | MANUAL — real-plan sheet classification; seeded equivalent engine-tested (C2S12-B05) | — |
| M3 doors/windows match schedules; doors between rooms show 2 rooms | MANUAL — real-schedule matching; seeded equivalent browser-tested (B07) | — |
| M4 ceiling height 9 ft; drywall/painting up by perimeter × 1 ft; framing says "9" | AUTO | `test_E2E_S12_M4_ceiling_height_recalc` |
| M5 approve outlets in Reviews, reload; approved count, rest "still to check" | AUTO | `test_E2E_S12_M5_approved_counts_after_reload` |
| M6 tankless water heater in legend; plumbing answer "tankless" once approved | AUTO | `test_E2E_S12_M6_tankless_water_heater` |
| M7 ask the AI "give me the drywall quantities" | MANUAL — live AI via `plan_trade_answers` | — |
| M8 drywall vs painting arithmetic | AUTO | `test_E2E_S12_M8_drywall_painting_arithmetic` |

### Sprint 13 — PWA mobile reviews

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 real phone through Remote Access, Jobs → Estimates → Reviews | MANUAL — real device + Remote Access is the point; server-mode token picture load browser-tested (B05) | — |
| M2 approve 10 symbols in a row by thumb | AUTO | `test_E2E_S13_M2_approve_ten_in_a_row` |
| M3 swipe left/right; swiping asks first; vertical scroll doesn't swipe | AUTO | `test_E2E_S13_M3_swipe_guards` |
| M4 relabel with "every identical match"; desktop Reviews agrees | AUTO | `test_E2E_S13_M4_phone_relabel_desktop_agrees` |
| M5 approve a measurement on the phone; locked on desktop, priced on Estimate page | AUTO | `test_E2E_S13_M5_phone_measurement_locked_and_priced` |
| M6 tablet portrait + landscape; picture + buttons fit | AUTO* — layout/fit via Playwright viewports (768×1024 / 1024×768); real-tablet touch feel is manual | `test_E2E_S13_M6_tablet_layout` |
| M7 field staff sign-in; symbols only, no buttons | AUTO* — needs the role sign-in fixture | `test_E2E_S13_M7_field_symbols_only` |
| M8 desktop Reviews thumbnails through Remote Access | AUTO* — token-loaded thumbnails in server mode (B05 pattern); literal Remote Access path manual | `test_E2E_S13_M8_server_mode_thumbnails` |

### Sprint 14 — Elevations, door/window schedule linking, HVAC library

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 real elevation sheet, 4 sides, walls within 5% of hand measure | MANUAL — real-plan accuracy | — |
| M2 elevation without plate marks; note says roof may be included | MANUAL — real-plan note check; seeded equivalent engine-tested (C2S14-E03) | — |
| M3 window counts on an elevation, mullions don't split a window | MANUAL — real-plan counting accuracy | — |
| M4 real door/window schedule; every mark listed, untagged yellow + noted | MANUAL — real-schedule accuracy | — |
| M5 windows/doors match hand count | MANUAL — hand-count comparison on a real plan | — |
| M6 L-shaped house; siding corners | MANUAL — real-plan corner counting | — |
| M7 mechanical plan; diffusers/returns/thermostats counted after approval; mini-split heads set system | AUTO | `test_E2E_S14_M7_hvac_counts_after_approval` |
| M8 plan with garage; HVAC area leaves garage out and says so | AUTO | `test_E2E_S14_M8_garage_excluded_from_hvac` |

### Sprint 15 — Site-plan zones for fencing/landscaping

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 real landscape plan; lawn/rock/mulch areas sensible | MANUAL — real-plan zone accuracy | — |
| M2 real site plan with fence note; fence run starts/stops where the plan's does | MANUAL — real-plan fence tracing | — |
| M3 plant schedule; trees/shrubs match QTY, ground covers not counted | MANUAL — real-schedule accuracy | — |
| M4 CAD landscape plan (DXF) with hatches + fence layer | MANUAL — real-DXF accuracy | — |
| M5 site + landscape plan; each zone/fence counted once; note says which sheet | MANUAL — real-plan dedup | — |
| M6 propose measurements via chat (`takeoff_propose`); approve + price | MANUAL — live AI; deterministic propose path engine-tested (C2S15-T05) | — |
| M7 plan quantities in Jobs app (phone), yard-only project; "Site and landscape" section, no "no rooms found" box | AUTO | `test_E2E_S15_M7_phone_yard_project_sections` |
| M8 re-read a plan set read before this sprint; zones/fences appear | AUTO | `test_E2E_S15_M8_reread_adds_zones` |

### Sprint 16 — Scans/photos, DWG

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 real scanned floor plan; walls + named rooms; quantities show Needs review | MANUAL — real-scan accuracy; seeded 150 DPI scan engine-tested (C2S16-E01/E02/E06) | — |
| M2 calibrate a scan's scale from a known dimension | AUTO* — mechanics automatable once the calibrate control's selector is confirmed at build time; if it has no stable selector, this drops to MANUAL and the plan is updated | `test_E2E_S16_M2_scan_calibration` |
| M3 phone photo of a printed sheet on a dark desk | MANUAL — the photo-taking itself can't be scripted | — |
| M4 blueprint scan (white on blue); read inverted; sheet image dark-on-light | AUTO — generated inverted image upload is sufficient | `test_E2E_S16_M4_blueprint_inversion` |
| M5 propose measurements from a scan via chat | MANUAL — live AI via `takeoff_propose`; raster method/confidence engine-tested (C2S16-N03) | — |
| M6 no ODA converter: DWG upload warns, reading fails with ODA guidance; tab shows "Not installed" | AUTO* — with `ESTIMATOR_DWG_CONVERTER=off` (pattern already used in Sprint 5 tests); the no-converter environment is a setup precondition | `test_E2E_S16_M6_dwg_without_converter_warns` |
| M7 install ODA File Converter, restart, read DWG again | MANUAL — installs software and restarts the app; cannot run in a throwaway sandbox | — |
| M8 re-read a scan read before this sprint; walls + needs-review notes appear | AUTO | `test_E2E_S16_M8_reread_scan_notes` |

### Sprint 17 — Reports, Settings, full Price Book

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 real Rev A→B pair; overlay boxes sit on changes; picker switches; "Show Rev A (old)" shows old sheet | MANUAL — overlay box positions on a real sheet are only proven here; seeded overlay mechanics covered by S19 M1 | — |
| M2 "Measurements to re-measure"; flagged link opens Blueprint Review; re-measuring clears flag; unchanged keep approval | AUTO | `test_E2E_S17_M2_flagged_remeasure_clears` |
| M3 Reports → Win/loss; mark won/lost; rate/value/month/trade move; practice stays out | AUTO | `test_E2E_S17_M3_win_loss_moves` |
| M4 Reports → Takeoff + Estimate vs actual; approved vs waiting match Blueprint Review; actuals show against estimate lines | AUTO | `test_E2E_S17_M4_takeoff_vs_actuals` |
| M5 Reports → Exports; CSV + Excel download and open with right rows | AUTO | `test_E2E_S17_M5_exports_download` |
| M6 Settings as owner (ask-first old→new); estimator/reviewer/office/field get Settings absent/refused | AUTO* — settings form AUTO; role sign-ins need the role sign-in fixture | `test_E2E_S17_M6_settings_ask_first_and_roles` |
| M7 Price Book: change price, history; Markups; import supplier CSV; mapping guesses fixable; import saves | AUTO | `test_E2E_S17_M7_price_book_history_markups_import` |
| M8 role gates: reviewer/office open Reports; field opens neither Reports nor Settings; reviewer/office see Reports but not Settings/Price Book; Compare button owner/estimator only | AUTO* — needs the role sign-in fixture | `test_E2E_S17_M8_role_gates_reports_settings` |

### Sprint 18 — Guided tours, help panel, empty states

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 first open as fresh user: tour auto-starts; reopening doesn't restart; Skip/Finish never auto-starts | AUTO | `test_E2E_S18_M1_tour_autostart_once` |
| M2 tour on small screen: popup sits under control, flips above near bottom, never runs off right edge; centred step in view | AUTO — bounding-box assertions; only visual polish stays human | `test_E2E_S18_M2_tour_popup_positioning` |
| M3 practice tour from dashboard help panel; walks project → upload → Blueprint Review → Reviews → approve → estimate → bids without getting stuck | AUTO* — seed a plan set onto the practice estimate first (the practice project alone has no plans, so plan steps would be skipped, not walked) | `test_E2E_S18_M3_practice_tour_no_stuck` |
| M4 "?" on dashboard/project/Blueprint Review; panel search; Escape; hash change; "Open full Help screen" lands on #/help | AUTO | `test_E2E_S18_M4_help_panel_search_escape` |
| M5 Help screen: replay finished/skipped/practice tour; done/skipped state shows | AUTO | `test_E2E_S18_M5_help_replay_states` |
| M6 phone: Reviews from Jobs app, replay mobile tour; first step lands on #/m/reviews; buttons point at real phone buttons; swiping still works after close | AUTO | `test_E2E_S18_M6_mobile_tour_reviews` |
| M7 empty states: no projects/estimates/agents, plan-less project; each says what to do next, link goes there | AUTO | `test_E2E_S18_M7_empty_states_links` |
| M8 role gates: "?" opens panel on every screen each role can open; role-gated step skipped not stuck; progress per user | AUTO* — needs the role sign-in fixture + two browser contexts | `test_E2E_S18_M8_tour_per_user_progress` |

### Sprint 19 — Revision clouds + Price Book file import (extends S17)

| Check | Verdict | E2E test / note |
|---|---|---|
| M1 real Rev A→B pair **with architect's clouds/deltas**; purple boxes on clouds; checkbox hides/shows; listed in "Changes on this sheet"; old-sheet view unaffected; clouds-only sheet shows as changed | AUTO* — every overlay mechanic with the seeded `revs` fixture (which already contains a REV CLOUD polyline); cloud *positions on a real sheet* stay manual | `test_E2E_S19_M1_revision_clouds_overlay` |
| M7 Price Book: multi-sheet supplier .xlsx, then .csv; sheet picker, preview, import saves; >5 MB and wrong-extension refused; staged file gone after import; paste still works | AUTO — `set_input_files` on `#pb-file`, `#pb-sheet` picker; staged-file-gone via a follow-up 404 on the stage id | `test_E2E_S19_M7_price_book_file_import` |

## Totals

- **45 checks automated** (S10: 2, S11: 7, S12: 4, S13: 7, S14: 2, S15: 2, S16: 4, S17: 7, S18: 8, S19: 2) across 10 new test files, one per sprint.
- **28 checks stay manual**: 19 real-plan accuracy checks (hand counts, written areas, schedules, scans, DXF, elevations, zones — the seeded equivalents are already engine-tested, so these stay manual deliberately), 5 live-AI chat checks, 3 real-device / Remote Access / physical-photo checks, 1 environment mutation (ODA install + restart).
- Existing browser tests (Sprints 11–13: 14 tests) already cover parts of S11 M1/M2/M4, S12 M4, S13 M2/M3/M5; the new E2E tests build on those fixtures rather than redoing them, and extend the assertions to the full M-check wording.

## Test hooks needed (production changes, minimal)

The Estimator web app has **zero `data-testid`** today. Existing browser tests
already drive stable `#id`s (emitted as JS object literals; the authoritative
list is the 70 distinct `#id`s in `tour.js`, verified by Sprint 18 test W12).
New hooks are needed only where no stable selector exists — add them in the
web app code, keep them minimal, and list them in the build report:

- Revision overlay (`reports.js`): ids on the "Revision clouds" toggle, the
  sheet picker, the "Show Rev A (old)" button, and the "Changes on this
  sheet" rows (S17 M1/M2, S19 M1).
- Tour popup (`tour.js`): ids on Back / Next / Finish / Skip tour / X
  buttons (S18 M1–M6). Today these are text locators only.
- Help "?" button: an id on `.help-link` (S18 M4/M8).
- Reports / Settings / Price Book inner controls: ids on export buttons,
  settings fields, and Price Book import mapping controls — today only the
  containers exist (`#report-body`, `#settings-body`, `#pb-import-box`,
  `#pb-file`, `#pb-sheet`) (S17 M5–M7, S19 M7).
- Blueprint Review sheet clicks: no selector for clicking a point on a
  sheet; the existing workaround is coordinate math via the `RV.viewer` JS
  object + Alt-click — keep it, do not invent a new mechanism (S17 M2).
- Role sign-in in the browser: **no production change**. This is a test-only
  fixture to build first (server mode + seeded users, or a minted session
  token in `localStorage` like the Jobs E2E `ap_auth` injection — whichever
  the auth code supports; see `estimator/api/auth.py` and
  `estimator/api/prowler_link.py`). It gates S11 M8, S13 M7, S17 M6/M8,
  S18 M8.

## What success looks like

- `run_tests_estimator.bat browser` runs the existing 14 browser tests plus
  the 45 new E2E tests, all green, headless and `--human`.
- `run_tests_estimator.bat` (no args) still passes with the browser tests
  skipped — the E2E files change nothing about the default suite.
- No test reads a real API key, starts the Task Queue, or makes a network
  call outside `localhost`; no test data survives the run (throwaway data
  folder per test, deleted by the runner).
- Every AUTO/AUTO* row above names a test that actually drives the browser
  through the check. Anything the builder cannot automate is moved to
  MANUAL in this plan with the reason, not silently dropped.
