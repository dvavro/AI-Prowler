# AI-Prowler Estimator — Implementation Plan

Nov 5, 2026 · Team: 2 coders, 2 testers · Companion to *AI-Prowler Estimator Design Spec.md*

## Summary

The Estimator is built in **20 two-week sprints (about 40 weeks)**, plus a recommended 4-week buffer (about 44 weeks total), with testing done **in the same sprint as the code** rather than at the end. Quick service estimates are release-ready at the end of **Sprint 4 (week 8)**, the first construction trades at the end of **Sprint 8 (week 16)**, and the full product at **Sprint 20 (week 40)**.

Two testers make testing-as-you-build practical: while the coders build a feature, the testers write its acceptance tests and prepare its test data (reference plans, hand counts, golden estimates), so each feature is tested the moment it lands.

All durations are planning estimates. Phase gates from the design spec still decide when a phase is done.

## Team and responsibilities

| Person | Owns | Also does |
| --- | --- | --- |
| **Coder 1 — Platform and estimating (Jamie)** | `estimator/core` (runner, agent manager, formula engine, units/money), database and migrations, estimating and pricing engines, trade/service module engine, bids, integrations (quotes, jobs, invoices, exports), MCP tools, API-key agents (`claude_api` / `grok_api`), estimate revisions | Unit tests for own code; code reviews for Coder 2 |
| **Coder 2 — Plan engine and web app (David)** | Web app shell and hosting, JSON API, documents and validation, drawing analyzer (sheets, viewports, CAD, vector, raster, text, legends, schedules, symbols, revisions), drawing model, geometry, Blueprint Review and visual verification, PWA screens | Unit tests for own code; code reviews for Coder 1 |
| **Tester 1 — Automation and platform QA** | Test harness and CI (`run_tests.bat`, `release_gate.bat`), unit/contract test coverage checks, MCP contract and web-app parity tests, agent scenario scripts (Claude, then Grok), provider/budget tests, security and role tests, performance tests, release checklist | Writes acceptance tests for Coder 1's features before or during development |
| **Tester 2 — Plans, trades and UI QA** | Reference plan library and hand-counted answers, golden estimate cases per trade, module content checks (assemblies, waste, sample prices), Playwright UI tests, PWA/mobile tests, usability, how-to guides and tour checks, pilot/UAT coordination | Writes acceptance tests and test data for Coder 2's features before or during development; drafts module content for coders to load |

**Trade knowledge**: Tester 2 drafts each module's assemblies, formulas, waste factors and sample prices in the module's YAML/CSV format (from the design spec tables, checked against real past bids). Coder 1 loads, wires and fixes them. This keeps trade content off the coders' critical path.

## How we test as we build

**Every feature goes through the same loop inside its sprint:**

1. **Before coding (sprint planning)**: the tester assigned to the feature writes its acceptance criteria and test cases from the design spec and prepares the test data. Test data needed for a sprint is ready by the start of that sprint (testers work one sprint ahead on fixtures).
2. **While coding**: the coder writes unit tests with the code (pytest). Pull requests need passing unit tests and a review from the other coder.
3. **When the feature lands**: the tester runs the acceptance tests the same day or the next, files bugs, and the coder fixes them in the same sprint when possible.
4. **Every night**: the full automated suite runs on the test laptop (unit, golden, contract, parity, plan-accuracy and Playwright smoke tests). Failures are first item at the next morning's stand-up.
5. **End of sprint**: demo of working features, a short regression run, and a gate check if the sprint ends a phase.

**Definition of ready** (before a feature starts): design spec section referenced, acceptance criteria written, test data available or scheduled, dependencies done.

**Definition of done** (before a feature counts as finished):
- Code merged with unit tests passing and reviewed
- Acceptance tests written by a tester and passing
- MCP tool and web-app control both exist where the parity rule requires them
- No open severity 1 or 2 bugs on the feature
- How-to guide text drafted if users will see it
- **Design spec updated** to match what was actually built (see Keeping the spec up to date)
- **User guide updated**: the feature's section in `Estimator User Guide.md` is written or updated, with real screenshots, and a tester has followed the steps successfully

**Bug severity and response**:

| Severity | Meaning | Response |
| --- | --- | --- |
| 1 — Blocker | Wrong money or quantity math, data loss, crash, security hole | Fix before any other work |
| 2 — Major | Feature doesn't work as specified; no workaround | Fix in the same sprint |
| 3 — Minor | Works with a workaround; cosmetic issues on key screens | Fix within two sprints |
| 4 — Trivial | Typos, small layout issues | Backlog |

**Test environments**:
- Developer PCs for unit tests.
- **Test laptop A**: Windows 11, 16 GB RAM, NVIDIA GPU (the target hardware).
- **Test laptop B**: Windows 11, 16 GB RAM, no GPU (CPU fallback).
- **Server box** (from Sprint 7): office-network and multi-user tests.
- A phone and a tablet for PWA tests.
- Separate test API keys for Claude and Grok with low budgets for agent tests.

**Meetings**: 15-minute daily stand-up; sprint planning and demo every two weeks; bug triage twice a week (both testers and one coder).

## Keeping the spec up to date

The design spec (`AI-Prowler Estimator Design Spec.md`) is a **living document**. It must always describe what the software actually does, so it is updated as part of every phase, not after release.

**Who updates what**

| Change | Who updates the spec | When |
| --- | --- | --- |
| A feature is built differently from the spec (new field, different tool name, changed screen) | The coder who built it | In the same pull request as the code |
| A new MCP tool, table, column, screen or folder | The coder who added it | In the same pull request |
| Test results change a target (accuracy, performance, limits) | The tester who ran the tests | Same sprint |
| Module content (assemblies, formulas, waste factors) differs from the spec tables | Tester 2 | When the module's golden tests pass |
| A product decision is made or changed (scope, defaults, priorities) | Spec owner (Jamie) | Same day, in the Decisions table |
| A new open question comes up | Whoever finds it | Added to Open questions immediately |

**Rules**

- **Spec owner**: Jamie approves every spec change; David reviews changes to licensing, pricing tiers and architecture.
- **Same pull request**: code that changes behaviour described in the spec isn't merged until the spec change is in the same pull request. Reviewers check for it.
- **AI-assisted updates**: the team can ask Claude (through AI-Prowler's file tools) to apply spec edits from a pull request description or a demo summary; a person still reviews the edit.
- **Change log**: every spec change adds one line to the spec's **Change log** section (date, sprint, section, what changed, who).
- **Versioning**: the spec gets a version number in its header. Minor updates bump the minor version (v1.1, v1.2…); each phase gate bumps the major version and is tagged with the code release.
- **Reindex**: after each update, reindex the spec in AI-Prowler so Claude, Grok and the agents always read the current version (`how_to_estimate` and the role prompts reference it).
- **Generated copies**: the Word and online-doc copies are regenerated from the `.md` at each phase gate, never edited by hand.

## Writing the user guide as we build

A complete **Estimator User Guide** (`docs/Estimator User Guide.md`, chapters listed in the design spec) is a release deliverable. It is written feature by feature, so it is finished when the product is.

| Task | Who | When |
| --- | --- | --- |
| Create the guide skeleton (all 17 chapter headings, style rules, screenshot folder) | Tester 2 | Sprint 1 |
| Write the section for each finished feature: what it's for, step-by-step instructions, real screenshots | Tester 2 (Tester 1 for setup, AI, agents and admin topics) | Same sprint the feature passes acceptance tests |
| Technical review of each new section | The coder who built the feature | Same sprint |
| Follow every new section on a clean install exactly as written | The tester who didn't write it | Same sprint |
| Add short in-app how-to guides extracted from the chapter | Tester 2, with Coder 2 wiring them into the help panel | Same sprint |
| Reindex the guide in AI-Prowler so Claude and Grok can answer from it | Whoever updated it | After every update |
| Full read-through, refresh outdated screenshots, update `COMPLETE_USER_GUIDE.md` summary | Both testers | Every phase gate |
| Final edit and video links | Both testers | Sprint 18–19 |

Rules: screenshots always come from the real app (never mockups); every chapter is retested whenever its screens change; a phase gate isn't passed until the guide chapters for that phase are written and followed successfully.

Guide chapters by milestone:
- **M1 (week 8)**: Getting started, Setup in the Estimator tab (first version), Quick service estimates, Bids and follow-up
- **M2 (week 16)**: Projects and plans, Takeoffs and Blueprint Review, Estimates, Trades (concrete, flooring, roofing)
- **Week 22**: Reviews and visual verification, Symbols, Working with AI
- **Week 26–30**: Trades (all remaining), Mobile (PWA)
- **Week 34**: Plan revisions, Reports and exports, Users and roles
- **Week 40**: Troubleshooting and FAQ, Glossary, final setup chapter

**Spec tasks built into every sprint**

1. **Sprint planning**: compare the sprint's tickets with the spec; fix any section that is already out of date before work starts.
2. **During the sprint**: spec edits travel with each pull request.
3. **Sprint demo**: walk through the Change log entries for the sprint; testers confirm the spec matches what was demoed.
4. **Phase gate**: full read-through of the sections that phase touched; spec version bumped; Word copy regenerated; gate is not passed until the spec review is done.

## Sprint plan

Each sprint lists what the coders build and what the testers prepare and test in the same sprint.

### Phase 0 — Foundations

**Sprint 1 (weeks 1–2)**

| Role | Work |
| --- | --- |
| Coder 1 | `estimator/` package, `estimator.db` schema and migrations, backup hooks; units, integer-cents money, rounding; sandboxed formula engine; pricing stack |
| Coder 2 | Web app shell: hosting under AI-Prowler's HTTP server, Personal mode (no login on the same PC) and Server mode login, navigation, JSON API skeleton on the shared service layer, server-sent events; every table and API call carries the user so multi-user works later without rework |
| Tester 1 | `tests/estimator/` structure, pytest config, hook into `run_tests.bat` and nightly run; MCP contract-test framework; unit tests for money and formulas (property tests) |
| Tester 2 | Reference plan library plan: collect plan sets (vector PDF, scanned, photos, DXF), define the hand-count and golden-answer formats; golden-case format for modules; User Guide skeleton and style rules |

**Gate G0**: a hand-built estimate calculates correctly through MCP from Claude; web app opens with login.

### Phase 1 — Quick service estimates (first sellable release)

**Sprint 2 (weeks 3–4)**

| Role | Work |
| --- | --- |
| Coder 1 | Module registry and manifest validation; core MCP tools (`est_create_estimate`, `est_get_estimate`, `est_add_line_item`, `est_calculate`, `est_list_modules`); quick-estimate engine (`est_quick_questions`, `est_quick_answer`) |
| Coder 2 | Documents: upload and validation, file storage in the project folder; Dashboard and Projects screens; Quick estimate screen |
| Tester 1 | Contract tests for every new tool; malformed/malicious manifest tests; acceptance tests for quick estimates |
| Tester 2 | Pressure washing and house cleaning module content (questions, rates, add-ons, minimums) and golden cases; Playwright tests for Projects and Quick estimate |

**Sprint 3 (weeks 5–6)**

| Role | Work |
| --- | --- |
| Coder 1 | Price book basics and sample-price flags; generic service template; integrations: `create_customer`, `create_quote`, `create_job`; setup wizard backend (`est_setup_status`, `est_setup_step`); **Estimating Director v1 foundation**: job file tables (`director_jobs`, `director_steps`, `playbook_overrides`), playbook format, loader and validation, quick-quote lane playbooks for pressure washing and house cleaning, triage for service requests, `est_director_start`, `est_director_next`, `est_job_status` |
| Coder 2 | 🏗 Estimator tab in the AI-Prowler GUI v1 (`estimator/ui/gui_tab/`, added to `rag_gui.py`): Status with start/stop/Open Estimator, health lights, Setup wizard v1, Company, AI and agents, Data and backups; Price Book screen (basic); PWA Estimates tab (quick estimates) |
| Tester 1 | Integration tests: quote → job links, backups include `estimator.db`; Estimator tab checks (every control, health lights); setup wizard resume/skip tests; writes the "Setup in the Estimator tab" guide chapter; playbook validation tests; first 20 Director triage requests with expected lanes |
| Tester 2 | Generic service golden cases; PWA tests on phone; wizard usability run-through |

**Sprint 4 (weeks 7–8)**

| Role | Work |
| --- | --- |
| Coder 1 | Bids: `bid_generate`, `bid_preview`, `bid_send`, `bid_set_status`, `bid_convert_to_job`; bid PDF templates; email/text sending through existing tools; **Director drives the quick lane end to end**: checkpoints (one-tap send under the quick-send limit, default $100, configurable), Director settings (`director_settings`, `est_director_settings_*`) shown in the Estimator tab and web app Settings, Bid Writer and Follow-up hand-offs, Director role prompt in `how_to_estimate`, `est_jobs_board` |
| Coder 2 | Bids screen; sample service quote in the wizard; how-to guide panel (first guides); Jobs board screen (quick lane) |
| Tester 1 | Scripted Claude conversations for the full service flow (quote → send → convert), started from one plain-language request to the Director; checkpoint tests (nothing sent without a tap); release checklist v1 |
| Tester 2 | End-to-end UAT with sample service scenarios; how-to guide for service quotes checked step by step |

**Milestone M1 (end of week 8)**: quick service estimates release-ready. **Phase 1 gate**: a service company can quote, send and convert a job end to end by chat and in the web app, with the Estimating Director leading every step from one plain-language request.

### Phase 2 — Plan engine MVP and Blueprint Review

**Sprint 5 (weeks 9–10)**

| Role | Work |
| --- | --- |
| Coder 1 | Drawing model tables (`drawing_objects`, `viewports`, sheets) and `plan_*` tools; multi-trade estimate structure |
| Coder 2 | Sheet splitting and rendering (`pypdfium2`), title-block reading, sheet classification; viewport detection, per-viewport scale parsing, two-point calibration |
| Tester 1 | Contract tests for `plan_*` tools; upload validation tests (corrupt, encrypted, oversized, duplicates) |
| Tester 2 | 10 vector plan sets with measured areas and lengths; 10 mixed-scale sheets with known viewport scales |

**Sprint 6 (weeks 11–12)**

| Role | Work |
| --- | --- |
| Coder 1 | Measurements: proposed/approved states, locking, suggested changes; `takeoff_*` tools; review versions model |
| Coder 2 | Vector extraction (`pdfplumber`), DXF import (`ezdxf`), geometry (`shapely`): walls, rooms, polygons |
| Tester 1 | Approval-lock tests (AI never overwrites approved values); scale/viewport accuracy tests automated |
| Tester 2 | 5 DXF reference drawings with answers; area/length accuracy runs as features land |

**Sprint 7 (weeks 13–14)**

| Role | Work |
| --- | --- |
| Coder 1 | Concrete and flooring modules wired from Tester 2's content; background processing through the task queue |
| Coder 2 | Blueprint Review v1: tiled viewer, overlays, tool palette, layers, measurement list, detail panel, approve/correct |
| Tester 1 | Performance baseline on laptops A and B (sheet processing time, memory); server-box setup for network tests |
| Tester 2 | Concrete and flooring golden cases; Playwright tests for the viewer and manual tools |

**Phase 2 gate**: areas within ±2% on the 10 vector plans and ±0.5% on the 5 DXF files; mixed-scale sheets measured with the right viewport scale.

### Phase 3 — First construction trades

**Sprint 8 (weeks 15–16)**

| Role | Work |
| --- | --- |
| Coder 1 | Roofing module (pitch factors); scenarios (good/better/best); combined estimate; bid scope by trade; **Director standard lane**: playbooks for concrete, flooring and roofing, Reviewer checkpoint by job size, lane change quick → standard (`est_director_change_lane`), company playbook overrides (`est_playbook_list`, `est_playbook_update`); optional site-visit booking on AI-Prowler's calendar (setting, off by default) |
| Coder 2 | Two-way linking (material ↔ measurement); Estimates screen; manual takeoff tool polish |
| Tester 1 | Integration tests for multi-trade estimates and bids; regression suite expanded; Director standard-lane scripts and lane-change tests (nothing collected is lost) |
| Tester 2 | Roofing golden cases; compare 5 real past jobs against the tool (concrete, flooring, roofing) |

**Milestone M2 (end of week 16)**: concrete, flooring and roofing usable with manual and vector takeoffs. **Phase 3 gate**: within ±5% of the estimators' own bids on 5 real jobs.

### Phase 4 — Legends, schedules, symbols, agents and reviews

**Sprint 9 (weeks 17–18)**

| Role | Work |
| --- | --- |
| Coder 1 | Estimate Runner: runs, trade tasks, dependencies, task states; `runner_*` and `est_project_status`; Agent Manager backend (`agent_config_*`); **Director full takeoff lane**: hand-off to the Runner and back, plan-set triage |
| Coder 2 | Text and dimension OCR (Tesseract); legend detection and plan-set symbol dictionary; schedule extraction with tag linking |
| Tester 1 | Runner tests: routing, parallel trades, dependent trades waiting, one failed trade not blocking others |
| Tester 2 | 15 legend sheets and 20 schedules with hand-entered answers |

**Sprint 10 (weeks 19–20)**

| Role | Work |
| --- | --- |
| Coder 1 | API-key agents: `claude_api` / `grok_api` per role using the Small Business tab agent keys, fallback provider, `chat_only`, budget meter; agent role prompts and `how_to_estimate`; **Director unattended loop** on the task queue, stall watcher (review reminders, due-date warnings, provider fallback, idle jobs) and daily briefing (`est_director_briefing`) |
| Coder 2 | Symbol Recognition Engine v1: template/feature matching, OCR fusion, standard symbol library, fused results (`symbol_detections_*`); Jobs board for all lanes |
| Tester 1 | Provider tests (mock and live, low-budget keys): correct key file, fallback, budget pause, keys never logged; prompt-injection tests; Director stall-watcher and briefing tests with seeded jobs and a fake clock; full 40-request triage set |
| Tester 2 | Symbol hand counts per type on reference plans; detection accuracy runs |

**Sprint 11 (weeks 21–22)**

| Role | Work |
| --- | --- |
| Coder 1 | AI crop reasoning (crop sending on by default with one-time notice); `takeoff_propose`; Reviewer QA (`est_validate`); review tools (`review_*`) |
| Coder 2 | Visual verification: click-to-highlight counts, symbol detection panel, add/deselect/relabel, find similar; company symbol library and learning workflow; Reviews, Agents and Symbol Library screens |
| Tester 1 | Agent scenario scripts on Claude, then Grok (full project run by chat); AI crop privacy test; web-app/MCP parity check started |
| Tester 2 | Playwright tests for verification and review versions; learning test (same-firm plan pair) |

**Phase 4 gate**: AI-proposed takeoffs need edits on under 20% of regions; schedules ≥95% correct cells; symbols ≥95% recall and precision on vector sheets.

### Phase 5 — Remaining core trades

**Sprint 12 (weeks 23–24)**

| Role | Work |
| --- | --- |
| Coder 1 | Framing and drywall modules |
| Coder 2 | Shared wall-and-room model; electrical and plumbing symbol libraries |
| Tester 1 | Cross-trade consistency tests (same rooms and walls across trades) |
| Tester 2 | Framing, drywall, painting, plumbing and electrical content and golden cases |

**Sprint 13 (weeks 25–26)**

| Role | Work |
| --- | --- |
| Coder 1 | Painting, plumbing and electrical modules |
| Coder 2 | PWA mobile reviews (review queue, highlight, approve/relabel by touch) |
| Tester 1 | Parity check for all screens built so far; regression |
| Tester 2 | One full plan set priced across all 8 trades; phone and tablet review tests |

**Phase 5 gate**: all 8 core trades pass golden tests; one plan set priced across all trades.

### Phase 6 — Expansion trades and services

**Sprint 14 (weeks 27–28)**

| Role | Work |
| --- | --- |
| Coder 1 | HVAC, windows/doors, siding and insulation modules |
| Coder 2 | Elevation-sheet support; door/window schedule linking; HVAC symbol library |
| Tester 1 | Contract tests for new module behaviour; regression |
| Tester 2 | Content and golden cases for HVAC, windows/doors, siding, insulation |

**Sprint 15 (weeks 29–30)**

| Role | Work |
| --- | --- |
| Coder 1 | Fencing, landscaping, demolition; service modules (window cleaning, pool service, pest control, junk removal, landscaping maintenance); recurring-service pricing linked to `schedule_next_recurring_job` |
| Coder 2 | Site-plan zones for fencing and landscaping |
| Tester 1 | Recurring-job integration tests |
| Tester 2 | Golden cases for all expansion trades and services; pilot service companies quote each new service by chat |

**Phase 6 gate**: every new module passes golden tests.

### Phase 7 — Scans, CAD, revisions, learning and polish

**Sprint 16 (weeks 31–32)**

| Role | Work |
| --- | --- |
| Coder 1 | Plan revision comparison logic and revision reports (flag only, never auto-reprice); estimate revisions (`est_create_revision`) |
| Coder 2 | Raster pipeline for scans and photos ("needs review" handling); DWG via a user-installed converter (detection and guidance) |
| Tester 1 | Revision comparison tests (5 seeded pairs); estimate revision tests |
| Tester 2 | 10 scanned and 5 photo plans; 3 DWG files; seeded revision pairs |

**Sprint 17 (weeks 33–34)**

| Role | Work |
| --- | --- |
| Coder 1 | Actual-vs-estimate learning loop (`est_compare_history`); price book import with column mapping; Server mode multi-user: roles and permissions, "is editing" indicators, assignments, notifications; Personal → Server export/import; **Server mode compute limits**: heavy-job guard, processing-PC queue and publish (`plan_processing_queue`, `plan_publish_to_server`), optional capped small processing on the server, Director routing to processing PCs |
| Coder 2 | Revision overlay UI; Reports, Settings and full Price Book screens |
| Tester 1 | Server mode multi-user tests (4 test users, one per role, editing the same project); server compute-limit tests (heavy jobs never run on the server by default, published results match Personal processing, light work stays responsive while plans process); role and security tests; office-network and remote-access tests; performance re-run; "Users and roles" guide chapter |
| Tester 2 | UI tests for new screens; full parity checklist pass |

**Phase 7 gate**: DWG/DXF within ±0.5%; all seeded revision changes found and takeoffs flagged; performance targets met on laptops A and B.

### Phase 8 — Onboarding, beta and release

**Sprint 18 (weeks 35–36)**

| Role | Work |
| --- | --- |
| Coder 1 | Full setup wizard in the Estimator tab (trades, team and approvals); remaining tab sections (Web app access, CAD and tools, Modules, Help); practice project data (`est_sample_project`); installer: `AI-Prowler-Setup.iss`, pinned `requirements.txt` additions, user guide shipped in `docs/` |
| Coder 2 | Guided tours for every screen; help panel; contextual help and empty states |
| Tester 1 | Clean-install tests on both laptops and the server box; `release_gate.bat` updated for the Estimator |
| Tester 2 | Tours and how-to guides tested step by step; User Guide final chapters (Troubleshooting, FAQ, Glossary) and full read-through; Estimator chapter for `COMPLETE_USER_GUIDE.md` |

**Sprint 19 (weeks 37–38)**: beta with pilot contractors and service companies.

| Role | Work |
| --- | --- |
| Coders | Fix beta bugs (severity 1–2 first); performance tuning |
| Tester 1 | Triage beta reports; regression after every fix |
| Tester 2 | Coordinate pilots; side-by-side comparisons with their manual estimates |

**Sprint 20 (weeks 39–40)**: release candidate, final regression and release.

| Role | Work |
| --- | --- |
| Coders | Release-candidate fixes only |
| Testers | Full regression, release checklist, sign-off |

**Milestone M3 (end of week 40)**: release. **Phase 8 gate**: pilot users send real bids and rate the feature ready.

**Buffer (weeks 41–44)**: kept free for slips; any unused time goes to the backlog.

## Milestones

| Milestone | Week | What's usable |
| --- | --- | --- |
| G0 Foundations | 2 | Estimates calculate through MCP; web app opens |
| **M1 Service estimates** | 8 | Quick quotes for pressure washing, house cleaning and generic services; bids; quote → job; PWA quick estimates |
| Plan engine MVP | 14 | Upload, scale, vector/DXF measuring, Blueprint Review |
| **M2 First trades** | 16 | Concrete, flooring, roofing estimates and bids |
| AI and symbols | 22 | Runner, API-key agents, legends, schedules, symbols, visual verification |
| Core 8 trades | 26 | All core trades; mobile reviews |
| Expansion trades | 30 | 7 more trades and 5 more services |
| Polish | 34 | Scans, DWG, revisions, reports, roles |
| **M3 Release** | 40 | Full product with setup wizard, tours and guides |

## Dependencies and critical path

- **Critical path**: Coder 2's plan engine (sheets → viewports → vector/DXF → drawing model → legends/symbols) gates every plan-based trade. Coder 1 builds non-plan work (service estimates, bids, runner, agents, modules) in parallel so neither coder waits.
- **Test data ahead of code**: Tester 2's reference plans and golden answers for each sprint must be ready at that sprint's start; this is tracked at sprint planning.
- **Shared service layer first** (Sprint 1–2): both the web app and MCP tools depend on it, so it is built and reviewed before screens multiply.
- **Module content**: Tester 2 drafts content one sprint before Coder 1 wires each module.

## Risks for a 4-person team

| Risk | Effect | Mitigation |
| --- | --- | --- |
| One coder out sick or pulled to other AI-Prowler work | Plan engine or platform stalls | Code reviews across both coders so each knows the other's area; buffer weeks 41–44 |
| Plan engine harder than estimated | Plan-based trades slip | Service estimates (M1) ship independently; manual takeoff tools always work as fallback |
| Test data not ready on time | Testing falls behind coding | Testers work one sprint ahead; data readiness checked at every sprint planning |
| AI API costs during testing | Budget surprises | Separate low-budget test keys; mock provider for nightly runs; live runs only for scenario tests |
| Scope creep from pilot feedback | Release slips | New requests go to the backlog unless they fix a severity 1–2 problem |

## Tracking

- Each sprint's tasks become tickets in AI-Prowler's own ticketing app (or the team's tracker), tagged by phase, owner and type (feature, test, bug, content).
- The design spec's phase gates are checked off in this file at each gate.
- A short sprint summary is added to `notes\` in the work folder after every demo.

**Coder 2 sprint status** (updated 2026-11-09, after Sprint 18)

| Sprint | Coder 2 work (from the sprint plan) | Status |
| --- | --- | --- |
| 1 | Web app shell, sign-in, navigation, JSON API, live updates | Done |
| 2 | Documents upload; Dashboard, Projects, Quick estimate screens | Done |
| 3 | Price Book screen (basic); PWA Estimates tab | Done (the 🏗 Estimator GUI tab was built by Coder 1, Sprint 16) |
| 4 | Bids screen; how-to guides; Jobs board (quick lane) | Done |
| 5 | Sheet splitting and rendering, title blocks, sheet classification, viewports, scales, calibration | Done |
| 6 | Vector extraction, DXF import, walls, rooms, polygons | Done |
| 7 | Blueprint Review v1 | Done |
| 8 | Two-way linking; Estimates screen; manual takeoff polish | Done |
| 9 | Text and dimension OCR; legends and symbol dictionary; schedules with tag linking | Done |
| 10 | Symbol Recognition Engine v1; Jobs board for all lanes | Done |
| 11 | Visual verification, find similar, company symbol library and learning; Reviews, Agents, Symbol Library screens | Done |
| 12 | Shared wall-and-room model; electrical and plumbing symbol libraries | Done |
| 13 | PWA mobile reviews | Done |
| 14 | Elevations; door/window schedule linking; HVAC symbol library | Done |
| — | Roles: office approves symbols and measurements; Estimating scope | Done (2026-11-09) |
| 15 | Site-plan zones for fencing and landscaping | Done (2026-11-09) |
| 16 | Raster pipeline for scans and photos; DWG via a user-installed converter | Done (2026-11-09) |
| 17 | Revision overlay UI; Reports, Settings and full Price Book screens | Done (2026-11-09) |
| 18 | Guided tours, help panel, contextual help and empty states | Done (2026-11-09) |
| 19–20 | Beta, release candidate, release (whole team) | Not started |

Manual checks for Sprints 10–18 (in each sprint's `tests/estimator/SPRINT_n_CODER2_TEST_PLAN.md`) are still open, starting with real plan sets. Gates G0 onward are still unchecked below.

**Progress log**

| Date | Sprint | Who | Done |
| --- | --- | --- | --- |
| 2026-11-05 | Sprint 1 | Coder 1 (Jamie) | `estimator/` package and data folder config; money (integer cents) and units; sandboxed formula engine; pricing stack; `estimator.db` schema v1, migrations, backup/restore/prune. 135 unit tests in `tests/estimator/` passing on Windows 11 / Python 3.11.8 and on Linux / Python 3.13; manual checks S1-X02 (default data folder) and S1-X03 (backup while the database is open) pass. Waiting on: code review by David. Test plan: `tests/estimator/SPRINT_1_CODER1_TEST_PLAN.md` |
| 2026-11-05 | Team change | Jamie | David (Coder 2) is not available. His track (plan engine, web app, 🏗 Estimator GUI tab) is on hold until he's back. Jamie continues the Coder 1 track alone. Code reviews: Jamie self-reviews with the checklist in each sprint's test plan, and David's reviews of Sprints 1 and 2 are deferred. The G0 gate stays open until a review is done. |
| 2026-11-05 | Sprint 2 | Coder 1 (Jamie) | Module registry with manifest checks; estimate service layer (rev checks, finalized lock, roles, company scoping, audit log); price book with flagged sample prices; quick-estimate engine; Pressure Washing and House Cleaning modules with golden cases; 8 Estimator MCP tools plus `register(mcp)`. 205 tests (135 + 70 new) passing on Windows 11 / Python 3.11.8 and on Linux. Not yet wired into `ai_prowler_mcp.py`; manual check S2-X01 runs after that hook is added. Test plan: `tests/estimator/SPRINT_2_CODER1_TEST_PLAN.md` |
| 2026-11-05 | Sprint 2 | Jamie | Estimator hook added to the development `ai_prowler_mcp.py`; `install_estimator.bat` copies the Estimator and the hook into the installed AI-Prowler (`C:\Program Files\AI-Prowler`), tested on a throwaway copy |
| 2026-11-06 | Design change | Jamie | Added the **Estimating Director** master agent to the spec. Built in stages on the Coder 1 track: foundation in Sprint 3, quick lane end to end in Sprint 4, standard lane in Sprint 8, full takeoff lane in Sprint 9, unattended loop, stall watcher and briefing in Sprint 10. Four open questions use working defaults (staff-only, $500 one-tap limit, no calendar booking yet, one Director per company) |
| 2026-11-06 | Decisions | Jamie | Director: staff only for now; one-tap quick-send limit $100 by default; calendar site-visit booking off by default; both configurable per company. Open: Estimator mainly for AI-Prowler Personal because of compute needs |
| 2026-11-06 | Decisions | Jamie | Server mode is supported for the Estimator, limited to low-compute work on the server; heavy plan processing runs on estimators' own PCs and is published to the server (added to Sprint 17). Director: one per install in Personal, one per company in Server |
| 2026-11-06 | Sprint 3 | Coder 1 (Jamie) | Estimating Director foundation: database v2 (job file, steps, playbook overrides, Director settings), three lane playbooks with validation, keyword triage, quick-quote lane running from request to approval (one-tap under $100, owner/reviewer above, sample prices block approval until confirmed), job status and board; generic service module; setup wizard backend; office and field roles can give quick quotes; 9 new MCP tools (17 total). 264 tests passing on Windows 11 / Python 3.11.8 and Linux. Moved to Sprint 4: links to AI-Prowler customers/quotes/jobs (with bids). Test plan: `tests/estimator/SPRINT_3_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 4 | Coder 1 (Jamie) | Bids: database v3, branded HTML quote with PDF printed by Microsoft Edge (no new dependency), frozen prices, numbered versions, send through AI-Prowler's `send_email` (PDF attached when allowed), viewed/won/lost, convert a won bid to an AI-Prowler customer + Approved quote + job through AI-Prowler's own tools; the Director now runs a quick quote start to finish (one tap approve and send under the limit, follow-up date, won → job, lost → closed); 6 bid tools (23 total). 286 tests passing on Windows 11 / Python 3.11.8 (Edge PDF) and Linux. Bids and Jobs board screens stay on hold with Coder 2. Test plan: `tests/estimator/SPRINT_4_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Live check | Jamie | Estimator installed into `C:\Program Files\AI-Prowler`; AI-Prowler registered all 23 Estimator tools; a real Director quote (pressure washing, $502.50) was priced and approved in chat. Email sending failed in AI-Prowler itself (Gmail drops the login) — to fix with a new Gmail app password |
| 2026-11-06 | Sprint 5 (re-ordered) | Coder 1 (Jamie) | Because the planned Sprint 5 depends on the plan engine (Coder 2, on hold), the Phase 6 quick-estimate services were pulled forward: Window Cleaning, Pool Service, Pest Control, Junk Removal, Landscaping Maintenance, with golden cases and keywords (8 services total). Triage rebalanced; failed Director steps recorded and retryable. 315 tests passing on Windows 11 and Linux. Remaining Phase 6 item for services: recurring-service links (`schedule_next_recurring_job`). Test plan: `tests/estimator/SPRINT_5_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 6 (re-ordered) | Coder 1 (Jamie) | Still Coder 1 work while the plan engine is on hold: price book by chat (`pricebook_get`, `pricebook_update`, confirm first, logged), estimate revisions (`est_create_revision`, Director `revise` and `reprice`), follow-ups due and daily briefing (`est_followups_due`, `est_director_briefing`), won repeat-service quotes become AI-Prowler jobs with Recurrence set (house cleaning, pool, landscaping, pest control), and dates shown in local time. 28 Estimator tools. 335 tests passing on Windows 11 and Linux. Scheduled briefing delivery stays with the unattended loop (Sprint 10). Test plan: `tests/estimator/SPRINT_6_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 7 (re-ordered) | Coder 1 (Jamie) | Phase 3 Coder 1 work pulled forward: Concrete, Flooring and Roofing modules priced from typed measurements (waste and pitch factors per the spec, hot-weather notes, 10 golden cases); Director standard-estimate lane live (collect, price, Reviewer check by job size with new setting `review_required_over_cents` default $500, owner/reviewer approval, bid, follow up); `est_validate` QA checks; `est_director_change_lane`; database v4. 30 Estimator tools, 11 modules. 372 tests passing on Windows 11 and Linux. Next Phase 3 items: good/better/best scenarios, combined estimate and bid scope by trade, `est_playbook_update`, calendar site visits. Test plan: `tests/estimator/SPRINT_7_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 8 | Coder 1 (Jamie) | Rest of the Phase 3 Coder 1 work: good/better/best options (`est_scenarios`, `est_choose_scenario`, built in for roofing, flooring, concrete, window cleaning, pressure washing; shown on the bid; carried into revisions); several trades on one job (`est_director_add_trade`) and bid detail by trade (`price_detail: trade_totals`); company playbook changes (`est_playbook_update`: review limit, one-tap limit, required approval checklist); site-visit booking as an AI-Prowler scheduled job (`est_director_book_site_visit`, off by default, confirm first). Database v5. 35 Estimator tools. 391 tests passing on Windows 11 and Linux. Phase 3 Coder 2 items (linking, Estimates screen) and the real-job ±5% gate wait for David and pilot jobs. Test plan: `tests/estimator/SPRINT_8_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 9 (re-ordered) | Coder 1 (Jamie) | Director unattended loop pulled forward from Sprint 10: background watcher in AI-Prowler's process (every 15 min, light work, Server mode too) with stall watcher (review reminders, stuck jobs, due soon/overdue), follow-up and expiring notices, auto-expiry of quotes past valid-until, and the daily briefing at briefing_time to the inbox or by email with retries. New tools `est_director_inbox`, `est_director_watch_now`, `est_director_watch_status`; database v6. 38 Estimator tools. 407 tests passing on Windows 11 and Linux. Still to do from Sprints 9–10: Estimate Runner, API-key agents and provider fallback. Test plan: `tests/estimator/SPRINT_9_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Live check | Jamie | Reinstalled; AI-Prowler shows the new tools; the Director watcher is running in the background (every 15 minutes) and made the first daily briefing |
| 2026-11-06 | Sprint 10 (re-ordered) | Coder 1 (Jamie) | Framing and Drywall (planned Sprint 12) and Painting (planned Sprint 13) built as construction modules priced from typed measurements with the spec's formulas, notes, and good/better/best options for drywall finish and paint; 9 golden cases; carpet cleaning triaged to the service quote. 14 modules (8 services, 6 trades). 431 tests passing on Windows 11 and Linux. Plan-based takeoff for these trades (shared wall-and-room model) waits for Coder 2. Test plan: `tests/estimator/SPRINT_10_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 11 (re-ordered) | Coder 1 (Jamie) | Plumbing and Electrical (rest of planned Sprint 13) priced by labor hours per fixture or device per the spec, with pipe and wire runs, fittings, waste, water heaters, gas, panels and permits; 8 golden cases. All 8 core trades now exist as typed-measurement modules (Phase 5 gate content met for typed input; plan-based takeoff still waits on Coder 2). 16 modules. 456 tests passing on Windows 11 and Linux. Test plan: `tests/estimator/SPRINT_11_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 12 (planned Sprint 14, expansion trades) | Coder 1 (Jamie) | Done | HVAC (sized by area ÷ sq ft per ton, or typed tons; split, heat pump, package, mini-split; reuse, seal or new ducts), Windows and Doors (unit counts by type and size; retrofit or new construction; good/better options), Siding (squares from wall area less openings; vinyl, fiber cement, wood, stucco, stone; good/better/best) and Insulation (blown attic by R-value, batts, spray foam; good/better/best). 12 construction trades, 20 modules. Triage routes AC, windows, siding and insulation requests; cleaning look-alikes still go to services. 489 tests pass on Linux and on Jamie's PC; PC files match. Test plan: `tests/estimator/SPRINT_12_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 13 (trade part of planned Sprint 15) | Coder 1 (Jamie) | Done | Fencing (wood, vinyl, chain link, block wall, wrought iron; posts every 8 ft; gates; good/better/best), Landscaping installs (sod, turf, rock over weed barrier, pavers, plants, drip and sprinkler zones, edging) and Demolition (selective or gut interior, walls, cabinets, fixtures, flooring, concrete by weight, structures, dumpsters, hazard test). All 15 planned construction trades now exist; 23 modules. Hand pricing still works for a trade a company turns off. 522 tests pass on Linux and on Jamie's PC; PC files match. Test plan: `tests/estimator/SPRINT_13_CODER1_TEST_PLAN.md` |
| 2026-11-06 | Sprint 14 (Coder 1 part of planned Sprint 9) | Coder 1 (Jamie) | Done | Estimate Runner: one takeoff task per trade, dependencies (drywall, painting, insulation wait for framing), task states, submit / review / retry, only approved quantities priced, one failed trade never blocks others; `runner_start`, `runner_status`, `runner_submit_takeoff`, `runner_review_task`, `runner_retry_task`, `est_project_status`. Agent Manager: enabled, confidence threshold, auto-advance, sheet rules and default answers per trade; `agent_config_get` / `agent_config_update`. Director full plan takeoff lane now works: trades from the request (or asked), hand-off to the Runner and back, then review, approval and bid. Database v7. 46 tools. 546 tests pass on Linux and on Jamie's PC; PC files match. Plan reading waits on the Plan Engine (Coder 2). Test plan: `tests/estimator/SPRINT_14_CODER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 15 (Coder 1 part of planned Sprint 10) | Coder 1 (Jamie) | Done | API-key agents on AI-Prowler's own desk_agent_providers (agents' keys from the Small Business tab, same models and prices): per-role provider (off / chat_only / claude_api / grok_api), model and backup provider; budget meter (daily and monthly, cost per call logged, pauses at the limit); agent task queue run by the watcher (Reviewer notes, Bid Writer scope drafts, Follow-up email drafts; JSON actions only, checked, no invented dollar amounts, 3 tries then a notice); chat_only work via est_agent_next / est_agent_submit; role prompts in estimator/agents/prompts and `how_to_estimate`. Database v8. 55 tools. 563 tests pass on Linux and on Jamie's PC; PC files match. Live run with a real key is a manual check (see test plan). Test plan: `tests/estimator/SPRINT_15_CODER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 16 (desktop part of planned Sprint 18, pulled forward) | Coder 1 (Jamie) | Done | Split agreed: Coder 1 builds the desktop screens now; Coder 2 builds the phone Estimates tab and the web app with the Plan Engine. 🏗 Estimator tab in AI-Prowler's GUI (estimator/ui/gui_tab.py, added by a few guarded lines in rag_gui.py after Learnings): on/off switch, what's installed, the 9-step setup checklist, company and pricing form (percent typed, stored as fractions), trade checkboxes, AI agents (keys saved?, provider/model/backup per role, budget and spend), Director settings, data and backups, phone/web placeholder, help. Setup AI-Prowler: "📐 Estimate and bid jobs" choice as a real switch, an Estimator step with its light and a guided company-basics window (estimator/ui/setup_flow.py). Switch off → no est_ tools and no watcher after restart; nothing lost. Logic in estimator/ui/model.py (no tkinter, every save through the service layer as the owner). 580 Estimator tests pass on Jamie's PC (571 + 1 skipped on Linux without a screen; GUI tests also run under a virtual screen); David's Setup tests pass with the new step; PC files match. Test plan: `tests/estimator/SPRINT_16_CODER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 17 (Coder 1 part of planned Sprint 17, without the Plan Engine) | Coder 1 (Jamie) | Done | Actual-vs-estimate learning loop: `est_record_actuals` (per line, price, kind of cost or whole job, for sold jobs; compared with cost incl. waste and burden; real vs estimated margin) and `est_compare_history` (lines against your usual unit cost and real job costs; suggested `pricebook_update` calls after 2+ jobs 10% off; never changes prices); Reviewer agent context gets the history flags. `pricebook_import` from CSV/Excel files or pasted CSV with column mapping or name guessing, key or description match, `add_new` custom prices, unit mismatches skipped, preview before confirm, supplier saved, logged. `est_export` to CSV/Excel (one estimate's lines and totals, or a list). Database v9 (`estimate_actuals`). 59 tools. Also: `run_tests_estimate.bat` (Estimator regressions; `setup` and `full` modes) and three test files renamed `test_est_*` so they no longer clash with AI-Prowler test names in one run. 599 tests pass on Linux, 608 on Jamie's PC; PC files match. Server multi-user, the processing-PC queue and Personal → Server export are still to do. Test plan: `tests/estimator/SPRINT_17_CODER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 18 (Coder 1 part of planned Sprints 17–18, without Server sign-in) | Coder 1 (Jamie) | Done | Assignments (`est_assign` to owner/estimator/office users, with a note and a personal "assigned" notice) and `est_my_work`; Director inbox and unread count show only notices for everyone or for you; "someone else is editing" warning on an estimate changed by another user in the last 10 minutes; practice project `est_sample_project` ("Practice: Garcia house", roofing + pressure washing, marked practice, left out of history, ticks the "Try a sample quote" setup step, delete asks first and removes everything it made). Tab: 📦 Modules section and 🎓/🗑 practice button. Database v10 (`director_notices.for_user`, `estimates.is_practice`). 62 tools. Server mode still waits on AI-Prowler Server's signed-in users. Test plan: `tests/estimator/SPRINT_18_CODER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 19 (Personal → Server move from planned Sprint 17) | Coder 1 (Jamie) | Done | `est_data_export` packs a company's Estimator settings, records and quote files into one .zip (manifest, data, files); `est_data_import` previews, then loads it into AI-Prowler Server or another PC with new IDs. Owner only. Safety: only expected file names read from the zip, a newer database version or unknown table refused, settings kept when the target already has estimates, practice data left out unless asked. Tab: 📤/📥 buttons in the Data section. No database change. 64 tools. Test plan: `tests/estimator/SPRINT_19_CODER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 20 (Tester 1 part of planned Sprint 19, beta preparation) | Tester 1 (Jamie) | Done | Scripted chat runs through the AI tools only: first-day setup, driveway call → quote → won → job → real cost, roof over the review limit with revision, team assignment and server move, 11 tools given bad input all answer JSON. Performance with 300 estimates: everyday reads well under 2 seconds. Quote PDF now retries with its own Edge profile, fixing the PDF test when run as Administrator. 630 tests pass on Jamie's PC (621 + 1 skipped on Linux); all 20 changed files match. Still by hand: the same scenarios typed in chat with Claude and Grok after deploy. Test plan: `tests/estimator/SPRINT_20_TESTER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 21 (Coder 1 part of planned Sprint 5, Phase 2) | Coder 1 (Jamie) | Done | Shared drawing model and `plan_*` tools: database v11 (`plan_sets`, `sheets`, `viewports`, `drawing_objects`, `schedules`, `schedule_rows`, `legends`); uploads checked by content (PDF, images, DXF, DWG; size, password, duplicates) and copied into the estimate's folder; exact measuring (scale notes, typed distances, lengths, areas, two-point calibration) with each object measured by its own viewport's scale, NTS and unscaled never measured; the plan engine's results checked in full before saving, schedule rows linked to tags; `plan_set_scale` re-measures; background processing with a drop-in `estimator.plan_engine` hook (result format in `drawing_model/engine.py`). 11 tools (75). Also: practice delete takes its plan sets; pack-up lists plan sets it leaves behind; "my work" lists practice jobs with a 🎓 label. 639 tests pass on Linux, 648 on Jamie's PC; PC files match. The plan engine itself is Coder 2's. Test plan: `tests/estimator/SPRINT_21_CODER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 22 (Coder 1 part of planned Sprint 6, Phase 2) | Coder 1 (Jamie) | Done | Measurements and approval locks: database v12 (`measurements`); quantities worked out from drawing objects (area sq ft, length and perimeter ft, count) or typed or drawn by a person; only a person approves, approved numbers are locked, agents can only suggest a change with a reason; `runner_submit_takeoff from_measurements=true` prices approved measurements only, converted to each question's unit; a scale change re-measures unlocked ones and suggests changes on locked ones; reading the plans again rejects proposed ones and flags approved ones to re-measure, never losing them; `est_validate` warns about waiting, flagged and suggested measurements. 8 tools (83): `takeoff_propose`, `takeoff_manual`, `takeoff_list`, `takeoff_confirm`, `takeoff_edit`, `takeoff_delete`, `takeoff_detail`, `takeoff_suggest_change`. 650 tests pass on Linux, 659 on Jamie's PC; PC files match. Test plan: `tests/estimator/SPRINT_22_CODER1_TEST_PLAN.md` |
| 2026-11-07 | Sprint 23 (Coder 1 part of planned Sprint 8, Phase 4) | Coder 1 (Jamie) | Done | Reviews and AI crop privacy: database v13 (`reviews`, `ai_send_log`, crop notice and review-before-send settings); `review_start` keeps the original as version 0, every `review_save` is a new version (add missed items, remove false hits, relabel with matching, hand-corrected areas), `review_approve` by a person only (optional second check by someone else) becomes the priced value and locks the measurement; `review_history` and `review_highlight` (every item sheet by sheet, numbered, any version); schedule rows reviewable; detection sets wait for the symbol engine. Quotes can require every count and measurement approved before sending (owner, off by default); `est_validate` warns about open reviews. Crops: at most 15% of a sheet scaled to 1024 px, whole sheets only when a person asked, on by default with a one-time notice, owner can turn off, every send logged (`plan_get_crop`, `est_ai_privacy`). 8 tools (91). 664 tests pass on Linux, 673 on Jamie's PC; PC files match. Test plan: `tests/estimator/SPRINT_23_CODER1_TEST_PLAN.md` |
| 2026-11-08 | Sprint 1 (Coder 2) | Coder 2 (David) | Code done; manual checks M1–M7 open | Estimator web app shell: `estimator/api/` (auth, nav, live, router, server, prowler_link) and `estimator/ui/web/` at http://localhost:8770/estimator/. Personal same-PC with no login (loopback, no proxy or tunnel headers, local Host), otherwise sign-in with in-memory sessions, a CSRF header on writes, and a 5-failure lockout. The role-filtered menu has the 13 screens and MCP-tool parity. Dashboard and Projects work. Live updates come from `estimate_events` over SSE with polling as the fallback. Field never sees costs or margins. Hooked into `ai_prowler_mcp.py` (only AI-Prowler's own HTTP server process, never under pytest, `ESTIMATOR_WEB=off`); `install_estimator.py` adds the hook to installed copies. Server mode signs in with AI-Prowler accounts (role mapping waits for Jamie). New `run_tests_estimator.bat` (all / coder1 / coder2). 781 Estimator tests pass on David's PC after pulling Jamie's Sprints 21–23 (108 Coder 2). Waiting on Jamie: role mapping, sessions table or not, `est_add_trade`/`est_remove_trade`, the Estimator tab link, one test runner or two, Remote Access through port 8000. Test plan: `tests/estimator/SPRINT_1_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 2 (Coder 2) | Coder 2 (David) | Code done; manual checks M1–M7 open | Documents: browser plan upload on top of Jamie's `plan_upload` (Sprint 21). The file is streamed to a staging folder (up to 300 MB), checked, then attached only on "Attach"; refusals happen before the file is read; staged files belong to their uploader and expire. Project page: per-trade subtotals and lines (`est_project_status`), run tasks, Director stage, plan sets and upload, history. Dashboard: quick-estimate button, needs attention (reviews waiting, my work, notices), status tiles that open filtered Projects. Projects: status filter, find box, clickable rows. Quick estimate screen: service picker, form built from the module's questions, price, sample-price warnings, open the project; also adds to an existing project with its rev. New `estimator/api/staging.py`; router, server (streamed uploads), nav (`PAGES`, two permissions), app.js and app.css. No changes to Coder 1 files. 818 Estimator tests pass on David's PC (145 Coder 2, 37 new). PWA Estimates tab stays in Sprint 3 as planned. Test plan: `tests/estimator/SPRINT_2_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 3 (Coder 2) | Coder 2 (David) | Code done; manual checks M1–M4, P1–P7 open | Price Book screen (basic): list with yours or sample, trade filter, samples only, find; edit costs with old → new confirmation (`pricebook_update`); paste-CSV supplier import with preview and skipped rows (`pricebook_import`); costs only for owner and estimator. The Estimator tab from this row was done by Coder 1 in Sprint 16. PWA Estimates tab: the Estimator is also served by AI-Prowler's port-8000 server (`asgi_bridge`, both routers), so Remote Access and the Jobs app reach it; the Jobs app's token signs people in; a new Estimates tab in the Jobs app frames the quick estimate page. Deploy with `deploy_to_install.bat`. Coder 2 track 181 tests pass; AI-Prowler Jobs app tests 187 pass. Test plan: `tests/estimator/SPRINT_3_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 4 (Coder 2) | Coder 2 (David) | Code done; manual checks M1–M10 open | Jobs board (quick lane) and job page over the Director (`est_jobs_board`, `est_job_status`, `est_director_next`); new web quick quotes start a Director job. Approve (with checklist and sample-price boxes), send, won/lost and convert from the page; send and convert ask yes/no first. Bids screen: list, sandboxed preview, PDF download, send, status, convert (`bid_*`). Help screen with five first how-to guides (`estimator/ui/help/`), search and a "?" per screen. The wizard's sample service quote is left to Coder 1 (desktop wizard). Coder 2 track 221 tests pass. Test plan: `tests/estimator/SPRINT_4_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 5 (Coder 2) | Coder 2 (David) | Code done; manual checks M1-M8 open | Plan engine v0.5 (`estimator/plan_engine`): PDF sheets split and rendered (`pypdfium2`), text and frames (`pdfplumber`), title blocks (sheet number, title, revision, date), discipline from prefix and title, viewports with their own scale notes (frames or layout), NTS, title-block scale fallback, only scales `parse_scale` accepts; scans and photos as unscaled sheets; DXF/DWG next sprint. 0.18 s a page on David's PC. Plans screen: plan sets, read (asks first, background), sheets, sheet image with viewport outlines, set scale or two-point calibration by clicking. Coder 2 track 298 tests pass (53 engine, 22 web new). Test plan: `tests/estimator/SPRINT_5_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 6 (Coder 2) | Coder 2 (David) | Code done; manual checks M1-M7 open | Plan engine v0.6: PDF line work per viewport, walls (parallel line pairs, centerline + thickness) and rooms (`shapely` closed areas with a room name), measured with the view's scale or counted when unscaled; DXF import (`ezdxf`) at real size with units, layers, walls, rooms, symbols, text and dimensions; DWG asks for DXF or PDF. Sheet page "Found on this sheet" card. New Estimator section in requirements.txt (PyYAML, ezdxf, shapely). Coder 2 track 347 tests pass (49 new). Test plan: `tests/estimator/SPRINT_6_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 7 (Coder 2) | Coder 2 (David) | Code done; manual checks M1-M10 open | Blueprint Review v1: Takeoffs screen and per-project review page; tiled viewer (PDF tiles rendered per tile up to 300 DPI, cached); overlays and layer groups (show/hide, lock); tools (select and measure from the drawing, length, area, rectangle, count, calibrate); measurement list by trade and room with totals, review queue, bulk approve; detail panel with approve, correct, reject, suggest, accept. All through Jamie's takeoff service. Browser smoke test in headless Chromium passed. Coder 2 track 386 tests pass (39 new). Notes for Jamie: `layers` table, drawn counts on unscaled views. Test plan: `tests/estimator/SPRINT_7_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 8 (Coder 2) | Coder 2 (David) | Code done; manual checks M1-M9 open | Two-way linking (line ↔ measurements through the trade's questions; measured / differs / typed / waiting per question); Estimates screen (where quantities come from, price a trade with its approved measurements, lines with their measurements and plan links, checks, history, options, hand lines, recalculate, new version); Blueprint Review Lines tab and line links; drawing aids (snap, Shift, Backspace, perimeter, typed number). Browser smoke tests for Sprints 7 and 8 passed (one script name clash found and fixed). Coder 2 track 402 tests pass (16 new). Waiting on Coder 1: est_update_line_item, est_apply_assembly. Test plan: `tests/estimator/SPRINT_8_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 9 (Coder 2) | Coder 2 (David) | Code done; manual checks M1-M6 open | OCR with Tesseract for scans and images; dimension strings checking and supplying view scales; schedule extraction with tag linking across the plan set (including mark series); legend detection, item types and the plan-set symbol dictionary with symbol templates (sidecar file until symbol_definitions exists); schedules and legends on the plan set page with row corrections. Browser smoke test passed. Coder 2 track 447 tests pass (45 new). Test plan: `tests/estimator/SPRINT_9_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 10 (Coder 2) | Coder 2 (David) | Code done; manual checks M1-M7 open | Symbol Recognition Engine v1: legend-first template matching on vector sheets (any rotation, mirrored), raster matching on scans, CAD block names, OCR fusion with codes, standard symbol library, fused results in symbol_detections (migration 14) with symbol_detections_list; symbol counts on the plan set page and symbols in Blueprint Review's trade layers; Jobs board for all lanes with each plans job's progress. Browser smoke test passed. Coder 2 track 476 tests pass (29 new). Next (Sprint 11): symbol_detection_review, find similar, company library and learning. Test plan: `tests/estimator/SPRINT_10_CODER2_TEST_PLAN.md` |
| 2026-11-08 | Sprint 11 (Coder 2) | Coder 2 (David) | Code done; manual checks M1-M8 open | Visual verification: Reviews screen with a detection panel per plan set (thumbnails, filters, least sure first, select, bulk approve / take out / relabel / reset with every identical match, find similar, add a missed symbol, open on the plan; history of the first result); company symbol library and learning (approved, relabelled and added shapes become company examples and are found on the next plan set, the legend still wins); Symbol Library screen (by trade, define and version, export, import); Agents screen (Agent Manager settings, takeoff runs, retry). Migration 15; 4 new tools (symbol_detection_review, symbol_find_similar, symbol_library_list, symbol_define). Browser smoke test passed. Coder 2 track 498 tests pass (22 new). Next (Sprint 12): Symbols tab and ?symbol= highlight in Blueprint Review; waiting on Coder 1: counts into takeoff_propose, plan_sets.design_firm for firm profiles. Test plan: `tests/estimator/SPRINT_11_CODER2_TEST_PLAN.md` |
| 2026-11-09 | Sprint 11 (Coder 2, leftovers) | Coder 2 (David) / Tester 2 | Code done; manual checks M1-M8 open | Click-to-highlight counts: Blueprint Review Symbols tab (highlight a type, step through, link to Reviews), ?symbol= links from Reviews, ✳ Add symbol tool. Tester 2: Playwright tests for verification (`tests/estimator/browser`, `run_tests_estimator.bat browser [--human]`, 6 tests) and the same-firm learning test, which found a learned duplex also counting a fourplex: learned shapes now need 95% reverse score. The Estimator now has the AI-Prowler icon like the other apps. Coder 2 track 501 tests pass, all Estimator tests 1174. Next: Sprint 12 (shared wall-and-room model; electrical and plumbing symbol libraries). Test plan: `tests/estimator/SPRINT_11_CODER2_TEST_PLAN.md` |
| 2026-11-09 | Sprint 12 (Coder 2) | Coder 2 (David) / Tester 2 | Code done; manual checks M1-M8 open | Shared wall-and-room model (`estimator/building`): rooms, interior/exterior walls, doors and windows sized from the schedules, ceiling heights from the finish schedule; repeat views and other disciplines skipped; framing, drywall, painting, insulation and flooring answers all from the one model (same model_key). Electrical and plumbing: standard symbol library v2 (+25 types) with FEEDS to the module questions; approved symbols become answers. 2 new tools (plan_get_rooms_walls, plan_trade_answers; 98 in all); Plan quantities page linked from Blueprint Review; one guide. Coder 2 track 535 tests pass (34 new), browser track 8 (2 new), all Estimator tests 1208. Next / waiting on Coder 1: the Runner's trade tasks and takeoff_propose to use plan_trade_answers. Test plan: `tests/estimator/SPRINT_12_CODER2_TEST_PLAN.md` |
| 2026-11-09 | Sprint 13 (Coder 2) | Coder 2 (David) / Tester 2 | Code done; manual checks M1-M8 open | Reviews on a phone or tablet: one queue of symbols to check and measurements waiting, least sure first; each shown in place on its sheet, outlined (no tiled viewer needed); one item at a time with big Approve / Take out / Relabel / Skip and swipe, each asking first; Jobs app Estimates tab gets Quick estimate \| Reviews (n). Fixed: pictures inside the Jobs app (Remote Access) now load with the app's token. No new tables or tools. Coder 2 track 543 tests pass (8 new), browser track 14 (6 new, on a 390 x 844 touch screen), all Estimator tests 1216; Jobs app test ids 67 pass. Question: should Field approve on the phone (spec role list) or only look (current service roles)? Test plan: `tests/estimator/SPRINT_13_CODER2_TEST_PLAN.md` |
| 2026-11-09 | Sprint 14 (Coder 2) | Coder 2 (David) / Tester 2 | Code done; manual checks M1-M8 open | Exterior elevations: each side's wall from floor line to plate line (gables out) and its doors and windows, for siding and exterior paint when all four sides are drawn; walls and rooms no longer read from elevation views. Door and window schedule linking: each mark's size, type, QTY and count on the floor plans, with untagged and mismatched marks noted; windows and doors trade counts by kind. Siding corners from the building's outline. HVAC symbol library (v3, +12 types) feeding the hvac module; conditioned area from the rooms less garages and porches. Plan quantities shows the schedule, the elevations and 10 trades. No new tables or tools. Coder 2 track 588 tests pass (45 new), browser 14, all Estimator tests 1261. Plan sets read before this sprint need reading again for elevations. Next / waiting on Coder 1: the Runner and takeoff_propose to use plan_trade_answers. Test plan: `tests/estimator/SPRINT_14_CODER2_TEST_PLAN.md` |
| 2026-11-09 | Roles (Coder 2) | Coder 2 (David) / Tester 2 | Done | David's decision: field crews can't approve; owner, managers and staff can. Office (the Jobs app's managers and staff) now see Plans, Reviews and Takeoffs and approve symbols and measurements on the desktop and phone; field still look only. Estimating is a scope: a manager or staff member with the Estimating scope (Admin → Manage Scopes) signs in as an Estimator; field crews stay Field. Approving a whole estimate and the Runner's takeoff review are unchanged (owner, estimator, reviewer). All Estimator tests 1268 pass. Jamie signed off 2026-11-09: the mapping stands; the Estimating scope is how a manager or staff member gets estimator access (change and approve), a scope holder is never field crew, field crew stays view-only, and the Runner's takeoff review does not add office separately - a scope holder signs in as Estimator, who is already a review role. Recorded in the Spec change log (Roles sign-off, Coder 1). |
| 2026-11-09 | Sprint 24 (Coder 1 part of planned Sprint 11, Phase 7) | Coder 1 (Jamie) | Done | Plan revisions and Server mode compute limits: `plan_compare_revisions` with saved revision reports (sheets matched by number, title, page; objects unchanged / moved / changed / removed / added; schedule rows and revision clouds; overlay boxes); measurements on unchanged objects carry over, others are flagged re-measure, quantities never change. Processing-PC queue through a shared exchange folder (`ESTIMATOR_EXCHANGE_DIR`): Server uploads queue for the uploader's PC, `plan_processing_queue` claims (own jobs first, others after 15 min), `plan_publish_to_server` sends the results, the server takes them in (also from the Director's watcher), stale claims return after 2 h; heavy-job guard and the owner's small-plan setting (`est_server_compute`, off by default, 1-50 sheets). Migration 16 (after Coder 2's 14-15), 4 new tools (102). Merged with Coder 2 Sprints 1-14 first; Jamie's PC: all Estimator tests 1280 passed (shapely and ezdxf from requirements.txt installed on the PC). Test plan: `tests/estimator/SPRINT_24_CODER1_TEST_PLAN.md` |
| 2026-11-09 | Sprint 25 (Coder 1: the items Coder 2 was waiting on) | Coder 1 (Jamie) | Done | Plan quantities into takeoffs and the Runner: `takeoff_propose from_plans=true` turns the plans' answers (Coder 2's wall-and-room model, schedules, elevations and approved symbol counts, all plan trades) into proposed measurements, one per question, with where each came from and the symbol detections counted; re-running updates proposed ones and puts a suggested change beside approved (locked) ones. `runner_submit_takeoff from_plans=true` (approved measurements win over the plans, typed answers over both; counts with unchecked symbols never auto-advance). Design firm on plan sets (`plan_upload design_firm`, revisions keep it, `plan_set_design_firm` sets, clears and lists firms). Estimates and Projects screens: `est_get_assemblies`, `est_apply_assembly` (from approved measurements plus params / option, recorded in `assembly_uses`), `est_update_line_item` (overrides with reason, revert, remove; kept on re-apply and in revisions), `est_add_trade`, `est_remove_trade`; the web app's parity PENDING list is empty. Migration 17, 6 new tools (108). Jamie's PC: all Estimator tests 1294 passed. Test plan: `tests/estimator/SPRINT_25_CODER1_TEST_PLAN.md` |
| 2026-11-09 | Sprint 26 (Coder 1 part of planned Sprint 18, Phase 8) | Coder 1 (Jamie) | Done | The Estimator in the Inno installer: `AI-Prowler-Setup.iss` gained a 228-entry [Files] block covering the whole `estimator\` payload (code, trade data, web app), in the file's house style after the HR apps block, so a setup install ships the Estimator instead of relying on the dev install script. Drift guard `tests/estimator/unit/test_installer_estimator_block.py` (S26-I01..I03: every payload file is in the installer, no stale or duplicate entries, DestDir mirrors the folder). Found, not fixed: the .iss already listed `COMPLETE_USER_GUIDE.md` twice before this sprint. Roles sign-off recorded (David's Roles row above and the Spec change log): estimating is a scope on owner/manager/staff accounts, never field crew; scope holders sign in as Estimator and can change and approve; field crew view only; no code change needed - `estimator/api/prowler_link.py` already implements it. All Estimator tests 1297 passed. Test plan: `tests/estimator/SPRINT_26_CODER1_TEST_PLAN.md` |
| 2026-11-09 | Sprint 27 (Coder 1 part of planned Sprint 18, Phase 8) | Coder 1 (Jamie) | Done | release_gate.bat updated for the Estimator (the planned Sprint 18 Tester 1 item): Suite 5 now calls `run_tests_estimator.bat`, the unified Coder 1 + Coder 2 runner, instead of `run_tests_estimate.bat`, the older pre-unification runner, and the advertised Estimator count was corrected from ~630 to ~1,300 tests. Guard tests `tests/estimator/unit/test_release_gate_estimator_step.py` (S27-G01..G03) pin the gate to the unified runner. All Estimator tests 1300 passed. Test plan: `tests/estimator/SPRINT_27_CODER1_TEST_PLAN.md` |
| 2026-11-09 | Sprint 28 (Coder 1 part of planned Sprint 18, Phase 8) | Coder 1 (Jamie) | Done | The rest of the planned Sprint 18 tab/wizard work: the setup wizard gained its Spec step 8, `team_approvals` (Team and approvals) — who can estimate, review, approve and send comes from the AI-Prowler users, roles and the Estimating scope (the Sprint 26 sign-off), and the step applies the review and quick-send thresholds to the Director settings; the wizard now has the Spec's 10 steps. The Estimator tab gained the Spec's CAD and tools section (DXF/ezdxf, ODA DWG converter and Tesseract OCR status from `model.tool_status()`), and Phone and web app now shows the real web app address and sign-in rules instead of the stale 'coming next' note. Older tests that pinned the 9-step wizard / 9-section tab were updated. All Estimator tests 1306 passed. Test plan: `tests/estimator/SPRINT_28_CODER1_TEST_PLAN.md` |
| 2026-11-09 | Sprint 29 (Coder 1) | Coder 1 (Jamie) | Done | The Estimator chapter of the Complete User Guide (the Spec's Phase 8 list; the guide chapters every phase gate requires): COMPLETE_USER_GUIDE.md gained chapter 29, 'Estimator — Estimates, Takeoffs and Bids', plus its table-of-contents entry — before this the shipped guide never mentioned the Estimator at all. The chapter covers the tab and its sections, the 10-step setup wizard, the practice project, chat estimating, takeoffs and the Runner, approvals and the roles/Estimating-scope rules, the web app, CAD and tools, and troubleshooting. The tab's Help section gained an 'Open the User Guide' button (the Spec's Help row). Guard tests S29-G01..G04 in `tests/estimator/unit/test_user_guide_estimator_chapter.py`. All Estimator tests 1310 passed. Test plan: `tests/estimator/SPRINT_29_CODER1_TEST_PLAN.md` |
| 2026-11-09 | Sprint 30 (Coder 1) | Coder 1 (Jamie) | Done | The Design Spec's 'Build status by coder' section brought current (it was a Nov 7 snapshot): a code audit verified the blocks it still showed as not started are built - takeoff_* tools and takeoff_propose, review_* with second check, plan_compare_revisions, plan_processing_queue / plan_publish_to_server, drawing-model crops, 42 plan_* identifiers - so Coder 1's chart blocks A3, A4, A7, A10, A11, A13 are now done (14 of 14), Coder 2's B0-B11 are done per his Sprints 1-14 code-done in this log (B12 tours/help stays todo), the score line and phase table were refreshed (108 MCP tools, 1,310-test suite before this sprint), and the Phase 2/4 gate notes now say the accuracy evidence runs are still to do. No phase gate was marked passed - the gate checklist below stays unchecked; the gates' spec review, version bump, Word copy and evidence/pilot runs are still outstanding. Also verified: the installer's two COMPLETE_USER_GUIDE.md entries install to different destinations ({app} and Documents\AI-Prowler) - not a duplicate, left as is. Guard tests S30-G01..G06 in `tests/estimator/unit/test_spec_build_status.py`. All Estimator tests 1316 passed. Test plan: `tests/estimator/SPRINT_30_CODER1_TEST_PLAN.md` |
| 2026-11-09 | Sprint 31 (Coder 1) | Coder 1 (Jamie) | Done | Spec MCP tool catalog reconciled with the registry: 28 registered tools were missing from the catalog (agent budget/roles, the est_agent_* family, Director inbox/watch, data export/import, plan crops, Runner review/submit and more) and the intro still said 'About 45'; all 108 registered tools are now catalogued with Purpose and Writes? and drift guards S31-G01..G03 fail the suite if the catalog and the TOOLS registry diverge again. Suite 1,367 passed / 14 skipped on estimator. |
| 2026-11-09 | Sprint 16 (Coder 2) | Coder 2 (David) / Tester 2 | Code done; manual checks M1-M8 open | Scans and photos, and DWG. Scans and photos go through a raster pipeline (numpy/scipy): phone photos of a sheet are squared up to the page's edges, blueprints are inverted, tilted scans are straightened (the saved sheet image and OCR words too), and horizontal and vertical line work is traced, so walls, named rooms, elevations and site objects are found on scans. Everything from a scan or photo is raster, confidence 0.5 at most and "needs review" all the way through: sheet notes, the building model and every trade's answers (method, needs_review), a Needs review badge on Plan quantities, and measurements proposed as method raster with an ask to check each one; nothing is approved automatically. DWG is converted to DXF by the ODA File Converter or LibreDWG when the user installed one (detected on the PATH, in Program Files\ODA or from ESTIMATOR_DWG_CONVERTER), with guidance when none is. Changes in Coder 1 files (recorded in the spec): from_plans measurement method and confidence, the DWG upload warning only without a converter, the tab's DWG line uses the same search, and the installer lists the two new files. No new tables or tools. Merged with Jamie's Sprint 30: the spec's build-status chart shows B11 in progress, and his S30-G03 test expects that. All Estimator tests 1393 pass after the merge (29 new), browser track 14. Scans read before this sprint need reading again. Test plan: `tests/estimator/SPRINT_16_CODER2_TEST_PLAN.md` |
| 2026-11-09 | Sprint 17 (Coder 2) | Coder 2 (David) / Tester 2 | Code done; manual checks M1-M8 open | Revision overlay UI; Reports, Settings and full Price Book screens. The revision overlay lives on the Reports screen (red removed, green added, orange changed or moved; unchanged measurements carry over, the rest are flagged to re-measure with a deep link into Blueprint Review). Reports screen: summary, takeoff by trade, actuals (see_margins), CSV/XLSX export, revisions list and detail (reports_api.py). Settings screen: 8 sections, owner-only, ask-first writes with old to new confirmation (settings_api.py). Full Price Book: per-row price history, markups and tax card, paste-CSV supplier import with column-mapping preview. Router and nav role gates; four how-to guides (use_reports, change_your_settings, compare_plan_revisions, set_up_your_price_book). New files in the installer. Tests: test_web_sprint17.py (32 functions, 35 cases); all Estimator tests 1428 pass, browser track 14. Test plan: tests/estimator/SPRINT_17_CODER2_TEST_PLAN.md. Open: cloud/delta revision marks are counted, not drawn; import is paste-only (no file upload). |
| 2026-11-09 | Sprint 18 (Coder 2) | Coder 2 (David) / Tester 2 | Code done; manual checks M1-M8 open | Guided tours for every screen (tour.js, 27 tours incl. practice-project and phone tours, first-open auto-start, per-user progress in help_progress via tours_api.py); help panel slide-over from every "?" (guides for the screen + Replay tour); "?" added to dashboard, projects and project page; two new guides (use_the_dashboard, manage_your_projects); empty states with next steps on takeoffs, agents, estimates, estimate, symbol review, reports takeoff/revision, project, price book, plan set and sheet. New files in the installer. Tests: 25 new cases in test_web_sprint18.py + SPRINT_18_CODER2_TEST_PLAN.md (router wiring bug found by the tests — tours delegation was nested dead code — fixed); suite 1456 pass, 14 skipped, 0 failed (log estimator_all_20261109_195119.log). Open: manual checks M1-M8 (now Sprints 10-18) still open; a tour step whose control is not on the screen is skipped. |
| 2026-11-09 | Sprint 15 (Coder 2) | Coder 2 (David) / Tester 2 | Code done; manual checks M1-M8 open | Site-plan zones for fencing and landscaping: on site, landscape, planting and irrigation plans, lawn, artificial turf, rock, mulch, pavers and planting beds are measured from the note inside each area (or its leader), with hatching ignored and the house left out of the lawn; existing areas aren't counted. Fence lines are followed from their notes through dashes and corners (marked to check), with material and height from the note and old fences to remove; walk and drive gates. CAD: zone layers and hatches, fence layers, GATE blocks. Plant schedules give trees and shrubs; landscape symbol library v4 (trees, palms, shrubs, drip and zone valves). Fencing and landscaping answers from the plans (12 plan trades), counted once when a site plan and a landscape plan show the same yard; Jamie's from-plans measurements work for both with no change on his side. Plan quantities: Site and landscape section, Fencing and Landscaping cards. Changes in Coder 1 files: "plant" schedule type in the drawing model; the two new files in the installer. No new tables or tools. All Estimator tests 1354 pass (48 new), browser track 14. Plan sets read before this sprint need reading again. Test plan: `tests/estimator/SPRINT_15_CODER2_TEST_PLAN.md` |

**Gate checklist** (each gate also requires the spec review, version bump and regenerated Word copy, plus that phase's User Guide chapters written and followed successfully)

- [ ] G0 Foundations (week 2) — spec v1.0 baseline
- [ ] Phase 1 — service estimates (week 8) — spec v2.0
- [ ] Phase 2 — plan engine MVP (week 14) — spec v3.0
- [ ] Phase 3 — first trades (week 16) — spec v4.0
- [ ] Phase 4 — legends, symbols, agents, reviews (week 22) — spec v5.0
- [ ] Phase 5 — core 8 trades (week 26) — spec v6.0
- [ ] Phase 6 — expansion trades and services (week 30) — spec v7.0
- [ ] Phase 7 — scans, CAD, revisions, polish (week 34) — spec v8.0
- [ ] Phase 8 — release (week 40) — spec v9.0 (released)
