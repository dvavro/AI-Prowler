# Sprint 16 — Coder 1 (Jamie) test plan

**Scope:** The Estimator's desktop screens, pulled forward from planned Sprint 18 (Jamie's choice, "Split it": Coder 1 builds the desktop 🏗 Estimator tab with its settings and the Setup AI-Prowler step now; Coder 2 (David) builds the phone Estimates tab and the Estimator web app alongside the Plan Engine). It covers three things:
- the **🏗 Estimator tab** in AI-Prowler's desktop GUI
- the **Estimator choice and step** in Setup AI-Prowler
- the **on/off switch** that stops the Estimator's tools and background checks

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_wizard_tests.py
deploy_to_install.bat
```
Then start AI-Prowler again. There's no database change (still version 8), and there are still 55 Estimator tools.

## What was built

**🏗 Estimator tab** (`estimator/ui/gui_tab.py`). rag_gui.py adds it after the Learnings tab with a few lines, so the fixed tab numbers don't move. If anything in it fails, the GUI still starts. It has these sections:

| Section | What's in it |
|---|---|
| 🧭 Estimator setup | On/off switch; a line on what's installed (trades, services, tools, estimates, database version and size, whether background checks are running); the 9-step setup checklist with Set up / Done / Skip; a sample-prices warning |
| 🏢 Company and pricing | Name, phone, address, license number, sales tax %, overhead %, profit % and minimum charge. You type percentages as plain numbers (8.6); they're stored as fractions (0.086), as the pricing engine expects |
| 🏗 Trades | A checkbox for each of the 15 construction trades (Agent Manager "enabled") |
| 🤖 AI agents and budget | Whether the Claude and Grok keys are saved, with a button to 🔑 Agent API Key on the Small Business tab; each role's provider, model and backup; the daily and monthly budget; spend today and this month |
| 🧑‍💼 Director | Review limit, quick-send limit, follow-up days, review reminder days, briefing on/off, briefing time, channel and email, background checks, quote expiry |
| 💾 Data and backups | Where estimator.db is kept, Back up now, Open the folder, recent backups |
| 📱 Phone and web app | Says the Estimates tab and the web app are coming (David's track) and that everything works from chat until then |
| ❓ Help | Example prompts |

Logic and drawing are kept apart. `estimator/ui/model.py` holds the logic and has no tkinter. Every save runs as the owner through the same service layer the AI tools use, and returns (ok, message), so a bad value shows as a red line and never as a crash. While the Estimator is off, every section except setup folds to "(not enabled)". It uses AI-Prowler's own `gate_section`, so nothing typed or saved is lost.

**Setup AI-Prowler** (small additions to David's `setup_wizard.py`):
- "📐 Estimate and bid jobs (construction trades, service quotes)" in Change my choices. It's a real switch (`FEATURE_SERVICES`), like analyses, email and phone: unticking it turns the Estimator off after a restart.
- An "Estimator (estimates and bids)" step, which goes to the 🏗 Estimator tab and scrolls to "🧭 Estimator setup".
- Its light goes green when the company basics and markups are saved (`detect_estimator`).
- A guided window (`estimator/ui/setup_flow.py`) takes the company name, phone, tax, overhead, profit and minimum charge. It turns the Estimator on if it was off, saves, and marks the step done. It also has Skip for now.

**The switch** (`tool_config_store.feature_on("estimator")`; no entry means on, like the other features). When it's off, `est_tools.register` adds no tools and doesn't start the watcher. The data and settings are untouched.

## Test cases

| ID | Test | Expected |
|---|---|---|
| S16-M01 | Switch | On by default; off and on again; messages say restart, and that data is kept |
| S16-M02 | Overview | 15 trades, 8 services, 55 tools, database v8, 9 setup steps, no module errors |
| S16-M03 | Company basics | Saved with tax 8.6 → 0.086 shown back as 8.6, profit "15%" → 15, minimum "$150" → 150.00; Setup light green; off → no light |
| S16-M04 | Bad basics | No name, "abc" tax, 150% profit: each refused with a plain message |
| S16-M05 | Steps, trades, agents, Director | Skip a step; turn roofing off; reviewer to chat only; budget $1.50/$10 (daily over monthly and "lots" refused); follow-up 7 days (0 refused) |
| S16-M06 | Back up now | A backup file is made and listed |
| S16-G01 | Tab | Added as "🏗 Estimator" with all 8 sections; "🧭 Estimator setup" there for Setup to scroll to; ON; checklist 0 of 9; 15 trades ticked |
| S16-G02 | Company form | Save button stores it; the Setup light goes green; the checklist moves on |
| S16-G03 | Switch button | Off: OFF label, no checklist, switch written; on again |
| S16-G04 | Trade checkbox | Unticking Fencing turns the fencing trade off |
| S16-G05 | Never breaks the GUI | An error building the tab is printed and the tab is left out |
| S16-G06 | Setup window | Turns the Estimator on, saves the basics, marks the step done (real setup_wizard on the PC) |
| S16-G07 | Setup window errors | A missing name shows the message; the step isn't marked |
| S16-G08 | Tools follow the switch | Off → `register` adds no tools |
| S16-G09 | Setup knows the Estimator | In the choices and the switches; step on the 🏗 Estimator tab with its light and guided window; scroll marker; needs nothing else |
| David's tests | Setup and switches | `tests/test_setup_wizard.py`, `tests/unit/test_setup_choices_are_switches.py`, `tests/unit/test_desk_wizard.py`, `tests/unit/test_group_switch_one_truth.py`, `tests/gui/test_setup_choices_on_screen.py`, `tests/gui/test_setup_goes_to_the_right_place.py` (it checks that every step, now including the Estimator, opens its tab with its section in view) |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 (no tkinter) | 571 passed, 1 skipped (the GUI test file) |
| Linux, Python 3.12 under a virtual screen (Xvfb) | Sprint 16 GUI tests: 8 passed, 1 skipped (G09 needs AI-Prowler's setup_wizard) |
| Windows 11, Python 3.11.8 (Jamie's PC) | 580 passed in 32 s (2026-11-07), including all 9 GUI tests against the real setup_wizard |
| David's Setup and switch tests (PC) | 294 passed in 3 min 12 s |
| AI-Prowler's whole GUI suite, tests/gui (PC, with the new tab) | 793 passed, 15 skipped (Playwright not installed, unrelated) in 17 min 34 s |
| File check | All Estimator files on the PC match the tested copy |

## Manual check after deploying

1. Run `deploy_to_install.bat`, then start AI-Prowler again. A 🏗 Estimator tab appears after 🧠 Learnings.
2. Fill in Company and pricing and press Save. The checklist moves on.
3. Open Home → Setup AI-Prowler → Change my choices. "📐 Estimate and bid jobs" is there. Tick it and the Estimator step appears; its window saves the basics, and the light is green.
4. Untick it, then restart. The Estimator tab folds to "(not enabled)" and your AI no longer lists the est_ tools. Tick it again and restart: everything is back as it was.

## Self-review checklist

- [x] rag_gui.py gets a few guarded lines only; a problem in the tab never stops the GUI
- [x] setup_wizard.py changes are additive (one choice, one step, one marker, one guided window, one detect)
- [x] Off loses nothing: sections fold, tools aren't registered, data untouched
- [x] Every save goes through the service layer as the owner; bad values give a message, not a crash
- [ ] Coder 2: phone Estimates tab and web app (the 📱 section links to them when they land)
