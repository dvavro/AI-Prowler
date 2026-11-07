# Sprint 19 — Coder 1 (Jamie) test plan

**Scope:** The Personal → Server data move from planned Sprint 17. It packs up a company's Estimator data and loads it into AI-Prowler Server or another PC (`est_data_export`, `est_data_import`), with buttons on the Estimator tab. (Planned Sprint 19 is the beta; this sprint number just continues the Coder 1 sequence.)

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimate.bat
deploy_to_install.bat
```
No database change (still version 10). There are 64 Estimator tools (2 new).

## What was built

**Export** (`estimator/data_move.py`, `est_data_export`, owner only). It writes one .zip to the Estimator's exports folder with three parts:
- `manifest.json`: format, database version, company name, who made it and when, row counts
- `data.json`: every row of the company's estimating data
- `files/<bid>/…`: the quote HTML and PDF files

The data covers the company profile, setup progress, markups, Director settings, playbook overrides, agent settings and budget, price book, estimates (with revisions), trades, lines, history log, options, job costs, Director jobs and steps, quotes, and takeoff runs and tasks.

Left out on purpose: the inbox, watcher runs, the agent task queue and agent spend (they belong to the PC that made them). Practice estimates are left out unless `include_practice=true`.

**Import** (`est_data_import`, owner only). It loads into the company of whoever runs it, for example an AI-Prowler Server company.
- Every row gets a new number, and every link is rewired: lines to trades to estimates, revision chains, job costs to their line, Director steps, takeoff tasks to runs. Nothing on the receiving side is overwritten.
- Quote numbers stay as customers saw them, and quote files are copied into the new data folder.
- If the receiving company has no estimates yet, its settings and profile are replaced by the file's. A company that already has estimates keeps its own settings, prices and profile; the file's are added only where it has none.
- It always previews first: counts, where the file came from, what happens to the settings. Nothing changes without `confirm=true`.
- Safety:
  - Refused: a file from a newer Estimator, unknown tables, and anything that isn't an Estimator data .zip.
  - Size limits: 200 MB for the file, 100 MB for its data.
  - Only `files/<number>/<name>.html|pdf` entries are read, so nothing is written outside the data folder.
  - An inconsistent file fails before anything is saved.

**Estimator tab** (💾 Data and backups): 📤 Pack up my data to move, and 📥 Load a data file… (choose the .zip, read the preview, say yes). There's also one more example prompt.

## Test cases

| ID | Test | Expected |
|---|---|---|
| S19-D01 | Export | Manifest (format, company name, v10+, no practice); 3 estimates, 1 quote, 2 job costs, 1 Director job, prices, profile; quote files in the zip; with practice: 4 estimates |
| S19-D02 | Move to a server company | Preview first ("replaced"); 3 estimates in company "acme"; same title, status, total and lines; revision points at the moved original; quote number kept and its file copied into the new data folder; job costs still point at the moved line; price, profile, Director job moved; no practice estimates; nothing left under the old company id |
| S19-D03 | Into a busy company | Preview says settings are kept; Acme's profile and its $120 price stay; Acme's own estimate is untouched; 4 estimates afterwards |
| S19-D04 | Safety | Non-owners can't export or import; a missing file, a newer database, unknown tables and a non-Estimator zip are refused; a `../../outside.html` entry is never written |
| S19-D05 | Failed import | A line pointing at a missing trade fails as "inconsistent", and nothing at all is saved |
| S19-T01 | MCP tools | Export, then import on "another PC" (needs confirmation, then loads 3 estimates) |
| S19-U01 | Tab buttons | Pack up → path in the message; Load preview in words ("From Vavro Roofing … 3 estimate(s) … replaced"); load; a missing file gives a message |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 615 passed, 1 skipped (the GUI test file, no tkinter) |
| Linux, Python 3.12 under a virtual screen (Xvfb) | GUI tests 8 passed, 1 skipped |
| Windows 11, Python 3.11.8 (Jamie's PC) | 630 passed, 0 failed (run with Sprints 18, 19 and 20 together, 2026-11-07) |
| File check | All 20 changed files match the tested copies (zip SHA-256 checked on the PC) |

## Manual check after deploying

1. Estimator tab → 💾 → 📤 Pack up my data to move. A .zip appears in `%USERPROFILE%\AI-Prowler\Estimator\exports`.
2. On a second AI-Prowler (or the server box, as its owner): 📥 Load a data file…, choose the .zip, read the preview, say yes. The estimates and quotes are there, and quote PDFs open.

## Self-review checklist

- [x] Owner only, preview before confirm, one transaction (all or nothing)
- [x] Nothing on the receiving side is overwritten; a busy company keeps its own settings and prices
- [x] Zip entries are whitelisted; no writes outside the data folder; newer databases refused
- [ ] Server side: run it on the server box once AI-Prowler Server sign-in gives each company its own owner (David's half)
