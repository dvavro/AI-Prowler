# Sprint 18 — Coder 1 (Jamie) test plan

**Scope:** The Coder 1 work from planned Sprints 17 and 18 that doesn't need the Plan Engine or AI-Prowler Server's sign-in:
- **Assignments and "my work"**: who's working on what, with personal notices
- the **"someone else is editing" warning**
- the **practice project** (`est_sample_project`)
- the tab's **📦 Modules** section and a **practice project button**

Server mode still needs AI-Prowler Server's signed-in users. Until then everything runs as the one Personal-mode user, but assignments, notices and warnings already work per user.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimate.bat
deploy_to_install.bat
```
Then start AI-Prowler again. The database upgrades itself to version 10. There are 62 Estimator tools (3 new).

## What was built

**Assignments** (`estimator/team.py`)
- `est_assign(user_id, estimate_id | job_id, note)` assigns an estimate and its Director job together (an empty user_id clears it). The person gets an "assigned" notice that only they see in their inbox. Owner, estimator or office can assign.
- `est_my_work(user_id)` lists my open estimates, Director jobs and new notices. The owner or office can look at someone else's.
- Notices can now be for one person (database v10: `director_notices.for_user`). Company-wide notices still go to everyone.

**"Someone else is editing"**: `est_get_estimate` adds `editing_warning` when another person changed the estimate in the last 10 minutes ("maria changed this estimate 5 minutes ago..."). The `rev` check still refuses an overwrite.

**Practice project** (`estimator/practice.py`)
- `est_sample_project("create")` makes "Practice: Garcia house": a roof replacement plus a driveway and siding wash, priced from your price book. It ticks "Try a sample quote" in the setup checklist. There's only one at a time.
- Practice estimates are marked (database v10: `estimates.is_practice`) and stay out of the history comparisons and "my work".
- `est_sample_project("delete", confirm=true)` removes the practice estimate and everything made from it (bids, Director jobs, recorded costs, agent tasks, takeoff runs). Real work is never touched.

**Estimator tab**: a 📦 Modules section (all 23 modules with kind, how they're priced and version), a 🎓 practice project button in the setup section (it asks before deleting), and one more example prompt.

## Test cases

| ID | Test | Expected |
|---|---|---|
| S18-W01 | Assign with a note | Assigned; it's in maria's work; her notice says "assigned to you by owner" with the note; only maria's inbox and unread count show it |
| S18-W02 | Assign by Director job | The office assigns the job; the job and its estimate both get maria; clearing removes it from her work |
| S18-W03 | Rules | Field role refused; odd user names refused; nothing to assign refused; unknown job not found; assigning to yourself sends no notice; an estimator can't look at someone else's work, the office can |
| S18-W04 | Editing warning | Shown to others right after maria's change, never to maria; gone after 30 minutes; "5 minutes ago" wording |
| S18-P01 | Practice project | Made with roofing and pressure washing, marked practice, only one; "Try a sample quote" ticked; marked in the estimate list |
| S18-P02 | Stays out | Practice costs aren't in the history; a practice estimate assigned to maria isn't in her work |
| S18-P03 | Delete | Confirm needed; the bid and recorded costs are removed; the real estimate stays; a second delete finds nothing; field role and unknown actions refused |
| S18-M01 | Tab logic | 23 modules in 2 kinds, roofing "quick or plans"; the practice button makes and deletes it |
| S18-T01 | MCP tools | `est_sample_project` create, then delete (needs confirmation); `est_assign`; `est_my_work` |
| S16-G01 (updated) | Tab | 9 sections now, with modules |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 608 passed, 1 skipped (the GUI test file, no tkinter) |
| Linux, Python 3.12 under a virtual screen (Xvfb) | GUI tests 8 passed, 1 skipped (needs AI-Prowler's setup_wizard) |
| Windows 11, Python 3.11.8 (Jamie's PC) | 630 passed, 0 failed (run with Sprints 18, 19 and 20 together, 2026-11-07) |
| File check | All 20 changed files match the tested copies (zip SHA-256 checked on the PC) |

## Manual check after deploying

1. On the 🏗 Estimator tab, press 🎓 Make a practice project. In chat: "show me the practice estimate", then approve it and "preview the bid".
2. "Assign the practice estimate to maria". "What's my work?" for owner shows nothing. "What's maria's work?" shows it.
3. Press 🗑 Delete the practice project and say yes. Your other estimates are still there.

## Self-review checklist

- [x] Assignments and notices are company-scoped; personal notices are seen only by that person
- [x] The editing warning never blocks; the rev check still stops overwrites
- [x] Practice data never mixes into history or "my work", and deleting it never touches real work
- [ ] Later: Server sign-in for real users (AI-Prowler Server), the team-and-approvals wizard, installer and release files (with David)
