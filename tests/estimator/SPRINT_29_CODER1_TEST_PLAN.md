# Sprint 29 (Coder 1) — Test Plan

**Sprint:** 29 (Coder 1: the Estimator chapter of the Complete User Guide — the Spec's Phase 8 list, and the guide chapters every phase gate requires)
**Date:** 2026-11-09

## Scope

`COMPLETE_USER_GUIDE.md` — the guide the installer ships — never mentioned the Estimator at all (verified: 0 occurrences in 3,460 lines). This sprint writes its Estimator chapter and links it from the Estimator tab. Out of scope: the guide's version/date header and the regenerated Word copy — those belong to the phase-gate pass; the Troubleshooting/FAQ/Glossary chapters are Tester 2's planned Sprint 18 work; David's in-app guide library (estimator/ui/help) already exists and is untouched.

## How to run

- Guard tests only: `run_tests_estimator.bat coder1 -k user_guide`
- Full Estimator suite: `run_tests_estimator.bat`

## What was built

- `COMPLETE_USER_GUIDE.md`: new chapter **29. Estimator — Estimates, Takeoffs and Bids**, in the guide's own style (### subsections like chapters 27–28), placed after chapter 28 and before Appendix A, plus the table-of-contents entry. It covers: what the Estimator is; turning it on; the tab's ten sections; the setup wizard's ten steps (including Team and approvals and the sample-price rule); the practice project; estimating by chat (the tab's real example prompts); plans and takeoffs (scale, measurements, symbols, Blueprint Review, revisions); the Runner and the second check; quotes, approvals and sending (review limit $500 / quick-send limit $100 defaults); who can do what (roles + the Estimating scope, per the Sprint 26 sign-off); the web app (localhost:8770, Remote Access, Server mode); CAD and tools (DXF, the free ODA File Converter for DWG, Tesseract OCR); AI agents and budget; data and backups (estimator.db, export/import); and a troubleshooting list.
- `estimator/ui/gui_tab.py`: the Help section gains a "📖 Open the User Guide (Estimator is chapter 29)" button, shown when the guide file is present next to the install — the Spec's Help row ("Open the Estimator User Guide") now has a chapter to open.

## Tests

| ID | Test | What it proves |
| --- | --- | --- |
| S29-G01 | test_s29_g01_guide_has_the_estimator_chapter | the chapter 29 heading is in the guide |
| S29-G02 | test_s29_g02_table_of_contents_lists_it | the TOC carries the chapter 29 entry |
| S29-G03 | test_s29_g03_chapter_sits_before_the_appendices | the chapter is placed before Appendix A |
| S29-G04 | test_s29_g04_chapter_covers_the_built_features | the chapter covers the wizard, Team and approvals, practice project, Blueprint Review, the Runner, the Estimating scope, localhost:8770, CAD and tools, the ODA converter and the Director |

## Results

- Guard tests: 4 passed.
- Full Estimator suite: 1310 passed, 14 skipped (run_tests_estimator.bat, 2026-11-09).

## Manual check

Open the 🏗 Estimator tab → ❓ Help → "📖 Open the User Guide" and confirm the guide opens at a build that includes chapter 29; skim the chapter once against the real tab (section names and order). Still open from Sprint 26: the Inno compile / clean-install check (Inno Setup is not installed on this PC).
