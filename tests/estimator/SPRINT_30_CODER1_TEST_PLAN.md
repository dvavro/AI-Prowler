# Sprint 30 (Coder 1) — Test Plan

**Scope:** bring the Design Spec's "Build status by coder" section current.
It was a Nov 7, 2026 snapshot; Coder 1 Sprints 21–29 and Coder 2 Sprints
1–14 have landed since, but the section still showed built work as in
progress or not started — including blocks this month's code audit verified
in the tree (`takeoff_*` tools and `takeoff_propose`, `review_*` with
second check, `plan_compare_revisions`, `plan_processing_queue`,
`plan_publish_to_server`, drawing-model crops, 42 `plan_*` identifiers).

## Changes under test

- Section date Nov 7 → Nov 9, 2026.
- Coder 1 chart blocks A3, A4, A7, A10, A11, A13 flipped to done (A10's
  label updated: Server sign-in is in). Coder 1 is 14 of 14 done.
- Coder 2 chart blocks B0–B10 flipped to done per the Plan progress log
  (Sprints 1–15 code-done, merged, covered by the shared suite); B11
  (scans, DWG, revision overlay, Reports/Settings) and B12 (guided
  tours / help panel) stay todo — his Sprints 16–18 work. An earlier
  draft of this sprint had B11 as done; the merge with Coder 2
  Sprint 15 (site-plan zones) corrected that against his own chart.
- Connection diagram classes: DM/TK and ENG/WEB/BR done.
- Score line rewritten: Coder 1 14 of 14; Coder 2 11 of 13 with his
  Sprint 16 next and M-series manual checks open; 108 MCP tools;
  unified-suite test count as of the post-merge run.
- Phase table rows 0–8: stale "not merged / not started" claims replaced
  with the built state; Phase 2/4 gate notes now say the accuracy
  evidence runs are still to do.

## Deliberately NOT changed

- The Plan's gate checklist (G0, Phases 1–8) stays unchecked, and no gate
  is claimed passed: the gates also require the spec review, version
  bump, regenerated Word copy, and evidence runs (seeded plan accuracy,
  pilot jobs) that are still outstanding.
- `AI-Prowler-Setup.iss`: the two `COMPLETE_USER_GUIDE.md` entries found
  in Sprint 26 install to different destinations (`{app}` and
  Documents\AI-Prowler) — verified this sprint; not a duplicate, left
  as is.

## Tests

`tests/estimator/unit/test_spec_build_status.py`:

- S30-G01 — status section is dated Nov 9, 2026; the Nov 7 date is gone.
- S30-G02 — every Coder 1 chart block A0–A13 is `:::done`.
- S30-G03 — Coder 2 blocks B0–B10 are `:::done`; B11 and B12 are still
  `:::todo`.
- S30-G04 — the score line states 14 of 14 and 11 of 13.
- S30-G05 — the stale "not started / not merged / 630 tests" claims no
  longer appear anywhere in the Spec.
- S30-G06 — all nine Plan gate boxes remain unchecked; none was marked
  passed by this sprint.

## Verification

- Targeted: `test_spec_build_status.py` — all pass.
- Full Estimator suite — no regressions. Pre-merge: 1,316 passed
  (1,310 + 6 new), 14 skipped. The branch was then merged with
  Coder 2 Sprint 15 (his site-plan zones; conflicts in this section
  and the two progress logs, resolved keeping both sides) and the
  suite re-run post-merge before pushing.
