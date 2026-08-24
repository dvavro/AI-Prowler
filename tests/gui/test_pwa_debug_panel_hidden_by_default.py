"""
tests/gui/test_pwa_debug_panel_hidden_by_default.py
======================================================
RETIRED — the Jobs-screen debug panel (jobsDebugPanel, jobsDebugToggle,
toggleJobsDebug/clearJobsDebug/logJobsDebug) this file tested for was
intentionally removed from jobs/index.html once the feature had served
its purpose. See git history / session notes for the removal.

Original context (kept for history): this file started as a regression
guard for a real incident — a global developer debug panel that shipped
with `display:block` hardcoded instead of `display:none`, covering the
login screen. That panel was redesigned (moved into the Jobs screen,
real toggle button, wired into loadJobs() logging) and later removed
entirely by product decision. No replacement debug panel exists; there
is nothing left for this file to guard.

Full previous test content is preserved in test_pwa_debug_panel_hidden_by_default.py.bak6
alongside this file, in case a future debug panel needs equivalent
regression coverage.
"""
