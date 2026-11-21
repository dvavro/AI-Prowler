"""Measure screen: 🧹 Audit & clean up (2026-11-20, David: "an AI Cleanup run that fixes and removes double counted
items and 'from before the plans were read again' issues ... a way to remove [rejected items] ... make sure the user can
mass accept all of the changes; you may need a popup window ... that the user can work with").

    browser_upload.bat tests\\estimator\\browser\\test_browser_audit.py
"""
import json

import pytest

from test_browser_count_highlight import CTX, cad_job, sel  # noqa: F401 - cad_job is a fixture


def _m(db, est, sheet, feeds, qty, status, reason=None):
    mid = db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label, qty,"
        " unit, source_object_ids, calc_json, method, status, locked, reject_reason, proposed_by, created_at, updated_at)"
        " VALUES (?, ?, 'electrical', ?, ?, NULL, 'count', ?, ?, 'ea', '[]', ?, 'ai', ?, ?, ?, 'llm-takeoff',"
        " '2026-11-20T00:00:00+00:00', '2026-11-20T00:00:00+00:00')",
        (CTX.company_id, est, feeds, sheet, f"{feeds} (AI)", str(qty), json.dumps({"source": "llm", "how": "x"}),
         status, 1 if status == "approved" else 0, reason)).lastrowid
    db.commit()
    return mid


@pytest.fixture
def messy(db, cad_job):  # noqa: F811
    est = cad_job["estimate_id"]
    sheet = db.execute("SELECT s.id FROM sheets s JOIN plan_sets p ON p.id = s.plan_set_id WHERE p.estimate_id = ?",
                       (est,)).fetchone()[0]
    return {"estimate_id": est,
            "old_fans": _m(db, est, None, "fans", 4, "approved"),          # from before the plans were read again
            "new_fans": _m(db, est, sheet, "fans", 3, "approved"),         # ... and approved again: priced twice
            "switches": _m(db, est, sheet, "switches", 1, "proposed"),     # the drawing shows 2
            "rejected": _m(db, est, sheet, "dimmers", 1, "rejected", "the plans were read again")}


def _status(db, mid):
    r = db.execute("SELECT status, qty FROM measurements WHERE id = ?", (mid,)).fetchone()
    return None if r is None else (r["status"], float(r["qty"]))


def test_audit_panel_finds_shows_and_fixes_everything(page, db, messy):
    page.goto(page.base + f"#/takeoffs/{messy['estimate_id']}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.click("#bp-audit-open")
    page.wait_for_selector("#bp-audit-list")
    text = page.inner_text("#bp-audit")
    assert "Priced twice" in text and "is priced twice" in text and "Rejected items" in text
    assert "null" not in text                         # 2026-11-20: a missing button was written as the word "null"
    assert "Approve 2 ea (the drawing's number; the AI said 1)" in text
    # The panel sits beside the drawing: "Show on drawing" lights up the switches while it stays open.
    page.locator(f"#bp-audit [data-fid='waiting:{messy['switches']}'] .bp-audit-show").click()
    page.wait_for_function("() => document.querySelectorAll('#bp-viewer [data-oid].sel').length === 2")
    assert page.is_visible("#bp-audit")
    # Everything ticked to start with (CAD drawing): one click applies it all.
    assert page.inner_text("#bp-audit-apply").startswith("✓ Apply 3 fix")
    page.click("#bp-audit-apply")
    page.wait_for_selector("#bp-audit-done, #bp-audit-summary:has-text('Nothing to clean up')", timeout=20000)
    assert _status(db, messy["new_fans"]) == ("approved", 3) and _status(db, messy["old_fans"]) is None
    assert _status(db, messy["switches"]) == ("approved", 2) and _status(db, messy["rejected"]) is None
    priced = db.execute("SELECT SUM(CAST(qty AS REAL)) FROM measurements WHERE estimate_id = ? AND feeds = 'fans'"
                        " AND status = 'approved'", (messy["estimate_id"],)).fetchone()[0]
    assert priced == 3                                                    # priced once
    assert "Nothing to clean up" in page.inner_text("#bp-audit")
    page.click("#bp-audit-close")
    page.wait_for_selector("#bp-audit", state="detached")


def _priced_director_job(db, est):
    from estimator.director import engine
    from estimator.estimating import quick, service
    from estimator.modules.registry import ModuleRegistry
    reg = ModuleRegistry().load()
    quick.answer(db, CTX, est, "concrete", {"area_sqft": 400}, service.get_estimate(db, CTX, est)["rev"], reg)
    jid = engine.adopt(db, CTX, est, registry=reg)["job"]["id"]
    engine.next_step(db, CTX, jid, customer={"name": "Pat Lee", "email": "pat@example.com"}, registry=reg)
    db.commit()


def test_director_runs_the_audit_any_time_and_as_the_last_check(page, db, messy):
    """2026-11-20 (David): "allow the director to run [the audit] whenever the user decides or as a last check before
    moving from estimating"."""
    est = messy["estimate_id"]
    _priced_director_job(db, est)
    page.goto(page.base + f"#/projects/{est}")
    page.wait_for_selector("#director-audit")
    assert page.locator("#director-todo li[data-key='audit']").count() == 1
    # The last check: "the estimate is ready" stops on the count priced twice and offers Move on anyway.
    page.click("#director-ready")
    page.wait_for_selector("#director-skip-audit")
    assert "measurement audit found" in page.inner_text("body")
    # Any time: the button opens Audit & clean up on the Measure screen.
    page.click("#director-audit")
    page.wait_for_url(f"**#/takeoffs/{est}?audit=1")
    page.wait_for_selector("#bp-audit-list")
    assert "Priced twice" in page.inner_text("#bp-audit")
    page.click("#bp-audit-apply")
    page.wait_for_selector("#bp-audit-done, #bp-audit-summary:has-text('Nothing to clean up')", timeout=20000)
    # Back on the project the audit step is ticked off and the estimate moves on without being asked to skip anything.
    page.goto(page.base + f"#/projects/{est}")
    page.wait_for_selector("#director-todo li[data-key='audit']")
    page.click("#director-ready")
    page.wait_for_function("() => !document.querySelector('#director-ready')", timeout=20000)
    assert page.locator("#director-skip-audit").count() == 0


def test_move_on_anyway_skips_the_audit(page, db, messy):
    est = messy["estimate_id"]
    _priced_director_job(db, est)
    page.goto(page.base + f"#/projects/{est}")
    page.wait_for_selector("#director-ready:not([disabled])")
    page.click("#director-ready")
    page.wait_for_selector("#director-skip-audit")
    page.click("#director-skip-audit")
    page.wait_for_function("() => !document.querySelector('#director-ready')", timeout=20000)
    stage = db.execute("SELECT stage FROM director_jobs WHERE estimate_id = ?", (est,)).fetchone()[0]
    assert stage in ("review", "approve")
