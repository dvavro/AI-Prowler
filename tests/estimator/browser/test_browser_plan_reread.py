"""Project page, Upload plans: read a plan set again from the project's own copy of the file (2026-11-20, David:
"when I select it in the drop down box have a button to reread it so the user does not have to choose a file and
dir again").

    browser_upload.bat tests\\estimator\\browser\\test_browser_plan_reread.py
"""
import time

from test_browser_count_highlight import cad_job  # noqa: F401 - fixture


def _plan_set(db, estimate_id):
    return db.execute("SELECT id, status, processed_at FROM plan_sets WHERE estimate_id = ?", (estimate_id,)).fetchone()


def test_read_the_same_plans_again_without_a_file(page, db, cad_job):  # noqa: F811
    est = cad_job["estimate_id"]
    ps = _plan_set(db, est)
    before = ps["processed_at"]
    page.goto(page.base + f"#/projects/{est}")
    page.wait_for_selector("#upload-box")
    assert page.is_hidden("#plan-reread")                       # "New plan set": nothing to read again
    # Picking the plan set shows the Read again button.
    page.select_option("#plan-replaces", str(ps["id"]))
    assert page.is_visible("#plan-reread") and "again (same file)" in page.inner_text("#plan-reread")
    # The page redraws on live updates; what was picked stays picked.
    page.evaluate("() => route()")
    page.wait_for_selector("#plan-reread:not([hidden])")
    assert page.input_value("#plan-replaces") == str(ps["id"])
    # Read again: it asks first (reading replaces what was read), then reads the saved file - no file chosen.
    time.sleep(1.1)                                              # processed_at is to the second
    page.click("#plan-reread")
    page.wait_for_selector("#plan-reread-confirm")
    # The question names it by the project's number (#1, as the table shows), never the global id.
    question = page.inner_text("#plan-reread-confirm-box")
    assert "Plan set #1 (house.dxf)" in question, question
    page.click("#plan-reread-confirm")
    deadline = time.time() + 60
    while time.time() < deadline:
        now = _plan_set(db, est)
        if now["status"] == "processed" and now["processed_at"] != before:
            break
        time.sleep(0.5)
    now = _plan_set(db, est)
    assert now["status"] == "processed" and now["processed_at"] != before
    # Back to "New plan set": the button goes.
    page.goto(page.base + f"#/projects/{est}")
    page.wait_for_selector("#upload-box")
    page.select_option("#plan-replaces", "")
    assert page.is_hidden("#plan-reread")
