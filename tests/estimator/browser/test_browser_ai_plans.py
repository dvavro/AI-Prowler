"""Project page: ✨ AI design: describe the job (2026-11-24, David: "If the user does not have plans I want the user to be
able to use AI Design button so the user can just describe the plans and have AI Design it for him" and "We need all the
steps from the director to be a link to take me to the next page").

The Director's "No plans?" step jumps to the card; the person describes a back-yard fence, looks at the drawn site plan,
changes it in plain words and approves it - the sheet becomes the project's plans and the fence is priced from it. A fake
provider stands in for the AI; the job runs in the background like the real one and the card polls it.

    browser_upload.bat tests\\estimator\\browser\\test_browser_ai_plans.py
"""
import json
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("ezdxf")
pytest.importorskip("shapely")
from estimator.agents import providers, roles  # noqa: E402
from estimator.context import personal_context  # noqa: E402
from estimator.director import engine as director  # noqa: E402
from estimator.estimating import service  # noqa: E402
from estimator.modules.registry import ModuleRegistry  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from test_ai_design_describe import fence_job  # noqa: E402
from test_ai_design_runs import Fake  # noqa: E402

CTX = personal_context()
REG = ModuleRegistry().load()
ASK = "6 ft wood privacy fence around the back yard of a 100 x 150 lot, a walk gate and a drive gate, sod the back yard"


@pytest.fixture
def fake():
    f = Fake()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


def _fence_project(db):
    est = service.create_estimate(db, CTX, "Back yard fence", address="1 Main St")
    director.adopt(db, CTX, est["id"], registry=REG)
    director.set_project_trades(db, CTX, est["id"], ["fencing"], registry=REG)       # picked, not priced yet
    roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api"}, confirm=True)
    db.commit()
    return est["id"]


def test_no_plans_describe_draw_change_approve(page, db, fake):
    est = _fence_project(db)
    page.goto(page.base + f"#/projects/{est}")
    # the Director's step is a link that goes somewhere: the AI design card, opened
    step = page.locator("#director-todo li[data-key='design'] a")
    step.wait_for()
    assert "No plans?" in page.inner_text("#director-todo li[data-key='design']")
    step.click()
    page.wait_for_selector("#ai-plans[open] #ai-plans-form")
    assert page.locator("#ai-plans").is_visible()
    assert "nothing is priced until you approve it" in page.inner_text("#ai-plans")
    assert not page.is_checked("#ai-plans-auto")                         # approving each drawing: off unless ticked

    # describe it, with a screen clip of the yard pasted into the box (Ctrl+V) - 2026-11-25 (David: "I took a screen clip
    # of the area where I want a fence to be added, but there is no way to Ctrl V add an image")
    fake.vision = [json.dumps(fence_job())]
    page.click("#ai-plans-request")
    page.keyboard.type(ASK)
    assert "paste one into the box" in page.inner_text("#bp-design-shots-plans-start")
    page.evaluate("""async () => {
        const c = document.createElement('canvas'); c.width = 400; c.height = 300;
        const g = c.getContext('2d'); g.fillStyle = '#7c7'; g.fillRect(0, 0, 400, 300);
        g.strokeStyle = '#c00'; g.lineWidth = 6; g.strokeRect(40, 120, 320, 150);          // "the fence goes here"
        const blob = await new Promise(r => c.toBlob(r, 'image/png'));
        const dt = new DataTransfer(); dt.items.add(new File([blob], 'yard.png', { type: 'image/png' }));
        document.getElementById('ai-plans-request').dispatchEvent(
          new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
    }""")
    page.wait_for_selector("#bp-design-shots-plans-start .bp-shot img")
    assert "1 of 3" in page.inner_text("#bp-design-shots-plans-start")
    assert page.input_value("#ai-plans-request") == ASK                                     # the picture isn't pasted as text
    # 2026-11-25 (David: "the user is not notified of a plan to look at, and it would be nice if there is an AI Busy"): the
    # AI takes a few seconds here, like the real one - the card says it's busy, then opens the plan by itself
    real_vision = fake.ask_vision

    def slow_vision(*a, **k):
        time.sleep(5)
        return real_vision(*a, **k)
    fake.ask_vision = slow_vision
    page.click("#ai-plans-go")
    page.wait_for_selector("#ai-plans-working.bp-running .bp-spinner")
    busy = page.inner_text("#ai-plans-working")
    assert "AI busy" in busy and "laying out the job" in busy
    assert page.inner_text("#ai-plans-badge") == "⏳ AI busy"
    page.wait_for_function("() => /0:0[2-9]/.test(document.getElementById('ai-plans-clock').textContent)")  # it counts up
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)               # the plan opens by itself
    assert "C-101 SITE PLAN" in page.inner_text("#bp-wiring-viewer-title")
    page.keyboard.press("Escape")
    assert page.locator("#ai-plans-working").count() == 0
    assert "Plans ready" in page.inner_text("#ai-plans-badge")
    counts = page.inner_text("#ai-plans-counts")
    assert "320 ft of fence" in counts and "2 gates" in counts
    assert "1 sheet drawn" in page.inner_text("#ai-plans-sheets-say")
    kind, prompt, n = fake.calls[0]
    assert kind == "vision" and n == 1 and ASK in prompt and "PICTURES" in prompt
    fake.ask_vision = real_vision

    # 2026-11-27 (David: "when I hit the plans ready look them over button it takes me to a blank page with no drawings"):
    # the chip opens the drawing - it no longer folds the card shut
    page.click("#ai-plans-badge")
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)
    assert "C-101 SITE PLAN" in page.inner_text("#bp-wiring-viewer-title")
    page.keyboard.press("Escape")
    assert page.evaluate("document.getElementById('ai-plans').open")
    assert page.is_visible("#ai-plans-sheet-site")

    # the sheet button opens it again
    page.click("#ai-plans-sheet-site")
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)
    assert "C-101 SITE PLAN" in page.inner_text("#bp-wiring-viewer-title")
    page.keyboard.press("Escape")

    # change it in plain words
    taller = fence_job()
    taller["fences"][0]["height_ft"] = 8
    taller["changes"] = ["made the fence 8 ft"]
    fake.text = [json.dumps(taller)]
    page.fill("#ai-plans-change", "make it 8 ft tall")
    page.click("#ai-plans-change-go")
    page.wait_for_selector("#ai-plans-changes", timeout=30000)
    assert "revision 2" in page.inner_text("#ai-plans-summary")
    # 2026-11-25 (David: "lets always show the latest drawing"): it's the project's drawing on Measure at once - not approved
    assert "Revision 2 is on the Measure screen now — not approved yet" in page.inner_text("#ai-plans-on-screen")
    assert db.execute("SELECT COUNT(*) FROM plan_sets WHERE estimate_id = ?", (est,)).fetchone()[0] == 1
    # the changed plan opens by itself too
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)
    assert "revision 2" in page.inner_text("#bp-wiring-viewer-title")
    page.keyboard.press("Escape")

    # approve: asks first, then the sheet is the project's plans and the fence is priced from it
    page.click("#ai-plans-approve")
    page.wait_for_selector("#ai-plans-confirm")
    assert "C-101 SITE PLAN" in page.inner_text("#ai-plans-confirm-box")
    page.click("#ai-plans-confirm")
    page.wait_for_selector("#ai-plans-approved", timeout=30000)
    page.wait_for_function("() => document.body.innerText.includes('C-101 SITE PLAN.dxf')", timeout=30000)
    assert "Fencing" in page.inner_text("#trades")
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert float(sec["answers"]["length_lf"]) == 320.0 and str(sec["answers"]["height"]) == "8"

    # 2026-11-25 (David: on Measure, ✨ AI design "should come up as fence ... there is no fence option ... I clicked ON box
    # and nothing happens ... the design it button does not allow to be clicked"): it opens on the project's trade with the
    # plans already drawn, takes the change in plain words, and electrical can now be designed on the drawn plans
    page.goto(page.base + f"#/takeoffs/{est}")
    page.wait_for_selector("#bp-ai-design")
    page.click("#bp-ai-design")
    page.wait_for_selector("#bp-design-panel #ai-plans #ai-plans-change")
    assert page.input_value("#bp-design-mode") == "plans"
    assert "Fencing" in page.inner_text("#bp-design-mode-row")
    pool = fence_job()
    pool["fences"][0].update(material="aluminum", style="pool barrier", height_ft=4.5)
    pool["changes"] = ["wrought iron changed to black powder-coated aluminum, 4 ft 6 in high"]
    fake.text = [json.dumps(pool)]
    page.fill("#ai-plans-change", "it needs Aluminum powder coated black fence, 4' 6\" high not 4 ft")
    page.click("#ai-plans-change-go")
    page.wait_for_selector("#ai-plans-changes", timeout=30000)
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)            # the new plan opens
    page.keyboard.press("Escape")
    page.wait_for_selector("#bp-design-panel #ai-plans-changes")      # the screen showed the new drawing; the window is back
    assert "aluminum" in page.inner_text("#ai-plans-changes")
    assert "AI design revision 3" in page.inner_text("#review-sheet")  # already the drawing here, before it's approved
    page.click("#ai-plans-approve")
    page.click("#ai-plans-confirm")
    page.wait_for_selector("#ai-plans-approved", timeout=30000)
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert sec["answers"]["material"] == "aluminum" and str(sec["answers"]["height"]) == "4.5"
    lines = [ln["description"] for ln in sec["lines"]]
    assert "Aluminum fence panels (powder coated)" in lines and "Wrought iron panels" not in lines
    # 2026-11-25 (David: "when AI Design redraw the plan the window did not use the latest and there is no way to refresh
    # it"): approving reloads the Measure screen itself - the picker says the plans' revision, the drawing is the new one
    # (its tiles say which drawing they are, so the browser can't show the old one's), and 🔄 Reload is there
    # the AI design's own revision number: 1 drawn, 2 changed and approved on the project page, 3 changed and approved here
    page.wait_for_function("() => /AI design revision 3 · read/.test(document.getElementById('review-sheet').textContent)",
                           timeout=30000)
    assert page.locator("#bp-design-waiting").count() == 0                                 # approved: nothing waits
    ps = db.execute("SELECT id, processed_at FROM plan_sets WHERE estimate_id = ?", (est,)).fetchone()
    from estimator.plan_engine import tiles
    sheet_row = dict(db.execute("SELECT * FROM sheets WHERE plan_set_id = ?", (ps["id"],)).fetchone())
    v = tiles.version(sheet_row, dict(db.execute("SELECT * FROM plan_sets WHERE id = ?", (ps["id"],)).fetchone()))
    page.wait_for_selector(f"#bp-viewer img[src*='v={v}']", state="attached", timeout=30000)
    assert page.locator("#bp-design-panel #ai-plans").count() == 1                         # the window stays open
    page.click("#bp-design-x")                                                              # close the window, then reload
    page.click("#review-reload")
    page.wait_for_function("() => /AI design revision 3 · read/.test(document.getElementById('review-sheet').textContent)")
    page.wait_for_selector(f"#bp-viewer img[src*='v={v}']", state="attached", timeout=30000)
    # electrical: the drawings to design on are there now, and the button can be clicked
    page.click("#bp-ai-design")
    page.wait_for_selector("#bp-design-mode")
    page.select_option("#bp-design-mode", "electrical")
    page.wait_for_selector("#bp-design-form")
    assert "C-101 SITE PLAN" in page.inner_text("#bp-design-plans")
    page.fill("#bp-design-request", "add two GFCI receptacles by the pool equipment")
    assert page.locator("#bp-design-go").is_enabled() and page.locator("#bp-design-why").count() == 0
    # 2026-11-25 (David: "it does not count the drive double gates and inspections because they don't exist on the
    # drawing, so how do I remove them?"): To measure has "0 — none on this job" on what isn't measured yet
    page.click("#bp-design-x")
    page.click("#bp-tab-guide")
    row = "#bp-guide-fencing li[data-question='inspections']"
    page.wait_for_selector(row + " .bp-guide-none")
    assert "not yet measured" in page.inner_text(row)
    page.click(row + " .bp-guide-none")
    page.click("#bp-none-yes")
    page.wait_for_function(f"() => /approved — 0/.test(document.querySelector(\"{row}\").textContent)", timeout=30000)
    assert page.locator(row + " .bp-guide-none").count() == 0
    m = db.execute("SELECT qty, status FROM measurements WHERE estimate_id = ? AND feeds = 'inspections'", (est,)).fetchone()
    assert float(m["qty"]) == 0 and m["status"] == "approved"
    # 2026-11-25 (David: "I just reran AI Design ... when I went back to measure and hit the reload icon, it did not bring
    # up rev 4", then "lets always show the latest drawing"): a redraw is the drawing here at once, and it says it isn't
    # approved yet
    assert "AI design revision 3" in page.inner_text("#review-sheet")
    assert page.locator("#bp-design-waiting").count() == 0
    page.click("#bp-ai-design")
    page.wait_for_selector("#bp-design-mode")
    page.select_option("#bp-design-mode", "plans")
    page.wait_for_selector("#bp-design-panel #ai-plans-change")
    wider = fence_job()
    wider["fences"][0].update(material="aluminum", style="pool barrier", height_ft=5)
    wider["changes"] = ["made it 5 ft"]
    fake.text = [json.dumps(wider)]
    page.fill("#ai-plans-change", "make it 5 ft")
    page.click("#ai-plans-change-go")
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)
    page.keyboard.press("Escape")
    page.click("#bp-design-x")
    page.wait_for_selector("#bp-design-waiting", timeout=15000)
    # the new drawing is the one on the screen; it says it isn't approved yet
    said = page.inner_text("#bp-design-waiting")
    assert "This is AI design revision 4 — not approved yet" in said and "the approved one is revision 3" in said
    assert "AI design revision 4" in page.inner_text("#review-sheet")
    page.click("#review-reload")                                   # reloading shows the same: the newest drawing
    page.wait_for_selector("#bp-design-waiting")
    assert "AI design revision 4" in page.inner_text("#review-sheet")
    assert "AI design revision 4 — not approved yet" in page.inner_text("#bp-file-label")
    assert "📄 C-101 SITE PLAN.dxf" in page.inner_text("#bp-file-label")         # the file's name (it said "not known")
    assert "null" not in page.inner_text("#review-main" if page.locator("#review-main").count() else "main")
    assert "waiting" in page.get_attribute("#bp-file-label", "class")
    page.click("#bp-design-waiting-open")                          # opens AI design on the drawn plans, to approve
    page.wait_for_selector("#bp-design-panel #ai-plans-approve")
    # 🗑 Discard: the approved drawing (revision 3) is back on the screen, and nothing waits
    page.click("#ai-plans-discard")
    page.wait_for_function("() => /AI design revision 3 · read/.test(document.getElementById('review-sheet').textContent)",
                           timeout=30000)
    page.wait_for_function("() => !document.getElementById('bp-design-waiting')", timeout=15000)
    # (the screen draws itself again after Discard - the label is briefly not there)
    page.wait_for_function("() => /AI design revision 3$/.test(document.getElementById('bp-file-label')?.textContent || '')",
                           timeout=15000)                                                  # the label is back to it too
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert str(sec["answers"]["height"]) == "4.5"                                          # the approved price stands


def test_run_ai_design_demolition_without_a_drawing(page, db, fake):
    """2026-11-27 (David: "I am doing a Demolition estimate, but that job does not need a drawing ... The draw the plans
    button should say run AI Design and add a selection to draw plans and other options like include pricing and
    inspections"): a demolition-only project starts with Draw the plans off; ✨ Run AI design fills in the trade from the
    description, the card shows what it filled in, and ✅ Approve and price prices it - nothing drawn."""
    est = service.create_estimate(db, CTX, "Kitchen gut", address="1 Main St")
    director.adopt(db, CTX, est["id"], registry=REG)
    director.set_project_trades(db, CTX, est["id"], ["demolition"], registry=REG)
    roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api"}, confirm=True)
    db.commit()
    est = est["id"]
    page.goto(page.base + f"#/projects/{est}")
    page.wait_for_selector("#ai-plans-form")
    if not page.evaluate("document.getElementById('ai-plans').open"):
        page.click("#ai-plans > summary")
    assert page.inner_text("#ai-plans-go") == "✨ Run AI design"
    assert "What should AI design do?" in page.inner_text("#ai-plans-do")
    assert not page.is_checked("#ai-plans-do-draw")                    # a demolition job needs no drawing
    assert page.is_checked("#ai-plans-do-price") and not page.is_checked("#ai-plans-do-permits")
    # nothing ticked: it says so, and doesn't run
    page.click("#ai-plans-do-price")
    assert page.is_visible("#ai-plans-do-none")
    page.click("#ai-plans-go")
    page.wait_for_timeout(800)
    assert not fake.calls
    page.click("#ai-plans-do-price")
    page.click("#ai-plans-do-permits")                                 # and the permit this time
    job = {"summary": "Gut the 200 sq ft kitchen to the studs", "assumptions": [], "lot": None, "building": None,
           "fences": [], "gates": [], "zones": [], "flatwork": [], "fixtures": [],
           "demolition": [{"what": "tear out the kitchen", "qty": 200, "unit": "sqft"}],
           "trade_answers": {"demolition": {"interior_sqft": 200, "level": "gut", "cabinets_lf": 25, "fixtures": 1,
                                            "permit": True}}}
    fake.text = [json.dumps(job)]
    page.click("#ai-plans-request")
    page.keyboard.type("Gut the 10 x 20 kitchen to the studs: 25 ft of cabinets and the sink come out, pull the permit")
    page.click("#ai-plans-go")
    page.wait_for_selector("#ai-plans-answers", timeout=30000)
    said = page.inner_text("#ai-plans-answers")
    assert "Fills in the estimate" in said and "Demolition" in said
    assert "Gut to the studs" in said and "200 sqft" in said and "Pull a demolition permit?" in said
    assert page.locator("#ai-plans-sheets button").count() == 0                       # nothing drawn
    assert page.inner_text("#ai-plans-badge") == "✅ Ready — look it over"
    assert not page.is_checked("#ai-plans-do-draw")                    # the card remembers what it did
    approve = page.locator("#ai-plans-approve")
    assert approve.inner_text() == "✅ Approve and price"
    approve.click()
    page.wait_for_selector("#ai-plans-confirm")
    assert "No plans are drawn" in page.inner_text("#ai-plans-confirm-box")
    page.click("#ai-plans-confirm")
    page.wait_for_selector("#ai-plans-approved", timeout=30000)
    assert "filled in demolition from the description" in page.inner_text("#ai-plans-approved")
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "demolition")
    assert float(sec["answers"]["interior_sqft"]) == 200 and sec["answers"]["level"] == "gut"
    assert sec["answers"]["permit"] in (True, "true", 1) and sec["lines"]
    assert db.execute("SELECT COUNT(*) FROM plan_sets WHERE estimate_id = ?", (est,)).fetchone()[0] == 0
