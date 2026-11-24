"""Measure screen, "To measure" tab: ✨ AI design (2026-11-21, David: "type in a command like here's my shed drawings, I
want to add electricity to it, design me the lighting and receptacles ... then review"). Describe it, watch it work, look
at the plan and the panel schedule, change it in plain words, approve it. A fake provider stands in for the AI; the job
runs in the background like the real one and the card polls it.

    browser_upload.bat tests\\estimator\\browser\\test_browser_ai_design.py
"""
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("ezdxf")
from estimator.agents import providers, roles  # noqa: E402
from estimator.context import personal_context  # noqa: E402
from estimator.drawing_model import engine, store  # noqa: E402
from estimator.estimating import service  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from test_ai_design import shed_design  # noqa: E402
from test_ai_design_runs import Fake, _walls_dxf  # noqa: E402

CTX = personal_context()
ASK = "Here's my shed. Add LED shop lighting, 20 A receptacles, one 240 V 30 A receptacle and a 100 A subpanel."


@pytest.fixture
def fake():
    f = Fake()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


def _shed(db, tmp_path, ai_on=True):
    est = service.create_estimate(db, CTX, "NSB Shed electrical")
    service.add_trade(db, CTX, est["id"], "electrical", est.get("rev", 1))
    ps = store.upload(db, CTX, est["id"], _walls_dxf(tmp_path / "shed.dxf"), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    if ai_on:
        roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api"}, confirm=True)
    db.commit()
    return est["id"]


def open_design(page, estimate_id):
    """2026-11-23 (David): ✨ AI design is on the toolbar beside AI Auto Run, in its own window - not in To measure."""
    page.goto(page.base + f"#/takeoffs/{estimate_id}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.click("#bp-ai-design")
    page.wait_for_selector("#bp-design-panel #bp-design h4")
    page.wait_for_selector("#bp-design-form, #bp-design-counts")


def test_describe_view_change_approve(page, db, fake, tmp_path):
    est = _shed(db, tmp_path)
    page.goto(page.base + f"#/takeoffs/{est}")
    page.wait_for_selector("#bp-ai-design")
    page.click("#bp-tab-guide")                                          # not hidden in the To measure tab any more
    assert page.locator("#bp-pane-guide #bp-design").count() == 0
    open_design(page, est)
    card = page.inner_text("#bp-design-panel")
    assert "✨ AI design" in card and "Nothing is priced until you approve it" in card
    # 2026-11-23 (David: "it will not let me type anything"): typing goes in, and stays through a redraw of the
    # screen (a refresh) and of the window itself
    page.click("#bp-design-request")
    page.keyboard.type("Add lights")
    page.evaluate("() => { refreshData(); renderDesign(); }")
    page.wait_for_timeout(600)
    assert page.input_value("#bp-design-request") == "Add lights"
    page.fill("#bp-design-request", "")
    assert page.locator("#bp-design-off").count() == 0
    assert "shed.dxf (CAD)" in page.inner_text("#bp-design-plans")
    assert page.locator("#bp-design-trade option[value=plumbing]").is_disabled()          # electrical first
    fake.text = [json.dumps(shed_design())]
    page.fill("#bp-design-request", ASK)
    page.click("#bp-design-specs-box summary")
    page.fill("#bp-design-specs", "receptacles at 48 in")
    page.click("#bp-design-go")
    page.wait_for_selector("#bp-design-counts", timeout=30000)                              # polled until it's ready
    assert "46 devices · 6 circuits · 100 A subpanel" in page.inner_text("#bp-design-counts")
    assert "20 LED shop lights" in page.inner_text("#bp-design-counts")
    assert "Proposed — revision 1" in page.inner_text("#bp-design-proposed")
    assert "No code errors" in page.inner_text("#bp-design-findings")
    assert "46' x 45'" in page.inner_text("#bp-design-building") and "the CAD drawing" in page.inner_text("#bp-design-building")
    assert "100A subpanel in the house garage" in page.inner_text("#bp-design-feeder")
    assert ASK in fake.calls[0][1] and "receptacles at 48 in" in fake.calls[0][1]

    # look at it: the plan, then the panel schedule, in the drawing viewer
    page.click("#bp-design-view-plan")
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)
    assert page.inner_text("#bp-wiring-viewer-title") == "AI design — electrical plan"
    page.click("#bp-wiring-viewer-other")
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)
    assert page.inner_text("#bp-wiring-viewer-title") == "AI design — panel schedule"
    page.keyboard.press("Escape")
    assert page.locator("#bp-wiring-viewer").count() == 0

    # change it in plain words
    more = shed_design()
    more["devices"].append({"type": "outlet", "x": 20, "y": 45, "floor": 0, "circuit": "C-2"})
    more["changes"] = ["added a receptacle on the rear wall at x 20 (C-2)"]
    fake.text = [json.dumps(more)]
    page.fill("#bp-design-change", "add one more outlet on the rear wall")
    page.click("#bp-design-change-go")
    page.wait_for_selector("#bp-design-changes", timeout=30000)
    assert "added a receptacle on the rear wall" in page.inner_text("#bp-design-changes")
    assert "47 devices" in page.inner_text("#bp-design-counts")
    assert "add one more outlet on the rear wall" in fake.calls[-1][1]

    # approve: asks first, then it's two plan sets
    page.click("#bp-design-approve")
    page.wait_for_selector("#bp-design-confirm-box")
    assert "47 devices on 6 circuits" in page.inner_text("#bp-design-confirm-box")
    page.click("#bp-design-confirm")
    page.wait_for_selector("#bp-design-approved", timeout=60000)
    # 2026-11-23 (David: "easy and automatic"): approving also measured, approved and priced it - no other clicks
    said = page.inner_text("#bp-design-approved")
    assert "Approved:" in said and "measured" in said and "updated the estimate's electrical prices" in said
    names = [r[0] for r in db.execute("SELECT original_name FROM plan_sets WHERE estimate_id = ? ORDER BY id", (est,))]
    assert names[-2:] == ["AI design - electrical plan.dxf", "AI design - electrical panel schedule.dxf"]
    assert "shed.dxf" in names                                            # the building's own drawing stays
    n = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND module_id = 'electrical'"
                   " AND status = 'approved'", (est,)).fetchone()[0]
    assert n > 0


def test_ai_off_and_a_failed_design(page, db, fake, tmp_path):
    est = _shed(db, tmp_path, ai_on=False)
    open_design(page, est)
    assert "AI measuring is off" in page.inner_text("#bp-design-off")
    assert page.locator("#bp-design-go").is_disabled()
    roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api"}, confirm=True)
    db.commit()
    page.goto(page.base + "#/dashboard")                                  # turned on elsewhere, then back to Measure
    page.wait_for_timeout(800)
    open_design(page, est)
    page.wait_for_selector("#bp-design-go:not([disabled])")
    fake.text = ["I can't design that"]
    page.fill("#bp-design-request", ASK)
    page.click("#bp-design-go")
    page.wait_for_selector("#bp-design-failed", timeout=30000)
    assert "didn't answer with JSON" in page.inner_text("#bp-design-failed")
    assert page.input_value("#bp-design-request") == ASK                                   # the request is kept


def test_screenshots_and_the_numbered_plan(page, db, fake, tmp_path):
    """2026-11-23 (David: "add screenshots to the AI Design to give geometric guidance to the AI, for example move this
    here"): 📎 attach or paste a marked-up screenshot; 🔢 Numbered plan shows what the AI matches it against."""
    from PIL import Image, ImageDraw
    shot = tmp_path / "move_this_here.png"
    im = Image.new("RGB", (640, 400), "white")
    ImageDraw.Draw(im).line((100, 300, 500, 120), fill="red", width=8)                     # an arrow: "move this here"
    im.save(shot)
    est = _shed(db, tmp_path)
    open_design(page, est)
    fake.text = [json.dumps(shed_design())]
    page.fill("#bp-design-request", ASK)
    page.click("#bp-design-go")
    page.wait_for_selector("#bp-design-counts", timeout=30000)

    # the numbered plan: the building on a grid, every device numbered
    page.click("#bp-design-view-ref")
    page.wait_for_selector("#bp-wiring-viewer[data-ready='1']", timeout=30000)
    assert "numbered plan" in page.inner_text("#bp-wiring-viewer-title")
    assert page.inner_text("#bp-wiring-viewer-download") == "⬇ Save picture"
    assert page.evaluate("() => document.getElementById('bp-wiring-viewer-img').naturalWidth") > 400
    page.keyboard.press("Escape")

    # attach one, remove it, attach it again; paste a second one into the box
    assert "paste one into the box" in page.inner_text("#bp-design-shots-change")
    page.set_input_files("#bp-design-file-change", str(shot))
    page.wait_for_selector("#bp-design-shots-change .bp-shot img")
    page.click("#bp-design-shots-change .bp-shot button")
    assert page.locator("#bp-design-shots-change .bp-shot").count() == 0
    page.set_input_files("#bp-design-file-change", str(shot))
    page.wait_for_selector("#bp-design-shots-change .bp-shot img")
    page.evaluate("""async () => {
        const c = document.createElement('canvas'); c.width = 300; c.height = 200;
        const blob = await new Promise(r => c.toBlob(r, 'image/png'));
        const dt = new DataTransfer(); dt.items.add(new File([blob], 'pasted.png', { type: 'image/png' }));
        document.getElementById('bp-design-change').dispatchEvent(
          new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
    }""")
    page.wait_for_function("() => document.querySelectorAll('#bp-design-shots-change .bp-shot').length === 2")
    assert "2 of 3" in page.inner_text("#bp-design-shots-change")

    # the change goes to the AI with the numbered plan first, then the two screenshots
    moved = shed_design()
    moved["changes"] = ["moved device 3 (receptacle) to the rear wall where the arrow points"]
    fake.vision = [json.dumps(moved)]
    page.fill("#bp-design-change", "move this outlet here")
    page.click("#bp-design-change-go")
    page.wait_for_selector("#bp-design-changes", timeout=30000)
    assert "where the arrow points" in page.inner_text("#bp-design-changes")
    kind, prompt, n = fake.calls[-1]
    assert kind == "vision" and n == 3 and "move this outlet here" in prompt and "PICTURES" in prompt
    assert page.locator("#bp-design-shots-change .bp-shot").count() == 0                   # sent: the box is empty again
