"""Full screen on an iPhone (2026-11-13, David): "the full view screen isn't shown on my iPhone, but it shows up
everywhere else". iPhone Safari has no Fullscreen API for page elements, so the plan viewer's Full screen button
was never added there. Now it fills the window instead.

    run_tests_estimator.bat browser -k full_screen [--human]

The phone here is Chromium with the Fullscreen API taken away (what iPhone Safari offers a web page).
"""
import pytest

from e2e_helpers import CTX, dismiss_tour
from estimator.drawing_model import engine, store
from estimator.estimating import service
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape

NO_FULLSCREEN_API = """
for (const o of [Document.prototype, document]) {
  try { Object.defineProperty(o, 'fullscreenEnabled', { get: () => false, configurable: true }); } catch (e) {}
  try { Object.defineProperty(o, 'webkitFullscreenEnabled', { get: () => undefined, configurable: true }); } catch (e) {}
}
Element.prototype.requestFullscreen = undefined;
Element.prototype.webkitRequestFullscreen = undefined;
"""


@pytest.fixture
def job(db, tmp_path):
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5)
    est = service.create_estimate(db, CTX, "Smith house")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "sheet_id": store.sheets(db, CTX, ps)["sheets"][0]["id"]}


def test_sheet_viewer_fills_the_phone_screen_without_the_fullscreen_api(phone, job):
    phone.add_init_script(NO_FULLSCREEN_API)
    phone.goto(phone.base + f"#/sheets/{job['sheet_id']}")
    phone.wait_for_selector("#sheet-viewer")
    dismiss_tour(phone)
    assert phone.evaluate("() => document.fullscreenEnabled") is False
    full = phone.locator("#zoom-full")
    assert full.is_visible()                                        # the button is there on the "iPhone" now
    full.click()
    box = phone.evaluate("""() => { const w = document.getElementById('sheet-zoom'); const r = w.getBoundingClientRect();
        return { cls: w.className, x: r.x, y: r.y, w: r.width, h: r.height, vw: innerWidth, vh: innerHeight,
                 locked: document.documentElement.classList.contains('pseudo-full-on') }; }""")
    assert "pseudo-full" in box["cls"] and box["locked"]
    assert box["x"] == 0 and box["y"] == 0 and abs(box["w"] - box["vw"]) < 2 and abs(box["h"] - box["vh"]) < 2
    assert phone.locator("#zoom-full").inner_text().startswith("✕")
    phone.locator("#zoom-in").click()                               # the zoom buttons still work in it
    assert phone.locator("#zoom-pct").inner_text() != "100%"
    phone.locator("#zoom-full").click()                             # ✕ goes back to the page
    assert "pseudo-full" not in phone.evaluate("() => document.getElementById('sheet-zoom').className")
    assert not phone.evaluate("() => document.documentElement.classList.contains('pseudo-full-on')")


def test_blueprint_review_full_screen_on_the_phone(phone, job):
    phone.add_init_script(NO_FULLSCREEN_API)
    phone.goto(phone.base + f"#/takeoffs/{job['estimate_id']}")
    phone.wait_for_selector("#bp-viewer")
    dismiss_tour(phone)
    phone.locator("#bp-full").click()
    r = phone.evaluate("""() => { const v = document.getElementById('bp-viewer'); const b = v.getBoundingClientRect();
        return { full: v.classList.contains('pseudo-full'), w: b.width, h: b.height, vw: innerWidth, vh: innerHeight }; }""")
    assert r["full"] and abs(r["w"] - r["vw"]) < 2 and abs(r["h"] - r["vh"]) < 2
    close = phone.locator("#bp-full-close")
    assert close.is_visible()                                       # its own ✕, the toolbar is behind it
    close.click()
    assert not phone.evaluate("() => document.getElementById('bp-viewer').classList.contains('pseudo-full')")
    assert phone.locator("#bp-full-close").count() == 0
