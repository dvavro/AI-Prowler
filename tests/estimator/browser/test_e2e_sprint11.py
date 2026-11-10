"""Coder 2 Sprint 11 E2E GUI tests (Playwright, human mode): visual verification, company library, Agents screen.

    run_tests_estimator.bat browser -k E2E_S11 [--human]

Builds on the existing Sprint 11 browser tests (test_browser_sprint11.py) and extends
the assertions to the full M-check wording. See tests/estimator/E2E_GUI_TEST_PLAN.md.
"""
import json

import pytest

from browser_helpers import answer_yes, type_in
from e2e_helpers import CTX, dismiss_tour, sign_in_as
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from estimator.runner import runner
from estimator.symbols import review as sym_review
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape

CTX_ = CTX


@pytest.fixture
def job(db, tmp_path):
    """A plan with a legend (receptacle, special device); 3 receptacles, 2 special devices, and 3 triangles that aren't
    in the legend (the engine misses them). Same seed as test_browser_sprint11.py."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = (ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90)
             + shape("flag", 12, 8) + shape("flag", 14, 8, 30)
             + shape("tri", 5, 10) + shape("tri", 8, 10, 90) + shape("tri", 11, 10, 200))
    est = service.create_estimate(db, CTX, "Smith house")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps, "sheet_id": store.sheets(db, CTX, ps)["sheets"][0]["id"]}


def wait_cards(page, n):
    page.wait_for_function(f"() => document.querySelectorAll('#symrev-grid .sym-card').length === {n}")


def click_on_sheet(page, x, y):
    """Click the plan at sheet inches (x, y), holding Alt so the click isn't snapped to a corner."""
    cx, cy = page.evaluate("([x, y]) => { const v = RV.viewer, r = v.box.getBoundingClientRect();"
                           " return [r.left + v.tx + x * v.z, r.top + v.ty + y * v.z]; }", [x, y])
    page.keyboard.down("Alt")
    page.mouse.click(cx, cy)
    page.keyboard.up("Alt")


def open_reviews(page, job, query=""):
    page.goto(page.base + f"#/reviews/{job['plan_set_id']}" + query)
    page.wait_for_selector("#symrev-grid")


def card_confidences(page):
    return page.evaluate(
        "() => [...document.querySelectorAll('#symrev-grid .sym-card')].map(c => {"
        " const m = c.textContent.match(/(\\d+)%/); return m ? +m[1] : null; })")


# ------------------------------------------------------------------ M1: least-sure-first, thumbnails readable

def test_E2E_S11_M1_reviews_ordering(page, job):
    open_reviews(page, job)
    dismiss_tour(page)
    wait_cards(page, 5)
    page.wait_for_function("() => [...document.querySelectorAll('#symrev-grid img.sym-thumb')]"
                           ".every(i => i.complete && i.naturalWidth > 0)")
    confs = card_confidences(page)
    assert all(c is not None for c in confs), confs
    assert confs == sorted(confs), confs  # least sure first
    # The sort control agrees: least-sure-first is the default order.
    assert page.input_value("#symrev-sort") in ("confidence", "least_sure", "sure")
    # Every card shows its thumbnail in place on the sheet (readable, not broken).
    thumbs = page.locator("#symrev-grid img.sym-thumb")
    assert thumbs.count() == 5
    for i in range(5):
        box = thumbs.nth(i).bounding_box()
        assert box and box["width"] > 40 and box["height"] > 40


# ------------------------------------------------------------------ M2: relabel unknown, every match changes

def test_E2E_S11_M2_relabel_all_matches(page, job):
    open_reviews(page, job)
    dismiss_tour(page)
    wait_cards(page, 5)
    page.click("#symrev-types [data-type=unknown]")
    wait_cards(page, 2)
    page.locator("#symrev-grid .sym-card").nth(0).click()
    page.click("#symrev-relabel")
    type_in(page, "#symrev-relabel-type", "floor box")
    page.check("#symrev-relabel-all")
    page.click("#symrev-relabel-go")
    answer_yes(page, "symrev")
    page.wait_for_selector("#symrev-types [data-type=floor_box]")
    assert int(page.inner_text("#symrev-types [data-type=floor_box] .num")) == 2
    assert page.locator("#symrev-types [data-type=unknown]").count() == 0
    # Every match changed, and the counts follow: the grid shows both as floor boxes.
    page.click("#symrev-types [data-type=floor_box]")
    wait_cards(page, 2)
    assert "floor box" in page.inner_text("#symrev-grid").lower()
    assert "was unidentified symbol" in page.inner_text("#symrev-grid .sym-card >> nth=0")
    # Reload: the relabel stuck. A fresh navigation, not a bare reload: the type
    # filter lives in the URL (?type=unknown), so a reload would re-apply it and
    # show 0 cards instead of all 5.
    page.goto(page.base + f"#/reviews/{job['plan_set_id']}")
    page.wait_for_selector("#symrev-grid")
    wait_cards(page, 5)
    assert page.locator("#symrev-types [data-type=unknown]").count() == 0
    assert int(page.inner_text("#symrev-types [data-type=floor_box] .num")) == 2


# ------------------------------------------------------------------ M3: learned symbol, second plan set

def test_E2E_S11_M3_learned_symbol_second_set(page, job, db, tmp_path):
    open_reviews(page, job)
    dismiss_tour(page)
    wait_cards(page, 5)
    page.click("#symrev-types [data-type=unknown]")
    wait_cards(page, 2)
    page.locator("#symrev-grid .sym-card").nth(0).click()
    page.click("#symrev-relabel")
    type_in(page, "#symrev-relabel-type", "floor box")
    page.check("#symrev-relabel-all")
    page.click("#symrev-relabel-go")
    answer_yes(page, "symrev")
    page.wait_for_selector("#symrev-types [data-type=floor_box]")
    # A second plan set from the same architect with the learned shape in it: the
    # two flag shapes, but no legend row for them - a plan set's own legend always
    # wins over the company library, so the learned symbol is only found where the
    # legend doesn't claim the shape. (The triangles are never detections at all,
    # so a triangle-only second set shows just the receptacle.)
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    lines = (ll + shape("recept", 5, 5) + shape("flag", 12, 8) + shape("flag", 14, 8, 30))
    est = service.create_estimate(db, CTX, "Jones house")
    ps2 = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "power2.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps2, confirm=True)
    db.commit()
    page.goto(page.base + f"#/reviews/{ps2}")
    page.wait_for_selector("#symrev-grid")
    wait_cards(page, 3)
    assert page.locator("#symrev-types [data-type=floor_box]").count() == 1
    assert int(page.inner_text("#symrev-types [data-type=floor_box] .num")) == 2
    page.click("#symrev-types [data-type=floor_box]")
    wait_cards(page, 2)
    assert "floor box" in page.inner_text("#symrev-grid").lower()


# ------------------------------------------------------------------ M4: find similar on a legend-missed symbol

def test_E2E_S11_M4_find_similar(page, job):
    # Find similar on a symbol the legend missed: an unknown card has no typed
    # shape to search for, so add the missed triangle on the plan first (the
    # proven B02 flow), then find the other two like it in Reviews.
    page.goto(page.base + f"#/takeoffs/{job['estimate_id']}")
    page.wait_for_selector("#bp-viewer img.bp-tile", state="attached")
    dismiss_tour(page)
    page.click("#bp-tools [data-tool=symbol]")
    click_on_sheet(page, 5, 10)                          # the first triangle
    page.wait_for_selector("#bp-symbol-form")
    type_in(page, "#bp-symbol-type", "thermostat")
    page.click("#bp-symbol-add")
    answer_yes(page, "bp-sym")
    page.click("#bp-tab-symbols")
    page.wait_for_selector("#bp-symbol-types [data-symbol-type=thermostat]")
    # In Reviews, find the other two.
    page.goto(page.base + f"#/reviews/{job['plan_set_id']}?type=thermostat")
    wait_cards(page, 1)
    card = page.locator("#symrev-grid .sym-card")
    assert card.get_attribute("data-status") == "approved" and "added by a person" in card.inner_text()
    card.click()
    page.click("#symrev-similar")
    page.wait_for_selector("#symrev-confirm-box")
    assert "Found 2 more" in page.inner_text("#symrev-confirm-box")
    answer_yes(page, "symrev")
    wait_cards(page, 3)
    assert int(page.inner_text("#symrev-types [data-type=thermostat] .num")) == 3
    assert page.locator("#symrev-grid .sym-card[data-status=proposed]").count() == 2


# ------------------------------------------------------------------ M5: library export, import into a second company

def test_E2E_S11_M5_library_export_import(page, job, db, tmp_path):
    flags = [d["id"] for d in db.execute("SELECT id FROM symbol_detections WHERE item_type IS NULL")]
    sym_review.review(db, CTX, flags[:1], "relabel", item_type="floor_box", apply_to_matches=True, confirm=True)
    db.commit()
    page.goto(page.base + "#/symbol_library")
    page.wait_for_selector("#symlib-company tr[data-type=floor_box]")
    dismiss_tour(page)
    with page.expect_download() as dl:
        page.click("#symlib-export")
    download = dl.value
    assert download.suggested_filename.endswith(".json")
    exported = tmp_path / "symbol-library.json"
    download.save_as(exported)
    data = json.loads(exported.read_text(encoding="utf-8"))
    blob = json.dumps(data)
    assert "floor_box" in blob
    # Import it into a second company on this PC: the learned symbol arrives there.
    with sign_in_as(page, "owner", company="second"):
        page.goto(page.base + "#/symbol_library")
        page.wait_for_selector("#symlib-company, #symlib-standard")
        assert page.locator("#symlib-company tr[data-type=floor_box]").count() == 0
        page.click("#symlib-import")
        page.set_input_files("#symlib-import-file", exported)
        # Import asks first (like every change): confirm before the row appears.
        page.wait_for_selector("#symlib-confirm-box")
        answer_yes(page, "symlib")
        page.wait_for_selector("#symlib-company tr[data-type=floor_box]")
        assert "floor box" in page.inner_text("#symlib-company tr[data-type=floor_box]").lower()


# ------------------------------------------------------------------ M6: agent trade off, start run, skipped with warning

def test_E2E_S11_M6_agent_trade_off_run_skipped(page, db):
    est = service.create_estimate(db, CTX, "Jones house")
    runner.start_run(db, CTX, est["id"], ["framing", "drywall"])
    db.commit()
    page.goto(page.base + "#/agents")
    page.wait_for_selector("#agents-list tr[data-module=framing] input[type=checkbox]")
    dismiss_tour(page)
    # Turn framing off in the Agent Manager (asks first).
    page.uncheck("#agents-list tr[data-module=framing] input[type=checkbox] >> nth=0")
    page.click("#agents-list [data-save=framing]")
    page.wait_for_selector("#agents-confirm")
    page.click("#agents-confirm")
    # The save is async: the checkbox is already unchecked from the uncheck above,
    # so waiting on it alone passes before the save lands and the next start_run
    # reads the old setting. Wait for the confirm box to go away - askThen only
    # re-renders after the save POST finishes - then check the saved state.
    page.wait_for_selector("#agents-confirm", state="detached")
    page.wait_for_function("() => document.querySelector('#agents-list tr[data-module=framing] input[type=checkbox]').checked === false")
    # Start a run on a second estimate: framing is skipped, with the warning.
    est2 = service.create_estimate(db, CTX, "Smith house")
    out = runner.start_run(db, CTX, est2["id"], ["framing", "drywall"])
    db.commit()
    assert any("Skipped (turned off in Agent Manager)" in w and "framing" in w for w in out["warnings"])
    assert [t["module_id"] for t in out["tasks"]] == ["drywall"]
    # The page is already on #/agents, so goto to the same hash is a no-op -
    # it would show the runs list from before the Smith run was created.
    # A real reload re-fetches it.
    page.reload()
    page.wait_for_selector("#runs-list")
    card = page.locator("#runs-list details", has_text="Smith house")
    assert card.count() == 1
    card.locator("summary").click()
    page.wait_for_selector("#runs-list table")
    tasks = page.inner_text("#runs-list .run-tasks")
    assert "drywall" in tasks.lower()
    assert "framing" not in tasks.lower()
    # No key: nothing executes - the run waits for a human/chat submission, so
    # its task reads "running" and the estimate stays $0.00 (never "queued").
    assert "running" in tasks.lower()
    assert "$0.00" in tasks


# ------------------------------------------------------------------ M8: phone, field role, Reviews read-only

def test_E2E_S11_M8_phone_field_reviews_readonly(phone, job):
    with sign_in_as(phone, "field"):
        phone.goto(phone.base + "?embed=1#/m/reviews?kind=symbol")
        phone.wait_for_selector("#mrev-card")
        dismiss_tour(phone)
        # The phone tour auto-starts on first open and navigates to #/m/reviews
        # (dropping ?kind=symbol), re-rendering this page; wait until the picture
        # has actually loaded so the card is stable before counting it.
        phone.wait_for_function("() => { const i = document.querySelector('img#mrev-picture');"
                               " return i && i.complete && i.naturalWidth > 0; }")
        assert phone.locator("img#mrev-picture").count() == 1
        assert phone.evaluate("document.documentElement.scrollWidth") <= 390
        # Field staff look only: no approve / take-out / relabel buttons, and the note says so.
        assert phone.locator("#mrev-approve").count() == 0
        assert phone.locator("#mrev-reject").count() == 0
        assert phone.locator("#mrev-relabel").count() == 0
        assert phone.locator("#mrev-look-only").count() == 1
        assert "approves them" in phone.inner_text("#mrev-look-only")
        # The desktop Reviews list still opens for field, thumbnails show, no action buttons.
        phone.goto(phone.base + "#/reviews")
        phone.wait_for_selector("#reviews-list")
        assert "Smith house" in phone.inner_text("#reviews-list")
        phone.click("#reviews-list tbody tr")
        phone.wait_for_selector("#symrev-grid")
        page_cards = phone.locator("#symrev-grid .sym-card")
        page_cards.first.wait_for(state="visible")
        assert phone.locator("#symrev-approve").count() == 0
        assert "You can look at the symbols here" in phone.inner_text("main")
