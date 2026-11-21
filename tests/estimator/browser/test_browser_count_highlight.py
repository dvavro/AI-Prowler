"""Measure screen, "To measure" tab: clicking a count row (Outlets...) highlights the symbols it counts on the plan, and
clicking it again clears every one of them (2026-11-19, David: "when I click again not all of them disappear").

    browser_upload.bat tests\\estimator\\browser\\test_browser_count_highlight.py
"""
import pytest

from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape

CTX = personal_context()


@pytest.fixture
def job(db, tmp_path):
    """An electrical estimate on a plan with 3 receptacles in its legend."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90)
    est = service.create_estimate(db, CTX, "Count highlight house")
    service.add_trade(db, CTX, est["id"], "electrical", est.get("rev", 1))
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


def sel(page):
    return page.locator("#bp-viewer [data-oid].sel").count()


def focus(page):
    return page.evaluate("() => document.querySelector('#bp-viewer svg.bp-overlay').classList.contains('bp-focus')")


def test_count_row_click_twice_clears_all(page, job):
    page.goto(page.base + f"#/takeoffs/{job['estimate_id']}")
    page.wait_for_selector("#bp-viewer img.bp-tile", state="attached")
    page.click("#bp-tab-guide")
    row = page.locator("#bp-pane-guide li[data-feeds=outlets]")
    row.wait_for()
    hidden_before = page.evaluate("() => [...document.querySelectorAll('#bp-viewer [data-group].hidden')]"
                                  ".map(g => g.dataset.group).sort()")
    row.click()
    assert sel(page) == 3
    assert "on" in row.get_attribute("class").split()
    assert focus(page)                                    # the rest of the plan fades back while they're highlighted
    row = page.locator("#bp-pane-guide li[data-feeds=outlets]")
    row.click()
    assert sel(page) == 0
    assert "on" not in row.get_attribute("class").split()
    assert not focus(page)
    hidden_after = page.evaluate("() => [...document.querySelectorAll('#bp-viewer [data-group].hidden')]"
                                 ".map(g => g.dataset.group).sort()")
    assert hidden_after == hidden_before                  # a layer shown for the highlight is hidden again
    # ... and the same three times over (on, off, on, off).
    for _ in range(2):
        page.locator("#bp-pane-guide li[data-feeds=outlets]").click()
        page.locator("#bp-pane-guide li[data-feeds=outlets]").click()
    assert sel(page) == 0


@pytest.fixture
def cad_job(db, tmp_path):
    """An electrical estimate on a CAD plan like David's house test: 3 ceiling fans drawn as plain FAN blocks (and an
    exhaust fan, FAN_EXH), and 30 Amp circuits that are only labels (RANGE 30A, DRYER 30A), no symbols."""
    ezdxf = pytest.importorskip("ezdxf")
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 1                        # inches
    for name in ("FAN", "FAN_EXH", "SWITCH", "SWITCH_3WAY", "SWITCH_DIM"):
        doc.blocks.new(name=name).add_circle((0, 0), 6)
    msp = doc.modelspace()
    for name, x in (("SWITCH", 30), ("SWITCH", 90), ("SWITCH_3WAY", 150), ("SWITCH_DIM", 210)):
        msp.add_blockref(name, (x, 330), dxfattribs={"layer": "E-SWITCH"})
    for a, b in (((0, 0), (480, 0)), ((480, 0), (480, 360)), ((480, 360), (0, 360)), ((0, 360), (0, 0))):
        msp.add_line(a, b, dxfattribs={"layer": "A-WALL"})
    for x in (60, 180, 300):
        msp.add_blockref("FAN", (x, 200), dxfattribs={"layer": "E-FAN"})
    msp.add_blockref("FAN_EXH", (400, 200), dxfattribs={"layer": "E-FAN"})
    for x, y, t in ((60, 80, "RANGE 30A"), (200, 80, "DRYER 30A"), (320, 300, "KITCHEN")):
        msp.add_text(t, dxfattribs={"insert": (x, y), "height": 8, "layer": "E-ANNO"})
    # A legend under the plan, like David's: one sample of each, drawn with the same blocks - never counted.
    msp.add_text("LEGEND", dxfattribs={"insert": (0, -40), "height": 6, "layer": "E-ANNO"})
    for y, name, text in ((-50, "FAN", "CEILING FAN"), (-60, "FAN_EXH", "EXHAUST FAN"), (-70, "SWITCH", "SINGLE-POLE SWITCH")):
        msp.add_blockref(name, (10, y), dxfattribs={"layer": "E-FAN" if "FAN" in name else "E-SWITCH"})
        msp.add_text(text, dxfattribs={"insert": (25, y - 3), "height": 5, "layer": "E-ANNO"})
    path = tmp_path / "house.dxf"
    doc.saveas(path)
    est = service.create_estimate(db, CTX, "CAD house")
    service.add_trade(db, CTX, est["id"], "electrical", est.get("rev", 1))
    ps = store.upload(db, CTX, est["id"], str(path), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"]}


def open_guide(page, job):
    page.goto(page.base + f"#/takeoffs/{job['estimate_id']}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.click("#bp-tab-guide")


def test_ceiling_fans_light_up(page, cad_job):
    """The FAN blocks are ceiling fans now, so the Ceiling fans row lights up all 3 (not the exhaust fan)."""
    open_guide(page, cad_job)
    row = page.locator("#bp-pane-guide li[data-feeds=fans]")
    row.wait_for()
    assert "bp-step-link" in row.get_attribute("class").split()
    row.click()
    assert sel(page) == 3
    page.locator("#bp-pane-guide li[data-feeds=fans]").click()
    assert sel(page) == 0
    # ... and the Bath exhaust fans row (an Electrical count since 2026-11-19) lights up the one FAN_EXH.
    ex = page.locator("#bp-pane-guide li[data-feeds=exhaust_fans]")
    assert "bp-step-link" in ex.get_attribute("class").split()
    ex.click()
    assert sel(page) == 1
    page.locator("#bp-pane-guide li[data-feeds=exhaust_fans]").click()
    assert sel(page) == 0


def test_each_switch_type_is_its_own_row(page, cad_job):
    """2026-11-19 (David): every switch type is its own count (a different part to order), so each row lights up only
    its own switches: 2 single-pole, 1 three-way, 1 dimmer."""
    open_guide(page, cad_job)
    for feeds, n in (("switches", 2), ("switches_3way", 1), ("dimmers", 1)):
        row = page.locator(f"#bp-pane-guide li[data-feeds={feeds}]")
        row.wait_for()
        row.click()
        assert sel(page) == n, feeds
        page.locator(f"#bp-pane-guide li[data-feeds={feeds}]").click()
        assert sel(page) == 0, feeds
    assert page.locator("#bp-pane-guide li[data-feeds=switches_4way]").count() == 1      # asked, none on this plan
    assert "bp-step-link" not in page.get_attribute("#bp-pane-guide li[data-feeds=switches_4way]", "class").split()


def test_30_amp_labels_light_up(page, cad_job):
    """The 30 Amp circuits row highlights the RANGE 30A / DRYER 30A labels (not KITCHEN), showing the text layer that's
    off by default while they're highlighted and hiding it again after."""
    open_guide(page, cad_job)
    row = page.locator("#bp-pane-guide li[data-feeds=appliance_circuits]")
    row.wait_for()
    assert "bp-step-link" in row.get_attribute("class").split()
    text = page.locator("#bp-viewer [data-group=text]")
    assert "hidden" in text.get_attribute("class").split()
    row.click()
    assert sel(page) == 2 and "hidden" not in text.get_attribute("class").split()
    page.locator("#bp-pane-guide li[data-feeds=appliance_circuits]").click()
    assert sel(page) == 0 and "hidden" in text.get_attribute("class").split()


def test_cad_sheet_needs_no_calibration(page, cad_job):
    """2026-11-19 (David): a CAD drawing is at real size. The page mustn't send him to 📐 Calibrate (which then refuses):
    no 'no scale yet' note, the guide says no scale is needed, and Calibrate explains at once instead of taking clicks."""
    open_guide(page, cad_job)
    page.wait_for_selector("#bp-guide-calibration")
    assert page.locator("#bp-sheet-note").count() == 0 or "no scale yet" not in page.inner_text("#bp-sheet-note")
    assert "no scale needed" in page.inner_text("#bp-guide-calibration")
    assert page.locator("#bp-auto-calibration").count() == 0
    page.click("#bp-tools [data-tool=calibrate]")
    page.wait_for_selector("#bp-cad-no-scale")
    assert "calibrate" not in (page.get_attribute("#bp-tools .bp-tool.active", "data-tool") or "")


def test_hidden_layer_is_hidden_again(page, job):
    """A symbol whose layer is switched off is shown while highlighted, and its layer goes back off after."""
    page.goto(page.base + f"#/takeoffs/{job['estimate_id']}")
    page.wait_for_selector("#bp-viewer img.bp-tile", state="attached")
    group = page.evaluate("() => RV.objects.find(o => o.symbol).group")
    page.evaluate("g => localStorage.setItem('est_review_layers', JSON.stringify({hidden: ['text', g], locked: []}))", group)
    page.reload()
    page.wait_for_selector("#bp-viewer img.bp-tile", state="attached")
    layer = page.locator(f"#bp-viewer [data-group={group}]")
    assert "hidden" in layer.get_attribute("class").split()
    page.click("#bp-tab-guide")
    row = page.locator("#bp-pane-guide li[data-feeds=outlets]")
    row.click()
    assert sel(page) == 3 and "hidden" not in layer.get_attribute("class").split()
    page.locator("#bp-pane-guide li[data-feeds=outlets]").click()
    assert sel(page) == 0 and "hidden" in layer.get_attribute("class").split()
