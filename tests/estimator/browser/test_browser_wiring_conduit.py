"""Measure screen, Wiring options: surface conduit (2026-11-23, David: "a metal shed ... mount the conduit on top of the
steel and not drill holes through studs ... include a basic expansion coefficient of material used for conduit").
Pick EMT or PVC, the structure and the temperature swings; the run shows the conduit, fittings, THHN and the thermal
expansion table, and proposes them for approval.

    browser_upload.bat tests\\estimator\\browser\\test_browser_wiring_conduit.py
"""
import sys
from pathlib import Path

import pytest

pytest.importorskip("ezdxf")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_browser_wiring import job, open_wiring  # noqa: E402,F401  (the fixture and the helper)


def test_surface_conduit_with_thermal_expansion(page, db, job):  # noqa: F811
    open_wiring(page, job)
    page.click("#bp-wiring-run")
    page.wait_for_selector("#bp-wiring-options", state="visible")
    # NM cable by default: none of the conduit options show.
    assert page.input_value("#bp-wire-method") == "nm"
    assert page.locator("#bp-wire-structure").count() == 0
    # EMT on a steel building: the outdoor material, structure and temperature swings appear, each explained.
    page.select_option("#bp-wire-method", "emt")
    page.wait_for_selector("#bp-wire-structure")
    assert "THHN" in page.inner_text("#bp-wire-method-help")
    assert page.input_value("#bp-wire-outdoor_material") == "pvc"
    page.select_option("#bp-wire-structure", "steel")
    assert "6.5 millionths" in page.inner_text("#bp-wire-structure-help")
    # PVC everywhere: the "outside runs in" choice goes (it's all PVC) and the PVC note names NEC 352.44.
    page.select_option("#bp-wire-method", "pvc")
    assert page.locator("#bp-wire-outdoor_material").count() == 0
    assert "352.44" in page.inner_text("#bp-wire-method-help")
    page.fill("#bp-wire-temp_swing_indoor_f", "100")
    page.click("#bp-wiring-options-run")
    page.wait_for_selector("#bp-wiring-conduit-box", timeout=30000)

    box = page.inner_text("#bp-wiring-conduit-box")
    assert "Surface conduit" in box and "ft PVC" in box
    assert "1/2 in PVC" in page.inner_text("#bp-wiring-conduit")
    assert "THHN" in page.inner_text("#bp-wiring-bom")                 # wire in the pipe, not NM cable
    assert "NM-B" not in page.inner_text("#bp-wiring-bom")
    assert "PVC" in page.inner_text("#bp-wiring-routing")
    # The expansion table: each straight leg, its movement; legs moving 1/4 in or more get fittings (highlighted).
    if page.locator("#bp-wiring-expansion-box[open]").count() == 0:
        page.click("#bp-wiring-expansion-box summary")
    page.wait_for_selector("#bp-wiring-expansion", state="visible")
    assert page.locator("#bp-wiring-expansion tr").count() > 1
    assert page.locator("#bp-wiring-expansion tr.bp-exp-yes").count() >= 1   # 100 °F swing: the long PVC legs move

    feeds = {r[0] for r in db.execute("SELECT feeds FROM measurements WHERE estimate_id = ? AND proposed_by ="
                                      " 'wiring-takeoff' AND status = 'proposed'", (job,))}
    assert {"pvc_050_ft", "pvc_straps", "pvc_expansion", "thhn_12_ft"} <= feeds
    assert not any(f.startswith("wire_") for f in feeds)                # NM cable isn't proposed as well

    # The choices stay for the next run.
    page.click("#bp-wiring-run")
    page.wait_for_selector("#bp-wiring-options", state="visible")
    assert page.input_value("#bp-wire-method") == "pvc" and page.input_value("#bp-wire-temp_swing_indoor_f") == "100"
    page.click("#bp-wiring-options-close")

    # 2026-11-23 (David: "Cant see a visual of the conduit, so how can I review it?"): click a conduit measurement and
    # its runs are drawn on the plan with their size and length; the expansion fittings show where they go.
    mids = {r[0]: r[1] for r in db.execute("SELECT feeds, id FROM measurements WHERE estimate_id = ? AND proposed_by ="
                                           " 'wiring-takeoff' AND status = 'proposed'", (job,))}
    page.click("#bp-tab-list")
    page.click(f"#bp-rows li[data-mid='{mids['pvc_050_ft']}']")
    page.wait_for_selector("#bp-conduit .bp-conduit-run.on", state="attached")
    assert page.locator("#bp-conduit .bp-conduit-run.on .bp-conduit-label").count() >= 1
    assert "1/2 in PVC" in page.inner_text(".bp-wiring-key-head")
    page.click(f"#bp-rows li[data-mid='{mids['pvc_050_ft']}']", position={"x": 30, "y": 12})     # closed
    page.click(f"#bp-rows li[data-mid='{mids['pvc_expansion']}']")
    page.wait_for_selector("#bp-conduit[data-feeds=pvc_expansion] .bp-conduit-run.on .bp-conduit-fit", state="attached")
    assert "expansion fittings" in page.inner_text(".bp-wiring-key-head")
    # the colour key names the wire as it's installed: THHN in the pipe, not 12/2 cable
    assert "AWG THHN" in page.inner_text("#bp-wiring-key")

    # 2026-11-24 (David: "approving the 6 AWG run but why is it highlighting 12 AWG and other circuits?"): a THHN size
    # lights only its own circuits, even where a home run shares the conduit with other sizes.
    page.click(f"#bp-rows li[data-mid='{mids['pvc_expansion']}']", position={"x": 30, "y": 12})   # closed
    for feeds in sorted(f for f in mids if f.startswith("thhn_")):
        gauge = feeds.split("_")[1]
        page.click(f"#bp-rows li[data-mid='{mids[feeds]}']")
        page.wait_for_selector(f"#bp-conduit[data-feeds={feeds}]", state="attached")
        head = page.inner_text(".bp-wiring-key-head")
        assert f"{gauge} AWG THHN" in head and "circuit" in head and "ft of pipe" in head
        lit = page.locator("#bp-wiring-key .bp-wiring-key-row:not(.off)")
        assert lit.count() >= 1
        for i in range(lit.count()):
            assert f"{gauge} AWG THHN" in lit.nth(i).inner_text(), (feeds, lit.nth(i).inner_text())
        page.click(f"#bp-rows li[data-mid='{mids[feeds]}']", position={"x": 30, "y": 12})        # closed


def test_switching_to_conduit_replaces_the_approved_cable(page, db, job):  # noqa: F811
    """2026-11-23 (David: "What is the 6, 10, 12 AWG THHN wiring when we already have a cable lengths?"): NM cable approved,
    the wiring run again in EMT: each THHN says which cable it replaces, and approving it takes the cable off."""
    from estimator.context import personal_context
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import wiring_run
    ctx = personal_context()
    first = wiring_run.run(db, ctx, job)
    ms.confirm_measurements(db, ctx, first["measurement_ids"], confirm=True)
    wiring_run.run(db, ctx, job, {"method": "emt"}, keep_approved=True)
    db.commit()
    thhn = db.execute("SELECT id FROM measurements WHERE estimate_id = ? AND feeds = 'thhn_12_ft' AND status = 'proposed'",
                      (job,)).fetchone()[0]
    open_wiring(page, job)
    page.click("#bp-tab-list")
    page.click(f"#bp-rows li[data-mid='{thhn}']")
    page.wait_for_selector("#bp-review-handover")
    text = page.inner_text("#bp-review-handover")
    assert "Cable 12/2" in text and "wiring method changed" in text
    page.wait_for_selector("#bp-conduit .bp-conduit-run.on", state="attached")         # the conduit with 12 AWG in it
    page.click("#bp-review-approve")
    page.wait_for_function(f"() => !document.querySelector(\"#bp-rows li[data-mid='{thhn}'] #bp-review-handover\")",
                           timeout=15000)
    page.wait_for_timeout(500)
    st = db.execute("SELECT status, reject_reason FROM measurements WHERE estimate_id = ? AND feeds = 'wire_12_2_ft'"
                    " AND status != 'proposed' ORDER BY id LIMIT 1", (job,)).fetchone()
    assert st[0] == "rejected" and "wiring method changed" in st[1]
