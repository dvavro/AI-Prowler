"""AI design "Plans from a description" jobs (estimator/design/runs.py, trade 'plans'), 2026-11-24 (David: "If the user
does not have plans I want the user to be able to use AI Design button so the user can just describe the plans and have AI
Design it for him" - every trade, as a drawn plan).

start (no plan set needed) -> proposed with drawn sheets -> change -> approve: the sheets become the project's plans, the
plan engine reads them, every trade the plan readers answer is measured, approved and priced. A fake provider stands in
for Claude - no real API calls, no token cost. Everything runs in the test's thread (RUN_INLINE)."""
import json

import pytest

ezdxf = pytest.importorskip("ezdxf")
pytest.importorskip("shapely")
from estimator.agents import providers, roles  # noqa: E402
from estimator.context import personal_context  # noqa: E402
from estimator.design import runs  # noqa: E402
from estimator.drawing_model import engine  # noqa: E402
from estimator.errors import ConfirmationRequired, InvalidInput  # noqa: E402
from estimator.estimating import service  # noqa: E402
from test_ai_design_describe import fence_job, shed_job  # noqa: E402
from test_ai_design_runs import Fake  # noqa: E402

CTX = personal_context()
ASK = "6 ft wood privacy fence around the back yard of a 100 x 150 lot, a walk gate and a drive gate, sod the back yard"


@pytest.fixture
def fake(monkeypatch):
    f = Fake()
    providers.set_provider(f)
    monkeypatch.setattr(runs, "RUN_INLINE", True)
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield f
    providers.set_provider(None)
    engine.clear_engine()


def _on(db):
    roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api"}, confirm=True)


def _fence_project(db, quote=("fencing",)):
    est = service.create_estimate(db, CTX, "Back yard fence")
    for t in quote:
        est = service.add_trade(db, CTX, est["id"], t, int(est["rev"]))
    return est["id"]


def test_plans_need_no_plan_set_and_are_drawn(db, fake):                                  # DP-01
    _on(db)
    est = _fence_project(db)
    fake.text = [json.dumps(fence_job())]
    job = runs.start(db, CTX, est, "plans", ASK, None)
    assert job["status"] == "proposed" and job["error"] is None and job["rev"] == 1
    assert [c[0] for c in fake.calls] == ["ask"] and ASK in fake.calls[0][1]
    assert "fencing" in fake.calls[0][1]                                 # the trades the project quotes are in the ask
    assert [s["key"] for s in job["sheets"]] == ["site"] and job["has_drawings"] and job["can_approve"]
    assert job["counts"]["fence_lf"] == 320.0
    assert runs.sheet_path(est, 1, "site").is_file()
    # 2026-11-25 (David: "lets always show the latest drawing ... then the user still need to approve"): it's on the
    # Measure screen at once and measured - as proposals; nothing is approved or priced until the person approves it
    assert db.execute("SELECT COUNT(*) FROM plan_sets WHERE estimate_id = ?", (est,)).fetchone()[0] == 1
    st = [r[0] for r in db.execute("SELECT status FROM measurements WHERE estimate_id = ?", (est,))]
    assert st and set(st) == {"proposed"}
    assert job["placed"]["rev"] == 1 and job["approved_rev"] is None and job["auto_approve"] is False
    assert not next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")["lines"]
    assert any(t["id"] == "plans" and t["no_plans"] for t in runs.options(db, CTX, est)["trades"])


def test_an_error_gets_one_fix_turn(db, fake):                                             # DP-02
    _on(db)
    est = _fence_project(db)
    bad = fence_job()
    bad["gates"].append({"at": [50, 20], "kind": "walk", "width_ft": 4})                    # a gate on no fence
    fake.text = [json.dumps(bad), json.dumps({**fence_job(), "changes": ["moved the gate onto the fence"]})]
    job = runs.start(db, CTX, est, "plans", ASK, None)
    assert len(fake.calls) == 2 and job["errors"] == 0 and job["revisions"][-1]["auto_fixed"] is True


def test_change_it_in_plain_words(db, fake):                                               # DP-03
    _on(db)
    est = _fence_project(db)
    fake.text = [json.dumps(fence_job())]
    runs.start(db, CTX, est, "plans", ASK, None)
    taller = fence_job()
    taller["fences"][0]["height_ft"] = 8
    taller["changes"] = ["made the fence 8 ft"]
    fake.text = [json.dumps(taller)]
    job = runs.change(db, CTX, est, "plans", "make it 8 ft tall")
    assert "make it 8 ft tall" in fake.calls[-1][1]
    assert job["rev"] == 2 and job["design"]["changes"] == ["made the fence 8 ft"]
    assert runs.sheet_path(est, 2, "site").is_file()
    fake.text = ["sorry"]
    job = runs.change(db, CTX, est, "plans", "make it nicer")
    assert job["status"] == "proposed" and job["rev"] == 2 and "didn't go through" in job["error"]


def test_approve_makes_the_plans_measures_and_prices_the_fence(db, fake):                 # DP-04
    _on(db)
    est = _fence_project(db)
    fake.text = [json.dumps(fence_job())]
    runs.start(db, CTX, est, "plans", ASK, None)
    with pytest.raises(ConfirmationRequired, match="C-101 SITE PLAN"):
        runs.approve(db, CTX, est, "plans")
    out = runs.approve(db, CTX, est, "plans", confirm=True)
    assert out["status"] == "approved" and out["error"] is None, out
    a = out["approval"]
    assert len(a["plan_set_ids"]) == 1 and a["measured"].get("fencing", 0) > 0 and "fencing" in a["updated"]
    names = [r[0] for r in db.execute("SELECT original_name FROM plan_sets WHERE estimate_id = ?", (est,))]
    assert names == ["C-101 SITE PLAN.dxf"]
    left = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND status = 'proposed'", (est,)).fetchone()[0]
    assert left == 0
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert float(sec["answers"]["length_lf"]) == 320.0 and sec["answers"]["walk_gates"] in (1, "1")
    assert "Approved:" in out["say"] and "fencing" in out["say"]
    assert sec["answers"]["material"] == "wood" and str(sec["answers"]["height"]) == "6"   # from the approved plan
    # changed and approved again: the new site plan replaces the one it made (the old plan set is removed - one set per
    # sheet, store.upload 2026-11-21), and a taller fence is re-priced though its length didn't change
    first = out["approval"]["plan_set_ids"][0]
    taller = fence_job()
    taller["fences"][0]["height_ft"] = 8
    fake.text = [json.dumps(taller)]
    runs.change(db, CTX, est, "plans", "make it 8 ft tall")
    out2 = runs.approve(db, CTX, est, "plans", confirm=True)
    assert out2["status"] == "approved" and out2["error"] is None, out2
    rows = db.execute("SELECT id, revision FROM plan_sets WHERE estimate_id = ?", (est,)).fetchall()
    assert len(rows) == 1 and rows[0][0] != first and rows[0][1] == 2
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert str(sec["answers"]["height"]) == "8" and float(sec["answers"]["length_lf"]) == 320.0
    assert "fencing" in out2["approval"]["updated"]


def test_a_shed_from_a_description_lists_what_ai_auto_run_does(db, fake):                 # DP-05
    _on(db)
    est = _fence_project(db, quote=("flooring", "concrete"))
    fake.text = [json.dumps(shed_job())]
    job = runs.start(db, CTX, est, "plans", "a 20 x 30 shed with a shop and a half bath", None)
    assert [s["key"] for s in job["sheets"]] == ["floor", "foundation", "roof", "demolition"]
    out = runs.approve(db, CTX, est, "plans", confirm=True)
    a = out["approval"]
    assert len(a["plan_set_ids"]) == 4 and a["measured"].get("flooring", 0) > 0
    # 2026-11-25 (David: "the electrical and cement as well"): concrete is measured from the design's own foundation
    # plan when it's drawn, and priced when it's approved - no AI Auto Measure/Count run needed
    from estimator.design import describe
    want = describe.concrete_answers(runs.load(est, "plans")["design"])
    assert want["area_sqft"] > 0 and "concrete" not in a["auto_run"] and a["measured"].get("concrete", 0) >= 2
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "concrete")
    assert float(sec["answers"]["area_sqft"]) == want["area_sqft"] and str(sec["answers"]["thickness_in"]) == want["thickness_in"]
    assert float(sec["answers"]["perimeter_lf"]) == want["perimeter_lf"]


def _png_url(color=(200, 230, 200)):
    """A small picture as the page sends it: a data: URL."""
    import base64
    import io
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (120, 80), color).save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def test_screenshots_go_to_the_ai_with_the_description_and_a_change(db, fake):          # DP-07
    """2026-11-25 (David: "I took a screen clip of the area where I want a fence to be added, but there is no way to Ctrl V
    add an image to the design description"): the pictures go to the AI with what they're for; a change can bring its own."""
    _on(db)
    est = _fence_project(db)
    fake.vision = [json.dumps(fence_job())]
    job = runs.start(db, CTX, est, "plans", ASK, None, images=[_png_url()])
    assert job["status"] == "proposed", job["error"]
    assert fake.calls[0][0] == "vision" and fake.calls[0][2] == 1               # the description and its 1 picture
    assert ASK in fake.calls[0][1] and "PICTURES:" in fake.calls[0][1] and "aerial" in fake.calls[0][1]
    assert job["revisions"][-1]["screenshots"] == 1
    log = db.execute("SELECT purpose FROM ai_log ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert log == "AI design: plans from a description (design) (1 screenshot)"
    taller = fence_job()
    taller["fences"][0]["height_ft"] = 8
    fake.vision = [json.dumps(taller)]
    job = runs.change(db, CTX, est, "plans", "the fence goes where I marked", images=[_png_url(), _png_url((9, 9, 9))])
    assert fake.calls[-1][0] == "vision" and fake.calls[-1][2] == 2
    assert "change only what the pictures and the change ask for" in fake.calls[-1][1]
    assert job["rev"] == 2 and job["revisions"][-1]["screenshots"] == 2
    # no pictures: a plain text call, as before
    fake.text = [json.dumps(fence_job())]
    runs.change(db, CTX, est, "plans", "back to 6 ft")
    assert fake.calls[-1][0] == "ask" and "PICTURES:" not in fake.calls[-1][1]
    with pytest.raises(InvalidInput, match="isn't a picture"):
        runs.start(db, CTX, est, "plans", ASK, None, images=["data:text/plain;base64,aGVsbG8="])


def test_the_design_window_opens_on_the_projects_trade(db, fake):                         # DP-08
    """2026-11-25 (David: "The AI Design should know what trade I am in as a default (it should come up as fence) ... I
    clicked ON box and nothing happens"): a fence project opens on its plans; an electrical one on electrical; the plans
    the AI drew are drawings electrical can be designed on."""
    _on(db)
    est = _fence_project(db)
    o = runs.options(db, CTX, est)
    assert o["default_trade"] == "plans" and [t["name"] for t in o["project_trades"]] == ["Fencing"]
    assert o["plan_sets"] == []
    fake.text = [json.dumps(fence_job())]
    runs.start(db, CTX, est, "plans", ASK, None)
    runs.approve(db, CTX, est, "plans", confirm=True)
    o = runs.options(db, CTX, est)
    assert o["default_trade"] == "plans"                           # an AI plans design is there: it opens on it
    assert [p["name"] for p in o["plan_sets"]] == ["C-101 SITE PLAN.dxf"]
    elec = _fence_project(db, quote=("electrical",))
    assert runs.options(db, CTX, elec)["default_trade"] == "electrical"
    assert runs.options(db, CTX, _fence_project(db, quote=()))["default_trade"] == "electrical"   # nothing picked yet


def _approved_fence_plans(db, fake):
    _on(db)
    est = _fence_project(db)
    fake.text = [json.dumps(fence_job())]
    runs.start(db, CTX, est, "plans", ASK, None)
    out = runs.approve(db, CTX, est, "plans", confirm=True)
    sheet = db.execute("SELECT id FROM sheets WHERE plan_set_id = ?", (out["approval"]["plan_set_ids"][0],)).fetchone()[0]
    return est, sheet


def _ai_fence(db, est, sheet, length, walk, status="approved"):
    """What 🤖 AI Auto Measure/Count saved before 2026-11-25 on the same site plan: its own fence length and gates."""
    ids = []
    for feeds, label, qty, unit in (("length_lf", "Fence length (AI)", length, "lf"), ("walk_gates", "Walk gates (AI)", walk, "ea")):
        ids.append(db.execute(
            "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, kind, label, qty, unit,"
            " source_object_ids, calc_json, method, confidence, status, locked, proposed_by, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,'[]','{\"source\": \"llm\"}','ai','0.85',?,?,'llm-takeoff','2026-11-25','2026-11-25')",
            (CTX.company_id, est, "fencing", feeds, sheet, "length" if unit == "lf" else "count", label, str(qty), unit,
             status, 1 if status == "approved" else 0)).lastrowid)
    db.commit()
    return ids


def test_audit_takes_off_the_ai_count_of_what_the_plans_already_measured(db, fake):       # DP-09
    """2026-11-25 (David: "I hit AI Count and now I have 2 lengths and 2 gates counted twice, then I ran audit and clean up
    and it did not remove the double counting of fence material")."""
    from estimator.takeoff import audit
    from estimator.takeoff import measurements as ms
    est, sheet = _approved_fence_plans(db, fake)
    _ai_fence(db, est, sheet, 320, 1)
    assert ms.approved_answers(db, CTX, est, "fencing")["fencing"]["length_lf"] == 640.0        # priced twice
    found = {f["id"]: f for f in audit.audit(db, CTX, est)["findings"]}
    twice = found["twice:fencing:length_lf"]
    assert twice["kind"] == "double_counted" and twice["selected"] and "priced twice" in twice["title"]
    assert "320 lf" in twice["fix"] and "from the plans" in twice["fix"]
    assert found["twice:fencing:walk_gates"]["selected"]
    assert audit.price_problems(db, CTX, est)["count"] >= 2                                  # the Director's audit step
    audit.apply(db, CTX, est, ["twice:fencing:length_lf", "twice:fencing:walk_gates"], confirm=True)
    a = ms.approved_answers(db, CTX, est, "fencing")["fencing"]
    assert a["length_lf"] == 320.0 and a["walk_gates"] == 1
    assert not [f for f in audit.audit(db, CTX, est)["findings"] if f["kind"] == "double_counted"]
    # when they don't agree, a person decides: not ticked
    ids = _ai_fence(db, est, sheet, 300, 1)
    f = {f["id"]: f for f in audit.audit(db, CTX, est)["findings"]}["twice:fencing:length_lf"]
    assert not f["selected"] and "don't agree" in f["detail"]
    db.execute(f"DELETE FROM measurements WHERE id IN ({ids[0]}, {ids[1]})")
    # the site plan replaced by a newer revision (the plans' 320 lf re-checked unchanged, still marked with the old plan
    # set - David's estimate 12): the AI's count on the new sheet is still the same fence, priced twice
    taller = fence_job()
    taller["fences"][0]["height_ft"] = 8
    fake.text = [json.dumps(taller)]
    runs.change(db, CTX, est, "plans", "make it 8 ft tall")
    new_ps = runs.approve(db, CTX, est, "plans", confirm=True)["approval"]["plan_set_ids"][0]
    new_sheet = db.execute("SELECT id FROM sheets WHERE plan_set_id = ?", (new_ps,)).fetchone()[0]
    plans_m = db.execute("SELECT calc_json FROM measurements WHERE estimate_id = ? AND feeds = 'length_lf' AND method = 'cad'",
                         (est,)).fetchone()[0]
    assert new_ps not in json.loads(plans_m)["plan_set_ids"]          # still marked with the replaced plan set
    _ai_fence(db, est, new_sheet, 320, 1)
    found = {f["id"]: f for f in audit.audit(db, CTX, est)["findings"]}
    assert found["twice:fencing:length_lf"]["selected"] and found["twice:fencing:walk_gates"]["selected"]


def test_ai_auto_count_doesnt_add_what_the_plans_already_measured(db, fake):              # DP-10
    """The same run today: the plans' approved fence isn't measured a second time; a different number is a suggestion."""
    from estimator.takeoff import llm_fencing
    from estimator.takeoff import llm_quantities as lq
    from estimator.takeoff import measurements as ms
    est, sheet = _approved_fence_plans(db, fake)
    run = {"id": 77, "estimate_id": est, "keep_approved": 0, "viewport_id": None}
    reading = {"fencing_sheet_id": sheet, "confidence": 0.85, "evidence": {}, "notes": ""}
    made = lq.create_measurements(db, CTX, run, reading, {"values": {"length_lf": "320", "walk_gates": 1, "drive_gates": 1}},
                                  "claude_api", "m", llm_fencing.SPEC)
    assert made == []                                                     # nothing new: the plans measured all of it
    a = ms.approved_answers(db, CTX, est, "fencing")["fencing"]
    assert a["length_lf"] == 320.0 and a["walk_gates"] == 1 and a["drive_gates"] == 1
    lq.create_measurements(db, CTX, run, reading, {"values": {"length_lf": "300", "walk_gates": 1, "drive_gates": 1}},
                           "claude_api", "m", llm_fencing.SPEC)
    m = db.execute("SELECT qty, suggested_qty, suggested_reason FROM measurements WHERE estimate_id = ? AND module_id ="
                   " 'fencing' AND feeds = 'length_lf' AND status = 'approved'", (est,)).fetchall()
    assert len(m) == 1 and float(m[0]["qty"]) == 320.0 and float(m[0]["suggested_qty"]) == 300.0
    assert "AI Auto Measure/Count #77" in m[0]["suggested_reason"]
    assert ms.approved_answers(db, CTX, est, "fencing")["fencing"]["length_lf"] == 320.0    # still priced once


def test_a_redraw_on_an_approved_estimate_updates_material_and_height(db, fake):          # DP-11
    """2026-11-25 (David: the AI redraw made the pool fence aluminum, 4'-6", but the Lines still said wrought iron). The
    estimate was approved, so approving the plans can't re-price it; 🔄 Update from the plans now takes the plans'
    material and height too (no quantity changed, so it used to say there was nothing to update)."""
    from estimator.api import estimate_api, links
    from estimator.modules import get_registry
    est, _sheet = _approved_fence_plans(db, fake)
    e = service.get_estimate(db, CTX, est)
    service.set_status(db, CTX, est, e["rev"], "approved")
    alu = fence_job()
    alu["fences"][0]["material"], alu["fences"][0]["height_ft"] = "aluminum", 4.5
    fake.text = [json.dumps(alu)]
    runs.change(db, CTX, est, "plans", "aluminum powder coated black, 4' 6\" high")
    out = runs.approve(db, CTX, est, "plans", confirm=True)
    assert out["status"] == "approved" and "prices didn't change" in out["error"] and "Update from the plans" in out["error"]
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert sec["answers"]["material"] == "wood"                           # approved: not changed behind the person's back
    reg = get_registry()
    e = service.get_estimate(db, CTX, est)
    assert links.plan_choices(db, CTX, e, "fencing", reg) == {"material": "aluminum", "height": "4.5"}
    fence = next(t for t in links.estimate_links(db, CTX, est, e, reg)["trades"] if t["module_id"] == "fencing")
    assert fence["can_use_measurements"] and set(fence["plan_notes"]) == {"material", "height"}   # the 🔄 button shows
    said = estimate_api.plan_changes(db, CTX, e, reg)[0]["said"]
    assert "Material: Wood privacy → Aluminum (powder coated)" in said and "Height: 6 ft → 4 ft 6 in" in said
    estimate_api._update_from_plans(db, CTX, est, {"rev": e["rev"]}, True, True)
    e = service.get_estimate(db, CTX, est)
    sec = next(s for s in e["sections"] if s["module_id"] == "fencing")
    assert e["status"] == "draft" and sec["answers"]["material"] == "aluminum" and str(sec["answers"]["height"]) == "4.5"
    assert any("Aluminum fence panels" in li["description"] for li in sec["lines"])
    assert not any("Wood" in li["description"] for li in sec["lines"])
    assert estimate_api.plan_changes(db, CTX, e, reg) == []               # matches the plans now


def test_long_notes_wrap_and_stay_on_the_sheet_picture(tmp_path):                           # DP-12
    """2026-11-25 (David: "when I reloaded the sheet I did not see the latest notes about aluminum fence"): the notes column
    sits right of the drawing and the sheet picture ended where each note started, so every note was cut off; and a note
    over 110 characters was cut mid-word in the drawing itself."""
    from estimator.design import draw_plans
    from estimator.plan_engine import dxf_reader
    doc, msp = draw_plans._new("C-101 SITE PLAN")
    msp.add_lwpolyline([(0, 0), (60, 0), (60, 35), (0, 35)], close=True, dxfattribs={"layer": "L-FENCE"})
    long = ("PANELS: 22 ALUMINUM PANELS, 54 IN X 6 FT, BLACK (ABOUT 120 LF NET). BAYS SHORTER THAN 6 FT ARE CUT FROM FULL"
            " PANELS ON SITE AND THE CUT ENDS TOUCHED UP")
    draw_plans._notes(doc, msp, ["TOTAL 128 LF", long], 62, 35)
    words = [t.dxf.text for t in msp.query("TEXT")]
    assert all(len(w) <= draw_plans.NOTE_WIDTH for w in words)
    said = " ".join(" ".join(words).split())
    assert "TOUCHED UP" in said and "CUT FROM FULL PANELS" in said                          # nothing cut off
    path = tmp_path / "C-101 SITE PLAN.dxf"
    doc.saveas(path)
    out = dxf_reader.read(path, tmp_path, 1)
    sheet = (out.get("sheets") or [out])[0]
    widest = max(len(w) for w in words) * draw_plans.SMALL_H * 0.6           # the notes' own width, at least
    assert float(sheet["width"]) >= 62 + widest                             # the sheet reaches past the notes


def test_measure_says_which_design_revision_and_what_waits(db, fake):                     # DP-13
    """2026-11-25 (David: "I just reran AI Design and the drawing showed the notes, then when I went back to measure and hit
    the reload icon, it did not bring up rev 4"): the redraw was waiting for approval, and Measure's "revision 3" (the plan
    set's own count) didn't match AI design's revision 6. Measure now says the design revision and what's waiting."""
    est, _sheet = _approved_fence_plans(db, fake)
    ps = runs.load(est, "plans")["approved_plan_set_ids"][0]
    assert runs.on_measure(est) == {"plan_sets": {ps: 1}, "waiting": None}
    taller = fence_job()
    taller["fences"][0]["height_ft"] = 8
    fake.text = [json.dumps(taller)]
    runs.change(db, CTX, est, "plans", "make it 8 ft tall")
    # the new drawing is the one on the Measure screen at once (it replaced the old sheet); it waits for approval
    live = [r[0] for r in db.execute("SELECT id FROM plan_sets WHERE estimate_id = ?", (est,))]
    new = runs.load(est, "plans")["placed"]["plan_set_ids"][0]
    assert live == [new] and new != ps
    seen = runs.on_measure(est)
    assert seen["plan_sets"][new] == 2
    assert seen["waiting"] == {"trade": "plans", "rev": 2, "approved_rev": 1, "on_screen": True}
    # a design approved before approved_rev was kept (David's estimate 12): its newest approve folder says it
    st = runs.load(est, "plans")
    st.pop("approved_rev")
    runs.save(st)
    (runs.folder(est) / "approve_plans_rev1").mkdir(exist_ok=True)
    assert runs.approved_rev(runs.load(est, "plans")) == 1
    out = runs.approve(db, CTX, est, "plans", confirm=True)
    assert out["approval"]["plan_set_ids"] == [new]                       # approving doesn't put up another drawing
    assert runs.on_measure(est) == {"plan_sets": {new: 2}, "waiting": None}


def _fence(points=None, gates=None, height=6):
    job = fence_job()
    if points is not None:
        job["fences"][0]["points"] = points
    if gates is not None:
        job["gates"] = gates
    job["fences"][0]["height_ft"] = height
    return job


def _m(db, est, feeds):
    return [dict(r) for r in db.execute("SELECT * FROM measurements WHERE estimate_id = ? AND module_id = 'fencing' AND"
                                        " feeds = ? ORDER BY id", (est, feeds))]


def test_a_redraw_keeps_approved_items_and_takes_off_what_is_gone(db, fake):               # DP-14
    """2026-11-25 (David: "the user still need to approve the new drawing, dont auto approve unless the user selects that
    and also conform to the keep approved items on rerun unless that item has been removed")."""
    est, _sheet = _approved_fence_plans(db, fake)                          # 320 lf, 1 walk gate, 1 drive gate - approved
    walk = fence_job()["gates"][0]
    short = [[30, 70], [0, 70], [0, 150], [100, 150], [100, 70]]           # 290 lf, and the drive gate is gone
    fake.text = [json.dumps(_fence(short, [walk]))]
    job = runs.change(db, CTX, est, "plans", "drop the drive gate and the last 30 ft", keep_approved=True)
    assert job["status"] == "proposed" and job["placed"]["rev"] == 2 and job["placed"]["gone"] == 1
    length, drive = _m(db, est, "length_lf")[-1], _m(db, est, "drive_gates")[-1]
    # before approval: the approved numbers stand; the new ones wait beside them
    assert length["status"] == "approved" and float(length["qty"]) == 320 and float(length["suggested_qty"]) == 290
    assert drive["status"] == "approved" and float(drive["suggested_qty"]) == 0 and runs.GONE in drive["suggested_reason"]
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert sec["answers"]["drive_gates"] in (1, "1")                         # not priced until approved
    # 2026-11-25 (David: "a change to the drawing is treated like the current one and estimates are based on it"):
    # approving it, what was approved takes the new drawing's numbers - Keep approved items on rerun or not
    with pytest.raises(ConfirmationRequired, match="takes the new drawing's numbers"):
        runs.approve(db, CTX, est, "plans", keep_approved=True)
    out = runs.approve(db, CTX, est, "plans", confirm=True, keep_approved=True)
    assert out["status"] == "approved" and out["approval"]["removed"] == 1 and out["approval"]["changed"] == 1, out
    length, drive = _m(db, est, "length_lf")[-1], _m(db, est, "drive_gates")[-1]
    assert float(length["qty"]) == 290 and length["suggested_qty"] is None                # the drawing's number
    assert drive["status"] == "rejected"                                                  # gone from the drawing: off
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert sec["answers"]["drive_gates"] in (0, "0") and float(sec["answers"]["length_lf"]) == 290
    assert not any("Drive" in li["description"] for li in sec["lines"] if float(li["quantity"] or 0))
    shorter = [[30, 70], [0, 70], [0, 150], [100, 150]]                    # 210 lf
    fake.text = [json.dumps(_fence(shorter, [walk]))]
    runs.change(db, CTX, est, "plans", "drop the right side too")
    out = runs.approve(db, CTX, est, "plans", confirm=True, keep_approved=False)
    assert out["status"] == "approved", out
    length = [m for m in _m(db, est, "length_lf") if m["status"] == "approved"][-1]
    assert float(length["qty"]) == 210 and length["suggested_qty"] is None
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert float(sec["answers"]["length_lf"]) == 210
    # Approve automatically: the next drawing is approved as soon as it's drawn
    fake.text = [json.dumps(_fence(shorter, [walk], height=8))]
    job = runs.change(db, CTX, est, "plans", "make it 8 ft", auto_approve=True)
    assert job["status"] == "approved" and job["approval"]["say"].startswith("Approved automatically")
    assert job["approved_rev"] == 4 and job["auto_approve"] is True
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert str(sec["answers"]["height"]) == "8"
    # 🗑 Discard a drawing that wasn't approved: the approved one goes back on the Measure screen, its proposals go
    fake.text = [json.dumps(_fence(short, [walk], height=8))]
    job = runs.change(db, CTX, est, "plans", "put the right side back", auto_approve=False)
    assert job["status"] == "proposed" and job["placed"]["rev"] == 5
    assert float(_m(db, est, "length_lf")[-1]["suggested_qty"]) == 290
    runs.discard(db, CTX, est, "plans")
    st = runs.load(est, "plans")
    assert st["placed"]["rev"] == 4 and runs.on_measure(est)["waiting"] is None
    length = [m for m in _m(db, est, "length_lf") if m["status"] == "approved"][-1]
    assert float(length["qty"]) == 210 and length["suggested_qty"] is None
    assert not [m for m in _m(db, est, "length_lf") if m["status"] == "proposed"]
    live = [r[0] for r in db.execute("SELECT id FROM plan_sets WHERE estimate_id = ?", (est,))]
    assert live == st["placed"]["plan_set_ids"]


def test_every_note_and_where_each_gate_is_go_on_the_sheet(db, fake):                     # DP-15
    """2026-11-27 (David: "I asked AI Design to make the gates 4 ft from the house and make the gate latch closes to the
    house and obey the pool fence safety laws. But the image did not show the new dimensions of the gate location or the
    new notes"): the sheet left out every note that named a gate, a fence or a wall (so the plan reader wouldn't count
    them), kept 8 notes, cut each at 240 characters, and showed no gate position. Now every note is on the sheet, whole,
    each gate has its posts and a dimension from the end of its fence - and the plan reader still counts 1 + 1 gates."""
    from estimator.design import draw_plans
    _on(db)
    est = _fence_project(db)
    job = fence_job()
    long = "POST INSTALL, CORE-DRILLED AND CEMENTED: " + "LAY OUT POST CENTERS WITH A STRING LINE AND CHECK THEM. " * 6
    job["notes"] = ["GATE LOCATION: each gate opening starts 13 ft from the fence end; the latch post is nearest the house",
                    "CHILD-SAFETY GATES: self-closing and self-latching, opening outward away from the pool",
                    "LATCH: magnetic top-pull latch 54 in or more above the deck",
                    "ALL FENCE AND WALL TIE-INS WITH STAINLESS ANCHORS", long] + [f"EXTRA NOTE {i}" for i in range(8)]
    fake.text = [json.dumps(job)]
    runs.start(db, CTX, est, "plans", ASK, None)
    assert runs.load(est, "plans")["design"]["notes"][4] == long.strip()                     # not cut at 240 characters
    doc = ezdxf.readfile(runs.sheet_path(est, 1, "site"))
    words = [t.dxf.text for t in doc.modelspace().query("TEXT")]
    said = " ".join(" ".join(words).split())
    for n in ("GATE LOCATION: EACH GATE OPENING", "CHILD-SAFETY GATES", "LATCH: MAGNETIC", "STAINLESS ANCHORS",
              "EXTRA NOTE 7", "CHECK THEM. LAY OUT POST CENTERS"):
        assert n in said, n
    assert {t.dxf.layer for t in doc.modelspace().query("TEXT") if "CHILD-SAFETY" in t.dxf.text} == {"A-ANNO-NOTE"}
    # where each gate is: from the end of the fence line - the walk gate 13 ft, the drive gate 9 ft (its 12 ft opening)
    dims = [t.dxf.text for t in doc.modelspace().query("TEXT") if t.dxf.layer == "L-ANNO-DIMS"]
    assert draw_plans.ft_in(13) in dims and draw_plans.ft_in(9) in dims
    assert not [d for d in dims if "GATE" in d.upper()]                         # never read as another gate
    # approved: the plan reader still counts one walk gate and one drive gate - the gate notes aren't gates
    out = runs.approve(db, CTX, est, "plans", confirm=True)
    assert out["status"] == "approved" and out["error"] is None, out
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "fencing")
    assert sec["answers"]["walk_gates"] in (1, "1") and sec["answers"]["drive_gates"] in (1, "1")
    assert float(sec["answers"]["length_lf"]) == 320.0 and sec["answers"]["material"] == "wood"


def test_gates_show_their_latch_hinge_and_swing(tmp_path):                                 # DP-16
    """2026-11-27 (David: "Yes, can you add those changes to show more fence details"): the AI says each gate's latch post
    and the side it opens into; the sheet marks LATCH and HINGE at the posts and draws each leaf open with its swing arc
    (a double drive gate: a leaf from each post). The gate's dimension moves to the other side of the fence. Without
    them nothing is guessed. And the plan reader still counts exactly the 2 gates."""
    from estimator.design import describe as dsc
    from estimator.design import draw_plans
    from estimator.plan_engine import dxf_reader
    job = fence_job()                     # the walk gate at (15, 70) and the drive gate at (85, 70) on the y = 70 line
    job["gates"][0].update({"latch_at": [13, 70], "opens_toward": [15, 74]})           # latches west, opens into the yard
    job["gates"][1].update({"latch_at": None, "opens_toward": [85, 76]})                # a double drive gate, into the yard
    # 2026-11-27 (David: "we're gonna need to know the actual fence model in size on the drawing"): what the customer
    # picked goes in the FENCE AND GATE SCHEDULE; what wasn't picked says TO BE SELECTED
    job["fences"][0]["product"] = {"manufacturer": "Acme Fence", "model": "Pool Pro 200", "panel": "54 in x 6 ft",
                                   "color": "black", "details": ""}
    job["gates"][0]["product"] = {"manufacturer": "Acme Fence", "model": "PG-4", "color": "black",
                                  "hinges": "self-closing spring hinges", "latch": ""}
    design = dsc.parse_design(json.dumps(job))
    assert design["gates"][0]["latch_at"] == [13, 70] and design["gates"][1]["latch_at"] is None
    path = tmp_path / "C-101 SITE PLAN.dxf"
    draw_plans.draw_site(design, str(path), "Test")
    msp = ezdxf.readfile(path).modelspace()
    texts = [(t.dxf.text, t.dxf.layer, t.dxf.insert) for t in msp.query("TEXT")]
    latch = [p for s, _l, p in texts if s == "LATCH"]
    hinge = [p for s, _l, p in texts if s == "HINGE"]
    assert len(latch) == 1 and len(hinge) == 3                    # walk: 1 latch + 1 hinge; drive: a hinge at each post
    assert latch[0].x < 13 and latch[0].y > 70                    # beyond the latch post (x 13), on the yard side
    arcs = [e for e in msp.query("ARC") if e.dxf.layer == "L-GATE"]
    assert len(arcs) == 3                                         # the walk leaf + the drive gate's two leaves
    walk = next(e for e in arcs if abs(e.dxf.radius - 4) < 0.01)
    assert (round(walk.dxf.center.x, 2), round(walk.dxf.center.y, 2)) == (17.0, 70.0)          # hung on the hinge post
    assert (round(walk.dxf.start_angle) % 360, round(walk.dxf.end_angle) % 360) == (90, 180)    # swings into the yard
    assert sorted(round(e.dxf.radius, 2) for e in arcs) == [4.0, 6.0, 6.0]
    # the walk gate's 13 ft dimension is on the house side now (the gate swings into the yard)
    dim = next(p for s, lay, p in texts if lay == "L-ANNO-DIMS" and s == draw_plans.ft_in(13))
    assert dim.y < 70
    assert not [s for s, lay, _p in texts if "GATE" in s.upper() and s not in ("4' WALK GATE", "12' DBL DRIVE GATE")
                and lay != "A-ANNO-NOTE"]                          # only the gate labels - and the schedule's notes layer
    assert {s for s, lay, _p in texts if lay == "L-ANNO-GATE" and s.startswith("G")} == {"G1", "G2"}
    sched = " ".join(" ".join(s for s, lay, _p in texts if lay == "A-ANNO-NOTE").split())
    assert "FENCE AND GATE SCHEDULE" in sched
    assert ("RUN 1: 320.0 LF - 6'-0\" WOOD PRIVACY - PRODUCT: ACME FENCE POOL PRO 200 - PANELS: 54 IN X 6 FT - COLOR: BLACK"
            in sched)
    assert ("G1: 4' WALK GATE - PRODUCT: ACME FENCE PG-4 - COLOR: BLACK - HINGES: SELF-CLOSING SPRING HINGES - LATCH: TO BE"
            " SELECTED") in sched
    assert "G2: 12' DOUBLE DRIVE GATE - PRODUCT: TO BE SELECTED - COLOR: TO BE SELECTED - HINGES: TO BE SELECTED" in sched
    sheet = (lambda r: (r.get("sheets") or [r])[0])(dxf_reader.read(path, tmp_path, 1))
    gates = [o for o in sheet["objects"] if o.get("layer") == "SITE-GATE"]
    assert sorted(o["label"].split(" · ")[0] for o in gates) == ["1 drive gate", "1 walk gate"]
    # an old design (no latch or swing): the gates are drawn as before, nothing guessed
    plain = dsc.parse_design(json.dumps(fence_job()))
    assert plain["gates"][0]["latch_at"] is None and plain["gates"][0]["opens_toward"] is None
    draw_plans.draw_site(plain, str(tmp_path / "plain.dxf"), "Test")
    pm = ezdxf.readfile(tmp_path / "plain.dxf").modelspace()
    assert len(pm.query("ARC")) == 0 and not [t for t in pm.query("TEXT") if t.dxf.text in ("LATCH", "HINGE")]


def _demo_job(permit=True):
    """A kitchen gut with nothing to draw - only the estimate to fill in (the demolition trade's own questions)."""
    return {"summary": "Gut the 200 sq ft kitchen to the studs", "assumptions": ["about 25 ft of cabinets"],
            "lot": None, "building": None, "fences": [], "gates": [], "zones": [], "flatwork": [], "fixtures": [],
            "demolition": [{"what": "tear out the kitchen cabinets", "qty": 25, "unit": "lf"}],
            "trade_answers": {"demolition": {"interior_sqft": 200, "level": "Gut to the studs", "cabinets_lf": 25,
                                             "fixtures": 1, "flooring_sqft": 200, "floor_type": "marble",
                                             "walls_lf": 99999, "bogus": 5, "permit": permit, "inspections": 2}}}


def test_run_ai_design_without_a_drawing_fills_in_and_prices_the_trade(db, fake):          # DP-17
    """2026-11-27 (David: "I am doing a Demolition estimate, but that job does not need a drawing like other jobs. The
    draw the plans button should say run AI Design and add a selection to draw plans and other options like include
    pricing and inspections ... this can be the same for all trades"). A demolition-only project doesn't draw by default;
    the AI answers the trade's own questions, the ones it doesn't take are dropped and said, permits stay out unless
    asked for, and approving prices it - no plans drawn."""
    from estimator.design import trade_answers
    _on(db)
    est = _fence_project(db, quote=("demolition",))
    opts = runs.options(db, CTX, est)
    assert opts["do_default"] == {"draw": False, "price": True, "permits": False}
    fake.text = [json.dumps(_demo_job())]
    job = runs.start(db, CTX, est, "plans", "Gut the 10 x 20 kitchen to the studs, 25 ft of cabinets, one sink", None)
    assert job["status"] == "proposed" and job["error"] is None, job
    assert job["do"] == {"draw": False, "price": True, "permits": False}
    prompt = fake.calls[0][1]
    assert '"demolition" - Demolition' in prompt and '"interior_sqft"' in prompt and "NOT drawn" in prompt
    assert '"permit" (' not in prompt and '"inspections" (' not in prompt               # permits weren't asked for
    assert job["sheets"] == [] and not job["has_drawings"]
    assert db.execute("SELECT COUNT(*) FROM plan_sets WHERE estimate_id = ?", (est,)).fetchone()[0] == 0
    shown = {a["id"]: a["value"] for a in job["trade_answers"][0]["answers"]}
    assert job["trade_answers"][0]["name"] == "Demolition"
    assert shown["interior_sqft"] == "200 sqft" and shown["level"] == "Gut to the studs" and shown["fixtures"] == "1"
    assert "floor_type" not in shown and "walls_lf" not in shown and "permit" not in shown
    said = " ".join(f["message"] for f in job["findings"])
    assert "marble" in said and "bogus" in said and "99999" in said                    # dropped, and said - not guessed
    with pytest.raises(ConfirmationRequired, match="fills in Demolition .* No plans are drawn"):
        runs.approve(db, CTX, est, "plans")
    out = runs.approve(db, CTX, est, "plans", confirm=True)
    assert out["status"] == "approved" and out["error"] is None, out
    assert "filled in demolition from the description" in out["approval"]["say"]
    sec = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "demolition")
    a = sec["answers"]
    assert float(a["interior_sqft"]) == 200 and a["level"] == "gut" and float(a["cabinets_lf"]) == 25
    assert int(a["fixtures"]) == 1 and not a.get("permit") and sec["lines"]
    # the answers the trade takes, and what it doesn't
    mod = __import__("estimator.modules", fromlist=["get_registry"]).get_registry().modules["demolition"]
    ans, dropped = trade_answers.clean(mod, {"permit": "yes", "inspections": "2", "level": "x"}, permits=True)
    assert ans == {"permit": True, "inspections": 2} and len(dropped) == 1


def test_run_ai_design_permits_and_choices(db, fake):                                      # DP-18
    """Include permits and inspections: the AI answers them and they're priced; nothing ticked to do is refused; a fence
    project still draws by default and its drawing prices the fence (the AI's answers only add the permit)."""
    _on(db)
    est = _fence_project(db, quote=("demolition",))
    fake.text = [json.dumps(_demo_job(permit=True))]
    job = runs.start(db, CTX, est, "plans", "Gut the kitchen to the studs and pull the permit", None,
                     do={"permits": True})
    assert job["do"]["permits"] and '"permit" (' in fake.calls[0][1]
    shown = {a["id"]: a["value"] for a in job["trade_answers"][0]["answers"]}
    assert shown["permit"] == "yes" and shown["inspections"] == "2"
    runs.approve(db, CTX, est, "plans", confirm=True)
    a = next(s for s in service.get_estimate(db, CTX, est)["sections"] if s["module_id"] == "demolition")["answers"]
    assert a["permit"] in (True, "true", 1) and int(a["inspections"]) == 2
    with pytest.raises(InvalidInput, match="pick what AI design should do"):
        runs.start(db, CTX, est, "plans", "Gut the kitchen to the studs", None, do={"draw": False, "price": False})
    # a fence: drawn by default; the drawing prices the fence, the AI's answers only add the permit
    fe = _fence_project(db)
    assert runs.options(db, CTX, fe)["do_default"]["draw"] is True
    job = fence_job()
    job["trade_answers"] = {"fencing": {"length_lf": 999, "permit": True}}
    fake.text = [json.dumps(job)]
    j = runs.start(db, CTX, fe, "plans", ASK, None, do={"permits": True})
    assert j["sheets"] and j["do"] == {"draw": True, "price": True, "permits": True}
    runs.approve(db, CTX, fe, "plans", confirm=True)
    a = next(s for s in service.get_estimate(db, CTX, fe)["sections"] if s["module_id"] == "fencing")["answers"]
    assert float(a["length_lf"]) == 320.0 and a["permit"] in (True, "true", 1)       # the drawing's length, the AI's permit


def test_who_can_and_what_it_needs(db, fake):                                              # DP-06
    _on(db)
    est = _fence_project(db)
    with pytest.raises(InvalidInput):
        runs.start(db, CTX, est, "plans", "fence", None)                 # too short to design from
    with pytest.raises(InvalidInput):
        runs.approve(db, CTX, est, "plans", confirm=True)                # nothing proposed yet
