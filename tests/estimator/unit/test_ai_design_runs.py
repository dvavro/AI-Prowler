"""AI design jobs (estimator/design/runs.py): start -> proposed -> change -> approve (plan sets) / discard. A fake provider
stands in for Claude - no real API calls, no token cost. The job runs in the test's thread (RUN_INLINE)."""
import json

import pytest

ezdxf = pytest.importorskip("ezdxf")
from estimator.agents import ai_log, providers, roles  # noqa: E402
from estimator.context import RequestContext, personal_context  # noqa: E402
from estimator.design import runs  # noqa: E402
from estimator.drawing_model import store  # noqa: E402
from estimator.errors import ConfirmationRequired, InvalidInput, PermissionDenied  # noqa: E402
from estimator.estimating import service  # noqa: E402
from test_ai_design import SHED, shed_design  # noqa: E402

CTX = personal_context()
NOW = "2026-11-21T10:00:00+00:00"
ASK = "Here's my shed. Add LED lighting, 20 A receptacles, a 240 V 30 A receptacle and a 100 A subpanel."


class Fake:
    def __init__(self):
        self.keys = {"claude_api": True, "grok_api": True}
        self.text, self.vision, self.calls = [], [], []

    def ready(self, provider):
        return (True, "") if self.keys.get(provider) else (False, "no API key saved")

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3"}[provider]

    def ask(self, provider, system, user, model=""):
        self.calls.append(("ask", user))
        r = self.text.pop(0) if self.text else "{}"
        if isinstance(r, Exception):
            raise r
        return r, {"input": 6000, "output": 3000}

    def ask_vision(self, provider, system, user, images, model=""):
        self.calls.append(("vision", user, len(images)))
        r = self.vision.pop(0) if self.vision else "{}"
        return r, {"input": 9000, "output": 800}

    def cost(self, model, usage):
        return round((usage["input"] * 2 + usage["output"] * 10) / 1_000_000, 5)


@pytest.fixture
def fake(monkeypatch):
    f = Fake()
    providers.set_provider(f)
    monkeypatch.setattr(runs, "RUN_INLINE", True)
    yield f
    providers.set_provider(None)


def _on(db):
    roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api"}, confirm=True)


def _walls_dxf(path):
    """The shed as a CAD drawing: exterior walls with the door gaps, the roll-up doors drawn, the room name."""
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 2
    msp = doc.modelspace()
    for a, b in (((0, 0), (2, 0)), ((14, 0), (16, 0)), ((28, 0), (30, 0)), ((44, 0), (46, 0)), ((0, 45), (7, 45)),
                 ((10, 45), (17, 45)), ((29, 45), (46, 45)), ((0, 0), (0, 1)), ((0, 4), (0, 45)), ((46, 0), (46, 45))):
        msp.add_line(a, b, dxfattribs={"layer": "A-WALL-EXT"})
    for x0, x1, y in ((2, 14, 0), (16, 28, 0), (30, 44, 0), (17, 29, 45)):
        msp.add_lwpolyline([(x0, y), (x1, y), (x1, y + 0.3), (x0, y + 0.3)], close=True, dxfattribs={"layer": "A-DOOR"})
    msp.add_text("SHOP", height=1, dxfattribs={"layer": "A-TEXT", "insert": (23, 27)})
    doc.saveas(path)
    return str(path)


@pytest.fixture
def shed(db, tmp_path):
    est = service.create_estimate(db, CTX, "NSB Shed electrical")["id"]
    ps = store.upload(db, CTX, est, _walls_dxf(tmp_path / "shed.dxf"), confirm=True)["plan_set_id"]
    return {"est": est, "ps": ps}


def test_a_design_from_a_cad_drawing_is_proposed_not_priced(db, fake, shed):             # AR-01
    _on(db)
    fake.text = [json.dumps(shed_design())]
    job = runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])
    assert job["status"] == "proposed" and job["error"] is None
    assert [c[0] for c in fake.calls] == ["ask"]                    # a CAD drawing: no picture is read
    assert ASK in fake.calls[0][1] and '"outline":[[0,0],[46' in fake.calls[0][1].replace(".0", "")
    assert job["building"]["source"] == "dxf" and job["building"]["size"] == "46' x 45'"
    assert job["counts"]["total"] == 46 and job["counts"]["circuits"] == 6 and job["errors"] == 0
    assert job["can_approve"] and job["has_drawings"] and job["rev"] == 1
    assert runs.drawing(shed["est"], "electrical", "plan").is_file()
    # 2026-11-25 (David: "the updated plans ... should be the default viewed plans in any viewer"): the plan and panel
    # schedule are on the Measure screen at once and every device is counted - as proposals; nothing is priced yet
    assert job["placed"]["rev"] == 1 and len(job["placed"]["plan_set_ids"]) == 2 and job["approved_rev"] is None
    st = {r[0] for r in db.execute("SELECT status FROM measurements WHERE estimate_id = ?", (shed["est"],))}
    assert st == {"proposed"}
    assert not service.get_estimate(db, CTX, shed["est"])["sections"]
    log = db.execute("SELECT purpose, ok, estimate_id FROM ai_log ORDER BY id DESC LIMIT 1").fetchone()
    assert tuple(log) == ("AI design: electrical design", 1, shed["est"])
    assert job["cost_usd"] > 0


def test_a_design_with_code_errors_gets_one_fix_turn(db, fake, shed):                    # AR-02
    _on(db)
    bad = shed_design()
    bad["devices"] = [d for d in bad["devices"] if d["type"] != "outlet_gfci"]       # no GFCI anywhere: errors
    fake.text = [json.dumps(bad), json.dumps({**shed_design(), "changes": ["added a GFCI first on each circuit"]})]
    job = runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])
    assert len(fake.calls) == 2 and "Fix these problems" in fake.calls[1][1] and "GFCI" in fake.calls[1][1]
    assert job["errors"] == 0 and job["revisions"][-1]["auto_fixed"] is True


def test_change_it_in_plain_words(db, fake, shed):                                        # AR-03
    _on(db)
    fake.text = [json.dumps(shed_design())]
    runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])
    more = shed_design()
    more["devices"].append({"type": "outlet", "x": 20, "y": 45, "floor": 0, "circuit": "C-2"})
    more["changes"] = ["added a receptacle on the rear wall at x 20 (C-2)"]
    fake.text = [json.dumps(more)]
    job = runs.change(db, CTX, shed["est"], "electrical", "add one more outlet on the rear wall")
    assert "add one more outlet on the rear wall" in fake.calls[-1][1] and "THE CURRENT DESIGN" in fake.calls[-1][1]
    assert job["rev"] == 2 and job["counts"]["devices"]["outlet"] == 11
    assert job["design"]["changes"] == ["added a receptacle on the rear wall at x 20 (C-2)"]
    # a change the AI can't answer keeps the design that was there
    fake.text = ["sorry, I can't"]
    job = runs.change(db, CTX, shed["est"], "electrical", "make it nicer")
    assert job["status"] == "proposed" and job["rev"] == 2 and "didn't go through" in job["error"]


def test_approve_makes_plan_sets_and_asks_first(db, fake, shed):                          # AR-04
    _on(db)
    fake.text = [json.dumps(shed_design())]
    runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])
    with pytest.raises(ConfirmationRequired, match="46 devices on 6 circuits"):
        runs.approve(db, CTX, shed["est"], "electrical")
    out = runs.approve(db, CTX, shed["est"], "electrical", confirm=True)
    ids = out["approved_plan_set_ids"]
    names = [db.execute("SELECT original_name FROM plan_sets WHERE id = ?", (i,)).fetchone()[0] for i in ids]
    assert names == ["AI design - electrical plan.dxf", "AI design - electrical panel schedule.dxf"]
    assert out["status"] == "approved"
    # the design's plan sets aren't offered as a building to design on
    assert [p["id"] for p in runs.plan_sets(db, CTX, shed["est"])] == [shed["ps"]]
    # changed and approved again: the new drawings replace the ones it made
    fake.text = [json.dumps(shed_design())]
    runs.change(db, CTX, shed["est"], "electrical", "move nothing")
    out2 = runs.approve(db, CTX, shed["est"], "electrical", confirm=True)
    left = {r[0] for r in db.execute("SELECT id FROM plan_sets WHERE estimate_id = ?", (shed["est"],))}
    assert set(out2["approved_plan_set_ids"]) <= left and not set(ids) & left


def test_approving_replaces_the_older_electrical_work_and_prices_it(db, fake, shed, tmp_path):   # AR-08
    """2026-11-23 (David: "it did not use the new AI Design ... I want all the older drawings to be updated along with the
    wiring and estimate ... easy and automatic"): approving puts the design in place of the hand-drawn electrical plan,
    sets aside the old counts, and measures, approves and prices the design - one question, no other clicks."""
    from estimator.design import draw_electrical
    from estimator.drawing_model import engine
    est = shed["est"]
    service.add_trade(db, CTX, est, "electrical", service.get_estimate(db, CTX, est)["rev"])
    engine.start(db, CTX, shed["ps"], confirm=True)                     # the building's drawing, read as usual
    # the older work: a hand-drawn electrical plan (fewer outlets), read, with an approved count on it ...
    old = shed_design()
    old["devices"] = [d for d in old["devices"] if d["type"] != "outlet"][:30]
    old_dxf = tmp_path / "nsb_shed_electrical_plan.dxf"
    draw_electrical.draw_plan(SHED, old, str(old_dxf), "NSB SHED - ELECTRICAL (by hand)")
    old_ps = store.upload(db, CTX, est, str(old_dxf), confirm=True)["plan_set_id"]
    engine.start(db, CTX, old_ps, confirm=True)
    disc = {r[0] for r in db.execute("SELECT discipline FROM sheets WHERE plan_set_id = ?", (old_ps,))}
    assert disc == {"electrical"}
    old_sheet = db.execute("SELECT id FROM sheets WHERE plan_set_id = ?", (old_ps,)).fetchone()[0]
    def approved(feeds, qty, sheet):
        return db.execute(
            "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, kind, label, qty, unit,"
            " calc_json, method, status, locked, proposed_by, created_at, updated_at, approved_by, approved_at)"
            " VALUES ('default', ?, 'electrical', ?, ?, 'count', ?, ?, 'ea', '{}', 'ai', 'approved', 1, 'llm-takeoff',"
            " ?, ?, 'owner', ?)", (est, feeds, sheet, feeds, str(qty), NOW, NOW, NOW)).lastrowid
    a = approved("outlets", 7, old_sheet)
    # ... and an electrical count someone made on the architectural sheet
    arch_sheet = db.execute("SELECT id FROM sheets WHERE plan_set_id = ?", (shed["ps"],)).fetchone()[0]
    stray = approved("lights", 20, arch_sheet)
    db.commit()

    _on(db)
    fake.text = [json.dumps(shed_design())]
    runs.start(db, CTX, est, "electrical", ASK, shed["ps"])
    with pytest.raises(ConfirmationRequired) as q:
        runs.approve(db, CTX, est, "electrical")
    said = q.value.message
    assert "replaces the older electrical drawings" in said and "nsb_shed_electrical_plan.dxf" in said
    assert "counts every device, runs the wiring" in said and "updates the estimate's electrical prices" in said
    out = runs.approve(db, CTX, est, "electrical", confirm=True)
    assert out["status"] == "approved" and out["error"] is None, out["error"]
    a_ = out["approval"]
    assert a_["replaced"] == ["nsb_shed_electrical_plan.dxf"] and a_["rejected"] >= 1
    assert a_["counted"] > 0 and a_["wired"] > 0 and a_["approved"] == a_["counted"] + a_["wired"]
    assert a_["estimate"] == "updated" and out["say"].startswith("Approved: replaced nsb_shed_electrical_plan.dxf")
    # the old drawing is gone (replaced by the design's plan), the stray count is set aside, not deleted
    assert db.execute("SELECT COUNT(*) FROM plan_sets WHERE id = ?", (old_ps,)).fetchone()[0] == 0
    new_plan = out["approved_plan_set_ids"][0]
    # the design's drawing went on the project when it was drawn (2026-11-25); approving took the old one away
    assert new_plan == runs.load(est, "electrical")["placed"]["sheets"]["plan"]
    live = {r[0] for r in db.execute("SELECT id FROM plan_sets WHERE estimate_id = ?", (est,))}
    assert live == {shed["ps"], *out["approved_plan_set_ids"]}
    s = db.execute("SELECT status, reject_reason FROM measurements WHERE id = ?", (stray,)).fetchone()
    assert tuple(s) == ("rejected", "replaced by the approved AI design")
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE id = ?", (a,)).fetchone()[0] == 0   # went with its plan
    # the design's counts are what's approved now: 10 receptacles, 20 LED shop lights ... (shed_design)
    got = {r[0]: r[1] for r in db.execute(
        "SELECT feeds, qty FROM measurements WHERE estimate_id = ? AND module_id = 'electrical' AND status = 'approved'",
        (est,))}
    from test_ai_design import shed_design as sd
    n_out = sum(1 for d in sd()["devices"] if d["type"] == "outlet")
    assert float(got["outlets"]) == n_out and any(k.startswith("wire_") for k in got)
    # and the estimate is priced from them
    e = service.get_estimate(db, CTX, est)
    assert (e.get("totals") or {}).get("total_cents", 0) > 0
    from estimator.api.estimate_api import plan_changes
    from estimator.modules import get_registry
    assert not [t for t in plan_changes(db, CTX, e, get_registry()) if t["module_id"] == "electrical"]  # up to date


def _counts(db, est, status="approved"):
    out = {}
    for feeds, qty, calc in db.execute("SELECT feeds, qty, calc_json FROM measurements WHERE estimate_id = ? AND"
                                       " module_id = 'electrical' AND status = ?", (est, status)):
        if json.loads(calc or "{}").get("from") == "plans":
            out[feeds] = float(qty)
    return out


def test_an_electrical_change_is_the_drawing_shown_and_its_counts_take_over(db, fake, shed):   # AR-10
    """2026-11-25 (David: "the updated plans are assumed as the latest and should be the default viewed plans in any
    viewer so the user is not confused what he is approving" - "the electrical and cement as well")."""
    _on(db)
    est = shed["est"]
    service.add_trade(db, CTX, est, "electrical", int(service.get_estimate(db, CTX, est)["rev"]))
    fake.text = [json.dumps(shed_design())]
    runs.start(db, CTX, est, "electrical", ASK, shed["ps"])
    runs.approve(db, CTX, est, "electrical", confirm=True)
    first = runs.load(est, "electrical")["approved_plan_set_ids"]
    before = _counts(db, est)
    # the change: four fewer LED lights, no exterior lights
    fewer = shed_design()
    leds = [i for i, d in enumerate(fewer["devices"]) if d["type"] == "light_led"][:4]
    fewer["devices"] = [d for i, d in enumerate(fewer["devices"]) if i not in leds and d["type"] != "light_exterior"]
    fake.text = [json.dumps(fewer)]
    job = runs.change(db, CTX, est, "electrical", "four fewer shop lights and no exterior lights")
    assert job["status"] == "proposed" and job["placed"]["rev"] == 2 and job["approved_rev"] == 1
    live = {r[0] for r in db.execute("SELECT id FROM plan_sets WHERE estimate_id = ?", (est,))}
    assert live == {shed["ps"], *job["placed"]["plan_set_ids"]} and not live & set(first)   # the new drawing, shown
    seen = runs.on_measure(est)
    assert seen["waiting"] == {"trade": "electrical", "rev": 2, "approved_rev": 1, "on_screen": True}
    sug = {r[0]: (float(r[1]), r[2] or "") for r in db.execute(
        "SELECT feeds, suggested_qty, suggested_reason FROM measurements WHERE estimate_id = ? AND module_id = 'electrical'"
        " AND status = 'approved' AND suggested_qty IS NOT NULL", (est,))}
    assert any(q == 0 and runs.GONE in why for q, why in sug.values())                     # exterior lights: gone
    assert any(0 < q < before[f] for f, (q, why) in sug.items())                           # fewer shop lights
    assert _counts(db, est) == before                                                      # not priced until approved
    out = runs.approve(db, CTX, est, "electrical", confirm=True)
    assert out["status"] == "approved" and out["approval"]["removed"] >= 1 and out["approval"]["changed"] >= 1, out
    after = _counts(db, est)
    gone = [f for f, (q, _w) in sug.items() if q == 0]
    assert all(f not in after for f in gone) and all(after[f] == q for f, (q, _w) in sug.items() if q)
    e = service.get_estimate(db, CTX, est)
    sec = next(s for s in e["sections"] if s["module_id"] == "electrical")
    assert all(str(sec["answers"].get(f) or 0) in ("0", "0.0") for f in gone)               # priced as none
    # 🗑 Discard a change that wasn't approved: revision 2's drawing is back, its counts as they were
    fake.text = [json.dumps(shed_design())]
    runs.change(db, CTX, est, "electrical", "put the exterior lights back")
    assert runs.load(est, "electrical")["placed"]["rev"] == 3
    runs.discard(db, CTX, est, "electrical")
    st = runs.load(est, "electrical")
    assert st["placed"]["rev"] == 2 and runs.on_measure(est)["waiting"] is None
    assert _counts(db, est) == after and not _counts(db, est, "proposed")
    assert not db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND module_id = 'electrical' AND"
                          " status = 'approved' AND suggested_qty IS NOT NULL", (est,)).fetchone()[0]


def test_a_design_approved_the_old_way_can_be_put_in_place(db, fake, shed):                 # AR-09
    """A design approved before 2026-11-23 only became plan sets (the older drawings stayed, nothing was measured): it
    can be approved once more, and that does the rest."""
    _on(db)
    fake.text = [json.dumps(shed_design())]
    runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])
    st = runs.load(shed["est"], "electrical")
    st["status"], st["approved_plan_set_ids"] = "approved", []                # the old kind of approval: no record
    runs.save(st)
    j = runs.get(db, CTX, shed["est"], "electrical")
    assert j["reapply"] and j["can_approve"]
    out = runs.approve(db, CTX, shed["est"], "electrical", confirm=True)
    assert out["status"] == "approved" and out["approval"]["counted"] > 0 and not out["reapply"]
    assert not runs.get(db, CTX, shed["est"], "electrical")["can_approve"]         # once: it's in place now
    with pytest.raises(InvalidInput, match="no proposed AI design"):
        runs.approve(db, CTX, shed["est"], "electrical", confirm=True)


def test_a_design_with_errors_cant_be_approved(db, fake, shed):                           # AR-05
    _on(db)
    bad = shed_design()
    bad["devices"] = [d for d in bad["devices"] if d["type"] != "outlet_gfci"]
    fake.text = [json.dumps(bad), json.dumps(bad)]                     # the fix turn doesn't fix it
    job = runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])
    assert job["errors"] > 0 and not job["can_approve"]
    with pytest.raises(InvalidInput, match="code error"):
        runs.approve(db, CTX, shed["est"], "electrical", confirm=True)
    assert runs.discard(db, CTX, shed["est"], "electrical")["status"] == "discarded"


def test_the_ai_reads_the_building_from_a_pdf(db, fake, tmp_path):                       # AR-06
    from PIL import Image
    _on(db)
    est = service.create_estimate(db, CTX, "Shed from a PDF")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                    " sha256, status, uploaded_by, created_at) VALUES ('default', ?, 'x.pdf', 'shed plans.pdf', 'pdf',"
                    " 1, 'bb', 'processed', 'owner', ?)", (est, NOW)).lastrowid
    for n, title in ((1, "ELEVATIONS"), (2, "FLOOR PLAN")):
        img = tmp_path / f"p{n}.png"
        Image.new("RGB", (600, 400), "white").save(img)
        db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                   " VALUES ('default', ?, ?, ?, ?, ?)", (ps, n, f"A-{n}", title, str(img)))
    fake.vision = [json.dumps(SHED)]
    fake.text = [json.dumps(shed_design())]
    job = runs.start(db, CTX, est, "electrical", ASK, ps)
    assert job["status"] == "proposed", job["error"]
    v = [c for c in fake.calls if c[0] == "vision"]
    assert len(v) == 1 and v[0][2] == 2 and "FLOOR PLAN" in v[0][1].split("\n")[1]     # plan views first
    assert job["building"]["source"] == "ai" and job["building"]["kind"] == "accessory"
    purposes = [r[0] for r in db.execute("SELECT purpose FROM ai_log WHERE estimate_id = ? ORDER BY id", (est,))]
    assert purposes == ["AI design: read the building", "AI design: electrical design"]
    # a change doesn't read the building again
    fake.text = [json.dumps(shed_design())]
    runs.change(db, CTX, est, "electrical", "keep it")
    assert len([c for c in fake.calls if c[0] == "vision"]) == 1


def test_who_and_when(db, fake, shed):                                                    # AR-07
    with pytest.raises(InvalidInput, match="say what you want"):
        runs.start(db, CTX, shed["est"], "electrical", "lights", shed["ps"])
    with pytest.raises(InvalidInput, match="coming"):
        runs.start(db, CTX, shed["est"], "plumbing", ASK, shed["ps"])
    with pytest.raises(PermissionDenied):
        runs.start(db, RequestContext(user_id="o", role="office"), shed["est"], "electrical", ASK, shed["ps"])
    job = runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])            # the AI role is off
    assert job["status"] == "failed" and "AI measuring is off" in job["error"]
    assert runs.options(db, CTX, shed["est"])["ai_on"] is False
    _on(db)
    fake.text = ["not json"]
    job = runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])
    assert job["status"] == "failed" and "JSON" in job["error"]
    assert db.execute("SELECT ok FROM ai_log ORDER BY id DESC LIMIT 1").fetchone()[0] == 0
