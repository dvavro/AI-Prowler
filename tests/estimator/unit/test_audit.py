"""Audit & clean up (2026-11-20, David: "an AI Cleanup run that fixes and removes double counted items and 'from before
the plans were read again' issues ... a way to remove [rejected items] ... make sure the user can mass accept all of the
changes"). The estimate below is David's estimate 9 in miniature."""
import json

import pytest

from estimator.context import RequestContext, personal_context
from estimator.errors import ConfirmationRequired, InvalidInput, PermissionDenied
from estimator.estimating import service
from estimator.symbols import results
from estimator.takeoff import audit

CTX = personal_context()
NOW = "2026-11-20T00:00:00+00:00"


def _m(db, est, sheet, feeds, qty, status, by="llm-takeoff", method="ai", reason=None, unit="ea"):
    return db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label, qty,"
        " unit, source_object_ids, calc_json, method, status, locked, reject_reason, proposed_by, created_at, updated_at)"
        " VALUES ('default', ?, 'electrical', ?, ?, NULL, 'count', ?, ?, ?, '[]', ?, ?, ?, ?, ?, ?, ?, ?)",
        (est, feeds, sheet, feeds.replace("_", " ") + " (AI)", str(qty), unit, json.dumps({"source": "llm"}), method,
         status, 1 if status == "approved" else 0, reason, by, NOW, NOW)).lastrowid


def _symbols(db, ps, sheet, item_type, n, method="cad"):
    for i in range(n):
        results.insert_detection(db, "default", ps, sheet_id=sheet, object_id=None, definition_id=None, viewport_id=None,
                                 room_id=None, item_type=item_type, trade="electrical", label=item_type,
                                 point=(i, 1), bbox=None, rotation=None, mirrored=False, method=method,
                                 scores={"cad": 0.95}, confidence=0.95, needs_review=False, origin="engine", now=NOW)


@pytest.fixture
def est9(db):
    est = service.create_estimate(db, CTX, "House Electrical Test")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                    " sha256, status, uploaded_by, created_at) VALUES ('default', ?, 'x.dxf', 'x.dxf', 'dxf', 1, 'aa',"
                    " 'processed', 'owner', ?)", (est, NOW)).lastrowid
    sheet = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, title, discipline, units, width, height)"
                       " VALUES ('default', ?, 1, 'E-1', 'electrical', 'ft', '108', '64')", (ps,)).lastrowid
    _symbols(db, ps, sheet, "duplex_receptacle", 41)
    _symbols(db, ps, sheet, "duplex_receptacle_gfci", 12)
    _symbols(db, ps, sheet, "switch", 16)
    _symbols(db, ps, sheet, "ceiling_fan", 5)
    _symbols(db, ps, sheet, "light_wall", 4)
    j = {
        "est": est, "sheet": sheet,
        # priced twice: the old outlets (sheet gone) and the new ones, both approved
        "old_outlets": _m(db, est, None, "outlets", 41, "approved"),
        "new_outlets": _m(db, est, sheet, "outlets", 41, "approved"),
        # an old GFCI count, the new one waiting (the AI said 18; the drawing shows 12)
        "old_gfci": _m(db, est, None, "gfci", 18, "approved"),
        "new_gfci": _m(db, est, sheet, "gfci", 18, "proposed"),
        # waiting, and the AI is wrong: the drawing shows 16
        "switches": _m(db, est, sheet, "switches", 14, "proposed"),
        # waiting, and the drawing agrees
        "fans": _m(db, est, sheet, "fans", 5, "proposed"),
        # waiting, nothing on the drawing to compare with: not ticked
        "exterior": _m(db, est, sheet, "exterior_lights", 2, "proposed"),
        # approved, but the drawing shows 4
        "wall": _m(db, est, sheet, "wall_lights", 6, "approved"),
        # old cable, nothing new measured: run the wiring again
        "old_cable": _m(db, est, None, "wire_12_2_ft", "2071.5", "approved", by="wiring-takeoff", unit="ft"),
        # a typed count without a sheet is the person's: never touched
        "typed": _m(db, est, None, "dimmers", 1, "approved", by="owner", method="typed"),
        "rej1": _m(db, est, None, "lights", 15, "rejected", reason="the plans were read again"),
        "rej2": _m(db, est, sheet, "recessed_lights", 4, "rejected", reason="rejected in review"),
    }
    db.commit()
    return j


def _status(db, mid):
    r = db.execute("SELECT status, qty FROM measurements WHERE id = ?", (mid,)).fetchone()
    return None if r is None else (r["status"], float(r["qty"]))


def test_the_audit_finds_every_problem(db, est9):
    out = audit.audit(db, CTX, est9["est"])
    f = {x["id"]: x for x in out["findings"]}
    assert [x["kind"] for x in out["findings"]][:1] == ["double_counted"]           # the costly ones first
    dbl = f[f"double:{est9['old_outlets']}"]
    assert dbl["selected"] and dbl["reject_ids"] == [est9["old_outlets"]] and "82 ea" in dbl["detail"]
    rep = f[f"replace:{est9['old_gfci']}"]
    assert rep["selected"] and rep["approve_ids"] == [est9["new_gfci"]] and rep["set_qty"] == {str(est9["new_gfci"]): "12"}
    assert "Approve 12 ea (the 12 on the drawing; the AI said 18)" in rep["fix"]
    sw = f[f"waiting:{est9['switches']}"]
    assert sw["selected"] and sw["set_qty"] == {str(est9["switches"]): "16"}             # CAD: the drawing's number
    assert f[f"waiting:{est9['fans']}"]["selected"] and f[f"waiting:{est9['fans']}"]["set_qty"] == {}
    ext = f[f"waiting:{est9['exterior']}"]
    assert not ext["selected"] and "nothing for it on the drawing" in ext["detail"]       # a person looks first
    wall = f[f"differs:{est9['wall']}"]
    assert wall["selected"] and wall["set_qty"] == {str(est9["wall"]): "4"}
    rerun = f[f"rerun:{est9['old_cable']}"]
    assert not rerun["can_fix"] and "wiring" in rerun["advice"]
    rej = f["rejected"]
    assert rej["selected"] and sorted(rej["delete_ids"]) == sorted([est9["rej1"], est9["rej2"]])
    assert not any(est9["typed"] in (x["reject_ids"] + x["approve_ids"]) for x in out["findings"])
    assert "priced twice" in out["summary"]


def test_apply_all_ticked_fixes_in_one_go(db, est9):
    out = audit.audit(db, CTX, est9["est"])
    ticked = [x["id"] for x in out["findings"] if x["selected"]]
    with pytest.raises(ConfirmationRequired):
        audit.apply(db, CTX, est9["est"], ticked)
    done = audit.apply(db, CTX, est9["est"], ticked, confirm=True)
    # The old counts are taken off - and, with "remove rejected items" ticked too, gone (no fresh clutter left behind).
    assert _status(db, est9["old_outlets"]) is None and _status(db, est9["new_outlets"]) == ("approved", 41)
    assert _status(db, est9["new_gfci"]) == ("approved", 12) and _status(db, est9["old_gfci"]) is None
    assert _status(db, est9["switches"]) == ("approved", 16) and _status(db, est9["fans"]) == ("approved", 5)
    assert _status(db, est9["wall"]) == ("approved", 4)
    assert _status(db, est9["exterior"]) == ("proposed", 2)                                # not ticked: untouched
    assert _status(db, est9["rej1"]) is None and _status(db, est9["rej2"]) is None          # removed for good
    assert _status(db, est9["typed"]) == ("approved", 1) and _status(db, est9["old_cable"])[0] == "approved"
    assert "approved" in done["summary"] and "removed" in done["summary"]
    # Priced once each now.
    for feeds, want in (("outlets", 41), ("gfci", 12), ("switches", 16), ("wall_lights", 4)):
        got = db.execute("SELECT SUM(CAST(qty AS REAL)) FROM measurements WHERE estimate_id = ? AND feeds = ? AND"
                         " status = 'approved'", (est9["est"], feeds)).fetchone()[0]
        assert got == want, feeds
    # The audit again: only what a person has to decide is left.
    left = {x["kind"] for x in audit.audit(db, CTX, est9["est"])["findings"]}
    assert left == {"waiting", "rerun"}
    actions = [r["action"] for r in db.execute("SELECT action FROM estimate_events WHERE estimate_id = ?", (est9["est"],))]
    assert "measurements_audited" in actions and "measurement_deleted" in actions


def test_without_removing_rejected_the_old_counts_stay_as_history(db, est9):
    ids = [x["id"] for x in audit.audit(db, CTX, est9["est"])["findings"] if x["kind"] == "double_counted"]
    audit.apply(db, CTX, est9["est"], ids, confirm=True)
    assert _status(db, est9["old_outlets"])[0] == "rejected" and _status(db, est9["rej1"])[0] == "rejected"


def test_only_a_person_who_approves_applies(db, est9):
    ids = [x["id"] for x in audit.audit(db, CTX, est9["est"])["findings"] if x["selected"]]
    agent = RequestContext(company_id="default", user_id="bot", role="estimator", mode=CTX.mode, agent="director")
    with pytest.raises(PermissionDenied):
        audit.apply(db, agent, est9["est"], ids, confirm=True)
    with pytest.raises(InvalidInput):
        audit.apply(db, CTX, est9["est"], ["nope:1"], confirm=True)                       # nothing like that any more
