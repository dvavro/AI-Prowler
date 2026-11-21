"""2026-11-20 (David: "why AI counted 18 but the highlighted shows 12"): after the plans were read again, an AI Auto
Run count approved on the old sheet lost its sheet, the rerun proposed the new count on the new sheet, and approving the
new one left both approved - so they were priced twice (outlets 41 + 41). Approving the new count now retires the old
one; a typed count, or one still on a sheet, is never touched."""
import json

import pytest

from estimator.context import personal_context
from estimator.errors import ConfirmationRequired
from estimator.estimating import service
from estimator.takeoff import measurements as ms

CTX = personal_context()
NOW = "2026-11-20T00:00:00+00:00"


def _sheet(db, ps, page):
    return db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, title, discipline, units, width, height)"
                      " VALUES ('default', ?, ?, 'E-1', 'electrical', 'ft', '108', '64')", (ps, page)).lastrowid


def _m(db, est, sheet, feeds, qty, status, by="llm-takeoff", method="ai"):
    return db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label, qty,"
        " unit, source_object_ids, calc_json, method, status, locked, proposed_by, created_at, updated_at)"
        " VALUES ('default', ?, 'electrical', ?, ?, NULL, 'count', ?, ?, 'ea', '[]', ?, ?, ?, ?, ?, ?, ?)",
        (est, feeds, sheet, feeds, str(qty), json.dumps({"source": "llm"}), method, status,
         1 if status == "approved" else 0, by, NOW, NOW)).lastrowid


@pytest.fixture
def reread(db):
    est = service.create_estimate(db, CTX, "House Electrical Test")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                    " sha256, status, uploaded_by, created_at) VALUES ('default', ?, 'x.dxf', 'x.dxf', 'dxf', 1, 'aa',"
                    " 'processed', 'owner', ?)", (est, NOW)).lastrowid
    new_sheet = _sheet(db, ps, 1)
    other_sheet = _sheet(db, ps, 2)
    out = {
        "est": est,
        # From before the plans were read again: the old sheet went, so no sheet any more (approved, priced).
        "old_gfci": _m(db, est, None, "gfci", 18, "approved"),
        "old_outlets": _m(db, est, None, "outlets", 41, "approved"),
        # A typed count has no sheet either - it must never be replaced.
        "typed_fans": _m(db, est, None, "fans", 5, "approved", by="owner", method="typed"),
        # Still on a sheet: a real count on another sheet - never replaced.
        "other_sheet_gfci": _m(db, est, other_sheet, "gfci", 2, "approved"),
        # The rerun's new proposals on the new sheet.
        "new_gfci": _m(db, est, new_sheet, "gfci", 12, "proposed"),
        "new_fans": _m(db, est, new_sheet, "fans", 3, "proposed"),
    }
    db.commit()
    return out


def _status(db, mid):
    return db.execute("SELECT status, reject_reason FROM measurements WHERE id = ?", (mid,)).fetchone()


def test_approving_the_new_count_replaces_the_old_one(db, reread):
    with pytest.raises(ConfirmationRequired) as asked:
        ms.confirm_measurements(db, CTX, [reread["new_gfci"]])
    assert "replaces the approved 18 ea from before the plans were read again" in asked.value.message
    out = ms.confirm_measurements(db, CTX, [reread["new_gfci"]], confirm=True)
    assert out["done"] == [reread["new_gfci"]] and out["replaced"] == [reread["old_gfci"]]
    old = _status(db, reread["old_gfci"])
    assert old["status"] == "rejected" and f"replaced by measurement {reread['new_gfci']}" in old["reject_reason"]
    assert _status(db, reread["other_sheet_gfci"])["status"] == "approved"      # a count on another sheet stays
    assert _status(db, reread["old_outlets"])["status"] == "approved"           # another question: untouched
    priced = db.execute("SELECT SUM(CAST(qty AS REAL)) FROM measurements WHERE estimate_id = ? AND feeds = 'gfci'"
                        " AND status = 'approved'", (reread["est"],)).fetchone()[0]
    assert priced == 14                                                         # 12 new + 2 on the other sheet, not 32


def test_a_typed_count_is_never_replaced(db, reread):
    out = ms.confirm_measurements(db, CTX, [reread["new_fans"]], confirm=True)
    assert out["replaced"] == []
    assert _status(db, reread["typed_fans"])["status"] == "approved"


def test_the_old_one_can_be_brought_back(db, reread):
    """The user can still change their mind: the replaced count can be approved again."""
    ms.confirm_measurements(db, CTX, [reread["new_gfci"]], confirm=True)
    ms.confirm_measurements(db, CTX, [reread["old_gfci"]], confirm=True)
    assert _status(db, reread["old_gfci"])["status"] == "approved"
