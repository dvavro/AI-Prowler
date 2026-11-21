"""Per-project plan numbering (2026-11-19, David): the project page's "#" column shows the
plan set's number within its project (1, 2, ...), not its global database id — and the
sheet titles carry the same number, so the picker agrees with the table.

The sheet-title prefix comes from the stored filename (uploads.stored_name() names the
file "{id}_{stem}"; the DXF reader turns the stem into the title). The serializer swaps
the exact "{id} " prefix for the project number at read time, so deleting a set
renumbers the survivors. Title-block titles (PDF) never carry the prefix and are
untouched.
"""
from pathlib import Path

import pytest

from estimator.context import personal_context
from estimator.drawing_model import store
from estimator.estimating import service

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
NOW = "2026-11-19T08:00:00+00:00"


def _plan_set(db, est, name, file_type):
    return db.execute(
        "INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
        " file_size, sha256, status, uploaded_by, created_at)"
        " VALUES ('default', ?, ?, ?, ?, 1, 'aa', 'processed', 'owner', ?)",
        (est, "x." + file_type, name, file_type, NOW)).lastrowid


def _sheet(db, ps, page_no, title):
    return db.execute(
        "INSERT INTO sheets (company_id, plan_set_id, page_no, title) VALUES ('default', ?, ?, ?)",
        (ps, page_no, title)).lastrowid


@pytest.fixture
def two_projects(db):
    """Another project owns the first three global plan-set ids; the house project owns the
    next three — the panel DXF, the floor-plan DXF, and a PDF whose title-block title
    starts with a number of its own. The stored DXF titles carry the global id, the way
    the reader writes them from the stored filename."""
    ctx = personal_context()
    other = service.create_estimate(db, ctx, "Other job")["id"]
    for i in range(3):
        _plan_set(db, other, f"other_{i}.pdf", "pdf")
    est = service.create_estimate(db, ctx, "House Electrical Test")["id"]
    panel = _plan_set(db, est, "house_wiring_2300sf_panel_wiring.dxf", "dxf")
    floor = _plan_set(db, est, "house_wiring_2300sf_2story_electrical.dxf", "dxf")
    pdf = _plan_set(db, est, "shed.pdf", "pdf")
    assert panel > 3 and floor > 3 and pdf > 3   # the ids are global; the numbers are not
    panel_sheet = _sheet(db, panel, 1, f"{panel} house wiring 2300sf panel wiring")
    floor_sheet = _sheet(db, floor, 1, f"{floor} house wiring 2300sf 2story electrical")
    pdf_sheet = _sheet(db, pdf, 1, "11 TO RAFTER CONNECTION DETAIL")
    return {"est": est, "panel": panel, "floor": floor, "pdf": pdf,
            "panel_sheet": panel_sheet, "floor_sheet": floor_sheet, "pdf_sheet": pdf_sheet}


def test_project_page_numbers_its_plans_from_one(call, two_projects):                      # PN-01
    got = call("GET", f"{API}/estimates/{two_projects['est']}/project").json()
    assert [(p["id"], p["number"]) for p in got["plan_sets"]] == [
        (two_projects["panel"], 1), (two_projects["floor"], 2), (two_projects["pdf"], 3)]
    same = call("GET", f"{API}/estimates/{two_projects['est']}/plans").json()
    assert [p["number"] for p in same["plan_sets"]] == [1, 2, 3]


def test_sheet_titles_carry_the_project_number_not_the_global_id(call, two_projects):      # PN-02
    panel = call("GET", f"{API}/plan-sets/{two_projects['panel']}").json()
    assert [s["title"] for s in panel["sheets"]] == ["1 house wiring 2300sf panel wiring"]
    floor = call("GET", f"{API}/plan-sets/{two_projects['floor']}").json()
    assert [s["title"] for s in floor["sheets"]] == ["2 house wiring 2300sf 2story electrical"]
    # The PDF's title-block title keeps its own number: it never was a plan-set prefix.
    pdf = call("GET", f"{API}/plan-sets/{two_projects['pdf']}").json()
    assert [s["title"] for s in pdf["sheets"]] == ["11 TO RAFTER CONNECTION DETAIL"]
    # The single-sheet read (the Detail tab) agrees with the list.
    one = call("GET", f"{API}/sheets/{two_projects['panel_sheet']}").json()
    assert one["sheet"]["title"] == "1 house wiring 2300sf panel wiring"


def test_deleting_the_first_plan_set_renumbers_the_survivors(call, two_projects):          # PN-03
    done = call("POST", f"{API}/plan-sets/{two_projects['panel']}/remove", {"confirm": True}).json()
    assert done["ok"] is True
    got = call("GET", f"{API}/estimates/{two_projects['est']}/project").json()
    assert [(p["id"], p["number"]) for p in got["plan_sets"]] == [
        (two_projects["floor"], 1), (two_projects["pdf"], 2)]
    floor = call("GET", f"{API}/plan-sets/{two_projects['floor']}").json()
    assert [s["title"] for s in floor["sheets"]] == ["1 house wiring 2300sf 2story electrical"]


def test_display_sheet_title_swaps_only_the_exact_id_prefix():                             # PN-04
    assert store.display_sheet_title("4 house wiring", 4, 1, "dxf") == "1 house wiring"
    assert store.display_sheet_title("4 house wiring", 4, 2, "dwg") == "2 house wiring"
    assert store.display_sheet_title("11 TO RAFTER CONNECTION DETAIL", 2, 1, "pdf") == \
        "11 TO RAFTER CONNECTION DETAIL"
    assert store.display_sheet_title("11 TO RAFTER CONNECTION DETAIL", 11, 1, "pdf") == \
        "11 TO RAFTER CONNECTION DETAIL"   # even when the number matches the id, a PDF title is its own
    assert store.display_sheet_title("FOUNDATION PLAN", 4, 1, "dxf") == "FOUNDATION PLAN"
    assert store.display_sheet_title(None, 4, 1, "dxf") is None
    assert store.display_sheet_title("4 ", 4, 1, "dxf") == "4 "   # nothing left after the prefix: untouched


def test_project_table_and_upload_box_show_the_number():                                   # PN-05
    app = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'el("td", {}, r.number ?? r.id),' in app
    assert '"New revision of #" + (ps.number ?? ps.id)' in app
    # The Plans list page has no "#" column, so it needs no number.
    lines = app.splitlines()
    start = next(j for j, line in enumerate(lines) if "async function renderPlans" in line)
    plans_head = next(line for line in lines[start:] if 'el("th", {}, "Project")' in line)
    assert '"#"' not in plans_head
