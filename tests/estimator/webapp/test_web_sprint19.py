"""Coder 2 Sprint 19: draw the revision cloud/delta marks, and import a supplier price list
from a file (CSV or Excel) instead of pasting it.

Partial 1 finishes the Sprint 17 revision overlay (Spec:452): the comparison counted the
architect's clouds and deltas but never drew them. Now each sheet carries its marks' boxes,
and the overlay draws them in purple, toggleable like the other kinds. Partial 2 finishes the
Sprint 17 Price Book import (Spec:918): the server already read CSV and Excel files, but the
web app could only paste CSV. Now a file is staged, checked, previewed and imported, with a
sheet picker for workbooks. The paste flow is unchanged.
"""
import json
from pathlib import Path

import pytest

from estimator.api import staging
from estimator.context import personal_context
from estimator.drawing_model import revisions, store
from estimator.errors import NotFound
from estimator.estimating import service
from estimator.takeoff import measurements as m

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"

CTX = personal_context()
KEY = "pw_driveway_sqft"
CSV = "Item Code,Description,Unit,Unit Price\npw_driveway_sqft,Driveway,sqft,0.19\nbogus,Nothing like this,ea,5\n"
TOTALS = {"unchanged": 6, "moved": 1, "changed": 1, "removed": 1, "added": 3}
CLOUD_BOX = [11.0, 2.0, 13.0, 4.0]


@pytest.fixture(autouse=True)
def fresh_staging():
    staging.reset()
    yield
    staging.reset()


def pt(x, y):
    return {"type": "point", "points": [[x, y]]}


def poly(x0, y0, x1, y1):
    return {"type": "polygon", "points": [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]}


def PLAN(rev="A", image=None):
    """Rev A, or Rev B with: outlet 3 moved, slab bigger, the GFI removed, a new floor box, D1's size changed,
    a revision cloud, and a new sheet. (Copied from Sprint 17, which copied Coder 1's Sprint 24 fixture.)"""
    b = rev == "B"
    outlets = [{"viewport": "plan", "kind": "symbol", "label": "OUTLET", "block_name": "DUPLEX", "source": "cad",
                "geometry": pt(12 if (b and i == 3) else 2 + i, 3)} for i in range(5)]
    objs = outlets + [
        {"viewport": "plan", "kind": "polygon", "label": "SLAB", "source": "cad",
         "geometry": poly(1, 1, 7 if b else 6, 5)},                               # 20 x 16 ft -> 24 x 16 ft
        {"viewport": "plan", "kind": "polygon", "label": "PORCH", "source": "cad", "geometry": poly(8, 1, 10, 5)},
        {"viewport": "plan", "kind": "opening", "tag": "D1", "label": "door", "source": "cad", "geometry": pt(10, 12)},
    ]
    if not b:
        objs.append({"viewport": "plan", "kind": "symbol", "label": "GFI", "block_name": "GFI", "source": "cad",
                     "geometry": pt(5, 8)})
    else:
        objs += [{"viewport": "plan", "kind": "symbol", "label": "FLOOR BOX", "block_name": "FBOX", "source": "cad",
                  "geometry": pt(15, 15)},
                 {"viewport": "plan", "kind": "polyline", "label": "REV CLOUD", "layer": "REVISION", "source": "cad",
                  "geometry": {"type": "polyline", "points": [[11, 2], [13, 2], [13, 4]]}}]
    sheets = [{"page_no": 1, "sheet_no": "E-101", "title": "POWER PLAN", "discipline": "electrical",
               "units": "paper_in", "width": 36, "height": 24, "image_path": image,
               "viewports": [{"key": "plan", "label": "POWER PLAN", "scale_note": "1/4\" = 1'-0\""}],
               "objects": objs,
               "schedules": [{"schedule_type": "door", "rows": [
                   {"mark": "D1", "fields": {"size": "3'-0\" x 7'-0\"" if b else "3'-0\" x 6'-8\""}}]}]}]
    if b:
        sheets.append({"page_no": 2, "sheet_no": "E-102", "title": "LIGHTING", "discipline": "electrical",
                       "units": "paper_in", "width": 36, "height": 24,
                       "viewports": [{"key": "p", "label": "LIGHTING", "scale_note": "1/4\" = 1'-0\""}],
                       "objects": [{"viewport": "p", "kind": "symbol", "label": "CAN", "source": "cad",
                                    "geometry": pt(3, 3)}]})
    return {"sheets": sheets}


def _cloud_plan():
    """One sheet, one slab, and the same DELTA cloud on both revisions: nothing moves, nothing
    is added or removed, only the mark is there."""
    objs = [{"viewport": "plan", "kind": "polygon", "label": "SLAB", "source": "cad",
             "geometry": poly(1, 1, 6, 5)},
            {"viewport": "plan", "kind": "polyline", "label": "DELTA 1", "layer": "REVISION",
             "source": "cad", "geometry": {"type": "polyline", "points": [[2, 2], [4, 2], [4, 3]]}}]
    return {"sheets": [{"page_no": 1, "sheet_no": "A-101", "title": "PLAN", "discipline": "architectural",
                        "units": "paper_in", "width": 36, "height": 24,
                        "viewports": [{"key": "plan", "label": "PLAN", "scale_note": "1/4\" = 1'-0\""}],
                        "objects": objs}]}


def _pdf(path: Path, pages: int, note: str = "") -> str:
    body = b"".join(b"%d 0 obj << /Type /Page >> endobj\n" % (i + 3) for i in range(pages))
    path.write_bytes(b"%PDF-1.7\n1 0 obj << /Type /Pages >> endobj\n" + body + note.encode() + b"\n%%EOF\n")
    return str(path)


def _ids(conn, ctx, ps):
    out = {}
    for o in store.objects(conn, ctx, plan_set_id=ps)["objects"]:
        out.setdefault(o["label"] if o["kind"] != "opening" else o["tag"], []).append(o["id"])
    return out


@pytest.fixture
def revs(db, tmp_path):
    est = service.create_estimate(db, CTX, "Lopez remodel")["id"]
    a = store.upload(db, CTX, est, _pdf(tmp_path / "revA.pdf", 1, "A"), confirm=True)["plan_set_id"]
    store.save_results(db, CTX, a, PLAN("A"), "fake")
    o = _ids(db, CTX, a)
    keep = m.propose(db, CTX, est, "roofing", o["OUTLET"][:3], kind="count", label="outlets 1-3",
                     confirm=True)["proposed"][0]["id"]
    moved = m.propose(db, CTX, est, "roofing", o["OUTLET"][2:5], kind="count", label="outlets 3-5",
                      confirm=True)["proposed"][0]["id"]
    slab = m.propose(db, CTX, est, "roofing", o["SLAB"], feeds="roof_area_sqft", confirm=True)["proposed"][0]["id"]
    gfi = m.propose(db, CTX, est, "roofing", o["GFI"], kind="count", label="gfi", confirm=True)["proposed"][0]["id"]
    porch = m.propose(db, CTX, est, "roofing", o["PORCH"], kind="area", label="porch", confirm=True)["proposed"][0]["id"]
    typed = m.manual(db, CTX, est, "roofing", feeds="ridge_lf", qty="20", unit="lf", confirm=True)["measurement"]["id"]
    m.confirm_measurements(db, CTX, [keep, slab, porch], confirm=True)
    b = store.upload(db, CTX, est, _pdf(tmp_path / "revB.pdf", 2, "B"), supersedes_plan_set_id=a,
                     confirm=True)["plan_set_id"]
    store.save_results(db, CTX, b, PLAN("B"), "fake")
    db.commit()
    return {"est": est, "a": a, "b": b, "o": o, "keep": keep, "moved": moved, "slab": slab, "gfi": gfi,
            "porch": porch, "typed": typed}


def _xlsx_bytes(tmp_path):
    """A supplier workbook: the price table on 'Prices', a cover sheet after it."""
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Prices"
    ws.append(["Item Code", "Description", "Unit", "Unit Price"])
    ws.append(["pw_driveway_sqft", "Driveway", "sqft", 0.19])
    ws.append(["bogus", "Nothing like this", "ea", 5])
    cover = wb.create_sheet("Cover")
    cover.append(["Note"])
    cover.append(["supplier cover sheet"])
    path = tmp_path / "suppliers.xlsx"
    wb.save(path)
    return path.read_bytes()


def _stage_price(call, data, name, headers=None, write_header=True):
    return call("POST", f"{API}/price-book/import/stage?name={name}", headers=headers, raw=data,
                write_header=write_header)


def _price(call, key=KEY):
    book = call("GET", f"{API}/price-book?module_id=pressure_washing").json()
    return next(x for x in book["prices"] if x["price_key"] == key)


# ------------------------------------------------------------------ revision clouds and deltas

def test_revision_marks_have_boxes_on_the_sheet(db, revs):                       # C2S19-W01
    r = revisions.compare(db, CTX, revs["b"], confirm=True)
    assert r["totals"] == TOTALS and r["revision_marks"] == 1
    sheet = r["sheets"][0]
    assert sheet["sheet_no"] == "E-101" and sheet["marks"] == 1
    assert len(sheet["marks_items"]) == 1
    mark = sheet["marks_items"][0]
    assert mark["old"] is None and mark["new"]["label"] == "REV CLOUD"
    assert mark["new"]["kind"] == "polyline" and mark["new"]["bbox"] == CLOUD_BOX
    assert "REV CLOUD" in [x["new"]["label"] for x in sheet["added_items"]]  # a mark is also an added box


def test_marks_alone_mark_a_sheet_changed(db, tmp_path):                         # C2S19-W02
    est = service.create_estimate(db, CTX, "Cloud only")["id"]
    a = store.upload(db, CTX, est, _pdf(tmp_path / "cA.pdf", 1, "A"), confirm=True)["plan_set_id"]
    store.save_results(db, CTX, a, _cloud_plan(), "fake")
    b = store.upload(db, CTX, est, _pdf(tmp_path / "cB.pdf", 1, "B"), supersedes_plan_set_id=a,
                     confirm=True)["plan_set_id"]
    store.save_results(db, CTX, b, _cloud_plan(), "fake")
    db.commit()
    r = revisions.compare(db, CTX, b, confirm=True)
    assert r["totals"] == {"unchanged": 2, "moved": 0, "changed": 0, "removed": 0, "added": 0}
    sheet = r["sheets"][0]
    assert sheet["marks"] == 1 and sheet["changed_anything"] is True
    assert sheet["marks_items"][0]["old"] is None
    assert sheet["marks_items"][0]["new"]["bbox"] == [2.0, 2.0, 4.0, 3.0]
    assert sheet["marks_items"][0]["new"]["label"] == "DELTA 1"
    assert r["revision_marks"] == 1


def test_revision_detail_returns_marks_items(db, call, revs):                    # C2S19-W03
    done = call("POST", f"{API}/reports/revisions",
                {"new_plan_set_id": revs["b"], "confirm": True}).json()
    detail = call("GET", f"{API}/reports/revisions/{done['report_id']}").json()
    assert detail["revision_marks"] == 1
    sheet = detail["sheets"][0]
    assert sheet["marks"] == 1 and len(sheet["marks_items"]) == 1
    assert sheet["marks_items"][0]["new"]["bbox"] == CLOUD_BOX
    assert sheet["marks_items"][0]["old"] is None
    assert sheet["changed_anything"] is True


def test_old_report_without_marks_still_loads(db, call, revs):                   # C2S19-W04
    done = call("POST", f"{API}/reports/revisions",
                {"new_plan_set_id": revs["b"], "confirm": True}).json()
    rid = done["report_id"]
    s = json.loads(db.execute("SELECT summary_json FROM revision_reports WHERE id = ?", (rid,)).fetchone()[0])
    for sheet in s["sheets"]:
        sheet.pop("marks", None)
        sheet.pop("marks_items", None)
    db.execute("UPDATE revision_reports SET summary_json = ? WHERE id = ?", (json.dumps(s), rid))
    db.commit()
    detail = call("GET", f"{API}/reports/revisions/{rid}").json()
    assert detail["sheets"][0].get("marks_items") is None
    assert detail["sheets"][0].get("marks") is None
    assert detail["revision_marks"] == 1      # the whole-set count was there before Sprint 19


def test_revision_clouds_are_drawn_in_the_overlay():                            # C2S19-W05
    reports = (WEB / "reports.js").read_text(encoding="utf-8")
    assert '["marks", "Revision clouds", "rev-marks"]' in reports
    assert 'tile(r.revision_marks || 0, "Revision clouds", "rev-marks")' in reports
    assert '"added", "removed", "changed", "moved", "marks"' in reports   # the picker lists marks
    assert "purple outlines revision clouds" in reports
    assert 's[k + "_items"] || []' in reports   # a sheet without marks_items still renders
    css = (WEB / "app.css").read_text(encoding="utf-8")
    for part in (".rev-overlay .rev-marks rect { fill: #7c3aed; stroke: #6d28d9; }",
                 ".tile.rev-marks .num { color: #6d28d9; }",
                 "label.rev-marks { color: #6d28d9; }",
                 ".rev-tag.rev-marks { background: #ede9fe; }"):
        assert part in css, part


# ------------------------------------------------------------------ staging a price list file

def test_stage_excel_price_list(call, tmp_path):                                 # C2S19-W06
    r = _stage_price(call, _xlsx_bytes(tmp_path), "suppliers.xlsx")
    assert r.status == 200, r.body
    s = r.json()
    assert s["ok"] is True and s["file"] == "suppliers.xlsx" and s["stage_id"]
    assert s["sheets"] == ["Prices", "Cover"]
    assert s["columns"] == ["Item Code", "Description", "Unit", "Unit Price"]
    assert s["row_count"] == 2
    assert (staging.root() / s["stage_id"]).is_dir() and staging.count() == 1


def test_stage_csv_price_list(call):                                             # C2S19-W07
    r = _stage_price(call, CSV.encode(), "suppliers.csv")
    assert r.status == 200, r.body
    s = r.json()
    assert s["ok"] is True and s["file"] == "suppliers.csv" and s["stage_id"]
    assert s["sheets"] == [] and s["columns"] == ["Item Code", "Description", "Unit", "Unit Price"]
    assert s["row_count"] == 2 and staging.count() == 1


@pytest.mark.parametrize("data, name, code, words", [
    (b"%PDF-1.4 fake", "suppliers.pdf", 400, "cannot be used"),
    (b"", "suppliers.csv", 400, "is empty"),
    (b"not a workbook at all", "suppliers.xlsx", 400, "could not be read"),
])
def test_stage_refuses_bad_files(call, data, name, code, words):                # C2S19-W08
    r = _stage_price(call, data, name)
    assert r.status == code, r.body
    assert words in json.dumps(r.json()), r.body
    assert staging.count() == 0
    root = staging.root()
    assert not root.exists() or not any(root.iterdir())


def test_stage_refuses_too_big_wrong_role_and_missing_name(call, session_for):   # C2S19-W09
    big = b"x" * (5 * 1024 * 1024 + 1)
    r = _stage_price(call, big, "suppliers.csv")
    assert r.status == 413 and r.json()["error"] == "too_large"
    assert "the limit is 5 MB" in r.json()["message"]
    assert staging.count() == 0
    r = _stage_price(call, CSV.encode(), "suppliers.csv", headers=session_for("reviewer"))
    assert r.status == 403 and r.json()["error"] == "permission_denied"
    r = call("POST", f"{API}/price-book/import/stage", raw=CSV.encode())
    assert r.status == 400 and "the file name is missing" in r.json()["message"]


# ------------------------------------------------------------------ preview and import from a staged file

def test_preview_from_a_staged_file_picks_the_sheet(call, tmp_path):             # C2S19-W10
    stage_id = _stage_price(call, _xlsx_bytes(tmp_path), "suppliers.xlsx").json()["stage_id"]
    b = call("POST", f"{API}/price-book/import/preview", {"file_path": stage_id}).json()
    assert b["sheets"] == ["Prices", "Cover"]
    assert b["columns"] == ["Item Code", "Description", "Unit", "Unit Price"]
    assert b["mapping"]["price_key"] == "Item Code" and b["mapping"]["cost"] == "Unit Price"
    assert b["rows"][0] == {"Item Code": "pw_driveway_sqft", "Description": "Driveway",
                            "Unit": "sqft", "Unit Price": "0.19"}
    assert b["row_count"] == 2
    cover = call("POST", f"{API}/price-book/import/preview",
                 {"file_path": stage_id, "sheet": "Cover"}).json()
    assert cover["columns"] == ["Note"] and cover["rows"][0] == {"Note": "supplier cover sheet"}
    r = call("POST", f"{API}/price-book/import/preview", {"file_path": stage_id, "sheet": "Nope"})
    assert r.status == 400 and "no sheet called" in r.json()["message"]


def test_import_from_a_staged_csv_saves_and_drops_the_stage(call):               # C2S19-W11
    stage_id = _stage_price(call, CSV.encode(), "suppliers.csv").json()["stage_id"]
    preview = call("POST", f"{API}/price-book/import/preview", {"file_path": stage_id}).json()
    assert preview["sheets"] == [] and preview["row_count"] == 2
    ask = call("POST", f"{API}/price-book/import",
               {"file_path": stage_id, "mapping": preview["mapping"]}).json()
    assert ask["needs_confirmation"] is True and ask["updates"] == 1 and ask["skipped"] == 1
    assert staging.get(stage_id, CTX, None).is_file()      # asking first keeps the stage
    assert (staging.root() / stage_id).is_dir()
    done = call("POST", f"{API}/price-book/import",
                {"file_path": stage_id, "mapping": preview["mapping"], "confirm": True}).json()
    assert done["saved"] == 1
    p = _price(call)
    assert p["cost_cents"] == 19 and p["sample"] is False
    with pytest.raises(NotFound):
        staging.get(stage_id, CTX, None)
    assert not (staging.root() / stage_id).exists() and staging.count() == 0


def test_import_from_a_staged_workbook_and_bad_sources(call, tmp_path):          # C2S19-W12
    stage_id = _stage_price(call, _xlsx_bytes(tmp_path), "suppliers.xlsx").json()["stage_id"]
    ask = call("POST", f"{API}/price-book/import",
               {"file_path": stage_id, "sheet": "Prices"}).json()
    assert ask["needs_confirmation"] is True and ask["updates"] == 1
    done = call("POST", f"{API}/price-book/import",
                {"file_path": stage_id, "sheet": "Prices", "confirm": True}).json()
    assert done["saved"] == 1
    assert _price(call)["cost_cents"] == 19
    r = call("POST", f"{API}/price-book/import", {"csv_text": CSV, "file_path": stage_id})
    assert r.status == 400 and "not both" in r.json()["message"]
    r = call("POST", f"{API}/price-book/import", {"file_path": "no-such-stage"})
    assert r.status == 404 and r.json()["error"] == "not_found"
    r = call("POST", f"{API}/price-book/import/preview", {"file_path": "no-such-stage"})
    assert r.status == 404


def test_paste_csv_preview_and_import_still_work(call):                           # C2S19-W13
    preview = call("POST", f"{API}/price-book/import/preview", {"csv_text": CSV}).json()
    assert preview["columns"] == ["Item Code", "Description", "Unit", "Unit Price"]
    assert "sheets" not in preview
    assert preview["mapping"]["price_key"] == "Item Code" and preview["mapping"]["cost"] == "Unit Price"
    ask = call("POST", f"{API}/price-book/import",
               {"csv_text": CSV, "mapping": preview["mapping"]}).json()
    assert ask["needs_confirmation"] is True and ask["updates"] == 1 and ask["skipped"] == 1
    done = call("POST", f"{API}/price-book/import",
                {"csv_text": CSV, "mapping": preview["mapping"], "confirm": True}).json()
    assert done["saved"] == 1
    p = _price(call)
    assert p["cost_cents"] == 19 and p["sample"] is False


# ------------------------------------------------------------------ staging, and the page wiring

def test_stages_keep_their_estimate():                                           # C2S19-W14
    plan, plan_path = staging.new(CTX, 7, "plans.pdf")
    plan_path.write_bytes(b"plans")  # get() refuses a stage whose file was never written
    assert staging.get(plan, CTX, 7).name == "plans.pdf"
    for wrong in (None, 8):
        with pytest.raises(NotFound):
            staging.get(plan, CTX, wrong)
    free, free_path = staging.new(CTX, None, "suppliers.csv")
    free_path.write_bytes(b"suppliers")
    assert staging.get(free, CTX, None).name == "suppliers.csv"
    with pytest.raises(NotFound):
        staging.get(free, CTX, 7)
    staging.drop(plan)
    staging.drop(free)
    assert staging.count() == 0


def test_price_book_upload_is_wired_in_the_page():                               # C2S19-W15
    app = (WEB / "app.js").read_text(encoding="utf-8")
    for part in ("uploadPriceList", '"/price-book/import/stage?name="', '"pb-file"',
                 '".csv,.txt,.xlsx,.xlsm"', '"pb-sheet"', "file_path: staged.stage_id",
                 "Import a supplier price list (CSV or Excel file)"):
        assert part in app, part
