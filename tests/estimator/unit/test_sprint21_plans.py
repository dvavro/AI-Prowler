"""Sprint 21 (Coder 1 part of planned Sprint 5): the shared drawing model and the plan_* tools (S21-..).

The plan engine itself is Coder 2's; here a fake engine returns results in the agreed format, so everything the
Estimator does with them (checking, saving, measuring with each viewport's scale, scale fixes, schedule links,
queries, the tools) is tested on its own.
"""
import json
import sys
import types
from decimal import Decimal

import pytest

from estimator.context import RequestContext, personal_context
from estimator.drawing_model import engine, geometry as geo, store, uploads
from estimator.errors import ConfirmationRequired, InvalidInput, NotAvailable, PermissionDenied
from estimator.estimating import service
from estimator.mcp_tools import est_tools as t

CTX = personal_context()
FIELD = RequestContext(user_id="fred", role="field")
OFFICE = RequestContext(user_id="olga", role="office")
OTHER = RequestContext(company_id="other-co", user_id="zed", role="owner")


@pytest.fixture(autouse=True)
def clean_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    monkeypatch.setattr(engine, "ENGINE_MODULES", ("estimator.plan_engine_for_tests_only",))
    yield
    engine.clear_engine()


def j(text):
    return json.loads(text)


def _pdf(tmp_path, name="plans.pdf", body=b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n"):
    p = tmp_path / name
    p.write_bytes(body)
    return p


def _estimate(db, ctx=CTX):
    return service.create_estimate(db, ctx, "Miller remodel")


def _uploaded(db, tmp_path, ctx=CTX):
    est = _estimate(db, ctx)
    out = store.upload(db, ctx, est["id"], str(_pdf(tmp_path)), confirm=True)
    return est, out["plan_set_id"]


SQUARE = {"type": "polygon", "points": [[0, 0], [5, 0], [5, 4], [0, 4]]}      # 5 x 4 paper inches


def RESULTS():
    return {"page_count": 2, "sheets": [
        {"page_no": 1, "sheet_no": "A-101", "title": "FLOOR PLAN", "discipline": "architectural", "units": "paper_in",
         "image_path": None,
         "viewports": [{"key": "main", "label": "FLOOR PLAN", "scale_note": "1/4\" = 1'-0\"", "bbox": [0, 0, 20, 20]},
                       {"key": "detail", "label": "DETAIL 3", "scale_note": "NTS"},
                       {"key": "enlarged", "label": "ENLARGED BATH"}],
         "objects": [
             {"viewport": "main", "kind": "room", "label": "KITCHEN", "geometry": SQUARE, "source": "vector",
              "confidence": 0.92, "layer": "A-ROOM"},
             {"viewport": "main", "kind": "wall", "geometry": {"type": "polyline", "points": [[0, 0], [5, 0]]},
              "source": "vector", "layer": "A-WALL"},
             {"viewport": "main", "kind": "opening", "tag": "D3", "label": "door",
              "geometry": {"type": "point", "points": [[2, 0]]}, "source": "vector"},
             {"viewport": "main", "kind": "opening", "tag": "d 3", "geometry": {"type": "point", "points": [[9, 9]]},
              "source": "vector"},
             {"viewport": "detail", "kind": "polygon", "geometry": SQUARE, "source": "vector"},
             {"viewport": "enlarged", "kind": "room", "label": "BATH", "geometry": SQUARE, "source": "vector"},
             {"kind": "text", "label": "GENERAL NOTES", "geometry": {"type": "point", "points": [[30, 1]]},
              "source": "vector"}],
         "schedules": [{"schedule_type": "door", "title": "DOOR SCHEDULE",
                        "rows": [{"mark": "D3", "fields": {"size": "3'-0\" x 6'-8\"", "qty": 2}, "confidence": 0.9},
                                 {"mark": "D4", "fields": {"size": "2'-8\" x 6'-8\""}, "confidence": 0.6}]}],
         "legends": [{"discipline": "electrical", "title": "ELECTRICAL LEGEND", "bbox": [30, 2, 35, 8]}]},
        {"page_no": 2, "sheet_no": "S-1", "title": "FOUNDATION", "discipline": "structural", "units": "ft",
         "objects": [{"kind": "polygon", "label": "SLAB",
                      "geometry": {"type": "polygon", "points": [[0, 0], [10, 0], [10, 10], [0, 10]]},
                      "source": "cad", "layer": "S-SLAB"}]}]}


def _processed(db, tmp_path):
    est, ps = _uploaded(db, tmp_path)
    store.save_results(db, CTX, ps, RESULTS(), "fake")
    return est, ps


# ---------------------------------------------------------------- measuring math

def test_scale_notes():  # S21-G01
    assert geo.parse_scale("1/4\" = 1'-0\"") == (Decimal(48), False)
    assert geo.parse_scale("SCALE: 1/8\"=1'-0\"")[0] == 96
    assert geo.parse_scale("3/16\" = 1'-0\"")[0] == 64
    assert geo.parse_scale("1-1/2\" = 1'-0\"")[0] == 8
    assert geo.parse_scale("1\" = 20'")[0] == 240
    assert geo.parse_scale("1:100")[0] == 100
    assert geo.parse_scale("N.T.S.") == (None, True) and geo.parse_scale("not to scale") == (None, True)
    for bad in ("", "big", "0\" = 1'", "1:0"):
        with pytest.raises(InvalidInput):
            geo.parse_scale(bad)


def test_typed_distances():  # S21-G02
    assert geo.parse_length("12'-6\"") == Decimal("12.5")
    assert geo.parse_length("12' 6\"") == Decimal("12.5")
    assert geo.parse_length("6\"") == Decimal("0.5")
    assert geo.parse_length("150 in") == Decimal("12.5")
    assert geo.parse_length("10") == 10
    assert geo.q(geo.parse_length("3.048 m")) == "10.00"
    with pytest.raises(InvalidInput):
        geo.parse_length("a while")


def test_lengths_areas_and_calibration():  # S21-G03
    sq = geo.check_geometry({"type": "polygon", "points": [[0, 0], [0, 10], [10, 10], [10, 0]]})   # clockwise
    assert geo.polygon_area(sq["points"]) == 100 and geo.polygon_perimeter(sq["points"]) == 40
    assert geo.path_length(geo.check_geometry({"type": "line", "points": [[0, 0], [3, 4]]})["points"]) == 5
    assert geo.calibrate([0, 0], [4, 0], "16'") == Decimal("48.0000")
    assert geo.measure(sq, None) is None                                        # unknown scale: never guessed
    for bad in ({"type": "polygon", "points": [[0, 0], [1, 1]]}, {"type": "blob", "points": [[0, 0]]},
                {"type": "line", "points": [[0, "x"], [1, 1]]}, "square"):
        with pytest.raises(InvalidInput):
            geo.check_geometry(bad)
    with pytest.raises(InvalidInput):
        geo.calibrate([1, 1], [1, 1], "10'")


# ---------------------------------------------------------------- uploads

def test_upload_checks_then_copies(db, tmp_path):  # S21-U01
    est = _estimate(db)
    pdf = _pdf(tmp_path)
    with pytest.raises(ConfirmationRequired) as ask:
        store.upload(db, CTX, est["id"], str(pdf))
    assert ask.value.details["file_type"] == "pdf"
    out = store.upload(db, CTX, est["id"], str(pdf), confirm=True)
    ps = store.load_plan_set(db, CTX, out["plan_set_id"])
    assert ps["status"] == "uploaded" and ps["file_path"] != str(pdf) and ps["sha256"]
    assert ps["file_path"].replace("\\", "/").split("/projects/")[1].startswith(f"estimate_{est['id']:04d}/plans/")
    pdf.unlink()                                                                 # the copy stays usable
    assert store.load_plan_set(db, CTX, ps["id"])["file_path"] and \
        __import__("pathlib").Path(ps["file_path"]).is_file()
    with pytest.raises(InvalidInput) as dup:
        store.upload(db, CTX, est["id"], str(_pdf(tmp_path, "copy.pdf")), confirm=True)
    assert dup.value.details["plan_set_id"] == ps["id"]


def test_upload_refusals(db, tmp_path, monkeypatch):  # S21-U02
    est = _estimate(db)
    cases = {
        "fake.pdf": b"MZ\x90\x00 this is really a program",
        "locked.pdf": b"%PDF-1.6\n trailer << /Encrypt 5 0 R >>\n%%EOF",
        "empty.pdf": b"",
        "notes.docx": b"PK\x03\x04",
        "photo.jpg": b"\x89PNG\r\n\x1a\nnot a jpeg",
    }
    for name, body in cases.items():
        p = tmp_path / name
        p.write_bytes(body)
        with pytest.raises(InvalidInput):
            store.upload(db, CTX, est["id"], str(p), confirm=True)
    with pytest.raises(InvalidInput):
        store.upload(db, CTX, est["id"], "plans.pdf", confirm=True)              # not a full path
    with pytest.raises(InvalidInput):
        store.upload(db, CTX, est["id"], str(tmp_path / "missing.pdf"), confirm=True)
    monkeypatch.setattr(uploads, "MAX_BYTES", 10)
    with pytest.raises(InvalidInput) as big:
        store.upload(db, CTX, est["id"], str(_pdf(tmp_path, "big.pdf")), confirm=True)
    assert "limit" in big.value.message
    assert db.execute("SELECT COUNT(*) FROM plan_sets").fetchone()[0] == 0


def test_upload_kinds_revisions_and_roles(db, tmp_path, monkeypatch):  # S21-U03
    # The DWG warning only appears when no converter is installed; David installed the ODA
    # File Converter on 2026-11-10, so force the no-converter path or the warning is empty.
    monkeypatch.setenv("ESTIMATOR_DWG_CONVERTER", "off")
    est = _estimate(db)
    dxf = tmp_path / "site.dxf"
    dxf.write_text("  0\nSECTION\n  2\nHEADER\n  0\nENDSEC\n  0\nEOF\n")
    png = tmp_path / "photo.png"
    try:
        from PIL import Image
        Image.new("L", (300, 200), 255).save(png, dpi=(72, 72))                 # a real but low-resolution photo
    except ImportError:
        png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    dwg = tmp_path / "house.dwg"
    dwg.write_bytes(b"AC1032" + b"\x00" * 64)
    first = store.upload(db, CTX, est["id"], str(dxf), confirm=True)
    assert first["file_type"] == "dxf"
    photo = store.upload(db, OFFICE, est["id"], str(png), confirm=True)
    assert photo["file_type"] == "image"
    if "PIL" in sys.modules:
        assert "DPI" in photo["warnings"][0]
    rev = store.upload(db, CTX, est["id"], str(dwg), supersedes_plan_set_id=first["plan_set_id"], confirm=True)
    assert rev["revision"] == 2 and "converter" in rev["warnings"][0]
    with pytest.raises(PermissionDenied):
        store.upload(db, FIELD, est["id"], str(_pdf(tmp_path)), confirm=True)
    with pytest.raises(Exception):
        store.load_plan_set(db, OTHER, first["plan_set_id"])                   # another company can't see it
    other = _estimate(db)
    with pytest.raises(InvalidInput):
        store.upload(db, CTX, other["id"], str(_pdf(tmp_path, "x.pdf")), supersedes_plan_set_id=first["plan_set_id"],
                     confirm=True)
    assert store.list_plan_sets(db, CTX, est["id"])["count"] == 3


# ---------------------------------------------------------------- saving and measuring the engine's results

def test_results_are_saved_and_measured_per_viewport(db, tmp_path):  # S21-M01
    est, ps = _uploaded(db, tmp_path)
    out = store.save_results(db, CTX, ps, RESULTS(), "fake")
    assert out["sheets"] == 2 and out["viewports"] == 3 and out["objects"] == 8 and out["linked_rows"] == 1
    st = store.status(db, CTX, ps)
    assert st["status"] == "processed" and st["page_count"] == 2 and st["engine"] == "fake"
    objs = {(o["label"] or o["kind"]): o for o in store.objects(db, CTX, plan_set_id=ps)["objects"]}
    # 1/4" = 1'-0": one paper inch is 4 feet, so the 5 x 4 inch kitchen is 20 x 16 feet
    assert objs["KITCHEN"]["real_units"] == {"area_sqft": "320.00", "perimeter_ft": "72.00"}
    assert objs["wall"]["real_units"] == {"length_ft": "20.00"}
    assert objs["polygon"]["real_units"] is None and "NTS" in objs["polygon"]["not_measured"]
    assert objs["BATH"]["real_units"] is None and "no scale" in objs["BATH"]["not_measured"]
    assert "viewport" in objs["GENERAL NOTES"]["not_measured"]
    assert objs["SLAB"]["real_units"]["area_sqft"] == "100.00"                  # CAD sheet in feet: no scale needed
    sheets = {s["sheet_no"]: s for s in store.sheets(db, CTX, ps)["sheets"]}
    assert sheets["A-101"]["needs_scale"] is True and sheets["S-1"]["needs_scale"] is False
    assert st["sheets_needing_scale"] == [sheets["A-101"]["id"]]
    assert store.sheets(db, CTX, ps, "structural")["count"] == 1


def test_bad_results_never_leave_half_a_model(db, tmp_path):  # S21-M02
    est, ps = _processed(db, tmp_path)
    before = store.objects(db, CTX, plan_set_id=ps)["count"]
    breakers = [
        lambda r: r["sheets"][0]["objects"].append({"kind": "cloud", "geometry": SQUARE, "source": "vector"}),
        lambda r: r["sheets"][1].update(page_no=1),
        lambda r: r["sheets"][0]["objects"].append({"viewport": "nowhere", "kind": "room", "geometry": SQUARE,
                                                    "source": "vector"}),
        lambda r: r["sheets"][0]["objects"][0].update(confidence=1.5),
        lambda r: r["sheets"][0].update(discipline="kitchen"),
        lambda r: r["sheets"][0]["viewports"][0].update(scale_note="huge"),
        lambda r: r["sheets"][0]["schedules"][0]["rows"][0].update(fields={"size": ["3", "0"]}),
        lambda r: r.pop("sheets"),
    ]
    for brk in breakers:
        res = RESULTS()
        brk(res)
        with pytest.raises(InvalidInput):
            store.save_results(db, CTX, ps, res, "fake")
    assert store.objects(db, CTX, plan_set_id=ps)["count"] == before            # the good model is untouched


def test_set_scale_remeasures(db, tmp_path):  # S21-M03
    est, ps = _processed(db, tmp_path)
    a101 = store.sheets(db, CTX, ps)["sheets"][0]
    vps = {v["label"]: v for v in store.viewports(db, CTX, a101["id"])["viewports"]}
    bath = vps["ENLARGED BATH"]["id"]
    with pytest.raises(ConfirmationRequired):
        store.set_scale(db, CTX, bath, scale_note="1/2\" = 1'-0\"")
    out = store.set_scale(db, CTX, bath, scale_note="1/2\" = 1'-0\"", confirm=True)
    assert out["viewport"]["scale_ratio"] == "24" and out["measured"] == 1
    bath_obj = store.objects(db, CTX, sheet_id=a101["id"], viewport_id=bath)["objects"][0]
    assert bath_obj["real_units"]["area_sqft"] == "80.00"                       # 10 x 8 ft
    # two-point calibration: 4 paper inches are really 16 feet -> 48
    out = store.set_scale(db, CTX, bath, calibration={"p1": [0, 0], "p2": [4, 0], "distance": "16'-0\""}, confirm=True)
    assert out["viewport"]["scale_method"] == "calibration"
    assert store.objects(db, CTX, sheet_id=a101["id"], viewport_id=bath)["objects"][0]["real_units"]["area_sqft"] \
        == "320.00"
    out = store.set_scale(db, CTX, bath, scale_note="NTS", confirm=True)
    assert out["viewport"]["is_nts"] and out["measured"] == 0
    assert store.sheets(db, CTX, ps)["sheets"][0]["needs_scale"] is False       # NTS is a decision, not a gap
    with pytest.raises(InvalidInput):
        store.set_scale(db, CTX, bath, scale_note="1:10", scale_ratio="10", confirm=True)
    with pytest.raises(PermissionDenied):
        store.set_scale(db, FIELD, bath, scale_ratio="48", confirm=True)
    events = [r["action"] for r in db.execute("SELECT action FROM estimate_events WHERE estimate_id = ?",
                                              (est["id"],))]
    assert {"plan_uploaded", "plan_processed", "plan_scale_set"} <= set(events)


def test_cad_sheets_dont_take_a_scale(db, tmp_path):  # S21-M04
    est, ps = _uploaded(db, tmp_path)
    res = RESULTS()
    res["sheets"][1]["viewports"] = [{"key": "plan", "label": "PLAN"}]
    res["sheets"][1]["objects"][0]["viewport"] = "plan"
    store.save_results(db, CTX, ps, res, "fake")
    s1 = store.sheets(db, CTX, ps)["sheets"][1]
    with pytest.raises(InvalidInput):
        store.set_scale(db, CTX, s1["viewports"][0]["id"], scale_ratio="48", confirm=True)


def test_queries(db, tmp_path):  # S21-Q01
    est, ps = _processed(db, tmp_path)
    a101 = store.sheets(db, CTX, ps)["sheets"][0]["id"]
    rooms = store.objects(db, CTX, plan_set_id=ps, kind="room")
    assert rooms["count"] == 2 and rooms["totals"]["room"] == {"count": 2, "measured": 1, "area_sqft": "320.00",
                                                               "length_ft": "0.00"}
    assert store.objects(db, CTX, plan_set_id=ps, kind="room,wall")["count"] == 3
    assert store.objects(db, CTX, plan_set_id=ps, tag="d3")["count"] == 2        # case and spaces don't matter
    assert store.objects(db, CTX, plan_set_id=ps, layer="A-WALL")["count"] == 1
    near = store.objects(db, CTX, sheet_id=a101, area=[8, 8, 10, 10])
    assert near["count"] == 1 and near["objects"][0]["tag"] == "d 3"
    page = store.objects(db, CTX, plan_set_id=ps, limit=2, offset=2, include_geometry=True)
    assert page["returned"] == 2 and page["count"] == 8 and "geometry" in page["objects"][0]
    with pytest.raises(InvalidInput):
        store.objects(db, CTX)
    with pytest.raises(InvalidInput):
        store.objects(db, CTX, plan_set_id=ps, kind="cloud")
    with pytest.raises(InvalidInput):
        store.objects(db, CTX, plan_set_id=ps, area=[0, 0, 1, 1])               # area needs one sheet
    assert store.legends(db, CTX, ps)["legends"][0]["title"] == "ELECTRICAL LEGEND"
    assert store.sheet_image(db, CTX, a101)["error"] == "not_available"
    img = tmp_path / "a101.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n")
    db.execute("UPDATE sheets SET image_path = ? WHERE id = ?", (str(img), a101))
    assert store.sheet_image(db, CTX, a101)["path"] == str(img)
    with pytest.raises(Exception):
        store.objects(db, OTHER, plan_set_id=ps)


def test_schedules_link_and_corrections(db, tmp_path):  # S21-S01
    est, ps = _processed(db, tmp_path)
    sch = store.schedules(db, CTX, ps)["schedules"][0]
    d3, d4 = sch["rows"]
    assert len(d3["linked_object_ids"]) == 2 and d4["linked_object_ids"] == [] and sch["unlinked_marks"] == ["D4"]
    assert store.schedules(db, CTX, ps, "window")["count"] == 0
    with pytest.raises(ConfirmationRequired) as ask:
        store.update_schedule_row(db, CTX, d4["id"], fields={"size": "3'-0\" x 6'-8\""}, mark="D3")
    assert ask.value.details["after"]["mark"] == "D3"
    out = store.update_schedule_row(db, CTX, d4["id"], fields={"size": "3'-0\" x 6'-8\""}, mark="D3", confirm=True)
    assert out["row"]["reviewed_by"] == "owner" and len(out["row"]["linked_object_ids"]) == 2
    assert out["row"]["fields"] == {"size": "3'-0\" x 6'-8\""}
    with pytest.raises(PermissionDenied):
        store.update_schedule_row(db, FIELD, d3["id"], mark="D9", confirm=True)
    with pytest.raises(InvalidInput):
        store.update_schedule_row(db, CTX, d3["id"], confirm=True)


# ---------------------------------------------------------------- the plan engine hook

def test_no_engine_yet(db, tmp_path):  # S21-E01
    est, ps = _uploaded(db, tmp_path)
    assert engine.engine_info() == {"installed": False, "name": None}
    with pytest.raises(NotAvailable) as na:
        engine.start(db, CTX, ps, confirm=True)
    assert "runner_submit_takeoff" in na.value.message
    assert store.status(db, CTX, ps)["status"] == "uploaded"


def test_engine_runs_and_fails_cleanly(db, tmp_path):  # S21-E02
    est, ps = _uploaded(db, tmp_path)
    seen = {}

    def fake(path, file_type, info):
        seen.update(path=path, file_type=file_type, info=info)
        return RESULTS()
    engine.register_engine("fake-engine", fake)
    with pytest.raises(ConfirmationRequired):
        engine.start(db, CTX, ps)
    out = engine.start(db, CTX, ps, confirm=True)
    assert out["status"] == "processed" and seen["file_type"] == "pdf" and seen["path"].is_file()
    assert seen["info"]["estimate_id"] == est["id"] and seen["info"]["work_dir"]
    with pytest.raises(ConfirmationRequired) as again:                          # re-reading replaces corrections
        engine.start(db, CTX, ps)
    assert "replaces" in again.value.message

    def broken(path, file_type, info):
        raise ValueError("page 3 is unreadable")
    engine.register_engine("broken", broken)
    out = engine.start(db, CTX, ps, confirm=True)
    assert out["error"] == "processing_failed" and "page 3" in out["message"]
    st = store.status(db, CTX, ps)
    assert st["status"] == "failed" and "page 3" in st["error"] and "failed" in st["say"]

    engine.register_engine("sloppy", lambda *a: {"sheets": [{"page_no": 0}]})
    with pytest.raises(InvalidInput):
        engine.start(db, CTX, ps, confirm=True)
    assert "checks" in store.status(db, CTX, ps)["error"]
    with pytest.raises(PermissionDenied):
        engine.start(db, FIELD, ps, confirm=True)


def test_engine_in_the_background_and_discovery(db, tmp_path, monkeypatch):  # S21-E03
    from estimator.database import open_database
    est, ps = _uploaded(db, tmp_path)
    mod = types.ModuleType("estimator.plan_engine_for_tests_only")
    mod.ENGINE_NAME = "dropped-in engine"
    mod.process = lambda path, file_type, info: RESULTS()
    monkeypatch.setitem(sys.modules, "estimator.plan_engine_for_tests_only", mod)
    assert engine.engine_info() == {"installed": True, "name": "dropped-in engine"}
    monkeypatch.setattr(engine, "RUN_INLINE", False)
    out = engine.start(db, CTX, ps, confirm=True, open_conn=open_database)
    assert out["status"] == "processing"
    engine.start.last_thread.join(timeout=20)
    assert store.status(db, CTX, ps)["status"] == "processed"


# ---------------------------------------------------------------- tools, pack-up, practice

def test_plan_tools(db, tmp_path):  # S21-T01
    est = _estimate(db)
    pdf = str(_pdf(tmp_path))
    assert j(t.plan_upload(est["id"], pdf))["error"] == "needs_confirmation"
    ps = j(t.plan_upload(est["id"], pdf, confirm=True))["plan_set_id"]
    assert j(t.plan_process(ps, confirm=True))["error"] == "not_available"
    engine.register_engine("fake", lambda *a: RESULTS())
    assert j(t.plan_process(ps, confirm=True))["status"] == "processed"
    listing = j(t.plan_status(estimate_id=est["id"]))
    assert listing["count"] == 1 and listing["plan_engine"]["installed"]
    assert j(t.plan_status(ps))["objects"] == 8
    sheets = j(t.plan_get_sheets(ps))["sheets"]
    a101 = sheets[0]["id"]
    bath = [v for v in j(t.plan_get_viewports(a101))["viewports"] if v["label"] == "ENLARGED BATH"][0]["id"]
    out = j(t.plan_set_scale(bath, calibration='{"p1": [0, 0], "p2": [2, 0], "distance": "8 ft"}', confirm=True))
    assert out["viewport"]["scale_ratio"] == "48" and out["measured"] == 1
    objs = j(t.plan_get_objects(sheet_id=a101, area="8,8,10,10"))
    assert objs["count"] == 1
    assert j(t.plan_get_objects(plan_set_id=ps, kind="room"))["totals"]["room"]["area_sqft"] == "640.00"
    row = j(t.plan_get_schedules(ps, "door"))["schedules"][0]["rows"][1]
    assert j(t.plan_update_schedule_row(row["id"], '{"size": "2\'-6\\""}', confirm=True))["row"]["reviewed_by"]
    assert j(t.plan_get_legends(ps))["count"] == 1
    assert j(t.plan_get_sheet_image(a101))["error"] == "not_available"
    bad = {"plan_upload": (999, pdf), "plan_process": (999,), "plan_status": (), "plan_get_sheets": (999,),
           "plan_get_sheet_image": (999,), "plan_get_viewports": (999,), "plan_set_scale": (999, "1:10"),
           "plan_get_objects": (), "plan_get_schedules": (999,), "plan_update_schedule_row": (999, "{}"),
           "plan_get_legends": (999,)}
    for name, args in bad.items():
        res = j(getattr(t, name)(*args))
        assert res["ok"] is False and res["error"] and res["message"], (name, res)


def test_pack_up_says_plans_stay_behind(db, tmp_path, monkeypatch):  # S21-T02
    est, ps = _processed(db, tmp_path)
    pack = j(t.est_data_export())
    assert pack["left_out"] and "plan set" in pack["left_out"][0]
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(tmp_path / "server"))
    done = j(t.est_data_import(pack["path"], confirm=True))
    assert done["imported"]["estimates"] == 1


def test_practice_delete_takes_its_plans(db, tmp_path):  # S21-T03
    from estimator import practice
    from estimator.modules.registry import ModuleRegistry
    out = practice.create(db, CTX, ModuleRegistry().load())
    store.upload(db, CTX, out["estimate_id"], str(_pdf(tmp_path)), confirm=True)
    practice.delete(db, CTX, confirm=True)
    assert db.execute("SELECT COUNT(*) FROM plan_sets").fetchone()[0] == 0
