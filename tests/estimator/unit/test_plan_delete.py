"""Removing plan sets and sheets: the ask-first warning (approved work called out), the full cascade,
and the files. Seeded straight into a throwaway database so every table the delete touches is covered."""
import json
from pathlib import Path

import pytest

from estimator import config
from estimator.context import RequestContext, personal_context
from estimator.errors import ConfirmationRequired, NotFound, PermissionDenied
from estimator.estimating import service
from estimator.takeoff import plan_delete

NOW = "2026-11-12T12:00:00+00:00"
COMPANY = "default"


def _ins(db, sql, args=()):
    return db.execute(sql, args).lastrowid


def _count(db, table, where="", args=()):
    return db.execute(f"SELECT COUNT(*) FROM {table} {where}", args).fetchone()[0]


def _seed(db, ctx, data: Path):
    """A processed plan set with two sheets and everything hanging off them, plus a second plan set
    on the same estimate that must stay untouched, and a plan set that replaces the first."""
    est = service.create_estimate(db, ctx, "Smith house")["id"]
    plans = data / "projects" / f"estimate_{est:04d}" / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    plan_file = plans / "1_smith_plans.pdf"
    plan_file.write_bytes(b"%PDF-fake")
    ps = _ins(db, "INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                  " file_size, sha256, revision, status, uploaded_by, created_at)"
                  " VALUES (?,?,?,?,?,?,?,?,'uploaded',?,?)",
              (COMPANY, est, str(plan_file), "smith plans.pdf", "pdf", 9, "aa", 1, "owner", NOW))
    work = plans / f"{ps}_sheets"
    work.mkdir(parents=True, exist_ok=True)
    (work / "symbol_dictionary.json").write_text("{}", encoding="utf-8")
    (work / "legend_p001_1_1.png").write_bytes(b"PNG-fake")
    img1 = work / "sheet_1.png"
    img2 = work / "sheet_2.png"
    img1.write_bytes(b"PNG-fake")
    img2.write_bytes(b"PNG-fake")
    s1 = _ins(db, "INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, discipline,"
                  " units, width, height, image_path) VALUES (?,?,?,?,?,?,?,?,?,?)",
              (COMPANY, ps, 1, "A-101", "FIRST FLOOR PLAN", "architectural", "paper_in", "36", "24", str(img1)))
    s2 = _ins(db, "INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, discipline,"
                  " units, width, height, image_path) VALUES (?,?,?,?,?,?,?,?,?,?)",
              (COMPANY, ps, 2, "E-101", "POWER PLAN", "electrical", "paper_in", "36", "24", str(img2)))
    for sid in (s1, s2):
        tiles = data / "tiles" / f"sheet{sid}_abc123"
        tiles.mkdir(parents=True, exist_ok=True)
        (tiles / "0_0_0.png").write_bytes(b"PNG-fake")
    v1 = _ins(db, "INSERT INTO viewports (company_id, sheet_id, label, scale_ratio) VALUES (?,?,?,?)",
              (COMPANY, s1, "FLOOR PLAN", "48"))
    v2 = _ins(db, "INSERT INTO viewports (company_id, sheet_id, label, scale_ratio) VALUES (?,?,?,?)",
              (COMPANY, s1, "WALL TYPES", "48"))
    v3 = _ins(db, "INSERT INTO viewports (company_id, sheet_id, label, scale_ratio) VALUES (?,?,?,?)",
              (COMPANY, s2, "POWER PLAN", "48"))
    o1 = _ins(db, "INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json,"
                  " source) VALUES (?,?,?,?,?,?)",
              (COMPANY, s1, v1, "room", "{}", "vector"))
    o2 = _ins(db, "INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json,"
                  " source) VALUES (?,?,?,?,?,?)",
              (COMPANY, s1, v2, "wall", "{}", "vector"))
    o3 = _ins(db, "INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json,"
                  " source) VALUES (?,?,?,?,?,?)",
              (COMPANY, s2, v3, "symbol", "{}", "vector"))

    def measurement(sheet_id, viewport_id, status, objects=()):
        return _ins(db, "INSERT INTO measurements (company_id, estimate_id, module_id, sheet_id, viewport_id,"
                        " kind, label, qty, unit, source_object_ids, method, status, proposed_by,"
                        " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (COMPANY, est, "concrete", sheet_id, viewport_id, "area", "slab", "100", "sqft",
                     json.dumps(list(objects)), "manual", status, "owner", NOW, NOW))

    m_approved_1 = measurement(s1, v1, "approved", [o1])
    m_proposed_1 = measurement(s1, v1, "proposed", [o2])
    m_approved_2 = measurement(s2, v3, "approved", [o3])
    # No sheet link at all, but it counted an object on sheet 1: it still belongs to these plans.
    m_cross = measurement(None, None, "proposed", [o1])
    run1 = _ins(db, "INSERT INTO auto_runs (company_id, estimate_id, sheet_id, viewport_id, module_id,"
                    " status, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (COMPANY, est, s1, v1, "concrete", "done", "owner", NOW, NOW))
    sch = _ins(db, "INSERT INTO schedules (company_id, sheet_id, schedule_type, title) VALUES (?,?,?,?)",
               (COMPANY, s1, "door", "DOOR SCHEDULE"))
    row1 = _ins(db, "INSERT INTO schedule_rows (company_id, schedule_id, mark, fields_json,"
                    " linked_object_ids) VALUES (?,?,?,?,?)",
                (COMPANY, sch, "D1", "{}", json.dumps([o1])))
    row2 = _ins(db, "INSERT INTO schedule_rows (company_id, schedule_id, mark, fields_json,"
                    " linked_object_ids) VALUES (?,?,?,?,?)",
                (COMPANY, sch, "D2", "{}", "[]"))
    _ins(db, "INSERT INTO legends (company_id, sheet_id, discipline, title) VALUES (?,?,?,?)",
         (COMPANY, s1, "architectural", "LEGEND"))
    leg = _ins(db, "INSERT INTO legends (company_id, sheet_id, discipline, title) VALUES (?,?,?,?)",
               (COMPANY, s2, "electrical", "LEGEND"))
    d1 = _ins(db, "INSERT INTO symbol_definitions (company_id, plan_set_id, legend_id, entry_key, code,"
                  " description, item_type, trade, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
              (COMPANY, ps, leg, "GFI", "GFI", "GFCI outlet", "outlet", "electrical", NOW))
    ex1 = _ins(db, "INSERT INTO symbol_examples (company_id, definition_id, image_path, source_sheet_id,"
                   " source, created_at) VALUES (?,?,?,?,?,?)",
               (COMPANY, d1, str(work / "legend_p001_1_1.png"), s1, "legend", NOW))
    _ins(db, "INSERT INTO symbol_detections (company_id, plan_set_id, drawing_object_id, definition_id,"
             " sheet_id, viewport_id, item_type, trade, label, location_json, method, created_at)"
             " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
         (COMPANY, ps, o3, d1, s2, v3, "outlet", "electrical", "GFI", "{}", "vector", NOW))
    _ins(db, "INSERT INTO symbol_detections (company_id, plan_set_id, drawing_object_id, definition_id,"
             " sheet_id, viewport_id, item_type, trade, label, location_json, method, created_at)"
             " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
         (COMPANY, ps, o1, d1, s1, v1, "outlet", "electrical", "GFI", "{}", "vector", NOW))
    rep = _ins(db, "INSERT INTO revision_reports (company_id, estimate_id, old_plan_set_id, summary_json,"
                   " flagged_measurement_ids, created_by, created_at) VALUES (?,?,?,?,?,?,?)",
               (COMPANY, est, ps, "{}", json.dumps([m_approved_1]), "owner", NOW))
    agent_run = _ins(db, "INSERT INTO runs (company_id, estimate_id, plan_set_id, state, started_by,"
                         " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                     (COMPANY, est, ps, "completed", "owner", NOW, NOW))
    task = _ins(db, "INSERT INTO takeoff_tasks (company_id, run_id, estimate_id, module_id, position,"
                    " sheet_ids_json, updated_at) VALUES (?,?,?,?,?,?,?)",
                (COMPANY, agent_run, est, "concrete", 1, json.dumps([s1, s2]), NOW))
    crops = data / "projects" / f"estimate_{est:04d}" / "ai_sent"
    crops.mkdir(parents=True, exist_ok=True)
    crop = crops / "000001_crop_sheet1.png"
    crop.write_bytes(b"PNG-fake")
    log = _ins(db, "INSERT INTO ai_send_log (company_id, estimate_id, sheet_id, kind, purpose, file_path,"
                   " provider, actor, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
               (COMPANY, est, s1, "crop", "is this a GFI outlet?", str(crop), "test", "owner", NOW))
    _ins(db, "INSERT INTO reviews (company_id, estimate_id, target_type, target_id, version, status,"
             " object_ids, created_at) VALUES (?,?,?,?,?,?,?,?)",
         (COMPANY, est, "measurement", m_approved_1, 1, "approved", json.dumps([o1]), NOW))
    _ins(db, "INSERT INTO reviews (company_id, estimate_id, target_type, target_id, version, status,"
             " created_at) VALUES (?,?,?,?,?,?,?)",
         (COMPANY, est, "schedule", row1, 1, "in_review", NOW))
    section = _ins(db, "INSERT INTO trade_sections (estimate_id, module_id, created_at) VALUES (?,?,?)",
                   (est, "concrete", NOW))
    assembly = _ins(db, "INSERT INTO assembly_uses (company_id, estimate_id, trade_section_id, assembly_id,"
                        " module_id, params_json, sources_json, measurement_ids, applied_by, applied_at)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (COMPANY, est, section, "concrete@1", "concrete", "{}",
                     json.dumps({"slab_sqft": {"from": "measured", "measurement_ids": [m_approved_1]}}),
                     json.dumps([m_approved_1]), "owner", NOW))
    # A plan set that replaces this one, and a second, unrelated plan set on the same estimate.
    newer = _ins(db, "INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                     " file_size, sha256, revision, supersedes_plan_set_id, status, uploaded_by, created_at)"
                     " VALUES (?,?,?,?,?,?,?,?,?,'uploaded',?,?)",
                 (COMPANY, est, str(plans / "2_rev_b.pdf"), "rev b.pdf", "pdf", 9, "bb", 2, ps, "owner", NOW))
    other_file = plans / "3_other.pdf"
    other_file.write_bytes(b"%PDF-fake")
    other = _ins(db, "INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                     " file_size, sha256, revision, status, uploaded_by, created_at)"
                     " VALUES (?,?,?,?,?,?,?,?,'uploaded',?,?)",
                 (COMPANY, est, str(other_file), "other.pdf", "pdf", 9, "cc", 1, "owner", NOW))
    os1 = _ins(db, "INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, discipline)"
                   " VALUES (?,?,?,?,?,?)",
               (COMPANY, other, 1, "A-001", "SITE PLAN", "architectural"))
    other_measurement = measurement(os1, None, "approved")
    return {"estimate_id": est, "plan_set_id": ps, "sheet_1": s1, "sheet_2": s2,
            "viewport_1": v1, "viewport_2": v2, "viewport_3": v3,
            "object_1": o1, "object_2": o2, "object_3": o3,
            "approved_1": m_approved_1, "proposed_1": m_proposed_1, "approved_2": m_approved_2,
            "cross": m_cross, "auto_run": run1, "schedule": sch, "row_1": row1, "row_2": row2,
            "definition": d1, "example": ex1, "report": rep, "run": agent_run, "task": task,
            "log": log, "assembly": assembly, "newer": newer, "other": other,
            "other_sheet": os1, "other_measurement": other_measurement,
            "plan_file": plan_file, "work": work, "img_1": img1, "img_2": img2, "crop": crop,
            "example_image": work / "legend_p001_1_1.png", "other_file": other_file}


@pytest.fixture
def seeded(db, estimator_sandbox):
    return _seed(db, personal_context(), estimator_sandbox)


# ------------------------------------------------------------------ the ask


def test_delete_plan_set_asks_first_and_warns_about_approved(db, seeded):
    ctx = personal_context()
    with pytest.raises(ConfirmationRequired) as exc:
        plan_delete.delete_plan_set(db, ctx, seeded["plan_set_id"])
    assert "2 approved measurements" in exc.value.message
    assert "deleting removes them" in exc.value.message
    assert "smith plans.pdf" in exc.value.message
    changes = exc.value.details["changes"]
    assert "Plan set %d (smith plans.pdf)" % seeded["plan_set_id"] in changes
    assert "2 sheets" in changes
    assert "3 viewports" in changes
    assert "3 drawing objects" in changes
    assert "4 measurements (2 approved, 2 proposed)" in changes
    assert "1 auto-run" in changes
    assert "1 schedule (2 rows)" in changes
    assert "2 legends" in changes
    assert "2 symbol detections" in changes
    assert "1 symbol definition (the plan set's dictionary) and 1 example image" in changes
    assert "2 reviews of the deleted measurements and schedules" in changes
    assert "1 AI-send log entry unlinked (the privacy record stays; the crop files are deleted)" in changes
    assert "1 revision report unlinked from this plan set" in changes
    assert "1 agent run unlinked from this plan set" in changes
    assert "1 takeoff task no longer lists these sheets" in changes
    assert "1 assembly record unlinked from the deleted measurements" in changes
    assert "1 plan set no longer replaces this one" in changes
    assert "Files: the uploaded file, 2 sheet images, viewer tiles, 1 AI crop." in changes
    assert exc.value.details["counts"]["measurements_approved"] == 2
    assert exc.value.details["approved_measurements"] == 2
    # Asking changes nothing.
    assert _count(db, "plan_sets", "WHERE id = ?", (seeded["plan_set_id"],)) == 1
    assert _count(db, "measurements") == 5
    assert seeded["plan_file"].is_file()


def test_delete_sheet_asks_first_and_warns_about_approved(db, seeded):
    ctx = personal_context()
    with pytest.raises(ConfirmationRequired) as exc:
        plan_delete.delete_sheet(db, ctx, seeded["sheet_1"])
    assert "1 approved measurement" in exc.value.message
    assert "deleting removes it" in exc.value.message
    assert "A-101 (FIRST FLOOR PLAN)" in exc.value.message
    changes = exc.value.details["changes"]
    assert "Sheet A-101 (FIRST FLOOR PLAN)" in changes
    assert "2 viewports" in changes
    assert "2 drawing objects" in changes
    # The cross-linked measurement counts: it has no sheet link but it counted an object on sheet 1.
    assert "3 measurements (1 approved, 2 proposed)" in changes
    assert "1 auto-run" in changes
    assert "1 schedule (2 rows)" in changes
    assert "1 legend" in changes
    assert "1 symbol detection" in changes
    assert "2 reviews of the deleted measurements and schedules" in changes
    assert "1 symbol example no longer names a deleted sheet" in changes
    assert "1 takeoff task no longer lists these sheets" in changes
    assert "1 assembly record unlinked from the deleted measurements" in changes
    assert "1 AI-send log entry unlinked (the privacy record stays; the crop files are deleted)" in changes
    assert "Files: the sheet image, its tiles, 1 AI crop." in changes
    # The plan set's dictionary belongs to the set, not the sheet: it is not in the changes.
    assert not [c for c in changes if "symbol definition" in c]
    assert _count(db, "sheets", "WHERE id = ?", (seeded["sheet_1"],)) == 1


# ------------------------------------------------------------------ the cascade


def test_delete_plan_set_cascades_everything(db, seeded):
    ctx = personal_context()
    out = plan_delete.delete_plan_set(db, ctx, seeded["plan_set_id"], confirm=True)
    assert out["deleted"]["sheets"] == 2
    assert out["deleted"]["measurements"] == 4
    assert out["deleted"]["measurements_approved"] == 2
    assert "Removed Plan set" in out["summary"]
    ps = seeded["plan_set_id"]
    assert _count(db, "plan_sets", "WHERE id = ?", (ps,)) == 0
    for table, where, args in (
            ("sheets", "WHERE plan_set_id = ?", (ps,)),
            ("viewports", "WHERE sheet_id IN (?, ?)", (seeded["sheet_1"], seeded["sheet_2"])),
            ("drawing_objects", "WHERE sheet_id IN (?, ?)", (seeded["sheet_1"], seeded["sheet_2"])),
            ("measurements", "WHERE id IN (?,?,?,?)", (seeded["approved_1"], seeded["proposed_1"],
                                                       seeded["approved_2"], seeded["cross"])),
            ("auto_runs", "WHERE id = ?", (seeded["auto_run"],)),
            ("schedules", "WHERE id = ?", (seeded["schedule"],)),
            ("schedule_rows", "WHERE schedule_id = ?", (seeded["schedule"],)),
            ("legends", "WHERE sheet_id IN (?, ?)", (seeded["sheet_1"], seeded["sheet_2"])),
            ("symbol_detections", "WHERE plan_set_id = ?", (ps,)),
            ("symbol_definitions", "WHERE plan_set_id = ?", (ps,)),
            ("symbol_examples", "WHERE definition_id = ?", (seeded["definition"],)),
            ("reviews", "WHERE target_id IN (?, ?)", (seeded["approved_1"], seeded["row_1"]))):
        assert _count(db, table, where, args) == 0, table
    # History that belongs to something else stays, unlinked.
    rep = db.execute("SELECT old_plan_set_id, flagged_measurement_ids FROM revision_reports WHERE id = ?",
                     (seeded["report"],)).fetchone()
    assert rep["old_plan_set_id"] is None and json.loads(rep["flagged_measurement_ids"]) == []
    assert db.execute("SELECT plan_set_id FROM runs WHERE id = ?",
                      (seeded["run"],)).fetchone()["plan_set_id"] is None
    assert json.loads(db.execute("SELECT sheet_ids_json FROM takeoff_tasks WHERE id = ?",
                                 (seeded["task"],)).fetchone()["sheet_ids_json"]) == []
    log = db.execute("SELECT sheet_id, file_path FROM ai_send_log WHERE id = ?",
                     (seeded["log"],)).fetchone()
    assert log["sheet_id"] is None and log["file_path"] is None
    asm = db.execute("SELECT measurement_ids, sources_json FROM assembly_uses WHERE id = ?",
                     (seeded["assembly"],)).fetchone()
    assert json.loads(asm["measurement_ids"]) == []
    assert json.loads(asm["sources_json"])["slab_sqft"]["measurement_ids"] == []
    assert db.execute("SELECT supersedes_plan_set_id FROM plan_sets WHERE id = ?",
                      (seeded["newer"],)).fetchone()["supersedes_plan_set_id"] is None
    # The other plan set, its sheet and its measurement are untouched.
    assert _count(db, "plan_sets", "WHERE id = ?", (seeded["other"],)) == 1
    assert _count(db, "sheets", "WHERE id = ?", (seeded["other_sheet"],)) == 1
    assert _count(db, "measurements", "WHERE id = ?", (seeded["other_measurement"],)) == 1
    assert seeded["other_file"].is_file()
    # Files: the upload, the work folder (images, dictionary, template crop), tiles and the AI crop.
    assert not seeded["plan_file"].exists()
    assert not seeded["work"].exists()
    assert not list((config.data_dir() / "tiles").glob("sheet*_abc123"))
    assert not seeded["crop"].exists()
    assert out["files"]["files_deleted"] >= 2      # the upload and the crop (images go with the work folder)
    assert out["files"]["dirs_deleted"] >= 3       # the work folder and two tile caches
    assert out["files"]["files_failed"] == []
    # The audit trail records the removal.
    assert _count(db, "estimate_events", "WHERE action = 'plan_set_removed' AND estimate_id = ?",
                  (seeded["estimate_id"],)) == 1


def test_delete_sheet_cascades_only_that_sheet(db, seeded):
    ctx = personal_context()
    out = plan_delete.delete_sheet(db, ctx, seeded["sheet_1"], confirm=True)
    assert out["deleted"]["sheets"] == 1
    assert out["deleted"]["measurements"] == 3
    s1, s2 = seeded["sheet_1"], seeded["sheet_2"]
    assert _count(db, "sheets", "WHERE id = ?", (s1,)) == 0
    assert _count(db, "sheets", "WHERE id = ?", (s2,)) == 1
    assert _count(db, "viewports", "WHERE sheet_id = ?", (s1,)) == 0
    assert _count(db, "viewports", "WHERE sheet_id = ?", (s2,)) == 1
    assert _count(db, "drawing_objects", "WHERE sheet_id = ?", (s1,)) == 0
    assert _count(db, "drawing_objects", "WHERE sheet_id = ?", (s2,)) == 1
    assert _count(db, "measurements", "WHERE id IN (?,?,?)",
                  (seeded["approved_1"], seeded["proposed_1"], seeded["cross"])) == 0
    assert _count(db, "measurements", "WHERE id = ?", (seeded["approved_2"],)) == 1
    assert _count(db, "auto_runs", "WHERE id = ?", (seeded["auto_run"],)) == 0
    assert _count(db, "schedules", "WHERE id = ?", (seeded["schedule"],)) == 0
    assert _count(db, "schedule_rows", "WHERE schedule_id = ?", (seeded["schedule"],)) == 0
    assert _count(db, "legends", "WHERE sheet_id = ?", (s1,)) == 0
    assert _count(db, "legends", "WHERE sheet_id = ?", (s2,)) == 1
    assert _count(db, "symbol_detections", "WHERE sheet_id = ?", (s1,)) == 0
    assert _count(db, "symbol_detections", "WHERE sheet_id = ?", (s2,)) == 1
    # The plan set and its dictionary stay; the example from sheet 1 loses its sheet link.
    assert _count(db, "plan_sets", "WHERE id = ?", (seeded["plan_set_id"],)) == 1
    assert _count(db, "symbol_definitions", "WHERE id = ?", (seeded["definition"],)) == 1
    assert db.execute("SELECT source_sheet_id FROM symbol_examples WHERE id = ?",
                      (seeded["example"],)).fetchone()["source_sheet_id"] is None
    assert json.loads(db.execute("SELECT sheet_ids_json FROM takeoff_tasks WHERE id = ?",
                                 (seeded["task"],)).fetchone()["sheet_ids_json"]) == [s2]
    assert _count(db, "estimate_events", "WHERE action = 'sheet_removed' AND estimate_id = ?",
                  (seeded["estimate_id"],)) == 1
    # Files: sheet 1's image and tiles go; sheet 2's, the upload and the work folder stay.
    assert not seeded["img_1"].exists()
    assert seeded["img_2"].is_file()
    assert seeded["plan_file"].is_file()
    assert seeded["work"].is_dir()
    assert not list((config.data_dir() / "tiles").glob(f"sheet{s1}_*"))
    assert list((config.data_dir() / "tiles").glob(f"sheet{s2}_*"))
    assert not seeded["crop"].exists()
    assert out["files"]["files_failed"] == []


def test_delete_last_sheet_leaves_an_empty_plan_set(db, seeded):
    ctx = personal_context()
    plan_delete.delete_sheet(db, ctx, seeded["sheet_1"], confirm=True)
    plan_delete.delete_sheet(db, ctx, seeded["sheet_2"], confirm=True)
    assert _count(db, "plan_sets", "WHERE id = ?", (seeded["plan_set_id"],)) == 1
    assert _count(db, "sheets", "WHERE plan_set_id = ?", (seeded["plan_set_id"],)) == 0
    assert seeded["plan_file"].is_file()     # the upload stays with the plan set


def test_delete_unprocessed_plan_set(db, estimator_sandbox):
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Bare")["id"]
    plans = estimator_sandbox / "projects" / f"estimate_{est:04d}" / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    f = plans / "9_bare.pdf"
    f.write_bytes(b"%PDF-fake")
    ps = _ins(db, "INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                  " file_size, sha256, revision, status, uploaded_by, created_at)"
                  " VALUES (?,?,?,?,?,?,?,?,'uploaded',?,?)",
              (COMPANY, est, str(f), "bare.pdf", "pdf", 9, "dd", 1, "owner", NOW))
    with pytest.raises(ConfirmationRequired) as exc:
        plan_delete.delete_plan_set(db, ctx, ps)
    assert exc.value.details["counts"]["sheets"] == 0
    assert "approved measurement" not in exc.value.message
    out = plan_delete.delete_plan_set(db, ctx, ps, confirm=True)
    assert out["deleted"]["sheets"] == 0 and out["deleted"]["measurements"] == 0
    assert _count(db, "plan_sets", "WHERE id = ?", (ps,)) == 0
    assert not f.exists()


# ------------------------------------------------------------------ guards


def test_delete_missing_ids_raise_not_found(db, seeded):
    ctx = personal_context()
    with pytest.raises(NotFound):
        plan_delete.delete_plan_set(db, ctx, 99999, confirm=True)
    with pytest.raises(NotFound):
        plan_delete.delete_sheet(db, ctx, 99999, confirm=True)


def test_delete_refuses_non_edit_roles(db, seeded):
    for role in ("reviewer", "office", "field"):
        ctx = RequestContext(company_id=COMPANY, user_id=role, role=role, mode="server")
        with pytest.raises(PermissionDenied):
            plan_delete.delete_plan_set(db, ctx, seeded["plan_set_id"], confirm=True)
        with pytest.raises(PermissionDenied):
            plan_delete.delete_sheet(db, ctx, seeded["sheet_1"], confirm=True)
    assert _count(db, "plan_sets", "WHERE id = ?", (seeded["plan_set_id"],)) == 1


def test_delete_is_transactional(db, seeded, monkeypatch):
    """A failure halfway through leaves the rows AND the files exactly as they were."""
    from estimator.estimating import service as svc

    def boom(*args, **kwargs):
        raise RuntimeError("the audit log is down")

    monkeypatch.setattr(svc, "_log", boom)
    with pytest.raises(RuntimeError):
        plan_delete.delete_plan_set(db, personal_context(), seeded["plan_set_id"], confirm=True)
    assert _count(db, "plan_sets", "WHERE id = ?", (seeded["plan_set_id"],)) == 1
    assert _count(db, "sheets", "WHERE plan_set_id = ?", (seeded["plan_set_id"],)) == 2
    assert _count(db, "measurements") == 5
    assert _count(db, "symbol_definitions", "WHERE plan_set_id = ?", (seeded["plan_set_id"],)) == 1
    assert seeded["plan_file"].is_file()
    assert seeded["work"].is_dir()


def test_delete_with_files_already_missing(db, seeded):
    # The individually-tracked files (upload, example image, AI crop) are already gone; the sheet
    # images live inside the work folder, so one of them being gone is covered by the folder too.
    seeded["plan_file"].unlink()
    seeded["example_image"].unlink()
    seeded["crop"].unlink()
    seeded["img_1"].unlink()
    out = plan_delete.delete_plan_set(db, personal_context(), seeded["plan_set_id"], confirm=True)
    assert _count(db, "plan_sets", "WHERE id = ?", (seeded["plan_set_id"],)) == 0
    assert out["files"]["files_missing"] == 3
    assert out["files"]["files_failed"] == []


def test_delete_skips_files_outside_the_data_dir(db, seeded, tmp_path):
    outside = tmp_path / "elsewhere.png"
    outside.write_bytes(b"PNG-fake")
    db.execute("UPDATE sheets SET image_path = ? WHERE id = ?", (str(outside), seeded["sheet_1"]))
    out = plan_delete.delete_sheet(db, personal_context(), seeded["sheet_1"], confirm=True)
    assert _count(db, "sheets", "WHERE id = ?", (seeded["sheet_1"],)) == 0
    assert outside.is_file()                                   # never touched: not the Estimator's file
    assert str(outside) in out["files"]["files_skipped"]
