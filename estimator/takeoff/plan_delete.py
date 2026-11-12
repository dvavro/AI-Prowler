"""Removing plan sets and sheets, with everything that came from them.

There was no way to remove plans at all: delete_plan_set removes one plan set
and delete_sheet removes one sheet, both asking first (the change is
destructive and can't be undone). The ask lists exactly what goes, with the
approved measurements called out, because deleting approved work is the
dangerous case - the warning is the protection; the owner decides after
seeing it.

What goes with a plan set: its sheets, their viewports, drawing objects,
measurements (any status), auto-runs, schedules and their rows, legends,
symbol detections, the plan set's symbol dictionary (definitions and their
example images), reviews of the deleted measurements and schedule rows, and
the files: the uploaded plan file, the sheet images and the plan set's work
folder (the symbol dictionary file, template crops and any DWG conversion),
the viewer tiles for its sheets, and the AI crops sent from its sheets.
History that belongs to something else stays but is unlinked: agent runs and
revision reports lose the plan-set link, a plan set that replaced this one
loses the supersedes link, takeoff tasks and assembly records lose the dead
sheet and measurement ids, and AI-send log entries keep their privacy record
(what was sent, when, why) but no longer name a sheet. Priced estimate lines
stay: the measurements were their inputs, not the lines themselves.

A sheet goes the same way, minus the plan set itself: after the last sheet of
a plan set is removed, the (now empty) plan set stays, to be removed
separately. The plan set's symbol dictionary also stays: it belongs to the
set, not the sheet - only examples that came from the deleted sheet lose
their sheet link.

Everything is deleted explicitly, in dependency order, in one transaction,
rather than relying on the database's ON DELETE actions: measurements are
ON DELETE SET NULL (they would survive as orphans), and runs, auto-runs,
the AI-send log and the takeoff tasks have no foreign key at all. Files go
after the database commit (a file can't roll back), best-effort, and only
inside the Estimator's own data folder: a file that is already gone, or one
that lives outside the folder, never fails the delete.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.drawing_model import store
from estimator.estimating import service


def _marks(ids) -> str:
    return ",".join("?" for _ in ids)


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _json_ids(value) -> list:
    """A JSON list of ids, or [] when it isn't one (null, bad JSON, not a list)."""
    try:
        items = json.loads(value or "[]")
    except ValueError:
        return []
    return items if isinstance(items, list) else []


def _scrub_ids(value, dead: set[int]) -> tuple[list, bool]:
    """Drop the dead ids from a JSON list. Returns (kept, changed)."""
    items = _json_ids(value)
    kept = [i for i in items if i not in dead]
    return kept, len(kept) != len(items)


# ------------------------------------------------------------------ scope: what a delete touches


def _sheet_scope(conn, company: str, sheet_ids: list[int]) -> dict:
    """Everything under a set of sheets: viewports, objects, measurements, and the rows tied to them."""
    scope: dict = {"sheet_ids": list(sheet_ids)}
    if not sheet_ids:
        return {**scope, "viewport_ids": [], "object_ids": [], "measurement_ids": [],
                "measurements_by_status": {}, "auto_run_ids": [], "schedule_ids": [],
                "schedule_row_ids": [], "legend_ids": [], "detection_ids": [], "log_ids": [],
                "log_files": [], "review_ids": [], "task_ids": [], "sheet_images": []}
    sm = _marks(sheet_ids)
    scope["sheet_images"] = [r[0] for r in conn.execute(
        f"SELECT image_path FROM sheets WHERE id IN ({sm}) AND image_path IS NOT NULL", sheet_ids)]
    scope["viewport_ids"] = [r[0] for r in conn.execute(
        f"SELECT id FROM viewports WHERE sheet_id IN ({sm})", sheet_ids)]
    vm = _marks(scope["viewport_ids"])
    obj_sql = f"SELECT id FROM drawing_objects WHERE sheet_id IN ({sm})"
    obj_args: list = list(sheet_ids)
    if scope["viewport_ids"]:
        obj_sql += f" OR viewport_id IN ({vm})"
        obj_args += scope["viewport_ids"]
    scope["object_ids"] = [r[0] for r in conn.execute(obj_sql, obj_args)]
    scope.update(_measurements_for(conn, company, set(sheet_ids), set(scope["viewport_ids"]),
                                   set(scope["object_ids"])))
    auto_sql = f"SELECT id FROM auto_runs WHERE company_id = ? AND sheet_id IN ({sm})"
    auto_args: list = [company, *sheet_ids]
    if scope["viewport_ids"]:
        auto_sql = (f"SELECT id FROM auto_runs WHERE company_id = ? AND "
                    f"(sheet_id IN ({sm}) OR viewport_id IN ({vm}))")
        auto_args = [company, *sheet_ids, *scope["viewport_ids"]]
    scope["auto_run_ids"] = [r[0] for r in conn.execute(auto_sql, auto_args)]
    scope["schedule_ids"] = [r[0] for r in conn.execute(
        f"SELECT id FROM schedules WHERE sheet_id IN ({sm})", sheet_ids)]
    if scope["schedule_ids"]:
        cm = _marks(scope["schedule_ids"])
        scope["schedule_row_ids"] = [r[0] for r in conn.execute(
            f"SELECT id FROM schedule_rows WHERE schedule_id IN ({cm})", scope["schedule_ids"])]
    else:
        scope["schedule_row_ids"] = []
    scope["legend_ids"] = [r[0] for r in conn.execute(
        f"SELECT id FROM legends WHERE sheet_id IN ({sm})", sheet_ids)]
    det_sql = f"SELECT id FROM symbol_detections WHERE sheet_id IN ({sm})"
    det_args: list = list(sheet_ids)
    if scope["viewport_ids"]:
        det_sql += f" OR viewport_id IN ({vm})"
        det_args += scope["viewport_ids"]
    if scope["object_ids"]:
        om = _marks(scope["object_ids"])
        det_sql += f" OR drawing_object_id IN ({om})"
        det_args += scope["object_ids"]
    scope["detection_ids"] = [r[0] for r in conn.execute(det_sql, det_args)]
    logs = conn.execute(
        f"SELECT id, file_path FROM ai_send_log WHERE sheet_id IN ({sm})", sheet_ids).fetchall()
    scope["log_ids"] = [r[0] for r in logs]
    scope["log_files"] = [r[1] for r in logs if r[1]]
    scope["review_ids"] = _reviews_for(conn, scope["measurement_ids"], scope["schedule_row_ids"])
    scope["task_ids"] = _tasks_for(conn, company, set(sheet_ids))
    return scope


def _measurements_for(conn, company: str, sheet_ids: set[int], viewport_ids: set[int],
                      object_ids: set[int]) -> dict:
    """Measurements from these sheets: by sheet or viewport, or by a drawing object they counted.

    The last case is the same rule plan_set_reread uses: a measurement counts objects, and its sheet
    link may be empty or point elsewhere, so the objects it counted are what ties it to the plans.
    """
    ids, by_status = [], {}
    for m in conn.execute("SELECT id, sheet_id, viewport_id, status, source_object_ids FROM measurements"
                          " WHERE company_id = ?", (company,)):
        mine = set(_json_ids(m["source_object_ids"]))
        if m["sheet_id"] in sheet_ids or m["viewport_id"] in viewport_ids or (mine & object_ids):
            ids.append(m["id"])
            by_status[m["status"]] = by_status.get(m["status"], 0) + 1
    return {"measurement_ids": ids, "measurements_by_status": by_status}


def _reviews_for(conn, measurement_ids: list[int], schedule_row_ids: list[int]) -> list[int]:
    """Reviews of the deleted measurements and schedule rows (detection_set reviews can't exist yet)."""
    out = []
    if measurement_ids:
        mm = _marks(measurement_ids)
        out += [r[0] for r in conn.execute(
            f"SELECT id FROM reviews WHERE target_type IN ('measurement', 'count') AND target_id IN ({mm})",
            measurement_ids)]
    if schedule_row_ids:
        rm = _marks(schedule_row_ids)
        out += [r[0] for r in conn.execute(
            f"SELECT id FROM reviews WHERE target_type = 'schedule' AND target_id IN ({rm})",
            schedule_row_ids)]
    return out


def _tasks_for(conn, company: str, sheet_ids: set[int]) -> list[int]:
    """Takeoff tasks whose sheet list names a deleted sheet (the task itself stays; the id is scrubbed)."""
    out = []
    for t in conn.execute("SELECT id, sheet_ids_json FROM takeoff_tasks WHERE company_id = ?", (company,)):
        if set(_json_ids(t["sheet_ids_json"])) & sheet_ids:
            out.append(t[0])
    return out


def _plan_set_scope(conn, ctx, ps: dict) -> dict:
    """Everything a plan-set delete touches, plus the plan-set-level rows a sheet delete leaves alone."""
    sheet_ids = [r[0] for r in conn.execute(
        "SELECT id FROM sheets WHERE plan_set_id = ? AND company_id = ?", (ps["id"], ctx.company_id))]
    scope = _sheet_scope(conn, ctx.company_id, sheet_ids)
    scope["plan_set"] = ps
    scope["estimate_id"] = ps["estimate_id"]
    scope["definition_ids"] = [r[0] for r in conn.execute(
        "SELECT id FROM symbol_definitions WHERE plan_set_id = ? AND company_id = ?", (ps["id"], ctx.company_id))]
    if scope["definition_ids"]:
        dm = _marks(scope["definition_ids"])
        ex = conn.execute(
            f"SELECT id, image_path FROM symbol_examples WHERE definition_id IN ({dm})",
            scope["definition_ids"]).fetchall()
        scope["example_ids"] = [r[0] for r in ex]
        scope["example_files"] = [r[1] for r in ex if r[1]]
        scope["surviving_detections"] = [r[0] for r in conn.execute(
            f"SELECT id FROM symbol_detections WHERE definition_id IN ({dm})", scope["definition_ids"])]
    else:
        scope["example_ids"], scope["example_files"], scope["surviving_detections"] = [], [], []
    scope["surviving_detections"] = [d for d in scope["surviving_detections"]
                                     if d not in set(scope["detection_ids"])]
    scope["report_ids"] = [r[0] for r in conn.execute(
        "SELECT id FROM revision_reports WHERE company_id = ? AND (old_plan_set_id = ? OR new_plan_set_id = ?)",
        (ctx.company_id, ps["id"], ps["id"]))]
    scope["run_ids"] = [r[0] for r in conn.execute(
        "SELECT id FROM runs WHERE company_id = ? AND plan_set_id = ?", (ctx.company_id, ps["id"]))]
    scope["superseder_ids"] = [r[0] for r in conn.execute(
        "SELECT id FROM plan_sets WHERE company_id = ? AND supersedes_plan_set_id = ?",
        (ctx.company_id, ps["id"]))]
    scope["surviving_examples"] = _surviving_examples(conn, scope["definition_ids"], set(sheet_ids))
    scope.update(_scrub_scope(conn, ctx.company_id, scope))
    return scope


def _sheet_delete_scope(conn, ctx, sheet: dict, ps: dict) -> dict:
    """Everything a single-sheet delete touches. The plan set, its dictionary and sibling sheets stay."""
    scope = _sheet_scope(conn, ctx.company_id, [sheet["id"]])
    scope["sheet"] = sheet
    scope["plan_set"] = ps
    scope["estimate_id"] = ps["estimate_id"]
    scope["definition_ids"] = []
    scope["example_ids"], scope["example_files"], scope["surviving_detections"] = [], [], []
    scope["report_ids"], scope["run_ids"], scope["superseder_ids"] = [], [], []
    scope["surviving_examples"] = _surviving_examples(conn, [], {sheet["id"]})
    scope.update(_scrub_scope(conn, ctx.company_id, scope))
    return scope


def _scrub_scope(conn, company: str, scope: dict) -> dict:
    """Surviving rows whose JSON id-lists name a deleted measurement, object or sheet."""
    return {
        "assembly_ids": _assemblies_for(conn, company, set(scope["measurement_ids"])),
        "report_measurement_ids": _reports_for_measurements(conn, company, set(scope["measurement_ids"])),
        "auto_run_measurement_ids": _auto_runs_for_measurements(conn, company, set(scope["measurement_ids"]),
                                                                set(scope["auto_run_ids"])),
        "review_object_ids": _reviews_for_objects(conn, company, set(scope["object_ids"]),
                                                  set(scope["review_ids"])),
        "schedule_object_ids": _schedule_rows_for_objects(conn, company, set(scope["object_ids"]),
                                                          set(scope["schedule_row_ids"])),
    }


def _surviving_examples(conn, deleted_definition_ids: list[int], sheet_ids: set[int]) -> list[int]:
    """Examples that stay (their definition survives) but came from a deleted sheet: their sheet link is cleared."""
    if not sheet_ids:
        return []
    sm = _marks(sheet_ids)
    sql = f"SELECT id FROM symbol_examples WHERE source_sheet_id IN ({sm})"
    args: list = list(sheet_ids)
    if deleted_definition_ids:
        sql += f" AND definition_id NOT IN ({_marks(deleted_definition_ids)})"
        args += deleted_definition_ids
    return [r[0] for r in conn.execute(sql, args)]


def _assemblies_for(conn, company: str, measurement_ids: set[int]) -> list[int]:
    """Assembly records whose measurement list names a deleted measurement (the priced lines stay)."""
    if not measurement_ids:
        return []
    out = []
    for a in conn.execute("SELECT id, measurement_ids FROM assembly_uses WHERE company_id = ?", (company,)):
        if set(_json_ids(a["measurement_ids"])) & measurement_ids:
            out.append(a[0])
    return out


def _reports_for_measurements(conn, company: str, measurement_ids: set[int]) -> list[int]:
    """Revision reports whose flagged or carried measurement lists name a deleted measurement."""
    if not measurement_ids:
        return []
    out = []
    for r in conn.execute("SELECT id, flagged_measurement_ids, carried_measurement_ids FROM revision_reports"
                          " WHERE company_id = ?", (company,)):
        if (set(_json_ids(r["flagged_measurement_ids"]))
                | set(_json_ids(r["carried_measurement_ids"]))) & measurement_ids:
            out.append(r[0])
    return out


def _auto_runs_for_measurements(conn, company: str, measurement_ids: set[int],
                                deleted_run_ids: set[int]) -> list[int]:
    """Surviving auto-runs whose measurement list names a deleted measurement."""
    if not measurement_ids:
        return []
    out = []
    for r in conn.execute("SELECT id, measurement_ids_json FROM auto_runs WHERE company_id = ?", (company,)):
        if r[0] in deleted_run_ids:
            continue
        if set(_json_ids(r["measurement_ids_json"])) & measurement_ids:
            out.append(r[0])
    return out


def _reviews_for_objects(conn, company: str, object_ids: set[int], deleted_review_ids: set[int]) -> list[int]:
    """Surviving reviews whose object list names a deleted drawing object."""
    if not object_ids:
        return []
    out = []
    for r in conn.execute("SELECT id, object_ids FROM reviews WHERE company_id = ?", (company,)):
        if r[0] in deleted_review_ids:
            continue
        if set(_json_ids(r["object_ids"])) & object_ids:
            out.append(r[0])
    return out


def _schedule_rows_for_objects(conn, company: str, object_ids: set[int],
                               deleted_row_ids: set[int]) -> list[int]:
    """Surviving schedule rows whose linked plan tags name a deleted drawing object."""
    if not object_ids:
        return []
    out = []
    for r in conn.execute("SELECT id, linked_object_ids FROM schedule_rows WHERE company_id = ?", (company,)):
        if r[0] in deleted_row_ids:
            continue
        if set(_json_ids(r["linked_object_ids"])) & object_ids:
            out.append(r[0])
    return out


# ------------------------------------------------------------------ files


def _files_for_plan_set(scope: dict, root: Path) -> tuple[list[Path], list[Path]]:
    """(files, folders) a plan-set delete removes: the upload, the work folder, tiles and AI crops."""
    ps = scope["plan_set"]
    files = [Path(ps["file_path"])] if ps.get("file_path") else []
    files += [Path(p) for p in scope["log_files"]]
    files += [Path(p) for p in scope["example_files"]]
    folders = [root / "projects" / f"estimate_{ps['estimate_id']:04d}" / "plans" / f"{ps['id']}_sheets"]
    for sid in scope["sheet_ids"]:
        folders += _tile_dirs(root, sid)
    return files, folders


def _files_for_sheet(scope: dict, root: Path) -> tuple[list[Path], list[Path]]:
    """(files, folders) a sheet delete removes: the sheet image, its tiles and its AI crops."""
    sheet = scope["sheet"]
    files = [Path(sheet["image_path"])] if sheet.get("image_path") else []
    files += [Path(p) for p in scope["log_files"]]
    return files, _tile_dirs(root, sheet["id"])


def _tile_dirs(root: Path, sheet_id: int) -> list[Path]:
    """The viewer's tile caches for a sheet (sheet<id>_<key>/), whatever key they were rendered under."""
    tiles = root / "tiles"
    if not tiles.is_dir():
        return []
    return [p for p in tiles.glob(f"sheet{int(sheet_id)}_*") if p.is_dir()]


def _remove_files(files: list[Path], folders: list[Path], root: Path) -> dict:
    """Delete files and folders, best-effort and only inside the Estimator's data folder.

    A file that is already gone, or one that lives outside the folder, never fails the delete:
    both are reported, so the caller can say what happened.
    """
    out = {"files_deleted": 0, "dirs_deleted": 0, "files_missing": 0, "files_skipped": [], "files_failed": []}
    for f in files:
        try:
            resolved = f.resolve()
        except OSError:
            out["files_failed"].append(str(f))
            continue
        if root not in resolved.parents:
            out["files_skipped"].append(str(f))
            continue
        try:
            if resolved.is_dir():
                continue
            resolved.unlink()
            out["files_deleted"] += 1
        except FileNotFoundError:
            out["files_missing"] += 1
        except OSError:
            out["files_failed"].append(str(f))
    for d in folders:
        try:
            resolved = d.resolve()
        except OSError:
            out["files_failed"].append(str(d))
            continue
        if root not in resolved.parents:
            out["files_skipped"].append(str(d))
            continue
        if not resolved.exists():
            continue
        try:
            shutil.rmtree(resolved)
            out["dirs_deleted"] += 1
        except OSError:
            out["files_failed"].append(str(d))
    return out


# ------------------------------------------------------------------ the ask: question + changes


def _counts(scope: dict) -> dict:
    by_status = scope["measurements_by_status"]
    return {
        "sheets": len(scope["sheet_ids"]),
        "viewports": len(scope["viewport_ids"]),
        "drawing_objects": len(scope["object_ids"]),
        "measurements": len(scope["measurement_ids"]),
        "measurements_approved": by_status.get("approved", 0),
        "measurements_proposed": by_status.get("proposed", 0),
        "measurements_rejected": by_status.get("rejected", 0),
        "auto_runs": len(scope["auto_run_ids"]),
        "schedules": len(scope["schedule_ids"]),
        "schedule_rows": len(scope["schedule_row_ids"]),
        "legends": len(scope["legend_ids"]),
        "symbol_detections": len(scope["detection_ids"]),
        "symbol_definitions": len(scope["definition_ids"]),
        "symbol_examples": len(scope["example_ids"]),
        "reviews": len(scope["review_ids"]),
        "ai_send_log_entries": len(scope["log_ids"]),
        "revision_reports_unlinked": len(scope["report_ids"]),
        "runs_unlinked": len(scope["run_ids"]),
        "takeoff_tasks_scrubbed": len(scope["task_ids"]),
        "assembly_uses_scrubbed": len(scope["assembly_ids"]),
        "plan_sets_unlinked": len(scope["superseder_ids"]),
        "examples_unlinked": len(scope["surviving_examples"]),
    }


def _changes(counts: dict, what: str, file_line: str) -> list[str]:
    """One plain line per thing the delete removes or unlinks; only the ones that exist."""
    lines = [what]
    if counts["sheets"]:
        lines.append(_plural(counts["sheets"], "sheet"))
    if counts["viewports"]:
        lines.append(_plural(counts["viewports"], "viewport"))
    if counts["drawing_objects"]:
        lines.append(_plural(counts["drawing_objects"], "drawing object"))
    if counts["measurements"]:
        parts = []
        for status in ("approved", "proposed", "rejected"):
            if counts[f"measurements_{status}"]:
                parts.append(f"{counts[f'measurements_{status}']} {status}")
        lines.append(_plural(counts["measurements"], "measurement") + " (" + ", ".join(parts) + ")")
    if counts["auto_runs"]:
        lines.append(_plural(counts["auto_runs"], "auto-run"))
    if counts["schedules"]:
        lines.append(_plural(counts["schedules"], "schedule")
                     + (f" ({_plural(counts['schedule_rows'], 'row')})" if counts["schedule_rows"] else ""))
    if counts["legends"]:
        lines.append(_plural(counts["legends"], "legend"))
    if counts["symbol_detections"]:
        lines.append(_plural(counts["symbol_detections"], "symbol detection"))
    if counts["symbol_definitions"]:
        lines.append(_plural(counts["symbol_definitions"], "symbol definition")
                     + " (the plan set's dictionary)"
                     + (f" and {_plural(counts['symbol_examples'], 'example image')}"
                        if counts["symbol_examples"] else ""))
    if counts["reviews"]:
        lines.append(_plural(counts["reviews"], "review")
                     + " of the deleted measurements and schedules")
    if counts["ai_send_log_entries"]:
        lines.append(_plural(counts["ai_send_log_entries"], "AI-send log entry", "AI-send log entries")
                     + " unlinked (the privacy record stays; the crop files are deleted)")
    if counts["revision_reports_unlinked"]:
        lines.append(_plural(counts["revision_reports_unlinked"], "revision report")
                     + " unlinked from this plan set")
    if counts["runs_unlinked"]:
        lines.append(_plural(counts["runs_unlinked"], "agent run") + " unlinked from this plan set")
    if counts["takeoff_tasks_scrubbed"]:
        lines.append(_plural(counts["takeoff_tasks_scrubbed"], "takeoff task")
                     + " no longer lists these sheets")
    if counts["assembly_uses_scrubbed"]:
        lines.append(_plural(counts["assembly_uses_scrubbed"], "assembly record")
                     + " unlinked from the deleted measurements")
    if counts["examples_unlinked"]:
        lines.append(_plural(counts["examples_unlinked"], "symbol example")
                     + " no longer names a deleted sheet")
    if counts["plan_sets_unlinked"]:
        lines.append(_plural(counts["plan_sets_unlinked"], "plan set")
                     + " no longer replaces this one")
    if file_line:
        lines.append(file_line)
    return lines


def _ask(counts: dict, question: str, what: str, file_line: str, **details) -> None:
    """Raise the ask-first question, with the approved measurements called out in the question itself."""
    approved = counts["measurements_approved"]
    if approved:
        question += (f" It has {_plural(approved, 'approved measurement')} — deleting removes "
                     f"{'it' if approved == 1 else 'them'}.")
    store._confirm(False, question + " This can't be undone.",
                   changes=_changes(counts, what, file_line), counts=counts,
                   approved_measurements=approved, **details)


# ------------------------------------------------------------------ the delete


def _scrub_json_lists(conn, scope: dict) -> None:
    """Drop dead ids from the JSON lists on rows that survive (assemblies, reports, tasks, runs, reviews)."""
    dead_measurements = set(scope["measurement_ids"])
    dead_objects = set(scope["object_ids"])
    dead_sheets = set(scope["sheet_ids"])
    for aid in scope["assembly_ids"]:
        row = conn.execute("SELECT measurement_ids, sources_json FROM assembly_uses WHERE id = ?", (aid,)).fetchone()
        kept, changed = _scrub_ids(row["measurement_ids"], dead_measurements)
        try:
            sources = json.loads(row["sources_json"] or "{}")
        except ValueError:
            sources = {}
        sources_changed = False
        if isinstance(sources, dict):
            for entry in sources.values():
                if isinstance(entry, dict) and "measurement_ids" in entry:
                    kept_nested, changed_nested = _scrub_ids(json.dumps(entry["measurement_ids"]),
                                                             dead_measurements)
                    if changed_nested:
                        entry["measurement_ids"] = kept_nested
                        sources_changed = True
        if changed or sources_changed:
            conn.execute("UPDATE assembly_uses SET measurement_ids = ?, sources_json = ? WHERE id = ?",
                         (json.dumps(kept), json.dumps(sources), aid))
    for rid in scope["report_measurement_ids"]:
        row = conn.execute("SELECT flagged_measurement_ids, carried_measurement_ids, changed_object_ids"
                           " FROM revision_reports WHERE id = ?", (rid,)).fetchone()
        flagged, c1 = _scrub_ids(row["flagged_measurement_ids"], dead_measurements)
        carried, c2 = _scrub_ids(row["carried_measurement_ids"], dead_measurements)
        changed, c3 = _scrub_ids(row["changed_object_ids"], dead_objects)
        if c1 or c2 or c3:
            conn.execute("UPDATE revision_reports SET flagged_measurement_ids = ?, carried_measurement_ids = ?,"
                         " changed_object_ids = ? WHERE id = ?",
                         (json.dumps(flagged), json.dumps(carried), json.dumps(changed), rid))
    for tid in scope["task_ids"]:
        row = conn.execute("SELECT sheet_ids_json FROM takeoff_tasks WHERE id = ?", (tid,)).fetchone()
        kept, changed = _scrub_ids(row["sheet_ids_json"], dead_sheets)
        if changed:
            conn.execute("UPDATE takeoff_tasks SET sheet_ids_json = ? WHERE id = ?", (json.dumps(kept), tid))
    for rid in scope["auto_run_measurement_ids"]:
        row = conn.execute("SELECT measurement_ids_json FROM auto_runs WHERE id = ?", (rid,)).fetchone()
        kept, changed = _scrub_ids(row["measurement_ids_json"], dead_measurements)
        if changed:
            conn.execute("UPDATE auto_runs SET measurement_ids_json = ? WHERE id = ?", (json.dumps(kept), rid))
    for rid in scope["review_object_ids"]:
        row = conn.execute("SELECT object_ids FROM reviews WHERE id = ?", (rid,)).fetchone()
        kept, changed = _scrub_ids(row["object_ids"], dead_objects)
        if changed:
            conn.execute("UPDATE reviews SET object_ids = ? WHERE id = ?", (json.dumps(kept), rid))
    for rid in scope["schedule_object_ids"]:
        row = conn.execute("SELECT linked_object_ids FROM schedule_rows WHERE id = ?", (rid,)).fetchone()
        kept, changed = _scrub_ids(row["linked_object_ids"], dead_objects)
        if changed:
            conn.execute("UPDATE schedule_rows SET linked_object_ids = ? WHERE id = ?", (json.dumps(kept), rid))


def _delete_rows(conn, scope: dict, plan_set: bool) -> None:
    """Delete the scoped rows, leaves first, inside the caller's transaction."""
    company = scope["plan_set"]["company_id"]
    _scrub_json_lists(conn, scope)
    if scope["review_ids"]:
        conn.execute(f"DELETE FROM reviews WHERE id IN ({_marks(scope['review_ids'])})", scope["review_ids"])
    if scope["auto_run_ids"]:
        conn.execute(f"DELETE FROM auto_runs WHERE id IN ({_marks(scope['auto_run_ids'])})", scope["auto_run_ids"])
    if scope["measurement_ids"]:
        conn.execute(f"DELETE FROM measurements WHERE id IN ({_marks(scope['measurement_ids'])})",
                     scope["measurement_ids"])
    if scope["detection_ids"]:
        conn.execute(f"DELETE FROM symbol_detections WHERE id IN ({_marks(scope['detection_ids'])})",
                     scope["detection_ids"])
    if scope["surviving_detections"]:
        conn.execute(f"UPDATE symbol_detections SET definition_id = NULL"
                     f" WHERE id IN ({_marks(scope['surviving_detections'])})", scope["surviving_detections"])
    if scope["example_ids"]:
        conn.execute(f"DELETE FROM symbol_examples WHERE id IN ({_marks(scope['example_ids'])})",
                     scope["example_ids"])
    if scope["surviving_examples"]:
        conn.execute(f"UPDATE symbol_examples SET source_sheet_id = NULL"
                     f" WHERE id IN ({_marks(scope['surviving_examples'])})", scope["surviving_examples"])
    if scope["definition_ids"]:
        conn.execute(f"DELETE FROM symbol_definitions WHERE id IN ({_marks(scope['definition_ids'])})",
                     scope["definition_ids"])
    if scope["schedule_row_ids"]:
        conn.execute(f"DELETE FROM schedule_rows WHERE id IN ({_marks(scope['schedule_row_ids'])})",
                     scope["schedule_row_ids"])
    if scope["schedule_ids"]:
        conn.execute(f"DELETE FROM schedules WHERE id IN ({_marks(scope['schedule_ids'])})", scope["schedule_ids"])
    if scope["legend_ids"]:
        conn.execute(f"DELETE FROM legends WHERE id IN ({_marks(scope['legend_ids'])})", scope["legend_ids"])
    if scope["log_ids"]:
        conn.execute(f"UPDATE ai_send_log SET sheet_id = NULL, file_path = NULL"
                     f" WHERE id IN ({_marks(scope['log_ids'])})", scope["log_ids"])
    if plan_set:
        if scope["run_ids"]:
            conn.execute(f"UPDATE runs SET plan_set_id = NULL WHERE id IN ({_marks(scope['run_ids'])})",
                         scope["run_ids"])
        if scope["report_ids"]:
            conn.execute("UPDATE revision_reports SET old_plan_set_id = NULL"
                         " WHERE old_plan_set_id = ? AND company_id = ?", (scope["plan_set"]["id"], company))
            conn.execute("UPDATE revision_reports SET new_plan_set_id = NULL"
                         " WHERE new_plan_set_id = ? AND company_id = ?", (scope["plan_set"]["id"], company))
        if scope["superseder_ids"]:
            conn.execute(f"UPDATE plan_sets SET supersedes_plan_set_id = NULL"
                         f" WHERE id IN ({_marks(scope['superseder_ids'])})", scope["superseder_ids"])
    if scope["object_ids"]:
        conn.execute(f"DELETE FROM drawing_objects WHERE id IN ({_marks(scope['object_ids'])})", scope["object_ids"])
    if scope["viewport_ids"]:
        conn.execute(f"DELETE FROM viewports WHERE id IN ({_marks(scope['viewport_ids'])})", scope["viewport_ids"])
    if scope["sheet_ids"]:
        conn.execute(f"DELETE FROM sheets WHERE id IN ({_marks(scope['sheet_ids'])})", scope["sheet_ids"])
    if plan_set:
        conn.execute("DELETE FROM plan_sets WHERE id = ? AND company_id = ?",
                     (scope["plan_set"]["id"], company))


def _summary(what: str, counts: dict) -> str:
    bits = []
    if counts["sheets"]:
        bits.append(_plural(counts["sheets"], "sheet"))
    if counts["measurements"]:
        bits.append(_plural(counts["measurements"], "measurement"))
    if counts["drawing_objects"]:
        bits.append(_plural(counts["drawing_objects"], "drawing object"))
    return f"Removed {what}" + (f" with {', '.join(bits)}." if bits else ".")


# ------------------------------------------------------------------ public: plan sets and sheets


def delete_plan_set(conn, ctx: RequestContext, plan_set_id: int, confirm: bool = False) -> dict:
    """Remove a plan set and everything that came from it. Asks first unless confirm=true."""
    store._role(ctx, store.EDIT_ROLES, "remove plans")
    ps = store.load_plan_set(conn, ctx, plan_set_id)
    scope = _plan_set_scope(conn, ctx, ps)
    counts = _counts(scope)
    root = config.data_dir()
    files, folders = _files_for_plan_set(scope, root)
    file_bits = []
    if ps.get("file_path"):
        file_bits.append("the uploaded file")
    if scope["sheet_images"]:
        file_bits.append(_plural(len(scope["sheet_images"]), "sheet image"))
    if len(folders) > 1:
        file_bits.append("viewer tiles")
    if scope["log_files"]:
        file_bits.append(_plural(len(scope["log_files"]), "AI crop"))
    file_line = ("Files: " + ", ".join(file_bits) + ".") if file_bits else ""
    what = f"Plan set {ps['id']} ({ps['original_name']})"
    if not confirm:
        _ask(counts, f"Remove plan set {ps['id']} ({ps['original_name']}) and everything that came from it?",
             what, file_line, plan_set_id=ps["id"], estimate_id=ps["estimate_id"])
    with service.transaction(conn):
        _delete_rows(conn, scope, plan_set=True)
        service._log(conn, ctx, ps["estimate_id"], "plan_set_removed",
                     {"plan_set_id": ps["id"], "file": ps["original_name"], "counts": counts})
    removed = _remove_files(files, folders, root.resolve())
    return {"ok": True, "removed": what, "plan_set_id": ps["id"], "estimate_id": ps["estimate_id"],
            "deleted": counts, "files": removed, "summary": _summary(what, counts)}


def delete_sheet(conn, ctx: RequestContext, sheet_id: int, confirm: bool = False) -> dict:
    """Remove one sheet and everything that came from it. The plan set stays, even when it was the last sheet.

    Asks first unless confirm=true."""
    store._role(ctx, store.EDIT_ROLES, "remove plans")
    sheet = store._load_sheet(conn, ctx, sheet_id)
    ps = store.load_plan_set(conn, ctx, sheet["plan_set_id"])
    scope = _sheet_delete_scope(conn, ctx, sheet, ps)
    counts = _counts(scope)
    root = config.data_dir()
    files, folders = _files_for_sheet(scope, root)
    file_bits = []
    if sheet.get("image_path"):
        file_bits.append("the sheet image")
    if folders:
        file_bits.append("its tiles")
    if scope["log_files"]:
        file_bits.append(_plural(len(scope["log_files"]), "AI crop"))
    file_line = "Files: " + ", ".join(file_bits) + "."
    label = sheet["sheet_no"] or f"page {sheet['page_no']}"
    if sheet.get("title"):
        label += f" ({sheet['title']})"
    what = f"Sheet {label}"
    if not confirm:
        _ask(counts, f"Remove sheet {label} from plan set {ps['id']}?",
             what, file_line, sheet_id=sheet["id"], plan_set_id=ps["id"], estimate_id=ps["estimate_id"])
    with service.transaction(conn):
        _delete_rows(conn, scope, plan_set=False)
        service._log(conn, ctx, ps["estimate_id"], "sheet_removed",
                     {"sheet_id": sheet["id"], "sheet_no": sheet["sheet_no"], "plan_set_id": ps["id"],
                      "counts": counts})
    removed = _remove_files(files, folders, root.resolve())
    return {"ok": True, "removed": what, "sheet_id": sheet["id"], "plan_set_id": ps["id"],
            "estimate_id": ps["estimate_id"], "deleted": counts, "files": removed,
            "summary": _summary(what, counts)}
