"""Symbol libraries in estimator.db (spec: "Company symbol library (learns drawing conventions)").

Three levels: the standard library shipped with AI-Prowler (a copy per company, refreshed when it changes), the
company library of definitions the company has approved, and firm profiles (the table supports them; plan sets don't
record their design firm yet, so nothing writes one).

Learning workflow (Sprint 11): when a person approves, relabels or adds a symbol in review, the company library gets
(or keeps) a definition for that item type and the symbol's line work as an approved example. Every later plan set is
searched for those examples too (estimator.drawing_model.engine passes engine_templates() to the plan engine), after
the plan set's own legend and before the standard library. Definitions are versioned; editing one never changes
detections or measurements already approved.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput, NotFound, PermissionDenied

DEFINE_ROLES = ("owner", "estimator", "reviewer")      # the same people who approve counts; never an agent
TRADES = ("electrical", "plumbing", "mechanical", "fire", "architectural", "low_voltage", "other")
MAX_EXAMPLES_PER_DEFINITION = 12
ITEM_RE = re.compile(r"^[a-z][a-z0-9_]{1,59}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _person(ctx: RequestContext, what: str) -> None:
    if ctx.role not in DEFINE_ROLES:
        raise PermissionDenied(f"only {', '.join(DEFINE_ROLES)} can {what}", role=ctx.role)
    if getattr(ctx, "agent", None):
        raise PermissionDenied(f"an agent can't {what}; a person has to", agent=ctx.agent)


def ensure_standard(conn, company_id: str) -> dict[str, int]:
    """Make sure the company has the current standard library. Returns {item type: definition id}.
    Runs inside the caller's transaction."""
    from estimator.plan_engine import symbol_library as lib

    row = conn.execute("SELECT id, version FROM symbol_libraries WHERE company_id = ? AND level = 'standard'",
                       (company_id,)).fetchone()
    if row is None:
        lib_id = conn.execute("INSERT INTO symbol_libraries (company_id, level, version, updated_at) VALUES (?, 'standard', ?, ?)",
                              (company_id, lib.VERSION, _now())).lastrowid
        have = {}
    else:
        lib_id = row["id"]
        have = {r["item_type"]: r["id"] for r in conn.execute(
            "SELECT id, item_type FROM symbol_definitions WHERE library_id = ?", (lib_id,))}
        if row["version"] >= lib.VERSION and len(have) >= len(lib.STANDARD):
            return have
    now = _now()
    for e in lib.STANDARD:
        values = (e["description"], e["trade"], json.dumps(e["aliases"]), json.dumps(e["block_words"]))
        if e["item_type"] in have:
            conn.execute("UPDATE symbol_definitions SET description = ?, trade = ?, ocr_aliases_json = ?,"
                         " block_names_json = ?, version = ? WHERE id = ?", (*values, lib.VERSION, have[e["item_type"]]))
        else:
            have[e["item_type"]] = conn.execute(
                "INSERT INTO symbol_definitions (company_id, library_id, item_type, description, trade, ocr_aliases_json,"
                " block_names_json, status, approved_by, version, created_at, confidence)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'approved', 'AI-Prowler standard library', ?, ?, '0.9')",
                (company_id, lib_id, e["item_type"], *values, lib.VERSION, now)).lastrowid
    conn.execute("UPDATE symbol_libraries SET version = ?, updated_at = ? WHERE id = ?", (lib.VERSION, now, lib_id))
    return have


def ensure_company(conn, company_id: str) -> int:
    row = conn.execute("SELECT id FROM symbol_libraries WHERE company_id = ? AND level = 'company'",
                       (company_id,)).fetchone()
    if row:
        return row["id"]
    return conn.execute("INSERT INTO symbol_libraries (company_id, level, version, updated_at) VALUES (?, 'company', 1, ?)",
                        (company_id, _now())).lastrowid


def check_item_type(item_type: str) -> str:
    it = (item_type or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not ITEM_RE.match(it):
        raise InvalidInput("item_type must be a short name like duplex_receptacle or floor_box (letters, numbers, _)",
                           field="item_type")
    return it


def _company_def(conn, company_id: str, item_type: str):
    return conn.execute("SELECT f.* FROM symbol_definitions f JOIN symbol_libraries l ON l.id = f.library_id"
                        " WHERE f.company_id = ? AND l.level = 'company' AND f.item_type = ? AND f.status != 'rejected'",
                        (company_id, item_type)).fetchone()


def definition_for(conn, company_id: str, item_type: str) -> dict:
    """What an item type means here: the company's definition first, then the standard library's."""
    row = _company_def(conn, company_id, item_type)
    if row is None:
        std = ensure_standard(conn, company_id)
        if item_type in std:
            row = conn.execute("SELECT * FROM symbol_definitions WHERE id = ?", (std[item_type],)).fetchone()
    if row is not None:
        return dict(row)
    from estimator.plan_engine import symbol_library as lib
    e = lib.BY_TYPE.get(item_type)
    return {"id": None, "item_type": item_type, "trade": e["trade"] if e else None,
            "description": e["description"] if e else item_type.replace("_", " ").capitalize()}


def learn(conn, ctx: RequestContext, item_type: str, examples: list[dict], *, description=None, trade=None,
          code=None) -> int:
    """A person confirmed symbols as item_type: keep (or create) the company definition and add their line work as
    approved examples. examples: [{"template": json or None, "image_path": str or None, "sheet_id", "detection_id"}].
    Runs inside the caller's transaction. Returns the definition id."""
    lib_id = ensure_company(conn, ctx.company_id)
    row = _company_def(conn, ctx.company_id, item_type)
    now = _now()
    if row is None:
        base = definition_for(conn, ctx.company_id, item_type)
        did = conn.execute(
            "INSERT INTO symbol_definitions (company_id, library_id, code, description, item_type, trade, ocr_aliases_json,"
            " status, approved_by, approved_at, version, confidence, created_at)"
            " VALUES (?,?,?,?,?,?,?,'approved',?,?,1,'0.9',?)",
            (ctx.company_id, lib_id, code, description or base.get("description"), item_type,
             trade or base.get("trade"), json.dumps([code] if code else []), ctx.actor, now, now)).lastrowid
    else:
        did = row["id"]
    have = conn.execute("SELECT COUNT(*) FROM symbol_examples WHERE definition_id = ?", (did,)).fetchone()[0]
    seen = {r["detection_id"] for r in conn.execute("SELECT detection_id FROM symbol_examples WHERE definition_id = ?",
                                                     (did,))}
    for ex in examples:
        if have >= MAX_EXAMPLES_PER_DEFINITION:
            break
        if not ex.get("template") and not ex.get("image_path"):
            continue
        if ex.get("detection_id") and ex["detection_id"] in seen:
            continue
        conn.execute("INSERT INTO symbol_examples (company_id, definition_id, image_path, source_sheet_id, source,"
                     " created_at, template_json, detection_id, added_by) VALUES (?,?,?,?, 'confirmed', ?,?,?,?)",
                     (ctx.company_id, did, ex.get("image_path"), ex.get("sheet_id"), now,
                      json.dumps(ex["template"]) if ex.get("template") else None, ex.get("detection_id"), ctx.actor))
        have += 1
    conn.execute("UPDATE symbol_libraries SET updated_at = ? WHERE id = ?", (now, lib_id))
    return did


def engine_templates(conn, company_id: str) -> list[dict]:
    """The company library for the plan engine: one entry per learned example with line work (newest first)."""
    out = []
    for r in conn.execute(
            "SELECT f.id, f.item_type, f.trade, f.description, f.code, x.template_json FROM symbol_examples x"
            " JOIN symbol_definitions f ON f.id = x.definition_id JOIN symbol_libraries l ON l.id = f.library_id"
            " WHERE f.company_id = ? AND l.level IN ('company', 'firm') AND f.status = 'approved'"
            " AND x.template_json IS NOT NULL ORDER BY x.id DESC LIMIT 200", (company_id,)):
        try:
            tpl = json.loads(r["template_json"])
        except ValueError:
            continue
        out.append({"key": f"lib:{r['id']}", "item_type": r["item_type"], "trade": r["trade"],
                    "description": r["description"], "code": r["code"], "template": tpl})
    # one template per definition and shape is plenty; keep the first (newest) few per definition
    per, kept = {}, []
    for e in out:
        per[e["key"]] = per.get(e["key"], 0) + 1
        if per[e["key"]] <= 3:
            kept.append(e)
    return kept


# ---------------------------------------------------------------- symbol_library_list / symbol_define

def list_library(conn, ctx: RequestContext, level: str | None = None, trade: str | None = None) -> dict:
    """symbol_library_list: the standard, company and firm libraries, definitions grouped by trade, with how many
    examples each has and how many times it was found on this company's plans."""
    if level is not None and level not in ("standard", "company", "firm"):
        raise InvalidInput("level must be standard, company or firm", field="level")
    from estimator.estimating import service
    with service.transaction(conn):
        ensure_standard(conn, ctx.company_id)
        ensure_company(conn, ctx.company_id)
    libs = []
    for lib in conn.execute("SELECT * FROM symbol_libraries WHERE company_id = ? ORDER BY CASE level"
                            " WHEN 'company' THEN 0 WHEN 'firm' THEN 1 ELSE 2 END, id", (ctx.company_id,)):
        if level and lib["level"] != level:
            continue
        sql = ("SELECT f.*, (SELECT COUNT(*) FROM symbol_examples x WHERE x.definition_id = f.id) AS examples,"
               " (SELECT COUNT(*) FROM symbol_detections d WHERE d.definition_id = f.id AND d.status != 'rejected')"
               " AS found FROM symbol_definitions f WHERE f.library_id = ?")
        args: list = [lib["id"]]
        if trade:
            sql += " AND f.trade = ?"
            args.append(trade)
        defs = [_def_out(dict(r)) for r in conn.execute(sql + " ORDER BY f.trade, f.item_type", args)]
        by_trade: dict[str, list] = {}
        for d in defs:
            by_trade.setdefault(d["trade"] or "other", []).append(d)
        libs.append({"id": lib["id"], "level": lib["level"], "firm_name": lib["firm_name"], "version": lib["version"],
                     "updated_at": lib["updated_at"], "count": len(defs), "by_trade": by_trade})
    return {"ok": True, "libraries": libs, "can_define": ctx.role in DEFINE_ROLES and not getattr(ctx, "agent", None),
            "trades": list(TRADES)}


def _def_out(r: dict) -> dict:
    return {"id": r["id"], "item_type": r["item_type"], "description": r["description"], "trade": r["trade"],
            "code": r["code"], "assembly_id": r["assembly_id"], "status": r["status"], "approved_by": r["approved_by"],
            "approved_at": r["approved_at"], "version": r["version"], "examples": r.get("examples", 0),
            "found": r.get("found", 0), "aliases": json.loads(r["ocr_aliases_json"] or "[]")}


def define(conn, ctx: RequestContext, item_type: str, description: str | None = None, trade: str | None = None,
           code: str | None = None, assembly_id: str | None = None, definition_id: int | None = None,
           from_detection_ids: list[int] | None = None, confirm: bool = False) -> dict:
    """symbol_define: save a symbol to the company library (new, or a new version of one), optionally with the
    detections that show it as examples. Asks first."""
    from estimator.estimating import service
    from estimator.symbols import review
    _person(ctx, "define symbols")
    it = check_item_type(item_type)
    trade = (trade or "").strip().lower() or None
    if trade is not None and trade not in TRADES:
        raise InvalidInput(f"trade must be one of {', '.join(TRADES)}", field="trade")
    description = (description or "").strip()[:200] or None
    code = (code or "").strip()[:20] or None
    assembly_id = (assembly_id or "").strip()[:80] or None
    row = None
    if definition_id:
        row = conn.execute("SELECT f.*, l.level FROM symbol_definitions f JOIN symbol_libraries l ON l.id = f.library_id"
                           " WHERE f.id = ? AND f.company_id = ?", (int(definition_id), ctx.company_id)).fetchone()
        if row is None:
            raise NotFound(f"symbol definition {definition_id} not found", definition_id=definition_id)
        if row["level"] == "standard":
            raise InvalidInput("the standard library can't be edited; save a company definition instead (leave out "
                               "definition_id)", definition_id=definition_id)
    dets = review.load_detections(conn, ctx, from_detection_ids or []) if from_detection_ids else []
    what = (f"Save version {row['version'] + 1} of '{row['item_type']}'" if row else
            f"Save '{it}' to the company symbol library") + (f" with {len(dets)} example(s)" if dets else "")
    if not confirm:
        raise ConfirmationRequired(what + "? Approved detections and measurements don't change. Call again with "
                                   "confirm=true.", item_type=it, examples=len(dets))
    with service.transaction(conn):
        lib_id = ensure_company(conn, ctx.company_id)
        now = _now()
        if row is not None:
            conn.execute("UPDATE symbol_definitions SET item_type = ?, description = COALESCE(?, description),"
                         " trade = COALESCE(?, trade), code = ?, assembly_id = ?, ocr_aliases_json = ?, version = version + 1,"
                         " status = 'approved', approved_by = ?, approved_at = ? WHERE id = ?",
                         (it, description, trade, code, assembly_id, json.dumps([code] if code else []), ctx.actor, now,
                          row["id"]))
            did = row["id"]
        else:
            existing = _company_def(conn, ctx.company_id, it)
            if existing is not None:
                raise InvalidInput(f"the company library already has '{it}' (definition {existing['id']}); give "
                                   "definition_id to change it", definition_id=existing["id"])
            base = definition_for(conn, ctx.company_id, it)
            did = conn.execute(
                "INSERT INTO symbol_definitions (company_id, library_id, code, description, item_type, trade, assembly_id,"
                " ocr_aliases_json, status, approved_by, approved_at, version, confidence, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,'approved',?,?,1,'0.9',?)",
                (ctx.company_id, lib_id, code, description or base.get("description"), it, trade or base.get("trade"),
                 assembly_id, json.dumps([code] if code else []), ctx.actor, now, now)).lastrowid
        if dets:
            learn(conn, ctx, it, [review.example_of(conn, d) for d in dets[:MAX_EXAMPLES_PER_DEFINITION]])
        conn.execute("UPDATE symbol_libraries SET version = version + 1, updated_at = ? WHERE id = ?", (now, lib_id))
    r = conn.execute("SELECT f.*, (SELECT COUNT(*) FROM symbol_examples x WHERE x.definition_id = f.id) AS examples,"
                     " 0 AS found FROM symbol_definitions f WHERE f.id = ?", (did,)).fetchone()
    return {"ok": True, "definition": _def_out(dict(r))}


def export_library(conn, ctx: RequestContext) -> dict:
    """The company library as plain data, to share with another AI-Prowler install in the same company."""
    defs = []
    for r in conn.execute("SELECT f.* FROM symbol_definitions f JOIN symbol_libraries l ON l.id = f.library_id"
                          " WHERE f.company_id = ? AND l.level = 'company' ORDER BY f.item_type", (ctx.company_id,)):
        ex = [json.loads(x["template_json"]) for x in conn.execute(
            "SELECT template_json FROM symbol_examples WHERE definition_id = ? AND template_json IS NOT NULL", (r["id"],))]
        defs.append({"item_type": r["item_type"], "description": r["description"], "trade": r["trade"], "code": r["code"],
                     "assembly_id": r["assembly_id"], "version": r["version"], "examples": ex})
    return {"ok": True, "format": "ai-prowler-symbol-library", "version": 1, "definitions": defs}


def import_library(conn, ctx: RequestContext, data: dict, confirm: bool = False) -> dict:
    from estimator.estimating import service
    from estimator.plan_engine import symbols as engine_symbols
    _person(ctx, "import symbol libraries")
    if not isinstance(data, dict) or data.get("format") != "ai-prowler-symbol-library":
        raise InvalidInput("that isn't an AI-Prowler symbol library export")
    defs = data.get("definitions")
    if not isinstance(defs, list) or len(defs) > 1000:
        raise InvalidInput("the export has no definitions list (or more than 1,000)")
    clean = []
    for d in defs:
        if not isinstance(d, dict):
            continue
        it = check_item_type(str(d.get("item_type") or ""))
        ex = [e for e in (d.get("examples") or [])[:MAX_EXAMPLES_PER_DEFINITION]
              if engine_symbols.template_from_json(e) is not None]
        clean.append((it, d, ex))
    if not confirm:
        raise ConfirmationRequired(f"Add {len(clean)} symbol definition(s) to the company library? Ones you already have "
                                   "get the new examples. Call again with confirm=true.", definitions=len(clean))
    with service.transaction(conn):
        for it, d, ex in clean:
            learn(conn, ctx, it, [{"template": e} for e in ex],
                  description=(str(d.get("description") or "")[:200] or None), trade=d.get("trade") if d.get("trade") in TRADES else None,
                  code=(str(d.get("code") or "")[:20] or None))
    return {"ok": True, "imported": len(clean)}
