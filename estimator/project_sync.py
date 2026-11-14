"""Send one project (an estimate with its plans, takeoff and quotes) from this PC to the company server, so the crew can
see the plans and the quote in the server's Estimator and Jobs app, and everyone can keep working on it there.

Two ways to deliver the same file (one .zip "project bundle"):

- Over the internet: the PC signs in to the server's Estimator (its Remote Access address, with the person's own
  server user name and password - the password is never saved) and uploads the bundle to
  POST /estimator-api/sync/receive. The server takes it in straight away.
- Through the office network: the PC copies the bundle into the server's shared exchange folder (a mapped drive,
  e.g. Z:\\AI-Prowler\\Estimator\\exchange) under projects\\inbox\\. The server's Director watcher takes it in within a
  minute or so (or at once with take_in_inbox). Faster for big plan sets: nothing goes through the internet.

On the server (receive_bundle):
- The first send makes a new estimate. Sending the same project again replaces the server copy in place (same
  estimate number, so the Jobs app, notices and links keep working): its trades, lines, takeoff, plans and quotes are
  swapped for the new ones.
- Safety: if someone changed the server copy since the last send (an edit, a measurement, a new quote), it is NOT
  overwritten; the new send is kept as a second estimate next to it, unless the sender chose replace_anyway.
- Customer and job links are left empty on the server (this PC's customer numbers mean nothing there); the bid keeps
  the customer as the customer saw it. Every row gets a new number; JSON id lists are renumbered too.

Left out: the audit trail, Director jobs, agent runs, AI logs and auto-runs, which belong to the PC that made them.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.errors import EstimatorError, InvalidInput, PermissionDenied

FORMAT = "ai-prowler-estimator-project"
VERSION = 1
MAX_BUNDLE_BYTES = 500 * 1024 * 1024
MAX_DATA_BYTES = 150 * 1024 * 1024
INTERNET_MAX_BYTES = 95 * 1024 * 1024      # Cloudflare's tunnel refuses uploads over 100 MB
SEND_ROLES = ("owner", "estimator", "office")
RECEIVE_ROLES = ("owner", "estimator", "office")
SETTINGS_FILE = "server_sync.json"
INBOX_PARTS = ("projects", "inbox")

# (table, {column: table it points to}); parents first. "id" is renumbered on the server.
TABLES = (
    ("trade_sections", {"estimate_id": "estimates"}),
    ("plan_sets", {"estimate_id": "estimates", "supersedes_plan_set_id": "plan_sets"}),
    ("sheets", {"plan_set_id": "plan_sets"}),
    ("viewports", {"sheet_id": "sheets"}),
    ("drawing_objects", {"sheet_id": "sheets", "viewport_id": "viewports"}),
    ("schedules", {"sheet_id": "sheets"}),
    ("schedule_rows", {"schedule_id": "schedules"}),
    ("legends", {"sheet_id": "sheets"}),
    ("measurements", {"estimate_id": "estimates", "trade_section_id": "trade_sections", "sheet_id": "sheets",
                      "viewport_id": "viewports"}),
    ("assembly_uses", {"estimate_id": "estimates", "trade_section_id": "trade_sections"}),
    ("line_items", {"trade_section_id": "trade_sections", "assembly_use_id": "assembly_uses"}),
    ("estimate_scenarios", {"estimate_id": "estimates"}),
    ("bids", {"estimate_id": "estimates"}),
)
# JSON columns holding lists of ids: (table, column, table the ids point to)
ID_LISTS = (("schedule_rows", "linked_object_ids", "drawing_objects"),
            ("measurements", "source_object_ids", "drawing_objects"),
            ("assembly_uses", "measurement_ids", "measurements"))
# Estimate columns copied to the server copy. customer_id, job_id, assigned_to, parent_estimate_id stay empty there.
EST_COLUMNS = ("address", "title", "status", "rev", "revision", "change_summary", "due_date", "totals_json",
               "created_by", "created_at", "updated_by", "updated_at")
# Columns cleared on the server copy because they only mean something on the sending PC.
CLEAR = {"bids": ("customer_id", "quote_id", "job_id"),
         "plan_sets": ("queue_state", "queue_pc", "queued_at", "server_job")}
MEMBER_RE = re.compile(r"files/(plan|sheet|dict|bid)/(\d{1,9})/([A-Za-z0-9 _.()-]{1,120})")
NAME_RE = re.compile(r"[^A-Za-z0-9 _.()-]+")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe(name: str, fallback: str = "file") -> str:
    p = Path(str(name or "").replace("\\", "/"))
    stem = NAME_RE.sub("_", p.stem).strip(" ._")[:80] or fallback
    return stem + NAME_RE.sub("", p.suffix.lower())[:10]


def _columns(conn, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _marks(ids) -> str:
    return ",".join("?" for _ in ids)


def source_key(company_id: str, estimate_id: int) -> str:
    """Names this PC's copy of a project, so a second send finds the server copy the first one made."""
    return f"{config.pc_id()}|{company_id}|{int(estimate_id)}"


# ================================================================ on the sending PC: the bundle

def _rows(conn, sql: str, args=()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, args)]


def gather(conn, ctx: RequestContext, estimate_id: int) -> tuple[dict, dict, list[tuple[Path, str]]]:
    """(estimate row, tables, files to pack as (path, zip member)) for one project of this company."""
    from estimator.estimating import service
    service._load_row(conn, ctx, int(estimate_id))
    est = dict(conn.execute("SELECT * FROM estimates WHERE id = ?", (int(estimate_id),)).fetchone())
    eid, company = est["id"], ctx.company_id
    t: dict[str, list[dict]] = {}
    t["trade_sections"] = _rows(conn, "SELECT * FROM trade_sections WHERE estimate_id = ? ORDER BY id", (eid,))
    t["plan_sets"] = _rows(conn, "SELECT * FROM plan_sets WHERE estimate_id = ? AND company_id = ? ORDER BY id",
                           (eid, company))
    ps_ids = [p["id"] for p in t["plan_sets"]]
    t["sheets"] = (_rows(conn, f"SELECT * FROM sheets WHERE plan_set_id IN ({_marks(ps_ids)}) ORDER BY id", ps_ids)
                   if ps_ids else [])
    sh = [s["id"] for s in t["sheets"]]
    for table in ("viewports", "drawing_objects", "schedules", "legends"):
        t[table] = (_rows(conn, f"SELECT * FROM {table} WHERE sheet_id IN ({_marks(sh)}) ORDER BY id", sh)
                    if sh else [])
    sc = [s["id"] for s in t["schedules"]]
    t["schedule_rows"] = (_rows(conn, f"SELECT * FROM schedule_rows WHERE schedule_id IN ({_marks(sc)}) ORDER BY id",
                                sc) if sc else [])
    t["measurements"] = _rows(conn, "SELECT * FROM measurements WHERE estimate_id = ? AND company_id = ? ORDER BY id",
                              (eid, company))
    t["assembly_uses"] = _rows(conn, "SELECT * FROM assembly_uses WHERE estimate_id = ? AND company_id = ? ORDER BY id",
                               (eid, company))
    ts = [s["id"] for s in t["trade_sections"]]
    t["line_items"] = (_rows(conn, f"SELECT * FROM line_items WHERE trade_section_id IN ({_marks(ts)}) ORDER BY id",
                             ts) if ts else [])
    t["estimate_scenarios"] = _rows(conn, "SELECT * FROM estimate_scenarios WHERE estimate_id = ? ORDER BY id", (eid,))
    t["bids"] = _rows(conn, "SELECT * FROM bids WHERE estimate_id = ? AND company_id = ? ORDER BY id", (eid, company))
    t["sheet_trade_active"] = (_rows(conn, f"SELECT * FROM sheet_trade_active WHERE company_id = ? AND sheet_id IN "
                                           f"({_marks(sh)})", [company, *sh]) if sh else [])
    files: list[tuple[Path, str]] = []
    for p in t["plan_sets"]:
        f = Path(p["file_path"]) if p.get("file_path") else None
        if f and f.is_file():
            files.append((f, f"files/plan/{p['id']}/{_safe(p['original_name'] or f.name, 'plans')}"))
    dicts = set()
    for s in t["sheets"]:
        f = Path(s["image_path"]) if s.get("image_path") else None
        if f and f.is_file():
            files.append((f, f"files/sheet/{s['id']}/{_safe(f.name, 'sheet')}"))
            d = f.parent / "symbol_dictionary.json"
            if d.is_file() and s["plan_set_id"] not in dicts:
                dicts.add(s["plan_set_id"])
                files.append((d, f"files/dict/{s['plan_set_id']}/symbol_dictionary.json"))
    for b in t["bids"]:
        for col in ("html_path", "pdf_path"):
            f = Path(b[col]) if b.get(col) else None
            if f and f.is_file():
                files.append((f, f"files/bid/{b['id']}/{_safe(f.name, 'quote')}"))
    return est, t, files


def build_bundle(conn, ctx: RequestContext, estimate_id: int, out_dir: Path | None = None) -> dict:
    """Write the project bundle (.zip). Returns its path, size and what's in it."""
    from estimator.database.migrations import current_version
    if ctx.role not in SEND_ROLES:
        raise PermissionDenied("only the owner, an estimator or the office can send a project to the server",
                               role=ctx.role)
    est, tables, files = gather(conn, ctx, estimate_id)
    if est.get("is_practice"):
        raise InvalidInput("that's a practice estimate; practice estimates stay on this PC", estimate_id=est["id"])
    counts = {k: len(v) for k, v in tables.items()}
    manifest = {"format": FORMAT, "version": VERSION, "schema_version": current_version(conn),
                "source_key": source_key(ctx.company_id, est["id"]), "source_pc": config.pc_id(),
                "source_company": ctx.company_id, "source_estimate_id": est["id"], "title": est["title"],
                "address": est.get("address"), "sent_at": _now(), "sent_by": ctx.actor, "counts": counts,
                "files": len(files)}
    folder = Path(out_dir) if out_dir else config.data_dir() / "exports" / "to_server"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = folder / f"project_{re.sub(r'[^A-Za-z0-9_-]', '_', config.pc_id())}_{est['id']:04d}_{stamp}.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        z.writestr("data.json", json.dumps({"estimate": est, "tables": tables}, default=str))
        for src, member in files:
            z.write(src, member, compress_type=zipfile.ZIP_STORED if src.suffix.lower() in (".png", ".jpg", ".pdf")
                    else zipfile.ZIP_DEFLATED)
    return {"ok": True, "path": str(path), "file": path.name, "bytes": path.stat().st_size, "counts": counts,
            "files": len(files), "estimate_id": est["id"], "title": est["title"], "source_key": manifest["source_key"]}


# ================================================================ on the server: taking a bundle in

def _read(path: Path) -> tuple[dict, dict, zipfile.ZipFile]:
    if not path.is_file():
        raise InvalidInput("the project file isn't there", file=str(path))
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise InvalidInput("the project file is over 500 MB")
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise InvalidInput("that isn't a readable project file (.zip)") from None
    try:
        names = set(z.namelist())
        if not {"manifest.json", "data.json"} <= names:
            raise InvalidInput("that .zip isn't a project sent by AI-Prowler (no manifest.json / data.json)")
        if z.getinfo("data.json").file_size > MAX_DATA_BYTES:
            raise InvalidInput("the project's data is too big")
        try:
            manifest = json.loads(z.read("manifest.json"))
            data = json.loads(z.read("data.json"))
        except ValueError:
            raise InvalidInput("the project file is damaged") from None
        if manifest.get("format") != FORMAT or not isinstance(data.get("tables"), dict) \
                or not isinstance(data.get("estimate"), dict):
            raise InvalidInput("that .zip isn't a project sent by AI-Prowler")
        if int(manifest.get("version") or 0) > VERSION:
            raise InvalidInput("the project was sent by a newer AI-Prowler; update the server first")
        unknown = set(data["tables"]) - {t for t, _ in TABLES} - {"sheet_trade_active"}
        if unknown:
            raise InvalidInput(f"the project has tables this server doesn't know: {', '.join(sorted(unknown))}")
    except BaseException:
        z.close()
        raise
    return manifest, data, z


def _previous(conn, ctx: RequestContext, key: str) -> dict | None:
    row = conn.execute("SELECT * FROM project_sync WHERE company_id = ? AND source_key = ?",
                       (ctx.company_id, key)).fetchone()
    if row is None:
        return None
    alive = conn.execute("SELECT id FROM estimates WHERE id = ? AND company_id = ?",
                         (row["estimate_id"], ctx.company_id)).fetchone()
    return dict(row) if alive else None


def changed_on_server(conn, estimate_id: int, since: str) -> list[str]:
    """What people did to the server copy after it was last received (empty = untouched)."""
    out = []
    n = conn.execute("SELECT COUNT(*) FROM estimate_events WHERE estimate_id = ? AND at > ? AND action NOT IN"
                     " ('project_received', 'project_replaced')", (estimate_id, since)).fetchone()[0]
    if n:
        out.append(f"{n} change(s) to the estimate")
    m = conn.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND updated_at > ?",
                     (estimate_id, since)).fetchone()[0]
    if m:
        out.append(f"{m} measurement(s) added or edited")
    b = conn.execute("SELECT COUNT(*) FROM bids WHERE estimate_id = ? AND COALESCE(updated_at, created_at) > ?",
                     (estimate_id, since)).fetchone()[0]
    if b:
        out.append(f"{b} quote(s) made or changed")
    return out


def _clear_old(conn, ctx: RequestContext, estimate_id: int) -> tuple[list, list]:
    """Remove the server copy's trades, lines, takeoff, plans and quotes (inside the caller's transaction).
    Returns (files, folders) to delete after the commit."""
    from estimator.takeoff import plan_delete
    from estimator.drawing_model import store
    root = config.data_dir()
    files, folders = [], []
    for (ps_id,) in conn.execute("SELECT id FROM plan_sets WHERE estimate_id = ? AND company_id = ? ORDER BY id DESC",
                                 (estimate_id, ctx.company_id)).fetchall():
        ps = store.load_plan_set(conn, ctx, ps_id)
        scope = plan_delete._plan_set_scope(conn, ctx, ps)
        f, d = plan_delete._files_for_plan_set(scope, root)
        files += f
        folders += d
        plan_delete._delete_rows(conn, scope, plan_set=True)
    for b in conn.execute("SELECT html_path, pdf_path FROM bids WHERE estimate_id = ?", (estimate_id,)).fetchall():
        files += [Path(p) for p in (b["html_path"], b["pdf_path"]) if p]
    conn.execute("DELETE FROM reviews WHERE estimate_id = ?", (estimate_id,))
    conn.execute("DELETE FROM measurements WHERE estimate_id = ?", (estimate_id,))
    conn.execute("DELETE FROM estimate_scenarios WHERE estimate_id = ?", (estimate_id,))
    conn.execute("DELETE FROM bids WHERE estimate_id = ?", (estimate_id,))
    conn.execute("DELETE FROM trade_sections WHERE estimate_id = ?", (estimate_id,))   # lines + assemblies cascade
    return files, folders


def _remap_list(value, mapping: dict) -> str:
    try:
        items = json.loads(value or "[]")
    except ValueError:
        items = []
    if not isinstance(items, list):
        items = []
    return json.dumps([mapping[i] for i in items if i in mapping])


def _remap_sources(value, mapping: dict) -> str:
    try:
        sources = json.loads(value or "{}")
    except ValueError:
        return value or "{}"
    if isinstance(sources, dict):
        for entry in sources.values():
            if isinstance(entry, dict) and isinstance(entry.get("measurement_ids"), list):
                entry["measurement_ids"] = [mapping[i] for i in entry["measurement_ids"] if i in mapping]
    return json.dumps(sources)


def receive_bundle(conn, ctx: RequestContext, zip_path, *, replace_anyway: bool = False,
                   received_by: str | None = None) -> dict:
    """Take a project bundle into this company's Estimator (see the module notes for the rules)."""
    from estimator.database.migrations import current_version
    from estimator.drawing_model import uploads
    from estimator.estimating import service
    from estimator.takeoff import plan_delete
    if ctx.role not in RECEIVE_ROLES:
        raise PermissionDenied("only the owner, an estimator or the office can receive projects", role=ctx.role)
    manifest, data, z = _read(Path(str(zip_path)))
    try:
        if int(manifest.get("schema_version") or 0) > current_version(conn):
            raise InvalidInput(f"the project comes from a newer Estimator (database v{manifest['schema_version']}); "
                               "update AI-Prowler on the server first")
        key = str(manifest.get("source_key") or "")[:300]
        if not key:
            raise InvalidInput("the project file doesn't say which PC sent it")
        tables, est = data["tables"], data["estimate"]
        prev = _previous(conn, ctx, key)
        changed = changed_on_server(conn, prev["estimate_id"], prev["received_at"]) if prev else []
        mode = "new" if prev is None else ("replaced" if (replace_anyway or not changed) else "kept_both")
        target = ctx.company_id
        new_ids: dict[str, dict] = {t: {} for t, _ in TABLES}
        old_files: tuple[list, list] = ([], [])
        written: list[Path] = []
        names = set(z.namelist())
        now = _now()
        pc = str(manifest.get("source_pc") or "a PC")[:80]
        try:
            with service.transaction(conn):
                vals = {c: est.get(c) for c in EST_COLUMNS}
                vals["updated_at"] = now
                if mode == "replaced":
                    eid = prev["estimate_id"]
                    old_files = _clear_old(conn, ctx, eid)
                    conn.execute(f"UPDATE estimates SET {', '.join(c + ' = ?' for c in vals)} WHERE id = ?",
                                 [*vals.values(), eid])
                else:
                    if mode == "kept_both":
                        vals["title"] = f"{est.get('title') or 'Project'} (sent again from {pc})"
                    vals.update(company_id=target, is_practice=0)
                    eid = conn.execute(f"INSERT INTO estimates ({', '.join(vals)}) VALUES ({_marks(vals)})",
                                       list(vals.values())).lastrowid
                new_ids["estimates"] = {est["id"]: eid}
                self_refs = []
                for t, refs in TABLES:
                    cols = [c for c in _columns(conn, t) if c != "id"]
                    for row in tables.get(t) or []:
                        v = {c: row.get(c) for c in cols if c in row}
                        if "company_id" in cols:
                            v["company_id"] = target
                        for c in CLEAR.get(t, ()):
                            if c in v:
                                v[c] = None
                        for col, parent in refs.items():
                            old = row.get(col)
                            if old is None:
                                continue
                            if parent == t:
                                self_refs.append((t, row["id"], col, old))
                                v[col] = None
                            else:
                                v[col] = new_ids[parent].get(old)
                        try:
                            cur = conn.execute(f"INSERT INTO {t} ({', '.join(v)}) VALUES ({_marks(v)})", list(v.values()))
                        except Exception as exc:  # noqa: BLE001 - an inconsistent file must not half-import
                            raise InvalidInput(f"the project file is inconsistent ({t} row {row.get('id')}): {exc}") \
                                from None
                        new_ids[t][row["id"]] = cur.lastrowid
                for t, old_id, col, old in self_refs:
                    if old in new_ids[t]:
                        conn.execute(f"UPDATE {t} SET {col} = ? WHERE id = ?", (new_ids[t][old], new_ids[t][old_id]))
                for t, col, points in ID_LISTS:
                    for row in tables.get(t) or []:
                        conn.execute(f"UPDATE {t} SET {col} = ? WHERE id = ?",
                                     (_remap_list(row.get(col), new_ids[points]), new_ids[t][row["id"]]))
                for row in tables.get("assembly_uses") or []:
                    conn.execute("UPDATE assembly_uses SET sources_json = ? WHERE id = ?",
                                 (_remap_sources(row.get("sources_json"), new_ids["measurements"]),
                                  new_ids["assembly_uses"][row["id"]]))
                for row in tables.get("sheet_trade_active") or []:
                    sid = new_ids["sheets"].get(row.get("sheet_id"))
                    if sid is not None:
                        conn.execute("INSERT OR REPLACE INTO sheet_trade_active (company_id, sheet_id, module_id, active,"
                                     " updated_by, updated_at) VALUES (?,?,?,?,?,?)",
                                     (target, sid, row["module_id"], int(row["active"]), row.get("updated_by"),
                                      row.get("updated_at") or now))
                # ---- files: plan files, sheet images, symbol dictionaries, quotes
                plans = uploads.plans_folder(eid)
                members = [m for m in names if m.startswith("files/")]
                for member in members:
                    mm = MEMBER_RE.fullmatch(member)
                    if not mm:
                        continue
                    kind, old_id, name = mm.group(1), int(mm.group(2)), mm.group(3)
                    if kind == "plan" and old_id in new_ids["plan_sets"]:
                        nid = new_ids["plan_sets"][old_id]
                        dest = plans / f"{nid}_{_safe(name, 'plans')}"
                        col, table, rid = "file_path", "plan_sets", nid
                    elif kind == "sheet" and old_id in new_ids["sheets"]:
                        nid = new_ids["sheets"][old_id]
                        ps_old = next(s["plan_set_id"] for s in tables["sheets"] if s["id"] == old_id)
                        dest = plans / f"{new_ids['plan_sets'][ps_old]}_sheets" / _safe(name, "sheet")
                        col, table, rid = "image_path", "sheets", nid
                    elif kind == "dict" and old_id in new_ids["plan_sets"]:
                        dest = plans / f"{new_ids['plan_sets'][old_id]}_sheets" / "symbol_dictionary.json"
                        col = table = rid = None
                    elif kind == "bid" and old_id in new_ids["bids"]:
                        nid = new_ids["bids"][old_id]
                        dest = config.data_dir() / "projects" / f"estimate_{eid:04d}" / "bids" / _safe(name, "quote")
                        col = "pdf_path" if dest.suffix == ".pdf" else "html_path"
                        table, rid = "bids", nid
                    else:
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(member) as src, dest.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    written.append(dest)
                    if table:
                        conn.execute(f"UPDATE {table} SET {col} = ? WHERE id = ?", (str(dest), rid))
                # rows whose file didn't come along must not point at the sending PC's disk
                for t, col in (("sheets", "image_path"), ("bids", "html_path"), ("bids", "pdf_path")):
                    ids = list(new_ids[t].values())
                    if ids:
                        for r in conn.execute(f"SELECT id, {col} FROM {t} WHERE id IN ({_marks(ids)})", ids).fetchall():
                            if r[col] and Path(r[col]) not in written:
                                conn.execute(f"UPDATE {t} SET {col} = NULL WHERE id = ?", (r["id"],))
                for ps_new in new_ids["plan_sets"].values():
                    r = conn.execute("SELECT file_path FROM plan_sets WHERE id = ?", (ps_new,)).fetchone()
                    if r["file_path"] and Path(r["file_path"]) not in written:
                        conn.execute("UPDATE plan_sets SET file_path = '' WHERE id = ?", (ps_new,))
                conn.execute("INSERT OR REPLACE INTO project_sync (company_id, source_key, estimate_id, source_pc,"
                             " source_estimate_id, title, sent_by, sent_at, received_by, received_at)"
                             " VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (target, key, eid, pc, manifest.get("source_estimate_id"), est.get("title"),
                              manifest.get("sent_by"), manifest.get("sent_at"), received_by or ctx.actor, now)
                             if mode != "kept_both" else
                             (target, key, prev["estimate_id"], prev["source_pc"], prev["source_estimate_id"],
                              prev["title"], prev["sent_by"], prev["sent_at"], prev["received_by"], prev["received_at"]))
                counts = {t: len(tables.get(t) or []) for t, _ in TABLES}
                service._log(conn, ctx, eid, "project_replaced" if mode == "replaced" else "project_received",
                             {"from_pc": pc, "sent_by": manifest.get("sent_by"), "sent_at": manifest.get("sent_at"),
                              "counts": counts, "files": len(written), "mode": mode,
                              "kept_server_changes": changed if mode == "kept_both" else []})
        except BaseException:
            for f in written:
                try:
                    f.unlink()
                except OSError:
                    pass
            raise
    finally:
        z.close()
    removed = None
    if mode == "replaced":
        # SQLite can give the new plan set the old one's number, so its new files may sit where the old ones were:
        # never remove a file just written, or a folder holding one.
        keep = {f.resolve() for f in written}
        files = [f for f in old_files[0] if f.resolve() not in keep]
        folders = [d for d in old_files[1] if not any(d.resolve() in k.parents for k in keep)]
        removed = plan_delete._remove_files(files, folders, config.data_dir().resolve())
    say = {"new": f"Received “{est.get('title')}” from {pc} as estimate {eid}.",
           "replaced": f"Updated estimate {eid} (“{est.get('title')}”) with the new send from {pc}.",
           "kept_both": (f"The server copy (estimate {prev['estimate_id'] if prev else '?'}) was changed on the server "
                         f"since the last send ({'; '.join(changed)}), so it was kept and this send was saved as "
                         f"estimate {eid}. Send again with 'replace the server copy' to overwrite it instead.")}[mode]
    return {"ok": True, "mode": mode, "estimate_id": eid, "title": est.get("title"), "from_pc": pc,
            "counts": counts, "files": len(written), "server_changes": changed,
            "previous_estimate_id": prev["estimate_id"] if prev else None, "removed_old_files": removed, "say": say}


def received(conn, ctx: RequestContext) -> list[dict]:
    """Projects this server has received from PCs, newest first."""
    return [dict(r) for r in conn.execute(
        "SELECT s.*, e.title AS server_title, e.status FROM project_sync s JOIN estimates e ON e.id = s.estimate_id"
        " WHERE s.company_id = ? ORDER BY s.received_at DESC", (ctx.company_id,))]


# ================================================================ office network: the shared inbox

def inbox_dir(share: str | Path | None = None) -> Path:
    """projects\\inbox under the server's exchange folder (share = that folder as this PC sees it, e.g. Z:\\...)."""
    root = Path(share) if share else config.exchange_dir()
    if share and (root / "exchange").is_dir() and not (root / "jobs").is_dir():
        root = root / "exchange"                # they picked the server's Estimator folder, not exchange itself
    return root.joinpath(*INBOX_PARTS)


def send_to_share(conn, ctx: RequestContext, estimate_id: int, share: str, *, replace_anyway: bool = False) -> dict:
    """Build the bundle and copy it into the server's shared inbox (mapped network drive)."""
    share_path = Path(str(share or "").strip().strip('"'))
    if not str(share_path) or not share_path.is_dir():
        raise InvalidInput(f"can't reach the server folder {share_path or '(not set)'}. Check the mapped drive "
                           "(e.g. Z:) is connected to the office network", folder=str(share_path))
    built = build_bundle(conn, ctx, estimate_id)
    inbox = inbox_dir(share_path)
    try:
        inbox.mkdir(parents=True, exist_ok=True)
        dest = inbox / built["file"]
        tmp = inbox / (built["file"] + ".part")
        shutil.copyfile(built["path"], tmp)
        if replace_anyway:
            (inbox / (built["file"] + ".replace")).write_text("replace the server copy", encoding="utf-8")
        os.replace(tmp, dest)                   # the server only picks up whole .zip files
    except OSError as exc:
        raise InvalidInput(f"couldn't copy the project to {inbox}: {exc}", folder=str(inbox)) from None
    finally:
        Path(built["path"]).unlink(missing_ok=True)
    return {**built, "ok": True, "path": str(dest), "via": "network",
            "say": f"Copied “{built['title']}” to the server's inbox ({inbox}). The server takes it in within a "
                   "minute or two; the crew then sees it in the Estimator and the Jobs app."}


def take_in_inbox(conn, ctx: RequestContext) -> list[dict]:
    """On the server: take in every project PCs dropped into the shared inbox. Bad ones go to projects\\failed."""
    inbox = inbox_dir()
    if not inbox.is_dir():
        return []
    done, failed = inbox.parent / "done", inbox.parent / "failed"
    out = []
    for f in sorted(inbox.glob("*.zip")):
        flag = f.with_name(f.name + ".replace")
        try:
            with zipfile.ZipFile(f) as z:
                manifest = json.loads(z.read("manifest.json"))
            who = str(manifest.get("sent_by") or "a PC")[:80]
            pc = str(manifest.get("source_pc") or "a PC")[:80]
        except (OSError, ValueError, KeyError, zipfile.BadZipFile):
            who, pc = "a PC", "a PC"
        sync_ctx = RequestContext(company_id=ctx.company_id, user_id=who, role="estimator", mode=ctx.mode,
                                  agent=f"sync:{pc}")
        try:
            res = receive_bundle(conn, sync_ctx, f, replace_anyway=flag.is_file(), received_by=f"network share ({who})")
            done.mkdir(parents=True, exist_ok=True)
            shutil.move(str(f), str(done / f.name))
            out.append({"file": f.name, **{k: res[k] for k in ("ok", "mode", "estimate_id", "title", "say")}})
        except EstimatorError as exc:
            failed.mkdir(parents=True, exist_ok=True)
            shutil.move(str(f), str(failed / f.name))
            (failed / (f.name + ".why.txt")).write_text(exc.message, encoding="utf-8")
            out.append({"file": f.name, "ok": False, "error": exc.message})
        flag.unlink(missing_ok=True)
    return out


# ================================================================ over the internet

USER_AGENT = "AI-Prowler-Estimator/1.0 (project sync)"


def _http(url: str, *, data=None, headers=None, method="POST", timeout=60):
    import urllib.error
    import urllib.request
    # 2026-11-13: Cloudflare (Remote Access) refuses Python's default "Python-urllib/3.x" user agent with
    # 403 error 1010 before the request ever reaches the server, so every call names itself.
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 - https URL the person typed
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            body = json.loads(raw)
        except ValueError:                     # not the Estimator answering (Cloudflare, a proxy ...): say what came back
            body = {"message": "not the Estimator: " + raw.decode("utf-8", "replace").strip()[:120]}
        return e.code, body
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        reason = getattr(e, "reason", e)
        raise InvalidInput(f"couldn't reach the server at {url.split('/estimator-api')[0]} ({reason}). Check the "
                           "address and that the server's Remote Access is on") from None


def server_base(url: str) -> str:
    u = str(url or "").strip().rstrip("/")
    if not u:
        raise InvalidInput("enter the server's Remote Access address (the https://... address the Jobs app uses)")
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    for tail in ("/estimator-api", "/estimator", "/jobs"):
        if u.lower().endswith(tail):
            u = u[: -len(tail)]
    if u.lower().startswith("http://") and not re.match(r"^http://(localhost|127\.0\.0\.1|\[::1\]|192\.168\.|10\.)",
                                                        u, re.I):
        raise InvalidInput("use the server's https:// address; a password must not travel over plain http")
    own = own_remote_host()
    if own and re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].lower() == own:
        raise InvalidInput(f"{u} is THIS PC's own Remote Access address, not the server's. On the server, open the "
                           "🏢 Small Business tab, copy its Jobs App URL and paste it here")
    return u


def own_remote_host() -> str:
    """This PC's own Remote Access host name (from AI-Prowler's config.json), or "" when it has none."""
    try:
        cfg = json.loads((Path.home() / ".ai-prowler" / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    host = str(cfg.get("tunnel_domain") or "").strip().lower()
    return re.sub(r"^https?://", "", host).split("/")[0]


def sign_in(url: str, username: str, password: str) -> str:
    """Sign in to the server's Estimator; returns a session token (kept in memory only)."""
    base = server_base(url)
    status, body = _http(base + "/estimator-api/auth/login",
                         data=json.dumps({"username": username, "password": password}).encode("utf-8"),
                         headers={"Content-Type": "application/json", "X-Estimator-Request": "1"})
    if status != 200 or not body.get("token"):
        raise PermissionDenied(f"the server said: {body.get('message') or 'sign-in failed'} (HTTP {status})")
    return str(body["token"])


def send_over_internet(conn, ctx: RequestContext, estimate_id: int, url: str, token: str, *,
                       replace_anyway: bool = False) -> dict:
    """Build the bundle and upload it to the server's Estimator (streamed; nothing is kept on the server's disk
    except the project itself)."""
    base = server_base(url)
    built = build_bundle(conn, ctx, estimate_id)
    path = Path(built["path"])
    try:
        size = path.stat().st_size
        if size > INTERNET_MAX_BYTES:
            raise InvalidInput(f"the project is {size // (1024 * 1024)} MB; over the internet the limit is 95 MB. "
                               "Send it through the office network instead (mapped drive)", bytes=size)
        q = "?replace=1" if replace_anyway else ""
        with path.open("rb") as f:
            status, body = _http(base + "/estimator-api/sync/receive" + q, data=f, timeout=600,
                                 headers={"Content-Type": "application/zip", "Content-Length": str(size),
                                          "Authorization": f"Bearer {token}", "X-Estimator-Request": "1"})
    finally:
        path.unlink(missing_ok=True)
    if status == 401:
        raise PermissionDenied("the server sign-in expired; sign in again and resend")
    if status != 200 or not body.get("ok"):
        raise InvalidInput(f"the server didn't take the project: {body.get('message') or f'HTTP {status}'}")
    return {**built, "ok": True, "via": "internet", "server": body, "path": None,
            "say": body.get("say") or "Sent to the server."}


# ================================================================ this PC's settings (no passwords)

def settings_path() -> Path:
    return config.data_dir() / SETTINGS_FILE


def load_settings() -> dict:
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {"server_url": str(data.get("server_url") or ""), "username": str(data.get("username") or ""),
            "share_path": str(data.get("share_path") or "")}


def save_settings(server_url: str = "", username: str = "", share_path: str = "") -> dict:
    data = {"server_url": str(server_url or "").strip(), "username": str(username or "").strip(),
            "share_path": str(share_path or "").strip().strip('"')}
    p = settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, p)
    return data


def reachable_share(share: str) -> bool:
    try:
        return bool(share) and Path(share).is_dir()
    except OSError:
        return False


__all__ = ["build_bundle", "receive_bundle", "send_to_share", "take_in_inbox", "send_over_internet", "sign_in",
           "server_base", "load_settings", "save_settings", "received", "inbox_dir"]
