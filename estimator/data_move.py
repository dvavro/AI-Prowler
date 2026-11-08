"""Move a company's Estimator data to another AI-Prowler: Personal → Server, or to a new PC (est_data_export,
est_data_import).

Export writes one .zip to the Estimator's exports folder: manifest.json (what's in it, the database version), data.json
(every row of the company's estimating data) and the bid files (HTML and PDF quotes). Import reads that file into the
company of whoever runs it, giving every row a new number so nothing on the receiving side is overwritten, and keeps
quote numbers as customers saw them.

Left out on purpose: the inbox (notices), watcher runs, agent task queue and agent spend, which belong to the PC that
made them. Practice estimates are left out unless asked for.

Safety: owner only; import previews first and needs confirm=true; the file must come from this or an older Estimator
(never a newer database); only the expected names are read from the zip (no paths outside it); a company that already
has estimates keeps its own settings, prices and company profile (the file's are added only where it has none).
"""
from __future__ import annotations

import json
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput, PermissionDenied
from estimator.estimating import service

FORMAT = "ai-prowler-estimator-data"
MAX_ZIP_BYTES = 200 * 1024 * 1024
MAX_DATA_BYTES = 100 * 1024 * 1024
FILE_RE = re.compile(r"files/(\d{1,9})/([A-Za-z0-9 _.()-]{1,120}\.(?:html|pdf))")

# Company-wide settings: one row per company (or per company and key). Replaced only on an empty company.
SETTINGS = ("company_profile", "setup_progress", "markups", "director_settings", "playbook_overrides",
            "agent_configs", "agent_roles", "agent_budgets")
# (table, {column: table it points to}) in an order where parents come first. "id" is always renumbered.
RECORDS = (
    ("estimates", {"parent_estimate_id": "estimates"}),
    ("trade_sections", {"estimate_id": "estimates"}),
    ("line_items", {"trade_section_id": "trade_sections"}),
    ("estimate_events", {"estimate_id": "estimates"}),
    ("estimate_scenarios", {"estimate_id": "estimates"}),
    ("estimate_actuals", {"estimate_id": "estimates", "line_item_id": "line_items"}),
    ("director_jobs", {"estimate_id": "estimates"}),
    ("director_steps", {"job_id": "director_jobs"}),
    ("bids", {"estimate_id": "estimates"}),
    ("runs", {"estimate_id": "estimates", "job_id": "director_jobs"}),
    ("takeoff_tasks", {"run_id": "runs", "estimate_id": "estimates"}),
)
# How rows that have no company_id column are found: through their parent.
PARENT = {"trade_sections": ("estimate_id", "estimates"), "line_items": ("trade_section_id", "trade_sections"),
          "director_steps": ("job_id", "director_jobs")}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _owner(ctx: RequestContext) -> None:
    if ctx.role != "owner":
        raise PermissionDenied("only the owner can move the company's Estimator data", role=ctx.role)


def _columns(conn, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


# ---------------------------------------------------------------- export

def export_data(conn, ctx: RequestContext, include_practice: bool = False) -> dict:
    from estimator.database.migrations import current_version
    _owner(ctx)
    company = ctx.company_id
    tables: dict[str, list[dict]] = {}
    for t in SETTINGS + ("price_book",):
        tables[t] = [dict(r) for r in conn.execute(f"SELECT * FROM {t} WHERE company_id = ?", (company,))]
    est_where = "" if include_practice else " AND is_practice = 0"
    ids: dict[str, set] = {}
    for t, _refs in RECORDS:
        if t == "estimates":
            rows = conn.execute(f"SELECT * FROM estimates WHERE company_id = ?{est_where}", (company,)).fetchall()
        elif t in PARENT:
            col, parent = PARENT[t]
            keep = ids.get(parent, set())
            rows = [r for r in conn.execute(f"SELECT * FROM {t}") if r[col] in keep]
        else:
            rows = conn.execute(f"SELECT * FROM {t} WHERE company_id = ?", (company,)).fetchall()
            if "estimate_id" in _columns(conn, t):
                rows = [r for r in rows if r["estimate_id"] is None or r["estimate_id"] in ids["estimates"]]
            if t == "runs":
                rows = [r for r in rows if r["job_id"] is None or r["job_id"] in ids["director_jobs"]]
            if t == "takeoff_tasks":
                rows = [r for r in rows if r["run_id"] in ids["runs"]]
        tables[t] = [dict(r) for r in rows]
        ids[t] = {r["id"] for r in tables[t]}
    # parents left out (practice) must not be pointed at
    for row in tables["estimates"]:
        if row["parent_estimate_id"] not in ids["estimates"]:
            row["parent_estimate_id"] = None
    for row in tables["runs"]:
        row["plan_set_id"] = None              # plan sets aren't packed yet (see left_out)
    counts = {t: len(v) for t, v in tables.items()}
    plan_sets = conn.execute("SELECT COUNT(*) FROM plan_sets p JOIN estimates e ON e.id = p.estimate_id"
                             f" WHERE p.company_id = ?{est_where.replace('is_practice', 'e.is_practice')}",
                             (company,)).fetchone()[0]
    left_out = ([f"{plan_sets} plan set(s) and what was read from them: upload the plan files again on the other "
                 "AI-Prowler (moving processed plans to the server comes with the processing-PC work)"]
                if plan_sets else [])
    manifest = {"format": FORMAT, "schema_version": current_version(conn), "company_id": company,
                "company_name": (tables["company_profile"][0].get("name") if tables["company_profile"] else None),
                "exported_at": _now(), "exported_by": ctx.actor, "include_practice": bool(include_practice),
                "counts": counts}
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = config.data_dir() / "exports"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"estimator_data_{re.sub(r'[^A-Za-z0-9_-]', '_', company)}_{stamp}.zip"
    files = 0
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        z.writestr("data.json", json.dumps({"tables": tables}, default=str))
        for b in tables["bids"]:
            for col in ("html_path", "pdf_path"):
                p = Path(b[col]) if b.get(col) else None
                if p and p.is_file() and FILE_RE.fullmatch(f"files/{b['id']}/{p.name}"):
                    z.write(p, f"files/{b['id']}/{p.name}")
                    files += 1
    service._log(conn, ctx, None, "data_exported", {"file": path.name, "counts": counts})
    return {"ok": True, "path": str(path), "file": path.name, "counts": counts, "bid_files": files,
            "left_out": left_out,
            "note": "Copy this file to the other AI-Prowler and import it there with est_data_import (owner only)."}


# ---------------------------------------------------------------- import

def _read(file_path: str) -> tuple[dict, dict, zipfile.ZipFile]:
    path = Path(str(file_path or "").strip().strip('"'))
    if path.suffix.lower() != ".zip" or not path.is_file():
        raise InvalidInput("give the .zip file made by est_data_export", file=str(path))
    if path.stat().st_size > MAX_ZIP_BYTES:
        raise InvalidInput("the file is over 200 MB", file=str(path))
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise InvalidInput("that isn't a readable .zip file", file=str(path)) from None
    names = set(z.namelist())
    if not {"manifest.json", "data.json"} <= names:
        z.close()
        raise InvalidInput("that .zip isn't an Estimator data file (no manifest.json / data.json)")
    info = z.getinfo("data.json")
    if info.file_size > MAX_DATA_BYTES:
        z.close()
        raise InvalidInput("data.json in the file is too big")
    try:
        manifest = json.loads(z.read("manifest.json"))
        data = json.loads(z.read("data.json"))
    except ValueError:
        z.close()
        raise InvalidInput("the file's data is damaged") from None
    if manifest.get("format") != FORMAT or not isinstance(data.get("tables"), dict):
        z.close()
        raise InvalidInput("that .zip isn't an Estimator data file")
    return manifest, data["tables"], z


def import_data(conn, ctx: RequestContext, file_path: str, confirm: bool = False) -> dict:
    from estimator.database.migrations import current_version
    _owner(ctx)
    manifest, tables, z = _read(file_path)
    try:
        have = current_version(conn)
        if int(manifest.get("schema_version", 0)) > have:
            raise InvalidInput(f"the file comes from a newer Estimator (database v{manifest['schema_version']}, this one is "
                               f"v{have}). Update this AI-Prowler first.", schema_version=manifest["schema_version"])
        known = set(SETTINGS) | {"price_book"} | {t for t, _ in RECORDS}
        unknown = set(tables) - known
        if unknown:
            raise InvalidInput(f"the file has tables this Estimator doesn't know: {', '.join(sorted(unknown))}")
        target = ctx.company_id
        has_work = conn.execute("SELECT COUNT(*) FROM estimates WHERE company_id = ? AND is_practice = 0",
                                (target,)).fetchone()[0]
        counts = {t: len(tables.get(t) or []) for t in known}
        preview = {"from_company": manifest.get("company_name") or manifest.get("company_id"),
                   "exported_at": manifest.get("exported_at"), "counts": counts,
                   "settings": ("kept: this company already has estimates, so its own settings, prices and profile stay "
                                "(the file's are added only where it has none)" if has_work else
                                "replaced by the file's (company profile, markups, Director settings, agents, setup)"),
                   "your_estimates_now": has_work}
        if not confirm:
            raise ConfirmationRequired(
                f"Import {counts['estimates']} estimate(s), {counts['bids']} quote(s) and {counts['price_book']} price(s) "
                f"from {preview['from_company']} into this company? Settings will be {preview['settings'].split(':')[0]}. "
                "Call again with confirm=true.", **preview)
        new_ids: dict[str, dict] = {t: {} for t, _ in RECORDS}
        files = 0
        with service.transaction(conn):
            for t in SETTINGS:
                cols = _columns(conn, t)
                verb = "INSERT OR IGNORE" if has_work else "INSERT OR REPLACE"
                for row in tables.get(t) or []:
                    vals = {c: row.get(c) for c in cols if c in row}
                    vals["company_id"] = target
                    conn.execute(f"{verb} INTO {t} ({', '.join(vals)}) VALUES ({', '.join('?' for _ in vals)})",
                                 list(vals.values()))
            cols = [c for c in _columns(conn, "price_book") if c != "id"]
            for row in tables.get("price_book") or []:
                vals = {c: row.get(c) for c in cols if c in row}
                vals["company_id"] = target
                conn.execute(f"INSERT OR IGNORE INTO price_book ({', '.join(vals)}) VALUES "
                             f"({', '.join('?' for _ in vals)})", list(vals.values()))
            for t, refs in RECORDS:
                cols = [c for c in _columns(conn, t) if c != "id"]
                for row in tables.get(t) or []:
                    vals = {c: row.get(c) for c in cols if c in row}
                    if "company_id" in cols:
                        vals["company_id"] = target
                    for col, parent in refs.items():
                        old = row.get(col)
                        if old is None:
                            continue
                        if parent == t and t == "estimates":
                            vals[col] = None                         # filled in once every estimate has its number
                        elif old in new_ids[parent]:
                            vals[col] = new_ids[parent][old]
                        elif col == "line_item_id":
                            vals[col] = None
                        else:
                            raise InvalidInput(f"the file is inconsistent: {t} row {row.get('id')} points at a missing "
                                               f"{parent} row {old}")
                    cur = conn.execute(f"INSERT INTO {t} ({', '.join(vals)}) VALUES ({', '.join('?' for _ in vals)})",
                                       list(vals.values()))
                    new_ids[t][row["id"]] = cur.lastrowid
            for row in tables.get("estimates") or []:
                if row.get("parent_estimate_id") in new_ids["estimates"]:
                    conn.execute("UPDATE estimates SET parent_estimate_id = ? WHERE id = ?",
                                 (new_ids["estimates"][row["parent_estimate_id"]], new_ids["estimates"][row["id"]]))
            for row in tables.get("bids") or []:
                new_bid, new_est = new_ids["bids"][row["id"]], new_ids["estimates"][row["estimate_id"]]
                folder = config.data_dir() / "projects" / f"estimate_{new_est:04d}" / "bids"
                updates = {}
                for col in ("html_path", "pdf_path"):
                    name = Path(row[col]).name if row.get(col) else None
                    member = f"files/{row['id']}/{name}" if name else None
                    if member and FILE_RE.fullmatch(member) and member in z.namelist():
                        folder.mkdir(parents=True, exist_ok=True)
                        with z.open(member) as src, (folder / name).open("wb") as dst:
                            shutil.copyfileobj(src, dst)
                        updates[col] = str(folder / name)
                        files += 1
                    else:
                        updates[col] = None
                conn.execute("UPDATE bids SET html_path = ?, pdf_path = ? WHERE id = ?",
                             (updates["html_path"], updates["pdf_path"], new_bid))
            service._log(conn, ctx, None, "data_imported",
                         {"from": preview["from_company"], "counts": counts, "settings": "kept" if has_work else "replaced"})
    finally:
        z.close()
    return {"ok": True, "imported": counts, "bid_files": files, "settings": preview["settings"],
            "estimate_numbers": {str(k): v for k, v in new_ids["estimates"].items()},
            "note": "Estimates have new numbers here (see estimate_numbers: old → new). Quote numbers stay as customers "
                    "saw them."}
