"""What the 🏗 Estimator tab shows and saves, without any tkinter (so it can be tested on its own).

The desktop belongs to the owner, so every save here runs as the owner (personal_context) through the same
service layer the AI tools use; nothing here writes the database directly. Each save returns (ok, message).
"""
from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path

from estimator import config
from estimator.context import RequestContext, personal_context
from estimator.errors import EstimatorError

FEATURE = "estimator"            # the switch in tool_config.json (Setup AI-Prowler → Change my choices)
TAB_TITLE = "🏗 Estimator"


# ---------------------------------------------------------------- the on/off switch

def is_on() -> bool:
    """The Estimator's switch, shared with Setup AI-Prowler. Like AI-Prowler's other features, no entry means on."""
    try:
        import tool_config_store as tcs
        return bool(tcs.feature_on(FEATURE))
    except Exception:  # noqa: BLE001 - outside AI-Prowler there's no switch: on
        return True


def set_on(on: bool) -> tuple[bool, str]:
    try:
        import tool_config_store as tcs
        tcs.set_feature_on(FEATURE, bool(on))
    except Exception as exc:  # noqa: BLE001
        return False, f"Couldn't change the Estimator switch: {exc}"
    return True, ("The Estimator is on. Restart AI-Prowler so your AI gets the Estimator tools." if on else
                  "The Estimator is off. Its tools and background checks stop after AI-Prowler restarts; "
                  "your estimates and settings are kept.")


# ---------------------------------------------------------------- reading

def _ctx() -> RequestContext:
    return personal_context()


def _open():
    from estimator.database import open_database
    return closing(open_database())


def _registry():
    from estimator.modules import get_registry
    return get_registry()


def overview() -> dict:
    """Everything the tab shows at the top: modules, tools, database, watcher, setup progress."""
    from estimator.database.migrations import current_version
    from estimator.director import watch
    from estimator.estimating import setup
    from estimator.mcp_tools.est_tools import TOOLS
    reg = _registry()
    mods = reg.list()
    with _open() as conn:
        st = setup.setup_status(conn, _ctx())
        version = current_version(conn)
        estimates = conn.execute("SELECT COUNT(*) FROM estimates WHERE company_id = ?",
                                 (_ctx().company_id,)).fetchone()[0]
    path = config.db_path()
    return {"on": is_on(), "trades": sorted(m.name for m in mods if m.category == "construction"),
            "services": sorted(m.name for m in mods if m.category != "construction"),
            "module_errors": dict(reg.errors), "tools": len(TOOLS), "db_path": str(path),
            "db_kb": round(path.stat().st_size / 1024) if path.exists() else 0, "db_version": version,
            "estimates": estimates, "watcher_running": watch.is_running(), "setup": st}


def setup_light() -> bool | None:
    """For the Setup AI-Prowler checklist: True when the company basics are in, None while there's more to do."""
    if not is_on():
        return None
    try:
        from estimator.estimating import setup
        with _open() as conn:
            st = setup.setup_status(conn, _ctx())
    except Exception:  # noqa: BLE001
        return None
    done = {s["step"] for s in st["steps"] if s["status"] == "done"}
    return True if {"company_profile", "markups"} <= done else None


def profile() -> dict:
    with _open() as conn:
        row = conn.execute("SELECT * FROM company_profile WHERE company_id = ?", (_ctx().company_id,)).fetchone()
        m = conn.execute("SELECT * FROM markups WHERE company_id = ?", (_ctx().company_id,)).fetchone()
    out = {k: (row[k] if row else "") or "" for k in ("name", "address", "phone", "license_no")}
    out.update(tax_pct=_show_pct(m["tax_pct"] if m else 0), overhead_pct=_show_pct(m["overhead_pct"] if m else 0),
               profit_pct=_show_pct(m["profit_pct"] if m else 0),
               minimum_charge=f"{(m['minimum_charge_cents'] or 0) / 100:.2f}" if m and m["minimum_charge_cents"]
               else "")
    return out


def trades() -> list[dict]:
    from estimator.agent_manager import list_configs
    with _open() as conn:
        return list_configs(conn, _ctx().company_id, _registry())["agents"]


def agents() -> dict:
    from estimator.agents import roles
    with _open() as conn:
        return roles.overview(conn, _ctx().company_id)


def director_settings() -> dict:
    from estimator.director.settings import get_settings
    with _open() as conn:
        return get_settings(conn, _ctx().company_id)


def recent_backups(limit: int = 5) -> list[str]:
    from estimator.database.backup import list_backups
    try:
        return [p.name for p in list_backups()][-limit:][::-1]
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------- saving

def _try(fn) -> tuple[bool, str]:
    try:
        return True, fn() or "Saved."
    except EstimatorError as exc:
        return False, exc.message
    except Exception as exc:  # noqa: BLE001 - the tab shows it; it never crashes AI-Prowler
        return False, f"{type(exc).__name__}: {exc}"


def save_profile(values: dict) -> tuple[bool, str]:
    """Company name, address, phone, license, plus tax, overhead, profit and minimum charge."""
    from estimator.estimating import setup

    def go():
        with _open() as conn:
            prof = {k: (values.get(k) or "").strip() or None for k in ("address", "phone", "license_no")}
            setup.setup_step(conn, _ctx(), "company_profile", {"name": (values.get("name") or "").strip(), **prof})
            setup.setup_step(conn, _ctx(), "tax", {"tax_pct": _pct(values.get("tax_pct"), "Sales tax")})
            mk = {"overhead_pct": _pct(values.get("overhead_pct"), "Overhead"),
                  "profit_pct": _pct(values.get("profit_pct"), "Profit")}
            if (values.get("minimum_charge") or "").strip():
                mk["minimum_charge"] = values["minimum_charge"].strip().lstrip("$")
            setup.setup_step(conn, _ctx(), "markups", mk)
        return "Company details, tax and markups saved."
    return _try(go)


def _pct(value, label: str) -> str:
    from decimal import Decimal, InvalidOperation
    text = str(value or "0").strip().rstrip("%").strip() or "0"
    try:
        d = Decimal(text)
    except InvalidOperation:
        raise EstimatorError(f"{label} must be a number, like 8.6") from None
    if not Decimal(0) <= d <= Decimal(100):
        raise EstimatorError(f"{label} must be between 0 and 100")
    return str((d / 100).normalize()) if d else "0"          # stored as a fraction: 8.6% -> 0.086


def _show_pct(fraction) -> str:
    """A stored fraction as the percent people type: 0.086 -> 8.6."""
    from decimal import Decimal, InvalidOperation
    try:
        d = Decimal(str(fraction or "0")) * 100
    except InvalidOperation:
        return "0"
    text = format(d.normalize(), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def mark_step(step: str, status: str) -> tuple[bool, str]:
    from estimator.estimating import setup

    def go():
        with _open() as conn:
            setup.setup_step(conn, _ctx(), step, None, status=status)
        return "Done." if status == "done" else "Skipped (you can come back to it)."
    return _try(go)


def set_trade(module_id: str, enabled: bool) -> tuple[bool, str]:
    from estimator.agent_manager import update_config

    def go():
        with _open() as conn:
            update_config(conn, _ctx(), module_id, {"enabled": bool(enabled)}, confirm=True, registry=_registry())
        return f"{module_id.replace('_', ' ').title()} {'on' if enabled else 'off'}."
    return _try(go)


def labor_rates() -> list[dict]:
    """Every labor rate the Estimator knows: the company's own, or the module sample if none is saved yet.

    Labor rates are the labor-kind prices in the price book (per hour, per sq ft, per linear ft, ...).
    The web app Settings screen shows the same list; this is the desktop tab's copy of it.
    """
    from estimator.pricing import price_book

    with _open() as conn:
        rows = price_book.list_prices(conn, _ctx().company_id, registry=_registry())["prices"]
    return [{"price_key": r["price_key"], "module_id": r.get("module_id"), "description": r["description"],
             "unit": r["unit"], "cost_cents": r["cost_cents"], "sample": bool(r["sample"])}
            for r in rows if r["kind"] == "labor"]


def save_labor_rates(prices: dict) -> tuple[bool, str]:
    """Set your own labor rates (dollars as text, e.g. {"hc_labor_hr": "55"}).

    Only labor rates; anything else is refused (change those in the Price Book).
    Saving also marks the "Labor rates" setup step done.
    """
    from estimator.errors import InvalidInput
    from estimator.estimating import setup
    from estimator.pricing import price_book

    def go():
        with _open() as conn:
            labor = {r["price_key"] for r in price_book.list_prices(conn, _ctx().company_id, registry=_registry())["prices"]
                     if r["kind"] == "labor"}
            other = sorted(set(prices) - labor)
            if other:
                raise InvalidInput(f"these aren't labor rates: {', '.join(other)}; change them in the Price Book")
            if not prices:
                raise InvalidInput("change at least one labor rate")
            price_book.update_prices(conn, _ctx(), prices, confirm=True, registry=_registry())
            setup.setup_step(conn, _ctx(), "labor_rates", {"prices": prices})
        return f"Labor rates saved ({len(prices)} rate(s)). New rates apply to new and re-priced estimates."
    return _try(go)


def save_role(role: str, provider: str, model: str = "", fallback: str = "") -> tuple[bool, str]:
    from estimator.agents import roles

    def go():
        with _open() as conn:
            out = roles.update_role(conn, _ctx(), role, {"provider": provider, "model": model or "",
                                                          "fallback_provider": fallback or ""}, confirm=True)
        return " ".join(["Saved."] + out["warnings"])
    return _try(go)


def save_budget(daily_dollars: str, monthly_dollars: str) -> tuple[bool, str]:
    from estimator.agents import roles

    def cents(text, label):
        from decimal import Decimal, InvalidOperation
        try:
            d = Decimal(str(text).strip().lstrip("$") or "0")
        except InvalidOperation:
            raise EstimatorError(f"{label} must be dollars, like 2.00") from None
        return int((d * 100).to_integral_value())

    def go():
        with _open() as conn:
            roles.update_budget(conn, _ctx(), {"daily_cents": cents(daily_dollars, "The daily budget"),
                                               "monthly_cents": cents(monthly_dollars, "The monthly budget")},
                                confirm=True)
        return "AI budget saved."
    return _try(go)


def save_director(changes: dict) -> tuple[bool, str]:
    from estimator.director.settings import update_settings

    def go():
        with _open() as conn:
            update_settings(conn, _ctx(), changes)
        return "Director settings saved."
    return _try(go)


def backup_now() -> tuple[bool, str]:
    from estimator.database.backup import backup_database, prune_backups

    def go():
        path = backup_database()
        prune_backups()
        return f"Backed up to {Path(path).name}"
    return _try(go)


def modules() -> list[dict]:
    """Every installed trade and service module, for the 📦 Modules section."""
    reg = _registry()
    return [{"id": m.id, "name": m.name, "category": m.category, "version": m.version,
             "how": {"quick_estimate": "quick quote", "plan_takeoff": "plan takeoff", "both": "quick or plans"}.get(m.path, m.path)}
            for m in sorted(reg.list(), key=lambda m: (m.category, m.name))]


def services() -> list[dict]:
    """Every service module (pressure washing, cleaning, pest, ...), for the Trades section.

    Service quotes are always available for estimation (quick quotes, no plans needed);
    unlike construction trades they have no takeoff task, so there is no on/off switch.
    """
    reg = _registry()
    return [{"id": m.id, "name": m.name, "version": m.version,
             "how": {"quick_estimate": "quick quote", "plan_takeoff": "plan takeoff", "both": "quick or plans"}.get(m.path, m.path)}
            for m in sorted((m for m in reg.list() if m.category == "service"), key=lambda m: m.name)]


def practice_id() -> int | None:
    with _open() as conn:
        row = conn.execute("SELECT id FROM estimates WHERE company_id = ? AND is_practice = 1 ORDER BY id LIMIT 1",
                           (_ctx().company_id,)).fetchone()
    return row[0] if row else None


def practice_create() -> tuple[bool, str]:
    from estimator import practice

    def go():
        with _open() as conn:
            out = practice.create(conn, _ctx())
        from estimator.core.units.money import format_cents
        return (f"{out['title']} is ready (estimate {out['estimate_id']}, {format_cents(out['total_cents'])}). Ask your AI "
                "\"show me the practice estimate\" to try it." if out["created"] else out["message"])
    return _try(go)


def practice_delete() -> tuple[bool, str]:
    from estimator import practice

    def go():
        with _open() as conn:
            return practice.delete(conn, _ctx(), confirm=True)["message"]
    return _try(go)


def data_export() -> tuple[bool, str]:
    from estimator import data_move

    def go():
        with _open() as conn:
            out = data_move.export_data(conn, _ctx())
        return (f"Packed {out['counts']['estimates']} estimate(s) and {out['counts']['bids']} quote(s) into {out['path']}. "
                "Copy it to the other AI-Prowler and load it there.")
    return _try(go)


def data_import_preview(path: str) -> tuple[bool, str]:
    """What loading the file would do, in words (nothing is loaded)."""
    from estimator import data_move
    from estimator.errors import ConfirmationRequired
    try:
        with _open() as conn:
            data_move.import_data(conn, _ctx(), path, confirm=False)
    except ConfirmationRequired as ask:
        d = ask.details
        c = d["counts"]
        return True, (f"From {d['from_company']} (packed {str(d['exported_at'])[:10]}): {c['estimates']} estimate(s), "
                      f"{c['bids']} quote(s), {c['price_book']} price(s). Settings: {d['settings']}.")
    except EstimatorError as exc:
        return False, exc.message
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    return False, "That file has nothing to load."


def data_import(path: str) -> tuple[bool, str]:
    from estimator import data_move

    def go():
        with _open() as conn:
            out = data_move.import_data(conn, _ctx(), path, confirm=True)
        return (f"Loaded {out['imported']['estimates']} estimate(s) and {out['imported']['bids']} quote(s). Estimates have "
                "new numbers here; quote numbers are unchanged.")
    return _try(go)


def example_prompts() -> list[str]:
    return ["Quote a pressure wash for the Garcia house: 1,800 sq ft driveway and patio",
            "Replace the roof on 2,000 sq ft, 5/12 pitch, architectural shingles",
            "Bid the Miller plans: framing, drywall and a new roof (has plans)",
            "Show me the practice estimate",
            "Show my estimating jobs board",
            "What's waiting for review?",
            "Import my supplier price list from C:\\Users\\me\\Documents\\abc_supply_prices.csv",
            "The Garcia roof is done: it really cost $8,600. How did that compare?",
            "Where do my prices run high or low?",
            "Export the Miller estimate to Excel",
            "Pack up my Estimator data to move to the server",
            "Set the AI budget to $1 a day"]


def as_json(obj) -> str:
    return json.dumps(obj, indent=1, default=str)


# ---------------------------------------------------------------- CAD and tools, web app access

def _oda_glob() -> str:
    """The ODA File Converter exe from its usual install folders ("" when it is not installed)."""
    import glob
    import os
    drive = os.environ.get("SystemDrive", "C:")
    for base in (("Program Files", "ODA"), ("Program Files (x86)", "ODA")):
        pat = os.path.join(drive + os.sep, *base, "ODAFileConverter*", "ODAFileConverter.exe")
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[0]
    return ""


DWG_DOWNLOAD_URL = "https://www.opendesign.com/guestfiles/oda_file_converter"


def tool_status(which=None, find_spec=None) -> list[dict]:
    """CAD and file tools the Estimator can use on this PC, for the CAD and tools section of the tab.

    Each entry is {"tool", "ok", "detail"}; the DWG entry also carries "download_url" while the
    converter is missing, so the tab can show a copy button for it. Tests pass their own `which` /
    `find_spec` to fake the whole environment; with the real ones, the ODA converter is also looked
    for in its install folders.
    """
    import importlib.util
    import shutil
    real_which = which is None
    which = which or shutil.which
    find_spec = find_spec or importlib.util.find_spec
    dxf = find_spec("ezdxf") is not None
    # Coder 2 Sprint 16: the same search the plan engine converts DWG with (ODA, else LibreDWG's dwg2dxf).
    from estimator.plan_engine import dwg
    conv = dwg.find_converter(which=which, search_installs=real_which)
    oda = conv["path"] if conv else ""
    tess = which("tesseract") or ""
    dwg_entry = {"tool": "DWG converter (ODA File Converter)", "ok": bool(oda),
                 "detail": f"{conv['name']} found at {oda}; DWG plan files are converted to DXF with it." if oda else
                           "Not installed, so DWG plan files cannot be opened. It is a free download from the"
                           " Open Design Alliance (ODA File Converter) - install it like this:\n"
                           f"1. Open {DWG_DOWNLOAD_URL} in your browser.\n"
                           "2. Download the Windows version (Windows 10 or later, 64-bit).\n"
                           "3. Run the downloaded installer and accept the defaults.\n"
                           "4. Restart AI-Prowler - this line turns green and shows where the converter was found."}
    if not oda:
        dwg_entry["download_url"] = DWG_DOWNLOAD_URL
    return [
        {"tool": "DXF drawings", "ok": dxf,
         "detail": "ezdxf is installed, so DXF plan files can be read directly." if dxf else
                   "ezdxf is missing, so DXF plan files cannot be read. It ships in requirements.txt;"
                   " reinstalling AI-Prowler restores it."},
        dwg_entry,
        {"tool": "Tesseract OCR (reads scanned plans)", "ok": bool(tess),
         "detail": f"Found at {tess}." if tess else
                   "Not installed, so scanned plans and photos cannot be text-read (OCR)."},
    ]


def web_app_access() -> dict:
    """Where the Estimator web app is and who can sign in, for the Phone and web app section of the tab.

    The port matches estimator.api.server (ESTIMATOR_WEB_PORT, default 8770). The sign-in rules are
    the roles mapping in estimator.api.prowler_link (Jamie, 2026-11-09).
    """
    import os
    port = os.environ.get("ESTIMATOR_WEB_PORT", "8770")
    return {
        "url": f"http://localhost:{port}/estimator/",
        "port": port,
        "lines": [
            "The Estimator web app is built: plans, reviews and takeoffs in a browser, on this PC or a phone.",
            f"On this PC: http://localhost:{port}/estimator/",
            "On your phone: open the same address through Remote Access (in Server mode, your office network address works too).",
            "You can also see your estimates in the Jobs app, on the Estimates screen \u2014 it is the same web app, on your phone.",
            "Sign-in uses AI-Prowler accounts. The owner has full access; managers and staff sign in as office, and with the Estimating scope (Admin, Manage Scopes) as estimators who can change and approve; field crew can look, but not change or approve.",
        ],
    }

