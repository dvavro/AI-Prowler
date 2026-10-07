"""AI-Prowler Setup Center — the Home-page guide for new users and for adding
services later (SETUP_CENTER_SPEC.md).

Two layers:
  • Plain logic (no Tk) — the module registry, the "What do you want
    AI-Prowler to do?" choices, dependencies, and saved progress. Unit-tested
    in tests\\test_setup_wizard.py.
  • SetupCenterPanel (Tk) — the panel on the Home tab.

Phase 1 (2026-09-30): panel + picker + progress. Each module's Start button
opens the real tab where that thing is set up; the guided Why → Do → Check
screens arrive module by module in Phases 2–6. A module's detect() says
"already set up" by looking at the real settings — never a copy.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

PROGRESS_PATH = Path.home() / ".ai-prowler" / "setup_progress.json"
PROGRESS_VERSION = 1

# states a module can be in (saved); "done" is also reached through detect()
NOT_STARTED, IN_PROGRESS, DONE, SKIPPED = "not_started", "in_progress", "done", "skipped"

SERVER_INFO_URL = "https://ai-prowler.com"          # SETUP_CENTER_SPEC §8 Q2 — confirm with David


# ── detect helpers (real settings only) ─────────────────────────────────────
def _tracked_paths() -> list:
    """The folders/files AI-Prowler indexes. Uses rag_preprocessor's own loader
    when the app has it loaded (it honours the E2E test-state redirect);
    otherwise reads ~/.rag_auto_update_dirs.json ({"directories": [...]})."""
    import sys
    rp = sys.modules.get("rag_preprocessor")
    if rp is not None and hasattr(rp, "load_auto_update_list"):
        try:
            return [d for d in (rp.load_auto_update_list() or []) if str(d).strip()]
        except Exception:
            pass
    p = Path.home() / ".rag_auto_update_dirs.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(data, dict):                       # tolerate {"directories": [...]}
        data = data.get("directories") or data.get("paths") or []
    return [d for d in data if isinstance(d, str) and d.strip()] if isinstance(data, list) else []


def detect_indexed() -> Optional[bool]:
    return bool(_tracked_paths())


# ── "Keep your index up to date": File Watchdog + nightly Windows task ──────
AUTO_TASK_NAME = "AI Prowler Auto-Update"          # rag_gui.set_schedule's task name
ALL_DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
DEFAULT_NIGHTLY = "02:00"


def schedule_task_exists() -> bool:
    """True if the Schedule tab's Windows task exists (and isn't disabled)."""
    if os.name != "nt":
        return False
    import subprocess
    try:
        r = subprocess.run(f'schtasks /query /tn "{AUTO_TASK_NAME}" /fo list', shell=True,
                           capture_output=True, text=True, timeout=10,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return False
    return r.returncode == 0 and "Disabled" not in r.stdout


def watchdog_running() -> bool:
    try:
        import file_watchdog
        return bool(file_watchdog.is_running())
    except Exception:
        return False


def detect_auto_index() -> Optional[bool]:
    return watchdog_running() or schedule_task_exists()


def valid_hhmm(t: str) -> bool:
    try:
        h, m = t.strip().split(":")
        return len(m) == 2 and 0 <= int(h) <= 23 and 0 <= int(m) <= 59
    except (ValueError, AttributeError):
        return False


# ── Phase 3: Links & Analysis · Learnings · Email ───────────────────────────
EMAIL_CONFIG_PATH = Path.home() / ".ai-prowler" / "email_config.json"


def detect_links() -> Optional[bool]:
    try:
        import custom_tasks_manager as ctm
        return len(ctm.load_custom_tasks()) > 0
    except Exception:
        return None


def detect_learnings() -> Optional[bool]:
    try:
        import self_learning as sl
        return int(sl.get_learning_stats().get("active", 0)) > 0
    except Exception:
        return None


def email_configured() -> bool:
    """Same test the server uses (check_email_configured): the Settings tab /
    configure_email() write ~/.ai-prowler/email_config.json; SMTP needs a host,
    the Outlook backend needs no password."""
    try:
        cfg = json.loads(EMAIL_CONFIG_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return False
    return bool(cfg.get("smtp_host")) or str(cfg.get("backend", "")).lower() == "outlook"


def detect_email() -> Optional[bool]:
    return email_configured()


# Where each provider makes the "app password" AI-Prowler needs for SMTP.
APP_PASSWORD_LINKS = [
    ("Gmail", "https://myaccount.google.com/apppasswords"),
    ("Yahoo", "https://login.yahoo.com/account/security"),
    ("iCloud", "https://account.apple.com"),
]


def next_weekday(today, weekday: int):
    """The next date (after today) that falls on weekday (Mon=0…Sun=6)."""
    import datetime as dt
    d = today + dt.timedelta(days=1)
    while d.weekday() != weekday:
        d += dt.timedelta(days=1)
    return d


def first_of_next_month(today):
    import datetime as dt
    return dt.date(today.year + (today.month == 12), today.month % 12 + 1, 1)


# Ready-made scheduled analyses (Links & Analysis). Each becomes a normal custom
# task via custom_tasks_manager.create_task — nothing special about them after.
ANALYSIS_TEMPLATES = [
    {"id": "weekly_docs", "label": "Weekly summary of my new documents",
     "schedule": "weekly", "day": 0, "needs": None,
     "prompt": "Look at the documents added or changed in my indexed folders during the past week. "
               "Summarize the key points of each, and list anything that looks like it needs action "
               "from me, with the file it came from."},
    {"id": "overdue_invoices", "label": "Overdue invoices check",
     "schedule": "weekly", "day": 0, "needs": "business",
     "prompt": "Check my job tracker for invoices that are past due. List each customer, invoice, "
               "amount and days overdue, oldest first, and suggest a short, polite reminder for each."},
    {"id": "monthly_review", "label": "Monthly business review",
     "schedule": "monthly", "day": None, "needs": "business",
     "prompt": "Review last month's jobs, invoices and payments in my job tracker. Summarize revenue, "
               "jobs completed, top customers, anything unpaid, and three things worth doing next month."},
]


def template_task_args(tpl: dict, today, email_on: bool) -> dict:
    """Arguments for custom_tasks_manager.create_task for a template.
    Learnings always on (results land somewhere durable); email only if asked."""
    if tpl["schedule"] == "weekly":
        first = next_weekday(today, tpl["day"])
    else:
        first = first_of_next_month(today)
    args = {"label": tpl["label"], "prompt": tpl["prompt"], "schedule": tpl["schedule"],
            "first_due": first.isoformat(), "output_learnings": True, "output_email": bool(email_on)}
    if tpl.get("day") is not None and tpl["schedule"] in ("weekly", "biweekly", "monthly"):
        args["schedule_day_of_week"] = tpl["day"]
    return args


LEARNING_EXAMPLES = [
    ("My business hours", "We're open Monday–Friday 8 AM to 5 PM, and Saturday 9 AM to noon. Closed Sundays."),
    ("How I like reports", "Keep reports short: a 3-line summary first, then a bulleted list, "
                           "and money totals at the bottom."),
    ("A note about a client", "Blue Wave Cafe prefers text messages over phone calls and pays by check."),
]


# ── Phase 4: phone access (secure link, token, power, start with Windows) ───
POWER_CHECKS = [
    ("sleep", "Sleep while plugged in → Never"),
    ("hibernate", "Hibernate → Off"),
    ("active_hours", "Windows Update active hours → 6 AM to 11 PM"),
    ("no_auto_restart", "Auto-restart for updates → Off"),
]


def power_status() -> dict:
    """The four "keep AI-Prowler reachable" power checks — the ONE copy, used by
    the Settings tab's lights (Check Power Settings) and the Setup Center.
    {key: (ok, detail)}; any check that can't be read counts as not ok."""
    out = {k: (False, "") for k, _ in POWER_CHECKS}
    if os.name != "nt":
        return out
    import subprocess
    import winreg
    no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    def powercfg(sub, setting):
        try:
            r = subprocess.run(["powercfg", "/query", "SCHEME_CURRENT", sub, setting],
                               capture_output=True, text=True, creationflags=no_win, timeout=10)
            for line in r.stdout.splitlines():
                if "AC Power Setting Index" in line:
                    return int(line.split(":")[-1].strip(), 16)
        except Exception:
            pass
        return None

    def dword(path, name):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                return int(winreg.QueryValueEx(k, name)[0])
        except Exception:
            return None

    v = powercfg("SUB_SLEEP", "STANDBYIDLE")
    out["sleep"] = (v == 0, f"({v // 60} min)" if v else "")
    hib_off = not os.path.exists(r"C:\hiberfil.sys")
    out["hibernate"] = (hib_off, "" if hib_off else "(hiberfil.sys present)")
    wu = r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    s, e = dword(wu, "ActiveHoursStart"), dword(wu, "ActiveHoursEnd")
    out["active_hours"] = ((s is not None and e is not None and s <= 6 and e >= 23),
                           f"({s}:00–{e}:00)" if s is not None and e is not None else "(not set)")
    nr = dword(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoRebootWithLoggedOnUsers")
    out["no_auto_restart"] = (nr == 1, "(not set)" if nr is None else "")
    return out


AUTOSTART_TASK = "AI-Prowler-AutoStart"        # created by the installer (RegisterStartupTask)


def autostart_task_exists() -> bool:
    if os.name != "nt":
        return False
    import subprocess
    try:
        r = subprocess.run(f'schtasks /query /tn "{AUTOSTART_TASK}"', shell=True, capture_output=True,
                           text=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return False
    return r.returncode == 0 and "Disabled" not in r.stdout


def autostart_script(app_dir: Path, username: str) -> str:
    """The same schtasks command the installer's RegisterStartupTask runs:
    at logon, as this user, elevated (so the server can bind its port), after 1 min."""
    launcher = Path(app_dir) / "RAG_RUN.bat"
    return ("@echo off\r\n"
            f'schtasks /Create /F /RU "{username}" /SC ONLOGON /TN "{AUTOSTART_TASK}" '
            f'/TR "\\"{launcher}\\"" /RL HIGHEST /DELAY 0001:00\r\n'
            "del \"%~f0\"\r\n")


def create_autostart_task() -> tuple[bool, str]:
    """Create the AutoStart task through Windows' permission prompt (UAC) —
    /RL HIGHEST needs administrator rights."""
    import ctypes
    import tempfile
    user = os.environ.get("USERNAME", "")
    app_dir = Path(__file__).resolve().parent
    if not (app_dir / "RAG_RUN.bat").exists():
        return False, f"Couldn't find RAG_RUN.bat in {app_dir}."
    tmp = tempfile.NamedTemporaryFile(suffix=".bat", mode="w", delete=False, encoding="utf-8",
                                      prefix="aip_autostart_")
    tmp.write(autostart_script(app_dir, user))
    tmp.close()
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", tmp.name, None, None, 0)
    if ret <= 32:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        return False, "Windows' permission prompt was cancelled."
    return True, "Approve Windows' permission prompt — then click Check again."


def remote_app_url(domain: str | None = None) -> str:
    d = tunnel_domain() if domain is None else domain
    return f"https://{d}/remote/" if d else ""


def jobs_app_url(domain: str | None = None) -> str:
    d = tunnel_domain() if domain is None else domain
    return f"https://{d}/jobs/" if d else ""


PHONE_INSTALL_STEPS = ("iPhone: open it in Safari → Share → Add to Home Screen. If the QR opened in another browser, copy the link into Safari first (or set Safari as the default in Settings → Apps).\n"
                       "Android: open it in Chrome and tap the Install button on the page (or ⋮ → Install app).")


def show_qr_window(master, title: str, url: str, caption: str = "") -> bool:
    """A small window with a big QR code for `url`, the link with 📋 Copy, and
    the phone install steps. Shared by the Settings tab (Remote Control URL),
    the Small Business tab (Jobs App URL) and the Setup Center. The code holds
    ONLY the link — never the Bearer Token. False (after saying why) if there's
    no link or no QR library."""
    import tkinter as tk
    from tkinter import messagebox, ttk
    if not url:
        messagebox.showwarning("No link yet", "Set up phone access first — on the Settings tab, activate "
                               "your subscription and click ⚡ Configure Mobile Access.", parent=master)
        return False
    png = qr_png(url, scale=7)
    if not png:
        messagebox.showwarning("QR code unavailable", "The QR code needs the 'segno' package. Use Copy or "
                               f"Email instead:\n\n{url}", parent=master)
        return False
    import base64
    win = tk.Toplevel(master)
    win.title(title)
    win.transient(master.winfo_toplevel())
    win.resizable(False, False)
    body = ttk.Frame(win, padding=16)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=title, font=("Arial", 12, "bold")).pack()
    img = tk.PhotoImage(master=win, data=base64.b64encode(png).decode("ascii"))
    lbl = ttk.Label(body, image=img)
    lbl.image = img                                    # keep a reference
    lbl.pack(pady=8)
    ttk.Label(body, text="📱 Point your phone's camera at the code, then tap the link.",
              font=("Arial", 10, "bold")).pack()
    row = ttk.Frame(body)
    row.pack(pady=(8, 4))
    ent = ttk.Entry(row, width=46)
    ent.insert(0, url)
    ent.configure(state="readonly")
    ent.pack(side="left")
    note = ttk.Label(body, text="", foreground="#2e7d32")

    def copy():
        win.clipboard_clear()
        win.clipboard_append(url)
        note.config(text="✅ Link copied")
    ttk.Button(row, text="📋 Copy", command=copy).pack(side="left", padx=(6, 0))
    note.pack()
    ttk.Label(body, text=(caption + "\n" if caption else "") + PHONE_INSTALL_STEPS +
              "\nSign in with your Bearer Token — it is never in this code.",
              justify="left", foreground="#555").pack(anchor="w", pady=(6, 0))
    ttk.Button(body, text="Close", command=win.destroy).pack(pady=(10, 0))
    return True


def link_reachable(domain: str | None = None, timeout: int = 15) -> bool:
    """Does the secure link answer from the internet? (the public /pwa-token)"""
    d = tunnel_domain() if domain is None else domain
    if not d:
        return False
    import urllib.request
    try:
        req = urllib.request.Request(f"https://{d}/pwa-token", headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-Prowler-SetupCenter"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def detect_remote() -> Optional[bool]:
    """Phone access set up: a secure-link domain and a Bearer Token (fast —
    no network; the step's own window checks the link really answers)."""
    return bool(tunnel_domain() and bearer_token())


REMOTE_SEEN_PATH = Path.home() / ".ai-prowler" / "remote_app_seen.json"


def remote_seen_on_phone() -> bool:
    """Written by the server when the Remote app is used (ai_prowler_mcp /remote-api)."""
    try:
        return bool(json.loads(REMOTE_SEEN_PATH.read_text(encoding="utf-8")).get("phone_seen"))
    except (OSError, ValueError):
        return False


def detect_remote_pwa() -> Optional[bool]:
    return remote_seen_on_phone()


# ── Phase 5: Jobs app (business details · customers · the app on your phone) ─
def job_db_path() -> Path:
    """ai_prowler_jobs.db — always in AI-Prowler's state folder (~/.ai-prowler,
    or the test sandbox AIPROWLER_TEST_STATE_DIR), same rule as the server."""
    sd = os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
    return (Path(sd) if sd else Path.home() / ".ai-prowler") / "ai_prowler_jobs.db"


def read_settings(keys) -> dict:
    """Current values of Settings rows (read-only); missing → ''."""
    out = {k: "" for k in keys}
    p = job_db_path()
    if not p.exists():
        return out
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
        try:
            for k in keys:
                row = con.execute("SELECT value FROM settings WHERE key = ?", (k,)).fetchone()
                if row and row[0] is not None:
                    out[k] = str(row[0]).strip()
        finally:
            con.close()
    except Exception:
        pass
    return out


def customer_count() -> int:
    p = job_db_path()
    if not p.exists():
        return 0
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
        try:
            return int(con.execute("SELECT COUNT(*) FROM customers").fetchone()[0])
        finally:
            con.close()
    except Exception:
        return 0


# (Settings key, label, required) — the keys invoices/receipts already read
# (_read_business_info + Tax Rate).
BUSINESS_FIELDS = [
    ("Business Name", "Business name", True),
    ("Business Phone", "Phone", False),
    ("Business Email", "Email", False),
    ("Business Address", "Address (printed on invoices)", False),
    ("Tax Rate", "Sales tax rate (%)", False),
    ("Website", "Website", False),
    ("License / LLC Number", "License / LLC number", False),
]


def tax_to_store(text: str) -> str:
    """'7' / '7%' / '0.07' → '0.07' (the form invoices read). '' stays ''.
    Raises ValueError for anything that isn't a 0–100 % rate."""
    s = str(text).strip().rstrip("%").strip()
    if not s:
        return ""
    v = float(s)
    v = v if v < 1 else v / 100.0
    if not 0 <= v < 1:
        raise ValueError("tax rate must be between 0 and 100 %")
    return f"{v:.4f}".rstrip("0").rstrip(".") if v else "0"


def tax_to_show(stored: str) -> str:
    try:
        v = float(str(stored).strip().rstrip("%"))
    except ValueError:
        return str(stored)
    v = v * 100 if v <= 1 else v
    return f"{v:g}"


# CSV import: column name variants → Customers fields.
CSV_COLUMNS = {
    "Company Name": ("company", "company name", "business", "business name", "organization"),
    "First Name": ("first", "first name", "firstname", "given name"),
    "Last Name": ("last", "last name", "lastname", "surname", "family name"),
    "Phone": ("phone", "phone number", "mobile", "cell", "telephone"),
    "Email": ("email", "e-mail", "email address"),
    "Street Address": ("street", "street address", "address", "address 1", "address line 1"),
    "City": ("city", "town"),
    "State": ("state", "province", "region"),
    "ZIP": ("zip", "zip code", "postal code", "postcode"),
}


def parse_customers_csv(text: str) -> tuple[list[dict], int]:
    """(customers, skipped) from CSV text. A row is kept if it has a company
    or a first/last name. A single "Name"/"Full Name" column is split into
    first + last. Unknown columns are ignored."""
    import csv
    import io
    rdr = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    heads = {h: (h or "").strip().lower() for h in (rdr.fieldnames or [])}
    colmap = {}
    for field, aliases in CSV_COLUMNS.items():
        for h, low in heads.items():
            if low in aliases and h not in colmap:
                colmap[h] = field
                break
    full_name = next((h for h, low in heads.items() if low in ("name", "full name", "customer",
                                                               "customer name")), None)
    out, skipped = [], 0
    for row in rdr:
        c = {f: (row.get(h) or "").strip() for h, f in colmap.items() if (row.get(h) or "").strip()}
        if full_name and (row.get(full_name) or "").strip() and not (c.get("First Name") or c.get("Last Name")):
            parts = row[full_name].strip().split(None, 1)
            c["First Name"] = parts[0]
            if len(parts) > 1:
                c["Last Name"] = parts[1]
        if not (c.get("Company Name") or c.get("First Name") or c.get("Last Name")):
            skipped += 1
            continue
        c.setdefault("Status Active/Inactive", "Active")
        out.append(c)
    return out, skipped


def detect_jobs() -> Optional[bool]:
    """Jobs step green: phone app seen + business info (entered or skipped)
    + customers (entered or skipped). The phone section cannot be skipped.
    (David 2026-10-01)"""
    return jobs_seen_on_phone() and _jobs_biz_ok() and _jobs_cust_ok()


JOBS_SEEN_PATH = Path.home() / ".ai-prowler" / "jobs_app_seen.json"


def jobs_seen_on_phone() -> bool:
    try:
        return bool(json.loads(JOBS_SEEN_PATH.read_text(encoding="utf-8")).get("phone_seen"))
    except (OSError, ValueError):
        return False


JOBS_SKIPS_PATH = Path.home() / ".ai-prowler" / "jobs_section_skips.json"


def _jobs_skips() -> dict:
    """Which Jobs setup sections the user skipped: business info / customers."""
    try:
        d = json.loads(JOBS_SKIPS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        d = {}
    return {"business": bool(d.get("business")), "customers": bool(d.get("customers"))}


def _set_job_skip(section: str, value: bool) -> None:
    d = _jobs_skips()
    d[section] = bool(value)
    JOBS_SKIPS_PATH.parent.mkdir(parents=True, exist_ok=True)
    JOBS_SKIPS_PATH.write_text(json.dumps(d), encoding="utf-8")


def _jobs_biz_ok() -> bool:
    return bool(read_settings(["Business Name"])["Business Name"]) or _jobs_skips()["business"]


def _jobs_cust_ok() -> bool:
    return customer_count() > 0 or _jobs_skips()["customers"]


def _tool(name: str, **kw) -> str:
    """Call one of AI-Prowler's own tools as a plain function (the same way
    rag_gui.py does — filepath='' = the default job database)."""
    import inspect
    import ai_prowler_mcp as _mcp
    fn = getattr(_mcp, name)
    params = inspect.signature(fn).parameters
    if "ctx" in params and "ctx" not in kw:
        kw["ctx"] = None
    return str(fn(**kw))


def setting_exists(key: str) -> bool:
    p = job_db_path()
    if not p.exists():
        return False
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
        try:
            return con.execute("SELECT 1 FROM settings WHERE key = ? COLLATE NOCASE", (key,)).fetchone() is not None
        finally:
            con.close()
    except Exception:
        return False


def save_setting(key: str, value: str) -> str:
    """Update a Settings row, or create it if it doesn't exist yet (decided by
    looking, not by parsing an error message)."""
    if setting_exists(key):
        return _tool("update_job_spreadsheet", job_identifier=key, updates={"Value": value},
                     sheet_name="Settings", id_column="Setting")
    return _tool("create_setting", updates={"Setting": key, "Value": value})


def add_customer(fields: dict) -> str:
    return _tool("create_customer", updates=dict(fields))


# ── Phase 5: Payment links (Stripe · Square) ───────────────────────────────
# The Small Business tab's "Payment Links" section owns these settings (it keeps
# them in memory and saves config.json) — so the Setup Center only READS them,
# explains, opens that section, and makes a $1 test link with AI-Prowler's own
# checkout functions. It never writes them (no second copy that could clash).
PAYMENT_KEY_PAGES = [
    ("Stripe — API keys", "https://dashboard.stripe.com/apikeys"),
    ("Square — Developer apps (token + Location ID)", "https://developer.squareup.com/apps"),
]


def payment_status() -> dict:
    """What's configured (read-only, same config.json keys the server reads)."""
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        cfg = {}
    g = lambda k: str(cfg.get(k, "")).strip()
    stripe = "automatic" if g("stripe_secret_key") else ("fixed link" if g("stripe_payment_url") else "")
    square = ("automatic" if g("square_access_token") and g("square_location_id")
              else "fixed link" if g("square_payment_url") else
              "incomplete" if g("square_access_token") or g("square_location_id") else "")
    return {"stripe": stripe, "square": square,
            "email_on": bool(cfg.get("email_payment_link_enabled", True)),
            "sms_on": bool(cfg.get("sms_payment_link_enabled", False))}


def detect_payments() -> Optional[bool]:
    s = payment_status()
    return s["stripe"] in ("automatic", "fixed link") or s["square"] in ("automatic", "fixed link")


def make_test_payment_link(provider: str) -> str:
    """A real $1.00 checkout link in the user's own Stripe/Square account,
    made by AI-Prowler's own invoice functions (nothing is charged unless
    someone pays it). Returns the URL, or '' if it couldn't be made."""
    import ai_prowler_mcp as _mcp
    pay = _mcp._load_payment_settings()
    desc, ref = "AI-Prowler setup test ($1)", "SETUP-TEST"
    if provider == "stripe" and pay.get("stripe_secret_key"):
        return _mcp._create_stripe_checkout_url(pay["stripe_secret_key"], 1.00, desc, ref) or ""
    if provider == "square" and pay.get("square_access_token") and pay.get("square_location_id"):
        return _mcp._create_square_checkout_url(pay["square_access_token"], pay["square_location_id"],
                                                1.00, desc, ref) or ""
    return ""


# ── Phase 6: Crew routes (AI Route Optimizer) ──────────────────────────────
ROUTE_KEYS = ["Route Origin Mode", "Start/End Street Address", "Start/End City", "Start/End State",
              "Start/End ZIP", "Email Route On Build"]
ROUTE_MODES = ("Jobs Only", "Company Location")


def home_address() -> str:
    """The owner's home address (Settings tab → Home address; config.json
    owner_*), one line; '' if not set. Read-only — the Settings tab owns it."""
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return ""
    street, city = str(cfg.get("owner_street", "")).strip(), str(cfg.get("owner_city", "")).strip()
    state, zip_ = str(cfg.get("owner_state", "")).strip(), str(cfg.get("owner_zip", "")).strip()
    if not (street and city):
        return ""
    return ", ".join(p for p in (street, city, f"{state} {zip_}".strip()) if p)


def route_settings() -> dict:
    s = read_settings(ROUTE_KEYS)
    s["Route Origin Mode"] = s["Route Origin Mode"] or "Jobs Only"
    s["Email Route On Build"] = s["Email Route On Build"] or "Disabled"
    return s


def route_origin_ok(s: dict | None = None) -> tuple[bool, str]:
    """(ok, plain explanation) — is the address the chosen mode needs set?"""
    s = s or route_settings()
    if s["Route Origin Mode"] == "Company Location":
        if s["Start/End Street Address"] and s["Start/End City"]:
            return True, ("Company Location: every route starts and ends at " +
                          ", ".join(p for p in (s["Start/End Street Address"], s["Start/End City"],
                                                f"{s['Start/End State']} {s['Start/End ZIP']}".strip()) if p))
        return False, "Company Location needs a Start/End street address and city."
    home = home_address()
    if home:
        return True, f"Jobs Only: your jobs in order; mileage counts from your home address ({home})."
    return False, "Jobs Only needs your home address (Settings tab → Home address) for mileage."


def detect_routes() -> Optional[bool]:
    return route_origin_ok()[0]


def ai_routing_status() -> dict:
    """{'cli': bool, 'token': status, 'detail': str} — Claude Code installed?
    token from Links & Analysis → Get / Renew Token ok? (task_queue_automation's
    own checks; read-only)."""
    try:
        import task_queue_automation as tqa
        cli = bool(tqa.claude_code_cli_installed())
        tok = tqa.check_token_expiry()
        return {"cli": cli, "token": tok.get("status", "unknown"), "detail": tok.get("detail", "")}
    except Exception as e:
        return {"cli": False, "token": "unknown", "detail": str(e)}


# ── "Index your first folder": the User Guide as the first document ────────
GUIDE_NAME = "COMPLETE_USER_GUIDE.md"


def guide_candidates() -> list[Path]:
    """Where the User Guide lives — the indexed copy in Documents\\AI-Prowler
    (update_install.bat keeps it there) first, then the installed copy."""
    return [Path.home() / "Documents" / "AI-Prowler" / GUIDE_NAME,
            Path(__file__).resolve().parent / GUIDE_NAME]


def find_user_guide() -> Optional[Path]:
    return next((p for p in guide_candidates() if p.is_file()), None)


def _norm(p) -> str:
    return os.path.normcase(os.path.normpath(str(p))).rstrip("\\/")


def is_tracked(path) -> bool:
    """True if `path` is tracked itself or sits inside a tracked folder."""
    target = _norm(path)
    for t in _tracked_paths():
        tn = _norm(t)
        if target == tn or target.startswith(tn + os.sep):
            return True
    return False


def ocr_summary(info: dict) -> tuple[str, str]:
    """(state, plain message) from rag_gui's _check_ocr_ready() result.
    state: 'ready' | 'partial' (runs, a language pack is missing) | 'missing'."""
    if not info or not info.get("ready"):
        return "missing", (info or {}).get("detail") or "OCR (Tesseract) is not installed"
    if info.get("missing_langs"):
        return "partial", info.get("detail") or "OCR is missing a language pack"
    return "ready", info.get("detail") or "OCR ready"


# ── "Connect your AI": Claude · Grok · Muse (David 2026-09-30) ──────────────
CONNECTOR_NAME = "AI-Prowler Local"
CONFIG_PATH = Path.home() / ".ai-prowler" / "config.json"


def tunnel_domain() -> str:
    """The user's secure-link domain (set by ⚡ Configure Mobile Access), bare
    host only; '' if phone access isn't set up yet."""
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return ""
    d = str(cfg.get("tunnel_domain", "")).strip()
    return d.replace("https://", "").replace("http://", "").strip("/")


def mcp_url(domain: str | None = None) -> str:
    d = tunnel_domain() if domain is None else domain
    return f"https://{d}/mcp" if d else ""


def connect_page_url(domain: str | None = None) -> str:
    d = tunnel_domain() if domain is None else domain
    return f"https://{d}/connect" if d else ""


# Each AI: where its connector is added, and the steps. Grok is just like
# Claude (URL → name → Bearer). Muse HAS a connector menu, but it doesn't work
# with AI-Prowler yet, so for now you give Muse the URL + Bearer Token in a
# message and it connects itself (David 2026-09-30) — only this entry changes
# when Muse's menu starts working.
AI_APPS = [
    {"id": "claude", "name": "Claude", "icon": "🟠",
     "connect_url": "https://claude.ai/customize/connectors?modal=add-custom-connector",
     "get_url": "https://claude.ai",
     "apps": "Claude app: App Store / Google Play (optional) · Claude Desktop for Windows (optional)",
     "steps": ["Paste the URL into “Remote MCP server URL”",
               f"Name it “{CONNECTOR_NAME}”",
               "Leave the OAuth fields blank → Add",
               "Sign in with your Bearer Token when asked",
               "Set “Always allow” for the tools",
               "Added once on claude.ai → it's in the Claude phone app too"]},
    {"id": "grok", "name": "Grok", "icon": "⚫",
     "connect_url": "https://grok.com/connectors",
     "get_url": "https://grok.com",
     "apps": "Grok app: App Store / Google Play (optional) — nothing to install on the PC",
     "steps": ["New Connector → Custom",
               f"Name it “{CONNECTOR_NAME}”",
               "Paste the URL as the server URL → Add Connector",
               "Sign in with your Bearer Token when asked"]},
    {"id": "muse", "name": "Muse", "icon": "🔵",
     "connect_url": "https://muse.ai",
     "get_url": "https://muse.ai",
     "apps": "Muse app: App Store / Google Play, the web, or WhatsApp — nothing to install on the PC "
             "(U.S. only for now; sign-up asks for a payment card, even for the free plan)",
     "message": True,
     "steps": ["Muse's connector menu doesn't work with AI-Prowler yet — use a message instead:",
               "Copy the message below and send it to Muse",
               "When Muse asks, give it your Bearer Token",
               "Muse connects itself and saves it as a skill"],
     "caution": "Your Bearer Token is the password to your whole AI-Prowler. If you stop using "
                "Muse, change the token on the Settings tab."},
]
AI_BY_ID = {a["id"]: a for a in AI_APPS}


def muse_message(url: str) -> str:
    return (f"Please connect to my AI-Prowler MCP server at {url} and name the connection "
            f"\"{CONNECTOR_NAME}\". It uses a Bearer Token for sign-in — ask me for it.")


def email_link(url: str, to: str = "") -> str:
    """mailto: link that opens the user's own mail app with the connector URL,
    so they can send it to themselves (or their phone). No token, ever."""
    from urllib.parse import quote
    subject = "My AI-Prowler connector link"
    body = (f"My AI-Prowler connector URL:\n\n{url}\n\n"
            f"Add it as a custom connector in Claude, Grok or Muse and name it \"{CONNECTOR_NAME}\".\n"
            "Sign in with your Bearer Token when asked (it's on the AI-Prowler Settings tab — "
            "it is NOT in this email).\n")
    return f"mailto:{quote(to)}?subject={quote(subject)}&body={quote(body)}"


def qr_png(data: str, scale: int = 6) -> Optional[bytes]:
    """PNG bytes of a QR code for `data`, or None if segno isn't installed."""
    if not data:
        return None
    try:
        import io
        import segno
    except ImportError:
        return None
    buf = io.BytesIO()
    segno.make(data, error="m").save(buf, kind="png", scale=scale, border=3,
                                     dark="#111111", light="#ffffff")
    return buf.getvalue()


def open_ai_connector(root, ai_id: str, domain: str | None = None) -> bool:
    """The desktop "Connect <AI> (auto)" action — shared by the Settings tab's
    buttons and the Setup Center, so both always behave the same:
    copy the connector URL (for Muse: the ready-made message) to the clipboard,
    show the steps, then open that AI's connector page. Returns False (after
    telling the user why) if phone access isn't set up yet."""
    import webbrowser
    from tkinter import messagebox
    a = AI_BY_ID[ai_id]
    url = mcp_url(domain)
    if not url:
        messagebox.showwarning(
            "Set up phone access first",
            f"{a['name']} connects to AI-Prowler over the internet, through your secure link.\n\n"
            "Activate your subscription and click ⚡ Configure Mobile Access on the Settings tab "
            "first, then try again." +
            ("\n\n(Claude Desktop on this PC can connect without it.)" if ai_id == "claude" else ""),
            parent=root)
        return False
    to_copy = muse_message(url) if a.get("message") else url
    try:
        root.clipboard_clear()
        root.clipboard_append(to_copy)
        root.update()
    except Exception:
        pass
    what = "A ready-made message (with your URL)" if a.get("message") else "Your connector URL"
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(a["steps"], 1))
    caution = f"\n\n⚠️ {a['caution']}" if a.get("caution") else ""
    messagebox.showinfo(
        f"Connect {a['name']} to AI-Prowler",
        f"{what} has been copied to the clipboard:\n\n  {to_copy}\n\n"
        f"Click OK and {a['name']} will open.\n\n{steps}{caution}", parent=root)
    webbrowser.open(a["connect_url"])
    return True


def connect_page_html(url: str) -> str:
    """The phone page served at /connect (ai_prowler_mcp.py, personal mode).
    Shows ONLY the connector URL — never the Bearer Token (the page needs no
    sign-in, so anything on it is visible to anyone with the link)."""
    import html as _h
    u = _h.escape(url, quote=True)
    cards = []
    for a in AI_APPS:
        steps = "".join(f"<li>{_h.escape(s)}</li>" for s in a["steps"])
        extra = ""
        if a.get("message"):
            msg = _h.escape(muse_message(url), quote=True)
            extra = (f'<textarea readonly id="msg-{a["id"]}">{msg}</textarea>'
                     f'<button onclick="cp(\'msg-{a["id"]}\', this)">📋 Copy message</button>')
        caution = f'<p class="warn">⚠️ {_h.escape(a["caution"])}</p>' if a.get("caution") else ""
        cards.append(
            f'<section><h2>{a["icon"]} {_h.escape(a["name"])}</h2><ol>{steps}</ol>{extra}{caution}'
            f'<a class="go" href="{_h.escape(a["connect_url"], quote=True)}" '
            f'onclick="cpText(\'{u}\')" target="_blank" rel="noopener">'
            f'Copy URL &amp; open {_h.escape(a["name"])} →</a>'
            f'<p class="small">{_h.escape(a["apps"])}</p></section>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Connect your AI to AI-Prowler</title>
<style>
:root{{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--card:#f4f5f7;--acc:#0a66c2;--dim:#666}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111;--fg:#eee;--card:#1d1f23;--acc:#4ea3ff;--dim:#aaa}}}}
body{{margin:0;padding:16px;font:16px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:560px;margin:0 auto}}h1{{font-size:22px}}h2{{font-size:18px;margin:0 0 6px}}
section,.url{{background:var(--card);border-radius:12px;padding:14px;margin:12px 0}}
code{{display:block;word-break:break-all;font-size:15px;margin:6px 0 10px}}
button,.go{{display:inline-block;min-height:44px;padding:10px 14px;border-radius:10px;border:0;
background:var(--acc);color:#fff;font-size:16px;text-decoration:none;margin:4px 6px 4px 0;cursor:pointer}}
textarea{{width:100%;box-sizing:border-box;min-height:84px;font:inherit;border-radius:8px;padding:8px}}
.small{{color:var(--dim);font-size:13px}}.warn{{font-size:14px}}ol{{padding-left:20px}}
</style></head><body><main>
<h1>Connect your AI to AI-Prowler</h1>
<p class="small">Add AI-Prowler as a custom connector in Claude, Grok or Muse. Your Bearer Token is
<b>not</b> on this page — you'll type it (or paste it from your password manager) when your AI asks.</p>
<div class="url"><b>Your connector URL</b><code id="url">{u}</code>
<button onclick="cp('url', this)">📋 Copy URL</button>
<a class="go" href="{_h.escape(email_link(url), quote=True)}">📧 Email it to me</a>
<p class="small">Name the connection <b>{_h.escape(CONNECTOR_NAME)}</b>.</p></div>
{''.join(cards)}
</main><script>
function cpText(t){{try{{navigator.clipboard.writeText(t)}}catch(e){{}}}}
function cp(id,b){{var el=document.getElementById(id);var t=el.value||el.textContent;
cpText(t);var o=b.textContent;b.textContent='✅ Copied';setTimeout(function(){{b.textContent=o}},1500)}}
</script></body></html>"""


# ── the modules ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Module:
    id: str
    title: str
    minutes: int
    why: str
    tab: str = ""                         # the real tab where this is set up (Phase 1 target)
    requires: tuple = ()
    info_only: bool = False               # M12: nothing to set up
    detect: Optional[Callable[[], Optional[bool]]] = None   # None / returns None = can't tell yet


MODULES: list[Module] = [
    # Order (David 2026-09-30): Index your first folder FIRST, Connect your AI second.
    Module("index", "Index your first folder", 3,
           "Indexing lets your AI read and answer questions about your own documents — privately, "
           "from your PC. We'll check OCR (reading text in scanned PDFs and photos), repair it if "
           "needed, and index the AI-Prowler User Guide as your first document.",
           tab="📚 Index Docs", detect=detect_indexed),
    Module("connect_ai", "Connect your AI (Claude, Grok, Muse)", 5,
           "AI-Prowler is the memory; your AI app is the brain that reads it. "
           "Connect the AI you use — on your computer and your phone.",
           tab="⚙️ Settings"),
    Module("auto_index", "Keep your index up to date", 1,
           "New and changed files are picked up automatically — right away while AI-Prowler runs "
           "(File Watchdog), and with a nightly catch-up that runs even when it's closed.",
           tab="⏰ Schedule", requires=("index",), detect=detect_auto_index),
    Module("links", "Scheduled AI analyses (Links & Analysis)", 5,
           "Your AI can review things for you on a schedule — overdue invoices, a weekly summary — "
           "and save or email the result.", tab="🔗 Links & Analysis", requires=("index",),
           detect=detect_links),
    Module("learnings", "Teach AI-Prowler (Learnings)", 2,
           "Learnings are facts and preferences your AI should always remember.",
           tab="🧠 Learnings", detect=detect_learnings),
    Module("email", "Email", 3,
           "Lets AI-Prowler send reports, invoices and alerts.", tab="⚙️ Settings",
           detect=detect_email),
    Module("remote", "Phone access (secure link, power settings)", 10,
           "Reach your AI-Prowler — and your AI apps' connection to it — from your phone, anywhere. "
           "Your PC stays on and awake to answer.", tab="⚙️ Settings", detect=detect_remote),
    Module("remote_pwa", "Remote app on your phone", 3,
           "Browse, download and search your files, and manage learnings and tasks, from your phone.",
           tab="⚙️ Settings", requires=("remote",), detect=detect_remote_pwa),
    Module("jobs", "Jobs app (customers, jobs, invoices)", 10,
           "Track customers, jobs, quotes and invoices; your crew uses the Jobs app on their phones.",
           tab="🏢 Small Business", requires=("remote",), detect=detect_jobs),
    Module("payments", "Payment links", 5,
           "Customers pay invoices by card from a link in the email or text.",
           tab="🏢 Small Business", requires=("jobs", "email"), detect=detect_payments),
    Module("routes", "Crew routes (AI Route Optimizer)", 5,
           "AI plans the day's route across jobs — respecting fixed appointment times — and sends the "
           "crew a tap-to-navigate link.", tab="🏢 Small Business", requires=("jobs",),
           detect=detect_routes),
    Module("server_info", "About AI-Prowler Server (for teams)", 1,
           "One shared AI-Prowler for a whole company — shared knowledge, one job list for every "
           "crew, roles and per-person privacy. It runs on its own server box and is installed by "
           "the AI-Prowler IT team — there's nothing to set up here.", info_only=True),
]
BY_ID = {m.id: m for m in MODULES}

# "What do you want AI-Prowler to do?" → modules (dependencies are added on top)
SERVICES: list[tuple[str, str, tuple]] = [
    ("files",    "🔎 Ask questions about my own files",            ("connect_ai", "index", "auto_index", "learnings")),
    ("analyses", "🤖 Have AI review things for me on a schedule",  ("links",)),
    ("email",    "✉️ Send emails and reports",                     ("email",)),
    ("phone",    "📱 Use AI-Prowler from my phone",                ("remote", "remote_pwa")),
    ("business", "🧰 Run my service business (jobs, invoices)",    ("jobs", "payments")),
    ("routes",   "🚚 Plan routes for my crew",                     ("routes",)),
    ("team",     "🏢 A shared AI-Prowler for my whole team",       ("server_info",)),
]
SERVICE_IDS = [s[0] for s in SERVICES]
DEFAULT_SERVICES = ["files"]


def modules_for(services) -> list[Module]:
    """Modules for the chosen services + everything they require, in the
    spec's order (MODULES order)."""
    wanted: set[str] = set()
    for sid, _label, mods in SERVICES:
        if sid in services:
            wanted.update(mods)
    stack = list(wanted)
    while stack:                                   # pull in requirements
        for req in BY_ID[stack.pop()].requires:
            if req not in wanted:
                wanted.add(req)
                stack.append(req)
    return [m for m in MODULES if m.id in wanted]


def added_by_requirement(services) -> list[str]:
    """Module ids that are in the plan only because another needs them."""
    direct = {mid for sid, _l, mods in SERVICES if sid in services for mid in mods}
    return [m.id for m in modules_for(services) if m.id not in direct]


# ── progress (~/.ai-prowler/setup_progress.json) ────────────────────────────
# "Partly done" — read from the real settings, for steps where half-way is a
# real state (David 2026-10-01: yellow = partly done).
def _partial_jobs() -> bool:
    return _jobs_biz_ok() != _jobs_cust_ok()


def _partial_remote() -> bool:
    return bool(tunnel_domain()) != bool(bearer_token())


def _partial_payments() -> bool:
    return payment_status()["square"] == "incomplete"


def _partial_routes() -> bool:
    s = route_settings()
    return (s["Route Origin Mode"] == "Company Location"
            and bool(s["Start/End Street Address"]) != bool(s["Start/End City"]))


PARTIAL = {"jobs": _partial_jobs, "remote": _partial_remote,
           "payments": _partial_payments, "routes": _partial_routes}

# Lights (David 2026-10-01) — all based ONLY on the steps the user's
# "What do you want AI-Prowler to do?" choices put in their plan.
GREEN, YELLOW, RED, GREY = "green", "yellow", "red", "grey"
LIGHT_COLOR = {GREEN: "#2e7d32", YELLOW: "#f9a825", RED: "#c62828", GREY: "#9e9e9e"}
LIGHT_WORD = {GREEN: "done", YELLOW: "partly done", RED: "not done", GREY: "skipped"}

# The "core" steps for the overall light: the modules the "Ask questions about
# my own files" choice puts in your plan. The red light is reserved for these —
# and only when YOU chose them directly, never when they were pulled in as
# another step's requirement. Everything else in the plan is yellow until done.
CORE_IDS = frozenset(next(mods for _sid, _label, mods in SERVICES if _sid == "files"))


def chosen_module_ids(services) -> set[str]:
    """Module ids the user's choices name directly, before requirements are
    pulled in on top (see modules_for)."""
    return {mid for sid, _label, mods in SERVICES if sid in services for mid in mods}


@dataclass
class Progress:
    services: list = field(default_factory=list)
    states: dict = field(default_factory=dict)       # module id -> state
    picked: bool = False                             # has the user answered the picker?
    collapsed: Optional[bool] = None                 # panel folded? None = not chosen yet
    path: Path = PROGRESS_PATH

    @classmethod
    def load(cls, path: Path = PROGRESS_PATH) -> "Progress":
        try:
            d = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls(path=Path(path))
        services = [s for s in d.get("services", []) if s in SERVICE_IDS]
        states = {k: v for k, v in (d.get("states") or {}).items()
                  if k in BY_ID and v in (NOT_STARTED, IN_PROGRESS, DONE, SKIPPED)}
        col = d.get("collapsed")
        return cls(services=services, states=states, picked=bool(d.get("picked")),
                   collapsed=col if isinstance(col, bool) else None, path=Path(path))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": PROGRESS_VERSION, "services": self.services,
                                   "states": self.states, "picked": self.picked,
                                   "collapsed": self.collapsed}, indent=2),
                       encoding="utf-8")
        os.replace(tmp, self.path)

    # ── lights ──────────────────────────────────────────────────────────────
    def light(self, m: "Module") -> str:
        """🟢 done · 🟡 partly done (started, or half-configured) · 🔴 not done · ⚪ skipped."""
        st = self.state(m)
        if st == DONE:
            return GREEN
        if st == SKIPPED:
            return GREY
        part = PARTIAL.get(m.id)
        try:
            half = bool(part()) if part else False
        except Exception:
            half = False
        return YELLOW if (st == IN_PROGRESS or half) else RED

    def overall_light(self) -> str:
        """Only the steps your "What do you want AI-Prowler to do?" choices put
        in your plan count — and the red light is only for chosen CORE steps:
        🔴 a directly-chosen core step (Index your first folder, Connect your
        AI, Keep your index up to date, Teach AI-Prowler) isn't done · 🟡 those
        are done but another plan step isn't — a requirement pulled in on top
        (phone access, the Jobs app, Email) or a chosen non-core step (crew
        routes, scheduled analyses) · 🟢 every plan step is done. Skipped
        counts as decided (not red). Steps you didn't choose never turn
        anything red."""
        services = self.services or DEFAULT_SERVICES
        direct = chosen_module_ids(services)
        plan = [m for m in self.plan() if not m.info_only]
        finished = lambda m: self.state(m) in (DONE, SKIPPED)
        if any(not finished(m) for m in plan if m.id in CORE_IDS and m.id in direct):
            return RED
        if any(not finished(m) for m in plan):
            return YELLOW
        return GREEN

    def is_collapsed(self) -> bool:
        """The user's own choice if they made one; otherwise folded once every
        chosen step is finished, open while there's still something to do."""
        return self.collapsed if self.collapsed is not None else self.all_finished()

    def set_collapsed(self, value: bool) -> None:
        self.collapsed = bool(value)
        self.save()

    # the state shown for a module: detected-done beats anything saved
    def state(self, m: Module) -> str:
        if m.detect is not None:
            try:
                if m.detect():
                    return DONE
            except Exception:
                pass
        return self.states.get(m.id, NOT_STARTED)

    def set_state(self, mid: str, state: str) -> None:
        self.states[mid] = state
        self.save()

    def choose(self, services) -> None:
        self.services = [s for s in SERVICE_IDS if s in services]
        self.picked = True
        self.save()

    def add_service(self, sid: str) -> None:
        if sid not in self.services:
            self.choose(self.services + [sid])

    def plan(self) -> list[Module]:
        return modules_for(self.services or DEFAULT_SERVICES)

    def counts(self) -> tuple[int, int]:
        """(finished, total) — skipped counts as finished; info-only cards don't count."""
        plan = [m for m in self.plan() if not m.info_only]
        return sum(1 for m in plan if self.state(m) in (DONE, SKIPPED)), len(plan)

    def all_finished(self) -> bool:
        done, total = self.counts()
        return total > 0 and done == total


def is_first_launch(progress: Progress) -> bool:
    """Open the picker automatically only for a genuinely new user."""
    return not progress.picked and not _tracked_paths()


# ── the Home-page panel (Tk) ────────────────────────────────────────────────
STATE_ICON = {DONE: "✅", SKIPPED: "⏭", IN_PROGRESS: "🟡", NOT_STARTED: "⬜"}


class SetupCenterPanel:
    """🧭 Set up AI-Prowler — lives on the Home tab (SETUP_CENTER_SPEC §4)."""

    def __init__(self, parent, app, progress: Progress | None = None):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk = tk, ttk
        self.app = app                                   # the main GUI (for notebook / tabs)
        self.progress = progress or Progress.load()
        # Plain frame: the header row inside it carries the title, the fold
        # arrow and the overall light (David 2026-10-01: collapsible).
        self.frame = ttk.LabelFrame(parent, text="", padding=(14, 8))
        self.frame.pack(fill="x", pady=(0, 12))
        self.render()
        if is_first_launch(self.progress):
            self.frame.after(600, self.open_picker)

    @property
    def expanded(self) -> bool:
        return not self.progress.is_collapsed()

    # ── drawing ─────────────────────────────────────────────────────────────
    def _dot(self, parent, light: str, size: int = 12):
        """A coloured ● (green / yellow / red / grey)."""
        lbl = self.tk.Label(parent, text="●", fg=LIGHT_COLOR[light], font=("Arial", size),
                            bd=0, padx=0, pady=0)
        try:
            lbl.configure(bg=self.ttk.Style().lookup("TFrame", "background") or lbl.cget("bg"))
        except Exception:
            pass
        return lbl

    def render(self):
        tk, ttk = self.tk, self.ttk
        # Clear the panel's own rows only — the step windows (Toplevels) are
        # children of this frame too, and destroying them here would close a
        # step window the moment it finished (and hide its confirmation).
        for w in self.frame.winfo_children():
            if not isinstance(w, tk.Toplevel):
                w.destroy()
        done, total = self.progress.counts()
        overall = self.progress.overall_light()
        open_ = self.expanded

        # header — always visible: fold arrow · title · light · count
        head = ttk.Frame(self.frame)
        head.pack(fill="x")
        self.toggle_btn = ttk.Button(head, text=("▾" if open_ else "▸") + " 🧭 Set up AI-Prowler",
                                     command=lambda: self._toggle(not self.expanded))
        self.toggle_btn.pack(side="left")
        self.light_lbl = self._dot(head, overall, size=16)
        self.light_lbl.pack(side="left", padx=(8, 2))
        self.count_lbl = ttk.Label(head, text=f"{done} of {total} done  ({LIGHT_WORD[overall]})"
                                   if overall != GREEN else f"{done} of {total} done — all set")
        self.count_lbl.pack(side="left", padx=(2, 0))
        if not open_:
            ttk.Button(head, text="➕ Add a service", command=self.open_picker).pack(side="right")
            return
        ttk.Button(head, text="Change my choices", command=self.open_picker).pack(side="right")

        leg = ttk.Frame(self.frame)
        leg.pack(anchor="w", pady=(4, 0))
        ttk.Label(leg, text="Based on what you chose AI-Prowler to do: ", foreground="#777",
                  font=("Arial", 8)).pack(side="left")
        for lt in (GREEN, YELLOW, RED, GREY):
            self._dot(leg, lt, size=9).pack(side="left")
            ttk.Label(leg, text=LIGHT_WORD[lt] + "   ", foreground="#777", font=("Arial", 8)).pack(side="left")

        rows = ttk.Frame(self.frame)
        rows.pack(fill="x", pady=(6, 4))
        for m in self.progress.plan():
            self._row(rows, m)

        more = [s for s in SERVICES if s[0] not in self.progress.services]
        if more:
            bar = ttk.Frame(self.frame)
            bar.pack(fill="x", pady=(8, 0))
            ttk.Label(bar, text="➕ Add more:", font=("Arial", 9, "bold")).pack(side="left", padx=(0, 6))
            for sid, label, _mods in more:
                ttk.Button(bar, text=label, command=lambda s=sid: self._add(s)).pack(side="left", padx=2)

    def _row(self, parent, m: Module):
        ttk = self.ttk
        st = self.progress.state(m)
        r = ttk.Frame(parent)
        r.pack(fill="x", pady=2)
        if m.info_only:
            ttk.Label(r, text="ℹ️", width=3).pack(side="left")
        else:
            lt = self.progress.light(m)
            dot = self._dot(r, lt, size=12)
            dot.pack(side="left", padx=(2, 8))
            r.light = lt                                   # for tests / screen readers
        ttk.Label(r, text=m.title, font=("Arial", 10)).pack(side="left")
        ttk.Label(r, text=f"≈ {m.minutes} min", foreground="#888").pack(side="left", padx=8)
        if not m.info_only and self.progress.light(m) == YELLOW:
            ttk.Label(r, text="partly done", foreground=LIGHT_COLOR[YELLOW]).pack(side="left")
        if m.info_only:
            ttk.Button(r, text="Learn more", command=lambda: self.show_info(m)).pack(side="right")
            return
        if st == DONE:
            ttk.Button(r, text="Open this tab", command=lambda: self.open_tab(m)).pack(side="right")
            if m.id in GUIDED:
                ttk.Button(r, text="Check again", command=lambda: self.start(m)
                           ).pack(side="right", padx=(0, 4))
        elif st == SKIPPED:
            ttk.Button(r, text="Undo skip", command=lambda: self._set(m, NOT_STARTED)).pack(side="right")
        else:
            ttk.Button(r, text="Skip", command=lambda: self._set(m, SKIPPED)).pack(side="right", padx=(4, 0))
            ttk.Button(r, text="Continue" if st == IN_PROGRESS else "Start",
                       command=lambda: self.start(m)).pack(side="right")

    # ── actions ─────────────────────────────────────────────────────────────
    def _toggle(self, expanded: bool):
        self.progress.set_collapsed(not expanded)          # remembered between sessions
        self.render()

    def _set(self, m: Module, state: str):
        self.progress.set_state(m.id, state)
        self.render()

    def _add(self, sid: str):
        self.progress.add_service(sid)
        self.progress.set_collapsed(False)
        self.render()

    def start(self, m: Module):
        """Guided modules open their own step-by-step window; the rest (until
        their phase is built) take the user to the real tab."""
        if self.progress.state(m) == NOT_STARTED:
            self.progress.set_state(m.id, IN_PROGRESS)
        self.render()
        flow = GUIDED.get(m.id)
        if flow is not None:
            flow(self)
            return
        self.open_tab(m, why=True)

    def open_tab(self, m: Module, why: bool = False):
        from tkinter import messagebox
        nb = getattr(self.app, "notebook", None)
        target = None
        if nb is not None and m.tab:
            for t in nb.tabs():
                if nb.tab(t, "text").strip() == m.tab:
                    target = t
                    break
        if why:
            messagebox.showinfo(m.title, f"{m.why}\n\n"
                                f"This is set up on the {m.tab} tab — taking you there now.\n"
                                "Step-by-step guidance for this step is coming in a later update.",
                                parent=self.frame)
        if target is not None:
            nb.select(target)

    def show_info(self, m: Module):
        from tkinter import messagebox
        import webbrowser
        if messagebox.askyesno(m.title, m.why + "\n\nYour Personal AI-Prowler keeps working alongside it — "
                               "your AI app can connect to both (\"AI-Prowler Local\" and "
                               "\"AI-Prowler Server\").\n\nOpen the AI-Prowler website to learn more?",
                               parent=self.frame):
            webbrowser.open(SERVER_INFO_URL)

    def open_picker(self):
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.frame)
        win.title("What do you want AI-Prowler to do?")
        win.transient(self.frame.winfo_toplevel())
        win.resizable(False, False)
        body = ttk.Frame(win, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="What do you want AI-Prowler to do?", font=("Arial", 12, "bold")).pack(anchor="w")
        ttk.Label(body, text="Tick everything you're interested in — you can change this any time.",
                  foreground="#666").pack(anchor="w", pady=(2, 10))
        current = set(self.progress.services or DEFAULT_SERVICES)
        vars_ = {}
        for sid, label, _mods in SERVICES:
            v = tk.BooleanVar(master=win, value=sid in current)
            vars_[sid] = v
            ttk.Checkbutton(body, text=label, variable=v).pack(anchor="w", pady=2)
        note = ttk.Label(body, text="", foreground="#666", wraplength=420, justify="left")
        note.pack(anchor="w", pady=(10, 0))

        def refresh_note(*_):
            chosen = [s for s, v in vars_.items() if v.get()]
            extra = added_by_requirement(chosen)
            note.config(text=("Also added because they're needed: " +
                              ", ".join(BY_ID[x].title for x in extra)) if extra else "")
        for v in vars_.values():
            v.trace_add("write", refresh_note)
        refresh_note()

        btns = ttk.Frame(body)
        btns.pack(fill="x", pady=(14, 0))

        def save():
            chosen = [s for s, v in vars_.items() if v.get()] or list(DEFAULT_SERVICES)
            self.progress.choose(chosen)
            self.progress.set_collapsed(False)              # show what they just chose
            win.destroy()
            self.render()
        ttk.Button(btns, text="Save", command=save).pack(side="right")
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side="right", padx=6)
        win.grab_set()


class IndexFirstFolderFlow:
    """Guided "Index your first folder" (David 2026-09-30):
      1. Check OCR with the app's own _check_ocr_ready(); if it isn't fully
         installed, self-repair with the app's own _install_or_repair_ocr()
         and wait until it reports ready.
      2. Index the AI-Prowler User Guide through the Index Docs tab's own queue
         + ▶ Start (same worker, same single database writer, and the worker
         adds it to the tracked list itself).
      3. "Try it" — a question to ask your AI.
    Everything runs in the background; the window just shows progress."""

    OCR_WAIT_SECONDS = 600
    POLL_MS = 3000

    def __init__(self, panel: "SetupCenterPanel"):
        import tkinter as tk
        from tkinter import ttk
        self.panel, self.app = panel, panel.app
        self.tk, self.ttk = tk, ttk
        self.win = tk.Toplevel(panel.frame)
        self.win.title("Index your first folder")
        self.win.transient(panel.frame.winfo_toplevel())
        self.win.resizable(False, False)
        body = ttk.Frame(self.win, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Index your first folder", font=("Arial", 12, "bold")).pack(anchor="w")
        ttk.Label(body, text=BY_ID["index"].why, wraplength=460, justify="left",
                  foreground="#555").pack(anchor="w", pady=(4, 12))
        self.rows = {}
        for key, label in (("ocr", "1. Check OCR (reads text in scanned PDFs and photos)"),
                           ("guide", "2. Index the AI-Prowler User Guide as your first document"),
                           ("try", "3. Try it with your AI")):
            r = ttk.Frame(body)
            r.pack(fill="x", pady=3)
            icon = ttk.Label(r, text="⬜", width=3)
            icon.pack(side="left")
            ttk.Label(r, text=label, font=("Arial", 10)).pack(side="left")
            msg = ttk.Label(body, text="", foreground="#666", wraplength=440, justify="left")
            msg.pack(anchor="w", padx=(30, 0))
            self.rows[key] = (icon, msg)
        self.btns = ttk.Frame(body)
        self.btns.pack(fill="x", pady=(14, 0))
        self.close_btn = ttk.Button(self.btns, text="Close", command=self.win.destroy)
        self.close_btn.pack(side="right")
        self._ocr_deadline = 0.0
        self.win.after(200, self.check_ocr)

    # ── helpers ─────────────────────────────────────────────────────────────
    def _set(self, key, icon, msg=""):
        try:
            i, m = self.rows[key]
            i.config(text=icon)
            m.config(text=msg)
        except self.tk.TclError:
            pass                                       # window was closed

    def _alive(self) -> bool:
        try:
            return bool(self.win.winfo_exists())
        except self.tk.TclError:
            return False

    def _in_thread(self, fn, then):
        """Run fn() in the background; call then(result) on the Tk thread.
        The worker never touches Tk (calling Tk from another thread hangs
        unless the full mainloop is running) — it only fills a slot, and the
        window collects it on its own thread."""
        import threading
        box = {}

        def work():
            try:
                box["r"] = fn()
            except Exception as e:                     # pragma: no cover — defensive
                box["r"] = e

        def collect():
            if not self._alive():
                return
            if "r" in box:
                then(box["r"])
            else:
                self.win.after(50, collect)
        threading.Thread(target=work, daemon=True).start()
        self.win.after(50, collect)

    # ── step 1: OCR check + self-repair ─────────────────────────────────────
    def check_ocr(self):
        if not hasattr(self.app, "_check_ocr_ready"):
            self._set("ocr", "⚠️", "OCR check isn't available in this version — skipping.")
            return self.index_guide()
        self._set("ocr", "🔄", "Checking…")
        self._in_thread(self.app._check_ocr_ready, self._ocr_checked)

    def _ocr_checked(self, info):
        if not self._alive():
            return
        state, msg = ocr_summary(info if isinstance(info, dict) else {})
        if state == "ready":
            self._set("ocr", "✅", msg)
            return self.index_guide()
        if not hasattr(self.app, "_install_or_repair_ocr"):
            self._set("ocr", "⚠️", msg + " — repair isn't available here; continuing.")
            return self.index_guide()
        import time
        self._set("ocr", "🔧", f"{msg}. Repairing now (downloads OCR, about 50 MB) — "
                              "progress shows on the Index Docs tab's output…")
        try:
            self.app._install_or_repair_ocr()          # runs in its own background thread
        except Exception as e:
            self._set("ocr", "⚠️", f"Couldn't start the OCR repair ({e}) — continuing without it.")
            return self.index_guide()
        self._ocr_deadline = time.time() + self.OCR_WAIT_SECONDS
        self.win.after(self.POLL_MS, self._poll_ocr)

    def _poll_ocr(self):
        import time
        if not self._alive():
            return

        def done(info):
            if not self._alive():
                return
            state, msg = ocr_summary(info if isinstance(info, dict) else {})
            if state == "ready":
                self._set("ocr", "✅", "Repaired — " + msg)
                return self.index_guide()
            if time.time() > self._ocr_deadline:
                self._set("ocr", "⚠️", "The OCR repair hasn't finished. Text files still index fine; "
                                       "use Install / Repair OCR on the Index Docs tab to retry.")
                return self.index_guide()
            self.win.after(self.POLL_MS, self._poll_ocr)
        self._in_thread(self.app._check_ocr_ready, done)

    # ── step 2: index the User Guide via Index Docs ─────────────────────────
    def index_guide(self):
        guide = find_user_guide()
        if guide is None:
            self._set("guide", "⚠️", "Couldn't find the User Guide on this PC. Use Index Docs to add "
                                     "any folder instead.")
            return self._offer_more()
        if is_tracked(guide):
            self._set("guide", "✅", f"Already indexed: {guide}")
            self.panel.progress.set_state("index", DONE)
            return self.try_it()
        if not all(hasattr(self.app, a) for a in ("_queue_add_paths", "start_indexing")):
            self._set("guide", "⚠️", "Indexing isn't available here — use the Index Docs tab.")
            return self._offer_more()
        if getattr(self.app, "_index_running", False):
            self._set("guide", "⏳", "Another index is running — waiting for it to finish…")
            return self.win.after(self.POLL_MS, self.index_guide)
        queued_before = list(getattr(self.app, "_index_queue", []) or [])
        self.app._queue_add_paths([str(guide)])
        if queued_before:
            # Don't start the user's own queued folders without asking.
            self._set("guide", "🟡", f"Added {guide.name} to the Index Docs queue (it already had "
                                     "other items) — press ▶ Start there when you're ready.")
            self.panel.open_tab(BY_ID["index"])
            return self._offer_more()
        self._set("guide", "🔄", f"Indexing {guide} … (progress on the Index Docs tab)")
        self.panel.open_tab(BY_ID["index"])
        try:
            self.app.start_indexing()
        except Exception as e:
            self._set("guide", "⚠️", f"Couldn't start indexing ({e}).")
            return self._offer_more()
        self.win.lift()
        self.win.after(self.POLL_MS, lambda: self._poll_index(guide))

    def _poll_index(self, guide):
        if not self._alive():
            return
        if getattr(self.app, "_index_running", False):
            return self.win.after(self.POLL_MS, lambda: self._poll_index(guide))
        if is_tracked(guide):
            self._set("guide", "✅", f"Indexed and tracked: {guide}")
            self.panel.progress.set_state("index", DONE)
            self.panel.render()
            return self.try_it()
        self._set("guide", "⚠️", "Indexing finished but the guide isn't in the tracked list — check "
                                 "the Index Docs output.")
        self._offer_more()

    # ── step 3: try it ──────────────────────────────────────────────────────
    def try_it(self):
        self._set("try", "💬", 'Ask your AI app: "Using AI-Prowler, how do I schedule automatic '
                               'indexing?" — it will answer from the User Guide you just indexed.')
        self._offer_more()

    def _offer_more(self):
        ttk = self.ttk
        for w in self.btns.winfo_children():
            if w is not self.close_btn:
                w.destroy()
        ttk.Button(self.btns, text="📚 Index more folders…",
                   command=lambda: (self.panel.open_tab(BY_ID["index"]), self.win.destroy())
                   ).pack(side="right", padx=6)
        self.close_btn.config(text="Done")
        self.panel.render()


class ConnectAIFlow:
    """"Connect your AI" — Claude · Grok · Muse (David 2026-09-30).
    Opens from the Setup Center's Start button and from the Settings tab's
    "📱 Phone / QR · Copy · Email link…" button. Offers every way to get the
    connector URL: Copy, Email it to me, a QR code for the phone page
    (/connect), and a Connect (auto) button per AI. The Bearer Token is only
    ever copied to THIS desktop's clipboard on request — never put in a URL,
    an email, a QR code or the phone page."""

    def __init__(self, master, app, panel: "SetupCenterPanel | None" = None):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk, self.app, self.panel = tk, ttk, app, panel
        self.domain = tunnel_domain()
        self.url = mcp_url(self.domain)
        self.win = tk.Toplevel(master)
        self.win.title("Connect your AI to AI-Prowler")
        self.win.transient(master.winfo_toplevel())
        body = ttk.Frame(self.win, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Connect your AI — Claude · Grok · Muse", font=("Arial", 12, "bold")
                  ).pack(anchor="w")
        ttk.Label(body, text=BY_ID["connect_ai"].why + " Nothing needs to be installed on this PC for "
                  "Grok or Muse — just an account (their phone apps are optional).",
                  wraplength=560, justify="left", foreground="#555").pack(anchor="w", pady=(2, 10))

        if not self.url:
            warn = ttk.LabelFrame(body, text=" Phone access isn't set up yet ", padding=10)
            warn.pack(fill="x", pady=(0, 10))
            ttk.Label(warn, text="Claude (web and phone), Grok and Muse reach AI-Prowler over the internet, "
                      "through your secure link. Set up phone access first (Settings → activate your "
                      "subscription → ⚡ Configure Mobile Access). Claude Desktop on this PC works without it.",
                      wraplength=520, justify="left").pack(anchor="w")
            ttk.Button(warn, text="Open the Settings tab", command=self._open_settings).pack(anchor="w", pady=(6, 0))
        else:
            self._url_block(body)

        for a in AI_APPS:
            self._card(body, a)

        btns = ttk.Frame(body)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="Close", command=self.win.destroy).pack(side="right")
        if panel is not None:
            ttk.Button(btns, text="✓ I've connected my AI", command=self._done).pack(side="right", padx=6)

    @classmethod
    def open_from(cls, app):
        """From the Settings tab: attach to the Home panel if it exists (so
        "I've connected it" updates the checklist), else to the main window."""
        panel = getattr(app, "_setup_center", None)
        master = panel.frame if panel is not None else app.root
        return cls(master, app, panel)

    # ── pieces ──────────────────────────────────────────────────────────────
    def _url_block(self, body):
        tk, ttk = self.tk, self.ttk
        box = ttk.LabelFrame(body, text=" Your connector URL — name it “AI-Prowler Local” ", padding=10)
        box.pack(fill="x", pady=(0, 10))
        row = ttk.Frame(box)
        row.pack(fill="x")
        left = ttk.Frame(row)
        left.pack(side="left", fill="x", expand=True)
        ent = ttk.Entry(left, width=52)
        ent.insert(0, self.url)
        ent.configure(state="readonly")
        ent.pack(anchor="w", fill="x")
        b = ttk.Frame(left)
        b.pack(anchor="w", pady=(6, 0))
        ttk.Button(b, text="📋 Copy URL", command=lambda: self._copy(self.url, "URL")).pack(side="left")
        ttk.Button(b, text="📧 Email it to me", command=self._email).pack(side="left", padx=6)
        ttk.Button(b, text="📋 Copy Bearer Token", command=self._copy_token).pack(side="left")
        self.note = ttk.Label(left, text="", foreground="#2e7d32")
        self.note.pack(anchor="w", pady=(4, 0))
        ttk.Label(left, text="The token is the password to your whole AI-Prowler — it's never in the URL, "
                  "the email, the QR code or the phone page.", wraplength=360, justify="left",
                  foreground="#777", font=("Arial", 8)).pack(anchor="w", pady=(4, 0))
        # QR → the /connect phone page
        qr = qr_png(connect_page_url(self.domain), scale=4)
        right = ttk.Frame(row)
        right.pack(side="right", padx=(12, 0))
        if qr:
            import base64
            self._qr_img = tk.PhotoImage(master=right, data=base64.b64encode(qr).decode("ascii"))
            ttk.Label(right, image=self._qr_img).pack()
            ttk.Label(right, text="📱 Scan with your phone\nto connect from there", justify="center",
                      font=("Arial", 8)).pack()
        else:
            ttk.Label(right, text="(QR code needs the\n'segno' package —\nuse Copy or Email)",
                      justify="center", foreground="#777", font=("Arial", 8)).pack()

    def _card(self, body, a):
        ttk = self.ttk
        f = ttk.LabelFrame(body, text=f" {a['icon']} {a['name']} ", padding=8)
        f.pack(fill="x", pady=3)
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Button(row, text=f"📖 Connect {a['name']}  (auto)",
                   command=lambda: open_ai_connector(self.win, a["id"], self.domain)).pack(side="left")
        if a.get("message") and self.url:
            ttk.Button(row, text="📋 Copy message",
                       command=lambda: self._copy(muse_message(self.url), "message")).pack(side="left", padx=6)
        ttk.Label(f, text=a["apps"], wraplength=540, justify="left", foreground="#777",
                  font=("Arial", 8)).pack(anchor="w", pady=(4, 0))

    # ── actions ─────────────────────────────────────────────────────────────
    def _copy(self, text, what):
        try:
            self.win.clipboard_clear()
            self.win.clipboard_append(text)
            self.win.update()
            if hasattr(self, "note"):
                self.note.config(text=f"✅ {what.capitalize()} copied to the clipboard")
        except Exception:
            pass

    def _copy_token(self):
        from tkinter import messagebox
        tok = bearer_token()
        if not tok:
            messagebox.showwarning("No Bearer Token", "No Bearer Token is set yet — set one on the Settings "
                                   "tab (Remote access).", parent=self.win)
            return
        self._copy(tok, "Bearer Token")

    def _email(self):
        import webbrowser
        webbrowser.open(email_link(self.url))
        if hasattr(self, "note"):
            self.note.config(text="📧 Your mail app opened with the link — send it to yourself")

    def _open_settings(self):
        tabs = getattr(self.app, "notebook", None)
        if tabs is not None:
            for t in tabs.tabs():
                if tabs.tab(t, "text").strip() == "⚙️ Settings":
                    tabs.select(t)
        self.win.destroy()

    def _done(self):
        if self.panel is not None:
            self.panel.progress.set_state("connect_ai", DONE)
            self.panel.render()
        self.win.destroy()


class AutoIndexFlow:
    """"Keep your index up to date" — both of AI-Prowler's own ways, both ticked
    by default:
      🐾 File Watchdog — indexes added/changed files within seconds while
         AI-Prowler runs (the Schedule tab's Start Watchdog: app._watchdog_toggle)
      🕑 Nightly catch-up — the Schedule tab's Windows task (app.set_schedule),
         runs even when AI-Prowler is closed (the PC must be on).
    Then re-checks the real state and marks the step done."""

    def __init__(self, panel: "SetupCenterPanel"):
        import tkinter as tk
        from tkinter import ttk
        self.panel, self.app, self.tk, self.ttk = panel, panel.app, tk, ttk
        self.win = tk.Toplevel(panel.frame)
        self.win.title("Keep your index up to date")
        self.win.transient(panel.frame.winfo_toplevel())
        self.win.resizable(False, False)
        body = ttk.Frame(self.win, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Keep your index up to date", font=("Arial", 12, "bold")).pack(anchor="w")
        ttk.Label(body, text="When you add or change files in your indexed folders, AI-Prowler can pick "
                  "them up for you. Most people use both:", wraplength=480, justify="left",
                  foreground="#555").pack(anchor="w", pady=(4, 10))

        self.watch = tk.BooleanVar(master=self.win, value=True)
        ttk.Checkbutton(body, text="🐾 Watch my folders — index changes within seconds while AI-Prowler runs",
                        variable=self.watch).pack(anchor="w")
        self.watch_state = ttk.Label(body, text="", foreground="#666")
        self.watch_state.pack(anchor="w", padx=(24, 0), pady=(0, 8))

        self.nightly = tk.BooleanVar(master=self.win, value=True)
        row = ttk.Frame(body)
        row.pack(anchor="w")
        ttk.Checkbutton(row, text="🕑 Nightly catch-up every day at", variable=self.nightly).pack(side="left")
        self.time = tk.StringVar(master=self.win, value=DEFAULT_NIGHTLY)
        ttk.Entry(row, textvariable=self.time, width=6).pack(side="left", padx=4)
        ttk.Label(row, text="(24-hour, e.g. 02:00)", foreground="#888").pack(side="left")
        ttk.Label(body, text="Runs through Windows even when AI-Prowler is closed — your PC needs to be on "
                  "(not asleep) at that time.", wraplength=460, justify="left", foreground="#666"
                  ).pack(anchor="w", padx=(24, 0))
        self.night_state = ttk.Label(body, text="", foreground="#666")
        self.night_state.pack(anchor="w", padx=(24, 0), pady=(0, 8))

        self.msg = ttk.Label(body, text="", foreground="#b00020", wraplength=460, justify="left")
        self.msg.pack(anchor="w")
        b = ttk.Frame(body)
        b.pack(fill="x", pady=(12, 0))
        ttk.Button(b, text="Close", command=self.win.destroy).pack(side="right")
        ttk.Button(b, text="✅ Turn it on", command=self.apply).pack(side="right", padx=6)
        self.refresh()

    def refresh(self):
        w, n = watchdog_running(), schedule_task_exists()
        self.watch_state.config(text="✅ Watchdog is running" if w else "Not running yet")
        self.night_state.config(text="✅ A nightly schedule is set" if n else "No schedule yet")
        return w, n

    def apply(self):
        self.msg.config(text="")
        if not (self.watch.get() or self.nightly.get()):
            self.msg.config(text="Tick at least one — or close this and use Update Index by hand.")
            return
        t = self.time.get().strip()
        if self.nightly.get() and not valid_hhmm(t):
            self.msg.config(text="Enter the time as HH:MM, e.g. 02:00 or 23:30.")
            return
        if self.watch.get() and not watchdog_running() and hasattr(self.app, "_watchdog_toggle"):
            try:
                self.app._watchdog_toggle()                 # starts the File Watchdog
            except Exception as e:
                self.msg.config(text=f"Couldn't start the Watchdog: {e}")
        if self.nightly.get() and hasattr(self.app, "set_schedule"):
            self.app.set_schedule(t, list(ALL_DAYS))        # shows its own "Schedule set!" message
        self.win.after(2500, self._verify)

    def _verify(self):
        try:
            w, n = self.refresh()
        except self.tk.TclError:
            return
        ok = (w or not self.watch.get()) and (n or not self.nightly.get())
        if w or n:
            self.panel.progress.set_state("auto_index", DONE)
            self.panel.render()
        if not ok:
            self.msg.config(text="Not everything turned on — see the messages above, or set it up on the "
                            "⏰ Schedule tab.")


class _SimpleFlow:
    """Shared window scaffolding for the Phase 3 steps."""

    def __init__(self, panel: "SetupCenterPanel", title: str, module_id: str):
        import tkinter as tk
        from tkinter import ttk
        self.panel, self.app, self.tk, self.ttk = panel, panel.app, tk, ttk
        self.module_id = module_id
        self.win = tk.Toplevel(panel.frame)
        self.win.title(title)
        self.win.transient(panel.frame.winfo_toplevel())
        self.win.resizable(False, False)
        self.body = ttk.Frame(self.win, padding=18)
        self.body.pack(fill="both", expand=True)
        ttk.Label(self.body, text=title, font=("Arial", 12, "bold")).pack(anchor="w")
        ttk.Label(self.body, text=BY_ID[module_id].why, wraplength=500, justify="left",
                  foreground="#555").pack(anchor="w", pady=(4, 10))

    def _footer(self, action_text: str, action):
        ttk = self.ttk
        self.msg = ttk.Label(self.body, text="", wraplength=500, justify="left")
        self.msg.pack(anchor="w", pady=(8, 0))
        b = ttk.Frame(self.body)
        b.pack(fill="x", pady=(10, 0))
        ttk.Button(b, text="Close", command=self.win.destroy).pack(side="right")
        ttk.Button(b, text="Open this tab",
                   command=lambda: self.panel.open_tab(BY_ID[self.module_id])).pack(side="right", padx=6)
        if action_text:
            ttk.Button(b, text=action_text, command=action).pack(side="right")

    def _say(self, text: str, ok: bool = True):
        self.msg.config(text=text, foreground="#2e7d32" if ok else "#b00020")

    def _done(self):
        self.panel.progress.set_state(self.module_id, DONE)
        self.panel.render()


class LinksFlow(_SimpleFlow):
    """Scheduled AI analyses from ready-made templates (Links & Analysis)."""

    def __init__(self, panel: "SetupCenterPanel"):
        super().__init__(panel, "Scheduled AI analyses", "links")
        tk, ttk = self.tk, self.ttk
        business = "business" in panel.progress.services
        self.templates = [t for t in ANALYSIS_TEMPLATES if t["needs"] is None or business]
        self.vars = {}
        for t in self.templates:
            v = tk.BooleanVar(master=self.body, value=t["id"] == "weekly_docs")
            self.vars[t["id"]] = v
            when = "every Monday" if t["schedule"] == "weekly" else "on the 1st of each month"
            ttk.Checkbutton(self.body, text=f"{t['label']}  ({when})", variable=v).pack(anchor="w", pady=1)
        self.email_on = tk.BooleanVar(master=self.body, value=False)
        e = ttk.Checkbutton(self.body, text="✉️ Also email me the result", variable=self.email_on)
        e.pack(anchor="w", pady=(8, 0))
        if not email_configured():
            e.state(["disabled"])
            ttk.Label(self.body, text="(Set up Email first to use this.)", foreground="#888"
                      ).pack(anchor="w", padx=(24, 0))
        ttk.Label(self.body, text="Results are saved as Learnings your AI can use. Each run uses your AI "
                  "plan's usage. Due analyses wait until you run them — or until you switch on the "
                  "Autonomous AI Task Queue on the Links & Analysis tab (it's off unless you turn it on).",
                  wraplength=500, justify="left", foreground="#666").pack(anchor="w", pady=(8, 0))
        self._footer("✅ Add these", self.add)

    def add(self):
        import datetime as dt
        chosen = [t for t in self.templates if self.vars[t["id"]].get()]
        if not chosen:
            return self._say("Tick at least one analysis.", ok=False)
        try:
            import custom_tasks_manager as ctm
        except Exception as e:
            return self._say(f"Couldn't load the task manager: {e}", ok=False)
        tasks = ctm.load_custom_tasks()
        have = {t.get("label") for t in tasks}
        added, skipped = [], []
        for t in chosen:
            if t["label"] in have:
                skipped.append(t["label"])
                continue
            try:
                tasks.append(ctm.create_task(**template_task_args(t, dt.date.today(), self.email_on.get())))
                added.append(t["label"])
            except ValueError as e:
                return self._say(f"Couldn't add “{t['label']}”: {e}", ok=False)
        if added and not ctm.save_custom_tasks(tasks):
            return self._say("Couldn't save the tasks — nothing was added.", ok=False)
        # the Links tab's own list refresh (it also polls the tasks file on its own)
        refresh = getattr(self.app, "_refresh_custom_task_list", None)
        if callable(refresh):
            try:
                refresh()
            except Exception:
                pass
        parts = []
        if added:
            parts.append("Added: " + ", ".join(added))
        if skipped:
            parts.append("Already there: " + ", ".join(skipped))
        self._say(". ".join(parts) + ". See them on the Links & Analysis tab.")
        self._done()


class LearningsFlow(_SimpleFlow):
    """Record a first learning, from an example or their own words."""

    def __init__(self, panel: "SetupCenterPanel"):
        super().__init__(panel, "Teach AI-Prowler", "learnings")
        tk, ttk = self.tk, self.ttk
        ex = ttk.Frame(self.body)
        ex.pack(anchor="w", pady=(0, 6))
        ttk.Label(ex, text="Start from an example:").pack(side="left", padx=(0, 6))
        for title, content in LEARNING_EXAMPLES:
            ttk.Button(ex, text=title, command=lambda t=title, c=content: self._fill(t, c)
                       ).pack(side="left", padx=2)
        ttk.Label(self.body, text="Title").pack(anchor="w")
        self.title = tk.StringVar(master=self.body)
        ttk.Entry(self.body, textvariable=self.title, width=60).pack(anchor="w", fill="x")
        ttk.Label(self.body, text="What should your AI remember?").pack(anchor="w", pady=(6, 0))
        self.content = tk.Text(self.body, width=60, height=5, wrap="word")
        self.content.pack(anchor="w", fill="x")
        self._footer("✅ Save learning", self.save)

    def _fill(self, t, c):
        self.title.set(t)
        self.content.delete("1.0", "end")
        self.content.insert("1.0", c)

    def save(self):
        t, c = self.title.get().strip(), self.content.get("1.0", "end").strip()
        if not t or not c:
            return self._say("Fill in both the title and what to remember.", ok=False)
        try:
            import self_learning as sl
            sl.record_learning(title=t, content=c, category="general", source="operator",
                               context="Recorded from the Setup Center")
        except Exception as e:
            return self._say(f"Couldn't save it: {e}", ok=False)
        self._say(f"Saved “{t}”. Try it — ask your AI: \"Using AI-Prowler, {t.lower()}?\"")
        self._done()


class EmailFlow(_SimpleFlow):
    """Email: the Settings tab's Email Configuration does the work (type your
    address → server settings fill in → Save → Send Test Email). This explains
    it, links to the app-password pages, and detects when it's configured."""

    def __init__(self, panel: "SetupCenterPanel"):
        super().__init__(panel, "Email", "email")
        ttk = self.ttk
        steps = ("1. Outlook on this PC? Choose Outlook — no password needed.\n"
                 "2. Otherwise type your email address — the server settings fill in for you.\n"
                 "3. Paste an app password (not your normal password — links below).\n"
                 "4. Save, then Send Test Email to yourself.")
        ttk.Label(self.body, text=steps, justify="left").pack(anchor="w")
        links = ttk.Frame(self.body)
        links.pack(anchor="w", pady=(8, 0))
        ttk.Label(links, text="Make an app password:").pack(side="left", padx=(0, 6))
        import webbrowser
        for name, url in APP_PASSWORD_LINKS:
            ttk.Button(links, text=name, command=lambda u=url: webbrowser.open(u)).pack(side="left", padx=2)
        self.state_lbl = ttk.Label(self.body, text="")
        self.state_lbl.pack(anchor="w", pady=(8, 0))
        self._footer("🔄 Check again", self.check)
        self.check()

    def check(self):
        if email_configured():
            self.state_lbl.config(text="✅ Email is set up. (Use Send Test Email on Settings to confirm it "
                                       "reaches you.)", foreground="#2e7d32")
            self._done()
        else:
            self.state_lbl.config(text="Not set up yet — click Open this tab and follow the steps.",
                                  foreground="#666")


class RemoteFlow(_SimpleFlow):
    """Phone access — four checks, each with its one-click fix:
      1. Secure link: domain set (Settings → activate → ⚡ Configure Mobile Access)
         AND it answers from the internet.
      2. Bearer Token set (the password for phone apps / AI connectors).
      3. Power settings — the shared power_status() checks; fix = the Settings
         tab's own Apply Power Settings Now (Windows asks permission).
      4. Start AI-Prowler with Windows — the installer's AI-Prowler-AutoStart
         task; fix = create it the same way (Windows asks permission).
    Done when the link answers and a token is set (power + autostart are
    strongly recommended, shown, but not required)."""

    def __init__(self, panel: "SetupCenterPanel"):
        super().__init__(panel, "Phone access", "remote")
        ttk = self.ttk
        self.rows = {}
        for key, label in (("link", "Secure link to your phone (subscription + ⚡ Configure Mobile Access)"),
                           ("token", "Bearer Token — the password for your phone apps and AI connectors"),
                           ("power", "Power settings — the PC stays awake to answer"),
                           ("autostart", "Start AI-Prowler with Windows")):
            r = ttk.Frame(self.body)
            r.pack(fill="x", pady=3)
            icon = ttk.Label(r, text="⬜", width=3)
            icon.pack(side="left")
            ttk.Label(r, text=label).pack(side="left")
            fix = ttk.Frame(r)
            fix.pack(side="right")
            detail = ttk.Label(self.body, text="", foreground="#666", wraplength=520, justify="left")
            detail.pack(anchor="w", padx=(30, 0))
            self.rows[key] = (icon, detail, fix)
        self._footer("🔄 Check again", self.check)
        self.check()

    def _row(self, key, ok, detail, fix_text=None, fix=None):
        icon, lbl, fixf = self.rows[key]
        icon.config(text="✅" if ok else "❌")
        lbl.config(text=detail)
        for w in fixf.winfo_children():
            w.destroy()
        if not ok and fix_text:
            self.ttk.Button(fixf, text=fix_text, command=fix).pack(side="right")

    def check(self):
        d = tunnel_domain()
        self._row("link", False, "Checking…" if d else "")
        self._row("token", bool(bearer_token()),
                  "Set." if bearer_token() else "Not set — set one on the Settings tab (Remote access).",
                  "Open Settings", lambda: self.panel.open_tab(BY_ID["remote"]))
        ps = power_status()
        bad = [label for k, label in POWER_CHECKS if not ps[k][0]]
        self._row("power", not bad, "All four are set." if not bad else "Not yet: " + "; ".join(bad) + ".",
                  "⚡ Apply power settings", self.apply_power)
        auto = autostart_task_exists()
        self._row("autostart", auto, "AI-Prowler starts when you sign in to Windows." if auto
                  else "AI-Prowler won't start by itself after a restart.",
                  "Turn on", self.turn_on_autostart)
        if not d:
            self._row("link", False, "Not set up yet: on the Settings tab, activate your subscription "
                      "(Manage Subscription), then click ⚡ Configure Mobile Access.",
                      "Open Settings", lambda: self.panel.open_tab(BY_ID["remote"]))
            return self._finish(False)
        import threading
        box = {}
        threading.Thread(target=lambda: box.setdefault("ok", link_reachable(d)), daemon=True).start()

        def collect():
            try:
                if not self.win.winfo_exists():
                    return
            except self.tk.TclError:
                return
            if "ok" not in box:
                return self.win.after(200, collect)
            ok = box["ok"]
            self._row("link", ok, f"https://{d} answers from the internet." if ok else
                      f"https://{d} isn't answering — is AI-Prowler's secure link running? Try "
                      "⚡ Configure Mobile Access again on the Settings tab.",
                      "Open Settings", lambda: self.panel.open_tab(BY_ID["remote"]))
            self._finish(ok)
        self.win.after(200, collect)

    def _finish(self, link_ok: bool):
        if link_ok and bearer_token():
            self._say("✅ Phone access is set up. Next: the Remote app on your phone.")
            self._done()
        else:
            self._say("Fix the ❌ items above, then click Check again.", ok=False)

    def apply_power(self):
        fn = getattr(self.app, "_apply_power_settings", None)
        if not callable(fn):
            return self._say("Use Apply Power Settings Now on the Settings tab.", ok=False)
        fn()                                       # the Settings tab's own script (Windows asks permission)
        self._say("Approve Windows' permission prompt, then click Check again.")
        lights = getattr(self.app, "_refresh_power_lights", None)
        if callable(lights):
            self.win.after(8000, lights)

    def turn_on_autostart(self):
        ok, msg = create_autostart_task()
        self._say(msg, ok=ok)


class RemotePwaFlow(_SimpleFlow):
    """Remote app on your phone: QR for https://<link>/remote/, Copy / Email the
    link, iPhone + Android "add to home screen" steps; turns ✅ when the server
    sees the Remote app used from a phone (remote_app_seen.json)."""

    POLL_MS = 3000

    def __init__(self, panel: "SetupCenterPanel"):
        super().__init__(panel, "Remote app on your phone", "remote_pwa")
        tk, ttk = self.tk, self.ttk
        self.url = remote_app_url()
        if not self.url:
            ttk.Label(self.body, text="Set up Phone access first — the Remote app reaches your PC through "
                      "your secure link.", wraplength=500, justify="left").pack(anchor="w")
            self._footer("", None)
            return
        row = ttk.Frame(self.body)
        row.pack(fill="x")
        left = ttk.Frame(row)
        left.pack(side="left", fill="x", expand=True)
        steps = ("1. Point your phone's camera at the code → tap the link.\n"
                 "2. iPhone: in Safari tap Share → Add to Home Screen. If the link opened in another browser, copy it into Safari first.\n"
                 "    Android: in Chrome tap the Install button on the page (or ⋮ → Install app).\n"
                 "3. Open it from your home screen and sign in with your Bearer Token\n"
                 "    (📋 Copy Bearer Token is on the Connect your AI window / Settings tab).")
        ttk.Label(left, text=steps, justify="left").pack(anchor="w")
        b = ttk.Frame(left)
        b.pack(anchor="w", pady=(8, 0))
        ttk.Button(b, text="📋 Copy link", command=self._copy).pack(side="left")
        ttk.Button(b, text="📧 Email it to me", command=self._email).pack(side="left", padx=6)
        qr = qr_png(self.url, scale=4)
        if qr:
            import base64
            self._qr_img = tk.PhotoImage(master=self.body, data=base64.b64encode(qr).decode("ascii"))
            right = ttk.Frame(row)
            right.pack(side="right", padx=(12, 0))
            ttk.Label(right, image=self._qr_img).pack()
            ttk.Label(right, text="📱 Scan to open\nthe Remote app", justify="center",
                      font=("Arial", 8)).pack()
        self.wait_lbl = ttk.Label(self.body, text="", foreground="#666")
        self.wait_lbl.pack(anchor="w", pady=(10, 0))
        self._footer("", None)
        self._poll()

    def _copy(self):
        self.win.clipboard_clear()
        self.win.clipboard_append(self.url)
        self._say("✅ Link copied.")

    def _email(self):
        import webbrowser
        from urllib.parse import quote
        body = (f"Open this on your phone to install the AI-Prowler Remote app:\n\n{self.url}\n\n"
                "Sign in with your Bearer Token (it is NOT in this email).\n")
        webbrowser.open(f"mailto:?subject={quote('My AI-Prowler Remote app link')}&body={quote(body)}")
        self._say("📧 Your mail app opened with the link — send it to yourself.")

    def _poll(self):
        try:
            if not self.win.winfo_exists():
                return
        except self.tk.TclError:
            return
        if remote_seen_on_phone():
            self.wait_lbl.config(text="✅ Your phone is connected — the Remote app has signed in from it.",
                                 foreground="#2e7d32")
            self._done()
            return
        self.wait_lbl.config(text="⏳ Waiting for your phone to sign in…")
        self.win.after(self.POLL_MS, self._poll)


class JobsFlow(_SimpleFlow):
    """Jobs app: 1. your business (the Settings rows invoices print), 2. customers
    (add one, or import a CSV), 3. the Jobs app on your phone (QR, Copy, Email,
    install steps; ✅ when the server sees it used from a phone). Every write
    goes through AI-Prowler's own tools (update_job_spreadsheet / create_setting
    / create_customer). Done = a business name + at least one customer — or
      "Skip for now" to add them later in the Jobs app's Database tab."""

    POLL_MS = 3000

    def __init__(self, panel: "SetupCenterPanel"):
        super().__init__(panel, "Jobs app", "jobs")
        tk, ttk = self.tk, self.ttk

        # 1. business
        biz = ttk.LabelFrame(self.body, text=" 1. Your business — printed on invoices and receipts ", padding=8)
        biz.pack(fill="x")
        cur = read_settings([k for k, _, _ in BUSINESS_FIELDS])
        self.biz_vars = {}
        for i, (key, label, req) in enumerate(BUSINESS_FIELDS):
            ttk.Label(biz, text=label + (" *" if req else "")).grid(row=i, column=0, sticky="w", pady=1)
            v = tk.StringVar(master=self.body,
                             value=tax_to_show(cur[key]) if key == "Tax Rate" and cur[key] else cur[key])
            self.biz_vars[key] = v
            ttk.Entry(biz, textvariable=v, width=44).grid(row=i, column=1, sticky="w", padx=6, pady=1)
        self.biz_orig = {k: v.get() for k, v in self.biz_vars.items()}
        brow = ttk.Frame(biz)
        brow.grid(row=len(BUSINESS_FIELDS), column=1, sticky="w", padx=6, pady=(6, 0))
        ttk.Button(brow, text="💾 Save business details", command=self.save_business).pack(side="left")
        ttk.Button(brow, text="Skip this step", command=self.skip_business).pack(side="left", padx=(8, 0))
        self.biz_note = ttk.Label(biz, text="", foreground="#666", wraplength=400, justify="left")
        self.biz_note.grid(row=len(BUSINESS_FIELDS) + 1, column=0, columnspan=2, sticky="w", padx=6, pady=(2, 0))

        # 2. customers
        cust = ttk.LabelFrame(self.body, text=" 2. Customers ", padding=8)
        cust.pack(fill="x", pady=(8, 0))
        self.count_lbl = ttk.Label(cust, text="")
        self.count_lbl.grid(row=0, column=0, columnspan=4, sticky="w")
        self.cust_vars = {}
        fields = [("Company Name", "Company (or leave blank)"), ("First Name", "First name"),
                  ("Last Name", "Last name"), ("Phone", "Phone"), ("Email", "Email"),
                  ("Street Address", "Street"), ("City", "City"), ("State", "State"), ("ZIP", "ZIP")]
        for i, (key, label) in enumerate(fields):
            r, c = 1 + i // 3, (i % 3) * 2
            ttk.Label(cust, text=label).grid(row=r, column=c, sticky="w", padx=(0 if c == 0 else 8, 2))
            v = tk.StringVar(master=self.body)
            self.cust_vars[key] = v
            ttk.Entry(cust, textvariable=v, width=16).grid(row=r, column=c + 1, sticky="w")
        bb = ttk.Frame(cust)
        bb.grid(row=5, column=0, columnspan=6, sticky="w", pady=(6, 0))
        ttk.Button(bb, text="➕ Add customer", command=self.add_one).pack(side="left")
        ttk.Button(bb, text="📄 Import from CSV…", command=self.import_csv).pack(side="left", padx=6)
        ttk.Button(bb, text="Skip", command=self.skip_customers).pack(side="left", padx=6)
        ttk.Label(bb, text="(columns like Name, Company, Phone, Email, Address, City, State, ZIP)",
                  foreground="#888", font=("Arial", 8)).pack(side="left")
        self.cust_note = ttk.Label(cust, text="", foreground="#666", wraplength=460, justify="left")
        self.cust_note.grid(row=6, column=0, columnspan=6, sticky="w", pady=(2, 0))

        # 3. the app on your phone
        app = ttk.LabelFrame(self.body, text=" 3. The Jobs app on your phone ", padding=8)
        app.pack(fill="x", pady=(8, 0))
        self.url = jobs_app_url()
        if self.url:
            row = ttk.Frame(app)
            row.pack(fill="x")
            left = ttk.Frame(row)
            left.pack(side="left", fill="x", expand=True)
            ttk.Label(left, text="Scan the code with your phone (or a crew member's), then:\n" +
                      PHONE_INSTALL_STEPS + "\nSign in with your Bearer Token.", justify="left").pack(anchor="w")
            b = ttk.Frame(left)
            b.pack(anchor="w", pady=(6, 0))
            ttk.Button(b, text="📋 Copy link", command=self._copy).pack(side="left")
            ttk.Button(b, text="📧 Email it", command=self._email).pack(side="left", padx=6)
            qr = qr_png(self.url, scale=3)
            if qr:
                import base64
                self._qr_img = tk.PhotoImage(master=row, data=base64.b64encode(qr).decode("ascii"))
                ttk.Label(row, image=self._qr_img).pack(side="right", padx=(10, 0))
            self.phone_lbl = ttk.Label(app, text="", foreground="#666")
            self.phone_lbl.pack(anchor="w", pady=(6, 0))
        else:
            self.phone_lbl = None
            ttk.Label(app, text="Set up Phone access first — the Jobs app reaches your PC through your "
                      "secure link.", wraplength=480).pack(anchor="w")
        self._footer("", None)
        self._refresh()
        if self.phone_lbl is not None:
            self._poll()

    # ── actions ─────────────────────────────────────────────────────────────
    def _refresh(self):
        n = customer_count()
        self.count_lbl.config(text=f"You have {n} customer{'s' if n != 1 else ''}." if n else
                              "No customers yet — add your first one, or import a list.")
        skips = _jobs_skips()
        # a skip clears itself as soon as the real data shows up
        if skips["business"] and read_settings(["Business Name"])["Business Name"]:
            _set_job_skip("business", False)
            skips["business"] = False
        if skips["customers"] and n > 0:
            _set_job_skip("customers", False)
            skips["customers"] = False
        self.biz_note.config(
            text="Skipped — add your business info anytime in the Jobs app → Database tab."
            if skips["business"] else "")
        self.cust_note.config(
            text="Skipped — add customers anytime in the Jobs app → Database tab."
            if skips["customers"] else "")
        if detect_jobs():
            self._done()

    def save_business(self):
        if not self.biz_vars["Business Name"].get().strip():
            return self._say("Enter your business name.", ok=False)
        try:
            tax = tax_to_store(self.biz_vars["Tax Rate"].get())
        except ValueError:
            return self._say("Enter the tax rate as a percent, e.g. 7 or 6.5.", ok=False)
        errors, saved = [], 0
        for key, v in self.biz_vars.items():
            val = tax if key == "Tax Rate" else v.get().strip()
            if v.get() == self.biz_orig.get(key) or (not val and not self.biz_orig.get(key)):
                continue
            try:
                res = save_setting(key, val)
            except Exception as e:
                res = f"❌ {e}"
            if res.lstrip().startswith("❌"):
                errors.append(f"{key}: {res.strip()[:120]}")
            else:
                saved += 1
                self.biz_orig[key] = v.get()
        if errors:
            return self._say("Not saved — " + "; ".join(errors), ok=False)
        self._say(f"✅ Saved {saved} business detail{'s' if saved != 1 else ''}." if saved
                  else "Nothing changed.")
        self._refresh()

    def add_one(self):
        f = {k: v.get().strip() for k, v in self.cust_vars.items() if v.get().strip()}
        if not (f.get("Company Name") or f.get("First Name") or f.get("Last Name")):
            return self._say("Enter a company or a name for the customer.", ok=False)
        f["Status Active/Inactive"] = "Active"
        try:
            res = add_customer(f)
        except Exception as e:
            res = f"❌ {e}"
        if res.lstrip().startswith("❌"):
            return self._say(res.strip()[:200], ok=False)
        for v in self.cust_vars.values():
            v.set("")
        self._say("✅ " + res.strip().splitlines()[0][:160])
        self._refresh()

    def import_csv(self):
        from tkinter import filedialog, messagebox
        path = filedialog.askopenfilename(parent=self.win, title="Choose a customer list (CSV)",
                                          filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            rows, skipped = parse_customers_csv(Path(path).read_text(encoding="utf-8-sig", errors="replace"))
        except Exception as e:
            return self._say(f"Couldn't read that file: {e}", ok=False)
        if not rows:
            return self._say("No customers found — the file needs a Name or Company column.", ok=False)
        if not messagebox.askyesno("Import customers",
                                   f"Import {len(rows)} customer{'s' if len(rows) != 1 else ''}"
                                   + (f" ({skipped} row{'s' if skipped != 1 else ''} without a name skipped)"
                                      if skipped else "") + "?", parent=self.win):
            return
        ok, bad = 0, []
        for r in rows:
            try:
                res = add_customer(r)
            except Exception as e:
                res = f"❌ {e}"
            if res.lstrip().startswith("❌"):
                bad.append(r.get("Company Name") or f"{r.get('First Name', '')} {r.get('Last Name', '')}".strip())
            else:
                ok += 1
        self._say(f"✅ Imported {ok}." + (f" Couldn't add: {', '.join(bad[:5])}"
                                         + ("…" if len(bad) > 5 else "") if bad else ""), ok=not bad)
        self._refresh()

    def _copy(self):
        self.win.clipboard_clear()
        self.win.clipboard_append(self.url)
        self._say("✅ Link copied.")

    def _email(self):
        import webbrowser
        from urllib.parse import quote
        body = (f"Open this on your phone to install the AI-Prowler Jobs app:\n\n{self.url}\n\n"
                "Sign in with the Bearer Token (it is NOT in this email).\n")
        webbrowser.open(f"mailto:?subject={quote('AI-Prowler Jobs app link')}&body={quote(body)}")
        self._say("📧 Your mail app opened with the link.")

    def skip_business(self):
        """Section 1 skipped — business info can be added later in the Jobs app."""
        _set_job_skip("business", True)
        self._refresh()

    def skip_customers(self):
        """Section 2 skipped — customers can be added later in the Jobs app."""
        _set_job_skip("customers", True)
        self._refresh()

    def _poll(self):
        try:
            if not self.win.winfo_exists():
                return
        except self.tk.TclError:
            return
        if jobs_seen_on_phone():
            self.phone_lbl.config(text="✅ The Jobs app has been opened on a phone.", foreground="#2e7d32")
            return
        self.phone_lbl.config(text="⏳ Waiting for the Jobs app to be opened on a phone…")
        self.win.after(self.POLL_MS, self._poll)


class PaymentsFlow(_SimpleFlow):
    """Payment links — guide + check + $1 test link. The Small Business tab's
    Payment Links section owns the settings; this never writes them."""

    def __init__(self, panel: "SetupCenterPanel"):
        super().__init__(panel, "Payment links", "payments")
        ttk = self.ttk
        ttk.Label(self.body, justify="left", wraplength=520, text=(
            "Pick one (or both):\n"
            "• Stripe — paste your Secret Key (sk_live_…) and AI-Prowler makes a checkout link for each "
            "invoice's exact amount. Or paste a fixed Stripe payment link instead.\n"
            "• Square — paste your Access Token AND Location ID for exact-amount links, or a fixed "
            "Square payment link.\n"
            "Enter them on the Small Business tab → Payment Links, then Save.")).pack(anchor="w")
        links = ttk.Frame(self.body)
        links.pack(anchor="w", pady=(6, 0))
        ttk.Label(links, text="Get your keys:").pack(side="left", padx=(0, 6))
        import webbrowser
        for name, url in PAYMENT_KEY_PAGES:
            ttk.Button(links, text=name, command=lambda u=url: webbrowser.open(u)).pack(side="left", padx=2)
        self.state = ttk.Label(self.body, text="", justify="left")
        self.state.pack(anchor="w", pady=(10, 0))
        self.test_row = ttk.Frame(self.body)
        self.test_row.pack(anchor="w", pady=(6, 0))
        self._footer("🔄 Check again", self.check)
        self.check()

    def check(self):
        s = payment_status()
        label = {"automatic": "✅ exact-amount links", "fixed link": "✅ fixed payment link",
                 "incomplete": "❌ needs both the Access Token and the Location ID", "": "— not set"}
        self.state.config(text=(f"Stripe: {label[s['stripe']]}\n"
                                f"Square: {label[s['square']]}\n"
                                f"Pay Now button in emailed invoices: {'on' if s['email_on'] else 'off'}\n"
                                f"Payment link in texted invoices: {'on' if s['sms_on'] else 'off'}"
                                + ("" if s['sms_on'] else " (leave off until your texting registration "
                                   "allows links)")))
        for w in self.test_row.winfo_children():
            w.destroy()
        for prov in ("stripe", "square"):
            if s[prov] == "automatic":
                self.ttk.Button(self.test_row, text=f"🧪 Make a $1 {prov.capitalize()} test link",
                                command=lambda p=prov: self.test(p)).pack(side="left", padx=(0, 6))
        if detect_payments():
            self._say("✅ Payment links are set up." + (" Try a $1 test link — nothing is charged unless "
                                                        "you pay it." if "automatic" in (s["stripe"], s["square"])
                                                        else ""))
            self._done()
        else:
            self._say("Not set up yet — click Open this tab, fill in Payment Links, Save, then Check again.",
                      ok=False)

    def test(self, provider: str):
        """Make the $1 link in the background (Stripe/Square can take up to
        15 s) — the worker never touches Tk; the window collects the result."""
        import threading
        import webbrowser
        self._say(f"Making a $1 {provider.capitalize()} test link…")
        box = {}

        def work():
            try:
                box["url"] = make_test_payment_link(provider)
            except Exception as e:
                box["url"], box["err"] = "", str(e)

        def collect():
            try:
                if not self.win.winfo_exists():
                    return
            except self.tk.TclError:
                return
            if "url" not in box:
                return self.win.after(200, collect)
            if box["url"]:
                webbrowser.open(box["url"])
                self._say(f"✅ {provider.capitalize()} made a $1 checkout link and it opened in your browser. "
                          "Nothing is charged unless you pay it.")
            else:
                err = box.get("err", "")
                self._say(f"❌ {provider.capitalize()} didn't make a link — check the key on the Small Business "
                          "tab" + (f" ({err})" if err else "") + ".", ok=False)
        threading.Thread(target=work, daemon=True).start()
        self.win.after(200, collect)


class RoutesFlow(_SimpleFlow):
    """Crew routes: 1. where the day starts/ends (Route Origin Mode + Start/End
    address — job-database Settings, saved with AI-Prowler's own tools; the
    home address belongs to the Settings tab, which this opens), 2. email the
    route on build, 3. AI routing (optional): Claude Code installed? token ok?
    — with the free vs AI-usage explanation. Done = the address the chosen
    mode needs is set."""

    def __init__(self, panel: "SetupCenterPanel"):
        super().__init__(panel, "Crew routes", "routes")
        tk, ttk = self.tk, self.ttk
        s = route_settings()

        # 1. start / end
        box = ttk.LabelFrame(self.body, text=" 1. Where each day's route starts and ends ", padding=8)
        box.pack(fill="x")
        self.mode = tk.StringVar(master=self.body,
                                 value=s["Route Origin Mode"] if s["Route Origin Mode"] in ROUTE_MODES
                                 else "Jobs Only")
        ttk.Radiobutton(box, text="Jobs Only — the route is my jobs in order; mileage counts from my home "
                        "address", variable=self.mode, value="Jobs Only", command=self._mode_changed
                        ).pack(anchor="w")
        ttk.Radiobutton(box, text="Company Location — start and end every route at a shop / yard address",
                        variable=self.mode, value="Company Location", command=self._mode_changed).pack(anchor="w")
        self.addr = ttk.Frame(box)
        self.addr.pack(fill="x", padx=(20, 0), pady=(4, 0))
        self.addr_vars = {}
        for i, (key, label, width) in enumerate((("Start/End Street Address", "Street", 30),
                                                 ("Start/End City", "City", 16),
                                                 ("Start/End State", "State", 5),
                                                 ("Start/End ZIP", "ZIP", 8))):
            ttk.Label(self.addr, text=label).grid(row=0, column=i * 2, sticky="w", padx=(0 if i == 0 else 6, 2))
            v = tk.StringVar(master=self.body, value=s[key])
            self.addr_vars[key] = v
            ttk.Entry(self.addr, textvariable=v, width=width).grid(row=0, column=i * 2 + 1, sticky="w")
        self.home_row = ttk.Frame(box)
        self.home_row.pack(fill="x", padx=(20, 0), pady=(4, 0))
        self.origin_lbl = ttk.Label(box, text="", wraplength=520, justify="left")
        self.origin_lbl.pack(anchor="w", pady=(6, 0))

        # 2. email on build
        em = ttk.LabelFrame(self.body, text=" 2. Route email ", padding=8)
        em.pack(fill="x", pady=(8, 0))
        self.email_on = tk.BooleanVar(master=self.body,
                                      value=s["Email Route On Build"].lower() == "enabled")
        ttk.Checkbutton(em, text="Email me the route (stops, times, tap-to-navigate link) every time one is "
                        "built", variable=self.email_on).pack(anchor="w")
        ttk.Label(em, text="Either way, 📧 Email Approved Route Now (Jobs app → Route) sends it on request.",
                  foreground="#666").pack(anchor="w")

        # 3. AI routing
        ai = ttk.LabelFrame(self.body, text=" 3. AI routing (optional) ", padding=8)
        ai.pack(fill="x", pady=(8, 0))
        ttk.Label(ai, wraplength=520, justify="left", foreground="#555", text=(
            "Route Today is free and instant — it orders your jobs by drive time. Run AI Route reasons "
            "through fixed appointment times and fills gaps sensibly, but each run uses your Claude plan's "
            "usage. It needs Claude Code on this PC and a Claude token.")).pack(anchor="w")
        self.ai_lbl = ttk.Label(ai, text="Checking…", justify="left")
        self.ai_lbl.pack(anchor="w", pady=(6, 0))
        self.ai_fix = ttk.Frame(ai)
        self.ai_fix.pack(anchor="w", pady=(4, 0))

        self._footer("💾 Save", self.save)
        self._mode_changed()
        self._check_ai()

    # ── pieces ──────────────────────────────────────────────────────────────
    def _mode_changed(self):
        company = self.mode.get() == "Company Location"
        for w in self.addr.winfo_children():
            try:
                w.configure(state="normal" if company else "disabled")
            except self.tk.TclError:
                pass
        for w in self.home_row.winfo_children():
            w.destroy()
        if not company:
            home = home_address()
            self.ttk.Label(self.home_row, text=f"Home address: {home}" if home else
                           "Home address: not set yet").pack(side="left")
            self.ttk.Button(self.home_row, text="Set it on the Settings tab" if not home else "Change it",
                            command=self._open_settings).pack(side="left", padx=8)
        self._show_origin()

    def _show_origin(self):
        s = route_settings()
        s["Route Origin Mode"] = self.mode.get()
        for k, v in self.addr_vars.items():
            s[k] = v.get().strip()
        ok, msg = route_origin_ok(s)
        self.origin_lbl.config(text=("✅ " if ok else "❌ ") + msg, foreground="#2e7d32" if ok else "#b00020")
        return ok

    def _open_settings(self):
        nb = getattr(self.app, "notebook", None)
        if nb is not None:
            for t in nb.tabs():
                if nb.tab(t, "text").strip() == "⚙️ Settings":
                    nb.select(t)

    def _check_ai(self):
        import threading
        box = {}
        threading.Thread(target=lambda: box.setdefault("s", ai_routing_status()), daemon=True).start()

        def collect():
            try:
                if not self.win.winfo_exists():
                    return
            except self.tk.TclError:
                return
            if "s" not in box:
                return self.win.after(200, collect)
            st = box["s"]
            tok = {"ok": "✅ Claude token ok", "expiring_soon": "⚠️ Claude token expires within 7 days",
                   "expired": "❌ Claude token expired", "no_credentials": "❌ no Claude token yet",
                   "unreadable": "❌ Claude token unreadable"}.get(st["token"], "❓ Claude token unknown")
            self.ai_lbl.config(text=("✅ Claude Code installed" if st["cli"] else "❌ Claude Code not installed")
                               + "   ·   " + tok)
            for w in self.ai_fix.winfo_children():
                w.destroy()
            if not st["cli"]:
                self.ttk.Button(self.ai_fix, text="Install Claude Code", command=self._install_cli
                                ).pack(side="left", padx=(0, 6))
            if st["token"] != "ok":
                self.ttk.Button(self.ai_fix, text="🔑 Get / Renew Token (Links & Analysis)",
                                command=lambda: self.panel.open_tab(BY_ID["links"])).pack(side="left")
        self.win.after(200, collect)

    def _install_cli(self):
        import threading
        self._say("Installing Claude Code (Anthropic's official installer) — this can take a minute…")
        box = {}

        def work():
            try:
                import task_queue_automation as tqa
                box["r"] = tqa.install_claude_code_cli()
            except Exception as e:
                box["r"] = (False, str(e))

        def collect():
            try:
                if not self.win.winfo_exists():
                    return
            except self.tk.TclError:
                return
            if "r" not in box:
                return self.win.after(500, collect)
            ok, msg = box["r"]
            self._say(("✅ " if ok else "❌ ") + str(msg)[:200], ok=ok)
            self._check_ai()
        threading.Thread(target=work, daemon=True).start()
        self.win.after(500, collect)

    # ── save ────────────────────────────────────────────────────────────────
    def save(self):
        cur = route_settings()
        want = {"Route Origin Mode": self.mode.get(),
                "Email Route On Build": "Enabled" if self.email_on.get() else "Disabled"}
        if self.mode.get() == "Company Location":
            want.update({k: v.get().strip() for k, v in self.addr_vars.items()})
        errors, saved = [], 0
        for k, v in want.items():
            if cur.get(k, "") == v:
                continue
            try:
                res = save_setting(k, v)
            except Exception as e:
                res = f"❌ {e}"
            if res.lstrip().startswith("❌"):
                errors.append(f"{k}: {res.strip()[:100]}")
            else:
                saved += 1
        if errors:
            return self._say("Not saved — " + "; ".join(errors), ok=False)
        ok = self._show_origin()
        self._say((f"✅ Saved {saved} setting{'s' if saved != 1 else ''}." if saved else "Nothing changed.")
                  + ("" if ok else " Still needed: see ❌ above."), ok=ok)
        if ok:
            self._done()


def bearer_token() -> str:
    """The personal Bearer Token (config.json remote_token) — for the desktop's
    own 'Copy Bearer Token' button only."""
    try:
        return str(json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig")).get("remote_token", "")).strip()
    except (OSError, ValueError):
        return ""


# Modules with a guided step-by-step window (the rest open their tab until
# their phase is built). Filled in as each phase lands.
GUIDED: dict = {"index": IndexFirstFolderFlow,
                "connect_ai": lambda panel: ConnectAIFlow(panel.frame, panel.app, panel),
                "auto_index": AutoIndexFlow,
                "links": LinksFlow,
                "learnings": LearningsFlow,
                "email": EmailFlow,
                "remote": RemoteFlow,
                "remote_pwa": RemotePwaFlow,
                "jobs": JobsFlow,
                "payments": PaymentsFlow,
                "routes": RoutesFlow}


def build_setup_center(parent, app) -> Optional[SetupCenterPanel]:
    """Called from the Home tab. Never breaks the Home page: any error just
    leaves the panel out (and is printed for the log)."""
    try:
        return SetupCenterPanel(parent, app)
    except Exception as e:                           # pragma: no cover — defensive
        print(f"Setup Center unavailable: {e}")
        return None
