"""Service Desk settings on AI-Prowler's 🏢 Small Business tab (2026-10-30, David).

David 2026-10-30:
  1. "For the server mode where we have multiple users, remove the setting tab in the
     desk help PWA app and move them to the AI-Prowler Business tab setting area. In
     the personal mode … keep the setting tab as is and add to the Service Desk Agent
     section all the setting in the PWA App."
  2. "Make the whole Service Desk Agent hide except for the main section name that
     says (not enabled) when in the home page Service Desk is not selected, then if
     selected, the whole Service Desk Agent shows … (enabled in green) and the user can
     select (toggle) of all the setting to be hidden or show."

So, in BOTH modes, one section "🤖 Service Desk Agent" holds every setting the
Service Desk app's ⚙ Settings tab has, in four tabs:
  ⚙ General · 💾 Data & backups · 👥 Team (server only) · 🤖 Agent (desk_gui_agent)
The app keeps its Settings tab on a personal install only (desk/index.html).

"Selected on the home page" = Service Desk (tickets) switched on — the Setup Center
item and Settings → MCP Tool Configuration set the same switch
(desk_gui_links.desk_switched_on). The section re-checks it each time the tab is
shown. The Show/Hide choice is remembered in <state>/desk_gui_state.json.

Everything here writes through the same functions the app's API uses (desk_db,
desk_data, desk_backup, desk_routing), as the owner (actor None). Kept out of
rag_gui.py so the logic can be tested without building the GUI.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

GREEN, GREY = "#15803d", "#6b7280"
STATE_FILE = "desk_gui_state.json"

# Same rows, same words as the app's Settings tab (desk/index.html showSettings).
GENERAL_ROWS = (
    ("own_tickets", "I can file tickets to myself", "solo"),
    ("subcontractor_tickets", "I can open tickets about a subcontractor", None),
    ("sms_fallback_default", "New tickets also alert by text (SMS)", None),
    ("portal_enabled", "Customers can request service online (/support/new)", None),
    ("email_intake", "Read our email account for ticket replies", None),
    ("csat_enabled", "Ask customers to rate closed requests", None),
    ("customer_status_updates", "Tell customers (one line) when their request is in progress and when it's closed", None),
)
MODE_ROWS = (
    ("sms_new_request_mode", "A text that isn't a reply to a ticket",
     (("off", "Do nothing"), ("ask", "Ask if they want a request opened"),
      ("link", "Text back the request-form link"), ("create", "Open a ticket automatically"))),
    ("email_new_request_mode", "An email that isn't a reply to a ticket",
     (("off", "Do nothing"), ("create", "Open a ticket automatically"))),
)
BACKUP_KEYS = ("backup_enabled", "backup_frequency", "backup_hour", "backup_keep_daily",
               "backup_keep_weekly", "backup_keep_monthly", "backup_attachments", "backup_second_dir")
EXPORT_FORMATS = (("xlsx", "Excel", ".xlsx"), ("csv", "CSV", ".zip"),
                  ("json", "Full (moves to another Service Desk)", ".zip"))


# ── switched on? shown or hidden? ────────────────────────────────────────────

def section_status() -> dict:
    """Is Service Desk switched on (Setup Center / MCP Tool Configuration)?"""
    try:
        import desk_gui_links
        on = bool(desk_gui_links.desk_switched_on())
    except Exception:  # noqa: BLE001
        on = True
    return {"enabled": on, "text": "(enabled)" if on else "(not enabled)", "color": GREEN if on else GREY}


def agent_status(db: str | None = None) -> dict:
    """The Service Desk Agent's own switches as SAVED (David 2026-10-31: the header should show
    practice mode): "· 🤖 agent off" / "· 🤖 agent on — practice mode" / "· 🤖 agent on",
    plus booking when the agent is on: "· 📅 booking on — practice mode" etc."""
    try:
        import desk_db
        if db is None:
            import desk_gui_agent
            db, _ed = desk_gui_agent.db_and_edition()
        s = desk_db.get_settings(db)
    except Exception:  # noqa: BLE001
        return {"text": "", "color": GREY, "on": False, "practice": False}

    def word(on, practice):
        return "off" if not on else ("on — practice mode" if practice else "on")

    on, practice = bool(s.get("agent_enabled")), bool(s.get("agent_shadow"))
    text = f"· 🤖 agent {word(on, practice)}"
    live = on and not practice
    if on:
        bon, bpr = bool(s.get("agent_bk_enabled")), bool(s.get("agent_bk_shadow"))
        text += f" · 📅 booking {word(bon, bpr)}"
        live = live or (bon and not bpr)
    color = GREY if not on else (GREEN if live else das_practice_color())
    return {"text": text, "color": color, "on": on, "practice": on and practice}


def das_practice_color() -> str:
    try:
        import desk_agent_settings as das
        return das.MODE_COLORS["practice"]
    except Exception:  # noqa: BLE001
        return "#7c3aed"


def _state_path() -> Path:
    import desk_gui_links
    return desk_gui_links._state_dir() / STATE_FILE


def load_show() -> bool:
    try:
        return bool(json.loads(_state_path().read_text(encoding="utf-8")).get("show_settings", True))
    except Exception:  # noqa: BLE001
        return True


def save_show(show: bool) -> None:
    p = _state_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps({"show_settings": bool(show)}), encoding="utf-8")
        tmp.replace(p)
    except Exception:  # noqa: BLE001 — a preference, never worth an error box
        pass


# ── ⚙ General ────────────────────────────────────────────────────────────────

def general_rows(edition: str) -> list:
    return [(k, lab) for k, lab, only in GENERAL_ROWS if only is None or (only == "solo" and edition == "solo")]


SMS_NOTE = ("Texting isn't set up or is switched off — alerts go by email and phone notification only. "
            "Turn on SMS & WhatsApp (Settings → MCP Tool Configuration) and set up a text provider to send texts.")


def gui_channels() -> dict:
    """{"email": bool, "sms": bool}: can AI-Prowler email / text right now? The same test the
    server uses (ai_prowler_mcp._desk_configure_alerts → desk_portal.channels), done here
    because this screen runs outside the server, where desk_portal.channels() can't tell
    (it said "no email" even when email worked — fixed 2026-10-30)."""
    import desk_gui_links
    email = False
    try:
        raw = json.loads((desk_gui_links._state_dir() / "email_config.json").read_text(encoding="utf-8"))
        email = isinstance(raw, dict) and bool(
            raw.get("smtp_host") or (raw.get("backend") in ("outlook", "outlook+smtp") and raw.get("username")))
    except Exception:  # noqa: BLE001
        pass
    sms = False
    try:
        from sms_backends import get_sms_backend, load_sms_config
        sms = bool(get_sms_backend(load_sms_config()).validate_config()[0])
        if sms:
            import tool_config_store as tcs
            sms = bool(tcs.group_enabled(desk_gui_links.mode_of(), "sms_whatsapp"))
    except Exception:  # noqa: BLE001
        sms = False
    return {"email": email, "sms": sms}


def sms_note(pc: dict | None = None) -> str:
    """Shown under "New tickets also alert by text" when texts can't actually go out."""
    pc = gui_channels() if pc is None else pc
    return "" if pc.get("sms") else SMS_NOTE


def portal_note(pc: dict | None = None) -> str:
    pc = gui_channels() if pc is None else pc
    if not pc.get("email"):
        return "Set up email in AI-Prowler first — the request form stays off until email works."
    return ("Customers can get their code by text or email." if pc.get("sms") else
            "Customers get their code by email (texting isn't set up or is switched off, so the form has no mobile box).")


def set_one(db: str, key: str, value, edition: str) -> tuple[bool, str]:
    import desk_db
    try:
        desk_db.set_setting(db, key, value, actor=None, edition=edition)
        return True, "Saved."
    except desk_db.DeskError as e:
        return False, str(e)


def save_auto_close(db: str, text: str, edition: str) -> tuple[bool, str]:
    try:
        n = int(str(text).strip())
    except ValueError:
        return False, "Enter 0 to 60 days."
    if not 0 <= n <= 60:
        return False, "Enter 0 to 60 days."
    return set_one(db, "auto_close_days", n, edition)


def save_alerts(db: str, email: str, phone: str, edition: str) -> tuple[bool, str]:
    for k, v in (("alert_email", email), ("alert_phone", phone)):
        ok, msg = set_one(db, k, str(v or "").strip(), edition)
        if not ok:
            return ok, msg
    return True, "Saved."


# ── 💾 Data & backups ────────────────────────────────────────────────────────

def export_to(db: str, fmt: str, dest: str, edition: str) -> str:
    import desk_data
    _name, data, _mime = desk_data.export(db, fmt, actor=None, edition=edition)
    Path(dest).write_bytes(data)
    return dest


def export_name(db: str, fmt: str, edition: str) -> str:
    import desk_data
    return desk_data.export(db, fmt, actor=None, edition=edition)[0]


def import_file(db: str, path: str, edition: str, *, dry_run: bool) -> dict:
    import desk_backup
    import desk_data
    p = Path(path)
    return desk_data.import_tickets(db, p.read_bytes(), p.name, actor=None, edition=edition, dry_run=dry_run,
                                    backup_fn=lambda trig: desk_backup.backup_now(db, trig))


def import_summary(r: dict) -> str:
    head = ("Dry run — nothing imported yet." if r.get("dry_run")
            else f"Imported as {r.get('batch_id')} (undo for 7 days).")
    lines = [head, f"Rows: {r.get('rows', 0)}, to add: {r.get('to_add', 0)}, "
                   f"duplicates: {len(r.get('duplicates') or [])}, invalid: {len(r.get('invalid') or [])}"]
    lines += [f"  row {x.get('row')}: {', '.join(x.get('problems') or [])}" for x in (r.get("invalid") or [])[:10]]
    return "\n".join(lines)


def undo_import(db: str, batch_id: str, edition: str) -> int:
    import desk_data
    return len(desk_data.undo_import(db, batch_id.strip(), actor=None, edition=edition).get("removed") or [])


def backup_rows(db: str) -> list:
    import desk_backup
    out = []
    for b in desk_backup.list_backups(db)[:30]:
        out.append((b["name"], f"{str(b.get('made_at', '')).replace('T', ' ')[:16]} · {b.get('trigger', '')} · "
                               f"{max(1, round((b.get('bytes') or 0) / 1024))} KB · "
                               f"{'✔ verified' if b.get('verified') else '⚠ not verified'}"))
    return out


def backup_now(db: str) -> dict:
    import desk_backup
    return desk_backup.backup_now(db, "manual")


def copy_backup(db: str, name: str, dest: str) -> str:
    import desk_backup
    src = desk_backup.backup_dir(db) / name
    shutil.copyfile(src, dest)
    return dest


def restore_backup(db: str, name: str, ticket_id: str, edition: str) -> dict:
    import desk_backup
    return desk_backup.restore(db, name, actor=None, edition=edition, confirm=True,
                               ticket_id=(ticket_id or "").strip().upper())


def save_backup_settings(db: str, form: dict, edition: str) -> tuple[bool, str]:
    vals, problems = {}, []
    for k in BACKUP_KEYS:
        if k not in form:
            continue
        v = form[k]
        if k in ("backup_enabled", "backup_attachments"):
            vals[k] = bool(v)
        elif k in ("backup_frequency", "backup_second_dir"):
            vals[k] = str(v or "").strip()
        else:
            try:
                vals[k] = int(str(v).strip())
            except ValueError:
                problems.append(f"{k.replace('backup_', '').replace('_', ' ')}: enter a whole number")
    for k, v in vals.items():
        ok, msg = set_one(db, k, v, edition)
        if not ok:
            problems.append(msg)
    return (not problems, "Saved." if not problems else "Not saved: " + "; ".join(problems))


# ── 👥 Team (server) ─────────────────────────────────────────────────────────

def team(db: str) -> dict:
    import desk_routing as rt
    return {"queues": rt.list_queues(db), "rules": rt.list_rules(db), "types": rt.list_types(db)}


def save_queue(db: str, queue_id: str, name: str, members: str, edition: str):
    import desk_routing as rt
    mem = [m.strip() for m in (members or "").split(",") if m.strip()]
    return rt.upsert_queue(db, queue_id.strip(), name=name.strip(), members=mem, actor=None, edition=edition)


def delete_queue(db: str, queue_id: str, edition: str) -> None:
    import desk_routing as rt
    rt.delete_queue(db, queue_id, actor=None, edition=edition)


def save_rule(db: str, rule_id: str, on: str, value: str, to: str, target: str, order, edition: str):
    import desk_routing as rt
    return rt.upsert_rule(db, rule_id.strip(), match={on: value.strip()}, action={to: target.strip()},
                          sort_order=int(order or 100), enabled=True, actor=None, edition=edition)


def delete_rule(db: str, rule_id: str, edition: str) -> None:
    import desk_routing as rt
    rt.delete_rule(db, rule_id, actor=None, edition=edition)


def save_type(db: str, type_id: str, name: str, default_queue: str, edition: str):
    import desk_routing as rt
    return rt.upsert_type(db, type_id.strip(), name=name.strip(), kind="external",
                          default_queue=default_queue.strip() or None, default_priority="P3",
                          actor=None, edition=edition)


# ── the section (Tk) ─────────────────────────────────────────────────────────

def build_section(app, parent) -> dict:
    """Build the whole "🤖 Service Desk Agent" section inside `parent` (the Business
    tab banner). Returns {"frame", "status", "rebuild"} for tests and rag_gui."""
    import tkinter as tk
    from tkinter import ttk

    try:
        import desk_gui_agent
        desk_gui_agent.no_wheel_changes(parent)        # scrolling never changes a setting (2026-10-31)
    except Exception:  # noqa: BLE001
        pass
    head = ttk.Frame(parent)
    ttk.Label(head, text="🤖 Service Desk Agent & settings", font=("Arial", 9, "bold")).pack(side="left")
    status_lbl = tk.Label(head, font=("Arial", 9, "bold"))
    status_lbl.pack(side="left", padx=(6, 0))
    agent_lbl = tk.Label(head, font=("Arial", 9, "bold"))       # the agent's own on / practice (2026-10-31)
    agent_lbl.pack(side="left", padx=(6, 0))
    lf = ttk.LabelFrame(parent, labelwidget=head, padding=(8, 4))
    lf.pack(fill="x", pady=(8, 0))
    body = ttk.Frame(lf)
    body.pack(fill="x")
    state = {"enabled": None}
    out = {"frame": lf, "status": status_lbl, "agent_status": agent_lbl}

    def refresh_agent(*_):
        a = agent_status() if state["enabled"] else {"text": "", "color": GREY}
        agent_lbl.configure(text=a["text"], foreground=a["color"])

    out["refresh_agent"] = refresh_agent

    def rebuild(force: bool = False):
        st = section_status()
        status_lbl.configure(text=st["text"], foreground=st["color"])
        if st["enabled"] == state["enabled"] and not force:
            refresh_agent()
            return
        state["enabled"] = st["enabled"]
        refresh_agent()
        for w in body.winfo_children():
            w.destroy()
        if not st["enabled"]:
            ttk.Label(body, font=("Arial", 8), foreground="gray", wraplength=900, justify="left",
                      text=("Service Desk is not switched on. Select \"Service Desk (tickets)\" on the Home page "
                            "(Setup Center) — or in Settings → MCP Tool Configuration — and restart AI-Prowler; "
                            "the Service Desk and agent settings then appear here.")).pack(anchor="w")
            return
        _build_enabled(app, body, out)

    out["rebuild"] = rebuild
    lf.bind("<Map>", lambda _e: rebuild(), add="+")     # re-check each time the tab is shown
    rebuild()
    return out


def _build_enabled(app, body, out: dict) -> None:
    import tkinter as tk
    from tkinter import ttk

    import desk_gui_agent
    db, edition = desk_gui_agent.db_and_edition()
    show = tk.BooleanVar(value=load_show())
    top = ttk.Frame(body); top.pack(fill="x")
    ttk.Checkbutton(top, text="Show settings", variable=show).pack(side="left")
    where = ("On a server these settings live only here — the Service Desk app has no Settings tab."
             if edition == "business" else
             "Same settings as the Service Desk app → ⚙ Settings; change them in either place.")
    ttk.Label(top, text=where, font=("Arial", 8), foreground="gray").pack(side="left", padx=(12, 0))
    content = ttk.Frame(body)
    nb = ttk.Notebook(content)
    nb.pack(fill="x", pady=(4, 0))
    tabs = {}
    for key, title in (("general", "⚙ General"), ("data", "💾 Data & backups"),
                       ("team", "👥 Team"), ("web", "🌐 Web forms"), ("agent", "🤖 Agent")):
        if key == "team" and edition != "business":
            continue
        f = ttk.Frame(nb, padding=(8, 6))
        nb.add(f, text=title)
        tabs[key] = f
    _build_general(app, tabs["general"], db, edition)
    _build_data(app, tabs["data"], db, edition)
    if "team" in tabs:
        _build_team(app, tabs["team"], db, edition)
    _build_webforms(app, tabs["web"], db, edition)
    desk_gui_agent.build_agent_settings(app, tabs["agent"], on_saved=out.get("refresh_agent"))

    def apply(*_):
        if show.get():
            content.pack(fill="x")
        else:
            content.pack_forget()
        save_show(show.get())

    show.trace_add("write", apply)
    apply()
    out.update(show=show, notebook=nb, tabs=tabs, content=content)


def _calm(combo):
    """No lingering dark highlight after picking from a drop-down (desk_gui_agent.calm)."""
    import desk_gui_agent
    return desk_gui_agent.calm(combo)


def _say(app, ok: bool, msg: str, title: str = "Service Desk"):
    from tkinter import messagebox
    if ok:
        app.status_var.set(f"🎫  {msg}")
        try:
            app.root.after(3000, lambda: app.status_var.set("Ready"))
        except Exception:  # noqa: BLE001
            pass
    else:
        messagebox.showwarning(title, msg)


def _build_general(app, f, db, edition):
    import tkinter as tk
    from tkinter import ttk

    import desk_db
    s = desk_db.get_settings(db)
    small = ("Arial", 8)
    pc = gui_channels()
    for key, label in general_rows(edition):
        var = tk.BooleanVar(value=bool(s.get(key)))

        def toggled(k=key, v=var):
            ok, msg = set_one(db, k, bool(v.get()), edition)
            if not ok:
                v.set(not v.get())
            _say(app, ok, msg)
        ttk.Checkbutton(f, text=label, variable=var, command=toggled).pack(anchor="w")
        if key == "portal_enabled":
            ttk.Label(f, text=portal_note(pc), font=small, foreground="gray").pack(anchor="w", padx=(22, 0))
        if key == "sms_fallback_default" and sms_note(pc):
            ttk.Label(f, text=sms_note(pc), font=small, foreground="#b45309", wraplength=760,
                      justify="left").pack(anchor="w", padx=(22, 0))
    for key, label, choices in MODE_ROWS:
        r = ttk.Frame(f); r.pack(fill="x", pady=(4, 0))
        ttk.Label(r, text=label, width=36, font=small).pack(side="left")
        var = tk.StringVar(value=dict(choices).get(s.get(key), choices[0][1]))
        cb = _calm(ttk.Combobox(r, textvariable=var, state="readonly", width=34, values=[lab for _, lab in choices]))
        cb.pack(side="left")

        def picked(_e=None, k=key, v=var, ch=choices):
            ok, msg = set_one(db, k, {lab: val for val, lab in ch}[v.get()], edition)
            _say(app, ok, msg)
        cb.bind("<<ComboboxSelected>>", picked)
    r = ttk.Frame(f); r.pack(fill="x", pady=(6, 0))
    ttk.Label(r, text="Close a Fixed customer ticket after this many days with no reply (0 = never)",
              font=small).pack(side="left")
    days = tk.StringVar(value=str(s.get("auto_close_days", 0)))
    ttk.Spinbox(r, textvariable=days, from_=0, to=60, width=4).pack(side="left", padx=(6, 4))
    ttk.Button(r, text="Save", command=lambda: _say(app, *save_auto_close(db, days.get(), edition))).pack(side="left")
    if edition == "solo":
        al = ttk.LabelFrame(f, text="My alerts", padding=(6, 4)); al.pack(fill="x", pady=(6, 0))
        em, ph = tk.StringVar(value=s.get("alert_email", "")), tk.StringVar(value=s.get("alert_phone", ""))
        r = ttk.Frame(al); r.pack(fill="x")
        ttk.Label(r, text="Send my alerts to (email)", font=small, width=24).pack(side="left")
        ttk.Entry(r, textvariable=em, width=34).pack(side="left")
        r = ttk.Frame(al); r.pack(fill="x", pady=(2, 0))
        ttk.Label(r, text="My mobile for text alerts", font=small, width=24).pack(side="left")
        ttk.Entry(r, textvariable=ph, width=20).pack(side="left")
        ttk.Button(al, text="Save alert contacts",
                   command=lambda: _say(app, *save_alerts(db, em.get(), ph.get(), edition))).pack(anchor="w", pady=(4, 0))


def _build_data(app, f, db, edition):
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk

    import desk_db
    small = ("Arial", 8)
    # export
    ex = ttk.LabelFrame(f, text="Export", padding=(6, 4)); ex.pack(fill="x")
    for fmt, label, _ext in EXPORT_FORMATS:
        def do_export(fm=fmt):
            try:
                name = export_name(db, fm, edition)
                dest = filedialog.asksaveasfilename(title="Save export", initialfile=name)
                if dest:
                    export_to(db, fm, dest, edition)
                    _say(app, True, f"Exported to {dest}")
            except Exception as e:  # noqa: BLE001
                messagebox.showerror("Export", str(e))
        ttk.Button(ex, text=label, command=do_export).pack(side="left", padx=(0, 4))
    # import
    im = ttk.LabelFrame(f, text="Import (.csv, .xlsx or a full export .zip)", padding=(6, 4))
    im.pack(fill="x", pady=(6, 0))
    path = tk.StringVar()
    r = ttk.Frame(im); r.pack(fill="x")
    ttk.Button(r, text="Choose file…", command=lambda: path.set(filedialog.askopenfilename(
        title="Import tickets", filetypes=[("Tickets", "*.csv *.xlsx *.zip"), ("All files", "*.*")]) or path.get())
               ).pack(side="left")
    ttk.Label(r, textvariable=path, font=small).pack(side="left", padx=(6, 0))
    outbox = tk.Text(im, height=4, width=90, font=("Consolas", 8))
    r2 = ttk.Frame(im); r2.pack(fill="x", pady=(4, 0))
    go = ttk.Button(r2, text="Import now")

    def run(dry: bool):
        if not path.get():
            messagebox.showwarning("Import", "Choose a file first."); return
        if not dry and not messagebox.askyesno("Import", "Import now? A backup is taken first."):
            return
        try:
            res = import_file(db, path.get(), edition, dry_run=dry)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Import", str(e)); return
        outbox.delete("1.0", "end"); outbox.insert("1.0", import_summary(res))
        go.state(["!disabled"] if dry and res.get("to_add") else ["disabled"])

    ttk.Button(r2, text="Check file (dry run)", command=lambda: run(True)).pack(side="left")
    go.configure(command=lambda: run(False)); go.pack(side="left", padx=(4, 0)); go.state(["disabled"])
    outbox.pack(fill="x", pady=(4, 0))
    r3 = ttk.Frame(im); r3.pack(fill="x", pady=(4, 0))
    batch = tk.StringVar()
    ttk.Entry(r3, textvariable=batch, width=24).pack(side="left")

    def undo():
        if not batch.get().strip() or not messagebox.askyesno("Undo import", f"Remove every ticket imported in {batch.get()}?"):
            return
        try:
            _say(app, True, f"Removed {undo_import(db, batch.get(), edition)} ticket(s).")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Undo import", str(e))
    ttk.Button(r3, text="Undo import (batch id IMP-…)", command=undo).pack(side="left", padx=(4, 0))
    # backups
    bk = ttk.LabelFrame(f, text="Backups", padding=(6, 4)); bk.pack(fill="x", pady=(6, 0))
    lst = tk.Listbox(bk, height=6, width=90, font=("Consolas", 8))
    names: list = []

    def reload():
        lst.delete(0, "end"); names.clear()
        for n, text in backup_rows(db):
            names.append(n); lst.insert("end", text)
        if not names:
            lst.insert("end", "No backups yet.")

    def chosen():
        sel = lst.curselection()
        if not sel or sel[0] >= len(names):
            messagebox.showwarning("Backups", "Pick a backup in the list first."); return None
        return names[sel[0]]

    def now():
        try:
            r = backup_now(db)
            _say(app, True, f"Backed up ({'verified' if r.get('verified') else 'NOT verified'}).")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Backups", str(e))
        reload()

    def save_copy():
        n = chosen()
        if n:
            dest = filedialog.asksaveasfilename(title="Save a copy of the backup", initialfile=n)
            if dest:
                _say(app, True, f"Saved {copy_backup(db, n, dest)}")

    def restore():
        n = chosen()
        if not n:
            return
        one = simpledialog.askstring("Restore", "Restore ONE ticket? Enter its number (e.g. T-0042), "
                                                "or leave blank to restore EVERYTHING.", parent=lst)
        if one is None:
            return
        what = f"ticket {one.strip().upper()}" if one.strip() else "ALL Service Desk data"
        if not messagebox.askyesno("Restore", f"Replace {what} with the copy in this backup? "
                                              "A safety backup is taken first."):
            return
        try:
            r = restore_backup(db, n, one, edition)
            _say(app, True, f"Restored {r.get('restored')}. Safety backup: {r.get('safety_backup')}")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Restore", str(e))
        reload()

    import desk_backup
    from desk_gui_agent import _tooltip
    H = desk_backup.BACKUP_HELP
    # where the backups live (2026-10-30: "list where the backup lives and allow the user to
    # set the default to a different folder")
    folder_var = tk.StringVar()

    def show_folder():
        d = desk_backup.backup_dir(db)
        std = d == desk_backup.default_backup_dir(db)
        folder_var.set(f"Saved in: {d}" + ("   (standard place)" if std else ""))

    def open_folder():
        d = desk_backup.backup_dir(db)
        d.mkdir(parents=True, exist_ok=True)
        try:
            import os
            os.startfile(str(d))                          # Windows Explorer
        except Exception as e:  # noqa: BLE001
            messagebox.showinfo("Backups", f"Backups are in:\n{d}\n\n({e})")

    def change_folder(path: str | None = None):
        new = path if path is not None else filedialog.askdirectory(title="Save Service Desk backups in…")
        if new is None or (path is None and not new):
            return
        try:
            r_ = desk_backup.set_backup_folder(db, new, edition=edition)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Backup folder", str(e)); return
        show_folder(); reload()
        _say(app, True, f"Backups now save in {r_['folder']}" + (f" — moved {r_['moved']} existing backup(s)"
                                                                 if r_["moved"] else ""))

    fr = ttk.Frame(bk); fr.pack(fill="x", pady=(0, 4))
    fl = ttk.Label(fr, textvariable=folder_var, font=small)
    fl.pack(side="left")
    _tooltip(fl, H["backup_dir"])
    ttk.Button(fr, text="Open folder", command=open_folder).pack(side="left", padx=(8, 0))
    b_change = ttk.Button(fr, text="Change…", command=change_folder)
    b_change.pack(side="left", padx=(4, 0))
    _tooltip(b_change, H["backup_dir"])
    ttk.Button(fr, text="Use standard place", command=lambda: change_folder("")).pack(side="left", padx=(4, 0))
    show_folder()

    r = ttk.Frame(bk); r.pack(fill="x")
    ttk.Button(r, text="Back up now", command=now).pack(side="left")
    ttk.Button(r, text="Save a copy…", command=save_copy).pack(side="left", padx=(4, 0))
    ttk.Button(r, text="Restore…", command=restore).pack(side="left", padx=(4, 0))
    lst.pack(fill="x", pady=(4, 0))
    reload()
    # automatic backups — every setting has a hover explanation (2026-10-30)
    s = desk_db.get_settings(db)
    au = ttk.LabelFrame(f, text="Automatic backups  (hover over a setting for what it does)", padding=(6, 4))
    au.pack(fill="x", pady=(6, 0))
    v = {"backup_enabled": tk.BooleanVar(value=bool(s["backup_enabled"])),
         "backup_attachments": tk.BooleanVar(value=bool(s["backup_attachments"])),
         "backup_frequency": tk.StringVar(value=s["backup_frequency"]),
         "backup_second_dir": tk.StringVar(value=s["backup_second_dir"])}
    for k in ("backup_hour", "backup_keep_daily", "backup_keep_weekly", "backup_keep_monthly"):
        v[k] = tk.StringVar(value=str(s[k]))
    r = ttk.Frame(au); r.pack(fill="x")
    ttk.Checkbutton(r, text="On", variable=v["backup_enabled"]).pack(side="left")
    w = ttk.Label(r, text="How often", font=small); w.pack(side="left", padx=(12, 4)); _tooltip(w, H["backup_frequency"])
    w = _calm(ttk.Combobox(r, textvariable=v["backup_frequency"], state="readonly", width=8,
                           values=["hourly", "daily", "weekly"]))
    w.pack(side="left"); _tooltip(w, H["backup_frequency"])
    w = ttk.Label(r, text="At hour (0-23)", font=small); w.pack(side="left", padx=(12, 4)); _tooltip(w, H["backup_hour"])
    w = ttk.Spinbox(r, textvariable=v["backup_hour"], from_=0, to=23, width=4); w.pack(side="left")
    _tooltip(w, H["backup_hour"])
    r = ttk.Frame(au); r.pack(fill="x", pady=(2, 0))
    for k, lab in (("backup_keep_daily", "Keep daily"), ("backup_keep_weekly", "weekly"),
                   ("backup_keep_monthly", "monthly")):
        tip = H[k] + "\n\n" + H["retention"]
        w = ttk.Label(r, text=lab, font=small); w.pack(side="left", padx=(0, 4)); _tooltip(w, tip)
        w = ttk.Spinbox(r, textvariable=v[k], from_=1, to=365, width=4); w.pack(side="left", padx=(0, 10))
        _tooltip(w, tip)
    w = ttk.Label(r, text="ⓘ", font=("Arial", 10), foreground="#2563eb"); w.pack(side="left")
    _tooltip(w, "\n\n".join([H["backup_keep_daily"], H["backup_keep_weekly"], H["backup_keep_monthly"],
                             H["retention"]]), wrap=420)
    w = ttk.Checkbutton(au, text="Include photos and documents", variable=v["backup_attachments"])
    w.pack(anchor="w"); _tooltip(w, H["backup_attachments"])
    r = ttk.Frame(au); r.pack(fill="x", pady=(2, 0))
    w = ttk.Label(r, text="Second copy to (drive, NAS or synced folder — optional)", font=small)
    w.pack(side="left"); _tooltip(w, H["backup_second_dir"])
    ttk.Entry(r, textvariable=v["backup_second_dir"], width=36).pack(side="left", padx=(4, 4))
    ttk.Button(r, text="Browse…", command=lambda: v["backup_second_dir"].set(
        filedialog.askdirectory(title="Second backup folder") or v["backup_second_dir"].get())).pack(side="left")
    ttk.Button(au, text="Save backup settings", command=lambda: _say(
        app, *save_backup_settings(db, {k: x.get() for k, x in v.items()}, edition))).pack(anchor="w", pady=(4, 0))


# ── 🌐 Web forms (2026-10-30, booking-spec.md §9.1) ─────────────────────────

# 2026-11-02 (David: "it's not clear ... the difference between Book a service and request a new service"):
# the same names and one-line explanations the customer page shows.
PATH_LABELS = {"book": "📅 Book a service — pick an open time online",
               "buy": "🛒 Shop products — photos, specs, order and pay online",
               "new": "✨ Get a quote — they tell you what they need, you call to quote and schedule",
               "problem": "🛠 Report a problem — something wrong after a visit or with a purchase"}
PATH_HELP = {
    "book": ("Customers pick an arrival window from your live schedule (plus backups). Open times are worked out "
             "the moment the page loads, from the Jobs app's jobs and Working Days/hours — and on a personal "
             "install also your Google Calendar's busy times (as of its last sync); a cancelled or moved job "
             "frees its time at once. The time is held and waits for your OK in the Service Desk app → "
             "📅 To approve — unless you change 'Approving bookings' below."),
    "buy": ("The Shop: every product (Type = Product, ticked Online) as a card with its photos, price and specs "
            "(Details… in the list below). One with a Base Price in Services & Pricing can be ordered — how "
            "many, and where to ship it; one without a price shows \"Ask about it\" (a quote request). The total adds your Shipping & handling (per item, below) and sales "
            "tax. It lands in the Jobs app as an order job plus an unpaid invoice, and the customer's page has "
            "a 💳 Pay now button — made from your Stripe or Square keys in Settings → Small Business → Online "
            "Payment Links. With no keys set, the order is still taken and you send the invoice."),
    "new": ("Get a quote (was \"Request a new service\"): for anything that can't be booked on the spot — not sure "
            "what they need, a bigger job, or no open time suits them. They give the address and preferred days, "
            "and it lands in the Jobs app as a 'Requested' job (no date yet) plus a ticket, so you call, quote "
            "and schedule it. With the Shop on it lists services only; products are in the Shop."),
    "problem": "Something wrong with a past or current job — a ticket, linked to their most recent job.",
}


AREA_HELP = ("The ZIP codes you serve, separated by commas or spaces. A request from any other ZIP is still "
             "taken (you have their phone number) but is marked 'outside service area', and the customer is told "
             "you'll call them. Leave blank to accept every area.")
MILES_HELP = ("Also count any address within this many miles (straight line) of the Jobs app's Start/End Address "
              "(Settings), or its Business Address if no Start/End Address is set. 0 = no radius. A ZIP on the list "
              "is always in. If an address can't be found on the map, it's treated like an outside one: the request "
              "is still taken and you call the customer.")


def parse_miles(text) -> int:
    """'25' / ' 25 mi' / '' -> 25 / 25 / 0 (desk_db checks 0–250)."""
    import re
    m = re.search(r"\d+", str(text or ""))
    return int(m.group()) if m else 0


def parse_zips(text: str) -> list:
    """'32168, 32169 32170' -> ['32168', '32169', '32170'] (desk_db checks each is 5 digits)."""
    import re
    return [z for z in re.split(r"[\s,;]+", str(text or "").strip()) if z]


def jobs_db_path() -> str:
    """The Jobs database, the same place the server uses (<AI-Prowler state>/jobs_database)."""
    import desk_gui_links
    from db_access import DEFAULT_DB_FILENAME, DEFAULT_DB_SUBDIR
    return str(desk_gui_links._state_dir() / DEFAULT_DB_SUBDIR / DEFAULT_DB_FILENAME)


def save_paths(db: str, chosen: list, edition: str) -> tuple[bool, str]:
    if not chosen:
        return False, "Keep at least one choice on the page."
    return set_one(db, "booking_paths", list(chosen), edition)


def service_rows(jobs_db: str, *, load: bool = False) -> tuple[list, str]:
    """(services, problem). load=True first brings the list in line with Services & Pricing."""
    from pathlib import Path
    if not Path(jobs_db).exists():
        return [], "No Jobs database yet — add services in the Jobs app (Database → Services & Pricing) first."
    import booking_db
    from db_access import init_db
    try:
        init_db(jobs_db)
        if load:
            booking_db.sync_services(jobs_db, by="AI-Prowler")
        return booking_db.list_services(jobs_db), ""
    except Exception as e:  # noqa: BLE001
        return [], f"Couldn't read the services: {e}"


TYPE_LABEL = {"service": "Service", "product": "Product"}
TYPE_HELP = ("Service = customers can book a time for it on the page (\"Book a service\").\n"
             "Product = something you sell — customers can buy it (\"Buy a product\", when it has a price) or "
             "ask for it (\"Request a new service\"); there's no booking time.")
SHIPPING_HELP = ("Shipping & handling for ONE of this product, in dollars — it's added for each one ordered "
                 "(2 ordered = twice this). 0 = free shipping. Only products are shipped; the price itself is "
                 "the Base Price in the Jobs app → Database → Services & Pricing.")


def set_shipping(jobs_db: str, code: str, amount) -> tuple[bool, str]:
    """Shipping & handling per item for one product (2026-11-02, "Buy a product")."""
    import booking_db
    row = next((r for r in booking_db.list_services(jobs_db) if r["code"] == code), None)
    if row and service_type(row) != "product":
        return False, "Only products are shipped — set its Type to Product first."
    ok, msg = set_service(jobs_db, code, shipping=amount)
    if ok:
        n = next(r for r in booking_db.list_services(jobs_db) if r["code"] == code)["shipping"]
        msg = f"Saved — shipping & handling ${n:,.2f} per item." if n else "Saved — free shipping."
    return ok, msg


DETAILS_HELP = ("What the Shop shows on this product's card: up to 4 photos (the first is the big one), a short "
                "description and the specs (one per line — \"Size: 12 x 8 in\" shows Size in bold).")


def product_details(jobs_db: str, tickets_db: str, code: str) -> dict:
    """{'description', 'specs', 'photos': [1, 2, …]} for the Details… window."""
    import booking_db
    import desk_product_media as media
    row = next((r for r in booking_db.list_services(jobs_db) if r["code"] == code), {})
    return {"description": row.get("description") or "", "specs": row.get("specs") or "",
            "photos": media.photos(tickets_db, code)}


def save_details(jobs_db: str, code: str, description: str, specs: str) -> tuple[bool, str]:
    ok, msg = set_service(jobs_db, code, description=description, specs=specs)
    return ok, ("Saved — the Shop shows it on the product's card." if ok else msg)


def add_product_photo(tickets_db: str, code: str, file: str) -> tuple[bool, str]:
    import desk_product_media as media
    from pathlib import Path
    try:
        n = media.add_photo(tickets_db, code, Path(file).read_bytes())
        return True, f"Photo {n} added."
    except OSError as e:
        return False, f"Couldn't read that file: {e}"
    except Exception as e:  # noqa: BLE001 — DeskError: full, or not a picture
        return False, str(e)


def remove_product_photo(tickets_db: str, code: str, n: int) -> tuple[bool, str]:
    import desk_product_media as media
    media.remove_photo(tickets_db, code, n)
    return True, "Photo removed."


def first_product_photo(tickets_db: str, code: str, n: int) -> tuple[bool, str]:
    import desk_product_media as media
    media.make_first(tickets_db, code, n)
    return True, "That photo is now the main one."


def _details_window(app, parent, jobs_db, tickets_db, code, name):
    """Details… for one product: description, specs, photos (2026-11-02)."""
    import tkinter as tk
    from tkinter import filedialog, ttk
    d = product_details(jobs_db, tickets_db, code)
    w = tk.Toplevel(parent)
    w.title(f"{name} — shown in the Shop")
    w.transient(parent.winfo_toplevel())
    f = ttk.Frame(w, padding=10); f.pack(fill="both", expand=True)
    ttk.Label(f, text=DETAILS_HELP, wraplength=520, foreground="gray", font=("Arial", 8)).pack(anchor="w")
    ttk.Label(f, text="Short description (one line on the card)").pack(anchor="w", pady=(8, 0))
    desc = tk.StringVar(master=w, value=d["description"])
    ttk.Entry(f, textvariable=desc, width=70).pack(fill="x")
    ttk.Label(f, text="Specs — one per line, e.g.  Storage: 0.5 TB SSD").pack(anchor="w", pady=(8, 0))
    specs = tk.Text(f, width=70, height=8, wrap="word")
    specs.insert("1.0", d["specs"]); specs.pack(fill="x")
    ph = ttk.LabelFrame(f, text="Photos (up to 4 — the first is the big one)", padding=6)
    ph.pack(fill="x", pady=(8, 0))
    lb = tk.Listbox(ph, height=4, width=30, exportselection=False); lb.pack(side="left")
    btns = ttk.Frame(ph); btns.pack(side="left", padx=8)

    def refresh():
        lb.delete(0, "end")
        for n in product_details(jobs_db, tickets_db, code)["photos"]:
            lb.insert("end", f"Photo {n}" + ("  (main)" if n == 1 else ""))

    def picked():
        sel = lb.curselection()
        return sel[0] + 1 if sel else None

    def add():
        fn = filedialog.askopenfilename(parent=w, title="Choose a product photo", filetypes=[
            ("Pictures", "*.png *.jpg *.jpeg *.webp *.heic *.gif"), ("All files", "*.*")])
        if fn:
            _say(app, *add_product_photo(tickets_db, code, fn)); refresh()

    def remove():
        n = picked()
        if n:
            _say(app, *remove_product_photo(tickets_db, code, n)); refresh()

    def first():
        n = picked()
        if n:
            _say(app, *first_product_photo(tickets_db, code, n)); refresh()
    ttk.Button(btns, text="Add photo…", command=add).pack(fill="x")
    ttk.Button(btns, text="Remove", command=remove).pack(fill="x", pady=2)
    ttk.Button(btns, text="Make main photo", command=first).pack(fill="x")
    refresh()

    def save():
        ok, msg = save_details(jobs_db, code, desc.get(), specs.get("1.0", "end"))
        _say(app, ok, msg)
        if ok:
            w.destroy()
    r = ttk.Frame(f); r.pack(fill="x", pady=(10, 0))
    ttk.Button(r, text="Save", command=save).pack(side="left")
    ttk.Button(r, text="Close", command=w.destroy).pack(side="left", padx=6)


def payment_ready() -> bool:
    """A Stripe Secret Key or Square Access Token + Location ID is set (Small Business tab)."""
    import json
    from pathlib import Path
    try:
        c = json.loads((Path.home() / ".ai-prowler" / "config.json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return False
    return bool(str(c.get("stripe_secret_key") or "").strip()
                or (str(c.get("square_access_token") or "").strip() and str(c.get("square_location_id") or "").strip()))


def service_type(row: dict) -> str:
    """'service' (bookable in a time window) or 'product' (request / order only)."""
    return "product" if str(row.get("mode") or "") == "request" else "service"


OUTDOOR_HELP = ("Outdoor work (windows, pressure washing, roofs…) — tick it and the booking agent checks "
                "tomorrow's weather for these visits and offers the customer a new time if rain or high wind "
                "is likely (the visit stays unless they accept). Leave it off for indoor work. The agent's own "
                "switch — 🤖 Agent → \"Check the weather for outdoor services\" — turns the check on or off "
                "for the whole business.")


def set_outdoor(jobs_db: str, code: str, on: bool) -> tuple[bool, str]:
    """Outdoor on/off for one service (2026-11-02, configurable per business). Never for a product."""
    import booking_db
    row = next((r for r in booking_db.list_services(jobs_db) if r["code"] == code), None)
    if on and row and service_type(row) == "product":
        return False, "A product has no visit, so there's no weather to check — set its Type to Service first."
    ok, msg = set_service(jobs_db, code, outdoor=bool(on))
    if ok:
        msg = ("Saved — the booking agent checks the weather for this service's visits." if on else
               "Saved — no weather check for this service.")
    return ok, msg


def set_type(jobs_db: str, code: str, label: str) -> tuple[bool, str]:
    kind = "product" if str(label).strip().lower().startswith("product") else "service"
    fields = {"mode": "request" if kind == "product" else "instant"}
    if kind == "product":
        fields["outdoor"] = False                      # a product has no visit, so no weather check
    ok, msg = set_service(jobs_db, code, **fields)
    if ok:
        msg = ("Saved — customers can book a time for it." if kind == "service" else
               "Saved — customers can ask for it; it isn't offered for booking.")
    return ok, msg


def services_count_text(online: dict) -> str:
    """The line above the services list: how many are on the customer page right now."""
    n = sum(1 for v in online.values() if v)
    return (f"{n} of {len(online)} shown on the page. "
            "The list comes from the Jobs app → Database → Services & Pricing.")


def set_service(jobs_db: str, code: str, **fields) -> tuple[bool, str]:
    import booking_db
    try:
        booking_db.update_service(jobs_db, code, by="AI-Prowler", **fields)
        return True, "Saved."
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def _build_webforms(app, f, db, edition):
    import tkinter as tk
    from tkinter import ttk

    import desk_db
    from desk_gui_agent import _tooltip
    small = ("Arial", 8)
    s = desk_db.get_settings(db)
    ttk.Label(f, text="The customer page — the request service link (/book or /support/new) on your website, "
                      "invoices and receipts.", font=small, foreground="gray").pack(anchor="w")
    paths = ttk.LabelFrame(f, text="Choices on the page  (hover for details)", padding=(6, 4))
    paths.pack(fill="x", pady=(4, 0))
    on = s.get("booking_paths") or ["problem"]
    pv = {}
    for p in desk_db.BOOKING_PATHS:
        pv[p] = tk.BooleanVar(value=p in on)
        cb = ttk.Checkbutton(paths, text=PATH_LABELS[p], variable=pv[p])
        cb.pack(anchor="w")
        _tooltip(cb, PATH_HELP[p])
    ttk.Label(paths, font=small, foreground="gray", wraplength=760, justify="left",
              text="One choice = the page goes straight to it. More than one = the page asks \"How can we help?\" "
                   "first. Every choice asks for a phone number so you can call back.").pack(anchor="w", pady=(2, 0))
    if not payment_ready():
        ttk.Label(paths, font=small, foreground="#b45309", wraplength=760, justify="left",
                  text="🛒 Buy a product: no Stripe or Square keys yet (Settings → Small Business → Online Payment "
                       "Links), so customers can order but can't pay online — you send them the invoice."
                  ).pack(anchor="w", pady=(2, 0))
    r = ttk.Frame(paths); r.pack(fill="x", pady=(4, 0))
    ttk.Label(r, text="Welcome line (optional)", font=small).pack(side="left")
    welcome = tk.StringVar(value=s.get("booking_welcome") or "")
    ttk.Entry(r, textvariable=welcome, width=70).pack(side="left", padx=(6, 0))
    r = ttk.Frame(paths); r.pack(fill="x", pady=(4, 0))
    w = ttk.Label(r, text="Service area ZIP codes (blank = everywhere)", font=small)
    w.pack(side="left")
    zips = tk.StringVar(value=", ".join(s.get("booking_area_zips") or []))
    ze = ttk.Entry(r, textvariable=zips, width=38)
    ze.pack(side="left", padx=(6, 0))
    for x in (w, ze):
        _tooltip(x, AREA_HELP)
    w2 = ttk.Label(r, text="or within", font=small)
    w2.pack(side="left", padx=(8, 0))
    miles = tk.StringVar(value=str(s.get("booking_area_miles") or 0))
    me = ttk.Spinbox(r, from_=0, to=250, textvariable=miles, width=5)
    me.pack(side="left", padx=(4, 0))
    w3 = ttk.Label(r, text="miles  (0 = no radius)", font=small)
    w3.pack(side="left", padx=(4, 0))
    for x in (w2, me, w3):
        _tooltip(x, MILES_HELP)

    def save_page():
        ok, msg = save_paths(db, [p for p in desk_db.BOOKING_PATHS if pv[p].get()], edition)
        if ok:
            ok, msg = set_one(db, "booking_welcome", welcome.get(), edition)
        if ok:
            ok, msg = set_one(db, "booking_area_zips", parse_zips(zips.get()), edition)
        if ok:
            ok, msg = set_one(db, "booking_area_miles", parse_miles(miles.get()), edition)
        _say(app, ok, "Web form saved." if ok else msg)

    ttk.Button(paths, text="Save page choices", command=save_page).pack(anchor="w", pady=(4, 0))
    _build_look(app, f, db, edition)

    # services offered online (from the Jobs app's Services & Pricing)
    sv = ttk.LabelFrame(f, text="Services offered online", padding=(6, 4))
    sv.pack(fill="x", pady=(6, 0))
    jobs_db = jobs_db_path()
    top = ttk.Frame(sv); top.pack(fill="x")
    info = tk.StringVar()
    ttk.Label(top, textvariable=info, font=small, foreground="gray").pack(side="left")
    grid = ttk.Frame(sv); grid.pack(fill="x", pady=(4, 0))

    def draw(load=False):
        for w in grid.winfo_children():
            w.destroy()
        rows, problem = service_rows(jobs_db, load=load)
        if problem:
            info.set(problem)
            return
        online = {x["code"]: bool(x["online"]) for x in rows}

        def count():   # 2026-11-02: kept up to date — it said "0 of 1 shown" after ticking Online
            info.set(services_count_text(online))
        count()
        # 2026-11-02 (David): "2 types ... services and ... products ... the takes (min) should be removed as
        # it is too custom to quote times and same thing with outdoor". Type replaces both columns: a
        # Service can be booked in a time window; a Product can only be requested / ordered (no times).
        # Outdoor came back the same day, per service (David: "make that configurable so different services
        # companies can turn it on or off"): tick it for weather-dependent services; products have none.
        # 2026-11-02: "Buy a product" — shipping & handling per item, products only.
        for c, h in enumerate(("Online", "Service / product", "Type", "Price shown", "Outdoor",
                               "Ship & handling $", "Shop card")):
            ttk.Label(grid, text=h, font=("Arial", 8, "bold")).grid(row=0, column=c, sticky="w", padx=(0, 10))
        for i, x in enumerate(rows, start=1):
            v = tk.BooleanVar(value=x["online"])

            def _toggle(code=x["code"], v=v):
                ok, msg = set_service(jobs_db, code, online=v.get())
                if ok:
                    online[code] = bool(v.get())
                else:
                    v.set(not v.get())
                count()
                _say(app, ok, msg)
            ttk.Checkbutton(grid, variable=v, command=_toggle).grid(row=i, column=0, sticky="w")
            ttk.Label(grid, text=f"{x['name']}  ({x['code']})", font=small).grid(row=i, column=1, sticky="w")
            tv = tk.StringVar(value=TYPE_LABEL[service_type(x)])
            tc = _calm(ttk.Combobox(grid, textvariable=tv, state="readonly", width=9,
                                    values=[TYPE_LABEL["service"], TYPE_LABEL["product"]]))
            tc.grid(row=i, column=2, sticky="w")
            _tooltip(tc, TYPE_HELP)
            pd = tk.StringVar(value=x["price_display"])
            cb = _calm(ttk.Combobox(grid, textvariable=pd, state="readonly", width=7, values=["none", "from", "exact"]))
            cb.grid(row=i, column=3, sticky="w")
            cb.bind("<<ComboboxSelected>>", lambda _e, code=x["code"], pd=pd: _say(
                app, *set_service(jobs_db, code, price_display=pd.get())), add="+")
            _tooltip(cb, "none = no price on the page; from = 'from $<minimum charge>'; exact = the base price")
            ov = tk.BooleanVar(value=bool(x.get("outdoor")) and service_type(x) == "service")
            oc = ttk.Checkbutton(grid, variable=ov, command=lambda code=x["code"], ov=ov: _say(
                app, *set_outdoor(jobs_db, code, ov.get())))
            oc.grid(row=i, column=4, sticky="w")
            if service_type(x) == "product":
                oc.state(["disabled"])
            _tooltip(oc, OUTDOOR_HELP)
            sh = tk.StringVar(value=f"{x.get('shipping') or 0:.2f}")
            se = ttk.Entry(grid, textvariable=sh, width=8)
            se.grid(row=i, column=5, sticky="w")
            if service_type(x) != "product":
                se.state(["disabled"])
            _tooltip(se, SHIPPING_HELP)

            saved = {"v": sh.get()}

            def _ship_save(_e=None, code=x["code"], sh=sh, se=se, saved=saved):
                if se.instate(["disabled"]) or sh.get().strip() == saved["v"]:
                    return                          # nothing changed: no "Saved" on every click away
                import booking_db
                ok, msg = set_shipping(jobs_db, code, sh.get())
                if ok:
                    n = next((r["shipping"] for r in booking_db.list_services(jobs_db) if r["code"] == code), 0)
                    sh.set(f"{n:.2f}")
                    saved["v"] = sh.get()
                _say(app, ok, msg)
            se.bind("<Return>", _ship_save, add="+")
            se.bind("<FocusOut>", _ship_save, add="+")
            # 2026-11-02: the product's card in the Shop — photos, short description, specs
            db_ = ttk.Button(grid, text="Details…", width=9, command=lambda code=x["code"], nm=x["name"]:
                             _details_window(app, grid, jobs_db, db, code, nm))
            db_.grid(row=i, column=6, sticky="w")
            if service_type(x) != "product":
                db_.state(["disabled"])
            _tooltip(db_, DETAILS_HELP)

            def _type_pick(_e=None, code=x["code"], tv=tv, ov=ov, oc=oc, se=se, db_=db_):
                ok, msg = set_type(jobs_db, code, tv.get())
                if ok and tv.get() == TYPE_LABEL["product"]:
                    ov.set(False)                   # a product has no visit, so no weather
                    oc.state(["disabled"])
                    se.state(["!disabled"])         # …but it can be shipped
                    db_.state(["!disabled"])        # …and has a Shop card
                elif ok:
                    oc.state(["!disabled"])
                    se.state(["disabled"])
                    db_.state(["disabled"])
                _say(app, ok, msg)
            tc.bind("<<ComboboxSelected>>", _type_pick, add="+")

    ttk.Button(top, text="Load from Services & Pricing", command=lambda: draw(load=True)).pack(side="right")
    draw(load=False)
    _build_approval(app, f, db, edition)


# ── Page look: icon, background and accent of the customer pages (2026-10-30) ──

BG_LABELS = {"plain": "Plain (light grey)", "color": "A colour", "picture": "A picture"}


def look_status(db: str) -> dict:
    """What the Page look section shows: {'logo': bool, 'background': bool, settings…}."""
    import desk_db
    import desk_page_look as pl
    s = desk_db.get_settings(db)
    return {"logo": pl.file_bytes(db, "logo") is not None, "background": pl.file_bytes(db, "background") is not None,
            "bg_mode": s.get("page_bg_mode") or "plain", "bg_color": s.get("page_bg_color") or pl.DEFAULT_BG,
            "accent": s.get("page_accent") or pl.DEFAULT_ACCENT}


def save_look(db: str, edition: str, *, bg_mode: str | None = None, bg_color: str | None = None,
              accent: str | None = None, logo_file: str | None = None, background_file: str | None = None,
              clear_logo: bool = False, clear_background: bool = False) -> tuple[bool, str]:
    """One change to the page look. Picture files are read from disk (AI-Prowler's file chooser)."""
    import desk_page_look as pl
    from pathlib import Path
    try:
        if logo_file:
            pl.set_logo(db, Path(logo_file).read_bytes(), actor=None, edition=edition)
            return True, "Icon saved — it shows on the booking, request and ticket pages."
        if clear_logo:
            pl.clear_logo(db, actor=None, edition=edition)
            return True, "Icon removed."
        if background_file:
            pl.set_background(db, Path(background_file).read_bytes(), actor=None, edition=edition)
            return True, "Background picture saved."
        if clear_background:
            pl.clear_background(db, actor=None, edition=edition)
            return True, "Background picture removed."
        for key, val in (("page_bg_color", bg_color), ("page_accent", accent), ("page_bg_mode", bg_mode)):
            if val is not None:
                if key == "page_bg_mode" and val == "picture" and not look_status(db)["background"]:
                    return False, "Choose a background picture first."
                ok, msg = set_one(db, key, val, edition)
                if not ok:
                    return ok, msg
        return True, "Page look saved."
    except OSError as e:
        return False, f"Couldn't read that file: {e}"
    except Exception as e:  # noqa: BLE001 — DeskError with a plain message
        return False, str(e)


def _build_look(app, f, db, edition):
    import tkinter as tk
    from tkinter import colorchooser, filedialog, ttk

    import desk_page_look as pl
    from desk_gui_agent import _tooltip
    small = ("Arial", 8)
    box = ttk.LabelFrame(f, text="Page look — booking, request and ticket pages  (hover for details)", padding=(6, 4))
    box.pack(fill="x", pady=(6, 0))
    st = look_status(db)
    pics = [("Pictures", "*.png *.jpg *.jpeg *.webp *.heic *.gif"), ("All files", "*.*")]
    info = {"logo": tk.StringVar(), "bg": tk.StringVar()}
    mode = tk.StringVar(value=BG_LABELS.get(st["bg_mode"], BG_LABELS["plain"]))
    swatch = {}

    def refresh():
        s2 = look_status(db)
        info["logo"].set("✔ icon set" if s2["logo"] else "no icon (the standard one is used)")
        info["bg"].set("✔ picture set" if s2["background"] else "no picture")
        mode.set(BG_LABELS.get(s2["bg_mode"], BG_LABELS["plain"]))
        for k in ("bg_color", "accent"):
            swatch[k].configure(background=s2[k])

    def run(**kw):
        ok, msg = save_look(db, edition, **kw)
        _say(app, ok, msg)
        refresh()

    def pick_file(kind):
        p = filedialog.askopenfilename(title="Choose your icon" if kind == "logo" else "Choose a background picture",
                                       filetypes=pics)
        if p:
            run(**{("logo_file" if kind == "logo" else "background_file"): p})

    def pick_color(kind):
        cur = look_status(db)[kind]
        got = colorchooser.askcolor(color=cur, title="Background colour" if kind == "bg_color" else "Accent colour")
        if got and got[1]:
            run(**({"bg_color": got[1], "bg_mode": "color"} if kind == "bg_color" else {"accent": got[1]}))

    r = ttk.Frame(box); r.pack(fill="x")
    w = ttk.Label(r, text="Icon", font=small, width=11); w.pack(side="left"); _tooltip(w, pl.HELP["logo"])
    ttk.Button(r, text="Choose…", command=lambda: pick_file("logo")).pack(side="left")
    ttk.Button(r, text="Remove", command=lambda: run(clear_logo=True)).pack(side="left", padx=(4, 8))
    ttk.Label(r, textvariable=info["logo"], font=small, foreground="gray").pack(side="left")
    r = ttk.Frame(box); r.pack(fill="x", pady=(4, 0))
    w = ttk.Label(r, text="Background", font=small, width=11); w.pack(side="left"); _tooltip(w, pl.HELP["background"])
    cb = _calm(ttk.Combobox(r, textvariable=mode, state="readonly", width=18, values=list(BG_LABELS.values())))
    cb.pack(side="left"); _tooltip(cb, pl.HELP["background"])
    code = {v: k for k, v in BG_LABELS.items()}
    cb.bind("<<ComboboxSelected>>", lambda _e: run(bg_mode=code[mode.get()]), add="+")
    swatch["bg_color"] = tk.Label(r, width=3, relief="groove", background=st["bg_color"])
    swatch["bg_color"].pack(side="left", padx=(8, 2))
    ttk.Button(r, text="Colour…", command=lambda: pick_color("bg_color")).pack(side="left")
    ttk.Button(r, text="Picture…", command=lambda: pick_file("background")).pack(side="left", padx=(8, 0))
    ttk.Button(r, text="Remove picture", command=lambda: run(clear_background=True)).pack(side="left", padx=(4, 8))
    ttk.Label(r, textvariable=info["bg"], font=small, foreground="gray").pack(side="left")
    r = ttk.Frame(box); r.pack(fill="x", pady=(4, 0))
    w = ttk.Label(r, text="Accent", font=small, width=11); w.pack(side="left"); _tooltip(w, pl.HELP["accent"])
    swatch["accent"] = tk.Label(r, width=3, relief="groove", background=st["accent"])
    swatch["accent"].pack(side="left", padx=(0, 2))
    ttk.Button(r, text="Colour…", command=lambda: pick_color("accent")).pack(side="left")
    ttk.Button(r, text="Standard colours", command=lambda: run(accent=pl.DEFAULT_ACCENT, bg_color=pl.DEFAULT_BG,
                                                              bg_mode="plain")).pack(side="left", padx=(8, 0))
    refresh()


# ── Approving bookings (booking-spec.md §7a; David 2026-10-30: configurable) ──

APPROVAL_CHOICES = [("approve_all", "Approve every booking (recommended)"),
                    ("preapprove", "Instant booking — book windows that meet the rules at once"),
                    ("auto", "Confirm every open window automatically")]
CREW_CHOICES = [("approver", "The approver picks the crew"), ("suggested", "Use the suggested crew"),
                ("office", "Leave it for the office")]
APPROVAL_HELP = {
    "booking_approval": ("Approve every booking: the customer's time is held and waits for your OK (Approve / "
                         "Suggest another time / Decline) in the Service Desk app → 📅 To approve. Instant booking "
                         "and automatic: the customer is told 'Booked' straight away. You can still suggest a change."),
    "booking_approve_managers": "On a server, managers can approve bookings as well as the owner.",
    "booking_crew_mode": "Who picks the crew when a booking is confirmed.",
    "booking_backups": "How many backup times a customer may pick besides their first choice (0–3).",
    "booking_hold_hours": "If a booking is still waiting after this many hours, you're reminded.",
    "booking_release_hours": ("After this many hours an undecided booking frees its time, becomes a 'Requested' job "
                              "and the customer is told you'll call."),
    "booking_suggest_hours": "How long a time you suggested waits for the customer's answer.",
    "booking_customer_changes": "Customers can reschedule or cancel from their request page.",
    "booking_change_hours": "…but not within this many hours of the visit (then they're asked to call).",
    "instant": ("Only with 'Instant booking': a booking is confirmed on its own when it meets EVERY limit you set "
                "here; anything else waits in 📅 To approve with the reason. You get an FYI line in the morning "
                "digest, and you can still suggest a change. Leave them all off to book any open time instantly."),
    "booking_pre_returning": "Only customers who've had a job with you before are booked instantly.",
    "booking_pre_services": ("Only these services (codes from Services & Pricing, separated by commas) are booked "
                             "instantly. Blank = every bookable service."),
    "booking_pre_min_days": "Only times at least this many days away (0 = any) — gives you time to plan.",
    "booking_pre_per_day": "At most this many instant bookings on any one day (0 = no limit).",
    "booking_reschedule_approval": ("A customer moving their visit waits for your OK. Off: a move into an open time "
                                    "is confirmed at once (only with Instant booking or Automatic)."),
}


def parse_codes(text) -> list:
    """'WIN-EXT, gut  PRESS' -> ['WIN-EXT', 'GUT', 'PRESS'] (service codes are kept upper-case)."""
    import re
    if isinstance(text, (list, tuple)):
        text = " ".join(map(str, text))
    return list(dict.fromkeys(z.upper() for z in re.split(r"[\s,;]+", str(text or "").strip()) if z))


def save_approval(db: str, form: dict, edition: str) -> tuple[bool, str]:
    """Save the Approving bookings settings (validated by desk_db). form values are strings/bools."""
    labels = dict(APPROVAL_CHOICES) | dict(CREW_CHOICES)
    code = {v: k for k, v in labels.items()}
    try:
        vals = {"booking_approval": code.get(form["booking_approval"], form["booking_approval"]),
                "booking_customer_changes": bool(form["booking_customer_changes"])}
        for k in ("booking_backups", "booking_hold_hours", "booking_release_hours", "booking_suggest_hours",
                  "booking_change_hours"):
            vals[k] = int(str(form[k]).strip())
        if "booking_pre_min_days" in form:                   # instant-booking limits (Phase 4)
            vals["booking_pre_returning"] = bool(form["booking_pre_returning"])
            vals["booking_reschedule_approval"] = bool(form["booking_reschedule_approval"])
            vals["booking_pre_services"] = parse_codes(form["booking_pre_services"])
            for k in ("booking_pre_min_days", "booking_pre_per_day"):
                vals[k] = int(str(form[k]).strip() or 0)
        if edition == "business":
            vals["booking_approve_managers"] = bool(form["booking_approve_managers"])
            vals["booking_crew_mode"] = code.get(form["booking_crew_mode"], form["booking_crew_mode"])
    except (KeyError, ValueError):
        return False, "Hours and backups must be whole numbers."
    if vals["booking_release_hours"] <= vals["booking_hold_hours"]:
        return False, "Free the time after a reminder: the release hours must be more than the reminder hours."
    for k, v in vals.items():
        ok, msg = set_one(db, k, v, edition)
        if not ok:
            return ok, msg
    return True, "Approval settings saved."


def _build_approval(app, f, db, edition):
    import tkinter as tk
    from tkinter import ttk

    import desk_db
    from desk_gui_agent import _tooltip
    small = ("Arial", 8)
    s = desk_db.get_settings(db)
    ap = ttk.LabelFrame(f, text="Approving bookings  (hover for details)", padding=(6, 4))
    ap.pack(fill="x", pady=(6, 0))
    labels = dict(APPROVAL_CHOICES) | dict(CREW_CHOICES)
    v = {"booking_approval": tk.StringVar(value=labels.get(s["booking_approval"], s["booking_approval"])),
         "booking_approve_managers": tk.BooleanVar(value=bool(s["booking_approve_managers"])),
         "booking_crew_mode": tk.StringVar(value=labels.get(s["booking_crew_mode"], s["booking_crew_mode"])),
         "booking_customer_changes": tk.BooleanVar(value=bool(s["booking_customer_changes"]))}
    for k in ("booking_backups", "booking_hold_hours", "booking_release_hours", "booking_suggest_hours",
              "booking_change_hours"):
        v[k] = tk.StringVar(value=str(s[k]))
    r = ttk.Frame(ap); r.pack(fill="x")
    w = ttk.Label(r, text="Bookings", font=small); w.pack(side="left"); _tooltip(w, APPROVAL_HELP["booking_approval"])
    w = _calm(ttk.Combobox(r, textvariable=v["booking_approval"], state="readonly", width=52,
                           values=[lab for _, lab in APPROVAL_CHOICES]))
    w.pack(side="left", padx=(6, 0)); _tooltip(w, APPROVAL_HELP["booking_approval"])
    if edition == "business":
        r = ttk.Frame(ap); r.pack(fill="x", pady=(2, 0))
        w = ttk.Checkbutton(r, text="Managers can approve", variable=v["booking_approve_managers"])
        w.pack(side="left"); _tooltip(w, APPROVAL_HELP["booking_approve_managers"])
        w = ttk.Label(r, text="Crew", font=small); w.pack(side="left", padx=(12, 4)); _tooltip(w, APPROVAL_HELP["booking_crew_mode"])
        w = _calm(ttk.Combobox(r, textvariable=v["booking_crew_mode"], state="readonly", width=28,
                               values=[lab for _, lab in CREW_CHOICES]))
        w.pack(side="left"); _tooltip(w, APPROVAL_HELP["booking_crew_mode"])
    r = ttk.Frame(ap); r.pack(fill="x", pady=(2, 0))
    for k, lab, lo, hi in (("booking_backups", "Backup times", 0, 3), ("booking_hold_hours", "Remind after (h)", 1, 336),
                           ("booking_release_hours", "Free after (h)", 2, 720),
                           ("booking_suggest_hours", "Suggestion waits (h)", 1, 336)):
        w = ttk.Label(r, text=lab, font=small); w.pack(side="left", padx=(0, 4)); _tooltip(w, APPROVAL_HELP[k])
        w = ttk.Spinbox(r, textvariable=v[k], from_=lo, to=hi, width=4); w.pack(side="left", padx=(0, 10))
        _tooltip(w, APPROVAL_HELP[k])
    r = ttk.Frame(ap); r.pack(fill="x", pady=(2, 0))
    w = ttk.Checkbutton(r, text="Customers can reschedule / cancel online", variable=v["booking_customer_changes"])
    w.pack(side="left"); _tooltip(w, APPROVAL_HELP["booking_customer_changes"])
    w = ttk.Label(r, text="until (hours before)", font=small); w.pack(side="left", padx=(8, 4))
    _tooltip(w, APPROVAL_HELP["booking_change_hours"])
    w = ttk.Spinbox(r, textvariable=v["booking_change_hours"], from_=0, to=336, width=4); w.pack(side="left")
    _tooltip(w, APPROVAL_HELP["booking_change_hours"])
    v["booking_reschedule_approval"] = tk.BooleanVar(value=bool(s.get("booking_reschedule_approval", True)))
    w = ttk.Checkbutton(r, text="Reschedules need approval", variable=v["booking_reschedule_approval"])
    w.pack(side="left", padx=(12, 0)); _tooltip(w, APPROVAL_HELP["booking_reschedule_approval"])
    # Instant-booking limits (Phase 4)
    r = ttk.Frame(ap); r.pack(fill="x", pady=(4, 0))
    w = ttk.Label(r, text="Instant booking only for:", font=small); w.pack(side="left"); _tooltip(w, APPROVAL_HELP["instant"])
    v["booking_pre_returning"] = tk.BooleanVar(value=bool(s.get("booking_pre_returning")))
    w = ttk.Checkbutton(r, text="returning customers", variable=v["booking_pre_returning"])
    w.pack(side="left", padx=(6, 8)); _tooltip(w, APPROVAL_HELP["booking_pre_returning"])
    for k, lab, hi in (("booking_pre_min_days", "days ahead ≥", 60), ("booking_pre_per_day", "max a day", 50)):
        v[k] = tk.StringVar(value=str(s.get(k) or 0))
        w = ttk.Label(r, text=lab, font=small); w.pack(side="left", padx=(0, 4)); _tooltip(w, APPROVAL_HELP[k])
        w = ttk.Spinbox(r, textvariable=v[k], from_=0, to=hi, width=4); w.pack(side="left", padx=(0, 10))
        _tooltip(w, APPROVAL_HELP[k])
    r = ttk.Frame(ap); r.pack(fill="x", pady=(2, 0))
    w = ttk.Label(r, text="…and these services (blank = all):", font=small); w.pack(side="left")
    _tooltip(w, APPROVAL_HELP["booking_pre_services"])
    v["booking_pre_services"] = tk.StringVar(value=", ".join(s.get("booking_pre_services") or []))
    w = ttk.Entry(r, textvariable=v["booking_pre_services"], width=40); w.pack(side="left", padx=(6, 0))
    _tooltip(w, APPROVAL_HELP["booking_pre_services"])
    ttk.Button(ap, text="Save approval settings", command=lambda: _say(
        app, *save_approval(db, {k: x.get() for k, x in v.items()}, edition))).pack(anchor="w", pady=(4, 0))
    _build_staff(app, f, db, edition)
    _build_calendar(app, f, db, edition)
    _build_embed(app, f, db, edition)


# ── Employee-facing form: booking for customers from the app's + (§9.2, Phase 3) ──

OVERRIDE_CHOICES = [("approvers", "Approvers only"), ("everyone", "Everyone who can book"), ("nobody", "Nobody")]
ROLE_LABELS = {"manager": "Managers", "staff": "Office staff", "field_crew": "Field crew"}
STAFF_HELP = {
    "staff_booking": ("In the Service Desk app, + → Customer request offers 'Book a visit' and 'New service "
                      "request' for a customer who phoned or walked in. Their phone number is required. It makes the "
                      "same job, booking and ticket (with a status link) as the website."),
    "staff_booking_roles": "On a server: who besides the owner can book for customers.",
    "staff_booking_approval": ("Bookings made by staff wait in 📅 To approve. Bookings made by an approver (the owner; "
                               "managers when allowed) are confirmed as they're made."),
    "staff_booking_override": ("Who can book outside the open times — outside working hours, past the daily limit or "
                               "over another job — by typing a date and times."),
    "staff_booking_double_book": "An override may put a crew on two visits at once (it's flagged on the ticket).",
    "staff_booking_all_services": "Staff can book any Services & Pricing item, not only those offered online.",
    "staff_booking_notify": "'Send the customer a confirmation' starts ticked (it can be unticked per booking).",
}


def save_staff(db: str, form: dict, edition: str) -> tuple[bool, str]:
    code = {lab: k for k, lab in OVERRIDE_CHOICES}
    vals = {"staff_booking": bool(form["staff_booking"]),
            "staff_booking_approval": bool(form["staff_booking_approval"]),
            "staff_booking_override": code.get(form["staff_booking_override"], form["staff_booking_override"]),
            "staff_booking_double_book": bool(form["staff_booking_double_book"]),
            "staff_booking_all_services": bool(form["staff_booking_all_services"]),
            "staff_booking_notify": bool(form["staff_booking_notify"])}
    if edition == "business":
        vals["staff_booking_roles"] = [r for r in ROLE_LABELS if form.get("role_" + r)]
    for k, val in vals.items():
        ok, msg = set_one(db, k, val, edition)
        if not ok:
            return ok, msg
    return True, "Booking-for-customers settings saved."


def _build_staff(app, f, db, edition):
    import tkinter as tk
    from tkinter import ttk

    import desk_db
    from desk_gui_agent import _tooltip
    s = desk_db.get_settings(db)
    st = ttk.LabelFrame(f, text="Employee-facing form: booking for customers in the app's +  (hover for details)",
                        padding=(6, 4))
    st.pack(fill="x", pady=(6, 0))
    labels = dict(OVERRIDE_CHOICES)
    v = {k: tk.BooleanVar(value=bool(s[k])) for k in ("staff_booking", "staff_booking_approval",
                                                      "staff_booking_double_book", "staff_booking_all_services",
                                                      "staff_booking_notify")}
    v["staff_booking_override"] = tk.StringVar(value=labels.get(s["staff_booking_override"], s["staff_booking_override"]))
    w = ttk.Checkbutton(st, text="Book visits and take new service requests for customers in the app",
                        variable=v["staff_booking"])
    w.pack(anchor="w"); _tooltip(w, STAFF_HELP["staff_booking"])
    if edition == "business":
        r = ttk.Frame(st); r.pack(fill="x", pady=(2, 0))
        w = ttk.Label(r, text="Who besides the owner:", font=("Arial", 8)); w.pack(side="left")
        _tooltip(w, STAFF_HELP["staff_booking_roles"])
        for role, lab in ROLE_LABELS.items():
            v["role_" + role] = tk.BooleanVar(value=role in (s.get("staff_booking_roles") or []))
            w = ttk.Checkbutton(r, text=lab, variable=v["role_" + role]); w.pack(side="left", padx=(6, 0))
            _tooltip(w, STAFF_HELP["staff_booking_roles"])
    r = ttk.Frame(st); r.pack(fill="x", pady=(2, 0))
    for k, lab in (("staff_booking_approval", "Staff bookings need approval"),
                   ("staff_booking_all_services", "Any service, not only online ones"),
                   ("staff_booking_notify", "Confirm to the customer (ticked)")):
        w = ttk.Checkbutton(r, text=lab, variable=v[k]); w.pack(side="left", padx=(0, 10)); _tooltip(w, STAFF_HELP[k])
    r = ttk.Frame(st); r.pack(fill="x", pady=(2, 0))
    w = ttk.Label(r, text="Book outside the open times:", font=("Arial", 8)); w.pack(side="left")
    _tooltip(w, STAFF_HELP["staff_booking_override"])
    w = _calm(ttk.Combobox(r, textvariable=v["staff_booking_override"], state="readonly", width=24,
                           values=[lab for _, lab in OVERRIDE_CHOICES]))
    w.pack(side="left", padx=(6, 10)); _tooltip(w, STAFF_HELP["staff_booking_override"])
    w = ttk.Checkbutton(r, text="…even double-booking a crew", variable=v["staff_booking_double_book"])
    w.pack(side="left"); _tooltip(w, STAFF_HELP["staff_booking_double_book"])
    ttk.Button(st, text="Save", command=lambda: _say(
        app, *save_staff(db, {k: x.get() for k, x in v.items()}, edition))).pack(anchor="w", pady=(4, 0))


# ── Calendar & openings (§6.2, §9.3; Phase 5) ────────────────────────────────

CAL_HELP = {
    "calendar_sync": ("Personal installs: Claude, Muse or Grok (with its Google Calendar connector) keeps ONE business "
                      "calendar in step — its busy times block bookings, and confirmed bookings are written to it "
                      "(\"Job: <service> — <first name>\"). AI-Prowler itself never connects to Google."),
    "calendar_name": "The Google Calendar's name exactly as it shows in Google, e.g. Blue Wave Jobs.",
    "calendar_days": "How many days ahead to sync. 0 = as far ahead as customers can book.",
    "calendar_fresh_hours": ("If the calendar hasn't synced for this many hours, every booking waits for your approval "
                             "(whatever the approval setting) until it does."),
    "prompt": "Copies the sync prompt — paste it into Claude, Muse or Grok to sync now.",
    "task": ("Adds a 'Business calendar sync' task to the Autonomous AI Task Queue: hourly 7:00–19:00 through your AI "
             "runner. That AI needs a Google Calendar connector."),
    "openings": ("Extra openings: hours customers can book outside your Working Days (e.g. a Saturday morning). "
                 "Closed days: holidays and time off — nothing can be booked."),
}


def save_calendar(db: str, form: dict, edition: str) -> tuple[bool, str]:
    if edition == "business":
        return False, "The server uses the Jobs app calendar only."
    vals = {"calendar_sync": "ai" if form.get("calendar_sync") else "off",
            "calendar_name": str(form.get("calendar_name") or "").strip()}
    for k in ("calendar_days", "calendar_fresh_hours"):
        try:
            vals[k] = int(str(form.get(k) or "0").strip() or 0)
        except ValueError:
            return False, f"{k.replace('_', ' ')} must be a whole number"
    if vals["calendar_sync"] == "ai" and not vals["calendar_name"]:
        return False, "Type the business calendar's name first."
    for k, val in vals.items():
        ok, msg = set_one(db, k, val, edition)
        if not ok:
            return ok, msg
    return True, "Calendar settings saved."


def calendar_status_text(db: str, edition: str) -> str:
    if edition == "business":
        return ""
    try:
        import booking_calendar
        import desk_db
        jobs_db = jobs_db_path()
        if not jobs_db:
            return "The Jobs app isn't set up yet."
        return booking_calendar.status_line(booking_calendar.status(jobs_db, desk_db.get_settings(db), edition=edition))
    except Exception as e:  # noqa: BLE001
        return f"Status unavailable: {e}"


OPENING_KINDS = [("open", "Extra opening"), ("closed", "Closed day")]


def opening_rows(jobs_db: str, days: int = 120) -> list:
    import datetime as _dt
    from db_access import get_connection
    if not jobs_db or not Path(jobs_db).exists():
        return []
    try:
        conn = get_connection(jobs_db)
        try:
            rows = conn.execute("SELECT * FROM booking_openings WHERE open_date >= ? ORDER BY open_date, start_time",
                                (_dt.date.today().isoformat(),)).fetchall()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — an old or missing Jobs database: nothing to list
        return []
    out = []
    for r in rows:
        hours = f"{r['start_time']}–{r['end_time']}" if r["start_time"] and r["end_time"] else "all day"
        out.append({"id": r["opening_id"], "text": f"{r['open_date']}  {dict(OPENING_KINDS)[r['kind']]:<14} {hours}"
                                                  + (f"  ({r['who']})" if r["who"] else "")
                                                  + (f" — {r['note']}" if r["note"] else "")})
    return out


def add_opening(jobs_db: str, kind_label: str, date: str, start: str, end: str, note: str) -> tuple[bool, str]:
    import booking_db
    kind = {lab: k for k, lab in OPENING_KINDS}.get(kind_label, kind_label)
    try:
        booking_db.add_opening(jobs_db, kind, date.strip(), start.strip(), end.strip(), note=note.strip(), by="owner")
    except booking_db.BookingError as e:
        return False, str(e)
    return True, "Added."


def _build_calendar(app, f, db, edition):
    import tkinter as tk
    from tkinter import ttk

    import desk_db
    from desk_gui_agent import _tooltip
    small = ("Arial", 8)
    s = desk_db.get_settings(db)
    cal = ttk.LabelFrame(f, text="Calendar & openings  (hover for details)", padding=(6, 4))
    cal.pack(fill="x", pady=(6, 0))
    ttk.Label(cal, font=small, foreground="gray", wraplength=760, justify="left",
              text="Working Days and Workday hours come from the Jobs app → Settings (change them there)."
              + ("" if edition != "business" else " On a server, the Jobs app's schedule plus the openings and closed "
                                                    "days below are the whole picture — no Google Calendar.")
              ).pack(anchor="w")
    if edition != "business":
        v = {"calendar_sync": tk.BooleanVar(value=s.get("calendar_sync") == "ai"),
             "calendar_name": tk.StringVar(value=s.get("calendar_name") or ""),
             "calendar_days": tk.StringVar(value=str(s.get("calendar_days") or 0)),
             "calendar_fresh_hours": tk.StringVar(value=str(s.get("calendar_fresh_hours") or 4))}
        w = ttk.Checkbutton(cal, text="Sync one business Google Calendar through Claude, Muse or Grok",
                            variable=v["calendar_sync"])
        w.pack(anchor="w", pady=(4, 0)); _tooltip(w, CAL_HELP["calendar_sync"])
        r = ttk.Frame(cal); r.pack(fill="x", pady=(2, 0))
        for key, lab, width in (("calendar_name", "Calendar name", 26), ("calendar_days", "Days ahead (0 = booking horizon)", 4),
                                ("calendar_fresh_hours", "Approve all if not synced for (hours)", 4)):
            w = ttk.Label(r, text=lab, font=small); w.pack(side="left", padx=(0, 4)); _tooltip(w, CAL_HELP[key])
            e = ttk.Entry(r, textvariable=v[key], width=width); e.pack(side="left", padx=(0, 10)); _tooltip(e, CAL_HELP[key])
        status = tk.StringVar(value=calendar_status_text(db, edition))
        ttk.Label(cal, textvariable=status, font=small, foreground="#555").pack(anchor="w", pady=(2, 0))
        r = ttk.Frame(cal); r.pack(fill="x", pady=(2, 0))

        def save():
            ok, msg = save_calendar(db, {k: x.get() for k, x in v.items()}, edition)
            status.set(calendar_status_text(db, edition))
            _say(app, ok, msg)

        def copy_prompt():
            import booking_calendar
            text = booking_calendar.sync_prompt(desk_db.get_settings(db))
            f.clipboard_clear()
            f.clipboard_append(text)
            _say(app, True, "Sync prompt copied — paste it into Claude, Muse or Grok.")

        def make_task():
            import booking_calendar
            try:
                msg = booking_calendar.create_scheduled_sync(desk_db.get_settings(db), edition=edition)
            except Exception as e:  # noqa: BLE001
                _say(app, False, str(e)); return
            _say(app, True, msg)

        ttk.Button(r, text="Save", command=save).pack(side="left")
        b = ttk.Button(r, text="📋 Copy sync prompt", command=copy_prompt); b.pack(side="left", padx=(6, 0))
        _tooltip(b, CAL_HELP["prompt"])
        b = ttk.Button(r, text="⏱ Create scheduled sync", command=make_task); b.pack(side="left", padx=(6, 0))
        _tooltip(b, CAL_HELP["task"])
        ttk.Button(r, text="↻", width=3, command=lambda: status.set(calendar_status_text(db, edition))).pack(
            side="left", padx=(6, 0))
    # extra openings and closed days (both editions)
    jobs_db = jobs_db_path()
    op = ttk.Frame(cal); op.pack(fill="x", pady=(6, 0))
    w = ttk.Label(op, text="Extra openings and closed days:", font=small); w.pack(anchor="w"); _tooltip(w, CAL_HELP["openings"])
    lb = tk.Listbox(op, height=4, width=90, font=("Consolas", 9)); lb.pack(anchor="w", fill="x")
    ids: list = []

    def reload():
        lb.delete(0, "end"); ids.clear()
        for row in opening_rows(jobs_db):
            ids.append(row["id"]); lb.insert("end", row["text"])

    r = ttk.Frame(op); r.pack(fill="x", pady=(2, 0))
    kind = tk.StringVar(value=OPENING_KINDS[1][1])
    _calm(ttk.Combobox(r, textvariable=kind, values=[lab for _, lab in OPENING_KINDS], state="readonly",
                       width=14)).pack(side="left")
    fields = {}
    for key, lab, width in (("date", "Date (YYYY-MM-DD)", 11), ("start", "From", 6), ("end", "To", 6), ("note", "Note", 22)):
        ttk.Label(r, text=lab, font=small).pack(side="left", padx=(8, 2))
        fields[key] = tk.StringVar(); ttk.Entry(r, textvariable=fields[key], width=width).pack(side="left")

    def add():
        if not jobs_db:
            _say(app, False, "The Jobs app isn't set up yet."); return
        ok, msg = add_opening(jobs_db, kind.get(), fields["date"].get(), fields["start"].get(), fields["end"].get(),
                              fields["note"].get())
        if ok:
            for x in fields.values():
                x.set("")
            reload()
        else:
            _say(app, False, msg)

    def remove():
        import booking_db
        sel = lb.curselection()
        if sel and jobs_db:
            booking_db.delete_opening(jobs_db, ids[sel[0]]); reload()

    ttk.Button(r, text="Add", command=add).pack(side="left", padx=(8, 0))
    ttk.Button(r, text="Remove selected", command=remove).pack(side="left", padx=(6, 0))
    ttk.Label(op, font=small, foreground="gray", text="Blank From/To on a closed day = the whole day.").pack(anchor="w")
    reload()


# ── Share & embed, waitlist, reminders (§4, §9.4; Phase 6) ───────────────────

EMBED_HELP = {
    "sites": ("Websites that may show the booking page inside their own page (the embed). Blank = nobody can; the "
              "link and button still work everywhere. Set only here, on this PC."),
    "booking_waitlist": ("Customers with a booking can tick 'Tell me if an earlier time opens'. When one opens (a "
                         "cancellation, a moved job, an extra opening…) the first one waiting gets it held for them."),
    "booking_waitlist_hold_hours": "How long an offered opening is held before it passes to the next person.",
    "booking_waitlist_approval": "Taking an offered opening waits for your OK (off: it follows the approval setting).",
    "booking_reminders": "Reminders before each confirmed visit. Text falls back to email when texting isn't set up.",
    "booking_reminder_hour": "The day-before reminder goes out at this hour.",
    "booking_reminder_morning": "Also a short reminder the morning of the visit.",
}
REMINDER_CHOICES = [("email", "Email"), ("text", "Text"), ("both", "Email and text"), ("off", "Off")]


def base_url() -> str:
    try:
        import setup_wizard
        d = setup_wizard.tunnel_domain()
        return f"https://{d}" if d else ""
    except Exception:  # noqa: BLE001
        return ""


def save_followup(db: str, form: dict, edition: str) -> tuple[bool, str]:
    import desk_db
    code = {lab: k for k, lab in REMINDER_CHOICES}
    try:
        sites = [desk_db.clean_site(x) for x in str(form.get("sites") or "").replace("\n", ",").split(",") if x.strip()]
        vals = {"booking_allowed_sites": list(dict.fromkeys(sites)),
                "booking_waitlist": bool(form.get("booking_waitlist")),
                "booking_waitlist_hold_hours": int(str(form.get("booking_waitlist_hold_hours") or 2)),
                "booking_waitlist_approval": bool(form.get("booking_waitlist_approval")),
                "booking_reminders": code.get(form.get("booking_reminders"), form.get("booking_reminders") or "email"),
                "booking_reminder_hour": int(str(form.get("booking_reminder_hour") or 17)),
                "booking_reminder_morning": bool(form.get("booking_reminder_morning"))}
    except (desk_db.DeskError, ValueError) as e:
        return False, str(e)
    for k, val in vals.items():
        ok, msg = set_one(db, k, val, edition)
        if not ok:
            return ok, msg
    return True, "Saved."


def _build_embed(app, f, db, edition):
    import tkinter as tk
    from tkinter import ttk

    import desk_db
    import desk_embed
    from desk_gui_agent import _tooltip
    small = ("Arial", 8)
    s = desk_db.get_settings(db)
    em = ttk.LabelFrame(f, text="Share & embed, waitlist and reminders  (hover for details)", padding=(6, 4))
    em.pack(fill="x", pady=(6, 0))
    url = base_url()
    if not url:
        ttk.Label(em, font=small, foreground="#a40", text="Remote access isn't set up yet, so there's no public link "
                  "to share — set it up in Settings → Remote Access.").pack(anchor="w")
    r = ttk.Frame(em); r.pack(fill="x")
    ttk.Label(r, text="Pre-select a service (code, optional)", font=small).pack(side="left")
    svc = tk.StringVar(); ttk.Entry(r, textvariable=svc, width=14).pack(side="left", padx=(4, 10))

    def copy(kind):
        text = desk_embed.snippets(url, service_code=svc.get().strip(), accent=s.get("page_accent") or "")[kind]
        f.clipboard_clear(); f.clipboard_append(text)
        _say(app, True, {"link": "Link", "button": "Button HTML", "embed": "Embed HTML"}[kind] + " copied.")

    for kind, lab in (("link", "📋 Copy link"), ("button", "📋 Copy button HTML"), ("embed", "📋 Copy embed HTML")):
        ttk.Button(r, text=lab, command=lambda k=kind: copy(k)).pack(side="left", padx=(0, 6))
    r = ttk.Frame(em); r.pack(fill="x", pady=(4, 0))
    w = ttk.Label(r, text="Allowed websites (for the embed)", font=small); w.pack(side="left"); _tooltip(w, EMBED_HELP["sites"])
    v = {"sites": tk.StringVar(value=", ".join(s.get("booking_allowed_sites") or []))}
    e = ttk.Entry(r, textvariable=v["sites"], width=50); e.pack(side="left", padx=(6, 0)); _tooltip(e, EMBED_HELP["sites"])
    note = tk.StringVar(value=desk_embed.embed_note(s.get("booking_allowed_sites") or []))
    ttk.Label(em, textvariable=note, font=small, foreground="gray").pack(anchor="w")
    for k in ("booking_waitlist", "booking_waitlist_approval", "booking_reminder_morning"):
        v[k] = tk.BooleanVar(value=bool(s.get(k)))
    v["booking_waitlist_hold_hours"] = tk.StringVar(value=str(s.get("booking_waitlist_hold_hours", 2)))
    v["booking_reminder_hour"] = tk.StringVar(value=str(s.get("booking_reminder_hour", 17)))
    v["booking_reminders"] = tk.StringVar(value=dict(REMINDER_CHOICES).get(s.get("booking_reminders", "email"), "Email"))
    r = ttk.Frame(em); r.pack(fill="x", pady=(4, 0))
    w = ttk.Checkbutton(r, text="Waitlist for earlier times", variable=v["booking_waitlist"]); w.pack(side="left")
    _tooltip(w, EMBED_HELP["booking_waitlist"])
    w = ttk.Label(r, text="hold an offer for (hours)", font=small); w.pack(side="left", padx=(8, 2))
    _tooltip(w, EMBED_HELP["booking_waitlist_hold_hours"])
    ttk.Spinbox(r, from_=1, to=48, textvariable=v["booking_waitlist_hold_hours"], width=4).pack(side="left")
    w = ttk.Checkbutton(r, text="taking one needs approval", variable=v["booking_waitlist_approval"])
    w.pack(side="left", padx=(10, 0)); _tooltip(w, EMBED_HELP["booking_waitlist_approval"])
    r = ttk.Frame(em); r.pack(fill="x", pady=(4, 0))
    w = ttk.Label(r, text="Visit reminders by", font=small); w.pack(side="left"); _tooltip(w, EMBED_HELP["booking_reminders"])
    _calm(ttk.Combobox(r, textvariable=v["booking_reminders"], values=[lab for _, lab in REMINDER_CHOICES],
                       state="readonly", width=14)).pack(side="left", padx=(4, 8))
    w = ttk.Label(r, text="the day before at", font=small); w.pack(side="left"); _tooltip(w, EMBED_HELP["booking_reminder_hour"])
    ttk.Spinbox(r, from_=6, to=21, textvariable=v["booking_reminder_hour"], width=4).pack(side="left", padx=(4, 2))
    ttk.Label(r, text=":00", font=small).pack(side="left")
    w = ttk.Checkbutton(r, text="and the morning of", variable=v["booking_reminder_morning"])
    w.pack(side="left", padx=(10, 0)); _tooltip(w, EMBED_HELP["booking_reminder_morning"])

    def save():
        ok, msg = save_followup(db, {k: x.get() for k, x in v.items()}, edition)
        note.set(desk_embed.embed_note(desk_db.get_settings(db).get("booking_allowed_sites") or []))
        _say(app, ok, msg)

    ttk.Button(em, text="Save", command=save).pack(anchor="w", pady=(4, 0))


def _build_team(app, f, db, edition):
    import tkinter as tk
    from tkinter import messagebox, ttk

    small = ("Arial", 8)
    lists = {}

    def reload():
        t = team(db)
        for key, rows, fmt in (
                ("queues", t["queues"], lambda q: f"{q['queue_id']} — {q['name']} — {', '.join(q.get('members') or []) or 'no members'}"),
                ("rules", t["rules"], lambda r: f"{r['sort_order']}. {r['rule_id']}  {json.dumps(r['match'])} → {json.dumps(r['action'])}"),
                ("types", t["types"], lambda y: f"{y['type_id']} — {y['name']} ({y['kind']}) → {y.get('default_queue') or 'no queue'}, {y['default_priority']}")):
            lb = lists[key]
            lb.delete(0, "end")
            lb.ids = [r.get("queue_id") or r.get("rule_id") or r.get("type_id") for r in rows]
            for r in rows:
                lb.insert("end", fmt(r))

    def run(fn, *a):
        try:
            fn(db, *a, edition)
            _say(app, True, "Saved.")
        except Exception as e:  # noqa: BLE001
            messagebox.showwarning("Team", str(e))
        reload()

    def picked(key):
        lb = lists[key]
        sel = lb.curselection()
        return lb.ids[sel[0]] if sel and sel[0] < len(lb.ids) else None

    # queues
    q = ttk.LabelFrame(f, text="Queues (new tickets go round-robin to members who aren't on time off)", padding=(6, 4))
    q.pack(fill="x")
    lists["queues"] = tk.Listbox(q, height=4, width=90, font=("Consolas", 8)); lists["queues"].pack(fill="x")
    qid, qname, qmem = tk.StringVar(), tk.StringVar(), tk.StringVar()
    r = ttk.Frame(q); r.pack(fill="x", pady=(4, 0))
    for lab, var, w in (("id", qid, 12), ("name", qname, 18), ("member user ids, comma-separated", qmem, 30)):
        ttk.Label(r, text=lab, font=small).pack(side="left", padx=(0, 2))
        ttk.Entry(r, textvariable=var, width=w).pack(side="left", padx=(0, 8))
    ttk.Button(r, text="Save queue", command=lambda: run(save_queue, qid.get(), qname.get(), qmem.get())).pack(side="left")
    ttk.Button(r, text="Delete selected", command=lambda: (picked("queues") and messagebox.askyesno(
        "Team", "Delete this queue?") and run(delete_queue, picked("queues")))).pack(side="left", padx=(4, 0))
    # rules
    rl = ttk.LabelFrame(f, text="Assignment rules (first match wins)", padding=(6, 4)); rl.pack(fill="x", pady=(6, 0))
    lists["rules"] = tk.Listbox(rl, height=4, width=90, font=("Consolas", 8)); lists["rules"].pack(fill="x")
    rid, ron, rval, rto, rtarget, rorder = (tk.StringVar(), tk.StringVar(value="keyword"), tk.StringVar(),
                                            tk.StringVar(value="user"), tk.StringVar(), tk.StringVar(value="100"))
    r = ttk.Frame(rl); r.pack(fill="x", pady=(4, 0))
    ttk.Label(r, text="id", font=small).pack(side="left"); ttk.Entry(r, textvariable=rid, width=10).pack(side="left", padx=(2, 6))
    _calm(ttk.Combobox(r, textvariable=ron, state="readonly", width=8, values=["keyword", "type"])).pack(side="left")
    ttk.Entry(r, textvariable=rval, width=14).pack(side="left", padx=(2, 6))
    ttk.Label(r, text="→", font=small).pack(side="left")
    _calm(ttk.Combobox(r, textvariable=rto, state="readonly", width=6, values=["user", "queue"])).pack(side="left", padx=(2, 2))
    ttk.Entry(r, textvariable=rtarget, width=12).pack(side="left", padx=(0, 6))
    ttk.Label(r, text="order", font=small).pack(side="left"); ttk.Entry(r, textvariable=rorder, width=5).pack(side="left", padx=(2, 6))
    ttk.Button(r, text="Save rule", command=lambda: run(save_rule, rid.get(), ron.get(), rval.get(), rto.get(),
                                                       rtarget.get(), rorder.get())).pack(side="left")
    ttk.Button(r, text="Delete selected", command=lambda: (picked("rules") and messagebox.askyesno(
        "Team", "Delete this rule?") and run(delete_rule, picked("rules")))).pack(side="left", padx=(4, 0))
    # types
    ty = ttk.LabelFrame(f, text="Ticket types", padding=(6, 4)); ty.pack(fill="x", pady=(6, 0))
    lists["types"] = tk.Listbox(ty, height=4, width=90, font=("Consolas", 8)); lists["types"].pack(fill="x")
    tid, tname, tq = tk.StringVar(), tk.StringVar(), tk.StringVar()
    r = ttk.Frame(ty); r.pack(fill="x", pady=(4, 0))
    for lab, var, w in (("id", tid, 12), ("name", tname, 18), ("default queue", tq, 12)):
        ttk.Label(r, text=lab, font=small).pack(side="left", padx=(0, 2))
        ttk.Entry(r, textvariable=var, width=w).pack(side="left", padx=(0, 8))
    ttk.Button(r, text="Save type", command=lambda: run(save_type, tid.get(), tname.get(), tq.get())).pack(side="left")
    reload()
