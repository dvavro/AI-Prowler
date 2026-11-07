"""The 🏗 Estimator tab in AI-Prowler's desktop GUI.

rag_gui.py calls build_estimator_tab(app) once, after its own tabs. Everything else lives here, so the
Estimator's screens never crowd AI-Prowler's main file. Sections (their titles are what Setup AI-Prowler scrolls
to, so keep the first words stable):

    🧭 Estimator setup        on/off, what's installed, the setup checklist
    🏢 Company and pricing    name, phone, license, sales tax, overhead, profit, minimum charge
    🏗 Trades                 which construction trades the Estimator runs takeoffs for
    🤖 AI agents and budget   which AI runs each agent, its backup, the daily and monthly budget
    🧑‍💼 Director              review limit, quick-send limit, follow-ups, daily briefing, watcher
    💾 Data and backups       where estimator.db lives, back up now
    📱 Phone and web app      what's coming (David's track) and how to use it from chat today
    ❓ Help                   what to ask your AI

While the Estimator is switched off, every section but the first folds up to "(not enabled)" (the same as
AI-Prowler's other features) and nothing that was typed or saved is lost.
"""
from __future__ import annotations

import os
import subprocess
import sys

from estimator.ui import model

WRAP = 760
GREEN, RED, GREY = "#2e7d32", "#b00020", "#6b7280"


def build_estimator_tab(app):
    """Add the tab to app.notebook. Returns the tab frame, or None if it couldn't be built (never raises)."""
    try:
        from tkinter import ttk
        outer = ttk.Frame(app.notebook)
        app.notebook.add(outer, text=model.TAB_TITLE)
        inner = app._make_scrollable_tab(outer) if hasattr(app, "_make_scrollable_tab") else outer
        app._estimator_tab = EstimatorTab(app, inner)
        return outer
    except Exception as exc:  # noqa: BLE001 - a problem here must never stop AI-Prowler's GUI
        print(f"[estimator tab] not shown: {exc}")
        return None


class EstimatorTab:
    def __init__(self, app, parent):
        import tkinter as tk
        from tkinter import ttk
        self.app, self.tk, self.ttk, self.parent = app, tk, ttk, parent
        self.root = parent.winfo_toplevel()
        self.sections = {}
        self._setup_section()
        for build in (self._company_section, self._trades_section, self._agents_section, self._director_section,
                      self._data_section, self._phone_section, self._help_section):
            try:
                build()
            except Exception as exc:  # noqa: BLE001 - one broken section doesn't take the rest down
                ttk.Label(parent, text=f"(couldn't show this section: {exc})", foreground=RED).pack(anchor="w",
                                                                                                    padx=16)
        self._gate()

    # ------------------------------------------------------------ helpers

    def _box(self, title: str, key: str):
        box = self.ttk.LabelFrame(self.parent, text=title, padding=(12, 8))
        box.pack(fill="x", padx=16, pady=(10, 4))
        self.sections[key] = box
        return box

    def _note(self, parent, text, color="#333", size=9):
        lbl = self.ttk.Label(parent, text=text, wraplength=WRAP, justify="left", foreground=color,
                             font=("Arial", size))
        lbl.pack(anchor="w")
        return lbl

    def _say(self, label, result):
        ok, msg = result
        label.config(text=("✅ " if ok else "❌ ") + msg, foreground=GREEN if ok else RED)
        return ok

    def _gate(self):
        """Fold every section but the first while the Estimator is switched off (AI-Prowler's own helper)."""
        try:
            import setup_wizard as sw
        except Exception:  # noqa: BLE001 - outside AI-Prowler: no switch, nothing to fold
            return
        note = "(not enabled)  Turn the Estimator on above, or in Setup AI-Prowler → Change my choices."
        for key, box in self.sections.items():
            if key != "setup":
                sw.gate_section(self.root, box, model.is_on, note)

    def _go_to_tab(self, title_start: str):
        nb = self.app.notebook
        for i in range(nb.index("end")):
            if str(nb.tab(i, "text")).startswith(title_start):
                nb.select(i)
                return True
        return False

    # ------------------------------------------------------------ 🧭 setup

    def _setup_section(self):
        ttk = self.ttk
        box = self._box("🧭 Estimator setup", "setup")
        self._note(box, "Estimates and bids for construction trades and service jobs, run by the Estimating "
                        "Director. You use it by asking your AI (Claude, Grok or Muse), for example \"quote a "
                        "pressure wash for the Garcia house\". This tab holds the settings.", "#444")
        row = ttk.Frame(box)
        row.pack(fill="x", pady=(8, 0))
        self.state_lbl = ttk.Label(row, text="", font=("Arial", 10, "bold"))
        self.state_lbl.pack(side="left")
        self.switch_btn = ttk.Button(row, text="", command=self._toggle)
        self.switch_btn.pack(side="left", padx=10)
        ttk.Button(row, text="🔄 Refresh", command=self.refresh_setup).pack(side="right")
        self.facts = self._note(box, "", GREY, 8)
        self.switch_msg = self._note(box, "")
        self.check_frame = ttk.Frame(box)
        self.check_frame.pack(fill="x", pady=(8, 0))
        self.refresh_setup()

    def _toggle(self):
        self._say(self.switch_msg, model.set_on(not model.is_on()))
        self.refresh_setup()

    def refresh_setup(self):
        ttk = self.ttk
        on = model.is_on()
        self.state_lbl.config(text="✅ The Estimator is ON" if on else "The Estimator is OFF",
                              foreground=GREEN if on else GREY)
        self.switch_btn.config(text="Turn it off" if on else "✅ Turn the Estimator on")
        for w in self.check_frame.winfo_children():
            w.destroy()
        try:
            ov = model.overview()
        except Exception as exc:  # noqa: BLE001
            self.facts.config(text=f"Couldn't read the Estimator: {exc}", foreground=RED)
            return
        bad = f"  ·  ⚠ {len(ov['module_errors'])} module(s) didn't load" if ov["module_errors"] else ""
        self.facts.config(text=(f"{len(ov['trades'])} construction trades and {len(ov['services'])} service quotes  ·  "
                                f"{ov['tools']} AI tools  ·  {ov['estimates']} estimate(s)  ·  database v"
                                f"{ov['db_version']}, {ov['db_kb']} KB  ·  background checks "
                                f"{'running' if ov['watcher_running'] else 'not running'}{bad}"))
        if not on:
            return
        st = ov["setup"]
        ttk.Label(self.check_frame, text=f"Setup checklist: {st['done']} of {st['total']} done",
                  font=("Arial", 9, "bold")).pack(anchor="w")
        icons = {"done": "✅", "skipped": "⏭", "not_started": "⬜"}
        quick = {"company_profile": "🏢 Company and pricing", "tax": "🏢 Company and pricing",
                 "markups": "🏢 Company and pricing", "services": "🏗 Trades", "ai_check": "🤖 AI agents and budget"}
        rows = ttk.Frame(self.check_frame)
        rows.pack(fill="x")
        for i, s in enumerate(st["steps"]):
            ttk.Label(rows, text=f"{icons.get(s['status'], '⬜')}  {s['label']}").grid(row=i, column=0, sticky="w",
                                                                                      padx=(0, 24), pady=1)
            if s["status"] == "done":
                continue
            if s["step"] in quick:
                ttk.Button(rows, text="Set up", width=8,
                           command=lambda t=quick[s["step"]]: self._scroll_to(t)).grid(row=i, column=1)
            ttk.Button(rows, text="Done", width=6,
                       command=lambda k=s["step"]: self._step(k, "done")).grid(row=i, column=2, padx=2)
            if s["status"] != "skipped":
                ttk.Button(rows, text="Skip", width=6,
                           command=lambda k=s["step"]: self._step(k, "skipped")).grid(row=i, column=3)
        if st["sample_prices_in_use"]:
            self._note(self.check_frame, f"⚠ {st['sample_prices_in_use']} sample prices are still in use. Ask your AI "
                                         "\"show my price book\" to set your own before sending real bids.",
                       "#b45309")

    def _step(self, step, status):
        ok, msg = model.mark_step(step, status)
        if not ok:
            self._say(self.switch_msg, (ok, msg))
        self.refresh_setup()

    def _scroll_to(self, title_start: str):
        box = next((b for b in self.sections.values() if str(b.cget("text")).startswith(title_start)), None)
        if box is None:
            return
        try:
            canvas = box.master.master
            canvas.update_idletasks()
            height = box.master.winfo_height()
            if height > 0 and canvas.winfo_class() == "Canvas":
                canvas.yview_moveto(max(0.0, (box.winfo_y() - 8) / height))
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------ 🏢 company

    def _company_section(self):
        ttk = self.ttk
        box = self._box("🏢 Company and pricing", "company")
        self._note(box, "Goes on every bid. Percentages are plain numbers: 8.6 means 8.6%.", GREY, 8)
        p = model.profile()
        grid = ttk.Frame(box)
        grid.pack(fill="x", pady=(6, 0))
        fields = (("name", "Company name *"), ("phone", "Phone"), ("address", "Address"), ("license_no", "License #"),
                  ("tax_pct", "Sales tax %"), ("overhead_pct", "Overhead %"), ("profit_pct", "Profit %"),
                  ("minimum_charge", "Minimum charge $"))
        self.company_vars = {}
        for i, (key, label) in enumerate(fields):
            ttk.Label(grid, text=label).grid(row=i // 2, column=(i % 2) * 2, sticky="w", padx=(0, 6), pady=2)
            var = self.tk.StringVar(value=p.get(key, ""))
            ttk.Entry(grid, textvariable=var, width=34 if key in ("name", "address") else 18).grid(
                row=i // 2, column=(i % 2) * 2 + 1, sticky="w", padx=(0, 18), pady=2)
            self.company_vars[key] = var
        b = ttk.Frame(box)
        b.pack(fill="x", pady=(6, 0))
        msg = None

        def save():
            if self._say(msg, model.save_profile({k: v.get() for k, v in self.company_vars.items()})):
                self.refresh_setup()
        ttk.Button(b, text="💾 Save company and pricing", command=save).pack(side="left")
        msg = self._note(box, "")

    # ------------------------------------------------------------ 🏗 trades

    def _trades_section(self):
        ttk = self.ttk
        box = self._box("🏗 Trades", "trades")
        self._note(box, "Trades that are on can be estimated and get a takeoff task in plan jobs. Service quotes "
                        "(pressure washing, cleaning, pools, pest, junk, windows, lawn care, other services) are "
                        "always available.", GREY, 8)
        grid = ttk.Frame(box)
        grid.pack(fill="x", pady=(6, 0))
        msg = None
        self.trade_vars = {}
        for i, t in enumerate(model.trades()):
            var = self.tk.BooleanVar(value=t["enabled"])
            self.trade_vars[t["module_id"]] = var
            ttk.Checkbutton(grid, text=t["name"], variable=var,
                            command=lambda m=t["module_id"], v=var: self._say(msg, model.set_trade(m, v.get()))
                            ).grid(row=i // 4, column=i % 4, sticky="w", padx=(0, 16), pady=1)
        msg = self._note(box, "")

    # ------------------------------------------------------------ 🤖 agents

    def _agents_section(self):
        ttk = self.ttk
        box = self._box("🤖 AI agents and budget", "agents")
        ov = model.agents()
        keys = ov["api_keys_saved"]
        krow = ttk.Frame(box)
        krow.pack(fill="x")
        ttk.Label(krow, text=("Agent API keys:  Claude " + ("✅ saved" if keys.get("claude_api") else "— not saved")
                              + "   ·   Grok " + ("✅ saved" if keys.get("grok_api") else "— not saved"))
                  ).pack(side="left")
        ttk.Button(krow, text="🔑 Open Agent API Key", command=lambda: self._go_to_tab("🏢 Small Business")
                   ).pack(side="left", padx=10)
        self._note(box, "Agents start Off, so nothing runs or costs money until you choose. \"From chat only\" waits "
                        "for your AI in chat; Claude or Grok runs on its own with the key above, within the budget. "
                        "Agents only write notes and drafts: they never approve, change prices or send anything.",
                   GREY, 8)
        grid = ttk.Frame(box)
        grid.pack(fill="x", pady=(6, 0))
        for c, h in enumerate(("Agent", "Runs on", "Model (blank = default)", "Backup", "")):
            ttk.Label(grid, text=h, font=("Arial", 8, "bold")).grid(row=0, column=c, sticky="w", padx=(0, 8))
        msg = None
        labels = {"off": "Off", "chat_only": "From chat only", "claude_api": "Claude", "grok_api": "Grok"}
        back = {v: k for k, v in labels.items()}
        for i, r in enumerate(ov["roles"], start=1):
            ttk.Label(grid, text=r["label"] + ("" if r["works_now"] else "  (needs plans)")).grid(
                row=i, column=0, sticky="w", padx=(0, 8), pady=1)
            prov = self.tk.StringVar(value=labels[r["provider"]])
            ttk.Combobox(grid, textvariable=prov, values=list(labels.values()), state="readonly", width=15).grid(
                row=i, column=1, sticky="w", padx=(0, 8))
            mdl = self.tk.StringVar(value=r["model"] if r["provider"] in ("claude_api", "grok_api") and r["model"]
                                    else "")
            ttk.Entry(grid, textvariable=mdl, width=22).grid(row=i, column=2, sticky="w", padx=(0, 8))
            fb = self.tk.StringVar(value={"claude_api": "Claude", "grok_api": "Grok"}.get(r["fallback_provider"], "None"))
            ttk.Combobox(grid, textvariable=fb, values=["None", "Claude", "Grok"], state="readonly", width=8).grid(
                row=i, column=3, sticky="w", padx=(0, 8))
            ttk.Button(grid, text="Save", width=6, command=lambda role=r["role"], p=prov, m=mdl, f=fb: self._say(
                msg, model.save_role(role, back[p.get()], m.get().strip(),
                                     {"Claude": "claude_api", "Grok": "grok_api"}.get(f.get(), "")))
                       ).grid(row=i, column=4, sticky="w")
        brow = ttk.Frame(box)
        brow.pack(fill="x", pady=(10, 0))
        b, s = ov["budget"], ov["spent"]
        ttk.Label(brow, text="Budget:  $ a day").pack(side="left")
        day = self.tk.StringVar(value=f"{b['daily_cents'] / 100:.2f}")
        ttk.Entry(brow, textvariable=day, width=8).pack(side="left", padx=4)
        ttk.Label(brow, text="   $ a month").pack(side="left")
        month = self.tk.StringVar(value=f"{b['monthly_cents'] / 100:.2f}")
        ttk.Entry(brow, textvariable=month, width=8).pack(side="left", padx=4)
        ttk.Button(brow, text="💾 Save budget", command=lambda: self._say(msg, model.save_budget(day.get(), month.get()))
                   ).pack(side="left", padx=8)
        ttk.Label(brow, text=(f"Spent today ${s['today']['micros'] / 1_000_000:.2f}  ·  this month "
                              f"${s['this_month']['micros'] / 1_000_000:.2f} ({s['this_month']['calls']} calls)"),
                  foreground=GREY).pack(side="left", padx=8)
        msg = self._note(box, "")

    # ------------------------------------------------------------ 🧑‍💼 director

    def _director_section(self):
        ttk = self.ttk
        box = self._box("🧑‍💼 Director", "director")
        self._note(box, "The Estimating Director runs every job: it asks the questions, prices, waits for the "
                        "checks you set here, and keeps an eye on jobs while AI-Prowler is running.", GREY, 8)
        s = model.director_settings()
        grid = ttk.Frame(box)
        grid.pack(fill="x", pady=(6, 0))
        self.dir_vars = {}

        def entry(row, col, label, key, value, width=10):
            ttk.Label(grid, text=label).grid(row=row, column=col, sticky="w", padx=(0, 6), pady=2)
            var = self.tk.StringVar(value=value)
            ttk.Entry(grid, textvariable=var, width=width).grid(row=row, column=col + 1, sticky="w", padx=(0, 18))
            self.dir_vars[key] = var

        def check(row, col, label, key):
            var = self.tk.BooleanVar(value=bool(s[key]))
            ttk.Checkbutton(grid, text=label, variable=var).grid(row=row, column=col, columnspan=2, sticky="w",
                                                                 pady=2)
            self.dir_vars[key] = var

        entry(0, 0, "A Reviewer checks estimates over $", "review_required_over_cents",
              f"{s['review_required_over_cents'] / 100:.2f}")
        entry(0, 2, "Quotes up to $ can be sent with one tap", "quick_send_limit_cents",
              f"{s['quick_send_limit_cents'] / 100:.2f}")
        entry(1, 0, "Follow up on quotes after (days)", "follow_up_days", str(s["follow_up_days"]))
        entry(1, 2, "Remind a reviewer after (days)", "review_reminder_days", str(s["review_reminder_days"]))
        check(2, 0, "Daily briefing", "briefing_enabled")
        entry(2, 2, "Briefing time (24-hour)", "briefing_time", s["briefing_time"])
        ttk.Label(grid, text="Briefing by").grid(row=3, column=0, sticky="w", pady=2)
        chan = self.tk.StringVar(value=s["briefing_channel"])
        ttk.Combobox(grid, textvariable=chan, values=["chat", "pwa", "email"], state="readonly", width=8).grid(
            row=3, column=1, sticky="w")
        self.dir_vars["briefing_channel"] = chan
        entry(3, 2, "Briefing email", "briefing_email", s["briefing_email"] or "", 26)
        check(4, 0, "Check jobs in the background", "watcher_enabled")
        check(4, 2, "Mark quotes expired after their valid-until date", "auto_expire_bids")
        msg = None

        def save():
            from decimal import Decimal, InvalidOperation
            changes = {}
            try:
                for key, var in self.dir_vars.items():
                    val = var.get()
                    if key.endswith("_cents"):
                        changes[key] = int((Decimal(str(val).strip().lstrip("$") or "0") * 100).to_integral_value())
                    elif key in ("follow_up_days", "review_reminder_days"):
                        changes[key] = val.strip()
                    elif key == "briefing_email":
                        changes[key] = val.strip() or None
                    else:
                        changes[key] = val
            except InvalidOperation:
                self._say(msg, (False, "Dollar amounts must be numbers, like 500.00"))
                return
            self._say(msg, model.save_director(changes))
        ttk.Button(box, text="💾 Save Director settings", command=save).pack(anchor="w", pady=(6, 0))
        msg = self._note(box, "")

    # ------------------------------------------------------------ 💾 data

    def _data_section(self):
        ttk = self.ttk
        box = self._box("💾 Data and backups", "data")
        from estimator import config
        self._note(box, f"Estimates, bids and settings are kept in {config.db_path()}", "#444")
        row = ttk.Frame(box)
        row.pack(fill="x", pady=(6, 0))
        msg = None
        listing = None

        def backup():
            self._say(msg, model.backup_now())
            listing.config(text="Recent backups: " + (", ".join(model.recent_backups()) or "none yet"))
        ttk.Button(row, text="💾 Back up now", command=backup).pack(side="left")
        ttk.Button(row, text="📂 Open the folder", command=lambda: _open_folder(config.data_dir())).pack(side="left",
                                                                                                     padx=6)
        listing = self._note(box, "Recent backups: " + (", ".join(model.recent_backups()) or "none yet"), GREY, 8)
        msg = self._note(box, "")

    # ------------------------------------------------------------ 📱 phone

    def _phone_section(self):
        box = self._box("📱 Phone and web app", "phone")
        self._note(box, "Coming next: an Estimates tab in the Jobs app on your phone, and an Estimator web app for "
                        "plan review on this PC (being built on the shared estimator branch). Until then, everything "
                        "works from your AI in chat, on this PC or on your phone through Remote Access: start, "
                        "review, approve and send estimates by asking.", "#444")

    # ------------------------------------------------------------ ❓ help

    def _help_section(self):
        ttk = self.ttk
        box = self._box("❓ Help", "help")
        self._note(box, "Try asking your AI:", "#444")
        for p in model.example_prompts():
            self._note(box, f"   •  \"{p}\"", "#333")
        self._note(box, "Ask \"how do I use the Estimator?\" and your AI will read the Estimator's own instructions "
                        "(how_to_estimate).", GREY, 8)


def _open_folder(path) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # noqa: S606
        else:
            subprocess.Popen(["xdg-open", str(path)])  # noqa: S603, S607
    except Exception:  # noqa: BLE001
        pass
