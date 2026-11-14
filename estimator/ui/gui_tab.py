"""The 🏗 Estimator tab in AI-Prowler's desktop GUI.

rag_gui.py calls build_estimator_tab(app) once, after its own tabs. Everything else lives here, so the
Estimator's screens never crowd AI-Prowler's main file. Sections (their titles are what Setup AI-Prowler scrolls
to, so keep the first words stable):

    🧭 Estimator setup        on/off, what's installed, the setup checklist
    🏢 Company and pricing    name, phone, license, sales tax, overhead, profit, minimum charge
    💰 Labor rates            what your crew's time costs, per hour or per unit
    🏗 Trades                 which construction trades the Estimator runs takeoffs for
    🤖 AI agents and budget   which AI runs each agent, its backup, the daily and monthly budget
    🧑‍💼 Director              review limit, quick-send limit, follow-ups, daily briefing, watcher
    📦 Modules               every installed trade and service, its version and how it's priced
    💾 Data and backups       where estimator.db lives, back up now
      🔧 CAD and tools          DXF support, the DWG converter and OCR status
    📱 Phone and web app      the web app address on this PC and your phone, and who can sign in
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
        self._section_box = {}
        self._section_title = {}
        self._section_header = {}
        self._section_collapsed = {}
        self._setup_section()
        for build in (self._company_section, self._labor_section, self._trades_section, self._agents_section,
                      self._director_section, self._modules_section, self._data_section, self._sync_section,
                      self._cad_section,
                      self._phone_section, self._help_section):
            try:
                build()
            except Exception as exc:  # noqa: BLE001 - one broken section doesn't take the rest down
                ttk.Label(parent, text=f"(couldn't show this section: {exc})", foreground=RED).pack(anchor="w",
                                                                                                    padx=16)
        self._gate()

    # ------------------------------------------------------------ helpers

    def _box(self, title: str, key: str):
        """A section whose title collapses/expands it when selected. A plain Frame is
        used, not a LabelFrame: a LabelFrame keeps its expanded height even after its
        content is unpacked, so a collapsed section would leave a big empty box.
        The body keeps a grooved border so the grouped look stays."""
        box = self.ttk.Frame(self.parent)
        box.pack(fill="x", padx=16, pady=(10, 4))
        header = self.ttk.Label(box, text="▼ " + title, font=("Arial", 9, "bold"), cursor="hand2")
        header.pack(anchor="w")
        body = self.ttk.Frame(box, relief="groove", borderwidth=1, padding=(12, 8))
        body.pack(fill="x")
        self.sections[key] = body
        self._section_box[key] = box
        self._section_title[key] = title
        self._section_header[key] = header
        self._section_collapsed[key] = False
        header.bind("<Button-1>", lambda e, k=key: self._toggle_section(k))
        return body

    def _toggle_section(self, key: str):
        """Collapse or expand a section (from its title)."""
        collapsed = not self._section_collapsed.get(key, False)
        self._section_collapsed[key] = collapsed
        title = self._section_title[key]
        if collapsed:
            self.sections[key].pack_forget()
            self._section_header[key].config(text="▶ " + title)
        else:
            self.sections[key].pack(fill="x")
            self._section_header[key].config(text="▼ " + title)

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
        prow = ttk.Frame(box)
        prow.pack(fill="x", pady=(8, 0))
        self.practice_btn = ttk.Button(prow, text="", command=self._practice)
        self.practice_btn.pack(side="left")
        ttk.Label(prow, text="A ready-made roof and house-wash estimate to try things on; it stays out of your history.",
                  foreground=GREY, font=("Arial", 8)).pack(side="left", padx=8)
        self.refresh_setup()

    def _practice(self):
        if model.practice_id():
            from tkinter import messagebox
            if not messagebox.askyesno("Delete the practice project?", "Delete the practice estimate and anything made "
                                       "from it (bids, recorded costs)? Your real work isn't touched.", parent=self.root):
                return
            self._say(self.switch_msg, model.practice_delete())
        else:
            self._say(self.switch_msg, model.practice_create())
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
        try:
            self.practice_btn.config(text="🗑 Delete the practice project" if model.practice_id() else
                                     "🎓 Make a practice project")
        except Exception:  # noqa: BLE001 - no database yet
            self.practice_btn.config(text="🎓 Make a practice project")
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
                 "markups": "🏢 Company and pricing", "services": "🏗 Trades", "team_approvals": "🧑‍💼 Director",
                 "ai_check": "🤖 AI agents and budget", "labor_rates": "💰 Labor rates"}
        # Steps with no section in this tab: the Price Book and the bid template live in the web app,
        # and a sample quote is the practice project.
        actions = {"price_book_review": lambda: self._open_web("#/price_book"),
                   "bid_template": lambda: self._open_web("#/settings"),
                   "sample_quote": self._sample_quote_setup}
        rows = ttk.Frame(self.check_frame)
        rows.pack(fill="x")
        rows.columnconfigure(1, weight=1)  # the leader line stretches; the buttons stay right
        for i, s in enumerate(st["steps"]):
            ttk.Label(rows, text=f"{icons.get(s['status'], '⬜')}  {s['label']}").grid(row=i, column=0, sticky="w",
                                                                                      padx=(0, 24), pady=1)
            self._checklist_leader(rows, i)
            # The button that opens the step's setup — "Set up" while it is not done,
            # "Change" once it is done, so a finished step can still be edited.
            if s["step"] in quick:
                open_cmd = lambda t=quick[s["step"]]: self._scroll_to(t)
            elif s["step"] in actions:
                open_cmd = actions[s["step"]]
            else:
                open_cmd = None
            if open_cmd is not None:
                ttk.Button(rows, text="Change" if s["status"] == "done" else "Set up", width=8,
                           command=open_cmd).grid(row=i, column=2)
            if s["status"] == "done":
                continue
            ttk.Button(rows, text="Done", width=6,
                       command=lambda k=s["step"]: self._step(k, "done")).grid(row=i, column=3, padx=2)
            if s["status"] != "skipped":
                ttk.Button(rows, text="Skip", width=6,
                           command=lambda k=s["step"]: self._step(k, "skipped")).grid(row=i, column=4)
        if st["sample_prices_in_use"]:
            self._note(self.check_frame, f"⚠ {st['sample_prices_in_use']} sample prices are still in use. Ask your AI "
                                         "\"show my price book\" to set your own before sending real bids.",
                       "#b45309")

    def _checklist_leader(self, rows, i):
        """A dashed line from a checklist item's text to its buttons, as in the
        Setup AI-Prowler home page (setup_wizard.SetupCenterPanel._leader).
        Gridded in the stretch column, so it fills exactly the gap between them."""
        try:
            bg = self.ttk.Style().lookup("TFrame", "background") or rows.winfo_toplevel().cget("bg")
        except Exception:  # noqa: BLE001 - fall back to the default canvas background
            bg = ""
        line = self.tk.Canvas(rows, width=20, height=3, highlightthickness=0, bd=0,
                              **({"bg": bg} if bg else {}))
        line.leader = True  # for tests

        def draw(e=None):
            line.delete("all")
            line.create_line(0, 2, line.winfo_width(), 2, dash=(3, 4), fill="#8a8a8a")
        line.bind("<Configure>", draw)
        line.grid(row=i, column=1, sticky="ew", padx=(8, 8))
        draw()  # the line exists even before the first Configure event (e.g. tests)

    def _step(self, step, status):
        ok, msg = model.mark_step(step, status)
        if not ok:
            self._say(self.switch_msg, (ok, msg))
        self.refresh_setup()

    def _open_user_guide(self):
        """Open the same User Guide popup as Help \u2192 User Guide, jumped to the Estimator chapter."""
        show = getattr(self.app, "show_user_guide", None)
        if callable(show):
            show(section="29. Estimator")
            return
        from pathlib import Path
        guide = Path(__file__).resolve().parents[2] / "COMPLETE_USER_GUIDE.md"
        if guide.exists():
            _open_folder(guide)

    def _open_web(self, path: str):
        """Open a page of the Estimator web app in the browser (Price Book, Settings, ...)."""
        _open_folder(model.web_app_access()["url"] + path)

    def _sample_quote_setup(self):
        """Make the practice project (the sample quote) if there isn't one, then mark the step done."""
        if not model.practice_id():
            ok, msg = model.practice_create()
            self._say(self.switch_msg, (ok, msg))
            if not ok:
                return
        self._step("sample_quote", "done")

    def _scroll_to(self, title_start: str):
        key = next((k for k, t in self._section_title.items() if t.startswith(title_start)), None)
        if key is None:
            return
        if self._section_collapsed.get(key):
            self._toggle_section(key)  # scrolling to a section opens it so its content is seen
        box = self._section_box[key]
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
        self._note(box, "Overhead % is the slice added to every bid to cover running the business \u2014 rent, "
                        "insurance, vehicle, office and phone \u2014 the costs that aren't tied to one job. It's "
                        "charged as a % of the job's direct cost (materials + labor + equipment + subs). Profit % "
                        "is then charged on top of cost + overhead, not on cost alone.", GREY, 8)
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

    # ------------------------------------------------------------ 💰 labor rates

    def _labor_section(self):
        ttk = self.ttk
        box = self._box("💰 Labor rates", "labor")
        self._note(box, "What your crew's time costs. These rates price the labor lines in every estimate. "
                        "Sample rates are placeholders \u2014 set your own before sending real bids.", GREY, 8)
        grid = ttk.Frame(box)
        grid.pack(fill="x", pady=(6, 0))
        msg = None
        self.labor_vars = {}
        rates = model.labor_rates()
        by_mod = {}
        for r in rates:
            by_mod.setdefault(r.get("module_id") or "other", []).append(r)
        row = 0
        for mod_id in sorted(by_mod):
            ttk.Label(grid, text=mod_id.replace("_", " ").title(), font=("Arial", 9, "bold")
                      ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(6, 1))
            row += 1
            for r in by_mod[mod_id]:
                # The description already ends in " (sample)" for sample rates, and the
                # flag would add it a second time — show neither. The section note
                # already says sample rates are placeholders.
                desc = r["description"]
                if desc.lower().endswith(" (sample)"):
                    desc = desc[: -len(" (sample)")].rstrip()
                label = f"{desc}  (per {r['unit']})"
                ttk.Label(grid, text=label).grid(row=row, column=0, sticky="w", padx=(0, 6), pady=1)
                var = self.tk.StringVar(value=f"{r['cost_cents'] / 100:.2f}")
                ttk.Entry(grid, textvariable=var, width=10).grid(row=row, column=1, sticky="w", pady=1)
                self.labor_vars[r["price_key"]] = var
                row += 1
        if not rates:
            self._note(box, "No labor rates yet.", GREY, 8)
        b = ttk.Frame(box)
        b.pack(fill="x", pady=(6, 0))

        def save():
            prices = {k: v.get().strip() for k, v in self.labor_vars.items() if v.get().strip()}
            if self._say(msg, model.save_labor_rates(prices)):
                self.refresh_setup()
        ttk.Button(b, text="💾 Save labor rates", command=save).pack(side="left")
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
        svc = ttk.Frame(box)
        svc.pack(fill="x", pady=(10, 0))
        ttk.Label(svc, text="Services (always available for estimation \u2014 quick quotes, no plans needed)",
                  font=("Arial", 9, "bold")).pack(anchor="w")
        sgrid = ttk.Frame(svc)
        sgrid.pack(fill="x", pady=(4, 0))
        for i, m in enumerate(model.services()):
            ttk.Label(sgrid, text=f"\u2705  {m['name']}  ({m['how']})", font=("Arial", 9)
                      ).grid(row=i // 4, column=i % 4, sticky="w", padx=(0, 16), pady=1)
        msg = self._note(box, "")

    # ------------------------------------------------------------ 🤖 agents

    def _agents_section(self):
        """🤖 AI agents (2026-11-13, David): set up like the Service Desk, Jobs and HR agents - each step's mode, the
        group it's in and so the model it uses (the two Claude models at the top of the Small Business tab), one AI
        and a backup for all of them, the flow picture coloured by each step's mode (hover for details), the budget.
        Saves as you change it. The Estimator's web page shows these settings but no longer changes them."""
        tk, ttk = self.tk, self.ttk
        from estimator.agents import providers
        from estimator.ui import agents_flow as af
        try:
            import desk_gui_agent as dga                   # the other agents' drawing and form helpers
        except Exception:  # noqa: BLE001 - outside AI-Prowler: the form works, without the picture
            dga = None
        small = ("Arial", 8)
        box = self._box("🤖 AI agents and budget  (hover for details)", "agents")
        ov = model.agents()
        keys = ov["api_keys_saved"]
        krow = ttk.Frame(box)
        krow.pack(fill="x")
        ttk.Label(krow, text=("Agent API keys:  Claude " + ("✅ saved" if keys.get("claude_api") else "— not saved")
                              + "   ·   Grok " + ("✅ saved" if keys.get("grok_api") else "— not saved"))
                  ).pack(side="left")
        ttk.Button(krow, text="🔑 Open Agent API Key", command=lambda: self._go_to_tab("🏢 Small Business")
                   ).pack(side="left", padx=10)
        main = providers.model_for("claude_api")
        light = providers.model_for_step("claude_api", "reviewer")
        self._note(box, "Which model each step uses follows the top of the 🏢 Small Business tab, like the Jobs and "
                        "Service Desk agents:  complex steps and customer messages → " + af._nice(main)
                        + "   ·   internal steps → " + af._nice(light) + ".  Reading plans and calibrating are "
                        "complex steps (a misread dimension is a wrong price).", GREY, 8)

        roles_by = {r["role"]: r for r in ov["roles"]}
        first_api = next((r for r in ov["roles"] if r["provider"] in providers.API_PROVIDERS), None)
        runners = {"claude_api": "Claude (API key)", "grok_api": "Grok (API key)"}
        back_runner = {v: k for k, v in runners.items()}
        v = {"runner": tk.StringVar(value=runners[(first_api or {}).get("provider") or "claude_api"]),
             "backup": tk.StringVar(value=runners.get((first_api or {}).get("fallback_provider") or "", "None"))}
        mode_label = dict(af.MODES)
        back_mode = {lab: m for m, lab in af.MODES}
        start_runner = (first_api or {}).get("provider") or "claude_api"

        def model_labels(runner):
            return [af.GROUP_DEFAULT] + [lab for _m, lab in af.model_choices(runner)]

        def label_of_model(runner, m):
            return dict(af.model_choices(runner)).get(m, af.GROUP_DEFAULT) if providers.fits(runner, m) \
                else af.GROUP_DEFAULT

        for role, _short, _state in af.STEPS:
            r = roles_by.get(role)
            if r:
                v["mode_" + role] = tk.StringVar(value=mode_label[af.mode_of(r["provider"])])
                v["model_" + role] = tk.StringVar(value=label_of_model(start_runner, r.get("model_pinned")))

        cols = ttk.Frame(box)
        cols.pack(fill="x", pady=(6, 0))
        left = ttk.Frame(cols)
        left.grid(row=0, column=0, sticky="nw")
        right = ttk.Frame(cols)
        right.grid(row=0, column=1, sticky="nw", padx=(16, 0))
        row = ttk.Frame(left)
        row.pack(fill="x")
        ttk.Label(row, text="Which AI runs them", font=small).pack(side="left")
        combo = ttk.Combobox(row, textvariable=v["runner"], state="readonly", width=16, values=list(runners.values()))
        combo.pack(side="left", padx=(6, 10))
        ttk.Label(row, text="Backup", font=small).pack(side="left")
        ttk.Combobox(row, textvariable=v["backup"], state="readonly", width=16,
                     values=["None"] + list(runners.values())).pack(side="left", padx=(6, 0))
        stages = ttk.LabelFrame(left, text="What the agents do", padding=(6, 4))
        stages.pack(fill="x", pady=(6, 0))
        group_lbls, model_boxes = {}, {}
        for c, h in enumerate(("Agent", "Does", "Model", "")):
            ttk.Label(stages, text=h, font=("Arial", 8, "bold")).grid(row=0, column=c, sticky="w", padx=(0 if c == 0 else 8, 0))
        for i, (role, short, _state) in enumerate(af.STEPS, start=1):
            r = roles_by.get(role)
            if not r:
                continue
            lbl = ttk.Label(stages, text=short + ("" if r["works_now"] else "  (needs plans)"), font=small)
            lbl.grid(row=i, column=0, sticky="w")
            cb = ttk.Combobox(stages, textvariable=v["mode_" + role], state="readonly", width=24,
                              values=[lab for _, lab in af.MODES])
            cb.grid(row=i, column=1, sticky="w", padx=(8, 0), pady=1)
            mb = ttk.Combobox(stages, textvariable=v["model_" + role], state="readonly", width=18,
                              values=model_labels(start_runner))
            mb.grid(row=i, column=2, sticky="w", padx=(8, 0), pady=1)
            model_boxes[role] = mb
            g = ttk.Label(stages, text="", font=small, foreground=GREY)
            g.grid(row=i, column=3, sticky="w", padx=(8, 0))
            group_lbls[role] = g
            if dga:
                dga.calm(cb)
                dga.calm(mb)
                dga._tooltip(lbl, af.STEP_HELP[role])
                dga._tooltip(cb, "\n\n".join(af.MODE_HELP.values()))
                dga._tooltip(mb, "\"" + af.GROUP_DEFAULT + "\" follows the top of the 🏢 Small Business tab: complex "
                                 "steps and customer messages get the stronger model, internal steps the cheaper one. "
                                 "Pick a model to set it for this agent only - e.g. Claude Opus 5.5 for AI takeoff, "
                                 "which reads plans and calibrates.")

        brow = ttk.Frame(left)
        brow.pack(fill="x", pady=(8, 0))
        b, s = ov["budget"], ov["spent"]
        ttk.Label(brow, text="Budget:  $ a day", font=small).pack(side="left")
        v["day"] = tk.StringVar(value=f"{b['daily_cents'] / 100:.2f}")
        ttk.Entry(brow, textvariable=v["day"], width=7).pack(side="left", padx=4)
        ttk.Label(brow, text="  $ a month", font=small).pack(side="left")
        v["month"] = tk.StringVar(value=f"{b['monthly_cents'] / 100:.2f}")
        ttk.Entry(brow, textvariable=v["month"], width=7).pack(side="left", padx=4)
        ttk.Label(left, text=(f"Spent today ${s['today']['micros'] / 1_000_000:.2f}  ·  this month "
                              f"${s['this_month']['micros'] / 1_000_000:.2f} ({s['this_month']['calls']} calls)"),
                  foreground=GREY, font=small).pack(anchor="w", pady=(2, 0))
        self._note(left, "Agents only make proposals and drafts: they never approve, change prices or send "
                         "anything. Nothing runs or costs money while a step is Off.", GREY, 8)

        def form():
            runner = back_runner.get(v["runner"].get(), "claude_api")
            backup = back_runner.get(v["backup"].get(), "")
            modes = {role: back_mode.get(v["mode_" + role].get(), "off")
                     for role, _s, _st in af.STEPS if "mode_" + role in v}
            by_label = {lab: m for m, lab in af.model_choices(runner)}
            pins = {role: by_label.get(v["model_" + role].get(), "") for role in modes}
            return runner, ("" if backup == runner else backup), modes, pins

        saved = {"form": None}
        msg_var = tk.StringVar(master=box, value="")

        def snapshot():
            runner, backup, modes, pins = form()
            return (runner, backup, tuple(sorted(modes.items())), tuple(sorted(pins.items())),
                    v["day"].get(), v["month"].get())

        def do_save(quiet=False):
            runner, backup, modes, pins = form()
            now = snapshot()
            if quiet and now == saved["form"]:
                return
            problems = []
            for role, m in modes.items():
                r = roles_by[role]
                provider = runner if m == "on" else m
                fb = backup if m == "on" else ""
                pin = pins.get(role, "")                  # "" = its group's model (the top of the Small Business tab)
                if (r["provider"], r.get("fallback_provider") or "", r.get("model_pinned") or "") == (provider, fb, pin):
                    continue
                ok, text = model.save_role(role, provider, pin, fb)
                if ok:
                    roles_by[role] = {**r, "provider": provider, "fallback_provider": fb, "model_pinned": pin or None}
                else:
                    problems.append(f"{r['label']}: {text}")
            if now[4:] != saved["form"][4:]:
                ok, text = model.save_budget(v["day"].get(), v["month"].get())
                if not ok:
                    problems.append(text)
            saved["form"] = now
            msg_var.set(("⚠  Not saved: " + "; ".join(problems)) if problems else ("" if quiet else "✅ Saved."))

        ttk.Button(left, text="💾 Save agent settings", command=do_save).pack(anchor="w", pady=(6, 0))
        ttk.Label(left, textvariable=msg_var, foreground="#b45309", wraplength=520, justify="left").pack(anchor="w")

        ttk.Label(right, text="How a job moves — the boxes above and below are the agents' steps (hover for details)",
                  font=small, foreground="gray").pack(anchor="w")
        scale = dga.flow_scale(right) if dga else 1.0
        pad = getattr(dga, "PAD", 6)
        canvas = tk.Canvas(right, width=round((af.FLOW_W + 2 * pad) * scale),
                           height=round((af.FLOW_H + 2 * pad) * scale), background="white",
                           highlightthickness=1, highlightbackground="#e5e7eb")
        canvas.pack(anchor="w")
        summary = tk.StringVar(master=box)
        ttk.Label(right, textvariable=summary, wraplength=round((af.FLOW_W + 2 * pad) * scale), justify="left",
                  font=("Arial", 9)).pack(anchor="w", pady=(4, 0))
        tips: dict = {}
        if dga:
            dga._hover_canvas(canvas, tips)
        shown_runner = {"r": start_runner}

        def redraw(*_):
            runner = back_runner.get(v["runner"].get(), "claude_api")
            if runner != shown_runner["r"]:                # another runner: offer its models, keep a pick that fits
                shown_runner["r"] = runner
                for role, mb in model_boxes.items():
                    mb.config(values=model_labels(runner))
                    if v["model_" + role].get() not in model_labels(runner):
                        v["model_" + role].set(af.GROUP_DEFAULT)
            runner, _backup, modes, pins = form()
            for role, g in group_lbls.items():
                g.config(text=af.model_line(role, runner if modes.get(role) == "on" else "off", pins.get(role)))
            pic = af.flow(modes, {r: roles_by[r]["works_now"] for r in modes}, runner, pins)
            if dga:
                dga.draw_flow(canvas, pic, tips, scale)
            summary.set(pic["summary"])

        for var in v.values():
            var.trace_add("write", redraw)
        redraw()
        saved["form"] = snapshot()
        if dga:
            dga.autosave(box, v, lambda: do_save(quiet=True))
        self._agent_vars = v                                # tests drive the form through these
        self._agent_save = do_save

    # ------------------------------------------------------------ 🧑‍💼 director

    def _director_section(self):
        ttk = self.ttk
        box = self._box("🧑‍💼 Director", "director")
        self._note(box, "The Estimating Director runs every job: it asks the questions, prices, waits for the "
                        "checks you set here, and keeps an eye on jobs while AI-Prowler is running. It is not an AI "
                        "agent: it uses no API key and no model - it follows rules and the pricing engine, and your "
                        "chat AI (Claude, Grok or Muse) drives it. The AI agents it can call on are set in 🤖 AI agents "
                        "above.", GREY, 8)
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

    # ------------------------------------------------------------ 📦 modules

    def _modules_section(self):
        ttk = self.ttk
        box = self._box("📦 Modules", "modules")
        self._note(box, "Each trade and service is a module with its own questions, formulas and sample prices.", GREY, 8)
        grid = ttk.Frame(box)
        grid.pack(fill="x", pady=(6, 0))
        for c, h in enumerate(("Module", "Kind", "Priced by", "Version")):
            ttk.Label(grid, text=h, font=("Arial", 8, "bold")).grid(row=0, column=c, sticky="w", padx=(0, 18))
        for i, m in enumerate(model.modules(), start=1):
            for c, v in enumerate((m["name"], m["category"], m["how"], m["version"])):
                ttk.Label(grid, text=v, font=("Arial", 8)).grid(row=i, column=c, sticky="w", padx=(0, 18))

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
        move = ttk.Frame(box)
        move.pack(fill="x", pady=(8, 0))
        ttk.Button(move, text="📤 Pack up my data to move", command=lambda: self._say(msg, model.data_export())
                   ).pack(side="left")
        ttk.Button(move, text="📥 Load a data file…", command=lambda: self._data_import(msg)).pack(side="left", padx=6)
        ttk.Label(move, text="Moves everything to AI-Prowler Server or another PC in one .zip.", foreground=GREY,
                  font=("Arial", 8)).pack(side="left", padx=6)
        msg = self._note(box, "")

    def _data_import(self, msg):
        from tkinter import filedialog, messagebox
        path = filedialog.askopenfilename(parent=self.root, title="Estimator data file",
                                          filetypes=[("Estimator data", "*.zip")])
        if not path:
            return
        ok, preview = model.data_import_preview(path)
        if not ok:
            self._say(msg, (ok, preview))
            return
        if messagebox.askyesno("Load this data?", preview + "\n\nLoad it now?", parent=self.root):
            self._say(msg, model.data_import(path))
            self.refresh_setup()

    # ------------------------------------------------------------ 📱 phone

    def _phone_section(self):
        """📱 Phone and web app (2026-11-13, David): on this PC first (the Estimator in your desktop browser - best for
        CAD plan viewing), then the Estimator's link for phones and the Jobs app's link (its Estimates screen opens the
        Estimator too), each with 📋 Copy, 📧 Email to user and 📱 QR like the Jobs App row in the Small Business tab."""
        ttk = self.ttk
        box = self._box("📱 Phone and web app", "phone")
        access = model.web_app_access()
        pc = ttk.LabelFrame(box, text="🖥 On this PC — the full Estimator in your desktop browser", padding=(8, 4))
        pc.pack(fill="x", pady=(0, 6))
        prow = ttk.Frame(pc)
        prow.pack(fill="x")
        ttk.Button(prow, text="🌐 Open Estimator in browser",
                   command=lambda: _open_folder(model.web_app_access()["url"])).pack(side="left", padx=(0, 8))
        ttk.Label(prow, text=access["url"], font=("Courier New", 9)).pack(side="left")
        self._note(pc, "Best for working at your desk: the big screen, mouse and keyboard make it the place for CAD "
                       "and PDF plan viewing, zooming into sheets, calibrating, measuring takeoffs in Blueprint Review "
                       "and building estimates. It runs on this PC (localhost), so it is fast and needs no Remote "
                       "Access.", GREY, 8)
        self.phone_url = self._link_row(
            box, "📱 Estimator — Mobile URL for phones", model.phone_link, "← send to phones",
            "AI-Prowler Estimator", "Open this link on your phone to use the Estimator (plans, takeoffs and estimates):",
            "Estimator — scan with your phone", "Opens the AI-Prowler Estimator (plans, takeoffs, estimates and bids).")
        self.jobs_url = self._link_row(
            box, "🧰 Jobs App — Mobile URL for Job Updates (its Estimates screen opens the Estimator too)",
            model.jobs_link, "← send to crew phones", "AI-Prowler Jobs App",
            "Open this link on your phone to access the Jobs App:",
            "Jobs app — scan with your phone", "Opens the AI-Prowler Jobs app (customers, jobs, invoices, routes).",
            note="The same link as the Jobs App row in the 🏢 Small Business tab. People who already use the Jobs app "
                 "open the Estimator from its Estimates screen - the same web app, no second link to install.")
        for line in access["lines"]:
            if not line.startswith(("On this PC", "The Estimator web app is built")):
                self._note(box, line, "#444")

    def _link_row(self, parent, title, getter, hint, subject, intro, qr_title, qr_note, note=None):
        """A link for phones with 📋 Copy, 📧 Email to user and 📱 QR - the Small Business tab's Jobs App row."""
        tk, ttk = self.tk, self.ttk
        lf = ttk.LabelFrame(parent, text=title, padding=(8, 4))
        lf.pack(fill="x", pady=(0, 6))
        url = tk.StringVar(value=getter())
        row = ttk.Frame(lf)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=url, width=44, state="readonly", font=("Courier New", 9)).pack(side="left",
                                                                                                padx=(0, 4))
        said = ttk.Label(lf, text="", font=("Arial", 8))

        def need_link() -> bool:
            url.set(getter())                               # Remote Access may have been turned on since
            if url.get():
                return True
            said.config(text="❌ No link yet — turn on Remote Access in the Settings tab first.", foreground=RED)
            return False

        def copy():
            if not need_link():
                return
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(url.get())
                self.root.update()
                said.config(text="📋 Copied: " + url.get(), foreground=GREEN)
            except Exception:  # noqa: BLE001 - clipboard unavailable (remote desktop, etc.)
                said.config(text="❌ Couldn't copy the link", foreground=RED)

        def email():
            if need_link():
                self._say(said, model.email_link(url.get(), subject, intro))

        def qr():
            if not need_link():
                return
            try:
                import setup_wizard as sw
                sw.show_qr_window(self.root, qr_title, url.get(), qr_note)
            except Exception as exc:  # noqa: BLE001
                said.config(text=f"❌ Couldn't show the QR code: {exc}", foreground=RED)

        ttk.Button(row, text="📋 Copy", command=copy).pack(side="left", padx=(0, 4))
        ttk.Button(row, text="📧 Email to user", command=email).pack(side="left", padx=(0, 4))
        ttk.Button(row, text="📱 QR", command=qr).pack(side="left", padx=(0, 8))
        ttk.Label(row, text=hint, font=("Arial", 8), foreground="gray").pack(side="left")
        said.pack(anchor="w")
        if note:
            self._note(lf, note, GREY, 8)
        return url

    # ------------------------------------------------------------ 📤 send a project to the server

    def _sync_section(self):
        """📤 Send a project to the server (2026-11-13, David): estimating is done on this PC; the server shows the plans
        and the quote to the crew (Estimator and Jobs app) and everyone can keep working on it there. Two ways: the
        office network (a mapped drive to the server's exchange folder - faster) or the internet (the server's Remote
        Access address, signed in with your server user name; the password is never saved)."""
        import threading
        tk, ttk = self.tk, self.ttk
        box = self._box("📤 Send a project to the server", "sync")
        self._note(box, "Do the estimating here, then send the project — plans, takeoff, estimate and quote — to the "
                        "company server, so the crew can see the plans and the quote in the server's Estimator and "
                        "Jobs app. Sending the same project again updates the server copy; if someone changed it on "
                        "the server since, it is kept and your send is saved next to it.", "#444")
        s = model.sync_settings()
        v = {"url": tk.StringVar(value=s["server_url"]), "user": tk.StringVar(value=s["username"]),
             "share": tk.StringVar(value=s["share_path"]), "password": tk.StringVar(),
             "project": tk.StringVar(), "replace": tk.BooleanVar(value=False)}
        where = ttk.LabelFrame(box, text="Where the server is", padding=(8, 4))
        where.pack(fill="x", pady=(6, 0))

        def field(label, var, width=46, browse=False):
            row = ttk.Frame(where)
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=label, width=24).pack(side="left")
            ttk.Entry(row, textvariable=var, width=width).pack(side="left")
            if browse:
                def pick():
                    from tkinter import filedialog
                    got = filedialog.askdirectory(title="The server's exchange folder (mapped drive)",
                                                  initialdir=var.get() or None)
                    if got:
                        var.set(got.replace("/", "\\"))
                ttk.Button(row, text="Browse…", command=pick).pack(side="left", padx=(4, 0))

        field("🏢 Office network folder", v["share"], browse=True)
        self._note(where, "In the office: the server's Estimator exchange folder (on the server: C:\\Users\\<server "
                          "user>\\AI-Prowler\\Estimator\\exchange), shared and mapped on this PC, e.g. Y:\\. Fastest — "
                          "big plan sets don't go through the internet.", GREY, 8)
        field("🌐 Server address", v["url"])
        field("👤 Your server user name", v["user"], width=24)
        self._note(where, "From home: the server's Remote Access address (the https://… one the Jobs app uses) and the "
                          "user name you sign in to the server's Estimator with. Up to 95 MB per send.", GREY, 8)
        saved = ttk.Label(where, text="", font=("Arial", 8))

        def save():
            self._say(saved, model.save_sync_settings(v["url"].get(), v["user"].get(), v["share"].get()))
            v["url"].set(model.sync_settings()["server_url"])
        ttk.Button(where, text="💾 Save", command=save).pack(anchor="w", pady=(4, 0))
        saved.pack(anchor="w")

        send = ttk.LabelFrame(box, text="Send", padding=(8, 4))
        send.pack(fill="x", pady=(6, 0))
        prow = ttk.Frame(send)
        prow.pack(fill="x")
        ttk.Label(prow, text="Project", width=24).pack(side="left")
        projects: dict[str, int] = {}
        pick = ttk.Combobox(prow, textvariable=v["project"], state="readonly", width=52)
        pick.pack(side="left")

        def refresh():
            projects.clear()
            for p in model.sync_projects():
                projects[p["label"]] = p["id"]
            pick.config(values=list(projects))
            if v["project"].get() not in projects:
                v["project"].set(next(iter(projects), ""))
        ttk.Button(prow, text="🔄", width=3, command=refresh).pack(side="left", padx=(4, 0))
        pw = ttk.Frame(send)
        pw.pack(fill="x", pady=(2, 0))
        ttk.Label(pw, text="Server password (internet only)", width=24).pack(side="left")
        ttk.Entry(pw, textvariable=v["password"], show="•", width=24).pack(side="left")
        ttk.Label(pw, text="  asked once per AI-Prowler run, never saved", font=("Arial", 8),
                  foreground="gray").pack(side="left")
        ttk.Checkbutton(send, text="Replace the server copy even if someone changed it on the server",
                        variable=v["replace"]).pack(anchor="w", pady=(4, 0))
        brow = ttk.Frame(send)
        brow.pack(fill="x", pady=(4, 0))
        status = ttk.Label(send, text="", wraplength=WRAP, justify="left", font=("Arial", 9))
        buttons = []

        def go(via):
            label = v["project"].get()
            if label not in projects:
                status.config(text="❌ Pick a project first.", foreground=RED)
                return
            ok_s = model.save_sync_settings(v["url"].get(), v["user"].get(), v["share"].get())
            if not ok_s[0]:
                self._say(status, ok_s)
                return
            for b in buttons:
                b.config(state="disabled")
            status.config(text="⏳ Sending " + label + " …", foreground="#444")
            result = {}
            eid, password, replace = projects[label], v["password"].get(), bool(v["replace"].get())

            def work():                                 # no Tk calls in here: Tk belongs to the GUI thread
                try:
                    result["r"] = model.send_project(eid, via, password=password, replace=replace)
                except Exception as exc:  # noqa: BLE001
                    result["r"] = (False, str(exc))

            def wait():
                if "r" not in result:
                    self.root.after(300, wait)
                    return
                for b in buttons:
                    b.config(state="normal")
                if result["r"][0]:
                    v["password"].set("")
                self._say(status, result["r"])
            threading.Thread(target=work, daemon=True).start()
            self.root.after(300, wait)

        buttons.append(ttk.Button(brow, text="🏢 Send through the office network (faster)",
                                  command=lambda: go("network")))
        buttons.append(ttk.Button(brow, text="🌐 Send over the internet", command=lambda: go("internet")))
        for b in buttons:
            b.pack(side="left", padx=(0, 6))
        status.pack(anchor="w", pady=(4, 0))
        refresh()
        self._sync_vars, self._sync_go, self._sync_status = v, go, status      # tests read them

    # ------------------------------------------------------------ 🔧 CAD and tools

    def _cad_section(self):
        """🔧 CAD and tools, with 🔄 Check again (2026-11-13, David): looks for the DWG converter, ezdxf and Tesseract
        OCR again - a tool installed since AI-Prowler started shows up without a restart."""
        box = self._box("🔧 CAD and tools", "cad")
        lines = self.ttk.Frame(box)
        lines.pack(fill="x")
        button = self.ttk.Button(box, text="🔄 Check again")
        button.pack(anchor="w", pady=(6, 0))
        when = self._note(box, "", GREY, 8)

        def show(tools):
            for w in lines.winfo_children():
                w.destroy()
            for tool in tools:
                mark = "✅" if tool["ok"] else "❌"
                self.ttk.Label(lines, text=mark + " " + tool["tool"] + ": " + tool["detail"], wraplength=WRAP,
                               justify="left", foreground=GREEN if tool["ok"] else RED,
                               font=("Arial", 9)).pack(anchor="w")
                link = tool.get("download_url")
                if link:
                    btn = self.ttk.Button(lines, text="📋 Copy download link")
                    btn.config(command=lambda b=btn, u=link: self._copy_link(b, u))
                    btn.pack(anchor="w", pady=(4, 0))

        def again():
            show(model.recheck_tools())
            import time
            when.config(text="Checked again at " + time.strftime("%H:%M:%S") + ".")

        show(model.tool_status())
        button.config(command=again)
        self.cad_lines, self.cad_recheck = lines, again    # tests read them

    def _copy_link(self, button, url):
        """Copy a download link to the clipboard; the button itself says so."""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            button.config(text="✅ Copied — paste it in your browser")
        except Exception:  # noqa: BLE001 - clipboard unavailable (remote desktop, etc.)
            button.config(text="❌ Couldn't copy the link")

    # ------------------------------------------------------------ ❓ help

    def _help_section(self):
        ttk = self.ttk
        box = self._box("❓ Help", "help")
        self._note(box, "Try asking your AI:", "#444")
        for p in model.example_prompts():
            self._note(box, f"   •  \"{p}\"", "#333")
        self._note(box, "Ask \"how do I use the Estimator?\" and your AI will read the Estimator's own instructions "
                        "(how_to_estimate).", GREY, 8)
        ttk.Button(box, text="📖 Open the User Guide (Estimator is chapter 29)",
                   command=self._open_user_guide).pack(anchor="w", pady=(6, 0))


def _open_folder(path) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # noqa: S606
        else:
            subprocess.Popen(["xdg-open", str(path)])  # noqa: S603, S607
    except Exception:  # noqa: BLE001
        pass
