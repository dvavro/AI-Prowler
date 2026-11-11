"""Service Desk Agent settings on the AI-Prowler Business tab (2026-10-29, David).

"Set the agent configuration settings in AI-Prowler Service Desk section ... the
agent identity name and photo." The agent is a named VIRTUAL ASSISTANT
(desk_agent_settings.py): the label ("Virtual assistant", …) always shows with
the name. Replies go out as soon as they're approved (no wait, 2026-10-30).

Same settings as the Service Desk app → ⚙︎ Settings → 🤖 Agent; both read the
choices from desk_agent_settings and save through desk_db.set_setting, so the
two screens can't drift. Kept out of rag_gui.py so load()/save() can be tested
without building the GUI (tests/gui/test_desk_gui_agent.py).
"""
from __future__ import annotations

import desk_agent_settings as das

INT_KEYS = ("agent_monthly_budget_usd", "agent_wait_hours", "agent_bk_confirm_per_day", "agent_bk_check_hour",
            "agent_ask_per_hour")
STR_KEYS = ("agent_name", "agent_reply_signoff", "agent_ask_context_file")
CHOICE_KEYS = (("agent_provider", "agent_label", "agent_ask_who") + tuple(f"agent_stage_{k}" for k, _ in das.STAGES)
               + tuple(f"agent_bk_stage_{k}" for k, _ in das.BK_STAGES))
BOOL_KEYS = ("agent_enabled", "agent_shadow", "agent_include_service_link", "agent_ask_services", "agent_ask_products",
             "agent_bk_enabled", "agent_bk_shadow", "agent_bk_can_confirm", "agent_bk_weather")


def db_and_edition() -> tuple[str, str]:
    import desk_db
    import desk_gui_links
    import desk_rules
    db = desk_db.default_db_path()
    desk_db.init_db(db)
    return db, desk_rules.edition_for_mode(desk_gui_links.mode_of())


def load(db_path: str) -> dict:
    import desk_db
    s = desk_db.get_settings(db_path)
    return {k: s[k] for k in das.DEFAULTS}


def save(db_path: str, form: dict, *, edition: str) -> tuple[bool, str]:
    """form: the values as the screen holds them (numbers may be strings).
    Saves everything or, if any box is refused, nothing; returns (all_ok, message). The owner is the actor
    (AI-Prowler on this PC is the owner's)."""
    import desk_db
    vals, problems = {}, []
    for k in BOOL_KEYS:
        if k in form:
            vals[k] = bool(form[k])
    for k in STR_KEYS + CHOICE_KEYS:
        if k in form:
            vals[k] = str(form[k] or "").strip()
    for k in INT_KEYS:
        if k in form:
            try:
                vals[k] = int(str(form[k]).strip())
            except ValueError:
                problems.append(f"{k.replace('agent_', '').replace('_', ' ')}: enter a whole number")
    if "agent_hours" in form:
        try:
            vals["agent_hours"] = [int(str(h).strip()) for h in form["agent_hours"]]
        except (TypeError, ValueError):
            problems.append("hours: enter whole numbers")
    for k, v in vals.items():           # every bad box is named, as before …
        try:
            desk_db.check_setting(k, v, edition)
        except desk_db.DeskError as e:
            problems.append(str(e))
    if not problems:                    # … but now one bad box saves none of them (F-6, 2026-11-03)
        try:
            desk_db.set_settings(db_path, vals, actor=None, edition=edition)
        except desk_db.DeskError as e:
            problems.append(str(e))
    return (not problems, "Saved." if not problems else "Not saved: " + "; ".join(problems))


def changed_only(form: dict, baseline: dict) -> dict:
    """Only the fields that differ from what the form showed when it was loaded / last saved
    (2026-10-31): a Save never writes back values the person didn't touch."""
    return {k: val for k, val in form.items() if k not in baseline or baseline[k] != val}


LIVE_SYNC_MS = 5000                                 # how often an open settings section re-reads what's saved


AUTOSAVE_MS = 600        # after the last change on the desktop panel


def autosave(widget, v: dict, save_quiet) -> None:
    """David 2026-11-05: the panels showed a change at once but only wrote it on Save, so a change on the desktop never
    reached the apps, which save as soon as you change something. A change here now saves itself the same way, shortly
    after the last keystroke or pick. Nothing was changed means nothing is written, so a change arriving from an app
    (live_sync) isn't saved back."""
    import tkinter as tk
    job = {"id": None}

    def fire():
        job["id"] = None
        try:
            if widget.winfo_exists():
                save_quiet()
        except tk.TclError:
            pass

    def changed(*_):
        try:
            if job["id"]:
                widget.after_cancel(job["id"])
            job["id"] = widget.after(AUTOSAVE_MS, fire)
        except tk.TclError:
            pass
    for x in v.values():
        x.trace_add("write", changed)


def mark_saved(shown: dict, v: dict, stored) -> None:
    """After a save, only the boxes edited here count as up to date. Marking every box hid a change the app had saved in
    the meantime: this panel kept showing the old value for good (test_changes_from_both_places_are_both_kept)."""
    for k, val in stored().items():
        if k in v and v[k].get() != shown.get(k):
            shown[k] = val


def live_sync(widget, v: dict, stored, on_change=None) -> dict:
    """2026-11-03 (David: changing auto / suggest / off in the app didn't reach AI-Prowler on a personal install).
    The app saves through the server process; this tab is built once, so it kept showing the old choice until
    AI-Prowler restarted. While the section exists it now re-reads what's saved every LIVE_SYNC_MS (a few small
    SQLite reads, no AI call). A box follows a change made elsewhere unless the person has an unsaved edit in that
    box; their edit stays, and autosave writes it. `stored()` returns {var key: value as the var holds it};
    `on_change(shown)` gets the new saved values so the section's Save baseline stays right. Returns the dict of
    what the boxes were last known to match: a successful save must call mark_saved at once, or a box
    changed again before the next tick looks unedited and is put back to the value just saved."""
    import tkinter as tk
    shown = stored()

    def tick():
        try:
            if not widget.winfo_exists():
                return
        except tk.TclError:
            return
        try:
            now, changed = stored(), False
            for k, val in now.items():
                if val == shown.get(k):
                    continue
                if v[k].get() == shown.get(k):
                    v[k].set(val)
                shown[k], changed = val, True
            if changed and on_change:
                on_change(shown)
        except Exception:  # noqa: BLE001 — a missed refresh just waits for the next one
            pass
        try:
            widget.after(LIVE_SYNC_MS, tick)
        except tk.TclError:
            pass
    widget.after(LIVE_SYNC_MS, tick)
    return shown


KEY_PROVIDERS = (                                   # (provider, label, what the key looks like)
    ("anthropic", "Claude API key", "sk-ant-api03-…  (console.anthropic.com → API Keys)"),
    ("grok", "Grok API key", "xai-…  (console.x.ai → API Keys)"),
)
KEYS_WHERE = "Small Business tab → Service Desk Agent → 🔑 AI keys for the agents"


def key_status(provider: str) -> str:
    """'Saved' / 'Not saved' — never the key itself."""
    import desk_agent_providers as prov
    return "✅ Saved" if prov.has_agent_key(provider) else "Not saved"


def save_agent_key(provider: str, key: str) -> tuple[bool, str]:
    """Save a Claude / Grok API key for the agents (2026-11-01, David). The agents use ONLY these keys —
    their own files (desk_agent_providers.agent_key_path), not the Task Queue's keys."""
    import desk_agent_providers as prov
    key = (key or "").strip()
    if not key or set(key) == {"•"}:
        return False, "Paste the key first."
    if provider == "anthropic" and key.startswith("sk-ant-oat"):
        return False, ("That's a Claude subscription (CLI) token, not an API key. The agents need an API key "
                       "(starts with sk-ant-api) from console.anthropic.com → API Keys.")
    if provider == "anthropic" and key.startswith("xai-"):
        return False, "That looks like a Grok (xAI) key — paste it in the Grok row."
    if provider == "grok" and key.startswith("sk-ant-"):
        return False, "That looks like a Claude key — paste it in the Claude row."
    prov.store_agent_key(key, provider)
    return True, ("Claude" if provider == "anthropic" else "Grok") + " API key saved for the agents."


def clear_agent_key(provider: str) -> tuple[bool, str]:
    import desk_agent_providers as prov
    if not prov.has_agent_key(provider):
        return True, "No key was saved."
    prov.delete_agent_key(provider)
    return True, ("Claude" if provider == "anthropic" else "Grok") + " API key removed from this PC."


AGENT_KEY_TITLE = "🔑 Agent API Key"
AGENT_KEY_NOTE = ("The agents (Service Desk, Jobs App and HR) need a saved API key, and run on their own with it; "
                  "without one they don't run. Save the key for the AI chosen in Service Desk "
                  "Agent & settings → 🤖 Agent → \"Which AI runs it\". Billed by the AI company per use (the "
                  "agents' monthly budget caps it). Kept on this PC only; never shown again after saving.")


AGENT_KEY_NOTE_PERSONAL = ("Needed when an agent (Service Desk, Jobs App) runs on its own on the Claude API or the "
                           "Grok bot — chosen in Service Desk Agent & settings → 🤖 Agent → \"Which AI runs it\" — and "
                           "for the 🤖 Autonomous AI Task Queue, which runs on these same keys. Not needed "
                           "for chat runs. Billed by the AI company per use. Kept on this PC only; never shown again "
                           "after saving.")
BUDGET_HELP = ("AI-Prowler's own monthly cap for every agent together (Service Desk, Jobs App, HR) and the Autonomous AI "
               "Task Queue. When this month's estimated API spend reaches it, they stop running on their own until next "
               "month; 0 = they don't run on their own. It's worked out from the tokens each run used, so it's an "
               "estimate — for a hard stop also set a spend limit with the AI company (Claude Console → Billing → Spend "
               "limits; xAI console → Billing). Runs from a chat don't count.")


def load_agent_budget() -> tuple:
    """(monthly budget in dollars, spent this month or None) — the one budget every agent shares,
    kept in the Service Desk settings database (the Jobs / HR agents copy it from there)."""
    import desk_db
    db = desk_db.default_db_path()
    desk_db.init_db(db)
    s = desk_db.get_settings(db)
    spent = None
    try:
        import desk_agent
        spent = desk_agent.spend(db, s)["spent_usd"]
    except Exception:  # noqa: BLE001
        pass
    return int(float(s.get("agent_monthly_budget_usd") or 0)), spent


def save_agent_budget(value, edition: str, warn_pct=None) -> tuple:
    """Save the monthly dollar limit every agent shares (same setting as Service Desk Agent → 🤖 Agent →
    Timing → Monthly AI budget) and, when given, the warn-at % for the owner's budget alert; then copy them
    to the Jobs / HR agents at once."""
    try:
        amount = int(str(value).strip().lstrip("$").replace(",", ""))
    except ValueError:
        return False, "Enter a whole number of dollars (0 to 10000)."
    pct = None
    if warn_pct is not None:
        try:
            pct = int(str(warn_pct).strip().rstrip("%"))
        except ValueError:
            return False, "Enter the warning as a whole percent (0 to 100; 0 = no budget alerts)."
    import desk_agent_hr_store
    import desk_agent_store
    import desk_db
    try:
        tdb = desk_db.default_db_path()
        desk_db.init_db(tdb)
        vals = {"agent_monthly_budget_usd": amount}
        if pct is not None:
            vals["agent_budget_alert_pct"] = pct
        desk_db.set_settings(tdb, vals, edition=edition)          # both or neither (F-7, 2026-11-03)
        desk_agent_store.sync_shared(tdb)
        try:
            from pathlib import Path
            if Path(desk_agent_hr_store.path()).exists():
                desk_agent_hr_store.sync_shared(tdb)
        except Exception:  # noqa: BLE001
            pass
    except (ValueError, desk_db.DeskError) as e:
        return False, str(e)
    warn = ("" if pct is None else
            (" No budget alerts." if pct == 0 else f" You'll be alerted at {min(pct, 100)}% and at 100%."))
    if amount == 0:
        return True, "Saved — $0 means the agents don't run on their own." + warn
    return True, f"Saved — every agent stops running on its own once this month's AI spend reaches ${amount}." + warn


FORECAST_REFRESH_MS = 60_000          # the "Spent this month" line re-reads the run records this often


def _spent_text(spent, budget) -> str:
    return "" if spent is None else f"Spent this month: ${spent:.2f} of ${budget}"


def forecast_line(edition: str | None) -> str:
    """'Spent this month: $4.20 of $20 (21%) · about $0.32/day … · runs out about Nov 23 · …' (desk_agent_budget)."""
    try:
        import desk_agent_budget as agent_budget
        return agent_budget.current(edition)["text"]
    except Exception:  # noqa: BLE001
        try:
            b, sp = load_agent_budget()
            return _spent_text(sp, b)
        except Exception:  # noqa: BLE001
            return ""


def alert_recipients_text(edition: str | None) -> str:
    if edition == "business":
        return "Budget alerts go to every owner and manager (email, and a text when they have a mobile)."
    try:
        import desk_agent_budget as agent_budget
        emails, phones = agent_budget.owner_recipients(edition)
    except Exception:  # noqa: BLE001
        emails, phones = [], []
    if not emails and not phones:
        return ("Budget alerts: no email set up yet — set one in Service Desk → My alerts, or Settings → "
                "Email Configuration.")
    return "Budget alerts go to " + ", ".join(emails + phones) + "."


def build_agent_key_section(parent, edition: str | None = None):
    """🔑 Agent API Key at the TOP of the Small Business tab: the agents' Claude / Grok keys and the monthly
    dollar limit every agent shares, on a server and on a personal install. The agents use only these keys, and don't
    run without one (David 2026-11-05)."""
    import tkinter as tk
    from tkinter import messagebox, ttk
    if edition is None:
        import desk_gui_links
        import desk_rules
        edition = desk_rules.edition_for_mode(desk_gui_links.mode_of())
    note = AGENT_KEY_NOTE if edition == "business" else AGENT_KEY_NOTE_PERSONAL
    out = build_api_keys_panel(parent, title=AGENT_KEY_TITLE, note=note,
                               pack=dict(fill="x", padx=16, pady=(10, 0)), wrap=900)
    import desk_agent_providers as prov
    box, small, row = out["frame"], ("Arial", 8), len(KEY_PROVIDERS) + 1

    # ── AI models (2026-11-01, David: "add controls which AI Model is used in the API" and "use expensive
    # models on complex jobs like routing and lower cost models on lower complex agent calls")
    out["models"] = {}

    def model_row(title, runner, choices, cur, save, tip):
        r = ttk.Frame(box)
        r.grid(row=model_row.n, column=0, columnspan=5, sticky="w", pady=(4 if model_row.n > len(KEY_PROVIDERS) + 1
                                                                          else 6, 0))
        model_row.n += 1
        mvar = tk.StringVar(value=_label_for(choices, cur) if any(m == cur for m, _ in choices) else cur)
        ttk.Label(r, text=title, font=small, width=30).pack(side="left")
        combo = calm(ttk.Combobox(r, textvariable=mvar, state="readonly", width=64, values=[lab for _, lab in choices]))
        combo.pack(side="left")
        _tooltip(combo, tip)

        def on_pick(_e=None):
            try:
                save(_value_for(choices, mvar.get()))
            except Exception as e:  # noqa: BLE001
                messagebox.showwarning("AI model", str(e))
                return
            try:
                fvar.set(forecast_line(edition))
            except Exception:  # noqa: BLE001
                pass
        combo.bind("<<ComboboxSelected>>", on_pick, add="+")
        out["models"][runner] = {"var": mvar, "pick": on_pick, "choices": choices}
    model_row.n = row

    claude = prov.model_choices("claude_api")
    model_row("Claude model — complex & customer", "claude_api", claude, prov.model_for("claude_api"),
              lambda m: prov.set_agent_model("claude_api", m),
              "The stronger model: complex steps (routing, scheduling, booking decisions …) and every customer "
              "message. " + prov.COMPLEX_HELP)
    light_choices = [("", "Same as complex & customer")] + claude
    model_row("Claude model — internal steps", "claude_light", light_choices, prov.light_model(),
              prov.set_light_model,
              "A cheaper model for internal steps saves money — complex steps and customer messages always keep "
              "the stronger model. " + prov.COMPLEX_HELP)
    model_row("Grok model", "grok_api", prov.model_choices("grok_api"), prov.model_for("grok_api"),
              lambda m: prov.set_agent_model("grok_api", m), "The model the agents use with the Grok key.")
    row = model_row.n

    # ── monthly budget + warn-at % + forecast
    try:
        cur, spent = load_agent_budget()
    except Exception:  # noqa: BLE001
        cur, spent = das.DEFAULTS["agent_monthly_budget_usd"], None
    try:
        import desk_db
        warn0 = int(desk_db.get_settings(desk_db.default_db_path()).get("agent_budget_alert_pct", 80) or 0)
    except Exception:  # noqa: BLE001
        warn0 = das.DEFAULTS.get("agent_budget_alert_pct", 80)
    bvar, wvar = tk.StringVar(value=str(cur)), tk.StringVar(value=str(warn0))
    spent_var = tk.StringVar(value=_spent_text(spent, cur))
    fvar = tk.StringVar(value=forecast_line(edition))
    brow = ttk.Frame(box)
    brow.grid(row=row, column=0, columnspan=5, sticky="w", pady=(6, 0))
    lbl = ttk.Label(brow, text="Monthly budget $", font=small)
    lbl.pack(side="left")
    ent = ttk.Spinbox(brow, from_=0, to=10000, increment=5, textvariable=bvar, width=8)
    ent.pack(side="left", padx=(4, 12))
    wl = ttk.Label(brow, text="Alert me at", font=small)
    wl.pack(side="left")
    went = ttk.Spinbox(brow, from_=0, to=100, increment=5, textvariable=wvar, width=5)
    went.pack(side="left", padx=(4, 2))
    ttk.Label(brow, text="% and at 100%", font=small).pack(side="left")
    for w in (ent, went):
        no_wheel_changes(w)                         # scrolling the tab never changes it
    for w in (lbl, ent):
        _tooltip(w, BUDGET_HELP)
    for w in (wl, went):
        _tooltip(w, "The owner gets an email (and a text when a mobile is set) once a month when the agents' "
                    "spend reaches this % of the budget, and again at 100% when they stop. 0 = no budget alerts.")

    def do_save_budget():
        ok, msg = save_agent_budget(bvar.get(), edition, wvar.get())
        if ok:
            try:
                c, s2 = load_agent_budget()
                bvar.set(str(c))
                spent_var.set(_spent_text(s2, c))
                fvar.set(forecast_line(edition))
            except Exception:  # noqa: BLE001
                pass
            messagebox.showinfo("Agent budget", msg)
        else:
            messagebox.showwarning("Agent budget", msg)

    ttk.Button(brow, text="Save", width=6, command=do_save_budget).pack(side="left", padx=(12, 0))
    def _open_costs():
        try:
            open_cost_analysis(box, edition, on_close=lambda: fvar.set(forecast_line(edition)))
        except Exception as e:  # noqa: BLE001 — never a silent button (2026-11-01)
            messagebox.showerror("Agent cost analysis", f"The cost analysis couldn't open:\n{e}")

    ttk.Button(brow, text="📊 Cost analysis…", command=_open_costs).pack(side="left", padx=(8, 0))
    row += 1
    ttk.Label(box, textvariable=fvar, font=("Arial", 8, "bold"), wraplength=900, justify="left").grid(
        row=row, column=0, columnspan=5, sticky="w", pady=(4, 0))
    row += 1
    ttk.Label(box, font=small, foreground="gray", wraplength=900, justify="left",
              text=("The forecast is worked out by AI-Prowler from the agents' own run records (no AI call, no "
                    "cost): this month's pace, when the budget runs out at that pace, and about how many tokens are "
                    "left on the chosen model. Shared by every agent — they stop running on their own at 100%. For a "
                    "hard stop, also set a spend limit with the AI company: Claude Console → Billing → Spend limits, "
                    "or the xAI console → Billing. " + alert_recipients_text(edition))
              ).grid(row=row, column=0, columnspan=5, sticky="w", pady=(2, 0))
    # 2026-11-03 (David: "check if the spent this much value is real time updated, because I dont see these cost
    # added to the number"): the line was worked out once when the tab was built and only again after a model
    # pick, Save or closing the popup — the agents' and AI tasks' spend recorded since never showed. It now
    # re-reads the run records every minute (a few small SQLite reads, no AI call) while the tab exists.
    def _refresh_forecast():
        try:
            if not box.winfo_exists():
                return
        except tk.TclError:
            return
        try:
            c2, s3 = load_agent_budget()
            spent_var.set(_spent_text(s3, c2))
            fvar.set(forecast_line(edition))
        except Exception:  # noqa: BLE001 — a missed refresh just waits for the next one
            pass
        try:
            box.after(FORECAST_REFRESH_MS, _refresh_forecast)
        except tk.TclError:
            pass
    box.after(FORECAST_REFRESH_MS, _refresh_forecast)
    out["budget"] = {"var": bvar, "warn": wvar, "save": do_save_budget, "spent": spent_var, "forecast": fvar,
                     "refresh": _refresh_forecast}
    return out


def _money(x) -> str:
    if x is None:
        return "—"
    return f"${x:,.2f}" if x >= 1 else (f"${x:.3f}" if x >= 0.01 else f"${x:.4f}")


def open_cost_analysis(parent, edition: str | None, on_close=None, *, analysis_fn=None, sample_fn=None,
                       measure_fn=None):
    """📊 Agent cost analysis popup (2026-11-01, David): this month by agent and model, the forecast, and what each
    model — and the smart mix — would cost at this business's volume. 🔄 Refresh reads the agents' records again
    (free); ▶ Run a new live analysis sends a few real queued items to the chosen models once (a few cents) and
    uses what they really cost. Nothing is submitted or changed."""
    import threading
    import tkinter as tk
    from tkinter import ttk

    import desk_agent_budget as ab
    import desk_agent_providers as prov
    analysis_fn = analysis_fn or (lambda measured: ab.analysis(edition, measured=measured))
    sample_fn = sample_fn or (lambda: ab.sample_items(3, edition or "solo"))
    measure_fn = measure_fn or ab.measure
    win = tk.Toplevel(parent)
    win.title("📊 Agent cost analysis")
    win.geometry("1000x700")
    state = {"measured": None, "busy": False}
    small = ("Arial", 9)
    head = tk.StringVar()
    ttk.Label(win, textvariable=head, font=("Arial", 10, "bold"), wraplength=960, justify="left").pack(
        anchor="w", padx=10, pady=(10, 4))
    info = tk.StringVar()
    ttk.Label(win, textvariable=info, font=small, foreground="gray", wraplength=960, justify="left").pack(
        anchor="w", padx=10)

    def table(title, cols, widths, height):
        ttk.Label(win, text=title, font=("Arial", 9, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
        tv = ttk.Treeview(win, columns=cols, show="headings", height=height)
        for c, w in zip(cols, widths):
            tv.heading(c, text=c)
            tv.column(c, width=w, anchor="w" if c in (cols[0],) else "e")
        tv.pack(fill="x", padx=10)
        return tv

    t_agents = table("This month, by agent", ("Agent", "Runs", "Items", "Tokens in", "Tokens out", "Cost"),
                     (260, 90, 90, 140, 140, 120), 4)
    t_est = table("What it would cost at your volume", ("Model", "Per call", "Per day", "Per month (30 days)", "Measured"),
                  (520, 110, 110, 150, 90), 7)
    t_live = table("Last live analysis (real calls, nothing submitted)",
                   ("Model / item", "Step", "Tokens in", "Tokens out", "Cost", "Answer"), (300, 80, 90, 90, 90, 330), 6)
    btns = ttk.Frame(win)
    btns.pack(fill="x", padx=10, pady=8)
    status = tk.StringVar()
    has_key = prov.has_agent_key("anthropic")

    def fill():
        try:
            a = analysis_fn(state["measured"])
        except Exception as e:  # noqa: BLE001
            head.set(f"Cost analysis unavailable: {e}")
            return
        f = a.get("forecast") or {}
        head.set(f.get("text") or "No agent runs this month yet.")
        cpd = a["calls_per_day"]
        tk_ = a.get("tasks") or {}
        info.set((f"Your volume: about {cpd:.1f} agent items a day — what the agents queued in the last "
                  f"{a.get('window_days') or 30:g} day(s), one AI call each" if cpd else
                  f"Nothing queued for the agents in the last 30 days — the estimates assume "
                  f"{a['calls_per_day_used']:.0f} items a day")
                 + (f" · AI Analysis Tasks: {tk_['runs_per_month']:g} scheduled run(s) a month at about "
                    f"${tk_['per_run']:.2f} a run" if tk_.get("runs_per_month") else "")
                 + f" · about {a['call_tokens'][0]:,} tokens in and {a['call_tokens'][1]:,} out per call"
                 + (f" · {a['complex_share']:.0%} of queued items need the stronger model (complex steps and "
                    f"customer messages)" if a["complex_share"] is not None
                    else f" · assumes {a['complex_share_used']:.0%} need the stronger model")
                 + f". Complex & customer model: {a['main_model']}; internal-steps model: {a['light_model'] or 'same'}. "
                 + "Prices per 1M tokens are AI-Prowler's built-in list (change in task_automation_config.json → "
                 + "agent_prices).")
        for tv in (t_agents, t_est):
            tv.delete(*tv.get_children())
        for g in a["agents"]:
            t_agents.insert("", "end", values=(g["name"], g["runs"], g["items"], f"{g['input']:,}", f"{g['output']:,}",
                                               _money(g["cost"])))
        for e in a["estimates"]:
            t_est.insert("", "end", values=(("★ " if e.get("smart") else "") + e["label"], _money(e["per_call"]),
                                            _money(e["per_day"]), _money(e["per_month"]), "yes" if e["measured"] else ""))

    def show_live(res):
        t_live.delete(*t_live.get_children())
        for r in res["rows"]:
            if "error" in r:
                t_live.insert("", "end", values=(f"{r['model']} — {r['item']}", "", "", "", "", "error: " + r["error"]))
            else:
                t_live.insert("", "end", values=(f"{r['model']} — {r['item']}", "stronger" if r["complex"] else "cheaper",
                                                 f"{r['input']:,}", f"{r['output']:,}", _money(r["cost"]), r["answer"]))

    def run_live():
        if state["busy"]:
            return
        state["busy"] = True
        live_btn.state(["disabled"])
        status.set("Running … sending real queued items to the chosen models (nothing is submitted or changed).")

        def work():
            try:
                system, samples = sample_fn()
                if not samples:
                    res = {"rows": [], "per_model": {}, "cost": 0.0, "none": True}
                else:
                    models = list(dict.fromkeys([prov.model_for("claude_api"),
                                                 prov.light_model() or "claude-haiku-5-5"]))
                    res = measure_fn(models, system, samples)
            except Exception as e:  # noqa: BLE001
                res = {"rows": [], "per_model": {}, "cost": 0.0, "error": str(e)}

            def done():
                state["busy"] = False
                try:
                    live_btn.state(["!disabled"])
                except tk.TclError:
                    return
                if res.get("error"):
                    status.set("Live analysis failed: " + res["error"])
                elif res.get("none"):
                    status.set("Nothing in the agents' queues to test with yet — the estimates use the records only.")
                else:
                    state["measured"] = res["per_model"]
                    status.set(f"Live analysis done — it cost {_money(res['cost'])} (not counted in the agents' budget). "
                               "The estimates now use these real numbers.")
                    show_live(res)
                fill()
            box_.append(done)               # handed back to the Tk thread by poll() — never touch Tk here

        box_ = []

        def poll():
            if box_:
                box_.pop()()
                return
            try:
                win.after(100, poll)
            except tk.TclError:
                pass
        threading.Thread(target=work, daemon=True).start()
        win.after(100, poll)

    ttk.Button(btns, text="🔄 Refresh (free)", command=fill).pack(side="left")
    live_btn = ttk.Button(btns, text="▶ Run a new live analysis (about 2–5¢)", command=run_live)
    live_btn.pack(side="left", padx=(8, 0))
    if not has_key:
        live_btn.state(["disabled"])
        status.set("Save a Claude API key above to run a live analysis.")

    def close():
        if on_close:
            try:
                on_close()
            except Exception:  # noqa: BLE001
                pass
        win.destroy()
    ttk.Button(btns, text="Close", command=close).pack(side="right")
    ttk.Label(win, textvariable=status, font=small, wraplength=960, justify="left").pack(anchor="w", padx=10)
    win.protocol("WM_DELETE_WINDOW", close)
    fill()
    return {"win": win, "fill": fill, "run_live": run_live, "state": state, "tables": (t_agents, t_est, t_live),
            "head": head, "status": status}


KEY_LIGHT_SAVED, KEY_LIGHT_NONE, KEY_NOT_SAVED, KEY_REFRESH_MS = "#2e7d32", "#9e9e9e", "Not saved", 2000


def build_api_keys_panel(parent, title: str = AGENT_KEY_TITLE, note: str = AGENT_KEY_NOTE,
                         pack: dict | None = None, wrap: int = 520) -> dict:
    """One row per AI: a hidden entry box, Save, Remove and whether a key is saved. Used for
    🔑 Agent API Key at the top of a server's Small Business tab (no Task Queue tab on a server)."""
    import tkinter as tk
    from tkinter import messagebox, ttk
    small = ("Arial", 8)
    box = ttk.LabelFrame(parent, text=title, padding=(8, 4))
    box.pack(**(pack or dict(fill="x", pady=(6, 0))))
    ttk.Label(box, font=small, foreground="gray", wraplength=wrap, justify="left",
              text=note).grid(row=0, column=0, columnspan=5, sticky="w")
    out = {"frame": box}
    for i, (prov, label, hint) in enumerate(KEY_PROVIDERS, start=1):
        var, status = tk.StringVar(), tk.StringVar(value=key_status(prov))
        cell = ttk.Frame(box)
        light = ttk.Label(cell, text="●", font=("Arial", 12))
        light.pack(side="left")
        ttk.Label(box, text=label, width=14, font=small).grid(row=i, column=0, sticky="w", pady=(3, 0))
        ent = ttk.Entry(box, textvariable=var, width=34, show="•")
        ent.grid(row=i, column=1, sticky="w", pady=(3, 0))
        _tooltip(ent, hint)

        def do_save(prov=prov, var=var, status=status):
            ok, msg = save_agent_key(prov, var.get())
            if ok:
                var.set("")
                status.set(key_status(prov))
                messagebox.showinfo("AI keys", msg)
            else:
                messagebox.showwarning("AI keys", msg)

        def do_clear(prov=prov, status=status):
            if not messagebox.askyesno("AI keys", f"Remove the saved {label} from this PC?"):
                return
            _ok, msg = clear_agent_key(prov)
            status.set(key_status(prov))
            messagebox.showinfo("AI keys", msg)

        ttk.Button(box, text="Save", width=6, command=do_save).grid(row=i, column=2, padx=(4, 0), pady=(3, 0))
        ttk.Button(box, text="Remove", width=8, command=do_clear).grid(row=i, column=3, padx=(4, 0), pady=(3, 0))
        ttk.Label(cell, textvariable=status, font=small).pack(side="left", padx=(3, 0))
        cell.grid(row=i, column=4, sticky="w", padx=(6, 0), pady=(3, 0))
        out[prov] = {"entry": ent, "var": var, "status": status, "save": do_save, "clear": do_clear, "light": light}

    # 2026-11-04 (David): a green light shows at a glance that a key is saved. Grey, not red: one AI's key is enough.
    # The row reads the saved state itself, so a key saved or removed elsewhere (the Setup popup) shows here too.
    def refresh_keys():
        try:
            if not box.winfo_exists():
                return
            for p, _label, _hint in KEY_PROVIDERS:
                now = key_status(p)
                out[p]["status"].set(now)
                out[p]["light"].configure(foreground=KEY_LIGHT_NONE if now == KEY_NOT_SAVED else KEY_LIGHT_SAVED)
            box.after(KEY_REFRESH_MS, refresh_keys)
        except tk.TclError:
            pass
    out["refresh_keys"] = refresh_keys
    refresh_keys()
    return out


def _label_for(pairs, value):
    return dict(pairs).get(value, value)


def _value_for(pairs, label):
    return {lab: v for v, lab in pairs}.get(label, label)


def _tooltip(widget, text: str, wrap: int = 360):
    """Hover help for a Tk widget (shows after a short pause, hides on leave)."""
    import tkinter as tk
    state = {"tip": None, "job": None}

    def show():
        if state["tip"] or not text:
            return
        x, y = widget.winfo_rootx() + 12, widget.winfo_rooty() + widget.winfo_height() + 4
        tip = tk.Toplevel(widget)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{x}+{y}")
        tk.Label(tip, text=text, justify="left", wraplength=wrap, background="#fffbe6",
                 relief="solid", borderwidth=1, font=("Arial", 9), padx=6, pady=4).pack()
        state["tip"] = tip

    def enter(_e):
        state["job"] = widget.after(400, show)

    def leave(_e):
        if state["job"]:
            widget.after_cancel(state["job"]); state["job"] = None
        if state["tip"]:
            state["tip"].destroy(); state["tip"] = None

    widget.bind("<Enter>", enter, add="+")
    widget.bind("<Leave>", leave, add="+")


PAD = 6                                            # room for the practice ring at the edges


def flow_scale(widget) -> float:
    """Windows display scaling (125 % / 150 % …) makes text bigger but not the drawing, so
    labels overflowed their boxes (David's screenshot 2026-10-30). Draw at the same scale."""
    try:
        return max(1.0, min(2.5, float(widget.tk.call("tk", "scaling")) / (96 / 72)))
    except Exception:  # noqa: BLE001
        return 1.0


def calm(combo):
    """A read-only drop-down keeps its text highlighted (dark) after a pick until focus
    leaves (David 2026-10-30: "Auto stays selected in a dark color"). Clear it at once."""
    def done(_e=None):
        try:
            combo.selection_clear()
            combo.winfo_toplevel().focus_set()
        except Exception:  # noqa: BLE001
            pass
    combo.bind("<<ComboboxSelected>>", done, add="+")
    combo.bind("<FocusOut>", lambda _e: combo.selection_clear(), add="+")
    no_wheel_changes(combo)
    return combo


WHEEL_EVENTS = ("<MouseWheel>", "<Shift-MouseWheel>", "<Button-4>", "<Button-5>")


def no_wheel_changes(widget) -> None:
    """Scrolling the page must never change a setting (Vicki 2026-10-31: "two other settings
    changed from auto to suggest"). Tk's drop-downs and number boxes step their value when the
    mouse wheel turns over them, so scrolling down the long Small Business tab quietly changed
    whatever passed under the pointer (Auto -> Suggest is one step), and the next Save kept it.
    Replace those class bindings with a do-nothing one: the value stays, and the wheel event
    carries on to the page's own scroll handler. App-wide, once; safe to call again."""
    try:
        if widget.tk.call("info", "exists", "::aiprowler_no_wheel"):
            return
        for cls in ("TCombobox", "TSpinbox", "Spinbox"):
            for ev in WHEEL_EVENTS:
                widget.bind_class(cls, ev, lambda _e: None)
        widget.tk.call("set", "::aiprowler_no_wheel", 1)
    except Exception:  # noqa: BLE001
        pass


def draw_flow(canvas, model: dict, tips: dict | None = None, scale: float = 1.0) -> None:
    """Draw desk_agent_settings.flow() on a Tk canvas (same picture as the app's SVG).
    Each 🤖 step is coloured by its own Off / Suggest / Auto choice; practice mode adds a
    purple dashed ring and a "practice" line; lit states take their step's colour.
    tips: canvas item id → help text for the step boxes (hover). Fonts are in pixels and
    everything is multiplied by `scale`, so nothing overflows at any display scaling."""
    s = float(scale or 1.0)
    P = lambda v: (v + PAD) * s                    # noqa: E731
    F = lambda px, *style: ("Arial", -max(1, round(px * s)), *style)   # noqa: E731
    purple = das.MODE_COLORS["practice"]
    canvas.delete("all")
    if tips is not None:
        tips.clear()
    for e in model["edges"]:
        canvas.create_line(P(e["x1"]), P(e["y1"]), P(e["x2"]), P(e["y2"]), fill=e["color"],
                           width=(2.5 if e["kind"] == "step" and not e["dash"] else 1.5) * s,
                           dash=(4, 3) if e["dash"] else None,
                           arrow="both" if e["both"] else "last", arrowshape=(8 * s, 9 * s, 3 * s))
    for st in model["states"]:
        canvas.create_rectangle(P(st["x"]), P(st["y"]), P(st["x"] + st["w"]), P(st["y"] + st["h"]),
                                fill=st["tint"], outline=st["color"], width=(2.5 if st["lit"] else 1) * s)
        canvas.create_text(P(st["x"] + st["w"] / 2), P(st["y"] + st["h"] / 2), text=st["label"],
                           font=F(12, "bold") if st["lit"] else F(12), fill="#111827")
    for p in model["steps"]:
        dim = p["mode"] in ("off", "inactive")
        items = []
        if p.get("practice"):
            items.append(canvas.create_rectangle(P(p["x"] - 4), P(p["y"] - 4), P(p["x"] + p["w"] + 4),
                                                 P(p["y"] + p["h"] + 4), outline=purple, width=1.5 * s,
                                                 dash=(5, 3)))
        items.append(canvas.create_rectangle(P(p["x"]), P(p["y"]), P(p["x"] + p["w"]), P(p["y"] + p["h"]),
                                             fill=p["tint"], outline=p["color"],
                                              width=(1 if p["mode"] == "off" else 1.5 if dim else 2.5) * s,
                                             dash=(4, 3) if dim else None))
        cx = P(p["x"] + p["w"] / 2)
        items.append(canvas.create_text(cx, P(p["y"] + 13), text=p["label"], font=F(12, "bold"), fill="#111827"))
        items.append(canvas.create_text(cx, P(p["y"] + 29), text=p["word"], font=F(11, "bold"), fill=p["color"]))
        if p.get("practice"):
            items.append(canvas.create_text(cx, P(p["y"] + 43), text="practice", font=F(10), fill=purple))
        if tips is not None:
            text = (f"{p['label']} — {p['word']}" + (" (practice mode: shows only)" if p.get("practice") else "")
                    + f"\n\n{p['help']}")
            for i in items:
                tips[i] = text


def build_agent_settings(app, parent, on_saved=None) -> dict:
    """Build the settings inside `parent` (a ttk.LabelFrame): settings on the left,
    the live ticket-flow diagram on the right. `app` gives .root and .status_var
    like the rest of the Business tab. Returns the tk variables."""
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    try:
        db, edition = db_and_edition()
        s = load(db)
    except Exception as e:  # noqa: BLE001
        ttk.Label(parent, text=f"Agent settings unavailable: {e}", font=("Arial", 8),
                  foreground="gray").pack(anchor="w")
        return {}

    providers = das.providers_for(edition)          # no Claude CLI on a server (2026-10-30)
    small = ("Arial", 8)
    v = {k: tk.BooleanVar(value=bool(s[k])) for k in BOOL_KEYS}
    v.update({k: tk.StringVar(value=str(s[k])) for k in STR_KEYS + INT_KEYS})
    _cur = das.effective_provider(s, edition)
    v["agent_provider"] = tk.StringVar(value=_label_for(providers, _cur) if any(p == _cur for p, _ in providers) else "")
    v["agent_label"] = tk.StringVar(value=s["agent_label"])
    v["agent_ask_who"] = tk.StringVar(value=_label_for(das.ASK_WHO, s["agent_ask_who"]))
    modes = [(m, das.STAGE_MODE_LABELS[m]) for m in das.STAGE_MODES]
    for k, _ in das.STAGES:
        v[f"agent_stage_{k}"] = tk.StringVar(value=_label_for(modes, s[f"agent_stage_{k}"]))
    for k, _ in das.BK_STAGES:
        v[f"agent_bk_stage_{k}"] = tk.StringVar(value=_label_for(modes, s[f"agent_bk_stage_{k}"]))
    v["h0"], v["h1"] = tk.StringVar(value=str(s["agent_hours"][0])), tk.StringVar(value=str(s["agent_hours"][1]))
    preview = tk.StringVar()
    mode_tip = "\n\n".join(das.MODE_HELP.values())

    ttk.Label(parent, font=small, foreground="gray", wraplength=900, justify="left",
              text=((("On a server these settings are set here only. " if edition == "business" else "")
                     + ("Works new tickets for you — sorts them, drafts replies, finds past fixes. Nothing "
                     "reaches a customer until you allow it. It runs on its own with a saved Claude or Grok key "
                     "(🔑 Agent API Key at the top of this tab), and its suggestions wait in the Service "
                     "Desk app's 🤖 Agent tab. With no key saved it doesn't run. "
                     "Same settings as the Service Desk app → Settings → 🤖 Agent. "))
                   + "Hover over anything for what it does.")
              ).pack(anchor="w", pady=(0, 4))
    cols = ttk.Frame(parent); cols.pack(fill="x")
    left = ttk.Frame(cols); left.grid(row=0, column=0, sticky="nw")
    right = ttk.Frame(cols); right.grid(row=0, column=1, sticky="nw", padx=(16, 0))
    outer, parent = parent, left                    # every ticket setting below goes in the left column

    row = ttk.Frame(parent); row.pack(fill="x")
    ttk.Checkbutton(row, text="Agent on", variable=v["agent_enabled"]).pack(side="left")
    cb = ttk.Checkbutton(row, text="Practice mode — only show what it would do", variable=v["agent_shadow"])
    cb.pack(side="left", padx=(12, 0))
    _tooltip(cb, das.PRACTICE_HELP)

    row = ttk.Frame(parent); row.pack(fill="x", pady=(4, 0))
    ttk.Label(row, text="Which AI runs it", width=16, font=small).pack(side="left")
    calm(ttk.Combobox(row, textvariable=v["agent_provider"], state="readonly", width=58,
                      values=[lab for _, lab in providers])).pack(side="left")

    stages = ttk.LabelFrame(parent, text="What the agent does  (hover for details)", padding=(6, 4))
    stages.pack(fill="x", pady=(6, 0))
    for i, (k, lab) in enumerate(das.STAGES):
        lbl = ttk.Label(stages, text=lab, font=small)
        lbl.grid(row=i, column=0, sticky="w")
        _tooltip(lbl, das.STAGE_HELP[k])
        combo = calm(ttk.Combobox(stages, textvariable=v[f"agent_stage_{k}"], state="readonly", width=28,
                                  values=[lab2 for _, lab2 in modes]))
        combo.grid(row=i, column=1, sticky="w", padx=(8, 0))
        _tooltip(combo, mode_tip)

    # ── how customers see it
    ident = ttk.LabelFrame(parent, text="How customers see it", padding=(6, 4))
    ident.pack(fill="x", pady=(6, 0))
    pic = ttk.Label(ident, text="🤖", font=("Arial", 22), width=4, anchor="center")
    pic.grid(row=0, column=0, rowspan=3, padx=(0, 8))
    holder = {}

    def show_photo():
        data = das.photo_bytes(db)
        if not data:
            pic.configure(image="", text="🤖"); holder.pop("img", None); return
        try:
            import io
            from PIL import Image, ImageTk
            img = ImageTk.PhotoImage(Image.open(io.BytesIO(data)).resize((64, 64)))
            holder["img"] = img
            pic.configure(image=img, text="")
        except Exception:  # noqa: BLE001
            pic.configure(text="🤖")

    def update_preview(*_):
        cur = dict(s, agent_name=v["agent_name"].get(), agent_label=v["agent_label"].get(),
                   agent_reply_signoff=v["agent_reply_signoff"].get())
        p = das.persona(cur)
        preview.set(f"{p['display']}    {p['signature']}")

    r = ttk.Frame(ident); r.grid(row=0, column=1, sticky="w")
    ttk.Label(r, text="Name (optional)", font=small).pack(side="left")
    ttk.Entry(r, textvariable=v["agent_name"], width=18).pack(side="left", padx=(4, 10))
    ttk.Label(r, text="Shown as", font=small).pack(side="left")
    calm(ttk.Combobox(r, textvariable=v["agent_label"], state="readonly", width=18,
                      values=list(das.LABELS))).pack(side="left", padx=(4, 0))
    r = ttk.Frame(ident); r.grid(row=1, column=1, sticky="w", pady=(2, 0))
    lbl = ttk.Label(r, text="Signature ending (blank = business name)", font=small)
    lbl.pack(side="left")
    ent = ttk.Entry(r, textvariable=v["agent_reply_signoff"], width=30)
    ent.pack(side="left", padx=(4, 0))
    _tooltip(lbl, das.SIGNOFF_HELP); _tooltip(ent, das.SIGNOFF_HELP)
    r = ttk.Frame(ident); r.grid(row=2, column=1, sticky="w", pady=(2, 0))

    def choose_photo():
        path = filedialog.askopenfilename(title="Agent photo", filetypes=[
            ("Pictures", "*.jpg *.jpeg *.png *.webp *.heic *.heif *.gif *.bmp"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                das.set_photo(db, f.read(), actor=None, edition=edition)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Agent photo", str(e)); return
        show_photo(); app.status_var.set("🤖  Agent photo saved")

    def remove_photo():
        try:
            das.clear_photo(db, actor=None, edition=edition)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Agent photo", str(e)); return
        show_photo(); app.status_var.set("🤖  Agent photo removed")

    ttk.Button(r, text="📷 Choose photo…", command=choose_photo).pack(side="left")
    ttk.Button(r, text="Remove photo", command=remove_photo).pack(side="left", padx=(4, 0))
    ttk.Label(ident, textvariable=preview, font=("Arial", 9, "bold")).grid(
        row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))
    ttk.Label(ident, font=small, foreground="gray", wraplength=520, justify="left",
              text=("That line is how every customer message ends. The label always shows with the name, "
                    "and the agent tells customers it's an assistant if they ask — it never pretends to "
                    "be a person.")).grid(row=4, column=0, columnspan=2, sticky="w")
    for k in ("agent_name", "agent_label", "agent_reply_signoff"):
        v[k].trace_add("write", update_preview)
    update_preview()
    show_photo()

    # ── timing
    tim = ttk.LabelFrame(parent, text="Timing", padding=(6, 4))
    tim.pack(fill="x", pady=(6, 0))

    def spin(parent_, var, lo, hi, width=5):
        return ttk.Spinbox(parent_, textvariable=var, from_=lo, to=hi, width=width)

    ttk.Label(tim, text="Replies go out as soon as they're approved. Hours 0 to 24 = any time.",
              font=small, foreground="gray").pack(anchor="w")
    r = ttk.Frame(tim); r.pack(fill="x", pady=(2, 0))
    ttk.Label(r, text="Works from hour", font=small).pack(side="left")
    spin(r, v["h0"], 0, 23, 3).pack(side="left", padx=(4, 4))
    ttk.Label(r, text="until", font=small).pack(side="left")
    spin(r, v["h1"], 1, 24, 3).pack(side="left", padx=(4, 12))
    ttk.Label(r, text="Monthly AI budget $", font=small).pack(side="left")
    spin(r, v["agent_monthly_budget_usd"], 0, 10000, 6).pack(side="left", padx=(4, 0))
    r = ttk.Frame(tim); r.pack(fill="x", pady=(2, 0))
    ttk.Label(r, text="Nudge after a customer waits (hours)", font=small).pack(side="left")
    spin(r, v["agent_wait_hours"], 1, 168, 4).pack(side="left", padx=(4, 0))
    ttk.Checkbutton(tim, text='Add the "request service" link to first replies',
                    variable=v["agent_include_service_link"]).pack(anchor="w", pady=(2, 0))

    # ── customer chat (2026-11-10, David: who may ask, what it answers, rate limit)
    chat = ttk.LabelFrame(parent, text="Customer chat \u2014 who may ask, and what it answers", padding=(6, 4))
    chat.pack(fill="x", pady=(6, 0))
    ttk.Label(chat, text="The \u201cAsk the AI assistant\u201d box on the main page and on each request form. "
                         "It answers to the page it sits on.", font=small, wraplength=520,
              justify="left").pack(anchor="w")
    row = ttk.Frame(chat); row.pack(fill="x", pady=(4, 0))
    ttk.Label(row, text="Who can ask", width=16, font=small).pack(side="left")
    cb = calm(ttk.Combobox(row, textvariable=v["agent_ask_who"], state="readonly", width=40,
                            values=[lab for _, lab in das.ASK_WHO]))
    cb.pack(side="left")
    _tooltip(cb, das.ASK_WHO_HELP)
    ttk.Checkbutton(chat, text="The chat may answer about services",
                    variable=v["agent_ask_services"]).pack(anchor="w", pady=(2, 0))
    ttk.Checkbutton(chat, text="The chat may answer about products",
                    variable=v["agent_ask_products"]).pack(anchor="w")
    row = ttk.Frame(chat); row.pack(fill="x", pady=(2, 0))
    ttk.Label(row, text="Questions per visitor per hour (0 = no limit)", font=small).pack(side="left")
    spin(row, v["agent_ask_per_hour"], 0, 1000, 6).pack(side="left", padx=(4, 0))
    row = ttk.Frame(chat); row.pack(fill="x", pady=(2, 0))
    ttk.Label(row, text="AI context file (optional)", font=small).pack(side="left")
    ent = ttk.Entry(row, textvariable=v["agent_ask_context_file"], width=40, state="readonly")
    ent.pack(side="left", padx=(4, 0), fill="x", expand=True)

    def choose_context():
        path = filedialog.askopenfilename(title="AI context file", filetypes=[
            ("Text files", "*.txt *.md"), ("All files", "*.*")])
        if path:
            v["agent_ask_context_file"].set(path)

    ttk.Button(row, text="Choose file\u2026", command=choose_context).pack(side="left", padx=(4, 0))
    ttk.Button(row, text="Clear",
               command=lambda: v["agent_ask_context_file"].set("")).pack(side="left")
    ttk.Label(chat, text="A .txt or .md file on this PC the Ask chat reads for extra business "
              "information (FAQs, policies, service details). Blank = none.",
              font=small, foreground="gray", wraplength=520, justify="left").pack(anchor="w")

    def current_form(src: dict | None = None) -> dict:
        get = (lambda k: src[k]) if src is not None else (lambda k: v[k].get())
        form = {k: get(k) for k in BOOL_KEYS + STR_KEYS + INT_KEYS}
        form["agent_provider"] = _value_for(providers, get("agent_provider"))
        form["agent_label"] = get("agent_label")
        form["agent_ask_who"] = _value_for(das.ASK_WHO, get("agent_ask_who"))
        for k, _ in das.STAGES:
            form[f"agent_stage_{k}"] = _value_for(modes, get(f"agent_stage_{k}"))
        for k, _ in das.BK_STAGES:
            form[f"agent_bk_stage_{k}"] = _value_for(modes, get(f"agent_bk_stage_{k}"))
        form["agent_hours"] = [get("h0"), get("h1")]
        return form

    def stored_view() -> dict:
        """What's saved now, as this form's boxes hold it (live_sync)."""
        x = load(db)
        out = {k: bool(x[k]) for k in BOOL_KEYS}
        out.update({k: str(x[k]) for k in STR_KEYS + INT_KEYS})
        cur = das.effective_provider(x, edition)
        out["agent_provider"] = _label_for(providers, cur) if any(p == cur for p, _ in providers) else ""
        out["agent_label"] = x["agent_label"]
        out["agent_ask_who"] = _label_for(das.ASK_WHO, x["agent_ask_who"])
        for k, _ in das.STAGES:
            out[f"agent_stage_{k}"] = _label_for(modes, x[f"agent_stage_{k}"])
        for k, _ in das.BK_STAGES:
            out[f"agent_bk_stage_{k}"] = _label_for(modes, x[f"agent_bk_stage_{k}"])
        out["h0"], out["h1"] = str(x["agent_hours"][0]), str(x["agent_hours"][1])
        return out

    # Vicki 2026-10-31: "when I select auto in some fields and save, it undoes the autos saved in the
    # other agent setting". Every Save used to write the WHOLE form — untouched fields still held the
    # values from when the tab was opened, so they put back anything saved since (the Service Desk
    # app, the Jobs section's runner, a chat tool). Now a Save writes only what changed on this form.
    baseline = {"form": current_form()}

    def _synced(shown):
        baseline["form"] = current_form(shown)
        if on_saved:
            on_saved()

    synced = live_sync(outer, v, stored_view, _synced)

    note = tk.StringVar(master=outer, value="")

    def do_save(quiet=False):
        form = current_form()
        changed = changed_only(form, baseline["form"])
        if quiet and not changed:
            note.set("")
            return
        ok, msg = save(db, changed, edition=edition) if changed else (True, "Nothing changed.")
        if ok:
            note.set("")
            baseline["form"] = form
            mark_saved(synced, v, stored_view)
            if on_saved:
                on_saved()          # the section header shows the agent / practice switches as saved
            app.status_var.set("🤖  Agent settings saved" if changed else "🤖  Nothing to save")
            app.root.after(3000, lambda: app.status_var.set("Ready"))
        elif quiet:
            note.set("⚠  Not saved yet: " + msg)
        else:
            messagebox.showwarning("Agent settings", msg)

    autosave(outer, v, lambda: do_save(quiet=True))
    ttk.Button(parent, text="💾 Save agent settings", command=do_save).pack(anchor="w", pady=(6, 0))
    ttk.Label(parent, textvariable=note, foreground="#b45309", wraplength=520, justify="left").pack(anchor="w")

    # ── right column: the ticket flow, lit up live as the settings change (2026-10-30)
    ttk.Label(right, text="How a ticket moves — the top and bottom boxes are the agent's steps (hover for details)",
              font=small, foreground="gray").pack(anchor="w")
    scale = flow_scale(right)
    canvas = tk.Canvas(right, width=round((das.FLOW_W + 2 * PAD) * scale),
                       height=round((das.FLOW_H + 2 * PAD) * scale), background="white",
                       highlightthickness=1, highlightbackground="#e5e7eb")
    canvas.pack(anchor="w")
    legend = ttk.Frame(right); legend.pack(anchor="w", pady=(4, 0))
    for m, color, word in das.flow({})["legend"]:
        tk.Label(legend, text="⬚" if m == "practice" else "■", foreground=color,
                 font=("Arial", 11, "bold")).pack(side="left")
        ttk.Label(legend, text=word, font=small).pack(side="left", padx=(0, 10))
    summary = tk.StringVar()
    ttk.Label(right, textvariable=summary, wraplength=round((das.FLOW_W + 2 * PAD) * scale), justify="left",
              font=("Arial", 9)).pack(anchor="w", pady=(4, 0))
    tips: dict = {}
    hover = {"tip": None}

    def redraw(*_):
        f = current_form()
        model = das.flow({**f, "agent_enabled": bool(f["agent_enabled"]),
                          "agent_shadow": bool(f["agent_shadow"])}, edition)
        draw_flow(canvas, model, tips, scale)
        summary.set(model["summary"])

    def on_motion(e):
        items = canvas.find_overlapping(e.x, e.y, e.x, e.y)
        text = next((tips[i] for i in reversed(items) if i in tips), "")
        if hover["tip"] and hover["tip"][1] == text:
            return
        if hover["tip"]:
            hover["tip"][0].destroy(); hover["tip"] = None
        if text:
            tip = tk.Toplevel(canvas); tip.wm_overrideredirect(True)
            tip.wm_geometry(f"+{e.x_root + 14}+{e.y_root + 10}")
            tk.Label(tip, text=text, justify="left", wraplength=340, background="#fffbe6",
                     relief="solid", borderwidth=1, font=("Arial", 9), padx=6, pady=4).pack()
            hover["tip"] = (tip, text)

    def on_leave(_e):
        if hover["tip"]:
            hover["tip"][0].destroy(); hover["tip"] = None

    canvas.bind("<Motion>", on_motion)
    canvas.bind("<Leave>", on_leave)
    for k in ("agent_enabled", "agent_shadow", "agent_provider") + tuple(f"agent_stage_{k}" for k, _ in das.STAGES):
        v[k].trace_add("write", redraw)
    redraw()
    _build_booking_section(outer, v, modes, current_form, do_save, edition, scale)
    # 2026-10-31 (Vicki): the Jobs and HR agents have their own sections on the Small Business tab
    # (build_standalone_section) — under the Jobs App link and the HR apps — not inside Service Desk.
    ttk.Label(outer, font=small, foreground="gray", wraplength=900, justify="left",
              text=(("The same assistant also works the Jobs app and the HR apps — their settings are in their own "
                     "sections on this tab: 🧰 Jobs App Agent & settings (under the Jobs App link) and 👥 HR Agent & "
                     "settings (under the HR apps). " if edition == "business" else
                     "The same assistant also works the Jobs app — its settings are in their own section on this "
                     "tab: 🧰 Jobs App Agent & settings (under the Jobs App link). ")
                    + "The AI chosen above, its hours and the monthly budget are shared by every agent.")
              ).pack(anchor="w", pady=(10, 0))
    return v


def _hover_canvas(canvas, tips):
    """Hover help for the step boxes of a flow canvas."""
    import tkinter as tk
    hover = {"tip": None}

    def on_motion(e):
        items = canvas.find_overlapping(e.x, e.y, e.x, e.y)
        text = next((tips[i] for i in reversed(items) if i in tips), "")
        if hover["tip"] and hover["tip"][1] == text:
            return
        if hover["tip"]:
            hover["tip"][0].destroy(); hover["tip"] = None
        if text:
            tip = tk.Toplevel(canvas); tip.wm_overrideredirect(True)
            tip.wm_geometry(f"+{e.x_root + 14}+{e.y_root + 10}")
            tk.Label(tip, text=text, justify="left", wraplength=340, background="#fffbe6",
                     relief="solid", borderwidth=1, font=("Arial", 9), padx=6, pady=4).pack()
            hover["tip"] = (tip, text)

    def on_leave(_e):
        if hover["tip"]:
            hover["tip"][0].destroy(); hover["tip"] = None

    canvas.bind("<Motion>", on_motion)
    canvas.bind("<Leave>", on_leave)


def jobs_form_values(form: dict, modes) -> dict:
    """GUI form (labels, strings) → typed Jobs agent settings. Raises ValueError with a plain message."""
    code = {lab: m for m, lab in modes}
    out = {"agent_jb_enabled": bool(form["agent_jb_enabled"]), "agent_jb_shadow": bool(form["agent_jb_shadow"]),
           "agent_jb_can_send_invoices": bool(form["agent_jb_can_send_invoices"]),
           "agent_jb_weather": bool(form["agent_jb_weather"])}
    for k, _ in das.JB_STAGES:
        val = form[f"agent_jb_stage_{k}"]
        out[f"agent_jb_stage_{k}"] = code.get(val, val)
    for k in ("agent_jb_invoice_max", "agent_jb_invoices_per_day", "agent_jb_quote_days", "agent_jb_prep_hour"):
        try:
            out[k] = int(str(form[k]).replace("$", "").replace(",", "").strip())
        except ValueError:
            raise ValueError(f"{k.replace('agent_jb_', '').replace('_', ' ')} must be a whole number") from None
    try:
        out["agent_jb_remind_days"] = [int(x) for x in str(form["agent_jb_remind_days"]).replace(",", " ").split()]
    except ValueError:
        raise ValueError("reminder days must be numbers, like 7, 14, 30") from None
    # the Route flow (2026-10-31) — its own on/off and practice switches
    for k in ("agent_jb_rt_enabled", "agent_jb_rt_shadow"):
        if k in form:
            out[k] = bool(form[k])
    for k, _ in das.RT_STAGES:
        if f"agent_jb_rt_stage_{k}" in form:
            val = form[f"agent_jb_rt_stage_{k}"]
            out[f"agent_jb_rt_stage_{k}"] = code.get(val, val)
    if "agent_jb_route_scope" in form:
        out["agent_jb_route_scope"] = {lab: k for k, lab in das.RT_SCOPES}.get(form["agent_jb_route_scope"],
                                                                              form["agent_jb_route_scope"])
    if "agent_jb_sort_weekday" in form:
        d = form["agent_jb_sort_weekday"]
        out["agent_jb_sort_weekday"] = das.WEEKDAYS.index(d) if d in das.WEEKDAYS else int(d)
    if "agent_jb_route_send_hour" in form:
        try:
            out["agent_jb_route_send_hour"] = int(str(form["agent_jb_route_send_hour"]).strip())
        except ValueError:
            raise ValueError("the route hour must be a whole number 0-23") from None
    return out


def save_jobs(form: dict, modes, edition: str, db: str | None = None,
              baseline: dict | None = None) -> tuple[bool, str]:
    """`baseline` = the form as loaded / last saved: only fields that differ from it are written,
    so a Save never puts back values saved elsewhere since (2026-10-31)."""
    import desk_agent_store
    import desk_db
    try:
        vals = jobs_form_values(form, modes)
        if baseline is not None:
            vals = changed_only(vals, jobs_form_values(baseline, modes))
        desk_agent_store.set_settings(vals, edition=edition, db=db)        # all or nothing (F-6)
    except (ValueError, desk_db.DeskError) as e:
        return False, str(e)
    return True, "Jobs agent settings saved." if vals else "Nothing changed."


def build_jobs_section(outer, modes, edition, scale, db: str | None = None, on_saved=None):
    """🧰 Jobs (jobs-agent-spec.md; David 2026-10-31): the Jobs agent's own on/off and practice
    switch, its 8 stages, "Let the agent send invoices", reminder days, and the jobs-flow
    diagram coloured like the ticket one. Saved in the separate agent database
    (desk_agent_store), so it doesn't need Service Desk."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    import desk_agent_store
    small = ("Arial", 8)
    mode_tip = "\n\n".join(das.MODE_HELP.values())
    s = desk_agent_store.settings(db)
    label = dict(modes)
    v = {k: tk.BooleanVar(value=bool(s[k])) for k in ("agent_jb_enabled", "agent_jb_shadow",
                                                      "agent_jb_can_send_invoices", "agent_jb_weather")}
    for k, _ in das.JB_STAGES:
        v[f"agent_jb_stage_{k}"] = tk.StringVar(value=label.get(s[f"agent_jb_stage_{k}"], s[f"agent_jb_stage_{k}"]))
    for k in ("agent_jb_invoice_max", "agent_jb_invoices_per_day", "agent_jb_quote_days", "agent_jb_prep_hour"):
        v[k] = tk.StringVar(value=str(s[k]))
    v["agent_jb_remind_days"] = tk.StringVar(value=", ".join(str(d) for d in s["agent_jb_remind_days"]))
    box = ttk.LabelFrame(outer, text="🧰 Jobs  (hover for details)", padding=(6, 4))
    box.pack(fill="x", pady=(10, 0))
    ttk.Label(box, font=small, foreground="gray", wraplength=900, justify="left",
              text=("The same assistant, working the Jobs app: follows up quotes, suggests dates, checks tomorrow, "
                    "watches jobs on site, drafts invoices, reminds customers who haven't paid, sets up the next "
                    "recurring visit and learns real job times. It never takes payments, changes prices or moves a "
                    "fixed-time job or anything today. Its settings and work are kept in their own database.")
              ).pack(anchor="w", pady=(0, 4))
    cols = ttk.Frame(box); cols.pack(fill="x")
    left = ttk.Frame(cols); left.grid(row=0, column=0, sticky="nw")
    right = ttk.Frame(cols); right.grid(row=0, column=1, sticky="nw", padx=(16, 0))
    row = ttk.Frame(left); row.pack(fill="x")
    ttk.Checkbutton(row, text="Jobs agent on", variable=v["agent_jb_enabled"]).pack(side="left")
    cb = ttk.Checkbutton(row, text="Practice mode for jobs", variable=v["agent_jb_shadow"])
    cb.pack(side="left", padx=(12, 0)); _tooltip(cb, das.JB_PRACTICE_HELP)
    stages = ttk.LabelFrame(left, text="What it does", padding=(6, 4))
    stages.pack(fill="x", pady=(6, 0))
    for i, (k, lab) in enumerate(das.JB_STAGES):
        lbl = ttk.Label(stages, text=lab, font=small); lbl.grid(row=i, column=0, sticky="w")
        _tooltip(lbl, das.JB_STAGE_HELP[k])
        combo = calm(ttk.Combobox(stages, textvariable=v[f"agent_jb_stage_{k}"], state="readonly", width=28,
                                  values=[lab2 for _, lab2 in modes]))
        combo.grid(row=i, column=1, sticky="w", padx=(8, 0)); _tooltip(combo, mode_tip)
    row = ttk.Frame(left); row.pack(fill="x", pady=(6, 0))
    cb = ttk.Checkbutton(row, text="Let the agent send invoices", variable=v["agent_jb_can_send_invoices"])
    cb.pack(side="left"); _tooltip(cb, das.JB_SEND_HELP)
    ttk.Label(row, text="up to $", font=small).pack(side="left", padx=(8, 2))
    ttk.Entry(row, textvariable=v["agent_jb_invoice_max"], width=7).pack(side="left")
    ttk.Label(row, text="each,", font=small).pack(side="left", padx=(4, 4))
    ttk.Spinbox(row, textvariable=v["agent_jb_invoices_per_day"], from_=1, to=100, width=4).pack(side="left")
    ttk.Label(row, text="a day", font=small).pack(side="left", padx=(4, 0))
    row = ttk.Frame(left); row.pack(fill="x", pady=(2, 0))
    w = ttk.Label(row, text="Follow up quotes after (days)", font=small); w.pack(side="left")
    ttk.Spinbox(row, textvariable=v["agent_jb_quote_days"], from_=1, to=60, width=4).pack(side="left", padx=(4, 10))
    w = ttk.Label(row, text="Payment reminders at days", font=small); w.pack(side="left"); _tooltip(w, das.JB_REMIND_HELP)
    e = ttk.Entry(row, textvariable=v["agent_jb_remind_days"], width=10); e.pack(side="left", padx=(4, 0))
    _tooltip(e, das.JB_REMIND_HELP)
    row = ttk.Frame(left); row.pack(fill="x", pady=(2, 0))
    cb = ttk.Checkbutton(row, text="Check the weather for outdoor jobs", variable=v["agent_jb_weather"])
    cb.pack(side="left"); _tooltip(cb, das.JB_WEATHER_HELP)
    ttk.Label(row, text="Prep tomorrow at hour", font=small).pack(side="left", padx=(10, 4))
    ttk.Spinbox(row, textvariable=v["agent_jb_prep_hour"], from_=0, to=23, width=3).pack(side="left")

    jb_base: dict = {}
    jb_sync: dict = {}

    jb_note = tk.StringVar(master=outer, value="")

    def do_save(quiet=False):
        form = {k: x.get() for k, x in v.items()}
        if quiet and form == jb_base.get("form"):
            jb_note.set("")
            return
        ok, msg = save_jobs(form, modes, edition, db, baseline=jb_base.get("form"))
        if ok:
            jb_note.set("")
            jb_base["form"] = form
            mark_saved(jb_sync["shown"], v, jb_sync["view"])
            if on_saved:
                on_saved()          # the section header shows what's now saved
        if quiet:
            jb_note.set("" if ok else "⚠  Not saved yet: " + msg)
        else:
            (messagebox.showinfo if ok else messagebox.showerror)("Jobs agent", msg)

    ttk.Button(left, text="💾 Save Jobs agent settings", command=do_save).pack(anchor="w", pady=(6, 0))
    ttk.Label(left, textvariable=jb_note, foreground="#b45309", wraplength=520, justify="left").pack(anchor="w")

    ttk.Label(right, text="How a job moves — the top and bottom boxes are the agent's steps (hover for details)",
              font=small, foreground="gray").pack(anchor="w")
    canvas = tk.Canvas(right, width=round((das.FLOW_W + 2 * PAD) * scale), height=round((das.FLOW_H + 2 * PAD) * scale),
                       background="white", highlightthickness=1, highlightbackground="#e5e7eb")
    canvas.pack(anchor="w")
    summary = tk.StringVar()
    ttk.Label(right, textvariable=summary, wraplength=round((das.FLOW_W + 2 * PAD) * scale), justify="left",
              font=("Arial", 9)).pack(anchor="w", pady=(4, 0))
    tips: dict = {}

    def redraw(*_):
        code = {lab: m for m, lab in modes}
        f = {k: (code.get(x.get(), x.get()) if k.startswith("agent_jb_stage_") else x.get()) for k, x in v.items()}
        f = {**s, **{k: val for k, val in f.items() if k.startswith("agent_jb_stage_")},
             **{k: bool(f[k]) for k in ("agent_jb_enabled", "agent_jb_shadow", "agent_jb_can_send_invoices")}}
        model = das.jobs_flow(f, edition)
        draw_flow(canvas, model, tips, scale)
        summary.set(model["summary"])

    _hover_canvas(canvas, tips)

    # 🗺 Route flow (David 2026-10-31): weekly sort → scheduled week → routed → crew gets the route.
    rt = ttk.LabelFrame(box, text="🗺 Route flow — sort the week, schedule it, route it, crews get their route",
                        padding=(6, 4))
    rt.pack(fill="x", pady=(8, 0))
    # Its own on/off and practice switches (David 2026-10-31), separate from the jobs ones.
    for k in ("agent_jb_rt_enabled", "agent_jb_rt_shadow"):
        v[k] = tk.BooleanVar(value=bool(s.get(k, das.DEFAULTS[k])))
    rrow = ttk.Frame(rt); rrow.pack(fill="x", pady=(0, 4))
    cb = ttk.Checkbutton(rrow, text="Route flow on", variable=v["agent_jb_rt_enabled"])
    cb.pack(side="left"); _tooltip(cb, das.RT_ENABLED_HELP)
    cb = ttk.Checkbutton(rrow, text="Practice mode for routes", variable=v["agent_jb_rt_shadow"])
    cb.pack(side="left", padx=(12, 0)); _tooltip(cb, das.RT_PRACTICE_HELP)
    rcols = ttk.Frame(rt); rcols.pack(fill="x")
    rleft = ttk.Frame(rcols); rleft.grid(row=0, column=0, sticky="nw")
    rright = ttk.Frame(rcols); rright.grid(row=0, column=1, sticky="nw", padx=(16, 0))
    for k, _ in das.RT_STAGES:
        v[f"agent_jb_rt_stage_{k}"] = tk.StringVar(value=label.get(s[f"agent_jb_rt_stage_{k}"],
                                                                   s[f"agent_jb_rt_stage_{k}"]))
    v["agent_jb_route_scope"] = tk.StringVar(value=dict(das.RT_SCOPES).get(s["agent_jb_route_scope"], "Each day"))
    v["agent_jb_sort_weekday"] = tk.StringVar(value=das.WEEKDAYS[int(s["agent_jb_sort_weekday"]) % 7])
    v["agent_jb_route_send_hour"] = tk.StringVar(value=str(s["agent_jb_route_send_hour"]))
    for i, (k, lab) in enumerate(das.RT_STAGES):
        lbl = ttk.Label(rleft, text=lab, font=small); lbl.grid(row=i, column=0, sticky="w")
        _tooltip(lbl, das.RT_STAGE_HELP[k])
        combo = calm(ttk.Combobox(rleft, textvariable=v[f"agent_jb_rt_stage_{k}"], state="readonly", width=28,
                                  values=[lab2 for _, lab2 in modes]))
        combo.grid(row=i, column=1, sticky="w", padx=(8, 0)); _tooltip(combo, mode_tip)
    n = len(das.RT_STAGES)
    w = ttk.Label(rleft, text="Route", font=small); w.grid(row=n, column=0, sticky="w", pady=(6, 0))
    _tooltip(w, das.RT_SCOPE_HELP)
    calm(ttk.Combobox(rleft, textvariable=v["agent_jb_route_scope"], state="readonly", width=28,
                      values=[lab for _, lab in das.RT_SCOPES])).grid(row=n, column=1, sticky="w", padx=(8, 0), pady=(6, 0))
    w = ttk.Label(rleft, text="Sort the coming week on", font=small); w.grid(row=n + 1, column=0, sticky="w")
    _tooltip(w, das.RT_SORT_HELP)
    calm(ttk.Combobox(rleft, textvariable=v["agent_jb_sort_weekday"], state="readonly", width=28,
                      values=list(das.WEEKDAYS))).grid(row=n + 1, column=1, sticky="w", padx=(8, 0))
    w = ttk.Label(rleft, text="Crews get tomorrow's route at hour", font=small); w.grid(row=n + 2, column=0, sticky="w")
    _tooltip(w, das.RT_SEND_HELP)
    ttk.Spinbox(rleft, textvariable=v["agent_jb_route_send_hour"], from_=0, to=23, width=4).grid(
        row=n + 2, column=1, sticky="w", padx=(8, 0))
    ttk.Button(rleft, text="💾 Save Jobs agent settings", command=do_save).grid(row=n + 3, column=0, sticky="w",
                                                                              pady=(6, 0))
    ttk.Label(rright, text="How a week of routes moves — the boxes above and below are the agent's steps",
              font=small, foreground="gray").pack(anchor="w")
    rcanvas = tk.Canvas(rright, width=round((das.FLOW_W + 2 * PAD) * scale),
                        height=round((das.FLOW_H + 2 * PAD) * scale),
                        background="white", highlightthickness=1, highlightbackground="#e5e7eb")
    rcanvas.pack(anchor="w")
    rsummary = tk.StringVar()
    ttk.Label(rright, textvariable=rsummary, wraplength=round((das.FLOW_W + 2 * PAD) * scale), justify="left",
              font=("Arial", 9)).pack(anchor="w", pady=(4, 0))
    rtips: dict = {}
    _hover_canvas(rcanvas, rtips)

    def redraw_all(*_):
        redraw()
        try:
            f = {**s, **jobs_form_values({k: x.get() for k, x in v.items()}, modes)}
        except ValueError:
            return
        model = das.route_flow(f, edition)
        draw_flow(rcanvas, model, rtips, scale)
        rsummary.set(model["summary"])

    for k in (("agent_jb_enabled", "agent_jb_shadow", "agent_jb_can_send_invoices", "agent_jb_route_scope",
               "agent_jb_sort_weekday", "agent_jb_rt_enabled", "agent_jb_rt_shadow")
              + tuple(f"agent_jb_stage_{k}" for k, _ in das.JB_STAGES)
              + tuple(f"agent_jb_rt_stage_{k}" for k, _ in das.RT_STAGES)):
        v[k].trace_add("write", redraw_all)
    redraw_all()
    jb_base["form"] = {k: x.get() for k, x in v.items()}     # what the form showed when loaded

    def stored_view() -> dict:
        """What's saved now, as this form's boxes hold it (live_sync)."""
        x = desk_agent_store.settings(db)
        out = {k: bool(x[k]) for k in ("agent_jb_enabled", "agent_jb_shadow", "agent_jb_can_send_invoices",
                                       "agent_jb_weather", "agent_jb_rt_enabled", "agent_jb_rt_shadow")}
        for k, _ in das.JB_STAGES:
            out[f"agent_jb_stage_{k}"] = label.get(x[f"agent_jb_stage_{k}"], x[f"agent_jb_stage_{k}"])
        for k, _ in das.RT_STAGES:
            out[f"agent_jb_rt_stage_{k}"] = label.get(x[f"agent_jb_rt_stage_{k}"], x[f"agent_jb_rt_stage_{k}"])
        for k in ("agent_jb_invoice_max", "agent_jb_invoices_per_day", "agent_jb_quote_days", "agent_jb_prep_hour",
                  "agent_jb_route_send_hour"):
            out[k] = str(x[k])
        out["agent_jb_remind_days"] = ", ".join(str(d) for d in x["agent_jb_remind_days"])
        out["agent_jb_route_scope"] = dict(das.RT_SCOPES).get(x["agent_jb_route_scope"], "Each day")
        out["agent_jb_sort_weekday"] = das.WEEKDAYS[int(x["agent_jb_sort_weekday"]) % 7]
        return out

    def _synced(shown):
        jb_base["form"] = dict(shown)
        if on_saved:
            on_saved()

    jb_sync.update(view=stored_view, shown=live_sync(box, v, stored_view, _synced))
    autosave(box, v, lambda: do_save(quiet=True))
    return v


HR_BOOLS = ("agent_hr_enabled", "agent_hr_shadow", "agent_hr_can_approve_timeoff", "agent_hr_ack_sensitive")
HR_INTS = ("agent_hr_timeoff_max_days", "agent_hr_timeoff_notice_days", "agent_hr_timeoff_max_off",
           "agent_hr_timeoff_per_day", "agent_hr_overtime_warn_hours")


def hr_form_values(form: dict, modes) -> dict:
    """GUI form (labels, strings) → typed HR agent settings. Raises ValueError with a plain message."""
    code = {lab: m for m, lab in modes}
    out = {k: bool(form[k]) for k in HR_BOOLS}
    for k, _ in das.HR_STAGES:
        val = form[f"agent_hr_stage_{k}"]
        out[f"agent_hr_stage_{k}"] = code.get(val, val)
    for k in HR_INTS:
        try:
            out[k] = int(str(form[k]).strip())
        except ValueError:
            raise ValueError(f"{k.replace('agent_hr_', '').replace('_', ' ')} must be a whole number") from None
    out["agent_hr_reviewers"] = {lab: k for k, lab in das.HR_REVIEWERS}.get(form["agent_hr_reviewers"],
                                                                            form["agent_hr_reviewers"])
    out["agent_hr_incidents_access"] = {lab: k for k, lab in das.HR_INCIDENTS}.get(
        form["agent_hr_incidents_access"], form["agent_hr_incidents_access"])
    try:
        out["agent_hr_quiet_hours"] = [int(x) for x in str(form["agent_hr_quiet_hours"]).replace("-", " ")
                                       .replace("–", " ").replace(",", " ").split()]
    except ValueError:
        raise ValueError("quiet hours must be two hours, like 8-18") from None
    try:
        out["agent_hr_expiry_days"] = [int(x) for x in str(form["agent_hr_expiry_days"]).replace(",", " ").split()]
    except ValueError:
        raise ValueError("warning days must be numbers, like 60, 30, 7") from None
    return out


def save_hr(form: dict, modes, edition: str, db: str | None = None,
            baseline: dict | None = None) -> tuple[bool, str]:
    """`baseline` as in save_jobs: only fields that changed on this form are written (2026-10-31)."""
    import desk_agent_hr_store
    import desk_db
    try:
        vals = hr_form_values(form, modes)
        if baseline is not None:
            vals = changed_only(vals, hr_form_values(baseline, modes))
        desk_agent_hr_store.set_settings(vals, edition=edition, db=db)     # all or nothing (F-6)
    except (ValueError, desk_db.DeskError) as e:
        return False, str(e)
    return True, "HR agent settings saved." if vals else "Nothing changed."


def build_hr_section(outer, modes, edition, scale, db: str | None = None, shared: dict | None = None,
                     on_saved=None):
    """👥 HR (hr-agent-spec.md; Vicki 2026-10-31): the HR agent's own on/off and practice switch,
    its 9 stages, "Let the agent approve time off" with its limits, who reviews, what it may see of
    incident reports, and the HR diagram coloured like the others. Saved in the HR agent's own
    database inside the HR data folder (desk_agent_hr_store). `shared` = the Service Desk settings
    (the runner the HR agent would use)."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    import desk_agent_hr_store
    small = ("Arial", 8)
    mode_tip = "\n\n".join(das.MODE_HELP.values())
    s = desk_agent_hr_store.settings(db)
    base = {**desk_agent_hr_store.all_settings(db), **{k: (shared or {})[k] for k in
                                                         desk_agent_hr_store.SHARED_KEYS if k in (shared or {})}}
    label = dict(modes)
    v = {k: tk.BooleanVar(value=bool(s[k])) for k in HR_BOOLS}
    for k, _ in das.HR_STAGES:
        v[f"agent_hr_stage_{k}"] = tk.StringVar(value=label.get(s[f"agent_hr_stage_{k}"], s[f"agent_hr_stage_{k}"]))
    for k in HR_INTS:
        v[k] = tk.StringVar(value=str(s[k]))
    v["agent_hr_reviewers"] = tk.StringVar(value=dict(das.HR_REVIEWERS)[s["agent_hr_reviewers"]])
    v["agent_hr_incidents_access"] = tk.StringVar(value=dict(das.HR_INCIDENTS)[s["agent_hr_incidents_access"]])
    v["agent_hr_quiet_hours"] = tk.StringVar(value="-".join(str(h) for h in s["agent_hr_quiet_hours"]))
    v["agent_hr_expiry_days"] = tk.StringVar(value=", ".join(str(d) for d in s["agent_hr_expiry_days"]))
    box = ttk.LabelFrame(outer, text="👥 HR  (hover for details)", padding=(6, 4))
    box.pack(fill="x", pady=(10, 0))
    ttk.Label(box, font=small, foreground="gray", wraplength=900, justify="left",
              text=("The same assistant, working the HR Admin and HR Portal apps: keeps onboarding and offboarding on "
                    "time, checks time-off requests, watches the time clock and expiring documents, drafts answers to "
                    "employees' questions and makes sure incident reports are acknowledged. People make every "
                    "decision about a person — it never changes pay, time or records. Its settings and work are kept "
                    "in the HR data folder.")).pack(anchor="w", pady=(0, 4))
    cols = ttk.Frame(box); cols.pack(fill="x")
    left = ttk.Frame(cols); left.grid(row=0, column=0, sticky="nw")
    right = ttk.Frame(cols); right.grid(row=0, column=1, sticky="nw", padx=(16, 0))
    row = ttk.Frame(left); row.pack(fill="x")
    ttk.Checkbutton(row, text="HR agent on", variable=v["agent_hr_enabled"]).pack(side="left")
    cb = ttk.Checkbutton(row, text="Practice mode for HR", variable=v["agent_hr_shadow"])
    cb.pack(side="left", padx=(12, 0)); _tooltip(cb, das.HR_PRACTICE_HELP)
    stages = ttk.LabelFrame(left, text="What it does", padding=(6, 4))
    stages.pack(fill="x", pady=(6, 0))
    for i, (k, lab) in enumerate(das.HR_STAGES):
        lbl = ttk.Label(stages, text=lab, font=small); lbl.grid(row=i, column=0, sticky="w")
        _tooltip(lbl, das.HR_STAGE_HELP[k])
        combo = calm(ttk.Combobox(stages, textvariable=v[f"agent_hr_stage_{k}"], state="readonly", width=28,
                                  values=[lab2 for _, lab2 in modes]))
        combo.grid(row=i, column=1, sticky="w", padx=(8, 0)); _tooltip(combo, mode_tip)
    row = ttk.Frame(left); row.pack(fill="x", pady=(6, 0))
    cb = ttk.Checkbutton(row, text="Let the agent approve time off", variable=v["agent_hr_can_approve_timeoff"])
    cb.pack(side="left"); _tooltip(cb, das.HR_TIMEOFF_HELP)
    row = ttk.Frame(left); row.pack(fill="x", pady=(2, 0))
    for text, k, lo, hi in (("up to (days)", "agent_hr_timeoff_max_days", 1, 10),
                            ("notice (days)", "agent_hr_timeoff_notice_days", 0, 90),
                            ("most off a day", "agent_hr_timeoff_max_off", 1, 20),
                            ("approvals a day", "agent_hr_timeoff_per_day", 1, 50)):
        w = ttk.Label(row, text=text, font=small); w.pack(side="left", padx=(0, 2)); _tooltip(w, das.HR_TIMEOFF_HELP)
        ttk.Spinbox(row, textvariable=v[k], from_=lo, to=hi, width=3).pack(side="left", padx=(0, 8))
    grid = ttk.Frame(left); grid.pack(fill="x", pady=(6, 0))
    w = ttk.Label(grid, text="Who reviews", font=small); w.grid(row=0, column=0, sticky="w")
    _tooltip(w, das.HR_REVIEWERS_HELP)
    calm(ttk.Combobox(grid, textvariable=v["agent_hr_reviewers"], state="readonly", width=46,
                      values=[lab for _, lab in das.HR_REVIEWERS])).grid(row=0, column=1, sticky="w", padx=(8, 0))
    w = ttk.Label(grid, text="Incident reports", font=small); w.grid(row=1, column=0, sticky="w")
    _tooltip(w, das.HR_INCIDENTS_HELP)
    calm(ttk.Combobox(grid, textvariable=v["agent_hr_incidents_access"], state="readonly", width=46,
                      values=[lab for _, lab in das.HR_INCIDENTS])).grid(row=1, column=1, sticky="w", padx=(8, 0))
    row = ttk.Frame(left); row.pack(fill="x", pady=(4, 0))
    ttk.Label(row, text="Overtime warning at (hours a week)", font=small).pack(side="left")
    ttk.Spinbox(row, textvariable=v["agent_hr_overtime_warn_hours"], from_=20, to=60, width=3).pack(side="left",
                                                                                                    padx=(4, 10))
    ttk.Label(row, text="Messages to employees only", font=small).pack(side="left")
    ttk.Entry(row, textvariable=v["agent_hr_quiet_hours"], width=6).pack(side="left", padx=(4, 0))
    row = ttk.Frame(left); row.pack(fill="x", pady=(2, 0))
    ttk.Label(row, text="Warn about expiring documents at (days)", font=small).pack(side="left")
    ttk.Entry(row, textvariable=v["agent_hr_expiry_days"], width=10).pack(side="left", padx=(4, 10))
    cb = ttk.Checkbutton(row, text="Acknowledge sensitive messages", variable=v["agent_hr_ack_sensitive"])
    cb.pack(side="left"); _tooltip(cb, "A message about something sensitive (injury, harassment, medical, pay "
                                       "dispute…) gets \"Thanks — HR will get back to you\" and goes to a person.")
    w = ttk.Label(left, text="Runs only on a Claude API key or the Grok bot — never from a chat.",
                  font=small, foreground="gray")
    w.pack(anchor="w", pady=(4, 0)); _tooltip(w, das.HR_RUNNER_HELP)

    hr_base = {"form": {k: x.get() for k, x in v.items()}}       # what the form showed when loaded
    hr_sync: dict = {}

    hr_note = tk.StringVar(master=outer, value="")

    def do_save(quiet=False):
        form = {k: x.get() for k, x in v.items()}
        if quiet and form == hr_base["form"]:
            hr_note.set("")
            return
        ok, msg = save_hr(form, modes, edition, db, baseline=hr_base["form"])
        if ok:
            hr_base["form"] = form
            mark_saved(hr_sync["shown"], v, hr_sync["view"])
            if on_saved:
                on_saved()          # the section header shows what's now saved
        if quiet:
            hr_note.set("" if ok else "⚠  Not saved yet: " + msg)
        else:
            (messagebox.showinfo if ok else messagebox.showerror)("HR agent", msg)

    ttk.Button(left, text="💾 Save HR agent settings", command=do_save).pack(anchor="w", pady=(6, 0))
    ttk.Label(left, textvariable=hr_note, foreground="#b45309", wraplength=520, justify="left").pack(anchor="w")

    ttk.Label(right, text="How an employee moves — the top and bottom boxes are the agent's steps (hover for details)",
              font=small, foreground="gray").pack(anchor="w")
    canvas = tk.Canvas(right, width=round((das.FLOW_W + 2 * PAD) * scale), height=round((das.FLOW_H + 2 * PAD) * scale),
                       background="white", highlightthickness=1, highlightbackground="#e5e7eb")
    canvas.pack(anchor="w")
    summary = tk.StringVar()
    ttk.Label(right, textvariable=summary, wraplength=round((das.FLOW_W + 2 * PAD) * scale), justify="left",
              font=("Arial", 9)).pack(anchor="w", pady=(4, 0))
    tips: dict = {}
    _hover_canvas(canvas, tips)

    def redraw(*_):
        try:
            f = {**base, **hr_form_values({k: x.get() for k, x in v.items()}, modes)}
        except ValueError:
            return
        model = das.hr_flow(f, edition)
        draw_flow(canvas, model, tips, scale)
        summary.set(model["summary"])

    for k in (HR_BOOLS + ("agent_hr_reviewers", "agent_hr_incidents_access")
              + tuple(f"agent_hr_stage_{k}" for k, _ in das.HR_STAGES)):
        v[k].trace_add("write", redraw)
    redraw()

    def stored_view() -> dict:
        """What's saved now, as this form's boxes hold it (live_sync)."""
        x = desk_agent_hr_store.settings(db)
        out = {k: bool(x[k]) for k in HR_BOOLS}
        for k, _ in das.HR_STAGES:
            out[f"agent_hr_stage_{k}"] = label.get(x[f"agent_hr_stage_{k}"], x[f"agent_hr_stage_{k}"])
        for k in HR_INTS:
            out[k] = str(x[k])
        out["agent_hr_reviewers"] = dict(das.HR_REVIEWERS)[x["agent_hr_reviewers"]]
        out["agent_hr_incidents_access"] = dict(das.HR_INCIDENTS)[x["agent_hr_incidents_access"]]
        out["agent_hr_quiet_hours"] = "-".join(str(h) for h in x["agent_hr_quiet_hours"])
        out["agent_hr_expiry_days"] = ", ".join(str(d) for d in x["agent_hr_expiry_days"])
        return out

    def _synced(shown):
        hr_base["form"] = dict(shown)
        if on_saved:
            on_saved()

    hr_sync.update(view=stored_view, shown=live_sync(box, v, stored_view, _synced))
    autosave(box, v, lambda: do_save(quiet=True))
    return v


# ── Their own sections on the Small Business tab (Vicki 2026-10-31) ────────────
# "Where is the jobs app agent and settings like the help desk in the small business tab?"
# The Jobs agent sits under the Jobs App link and the HR agent under the HR apps, each with its
# own header and "(on) / (off)", Show settings, and — when Service Desk is off, so its 🤖 Agent
# tab isn't there to choose one — which AI runs it (one runner for every agent).

_SECTIONS_FILE = "agent_sections.json"


def _section_shown(which: str) -> bool:
    import json
    import desk_gui_links
    try:
        return bool(json.loads((desk_gui_links._state_dir() / _SECTIONS_FILE).read_text(encoding="utf-8"))
                    .get(which, True))
    except Exception:  # noqa: BLE001
        return True


def _save_section_shown(which: str, show: bool) -> None:
    import json
    import desk_gui_links
    p = desk_gui_links._state_dir() / _SECTIONS_FILE
    try:
        cur = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except Exception:  # noqa: BLE001
        cur = {}
    cur[which] = bool(show)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cur), encoding="utf-8")
        tmp.replace(p)
    except Exception:  # noqa: BLE001 — a preference, never worth an error box
        pass


def _on_text(s: dict, on: str, practice: str) -> str:
    if not s.get(on):
        return "off"
    return "on — practice mode" if s.get(practice) else "on"


def agent_section_status(which: str) -> dict:
    """The header's status, read from what's SAVED: HR "(on)" / "(on — practice mode)" / "(off)";
    Jobs shows its two switches, e.g. "(jobs on — practice mode · routes off)" (2026-10-31)."""
    try:
        if which == "hr":
            import desk_agent_hr_store as st
            s, pairs = st.settings(), [("", "agent_hr_enabled", "agent_hr_shadow")]
        else:
            import desk_agent_store as st
            s, pairs = st.settings(), [("jobs ", "agent_jb_enabled", "agent_jb_shadow"),
                                       ("routes ", "agent_jb_rt_enabled", "agent_jb_rt_shadow")]
    except Exception:  # noqa: BLE001
        return {"text": "", "color": "#6b7280", "on": False}
    # David 2026-11-06: say what's really happening. The agent's own switches are kept, but they mean nothing while its
    # app is off or no key is saved.
    grey = "#6b7280"
    if which == "jobs":
        try:
            import desk_gui_links
            import tool_config_store
            if not tool_config_store.group_enabled(desk_gui_links.mode_of(), "job_tracker"):
                return {"text": "(not enabled)", "color": grey, "on": False}
        except Exception:  # noqa: BLE001
            pass
    states = [(lab, _on_text(s, on, pr)) for lab, on, pr in pairs]
    any_on = any(t != "off" for _, t in states)
    try:
        import desk_agent
        if any_on and not desk_agent._has_key(s):
            return {"text": "(not running: no API key saved)", "color": grey, "on": False}
    except Exception:  # noqa: BLE001
        pass
    text = "(" + " · ".join(f"{lab}{t}" for lab, t in states) + ")"
    if not any_on:
        color = "#6b7280"
    elif any(t == "on" for _, t in states):
        color = das.MODE_COLORS["auto"]
    else:
        color = das.MODE_COLORS["practice"]
    return {"text": text, "color": color, "on": any_on}


def save_shared_runner(provider: str, edition: str) -> tuple[bool, str]:
    """The runner every agent shares, chosen here when Service Desk (and its 🤖 Agent tab) is off:
    saved in the Service Desk settings database the agents copy it from, then copied now."""
    import desk_agent_hr_store
    import desk_agent_store
    import desk_db
    try:
        tdb = desk_db.default_db_path()
        desk_db.init_db(tdb)
        desk_db.set_setting(tdb, "agent_provider", provider, edition=edition)
        desk_agent_store.sync_shared(tdb)
        try:
            from pathlib import Path
            if Path(desk_agent_hr_store.path()).exists():
                desk_agent_hr_store.sync_shared(tdb)
        except Exception:  # noqa: BLE001
            pass
    except (ValueError, desk_db.DeskError) as e:
        return False, str(e)
    return True, "Saved — every agent uses this AI."


def build_standalone_section(app, parent, which: str) -> dict:
    """Build "🧰 Jobs App Agent & settings" (which="jobs") or "👥 HR Agent & settings" (which="hr")
    as its own section of the Small Business tab. Returns {"frame", "status", "refresh"}."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    import desk_gui_links
    import desk_rules
    small = ("Arial", 8)
    edition = desk_rules.edition_for_mode(desk_gui_links.mode_of())
    title = "🧰 Jobs App Agent & settings" if which == "jobs" else "👥 HR Agent & settings"
    no_wheel_changes(parent)                            # scrolling never changes a setting (2026-10-31)
    head = ttk.Frame(parent)
    ttk.Label(head, text=title, font=("Arial", 9, "bold")).pack(side="left")
    status_lbl = tk.Label(head, font=("Arial", 9, "bold"))
    status_lbl.pack(side="left", padx=(6, 0))
    lf = ttk.LabelFrame(parent, labelwidget=head, padding=(8, 4))
    out = {"frame": lf, "status": status_lbl}

    def refresh(*_):
        st = agent_section_status(which)
        status_lbl.configure(text=st["text"], foreground=st["color"])

    def keep_fresh():                                   # follows the Jobs app switch, the key and the app's own changes
        try:
            if status_lbl.winfo_exists():
                refresh()
                status_lbl.after(2000, keep_fresh)
        except tk.TclError:
            pass
    status_lbl.after(2000, keep_fresh)

    show = tk.BooleanVar(value=_section_shown(which))
    top = ttk.Frame(lf); top.pack(fill="x")
    ttk.Checkbutton(top, text="Show settings", variable=show).pack(side="left")
    where = ("Same settings as the Jobs app → 🤖 Agent tab; its suggestions wait there for your OK."
             if which == "jobs" else
             "Its suggestions wait in HR Admin → 🤖 Agent. HR data never goes to a chat AI.")
    ttk.Label(top, text=where, font=small, foreground="gray").pack(side="left", padx=(12, 0))
    content = ttk.Frame(lf)

    # Which AI runs it — one runner for every agent. With Service Desk on it's chosen in the Service
    # Desk Agent's 🤖 Agent tab; with it off, here.
    try:
        import desk_gui_settings
        desk_on = desk_gui_settings.section_status()["enabled"]
    except Exception:  # noqa: BLE001
        desk_on = True
    row = ttk.Frame(content); row.pack(fill="x", pady=(4, 2))
    if desk_on:
        ttk.Label(row, font=small, foreground="gray",
                  text="Which AI runs it, its hours and the monthly budget are shared by every agent — set them in "
                       "Service Desk Agent & settings → 🤖 Agent.").pack(side="left")
    else:
        provs = das.providers_for(edition)
        if which == "hr":
            provs = [p for p in provs if p[0] in das.HR_RUNNERS]
        try:
            import desk_agent_store
            cur = das.effective_provider(desk_agent_store.sync_shared(None), edition)
        except Exception:  # noqa: BLE001
            cur = "chat_only"
        pv = tk.StringVar(value=_label_for(provs, cur) if any(p[0] == cur for p in provs) else "")
        ttk.Label(row, text="Which AI runs it", font=small).pack(side="left")
        combo = calm(ttk.Combobox(row, textvariable=pv, state="readonly", width=60, values=[lab for _, lab in provs]))
        combo.pack(side="left", padx=(8, 4))
        _tooltip(combo, das.HR_RUNNER_HELP if which == "hr" else
                 "One AI runs every agent. Keys go in "
                 + "🔑 Agent API Key at the top of the Small Business tab.")

        runner = {"saved": cur}

        def save_runner(quiet=False):
            code = {lab: k for k, lab in provs}.get(pv.get())
            if quiet and (not code or code == runner["saved"]):
                return
            if not code:
                messagebox.showerror("Agent", "Choose which AI runs it first.")
                return
            ok, msg = save_shared_runner(code, edition)
            if ok:
                runner["saved"] = code
            if not quiet:
                (messagebox.showinfo if ok else messagebox.showerror)("Agent", msg)

        ttk.Button(row, text="💾 Save", command=save_runner).pack(side="left")

        def _runner_view():
            code = das.effective_provider(desk_agent_store.sync_shared(None), edition)
            return {"runner": _label_for(provs, code) if any(p[0] == code for p in provs) else pv.get()}

        def _runner_synced(shown):
            runner["saved"] = {lab: k for k, lab in provs}.get(shown["runner"], runner["saved"])

        live_sync(row, {"runner": pv}, _runner_view, _runner_synced)
        autosave(row, {"runner": pv}, lambda: save_runner(quiet=True))

    modes = [(m, das.STAGE_MODE_LABELS[m]) for m in das.STAGE_MODES]
    scale = flow_scale(content)
    try:
        if which == "hr":
            out["vars"] = build_hr_section(content, modes, edition, scale, on_saved=refresh)
        else:
            out["vars"] = build_jobs_section(content, modes, edition, scale, on_saved=refresh)
    except Exception as e:  # noqa: BLE001 — never takes the Small Business tab down
        ttk.Label(content, text=f"Agent settings unavailable: {e}", font=small, foreground="gray").pack(anchor="w")

    def apply(*_):
        if show.get():
            content.pack(fill="x")
        else:
            content.pack_forget()
        _save_section_shown(which, show.get())

    show.trace_add("write", apply)
    apply()
    lf.bind("<Map>", refresh, add="+")
    refresh()
    out.update(show=show, content=content, refresh=refresh)
    return out


def _build_booking_section(outer, v, modes, current_form, do_save, edition, scale):
    """📅 Booking & scheduling (booking-agent-spec.md; David 2026-10-30): the same assistant's
    booking stages, its own on/off and practice switch, "Let the agent confirm bookings", and
    the booking-flow diagram — the same picture as the app's."""
    import tkinter as tk
    from tkinter import ttk
    small = ("Arial", 8)
    mode_tip = "\n\n".join(das.MODE_HELP.values())
    box = ttk.LabelFrame(outer, text="📅 Booking & scheduling  (hover for details)", padding=(6, 4))
    box.pack(fill="x", pady=(10, 0))
    ttk.Label(box, font=small, foreground="gray", wraplength=900, justify="left",
              text=("The same assistant, working your bookings and schedule: checks new bookings, recommends what "
                    "to do in 📅 To approve, offers times, answers customers about their visit and keeps the week on "
                    "track. Your booking rules stay in charge — it never books outside your open times or "
                    "double-books.")).pack(anchor="w", pady=(0, 4))
    cols = ttk.Frame(box); cols.pack(fill="x")
    left = ttk.Frame(cols); left.grid(row=0, column=0, sticky="nw")
    right = ttk.Frame(cols); right.grid(row=0, column=1, sticky="nw", padx=(16, 0))
    row = ttk.Frame(left); row.pack(fill="x")
    ttk.Checkbutton(row, text="Booking & scheduling on", variable=v["agent_bk_enabled"]).pack(side="left")
    cb = ttk.Checkbutton(row, text="Practice mode for bookings", variable=v["agent_bk_shadow"])
    cb.pack(side="left", padx=(12, 0)); _tooltip(cb, das.BK_PRACTICE_HELP)
    stages = ttk.LabelFrame(left, text="What it does", padding=(6, 4))
    stages.pack(fill="x", pady=(6, 0))
    for i, (k, lab) in enumerate(das.BK_STAGES):
        lbl = ttk.Label(stages, text=lab, font=small); lbl.grid(row=i, column=0, sticky="w")
        _tooltip(lbl, das.BK_STAGE_HELP[k])
        combo = calm(ttk.Combobox(stages, textvariable=v[f"agent_bk_stage_{k}"], state="readonly", width=28,
                                  values=[lab2 for _, lab2 in modes]))
        combo.grid(row=i, column=1, sticky="w", padx=(8, 0)); _tooltip(combo, mode_tip)
    row = ttk.Frame(left); row.pack(fill="x", pady=(6, 0))
    cb = ttk.Checkbutton(row, text="Let the agent confirm bookings", variable=v["agent_bk_can_confirm"])
    cb.pack(side="left"); _tooltip(cb, das.BK_CONFIRM_HELP)
    w = ttk.Label(row, text="at most", font=small); w.pack(side="left", padx=(8, 4)); _tooltip(w, das.BK_CONFIRM_HELP)
    ttk.Spinbox(row, textvariable=v["agent_bk_confirm_per_day"], from_=1, to=50, width=4).pack(side="left")
    ttk.Label(row, text="a day", font=small).pack(side="left", padx=(4, 0))
    row = ttk.Frame(left); row.pack(fill="x", pady=(2, 0))
    cb = ttk.Checkbutton(row, text="Check the weather for outdoor services", variable=v["agent_bk_weather"])
    cb.pack(side="left"); _tooltip(cb, das.BK_WEATHER_HELP)
    ttk.Label(row, text="Check tomorrow's visits at hour", font=small).pack(side="left", padx=(10, 4))
    ttk.Spinbox(row, textvariable=v["agent_bk_check_hour"], from_=0, to=23, width=3).pack(side="left")
    ttk.Button(left, text="💾 Save booking settings", command=do_save).pack(anchor="w", pady=(6, 0))

    ttk.Label(right, text="How a booking moves — the top and bottom boxes are the agent's steps (hover for details)",
              font=small, foreground="gray").pack(anchor="w")
    canvas = tk.Canvas(right, width=round((das.FLOW_W + 2 * PAD) * scale), height=round((das.FLOW_H + 2 * PAD) * scale),
                       background="white", highlightthickness=1, highlightbackground="#e5e7eb")
    canvas.pack(anchor="w")
    summary = tk.StringVar()
    ttk.Label(right, textvariable=summary, wraplength=round((das.FLOW_W + 2 * PAD) * scale), justify="left",
              font=("Arial", 9)).pack(anchor="w", pady=(4, 0))
    tips: dict = {}

    def redraw(*_):
        f = current_form()
        model = das.booking_flow({**f, **{k: bool(f[k]) for k in ("agent_enabled", "agent_bk_enabled",
                                                                  "agent_bk_shadow", "agent_bk_can_confirm")}},
                                 edition)
        draw_flow(canvas, model, tips, scale)
        summary.set(model["summary"])

    _hover_canvas(canvas, tips)
    for k in ("agent_enabled", "agent_bk_enabled", "agent_bk_shadow", "agent_bk_can_confirm") + tuple(
            f"agent_bk_stage_{k}" for k, _ in das.BK_STAGES):
        v[k].trace_add("write", redraw)
    redraw()
