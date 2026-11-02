"""
task_queue_gui.py — the 🧠 AI Analysis Tasks section of the Links & Analysis tab (2026-11-01).

David: "get rid of the task queue and make every task have its own schedule." There is no queue any more.
Every task carries its own schedule (and time of day), an ⏱ Auto-run switch and an optional AI of its own.
With Auto-run on, AI-Prowler runs the task itself when it's due — one AI call per task, on the Agent API
Key (🔑 Agent API Key at the top of the Small Business tab), counted in the agents' monthly budget. Tasks
with Auto-run off are run from a chat (📋 Copy for chat, or "run my due analysis tasks").

This module replaces three old panels: Common Business AI Analysis (now starter buttons that open a
pre-filled task), Show Queue, and the Autonomous AI Task Queue (now the "Automatic runs" bar on top).
build_section() is testable without the rest of the app.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox as _mb, ttk

import custom_tasks_manager as ctm
import task_queue_automation as tqa

BG = "#1a2530"
ROW_BG = "#0d1a26"
FG = "#ffffff"
DIM = "#a0b4c8"
INTRO = ("Each task runs on its own schedule. With ⏱ Auto-run on, AI-Prowler runs it itself when it's due — "
         "one AI call per task, on your Agent API Key (🔑 Agent API Key at the top of the Small Business tab), "
         "a few cents a run, counted in the agents' monthly budget. Tasks with Auto-run off run from a chat: "
         "📋 Copy for chat, or ask Claude, Muse or Grok to \"run my due analysis tasks\". Claude, Muse or Grok "
         "can also create and change these tasks from a chat.")
AI_CHOICES = (("", "Default AI"), ("claude", "Claude"), ("grok", "Grok"))
_RUNNERS = {"claude": "claude_api", "grok": "grok_api"}


# ── text helpers (no Tk) ───────────────────────────────────────────────────────────────

def key_line(cfg: dict) -> tuple:
    """(text, ok) for the default AI's key / model."""
    try:
        import desk_agent_providers as prov
        name = tqa.PROVIDER_LABELS[cfg.get("provider", "claude")]
        if not tqa.has_key(cfg):
            return (f"⚠ No {name} API key saved — add it in 🔑 Agent API Key at the top of the Small Business "
                    f"tab", False)
        model = tqa.model_for(cfg)
        labels = dict(prov.AGENT_MODELS.get(tqa.runner(cfg), ()))
        shown = labels.get(model, model).split(" — ")[0]
        extra = " (the agents' complex & customer model)" if tqa.runner(cfg) == "claude_api" else ""
        return f"🔑 {name} key saved — tasks run on {shown}{extra} unless a task picks its own AI", True
    except Exception as e:  # noqa: BLE001
        return f"⚠ Key status unknown: {e}", False


def budget_line() -> str:
    try:
        import desk_agent_budget as ab
        return "💵 Shared budget — " + ab.current("solo")["text"]
    except Exception:  # noqa: BLE001
        return "💵 Shared monthly budget: set it in 🔑 Agent API Key → Monthly budget"


def last_run_line() -> str:
    last = tqa.load_last_run()
    if not last:
        return "Last run: (none yet)"
    cost = last.get("cost_usd")
    c = f" · ${cost:.4f}" if isinstance(cost, (int, float)) and cost else ""
    return f"Last run: {last.get('status', '?')} — {last.get('detail', '')}{c} ({str(last.get('timestamp', ''))[:19]})"


def chat_prompt(task: dict) -> str:
    """What 📋 Copy for chat puts on the clipboard: run this one task in a chat and record it."""
    tid = task.get("task_id", "")
    return (f"Run my AI-Prowler analysis task \"{task.get('label', '')}\" (task_id {tid}) now, using "
            f"AI-Prowler's tools. When you're done, call complete_analysis_task(task_id=\"{tid}\", summary=...) "
            f"with a short summary so AI-Prowler records the run.\n\n" + ctm.build_task_prompt(task))


def starter_task_fields(starter: dict) -> dict:
    """A Common Business starter → the fields the editor opens with (a new task, nothing saved yet)."""
    label = starter.get("label", "")
    return {"label": label[:60], "prompt": starter.get("prompt", ""), "schedule": "none",
            "output_learnings": True, "auto_run": True}


def tracked_dirs() -> list:
    try:
        p = Path.home() / ".rag_auto_update_dirs.json"
        raw = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
        items = raw.get("directories", []) if isinstance(raw, dict) else raw
        return [k for k in items if isinstance(k, str)
                and (os.path.isabs(k) or k.startswith("\\\\") or k.startswith("//"))]
    except Exception:  # noqa: BLE001
        return []


def models_for(provider: str) -> list:
    """[(model_id, friendly name)] — e.g. ('claude-sonnet-5-5', 'Claude Sonnet 5.5'). The id is the API's own
    name (Anthropic writes versions with dashes: claude-sonnet-5-5); people see the friendly name."""
    try:
        import desk_agent_providers as prov
        return [(m, lab.split(" — ")[0]) for m, lab in prov.AGENT_MODELS[_RUNNERS[provider]]]
    except Exception:  # noqa: BLE001
        return []


DEFAULT_MODEL_LABEL = "(that AI's default)"


def bind_wheel(win, canvas):
    """Mouse-wheel scrolling anywhere in a scrollable popup (2026-11-01, David: "the scroll mouse control does
    not always work"). Every widget inside gets the binding — Tk only sends the wheel to the widget under the
    mouse. A list box or the prompt box keeps its own scrolling; over a drop-down the page scrolls instead of
    the drop-down's value silently changing."""
    def wheel(e):
        try:
            canvas.yview_scroll(int(-1 * (e.delta / 120)) or (-1 if e.delta > 0 else 1), "units")
        except tk.TclError:
            pass
        return "break"

    def walk(w):
        if not isinstance(w, (tk.Text, tk.Listbox)):
            w.bind("<MouseWheel>", wheel)
        for c in w.winfo_children():
            walk(c)
    walk(win)
    return wheel


# ── the section ─────────────────────────────────────────────────────────────────────────

SERVER_INTRO = ("Each task runs on its own schedule, run by the AI-Prowler Server program itself when it's due — "
                "one AI call per task, on the Agent API Key (🔑 Agent API Key at the top of the Small Business tab), "
                "a few cents a run, counted in the agents' monthly budget. For the owner and managers: tasks made "
                "here belong to the owner; a manager can make their own from a chat, and each task only sees what "
                "its owner can see (HR included for the owner).")


def build_section(parent, root=None, messagebox=None, run_fn=None, legacy_check_fn=None, legacy_remove_fn=None,
                  status_fn=None, clipboard_fn=None, dirs_fn=None, starters=None, server=False) -> dict:
    """Build the section in parent. Returns {'banner': frame, ...vars and functions for tests}.
    run_fn(task_id) -> (ok, detail) runs one task (default: tqa.run_task, in a background thread)."""
    mb = messagebox or _mb
    root = root or parent.winfo_toplevel()
    run_fn = run_fn or (lambda tid: tqa.run_task(tid, "manual"))
    legacy_check_fn = legacy_check_fn or tqa.legacy_task_present
    legacy_remove_fn = legacy_remove_fn or tqa.remove_legacy_task_elevated
    status_fn = status_fn or (lambda text: None)
    dirs_fn = dirs_fn or tracked_dirs
    starters = STARTERS if starters is None else starters

    def clip(text):
        if clipboard_fn:
            clipboard_fn(text)
            return
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

    cfg = tqa.load_config()
    p: dict = {"cfg": cfg}
    banner = tk.Frame(parent, bg=BG, highlightthickness=1, highlightbackground="#2e4a62")
    banner.pack(fill="x", padx=20, pady=(0, 8))
    inner = tk.Frame(banner, bg=BG)
    inner.pack(fill="x", padx=14, pady=10)
    p["banner"] = banner

    hdr = tk.Frame(inner, bg=BG)
    hdr.pack(fill="x", pady=(0, 4))
    tk.Label(hdr, text="🧠  AI Analysis Tasks", bg=BG, fg=FG, font=("Arial", 11, "bold")).pack(side="left")
    count_var = tk.StringVar(value=f"0 / {ctm.MAX_CUSTOM_TASKS}")
    tk.Label(hdr, textvariable=count_var, bg=BG, fg="#6a8aa2", font=("Arial", 8)).pack(side="right")
    # 2026-11-02 (David): on a server every task is run by the server itself — no chat runner there.
    tk.Label(inner, text=SERVER_INTRO if server else INTRO, bg=BG, fg=DIM, font=("Arial", 8), wraplength=700,
             justify="left").pack(
        anchor="w", pady=(0, 6))

    # ── Automatic runs bar ──
    bar = tk.Frame(inner, bg="#14202b", highlightthickness=1, highlightbackground="#2e4a62")
    bar.pack(fill="x", pady=(0, 8))
    bi = tk.Frame(bar, bg="#14202b")
    bi.pack(fill="x", padx=10, pady=8)
    BB = "#14202b"
    r1 = tk.Frame(bi, bg=BB)
    r1.pack(fill="x")
    btn_toggle = tk.Button(r1, font=("Arial", 9, "bold"), relief="raised", bd=2, padx=10, pady=4, cursor="hand2")
    btn_toggle.pack(side="left", padx=(0, 10))
    tk.Label(r1, text="Default AI:", bg=BB, fg=DIM, font=("Arial", 9)).pack(side="left")
    provider_var = tk.StringVar(value=cfg.get("provider", "claude"))
    for val, lab in (("claude", "Claude"), ("grok", "Grok")):
        tk.Radiobutton(r1, text=lab, variable=provider_var, value=val, bg=BB, fg=FG, selectcolor=BB,
                       activebackground=BB, font=("Arial", 9)).pack(side="left", padx=(4, 0))
    key_var = tk.StringVar()
    key_lbl = tk.Label(bi, textvariable=key_var, bg=BB, fg="#6ab86a", font=("Arial", 8), anchor="w",
                       wraplength=680, justify="left")
    key_lbl.pack(fill="x", pady=(2, 2))
    r2 = tk.Frame(bi, bg=BB)
    r2.pack(fill="x")
    notify_var = tk.BooleanVar(value=bool(cfg.get("notify_on_complete")))
    method_var = tk.StringVar(value=cfg.get("notify_method", "sms"))
    tk.Checkbutton(r2, text="Text me when a run finishes", variable=notify_var, bg=BB, fg=FG, selectcolor=BB,
                   activebackground=BB, font=("Arial", 8)).pack(side="left")
    ttk.Combobox(r2, textvariable=method_var, values=["sms", "whatsapp"], width=9, state="readonly").pack(
        side="left", padx=(4, 0))
    web_var = tk.BooleanVar(value=bool(cfg.get("web_search", True)))
    tk.Checkbutton(r2, text="Claude may search the web (1¢ per search)", variable=web_var, bg=BB, fg=FG,
                   selectcolor=BB, activebackground=BB, font=("Arial", 8)).pack(side="left", padx=(10, 0))
    sched_var, budget_var, last_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
    sched_lbl = tk.Label(bi, textvariable=sched_var, bg=BB, fg="#6ab86a", font=("Arial", 9), anchor="w",
                         wraplength=680, justify="left")
    sched_lbl.pack(fill="x", pady=(4, 0))
    tk.Label(bi, textvariable=budget_var, bg=BB, fg=DIM, font=("Arial", 8), anchor="w", wraplength=680,
             justify="left").pack(fill="x")
    tk.Label(bi, textvariable=last_var, bg=BB, fg="#8899bb", font=("Arial", 8), anchor="w", wraplength=680,
             justify="left").pack(fill="x")
    legacy_row = tk.Frame(bi, bg=BB)
    tk.Label(legacy_row, text="⚠ The old Windows task \"AI-Prowler-QueueRunner\" from the CLI version is still on "
                              "this PC. It does nothing now, but you can remove it (Windows asks for admin rights "
                              "once).", bg=BB, fg="#e0c060", font=("Arial", 8), wraplength=520,
             justify="left").pack(side="left")
    r3 = tk.Frame(bi, bg=BB)
    r3.pack(fill="x", pady=(4, 0))

    def settings() -> dict:
        c = dict(tqa.load_config())
        c.update(provider=provider_var.get(), notify_on_complete=bool(notify_var.get()),
                 notify_method=method_var.get(), web_search=bool(web_var.get()))
        return c

    def save_settings(*_a):
        c = settings()
        tqa.save_config(c)
        cfg.clear()
        cfg.update(c)
        refresh_status()

    def refresh_status():
        c = tqa.load_config()
        cfg.clear()
        cfg.update(c)
        t, ok = key_line(c)
        key_var.set(t)
        key_lbl.config(fg="#6ab86a" if ok else "#cc8800")
        d = tqa.schedule_display(c)
        why = tqa.why_not_ready(c) if d["on"] else ""
        sched_var.set(d["display"] + (f" — but nothing can run yet: {why}" if why else ""))
        sched_lbl.config(fg="#cc8800" if why else ("#6ab86a" if d["on"] else "#aa4444"))
        budget_var.set(budget_line())
        last_var.set(last_run_line())
        paused = bool(c.get("paused"))
        btn_toggle.config(text="⏸ Automatic runs PAUSED — click to resume" if paused
                          else "🟢 Automatic runs ON — click to pause",
                          bg="#7a1f1f" if paused else "#1f7a3d", fg=FG,
                          activebackground="#7a1f1f" if paused else "#1f7a3d", activeforeground=FG)

    def toggle():
        c = settings()
        c["paused"] = not bool(tqa.load_config().get("paused"))
        tqa.save_config(c)
        if not c["paused"]:
            why = tqa.why_not_ready(c)
            if why:
                mb.showwarning("AI Analysis Tasks", f"Automatic runs are on, but nothing can run yet: {why}")
        refresh_status()

    btn_toggle.config(command=toggle)

    def view_log():
        win = tk.Toplevel(root)
        win.title("AI Analysis Tasks — run log")
        txt = tk.Text(win, width=110, height=32, font=("Consolas", 9))
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", tqa.read_audit_log_tail(300))
        txt.config(state="disabled")

    def clear_log():
        # 2026-11-02 (David): asks first, and empties the backups (.log.1 / .log.2) too — it used to
        # clear only the current file, without asking. The log also limits its own size now
        # (tqa.AUDIT_LOG_MAX_BYTES), so clearing is never needed just to save space.
        if not mb.askyesno("Clear log", "Empty the AI Analysis Tasks run log?\n\nYour tasks, their "
                                        "schedules and results aren't changed — only the history of "
                                        "what ran.", parent=root):
            return False
        ok = tqa.clear_audit_log()
        if not ok:
            mb.showerror("AI Analysis Tasks", "Couldn't clear the run log (is it open in another program?).")
        return ok

    def remove_legacy():
        ok, detail = legacy_remove_fn()
        if ok:
            legacy_row.pack_forget()
            mb.showinfo("AI Analysis Tasks", "The old Windows task was removed.")
        else:
            mb.showerror("AI Analysis Tasks", f"Couldn't remove the old Windows task: {detail}")
    ttk.Button(legacy_row, text="Remove old Windows task", command=remove_legacy).pack(side="left", padx=(8, 0))
    ttk.Button(r3, text="📄 Run log", command=view_log).pack(side="left")
    ttk.Button(r3, text="🗑 Clear log", command=clear_log).pack(side="left", padx=(4, 0))
    for v in (provider_var, notify_var, method_var, web_var):
        v.trace_add("write", save_settings)

    # ── starters ──
    if starters:
        tk.Label(inner, text="Start a task from a common business analysis (opens the task editor — nothing runs "
                             "until you save it):", bg=BG, fg=DIM, font=("Arial", 8), anchor="w").pack(
            fill="x", pady=(0, 2))
        grid = tk.Frame(inner, bg=BG)
        grid.pack(fill="x", pady=(0, 8))
        for i, s in enumerate(starters):
            b = tk.Button(grid, text=s.get("label", "?"), bg=s.get("color", "#1a5276"), fg=FG,
                          activebackground=s.get("hover", "#21618c"), activeforeground=FG, relief="flat",
                          font=("Arial", 8, "bold"), cursor="hand2", padx=6, pady=4,
                          command=lambda s=s: open_starter(s))
            b.grid(row=i // 3, column=i % 3, sticky="ew", padx=2, pady=2)
        for c in range(3):
            grid.columnconfigure(c, weight=1)

    # ── the tasks ──
    list_frame = tk.Frame(inner, bg=BG)
    list_frame.pack(fill="x")
    running: dict = {}

    def refresh_list():
        for w in list_frame.winfo_children():
            w.destroy()
        try:
            tasks = ctm.load_custom_tasks()
        except Exception as e:  # noqa: BLE001
            tk.Label(list_frame, text=f"Error loading tasks: {e}", bg=BG, fg="#cc4444", font=("Arial", 8)).pack(
                anchor="w")
            return
        count_var.set(f"{len(tasks)} / {ctm.MAX_CUSTOM_TASKS}")
        if not tasks:
            tk.Label(list_frame, text="No tasks yet — click a starter above or '+ New Task'.", bg=BG,
                     fg="#6a8aa2", font=("Arial", 8)).pack(anchor="w", pady=4)
        for t in tasks:
            draw_row(t)

    def draw_row(t):
        tid = t.get("task_id")
        row = tk.Frame(list_frame, bg=ROW_BG, highlightthickness=1, highlightbackground="#1e3a52")
        row.pack(fill="x", pady=2)
        info = tk.Frame(row, bg=ROW_BG)
        info.pack(side="left", fill="both", expand=True, padx=6, pady=4)
        top = tk.Frame(info, bg=ROW_BG)
        top.pack(anchor="w")
        tk.Label(top, text=t.get("label", "Unnamed"), bg=ROW_BG, fg="#d0e8ff", font=("Arial", 9, "bold")).pack(
            side="left")
        sched = t.get("schedule", "none")
        badge = ctm.SCHEDULE_LABELS.get(sched, sched)
        if sched in ctm.DOW_ELIGIBLE_SCHEDULES:
            dow = t.get("schedule_day_of_week")
            badge += (f" · {ctm.DOW_NAMES[dow][:3]}" if isinstance(dow, int) else "") + \
                f" · {t.get('run_time') or ctm.DEFAULT_RUN_TIME}"
        whose = f"  ·  {t['owner_name']}'s" if server and t.get("owner_name") else ""   # server: a manager's task
        tk.Label(top, text=f"  {badge}  ·  {ctm.ai_label(t)}{whose}", bg=ROW_BG, fg="#4a8fa8",
                 font=("Arial", 7)).pack(side="left")
        try:
            status = ctm.due_status_label(t)
        except Exception:  # noqa: BLE001
            status = ""
        if t.get("run_requested"):
            status = "▶ Run requested — " + ("AI-Prowler runs it next" if t.get("requested_by") == ctm.BY_AI_PROWLER
                                             else "a chat runs it")
        if (t.get("last_skip") or {}).get("why"):
            status += f"  (waiting: {t['last_skip']['why']})"
        if status and status != "Manual only":
            tk.Label(info, text=status, bg=ROW_BG, fg="#cc8800" if "waiting" in status else "#6a9fbf",
                     font=("Arial", 7), wraplength=520, justify="left").pack(anchor="w")
        tk.Label(info, text=ctm.last_run_text(t), bg=ROW_BG, fg="#5a7a6a", font=("Arial", 7)).pack(anchor="w")

        btns = tk.Frame(row, bg=ROW_BG)
        btns.pack(side="right", padx=4, pady=4)
        auto_var = tk.BooleanVar(value=bool(t.get("auto_run")))

        def set_auto(v=auto_var, i=tid):
            tasks = ctm.load_custom_tasks()
            try:
                ctm.update_task(tasks, i, auto_run=bool(v.get()))
                ctm.save_custom_tasks(tasks)
            except ValueError as e:
                mb.showwarning("AI Analysis Tasks", str(e))
            refresh_all()
        cb = tk.Checkbutton(btns, text="⏱ Auto-run", variable=auto_var, command=set_auto, bg=ROW_BG, fg=FG,
                            selectcolor=ROW_BG, activebackground=ROW_BG, font=("Arial", 7))
        if sched == "none" or server:          # server: always auto-run (no chat runner there)
            cb.config(state="disabled")
        cb.pack(anchor="w")
        bline = tk.Frame(btns, bg=ROW_BG)
        bline.pack()
        rb = tk.Button(bline, text="⏳ Running…" if tid in running else "▶ Run now", bg="#1a3a5a", fg=FG,
                       font=("Arial", 7, "bold"), relief="flat", cursor="hand2",
                       command=lambda i=tid: run_now(i))
        if tid in running:
            rb.config(state="disabled")
        rb.pack(side="left", padx=1)
        if not server:
            tk.Button(bline, text="📋 Copy for chat", bg="#1a2a3a", fg="#aaccee", font=("Arial", 7), relief="flat",
                      cursor="hand2", command=lambda i=tid: copy_for_chat(i)).pack(side="left", padx=1)
        tk.Button(bline, text="✎ Edit", bg="#1a2a1a", fg="#88cc88", font=("Arial", 7), relief="flat",
                  cursor="hand2", command=lambda i=tid: edit(i)).pack(side="left", padx=1)
        tk.Button(bline, text="🗑", bg="#2a1a1a", fg="#cc4444", font=("Arial", 7), relief="flat", cursor="hand2",
                  command=lambda i=tid: delete(i)).pack(side="left", padx=1)

    def open_starter(s):
        """2026-11-01 (David: "I changed my output to email and saved it, and it did not save when I reopened
        it"): a starter you already saved opens YOUR task (with your settings), not a fresh copy."""
        mine = next((t for t in ctm.load_custom_tasks() if t.get("label") == s.get("label", "")[:60]), None)
        return open_editor(mine or starter_task_fields(s))

    def copy_for_chat(tid):
        t = ctm.get_task(ctm.load_custom_tasks(), tid)
        if not t:
            return
        clip(chat_prompt(t))
        status_fn(f"📋 '{t.get('label')}' copied — paste it into Claude, Muse or Grok to run it there")

    def edit(tid):
        t = ctm.get_task(ctm.load_custom_tasks(), tid)
        if t:
            open_editor(t)

    def delete(tid):
        tasks = ctm.load_custom_tasks()
        t = ctm.get_task(tasks, tid)
        if not t or not mb.askyesno("Delete Task", f"Delete '{t.get('label')}'?\nThis cannot be undone."):
            return
        ctm.delete_task(tasks, tid)
        ctm.save_custom_tasks(tasks)
        refresh_all()

    results: list = []

    def run_now(tid):
        t = ctm.get_task(ctm.load_custom_tasks(), tid)
        if not t or tid in running:
            return
        why = tqa.why_not_ready(tqa.load_config(), t)
        if why:
            if server:                          # no chat runner on a server (2026-11-02)
                mb.showwarning("AI Analysis Tasks", f"It can't run yet: {why}.")
            elif mb.askyesno("AI Analysis Tasks", f"It can't run here yet: {why}.\n\nCopy it to run in a chat "
                                                  f"(Claude, Muse or Grok) instead?"):
                copy_for_chat(tid)
            return
        running[tid] = True
        refresh_list()

        def work():
            try:
                results.append((tid, *run_fn(tid)))
            except Exception as e:  # noqa: BLE001
                results.append((tid, False, str(e)))
        threading.Thread(target=work, name="analysis-task-run-now", daemon=True).start()
        root.after(200, poll_results)

    def poll_results():
        if not results:
            if running:
                root.after(500, poll_results)
            return
        tid, ok, detail = results.pop(0)
        running.pop(tid, None)
        refresh_all()
        (mb.showinfo if ok else mb.showerror)("AI Analysis Tasks", str(detail)[-3000:])
        if running or results:
            root.after(500, poll_results)

    # ── the editor ──
    def open_editor(task=None):
        """task: an existing task (has task_id) to edit, or a dict of starting fields for a new one."""
        existing = task if task and task.get("task_id") else None
        t = task or {}
        win = tk.Toplevel(root)
        win.title("Edit Analysis Task" if existing else "New Analysis Task")
        win.geometry("780x860")
        try:
            win.grab_set()
        except tk.TclError:
            pass
        canvas = tk.Canvas(win, highlightthickness=0)
        vsb = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=vsb.set)
        pad = tk.Frame(canvas, padx=16, pady=12)
        pid = canvas.create_window((0, 0), window=pad, anchor="nw", width=760)
        # 2026-11-01 fix (David: "the popup renders blank until you drag the scroll bar"): the content's width
        # used to be set from canvas.winfo_width() while the window wasn't drawn yet — 1 pixel — so everything
        # was squeezed to nothing until a scroll redrew it. The width now follows the canvas's own size.
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(pid, width=e.width))
        pad.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        def lbl(text, hint=None):
            tk.Label(pad, text=text, font=("Arial", 9, "bold"), anchor="w").pack(anchor="w")
            if hint:
                tk.Label(pad, text=hint, font=("Arial", 8), fg="gray", anchor="w", wraplength=720,
                         justify="left").pack(anchor="w")

        lbl("Name:")
        name_var = tk.StringVar(value=t.get("label", ""))
        ttk.Entry(pad, textvariable=name_var, width=60).pack(fill="x", pady=(2, 8))
        lbl("What should the AI do?", "Describe the analysis and what to report — be as specific as you like.")
        prompt_box = tk.Text(pad, height=8, width=60, wrap="word", font=("Arial", 9))
        prompt_box.insert("1.0", t.get("prompt", ""))
        prompt_box.pack(fill="x", pady=(2, 8))

        lbl("Scope (optional):", "Tick folders to focus on. Leave all unticked to search everything.")
        scope_box = tk.Frame(pad, bd=1, relief="sunken")
        scope_box.pack(fill="x", pady=(2, 8))
        scope_vars = {}
        dirs = dirs_fn()
        for d in dirs[:40]:
            scope_vars[d] = tk.BooleanVar(value=d in (t.get("scope_dirs") or []))
            ttk.Checkbutton(scope_box, text=d, variable=scope_vars[d]).pack(anchor="w", padx=4)
        if not dirs:
            tk.Label(scope_box, text="No indexed folders yet.", fg="gray", font=("Arial", 8)).pack(padx=4, pady=2)

        # schedule
        srow = tk.Frame(pad)
        srow.pack(fill="x", pady=(0, 4))
        tk.Label(srow, text="Schedule:", font=("Arial", 9, "bold")).pack(side="left")
        label_to_key = {v: k for k, v in ctm.SCHEDULE_LABELS.items()}
        sched_var = tk.StringVar(value=ctm.SCHEDULE_LABELS.get(t.get("schedule", "none"), "Manual only"))
        sched_combo = ttk.Combobox(srow, textvariable=sched_var, values=list(ctm.SCHEDULE_LABELS.values()),
                                   state="readonly", width=14)
        sched_combo.pack(side="left", padx=(6, 14))
        tk.Label(srow, text="Starting:", font=("Arial", 9, "bold")).pack(side="left")
        first = t.get("first_due") or (str(t.get("next_due") or "")[:10]) or \
            (_dt.date.today() + _dt.timedelta(days=1)).isoformat()
        due_var = tk.StringVar(value=first)
        ttk.Entry(srow, textvariable=due_var, width=11).pack(side="left", padx=(4, 2))
        tk.Label(srow, text="YYYY-MM-DD", font=("Arial", 7), fg="gray").pack(side="left")

        time_row = tk.Frame(pad)
        tk.Label(time_row, text="Time of day:", font=("Arial", 9, "bold")).pack(side="left")
        run_time_var = tk.StringVar(value=t.get("run_time") or ctm.DEFAULT_RUN_TIME)
        ttk.Entry(time_row, textvariable=run_time_var, width=6).pack(side="left", padx=(4, 14))
        tk.Label(time_row, text="Day:", font=("Arial", 9, "bold")).pack(side="left")
        dow = t.get("schedule_day_of_week")
        dow_var = tk.StringVar(value=ctm.DOW_LABELS[dow + 1] if isinstance(dow, int) else ctm.DOW_LABELS[0])
        ttk.Combobox(time_row, textvariable=dow_var, values=ctm.DOW_LABELS, state="readonly", width=11).pack(
            side="left", padx=(4, 0))

        daily_row = tk.Frame(pad)
        start_var = tk.StringVar(value=t.get("daily_start_time", "09:00"))
        end_var = tk.StringVar(value=t.get("daily_end_time", "17:00"))
        times_var = tk.StringVar(value=str(t.get("daily_times_per_day", 1)))
        for text, var, w in (("Start time:", start_var, 6), ("End time:", end_var, 6), ("Times per day:", times_var, 4)):
            tk.Label(daily_row, text=text, font=("Arial", 9, "bold")).pack(side="left", padx=(0, 2))
            ttk.Entry(daily_row, textvariable=var, width=w).pack(side="left", padx=(0, 12))
        preview_var = tk.StringVar()
        preview_lbl = tk.Label(pad, textvariable=preview_var, font=("Arial", 8), fg="#5a7a9a")

        def upd_preview(*_a):
            try:
                preview_var.set(ctm.format_daily_run_times_preview(start_var.get().strip(), end_var.get().strip(),
                                                                   times_var.get().strip() or "1"))
            except Exception:  # noqa: BLE001
                preview_var.set("")
        for v in (start_var, end_var, times_var):
            v.trace_add("write", upd_preview)
        upd_preview()

        auto_var = tk.BooleanVar(value=True if server else bool(t.get("auto_run", True)))
        auto_cb = ttk.Checkbutton(pad, text="⏱ Auto-run — AI-Prowler runs it when it's due, on the Agent API Key "
                                            "(a few cents a run)", variable=auto_var)
        if server:                              # a server always runs its tasks itself (2026-11-02)
            auto_cb.state(["disabled"])

        def show_sched_fields(*_a):
            k = label_to_key.get(sched_var.get(), "none")
            for w in (time_row, daily_row, preview_lbl, auto_cb):
                w.pack_forget()
            if k == "daily":
                daily_row.pack(fill="x", pady=(0, 2), after=srow)
                preview_lbl.pack(anchor="w", after=daily_row)
                auto_cb.pack(anchor="w", pady=(2, 8), after=preview_lbl)
            elif k != "none":
                time_row.pack(fill="x", pady=(0, 2), after=srow)
                auto_cb.pack(anchor="w", pady=(2, 8), after=time_row)
        sched_combo.bind("<<ComboboxSelected>>", show_sched_fields, add="+")
        sched_var.trace_add("write", show_sched_fields)

        # which AI
        arow = tk.Frame(pad)
        arow.pack(fill="x", pady=(4, 8))
        tk.Label(arow, text="AI:", font=("Arial", 9, "bold")).pack(side="left")
        ai_labels = [lab for _, lab in AI_CHOICES]
        ai_key = {lab: k for k, lab in AI_CHOICES}
        ai_var = tk.StringVar(value=dict(AI_CHOICES).get(t.get("ai_provider") or "", "Default AI"))
        ttk.Combobox(arow, textvariable=ai_var, values=ai_labels, state="readonly", width=11).pack(side="left",
                                                                                                    padx=(6, 10))
        tk.Label(arow, text="Model:", font=("Arial", 9)).pack(side="left")
        # 2026-11-01 (David: "the AI Model shows 5-5 instead of 5.5"): the list shows the friendly name
        # (Claude Sonnet 5.5); the task stores the API's own id (claude-sonnet-5-5 — the API writes the
        # version with a dash, so that id must stay as it is).
        model_names: dict = {}           # friendly name -> id, for the AI picked now

        def name_of(prov_key, mid):
            return next((lab for m, lab in models_for(prov_key) if m == mid), mid) if mid else DEFAULT_MODEL_LABEL
        model_var = tk.StringVar(value=name_of(t.get("ai_provider") or "", t.get("ai_model", "")))
        model_combo = ttk.Combobox(arow, textvariable=model_var, state="readonly", width=24)
        model_combo.pack(side="left", padx=(4, 0))

        def upd_models(*_a):
            prov_key = ai_key.get(ai_var.get(), "")
            pairs = models_for(prov_key) if prov_key else []
            model_names.clear()
            model_names.update({lab: m for m, lab in pairs})
            vals = [DEFAULT_MODEL_LABEL] + [lab for _, lab in pairs]
            model_combo.config(values=vals, state="readonly" if prov_key else "disabled")
            if model_var.get() not in vals:
                model_var.set(DEFAULT_MODEL_LABEL)
        ai_var.trace_add("write", upd_models)
        upd_models()
        tk.Label(pad, text="Default AI = the 'Default AI' in the Automatic runs bar, on the agents' complex & "
                           "customer model.", font=("Arial", 7), fg="gray",
                 anchor="w", wraplength=720, justify="left").pack(anchor="w", pady=(0, 8))

        lbl("Output:")
        learn_var = tk.BooleanVar(value=t.get("output_learnings", True))
        report_var = tk.BooleanVar(value=t.get("output_report", False))
        email_var = tk.BooleanVar(value=t.get("output_email", False))
        ttk.Checkbutton(pad, text="💡 Save key insights to Learnings", variable=learn_var).pack(anchor="w")
        ttk.Checkbutton(pad, text="📄 Save full analysis as a Word document (.docx)", variable=report_var).pack(
            anchor="w")
        ttk.Checkbutton(pad, text="✉️ Email the analysis", variable=email_var).pack(anchor="w")
        frow = tk.Frame(pad)
        frow.pack(fill="x", pady=(4, 8))
        tk.Label(frow, text="Report folder:", font=("Arial", 9, "bold")).pack(side="left")
        folder_var = tk.StringVar(value=t.get("report_folder") or ctm.DEFAULT_REPORT_FOLDER)
        ttk.Entry(frow, textvariable=folder_var, width=44).pack(side="left", padx=(6, 4))

        def browse():
            import tkinter.filedialog as fd
            d = fd.askdirectory(initialdir=folder_var.get() or str(Path.home()))
            if d:
                folder_var.set(d)
        ttk.Button(frow, text="Browse…", command=browse).pack(side="left")

        def fields() -> dict:
            k = label_to_key.get(sched_var.get(), "none")
            d = ctm.DOW_LABELS.index(dow_var.get()) - 1 if dow_var.get() in ctm.DOW_LABELS else -1
            try:
                n = int(times_var.get().strip() or 1)
            except ValueError:
                raise ValueError("Times per day must be a whole number (1-24).")
            prov_key = ai_key.get(ai_var.get(), "")
            return dict(label=name_var.get().strip(), prompt=prompt_box.get("1.0", "end-1c").strip(),
                        scope_dirs=[x for x, v in scope_vars.items() if v.get()], schedule=k,
                        first_due=(due_var.get().strip() or None) if k != "none" else None,
                        schedule_day_of_week=(d if d >= 0 else None) if k in ctm.DOW_ELIGIBLE_SCHEDULES else None,
                        daily_start_time=start_var.get().strip(), daily_end_time=end_var.get().strip(),
                        daily_times_per_day=n, run_time=run_time_var.get().strip() or ctm.DEFAULT_RUN_TIME,
                        auto_run=bool(auto_var.get()) and k != "none", ai_provider=prov_key,
                        ai_model=model_names.get(model_var.get(), "") if prov_key else "",
                        output_learnings=bool(learn_var.get()), output_report=bool(report_var.get()),
                        output_email=bool(email_var.get()), report_folder=folder_var.get().strip())

        def save(run_after=False):
            try:
                f = fields()
                tasks = ctm.load_custom_tasks()
                if existing:
                    ctm.update_task(tasks, existing["task_id"], **f)
                    tid = existing["task_id"]
                else:
                    nt = ctm.create_task(**f)
                    tasks.append(nt)
                    tid = nt["task_id"]
                ctm.save_custom_tasks(tasks)
            except ValueError as e:
                mb.showwarning("Check the task", str(e))
                return None
            win.destroy()
            refresh_all()
            status_fn(f"✅ Task '{f['label']}' saved")
            if run_after:
                run_now(tid)
            return tid

        brow = tk.Frame(pad)
        brow.pack(fill="x", pady=(8, 0))
        ttk.Button(brow, text="Cancel", command=win.destroy).pack(side="left", padx=(0, 8))
        ttk.Button(brow, text="Save", command=lambda: save(False)).pack(side="left", padx=(0, 8))
        ttk.Button(brow, text="Save & ▶ Run now", command=lambda: save(True)).pack(side="left")
        show_sched_fields()
        if existing and existing.get("schedule", "none") != "none":
            nxt_lbl = tk.Label(pad, text="Next run: " + (ctm.due_status_label(existing) or "—"),
                               font=("Arial", 8), fg="#5a7a9a")
            nxt_lbl.pack(anchor="w", after=srow)
        bind_wheel(win, canvas)
        try:                             # draw it now — never a blank window until the first scroll
            win.update_idletasks()
            canvas.itemconfig(pid, width=max(canvas.winfo_width(), 740))
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.yview_moveto(0)
        except tk.TclError:
            pass
        ed = dict(win=win, name_var=name_var, prompt_box=prompt_box, sched_var=sched_var, due_var=due_var,
                  run_time_var=run_time_var, dow_var=dow_var, start_var=start_var, end_var=end_var,
                  times_var=times_var, auto_var=auto_var, ai_var=ai_var, model_var=model_var,
                  learn_var=learn_var, report_var=report_var, email_var=email_var, folder_var=folder_var,
                  scope_vars=scope_vars, fields=fields, save=save, time_row=time_row, daily_row=daily_row,
                  auto_cb=auto_cb, model_combo=model_combo)
        p["editor"] = ed
        return ed

    nrow = tk.Frame(inner, bg=BG)
    nrow.pack(fill="x", pady=(6, 0))
    tk.Button(nrow, text="+ New Task", bg="#1a3a2a", fg="#88cc88", font=("Arial", 9, "bold"), relief="flat",
              cursor="hand2", command=lambda: open_editor(None)).pack(side="left")
    tk.Label(nrow, text=("  ▶ Run now runs it once on the Agent API Key · the server runs every task on its schedule"
                         if server else
                         "  ▶ Run now runs it once on the Agent API Key · 📋 Copy for chat runs it in Claude, Muse "
                         "or Grok · ⏱ Auto-run lets AI-Prowler run it on its schedule"), bg=BG, fg="#6a8aa2",
             font=("Arial", 7)).pack(side="left")

    def refresh_all():
        refresh_status()
        refresh_list()

    # live refresh: a chat (create_analysis_task / complete_analysis_task) or the scheduler changes the file
    mtime = {"last": None}

    def poll_file(reschedule=True):
        try:
            m = ctm.CUSTOM_TASKS_PATH.stat().st_mtime if ctm.CUSTOM_TASKS_PATH.exists() else None
            if m != mtime["last"]:
                mtime["last"] = m
                refresh_all()
        except Exception:  # noqa: BLE001
            pass
        if reschedule:
            try:
                if banner.winfo_exists():
                    root.after(3000, poll_file)
            except tk.TclError:
                pass

    def poll_status():
        try:
            if banner.winfo_exists():
                refresh_status()
                root.after(60_000, poll_status)
        except tk.TclError:
            pass

    legacy_box: list = []

    def legacy_poll():
        if not legacy_box:
            root.after(500, legacy_poll)
            return
        if legacy_box[0]:
            legacy_row.pack(fill="x", pady=(4, 0), before=r3)

    def legacy_work():
        try:
            legacy_box.append(bool(legacy_check_fn()))
        except Exception:  # noqa: BLE001
            legacy_box.append(False)

    refresh_all()
    try:
        mtime["last"] = ctm.CUSTOM_TASKS_PATH.stat().st_mtime if ctm.CUSTOM_TASKS_PATH.exists() else None
    except OSError:
        pass
    root.after(3000, poll_file)
    root.after(60_000, poll_status)
    threading.Thread(target=legacy_work, name="analysis-tasks-legacy-check", daemon=True).start()
    root.after(300, legacy_poll)

    p.update(count_var=count_var, list_frame=list_frame, provider_var=provider_var, notify_var=notify_var,
             method_var=method_var, web_var=web_var, key_var=key_var, sched_var=sched_var, budget_var=budget_var,
             last_var=last_var, btn_toggle=btn_toggle, legacy_row=legacy_row, toggle=toggle,
             refresh=refresh_all, refresh_list=refresh_list, refresh_status=refresh_status,
             poll_file=lambda: poll_file(False), open_editor=open_editor, open_starter=open_starter,
             run_now=run_now,
             copy_for_chat=copy_for_chat, delete=delete, remove_legacy=remove_legacy, legacy_poll=legacy_poll,
             poll_results=poll_results, running=running, starters=starters,
             view_log=view_log, clear_log=clear_log)
    return p


build_panel = build_section          # older name


# ── Common Business starters (were the "Common Business AI Analysis" buttons) ─────────────
# 2026-11-01 (David: "Find Problems is out of date — the jobs spreadsheet doesn't exist, it's a database —
# and it doesn't include the service desk, booking and scheduling, HR app"): rewritten for today's data.
# The job data is a database; read_job_spreadsheet reads it (the tool kept its old name; its "sheets" are
# the database's tables: Jobs_Schedule, Invoices, Customers, Quotes, TimeLog, Services_Pricing). Every
# section says "if available" — Service Desk / bookings can be off, and the HR tools exist on a server only.
# What to do with the findings (learnings / Word report / email) comes from the task's Output settings.

_SOURCES = (
    "DATA SOURCES (use what this install has; skip a source quietly if its tools aren't available and say so "
    "in one line of the summary):\n"
    "  • QuickBooks — if tools with 'quickbooks' or 'qbo' in the name exist, it is the authoritative source "
    "for invoices, payments, P&L and AR/AP; otherwise use AI-Prowler's job database.\n"
    "  • Job database — read_job_spreadsheet(sheet_name=...) reads the tables Jobs_Schedule, Invoices, "
    "Customers, Quotes, TimeLog and Services_Pricing; get_ar_aging_report() for invoice aging; "
    "find_stale_customers() for customers not serviced lately; get_working_days() for the crew's work days.\n"
    "  • Service Desk — list_tickets(overdue=true) and list_tickets() for open tickets, ticket_summary() for "
    "the open-ticket status and repeat fixes, triage_inbox() for new untyped tickets, ticket_report() for "
    "reply/fix times, SLA breaches and ratings.\n"
    "  • Bookings — review_booking(action='list') for website bookings waiting for approval (list only).\n"
    "  • Messages — list_sms_contacts_with_replies() and check_sms_replies(mark_read=false) for customer "
    "texts nobody has answered.\n"
    "  • Mileage — review_mileage_log() for gaps and problems in the mileage log.\n"
    "  • HR (server installs only) — hr_get_task_digest() for overdue onboarding/HR tasks, "
    "hr_get_report(report_name='i9_compliance') and hr_get_report(report_name='document_expiration') for "
    "compliance gaps.\n"
    "  • Knowledge — search_documents() for contracts, complaints and correspondence; search_learnings() "
    "for what is already known.\n"
    "Read only: never change, approve or send anything to customers while doing this analysis.\n\n"
)

STARTERS: list = [
    {
        'type': 'analyze_business',
        'label': '📊 Analyze My Business',
        'color': '#1a5276',
        'hover': '#21618c',
        'description': 'Full business health check across jobs, money, customers, Service Desk and bookings.',
        'prompt': (
            _SOURCES +
            "Give me a full health check of my business:\n"
            "  1. Money: revenue this month vs last month, open invoices and their aging, payments received, "
            "top 3 customers by revenue, most profitable services (Services_Pricing vs actual hours in TimeLog).\n"
            "  2. Work: jobs completed vs scheduled this month, jobs over their estimated time, the next two "
            "weeks' schedule load against the working days.\n"
            "  3. Customers: customers due for service (find_stale_customers), new customers this month, "
            "quotes sent but not accepted.\n"
            "  4. Service: open and overdue Service Desk tickets, reply and fix times, ratings; bookings "
            "waiting for approval.\n"
            "  5. Give the 3-5 most important, specific findings with the numbers behind them, and one "
            "concrete next step for each. If saving learnings, use category 'business_insight'."
        ),
    },
    {
        'type': 'weekly_advisor',
        'label': '💡 Weekly Business Advisor',
        'color': '#1a6b3a',
        'hover': '#1e8449',
        'description': "End-of-week debrief and 2-3 priorities for next week.",
        'prompt': (
            _SOURCES +
            "Act as my weekly business advisor for the last 7 days:\n"
            "  1. Jobs completed vs scheduled, actual vs estimated hours (TimeLog), jobs that slipped.\n"
            "  2. Invoices sent and paid this week, invoices that became overdue, cash in.\n"
            "  3. Service Desk: tickets opened and closed, any overdue or unhappy customers; bookings that came "
            "in and any still waiting for approval; customer texts still unanswered.\n"
            "  4. Next week: the schedule against the working days, open slots, and get_weather() for my area "
            "to flag rain days for outdoor jobs.\n"
            "  5. Learnings added this week (search_learnings).\n"
            "  6. Summarize the week in a few lines and suggest 2-3 specific priorities for next week. If "
            "saving learnings, use category 'weekly_review'."
        ),
    },
    {
        'type': 'find_problems',
        'label': '⚠️ Find Problems',
        'color': '#7d3c00',
        'hover': '#a04000',
        'description': 'Scans every part of the business for things that need attention now.',
        'prompt': (
            _SOURCES +
            "Scan my whole business for problems that need attention. Check each area:\n"
            "  1. Money: every invoice 31-60, 61-90 and 90+ days overdue (get_ar_aging_report or QuickBooks); "
            "completed jobs with no invoice; unpaid vendor bills if QuickBooks is connected.\n"
            "  2. Jobs & scheduling: jobs scheduled in the past that are still not completed; jobs over their "
            "estimated time by more than 20%; days over-booked for the crew; jobs scheduled on non-working days.\n"
            "  3. Customers: customers overdue for their regular service (find_stale_customers); quotes with "
            "no answer for 14+ days.\n"
            "  4. Service Desk: overdue tickets, SLA breaches, tickets with no reply for 24+ hours, new tickets "
            "nobody has triaged, repeat problems at the same customer.\n"
            "  5. Bookings: website bookings waiting for approval, oldest first.\n"
            "  6. Messages: customer texts unanswered for 24+ hours.\n"
            "  7. Mileage: missing days or problems in the mileage log.\n"
            "  8. HR (server installs only): overdue onboarding or HR tasks and compliance gaps.\n"
            "  9. Known issues: search_learnings(category='problem_flag') — say which are still unresolved; "
            "search_documents() for complaints or disputes.\n"
            "List every distinct problem with who/what, how old it is and what to do next, most urgent "
            "first, then point out any pattern (the same customer, crew or job type in several problems). If "
            "saving learnings, record each problem with category 'problem_flag'."
        ),
    },
    {
        'type': 'growth_opportunities',
        'label': '📈 Growth Opportunities',
        'color': '#1a4a6b',
        'hover': '#1f5c85',
        'description': 'Finds the most profitable services, best customers and ways to grow.',
        'prompt': (
            _SOURCES +
            "Find growth opportunities in my business:\n"
            "  1. Most profitable services: revenue per service vs the hours they really take (TimeLog), "
            "using QuickBooks P&L by service if connected.\n"
            "  2. Best customers: highest revenue, fastest payers, most repeat visits; customers who lapsed "
            "60+ days (find_stale_customers) and are worth winning back.\n"
            "  3. Seasonal pattern: monthly revenue for the last 12 months, busy and slow months.\n"
            "  4. Where the work is: towns/areas with the most jobs, for route efficiency and local marketing.\n"
            "  5. Demand signals: what customers ask for in Service Desk tickets and website bookings, quotes "
            "that weren't accepted and why, services often booked together (upsell pairs).\n"
            "  6. Give 3-5 specific, actionable opportunities with the numbers behind each. If saving "
            "learnings, use category 'growth_opportunity'."
        ),
    },
]
