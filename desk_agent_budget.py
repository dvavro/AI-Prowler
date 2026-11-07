"""
desk_agent_budget.py — the agents' monthly AI budget: a forecast and the owner's alert (2026-11-01, David:
"for the price monthly budget can an estimation of tokens budget and time to run out be predicted ...
we also need an alert to be sent out to the owner when the budget is about to be hit % amount").

* forecast(): this month's spend and tokens from every agent database (Service Desk, Jobs, HR), the daily
  pace, the month-end projection, the day it runs out at this pace, and about how many tokens are left on
  the chosen model. Worked out by AI-Prowler from the agents' own run records — no AI call, costs nothing.
* check_and_alert(): after every run, once a month per threshold — at the owner's warn-at % (default 80)
  and at 100 % — an email (and a text when a mobile is set) to the owner: Personal → the Service Desk
  "My alerts" email/mobile, else Settings → Email Configuration's default recipient; Server → every owner
  and manager. Sent through Service Desk's senders (desk_alerts), so it works wherever the agents run.
"""
from __future__ import annotations

import calendar
import datetime as dt
import json
import logging
import sqlite3
from pathlib import Path

log = logging.getLogger("desk_agent_budget")
STATE_PATH = Path.home() / ".ai-prowler" / "agent_budget_alerts.json"
send_fn = None                  # tests: fn(subject, body, sms_text, edition) -> [(channel, to)]
DEFAULT_IN_SHARE = 8 / 9        # before any runs: about 8 input tokens per output token


def agent_db_paths(db: str | None = None, s: dict | None = None) -> list:
    """Every agent database that exists (one budget for all of them)."""
    cands = [db, (s or {}).get("agent_shared_with")]
    for mod in ("desk_db", "desk_agent_store", "desk_agent_hr_store", "task_queue_automation"):
        try:
            m = __import__(mod)
            cands.append(m.default_db_path() if mod == "desk_db" else
                         m.runs_db_path() if mod == "task_queue_automation" else m.path())
        except Exception:  # noqa: BLE001
            pass
    out, seen = [], set()
    for c in cands:
        if not c:
            continue
        try:
            r = Path(c).resolve()
        except OSError:
            continue
        if str(r) not in seen and r.exists():
            seen.add(str(r))
            out.append(str(r))
    return out


def month_totals(paths: list, month: str) -> dict:
    tot = {"cost": 0.0, "input": 0, "output": 0, "runs": 0}
    for p in paths:
        try:
            con = sqlite3.connect(f"file:{Path(p).as_posix()}?mode=ro", uri=True)
        except sqlite3.Error:
            continue
        try:
            r = con.execute("SELECT COALESCE(SUM(cost_usd), 0), COALESCE(SUM(input_tokens), 0), "
                            "COALESCE(SUM(output_tokens), 0), COUNT(*) FROM agent_runs "
                            "WHERE substr(started_at, 1, 7) = ?", (month,)).fetchone()
            tot["cost"] += float(r[0] or 0)
            tot["input"] += int(r[1] or 0)
            tot["output"] += int(r[2] or 0)
            tot["runs"] += int(r[3] or 0)
        except sqlite3.Error:
            pass                # no agent tables there yet
        finally:
            con.close()
    tot["cost"] = round(tot["cost"], 4)
    return tot


def forecast(budget: float, totals: dict, now: dt.datetime, model: str = "", cfg: dict | None = None) -> dict:
    import desk_agent_providers as prov
    budget = float(budget or 0)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    days_in_month = calendar.monthrange(now.year, now.month)[1]
    elapsed = max((now - start).total_seconds() / 86400.0, 1.0)      # day 1 counts as a whole day
    spent = float(totals.get("cost", 0))
    toks = int(totals.get("input", 0)) + int(totals.get("output", 0))
    daily = spent / elapsed
    left = max(budget - spent, 0.0)
    runout = None
    if budget > 0 and daily > 0 and spent < budget:
        d = now + dt.timedelta(days=left / daily)
        if (d.year, d.month) == (now.year, now.month):
            runout = d.date().isoformat()
    tokens_left = None
    pr = prov.price_for(model, cfg) if model else None
    if pr and left > 0:
        share = (int(totals.get("input", 0)) / toks) if toks else DEFAULT_IN_SHARE
        per_token = (share * pr[0] + (1 - share) * pr[1]) / 1_000_000
        tokens_left = int(left / per_token) if per_token > 0 else None
    return {"budget": budget, "spent": round(spent, 2), "used_pct": round(100 * spent / budget, 1) if budget else None,
            "runs": int(totals.get("runs", 0)), "daily": round(daily, 4), "tokens": toks,
            "tokens_per_day": int(toks / elapsed), "projected": round(daily * days_in_month, 2),
            "left": round(left, 2), "runout": runout, "lasts_the_month": runout is None and spent < budget,
            "tokens_left": tokens_left, "model": model}


def _tok(n) -> str:
    n = int(n or 0)
    return f"{n / 1_000_000:.1f}M" if n >= 1_000_000 else (f"{n / 1000:.0f}K" if n >= 1000 else str(n))


def forecast_text(f: dict) -> str:
    head = f"Spent this month: ${f['spent']:.2f} of ${f['budget']:g}"
    if not f["runs"]:
        return head
    parts = [head + (f" ({f['used_pct']:.0f}%)" if f.get("used_pct") is not None else ""),
             f"about ${f['daily']:.2f}/day ({_tok(f['tokens_per_day'])} tokens/day)"]
    if f["budget"] <= 0:
        parts.append("budget is $0 — the agents don't run on their own")
    elif f["spent"] >= f["budget"]:
        parts.append("used up — the agents wait until next month")
    elif f["runout"]:
        d = dt.date.fromisoformat(f["runout"])
        parts.append(f"at this pace it runs out about {d:%b} {d.day}")
    else:
        parts.append(f"at this pace about ${f['projected']:.2f} for the month — it lasts the month")
    if f.get("tokens_left"):
        parts.append(f"about {_tok(f['tokens_left'])} tokens left on {f['model']}")
    return " · ".join(parts)


def current(edition: str | None = None, now: dt.datetime | None = None) -> dict:
    """The forecast for the screen (the Service Desk settings database holds the budget)."""
    import desk_agent_providers as prov
    import desk_agent_settings as das
    import desk_db
    now = now or dt.datetime.now().astimezone()
    db = desk_db.default_db_path()
    desk_db.init_db(db)
    s = desk_db.get_settings(db)
    provider = das.effective_provider(s, edition)
    f = forecast(float(s.get("agent_monthly_budget_usd") or 0),
                 month_totals(agent_db_paths(db, s), now.strftime("%Y-%m")), now, prov.model_for(provider))
    f["alert_pct"] = int(s.get("agent_budget_alert_pct", 80) or 0)
    f["text"] = forecast_text(f)
    return f


# ── the owner's alert ────────────────────────────────────────────────────────────────

def _load_state() -> dict:
    try:
        return json.loads(Path(STATE_PATH).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _save_state(state: dict) -> None:
    try:
        Path(STATE_PATH).parent.mkdir(parents=True, exist_ok=True)
        Path(STATE_PATH).write_text(json.dumps(state), encoding="utf-8")
    except OSError as e:
        log.warning("agent budget alert state not saved: %s", e)


def owner_recipients(edition: str | None) -> tuple:
    """(emails, phones) for the budget alert."""
    emails, phones = [], []
    try:
        import desk_alerts as da
        if edition == "business":
            for u in da._team():
                if u.get("role") in ("owner", "manager"):
                    emails.append(u.get("email") or "")
                    phones.append(u.get("phone") or "")
        else:
            o = da._owner_contact()
            emails.append(o.get("email") or "")
            phones.append(o.get("phone") or "")
    except Exception:  # noqa: BLE001
        pass
    emails = [e for e in dict.fromkeys(emails) if e]
    if not emails:
        try:
            from scheduler_engine import _read_default_to_email
            d = _read_default_to_email() or ""
            if d:
                emails = [d]
        except Exception:  # noqa: BLE001
            pass
    return emails, [p for p in dict.fromkeys(phones) if p]


def _default_send(subject: str, body: str, sms_text: str, edition: str | None) -> list:
    import desk_alerts as da
    emails, phones = owner_recipients(edition)
    went = []
    for e in emails:
        if da._call("email", e, subject, body, default=False):
            went.append(("email", e))
    for ph in phones:
        if da._call("sms", ph, sms_text, default=False):
            went.append(("sms", ph))
    return went


def check_and_alert(s: dict, *, edition: str | None, db: str | None = None, now: dt.datetime | None = None,
                    model: str | None = None) -> list:
    """Alert the owner once a month at the warn-at % and once at 100 %. Returns the thresholds alerted."""
    import desk_agent_providers as prov
    import desk_agent_settings as das
    now = now or dt.datetime.now().astimezone()
    budget = float(s.get("agent_monthly_budget_usd") or 0)
    pct = int(s.get("agent_budget_alert_pct", 80) or 0)
    if budget <= 0 or pct <= 0:
        return []
    month = now.strftime("%Y-%m")
    totals = month_totals(agent_db_paths(db, s), month)
    used = 100 * totals["cost"] / budget
    crossed = [m for m in sorted({min(pct, 100), 100}) if used >= m]
    state = _load_state()
    sent = [int(x) for x in state.get(month, [])]
    new = [m for m in crossed if m not in sent]
    if not new:
        return []
    top = max(new)
    model = model or prov.model_for(das.effective_provider(s, edition))
    f = forecast(budget, totals, now, model)
    if top >= 100:
        subject = f"AI-Prowler agents stopped: this month's AI budget is used up (${f['spent']:.2f} of ${budget:g})"
        what = ("The agents have stopped running on their own until the 1st of next month. Nothing is lost — "
                "their work waits in the queue.")
        sms = f"AI-Prowler: agents' AI budget used up (${f['spent']:.2f} of ${budget:g}). They wait until next month."
    else:
        subject = f"AI-Prowler agents: {used:.0f}% of this month's AI budget used (${f['spent']:.2f} of ${budget:g})"
        what = "When it reaches 100% the agents stop running on their own until next month."
        sms = f"AI-Prowler: agents used {used:.0f}% of this month's AI budget (${f['spent']:.2f} of ${budget:g})."
    body = "\n\n".join([
        f"Your AI-Prowler agents have used ${f['spent']:.2f} of this month's ${budget:g} AI budget ({used:.0f}%).",
        forecast_text(f) + ".", what,
        "To change the budget or the warning: AI-Prowler → Small Business tab → 🔑 Agent API Key → Monthly budget."])
    went = (send_fn or _default_send)(subject, body, sms, edition)
    if not went:
        log.warning("agent budget alert (%s%%) not sent — no owner email or mobile set up", top)
        return []
    state = {month: sorted(set(sent) | set(crossed))}            # only this month is kept
    _save_state(state)
    log.info("agent budget alert sent (%s%%) to %s", top, went)
    return new


# ── the cost analysis (2026-11-01, David: "make that cost analysis a popup menu with an on demand new analysis
# button so the user can gage the costs") ─────────────────────────────────────────────────────────────────
DEFAULT_CALL_TOKENS = (2000, 400)        # measured: live cost test 2026-11-03 (10 agent items, Sonnet/Haiku mix)
DEFAULT_COMPLEX_SHARE = 0.3
DEFAULT_CALLS_PER_DAY = 10               # a small business: David's install queued ~7 items a day (Oct 31-Nov 3)
DEFAULT_TASK_RUN_USD = 0.30              # measured: one AI analysis task run $0.20-0.38 on Sonnet 5.5 (Nov 2-3)
# Runs that never reached a paid API (the removed Claude CLI subscription runner, chat runs) cost nothing and are
# not API calls — the 2026-11-01 popup counted 54 failed CLI items as ~19 API calls a day and forecast $300+/month.
NON_API_PROVIDERS = ("claude_code", "chat", "chat_only")
TEST_TAG = "[live cost test]"            # the live cost test's own runs: real spend, but not the business's volume


def _agent_name(path: str) -> str:
    try:
        r = Path(path).resolve()
        import desk_db
        if r == Path(desk_db.default_db_path()).resolve():
            return "Service Desk"
        import desk_agent_store
        if r == Path(desk_agent_store.path()).resolve():
            return "Jobs app"
        import desk_agent_hr_store
        if r == Path(desk_agent_hr_store.path()).resolve():
            return "HR"
        import task_queue_automation
        if r == Path(task_queue_automation.runs_db_path()).resolve():
            return "Task Queue"
    except Exception:  # noqa: BLE001
        pass
    return Path(path).stem


def _ro(path):
    return sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)


def per_agent(paths: list, month: str) -> list:
    out = []
    for p in paths:
        row = {"name": _agent_name(p), "runs": 0, "items": 0, "input": 0, "output": 0, "cost": 0.0}
        try:
            con = _ro(p)
        except sqlite3.Error:
            continue
        try:
            r = con.execute("SELECT COUNT(*), COALESCE(SUM(items), 0), COALESCE(SUM(input_tokens), 0), "
                            "COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cost_usd), 0) FROM agent_runs "
                            "WHERE substr(started_at, 1, 7) = ?", (month,)).fetchone()
            row.update(runs=int(r[0]), items=int(r[1]), input=int(r[2]), output=int(r[3]), cost=round(float(r[4]), 4))
        except sqlite3.Error:
            pass
        finally:
            con.close()
        out.append(row)
    return out


def per_model(paths: list, month: str) -> list:
    agg = {}
    for p in paths:
        try:
            con = _ro(p)
        except sqlite3.Error:
            continue
        try:
            for m, items, cost, ti, to in con.execute(
                    "SELECT model, COALESCE(SUM(items), 0), COALESCE(SUM(cost_usd), 0), COALESCE(SUM(input_tokens), 0), "
                    "COALESCE(SUM(output_tokens), 0) FROM agent_runs WHERE substr(started_at, 1, 7) = ? GROUP BY model",
                    (month,)):
                a = agg.setdefault(m or "?", {"model": m or "?", "items": 0, "cost": 0.0, "input": 0, "output": 0})
                a["items"] += int(items); a["cost"] += float(cost); a["input"] += int(ti); a["output"] += int(to)
        except sqlite3.Error:
            pass
        finally:
            con.close()
    for a in agg.values():
        a["per_call"] = round(a["cost"] / a["items"], 5) if a["items"] else None
        a["cost"] = round(a["cost"], 4)
    return sorted(agg.values(), key=lambda a: -a["cost"])


def complex_share(paths: list, month: str):
    """Share of this month's queued items that are complex steps (None when nothing was queued)."""
    import desk_agent_providers as prov
    n = c = 0
    for p in paths:
        try:
            con = _ro(p)
        except sqlite3.Error:
            continue
        try:
            for kind, stage in con.execute("SELECT kind, stage FROM agent_queue WHERE substr(created_at, 1, 7) = ?",
                                           (month,)):
                n += 1
                c += 1 if prov.uses_strong_model(kind, stage) else 0
        except sqlite3.Error:
            pass
        finally:
            con.close()
    return (c / n) if n else None


WINDOW_DAYS = 30


def _is_task_db(path: str) -> bool:
    try:
        import task_queue_automation
        return Path(path).resolve() == Path(task_queue_automation.runs_db_path()).resolve()
    except Exception:  # noqa: BLE001
        return Path(path).name == "task_queue.db"


def _days_since(first, now_utc) -> float:
    days = float(WINDOW_DAYS)
    if first:
        try:
            f = dt.datetime.fromisoformat(str(first).replace("Z", "+00:00"))
            f = f if f.tzinfo else f.replace(tzinfo=dt.timezone.utc)
            days = max(1.0, min(float(WINDOW_DAYS), (now_utc - f).total_seconds() / 86400.0))
        except ValueError:
            pass
    return days


def window_totals(paths: list, now: dt.datetime) -> dict:
    """The last 30 days (or since the first queued item, if sooner). Reworked 2026-11-03 after the live cost test
    showed the popup forecasting ~$300-400 a month against a real ~$0.005 per agent item:
      * volume = the items the agents QUEUED (each is one AI call), whatever runs them — not the runs' item
        counts, which counted every retry of the removed Claude CLI runner (cost $0) as an API call;
      * tokens per call = agent items that really reached a paid API — never a whole AI-task run (many rounds,
        mostly cached), which made one 'call' look like 339K tokens;
      * the Task Queue's AI-task runs are counted on their own (runs, cost per run)."""
    import desk_agent_providers as prov
    now_utc = now.astimezone(dt.timezone.utc) if now.tzinfo else now
    since = (now_utc - dt.timedelta(days=WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%S")
    api_items = tok_items = tin = tout = n = c = task_runs = 0
    item_cost = task_cost = 0.0
    first_q = first_run = None
    for p in paths:
        try:
            con = _ro(p)
        except sqlite3.Error:
            continue
        is_task = _is_task_db(p)
        try:
            for started, it, ti, to, cst, provider, model, summary in con.execute(
                    "SELECT started_at, items, input_tokens, output_tokens, cost_usd, provider, model, summary "
                    "FROM agent_runs WHERE started_at >= ?", (since,)):
                it, ti, to, cst = int(it or 0), int(ti or 0), int(to or 0), float(cst or 0)
                if (provider or "") in NON_API_PROVIDERS or (model or "") == "subscription" or (ti + to) <= 0:
                    continue                         # never reached a paid API — not a call, cost nothing
                if is_task:
                    task_runs += 1
                    task_cost += cst
                    continue
                if it:
                    tok_items += it; tin += ti; tout += to; item_cost += cst
                if not str(summary or "").startswith(TEST_TAG):
                    api_items += it
                    first_run = started if first_run is None or started < first_run else first_run
        except sqlite3.Error:
            pass
        try:
            try:
                qrows = con.execute("SELECT kind, stage, created_at, ref, reason FROM agent_queue WHERE created_at >= ?",
                                    (since,)).fetchall()
            except sqlite3.OperationalError:          # a minimal / older queue table without ref or reason
                qrows = con.execute("SELECT kind, stage, created_at, '', '' FROM agent_queue WHERE created_at >= ?",
                                    (since,)).fetchall()
            for kind, stage, created, ref, reason in qrows:
                if "LCT" in str(ref or "") or str(reason or "").startswith(TEST_TAG):
                    continue                         # the live cost test's own items
                n += 1
                c += 1 if prov.uses_strong_model(kind, stage) else 0
                first_q = created if first_q is None or created < first_q else first_q
        except sqlite3.Error:
            pass
        finally:
            con.close()
    days = _days_since(first_q or first_run, now_utc)
    volume = n or api_items
    return {"items": api_items, "queued": n, "days": round(days, 2),
            "items_per_day": (volume / days) if volume else None,
            "call_tokens": (tin // tok_items, tout // tok_items) if tok_items else None,
            "cost_per_item": (item_cost / tok_items) if tok_items else None, "measured_items": tok_items,
            "complex_share": (c / n) if n else None,
            "task_runs": task_runs, "task_cost_per_run": (task_cost / task_runs) if task_runs else None}


def scheduled_task_runs_per_month(tasks: list | None = None) -> float:
    """How many AI-task runs a month the saved AI Analysis Tasks will make on their own (Auto-run on)."""
    if tasks is None:
        try:
            import custom_tasks_manager as ctm
            tasks = ctm.load_custom_tasks()
        except Exception:  # noqa: BLE001
            return 0.0
    per = {"daily": 30.0, "weekly": 52 / 12, "biweekly": 26 / 12, "monthly": 1.0}
    total = 0.0
    for t in tasks or []:
        sch = str(t.get("schedule") or "none")
        if not t.get("auto_run") or sch not in per:
            continue
        times = max(1, int(t.get("daily_times_per_day") or 1)) if sch == "daily" else 1
        total += per[sch] * times
    return round(total, 1)


def estimates(calls_per_day: float, call_tokens: tuple, share: float, *, cfg: dict | None = None,
              measured: dict | None = None) -> list:
    """Estimated cost per call / day / month (30 days) for each model, plus the smart mix
    (complex-work model for complex steps, simple-steps model for the rest)."""
    import desk_agent_providers as prov
    measured = measured or {}

    def per_call(m):
        ti, to = measured.get(m, {}).get("tokens", call_tokens)
        return prov.cost(m, {"input": ti, "output": to}, cfg if cfg is not None else {})
    rows = []
    for runner in ("claude_api", "grok_api"):
        for m, lab in prov.AGENT_MODELS[runner]:
            pc = per_call(m)
            rows.append({"label": lab, "model": m, "per_call": pc, "per_day": round(pc * calls_per_day, 4),
                         "per_month": round(pc * calls_per_day * 30, 2), "measured": m in measured})
    main = prov.model_for("claude_api", cfg)
    light = prov.light_model(cfg) or "claude-haiku-5-5"
    if light != main:
        pc = share * per_call(main) + (1 - share) * per_call(light)
        rows.append({"label": f"Smart mix: {main} for complex steps & customer messages ({share:.0%}), "
                              f"{light} for internal steps",
                     "model": f"{main}+{light}", "per_call": round(pc, 6), "per_day": round(pc * calls_per_day, 4),
                     "per_month": round(pc * calls_per_day * 30, 2), "measured": main in measured and light in measured,
                     "smart": True})
    return rows


def analysis(edition: str | None = None, now: dt.datetime | None = None, *, paths: list | None = None,
             measured: dict | None = None) -> dict:
    """Everything the cost popup shows. Free — read from the agents' own records, no AI call."""
    import desk_agent_providers as prov
    now = now or dt.datetime.now().astimezone()
    month = now.strftime("%Y-%m")
    try:
        f = current(edition, now)
    except Exception:  # noqa: BLE001
        f = {"text": "", "budget": 0, "spent": 0}
    paths = paths if paths is not None else agent_db_paths()
    agents = per_agent(paths, month)
    items = sum(a["items"] for a in agents)
    w = window_totals(paths, now)                  # last 30 days: volume, tokens per call, step mix
    cpd = w["items_per_day"]
    call_tokens = w["call_tokens"] or DEFAULT_CALL_TOKENS
    share = w["complex_share"]
    used_share = share if share is not None else DEFAULT_COMPLEX_SHARE
    used_cpd = cpd if cpd else DEFAULT_CALLS_PER_DAY
    est = estimates(used_cpd, call_tokens, used_share, measured=measured)
    smart = next((e for e in est if e.get("smart")), None)
    # 2026-11-03: once enough items really ran on the API, the smart mix uses what they really cost per item (the
    # records price prompt caching correctly) instead of tokens x list price.
    if smart and not measured and (w.get("measured_items") or 0) >= 3 and w.get("cost_per_item"):
        pc = w["cost_per_item"]
        smart.update(per_call=round(pc, 6), per_day=round(pc * used_cpd, 4), per_month=round(pc * used_cpd * 30, 2),
                     measured=True)
    # AI Analysis Tasks (the Task Queue) — runs, not calls: a run is several AI rounds over many tools.
    runs_month = scheduled_task_runs_per_month()
    per_run = w.get("task_cost_per_run") or DEFAULT_TASK_RUN_USD
    tasks = {"runs_per_month": runs_month, "per_run": round(per_run, 4), "per_month": round(runs_month * per_run, 2),
             "measured_runs": w.get("task_runs", 0)}
    if runs_month:
        est.append({"label": f"AI Analysis Tasks: {runs_month:g} scheduled run(s) a month at about "
                             f"${per_run:.2f} a run" + ("" if w.get("task_runs") else " (estimated)"),
                    "model": "tasks", "per_call": round(per_run, 4), "per_day": round(runs_month * per_run / 30, 4),
                    "per_month": tasks["per_month"], "measured": bool(w.get("task_runs")), "tasks": True})
    base = smart or next((e for e in est if e["model"] == prov.model_for("claude_api")), None)
    if base:
        total = round(base["per_month"] + tasks["per_month"], 2)
        est.append({"label": "Expected total a month: " + ("smart mix" if smart else base["model"])
                             + (" + AI tasks" if runs_month else ""),
                    "model": "total", "per_call": None, "per_day": round(total / 30, 4), "per_month": total,
                    "measured": bool(base.get("measured")), "total": True})
    return {"month": month, "forecast": f, "agents": agents, "models": per_model(paths, month),
            "items": items, "calls_per_day": cpd, "calls_per_day_used": round(used_cpd, 1),
            "call_tokens": call_tokens, "complex_share": share, "complex_share_used": used_share,
            "main_model": prov.model_for("claude_api"), "light_model": prov.light_model(),
            "estimates": est, "measured": measured or {}, "tasks": tasks,
            "queued": w.get("queued", 0), "window_days": w.get("days")}


def _jobs_db_path() -> str:
    try:
        import desk_portal
        p = desk_portal._jobs_db()
        if p:
            return p
    except Exception:  # noqa: BLE001
        pass
    import os
    from db_access import DEFAULT_DB_FILENAME, DEFAULT_DB_SUBDIR
    base = os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip() or str(Path.home() / ".ai-prowler")
    return str(Path(base) / DEFAULT_DB_SUBDIR / DEFAULT_DB_FILENAME)


def sample_items(limit: int = 3, edition: str = "solo") -> tuple:
    """(system prompt, [(label, user_json, complex?)]) — real context packs from the agents' queues, built
    read-only (nothing is claimed or changed). HR items are never used here."""
    import desk_agent
    import desk_agent_providers as prov
    import desk_agent_settings as das
    import desk_agent_store
    import desk_db
    import desk_jobs_agent
    jobs_db = _jobs_db_path()
    tdb = desk_db.default_db_path()
    ts = desk_db.get_settings(tdb) if Path(tdb).exists() else dict(das.DEFAULTS)
    sources = []
    if Path(desk_agent_store.path()).exists():
        sources.append((desk_agent_store.path(), desk_agent_store.settings()))
    if Path(tdb).exists():
        sources.append((tdb, ts))
    picked, seen = [], set()
    for db, s in sources:
        try:
            con = _ro(db)
            con.row_factory = sqlite3.Row
            rows = [dict(r) for r in con.execute("SELECT * FROM agent_queue ORDER BY item_id DESC LIMIT 40")]
            con.close()
        except sqlite3.Error:
            continue
        for r in rows:
            key = (r["kind"], r["stage"])
            if key in seen or r["kind"] == "hr":
                continue
            try:
                if r["kind"] in ("job", "route"):
                    pk = desk_jobs_agent.pack(db, jobs_db, r, s, edition, "")
                elif r["kind"] == "ticket":
                    pk = desk_agent._ticket_pack(db, r, s, edition, "")
                elif r["kind"] == "booking":
                    pk = desk_agent._booking_pack(db, jobs_db, r, s, edition, "")
                else:
                    pk = None
            except Exception:  # noqa: BLE001
                pk = None
            if not pk:
                continue
            pk = dict(pk, kind=r["kind"], stage=r["stage"], reason=r.get("reason"))
            seen.add(key)
            grp = prov.step_group(r["kind"], r["stage"])
            picked.append((f"{r['kind']} / {r['stage']} ({prov.GROUP_LABELS[grp]})",
                           json.dumps(pk, default=str, ensure_ascii=False), grp != "simple"))
    picked.sort(key=lambda x: not x[2])                       # a complex one first when there is one
    mix = picked[:1] + [x for x in picked[1:] if not x[2]][:max(0, limit - 1)]
    mix += [x for x in picked if x not in mix][:max(0, limit - len(mix))]
    system = (desk_agent.SYSTEM_PROMPT.format(identity=das.prompt_identity(ts, ""), never=desk_agent.NEVER)
              + prov.HEADLESS_RULES)
    return system, mix[:limit]


def measure(models: list, system: str, samples: list, ask_fn=None) -> dict:
    """Send each sample to each model ONCE and read the answers (never submitted). Real API calls — costs a few
    cents. Returns {"rows": [...], "per_model": {model: {"tokens": (in, out), "per_call": $}}, "cost": $}."""
    import desk_agent_providers as prov
    ask_fn = ask_fn or prov.ask
    rows, per, total = [], {}, 0.0
    for m in models:
        for label, user, cx in samples:
            try:
                text, u = ask_fn("claude_api", system, user, model=m)
                try:
                    acts, _ = prov.parse_actions(text)
                    answer = ", ".join(str(a.get("action")) for a in acts) or "no actions"
                except Exception as e:  # noqa: BLE001
                    answer = f"unusable answer: {e}"
                c = prov.cost(m, u)
                total += c
                rows.append({"model": m, "item": label, "complex": cx, "input": u.get("input", 0),
                             "output": u.get("output", 0), "cost": c, "answer": answer})
                a = per.setdefault(m, {"n": 0, "in": 0, "out": 0, "cost": 0.0})
                a["n"] += 1; a["in"] += u.get("input", 0); a["out"] += u.get("output", 0); a["cost"] += c
            except Exception as e:  # noqa: BLE001
                rows.append({"model": m, "item": label, "complex": cx, "error": str(e)[:200]})
    per_model_out = {m: {"tokens": (a["in"] // a["n"], a["out"] // a["n"]), "per_call": round(a["cost"] / a["n"], 6)}
                     for m, a in per.items() if a["n"]}
    return {"rows": rows, "per_model": per_model_out, "cost": round(total, 5)}
