"""
desk_tools.py — AI-Prowler Service Desk, Phase 1: the logic behind the MCP tools.

ai_prowler_mcp.py keeps only thin @mcp.tool() wrappers (house style: every
registered tool lives in that file so the tool-catalog guard can see it).
Each wrapper resolves who is calling and which edition this install is, then
calls one function here. Everything here is plain Python, so it is unit
tested without an MCP server.

Every function returns text written for Claude/Muse/Grok to read back,
except ticket_updates_json(), which returns JSON for app polling.

Callers pass:
    actor    None (personal-mode owner) or {"id", "role", "name"?, "queues"?}
    edition  "solo" (personal mode) or "business" (server mode)
    db_path  the tickets database
"""
from __future__ import annotations

import datetime
import json

import desk_db
import desk_rules as rules

STATE_ICON = {rules.OPEN: "🆕", rules.ASSIGNED: "📌", rules.IN_PROGRESS: "🔧",
              rules.ON_HOLD: "⏸️", rules.FIXED: "✅", rules.CLOSED: "🔒"}
KIND_LABEL = {rules.EXTERNAL: "customer", rules.INTERNAL: "internal",
              rules.SUBCONTRACTOR_KIND: "subcontractor"}


# ── helpers ──────────────────────────────────────────────────────────────────

def due_iso(value: str) -> str | None:
    """'2026-10-31' or an ISO date-time -> UTC ISO string. A bare date means the
    end of that day on this computer's clock."""
    v = (value or "").strip()
    if not v:
        return None
    try:
        if len(v) == 10:
            d = datetime.date.fromisoformat(v)
            local = datetime.datetime.combine(d, datetime.time(23, 59)).astimezone()
        else:
            local = datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
            if local.tzinfo is None:
                local = local.astimezone()
    except ValueError as e:
        raise desk_db.DeskError(f"due date {value!r} is not a date like 2026-10-31") from e
    return local.astimezone(datetime.timezone.utc).isoformat(timespec="seconds")


def _short_date(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone()
        return dt.strftime("%a %b %d")
    except ValueError:
        return iso[:10]


def ticket_line(t: dict) -> str:
    bits = [f"{STATE_ICON.get(t['state'], '•')} {t['ticket_id']} — {t['title']}",
            f"[{t['state']}, {t['priority']}, {KIND_LABEL.get(t['kind'], t['kind'])}]"]
    if t.get("assignee"):
        bits.append(f"→ {t['assignee']}")
    if t.get("due_resolve_at") and t["state"] not in (rules.FIXED, rules.CLOSED):
        bits.append(f"due {_short_date(t['due_resolve_at'])}")
    return " ".join(bits)


def _err(e: Exception) -> str:
    if isinstance(e, desk_db.StaleRowError):
        return f"⚠️ {e}"
    return f"❌ {e}"


def _run(fn):
    """Turn rule refusals into readable answers; let real bugs raise."""
    try:
        return fn()
    except desk_db.DeskError as e:
        return _err(e)


def _contact_for(db_path, kind, *, contact_id, name, phone, email, actor):
    if contact_id or not (phone or email):
        return contact_id or None
    ctype = "subcontractor" if kind == rules.SUBCONTRACTOR_KIND else "customer"
    return desk_db.upsert_contact(db_path, name=name, phone=phone, email=email,
                                  contact_type=ctype, actor=actor)["contact_id"]


# ── tools ────────────────────────────────────────────────────────────────────

def create_ticket(db_path, actor, edition, *, title, description="", kind="", priority="P3",
                  type="", contact_name="", contact_phone="", contact_email="", contact_id="",
                  customer_id="", job_id="", assignee="", queue_id="", due="",
                  private=False, sms_fallback=None, source="claude") -> str:
    def go():
        k = (kind or "").strip().lower()
        has_party = any([contact_id, contact_phone, contact_email, customer_id])
        if not k:
            k = rules.EXTERNAL if has_party else rules.INTERNAL
        cid = _contact_for(db_path, k, contact_id=contact_id, name=contact_name,
                           phone=contact_phone, email=contact_email, actor=actor)
        t = desk_db.create_ticket(
            db_path, title=title, kind=k, actor=actor, edition=edition,
            description=description, type=type, priority=(priority or "P3").upper(),
            source=source, contact_id=cid, customer_id=customer_id or None,
            job_id=job_id or None, visibility="private" if private else "normal",
            queue_id=queue_id or None, assignee=assignee or None,
            due_resolve_at=due_iso(due), sms_fallback=sms_fallback)
        who = t["assignee"] or "nobody yet (Open)"
        extra = []
        return (f"✅ Filed {t['ticket_id']} — {t['title']} ({KIND_LABEL[t['kind']]} ticket, "
                f"{t['priority']}). Assigned to: {who}. State: {t['state']}."
                + (f" Due {_short_date(t['due_resolve_at'])}." if t["due_resolve_at"] else "")
                + ("\n" + " ".join(extra) if extra else ""))
    return _run(go)


def get_ticket(db_path, actor, edition, *, ticket_id) -> str:
    def go():
        d = desk_db.get_ticket_detail(db_path, ticket_id.strip().upper(), actor=actor,
                                      edition=edition)
        lines = [ticket_line(d)]
        if d.get("description"):
            lines.append(f"Description: {d['description']}")
        facts = []
        for label, key in (("Customer", "customer_id"), ("Contact", "contact_id"),
                           ("Job", "job_id"), ("Type", "type"), ("Source", "source")):
            if d.get(key):
                facts.append(f"{label}: {d[key]}")
        if facts:
            lines.append(" | ".join(facts))
        lines.append(f"Version: {d.get('rev')} (pass as expected_version to avoid "
                     f"overwriting someone else's change)")
        if d.get("messages"):
            lines.append("Messages:")
            for m in d["messages"]:
                tag = "public" if m["visibility"] == "public" else "internal note"
                lines.append(f"  • {m['at'][:16].replace('T', ' ')} {m['author']} ({tag}, "
                             f"{m['channel']}): {m['body']}")
        if d.get("attachments"):
            lines.append("Attachments: " + ", ".join(
                f"{a['filename']} ({a['kind']}{', internal' if a['visibility'] == 'internal' else ''})"
                for a in d["attachments"]))
        if d.get("resolution"):
            lines.append(f"Resolution: {d['resolution']}")
        if d.get("close_reason"):
            lines.append(f"Closed: {d['close_reason']}")
        if d.get("csat_score") is not None:
            lines.append(f"Customer rating: {d['csat_score']}/5"
                         + (f" — \"{d['csat_comment']}\"" if d.get("csat_comment") else ""))
        if d.get("state_history"):
            lines.append("History: " + " → ".join(
                f"{h['to']}" + (f" ({h['reason']})" if h.get("reason") else "")
                for h in d["state_history"]))
        return "\n".join(lines)
    return _run(go)


def list_tickets(db_path, actor, edition, *, state="", open_only=True, assignee="", kind="",
                 customer_id="", priority="", overdue=False, text="", limit=25) -> str:
    def go():
        rows = desk_db.list_tickets(
            db_path, actor=actor, edition=edition, state=state or None,
            open_only=bool(open_only) and not state, assignee=assignee or None,
            kind=kind or None, customer_id=customer_id or None,
            priority=(priority or "").upper() or None, overdue=bool(overdue),
            text=text or None, limit=int(limit or 25))
        if not rows:
            return "No tickets match."
        return f"{len(rows)} ticket(s):\n" + "\n".join("  " + ticket_line(t) for t in rows)
    return _run(go)


def my_tickets(db_path, actor, edition) -> str:
    def go():
        rows = desk_db.my_tickets(db_path, actor=actor, edition=edition)
        if not rows:
            return "Nothing on your plate — no open tickets assigned to you."
        return (f"{len(rows)} open ticket(s) for you, soonest due first:\n"
                + "\n".join("  " + ticket_line(t) for t in rows))
    return _run(go)


def update_ticket(db_path, actor, edition, *, ticket_id, title="", description="",
                  priority="", type="", due="", job_id="", customer_id="",
                  sms_fallback=None, reason="", expected_version=None, resolution="") -> str:
    def go():
        fields = {}
        for k, v in (("title", title), ("description", description), ("type", type),
                     ("job_id", job_id), ("customer_id", customer_id),
                     ("resolution", (resolution or "").strip())):
            if v:
                fields[k] = v
        if priority:
            fields["priority"] = priority.upper()
        if due:
            fields["due_resolve_at"] = due_iso(due)
        if sms_fallback is not None:
            fields["sms_fallback"] = bool(sms_fallback)
        if not fields:
            return "❌ Nothing to change — pass at least one field."
        t = desk_db.update_ticket(db_path, ticket_id.strip().upper(), fields, actor=actor,
                                  edition=edition, reason=reason,
                                  expected_version=expected_version)
        return f"✅ Updated {t['ticket_id']}: {', '.join(fields)}. Now version {t['version']}."
    return _run(go)


def review_booking(db_path, actor, edition, *, action="list", booking="", window_key="", crew="",
                   message="", keep_request=False, jobs_db=None) -> str:
    """Bookings waiting for approval (booking-spec.md §7a.3): list / windows / approve /
    suggest / decline. `booking` = a job id (JOB-0012), a ticket id (T-0042) or part of the
    customer's name. Approvers only — the owner, and managers on a server when allowed."""
    import booking_flow
    import desk_portal
    s = desk_db.get_settings(db_path)
    if not booking_flow.can_approve(actor, edition, s):
        return ("❌ Only the owner" + (" or a manager" if edition == rules.BUSINESS
                                       and s.get("booking_approve_managers", True) else "")
                + " can review bookings.")
    jobs_db = jobs_db or desk_portal._jobs_db()
    if not jobs_db:
        return "❌ The Jobs app isn't available on this AI-Prowler."
    rows = booking_flow.to_approve(jobs_db)
    action = (action or "list").strip().lower()
    if action == "list":
        if not rows:
            return "📅 No bookings are waiting for approval."
        out = [f"📅 {len(rows)} booking(s):"]
        for b in rows:
            what = {"pending": f"wants {b['held_label']}", "reschedule": f"move {b['current']} → {b['held_label']}",
                    "suggested": f"you suggested {(b['suggested'] or {}).get('label', '')} — waiting for the customer"}
            out.append(f"• {b['job_id']} ({b['ticket_id'] or 'no ticket'}) {b['customer'] or 'customer'}, "
                       f"{b['service']}, {b['address']}, {b['phone']}: {what.get(b['status'], b['status'])}"
                       + (f"; backups: {', '.join(x['label'] for x in b['backups'])}" if b["backups"] else ""))
        return "\n".join(out) + ("\nSay approve, suggest another time (pick from action=windows) or decline.")
    key = (booking or "").strip().lower()
    hits = [b for b in rows if key and (key == b["job_id"].lower() or key == (b["ticket_id"] or "").lower()
                                         or key in (b["customer"] or "").lower())]
    if len(hits) != 1:
        return ("❌ " + ("No waiting booking matches that." if not hits else
                        "More than one booking matches: " + ", ".join(f"{b['job_id']} {b['customer']}" for b in hits))
                + " Use action=list to see them.")
    b = hits[0]
    try:
        if action == "windows":
            ws = booking_flow.windows(jobs_db, s, b["service_code"], edition, online_only=False)
            return (f"Open windows for {b['job_id']}: " + "; ".join(f"{w['label']} [{w['key']}]" for w in ws[:20])
                    if ws else "❌ No open windows in the booking horizon.")
        if action == "approve":
            r = booking_flow.approve(jobs_db, db_path, b["job_id"], actor=actor, edition=edition, settings=s,
                                     window_key=window_key, crew=crew or None)
            return f"✅ {b['job_id']} confirmed for {r['label']} — {b['customer'] or 'the customer'} has been told."
        if action == "suggest":
            if not window_key:
                return "❌ Which time? Use action=windows for the open ones, then pass its key as window_key."
            r = booking_flow.suggest(jobs_db, db_path, b["job_id"], window_key, actor=actor, edition=edition,
                                     settings=s, note=message)
            return f"✅ Suggested {r['label']} to {b['customer'] or 'the customer'} — waiting for their answer."
        if action == "decline":
            r = booking_flow.decline(jobs_db, db_path, b["job_id"], actor=actor, edition=edition, settings=s,
                                     message=message, keep_request=bool(keep_request))
            return f"✅ {b['job_id']} declined ({r['status']}); the customer has been told."
    except booking_flow.BookingError as e:
        return f"❌ {e}"
    return "❌ action must be list, windows, approve, suggest or decline."


# ── the agent's queue (desk_agent.py; desk-agent-spec §7, booking-agent-spec) ─

def _agent_ok(actor, edition) -> str:
    a = rules.normalize_actor(actor)
    if a["role"] not in (rules.OWNER, rules.MANAGER):
        return "❌ Only the owner or a manager can run or review the agent."
    return ""


def _agent_may(db_path, actor, edition, kind, ref) -> bool:
    """David 2026-11-05: on a server a chat's agent tools follow the user's role and scope, not just "owner or manager".
    The owner (and a personal install) sees everything; a manager gets a ticket only if they may view it (their queues
    or the shared inbox), a booking only if they may approve bookings, and the Jobs agent's work as in the Jobs app.
    HR never goes through these tools."""
    a = rules.normalize_actor(actor)
    if edition != rules.BUSINESS or a["role"] == rules.OWNER:
        return True
    if a["role"] != rules.MANAGER or kind == "hr":
        return False
    if kind == "ticket":
        try:
            t = desk_db.get_ticket(db_path, ref)
        except desk_db.DeskError:
            return False
        d = rules.can(actor, "view", t, edition=edition)
        return bool(getattr(d, "allowed", d))
    if kind == "booking":
        import booking_flow
        return bool(booking_flow.can_approve(actor, edition, desk_db.get_settings(db_path)))
    return kind in ("job", "route")


def _agent_row(db, table, key, n):
    import desk_agent
    conn = desk_agent._conn(db)
    try:
        r = conn.execute(f"SELECT * FROM {table} WHERE {key} = ?", (int(n),)).fetchone()
    finally:
        conn.close()
    return dict(r) if r else None


JOBS_PREFIX = "J"           # Jobs agent items / suggestions live in the agent's own database


def _jobs_agent_db():
    """The Jobs agent's database when it's switched on, else None."""
    try:
        import desk_agent_store
        from pathlib import Path
        p = desk_agent_store.path()
        js = desk_agent_store.settings(p) if Path(p).exists() else {}
        if js.get("agent_jb_enabled") or js.get("agent_jb_rt_enabled"):
            return p
    except Exception:  # noqa: BLE001
        pass
    return None


def _hr_agent_db():
    """The HR agent's database when it's switched on, else None."""
    try:
        import desk_agent_hr_store
        from pathlib import Path
        p = desk_agent_hr_store.path()
        if Path(p).exists() and desk_agent_hr_store.settings(p).get("agent_hr_enabled"):
            return p
    except Exception:  # noqa: BLE001
        pass
    return None


def _hr_reviewable(hdb, actor, rows) -> list:
    """The HR agent's suggestions this person may review (decision 2): the owner all of them, a
    manager only their own team's time off when the owner allowed it."""
    import desk_agent_hr_store
    import desk_hr_agent
    s = desk_agent_hr_store.all_settings(hdb)
    return [r for r in rows if desk_hr_agent.can_review(actor, r, s)[0]]


def hr_agent(actor, edition, *, action="status", tickets_db=None, business="") -> str:
    """The HR agent from a chat: counts and Run now only. Its suggestions are reviewed in HR Admin
    (🤖 Agent) — HR details are never handed to a chat AI (decision 5)."""
    import desk_agent
    import desk_agent_hr_store
    import desk_agent_settings as das
    a = rules.normalize_actor(actor)
    if a["role"] != rules.OWNER:
        return "❌ Only the owner can use this. HR reviews the HR agent's work in HR Admin → 🤖 Agent."
    adb = desk_agent_hr_store.init()
    s = desk_agent_hr_store.sync_shared(tickets_db, adb)
    provider, why = das.hr_runner(s, edition)
    action = (action or "status").strip().lower().replace(" ", "_")
    if action == "run_now":
        if not s.get("agent_hr_enabled"):
            return "👥 The HR agent is off (AI-Prowler → 🏢 Small Business → 👥 HR Agent & settings)."
        if why:
            return f"👥 Not started: {why}"
        desk_agent.retry_errors(adb)
        w = desk_agent.why_not_run(adb, s, edition=edition, now=desk_agent._now(), force=True)
        if w:
            return f"👥 Not started: {w}."
        return ("👥 Started — its suggestions show in HR Admin → 🤖 Agent." if
                desk_agent.run_in_background(adb, edition=edition, business=business, force=True)
                else "👥 A run is already going.")
    st = desk_agent.status(adb)
    return (f"👥 HR agent {'on' if s.get('agent_hr_enabled') else 'off'}"
            + (" (practice mode)" if s.get("agent_hr_shadow") else "")
            + f". Runner: {provider or 'none allowed'}" + (f" — {why}" if why else "")
            + f". Waiting in its queue: {st['waiting']}. Waiting for HR: {st['pending']}. "
              "Review them in HR Admin → 🤖 Agent (HR details stay out of chats).")


def _split_id(x):
    """('jobs', 12) for "J12", ('desk', 12) for 12 / "12"."""
    s = str(x or "").strip().upper()
    if s.startswith(JOBS_PREFIX):
        return "jobs", int(s[1:] or 0)
    return "desk", int(s or 0)


def desk_agent_review(db_path, actor, edition, *, action="list", proposal_id=0, edits=None, kind="",
                      business="", jobs_db=None) -> str:
    """The person's side: list what's waiting, approve / edit / reject, 👍 (up) / 👎 (down) practice work.
    Jobs agent suggestions have ids starting with J."""
    import json as _json

    import desk_agent
    bad = _agent_ok(actor, edition)
    if bad:
        return bad
    action = (action or "list").strip().lower()
    if action in ("list", "practice"):
        st = "pending" if action == "list" else "practice"
        rows = [] if kind in ("job", "route") else desk_agent.inbox(db_path, status=st, kind=kind, unrated=st == "practice")
        adb = _jobs_agent_db()
        if adb and kind in ("", "job", "route"):
            rows += [dict(x, proposal_id=f"{JOBS_PREFIX}{x['proposal_id']}")
                     for x in desk_agent.inbox(adb, status=st, kind=kind, unrated=st == "practice")]
        rows = [r for r in rows if _agent_may(db_path, actor, edition, r["kind"], r["ref"])]
        if not rows:
            return "🤖 Nothing waiting for review." if action == "list" else "🤖 No practice results."
        return "\n".join([f"🤖 {len(rows)} item(s):"] + [
            f"• #{r['proposal_id']} {r['kind']} {r['ref']} — {r['stage']}: {r['action']} "
            f"{_json.dumps(r['payload'], ensure_ascii=False)[:160]} — why: {r['why']}"
            + (f" (waiting because {r['hold_reason']})" if r.get("hold_reason") else "") for r in rows[:30]])
    if isinstance(edits, str) and edits.strip():
        try:
            edits = _json.loads(edits)
        except ValueError:
            return "❌ edits must be JSON, e.g. {\"body\": \"…\"}"
    try:
        where, n = _split_id(proposal_id)
    except ValueError:
        return "❌ proposal_id must be a number (or J and a number for a Jobs agent suggestion)"
    db = db_path
    if where == "jobs":
        import desk_agent_store
        db = desk_agent_store.path()
    row = _agent_row(db, "agent_proposals", "proposal_id", n)
    if row and not _agent_may(db_path, actor, edition, row["kind"], row["ref"]):
        return "❌ That suggestion is outside what you can see."
    try:
        out = desk_agent.review(db, n, action, actor_=actor, edition=edition,
                                edits=edits or None, business=business, jobs_db=jobs_db)
    except desk_db.DeskError as e:
        return f"❌ {e}"
    return f"✅ #{proposal_id}: {out.get('status') or out.get('feedback')}" + (f" — {out['result']}" if out.get("result") else "")


def desk_agent_status(db_path, actor, edition) -> str:
    import desk_agent
    bad = _agent_ok(actor, edition)
    if bad:
        return bad
    st = desk_agent.status(db_path)
    own = (f" Runs on its own; spent ${st['spent_usd']:.2f} of ${st['budget_usd']:.0f} this month."
           if st.get("runs_on_its_own") else (f" Doesn't run on its own: {st['ready_note']}." if st.get("ready_note") else ""))
    out = (f"🤖 Agent {'on' if st['enabled'] else 'off'} (bookings {'on' if st['booking_enabled'] else 'off'}), "
           f"runs on: {st['provider']}.{own} Waiting in the queue: {st['waiting']}. Waiting for review: "
           f"{st['pending']}. Practice results: {st['practice']} (you rated {st['rated_good']} good, "
           f"{st['rated_not_right']} not right).")
    adb = _jobs_agent_db()
    if adb:
        js = desk_agent.status(adb)
        out += (f"\n🧰 Jobs agent on — waiting in its queue: {js['waiting']}, waiting for review: {js['pending']}, "
                f"practice results: {js['practice']}.")
    return out


def jobs_agent(actor, edition, *, action="status", proposal_id="", edits=None, settings=None, tickets_db=None,
               business="", jobs_db=None) -> str:
    """The Jobs agent from the Jobs app or a chat (works with Service Desk off). JSON back.
    status · list · practice · approve / edit / reject / up / down (proposal_id) · run_now ·
    settings · set (settings = {key: value}). Reviewing: owner or manager; settings, run_now:
    owner (on a server, settings are changed at the server PC)."""
    import json as _json

    import desk_agent
    import desk_agent_settings as das
    import desk_agent_store
    a = rules.normalize_actor(actor)
    action = (action or "status").strip().lower().replace("-", "_").replace(" ", "_")
    if a["role"] not in (rules.OWNER, rules.MANAGER):
        return _json.dumps({"ok": False, "error": "Only the owner or a manager can use the Jobs agent."})
    adb = desk_agent_store.init()

    def ok(**kw):
        return _json.dumps({"ok": True, **kw}, default=str, ensure_ascii=False)

    def pid(x):
        return f"{JOBS_PREFIX}{x['proposal_id']}"
    try:
        s = desk_agent_store.sync_shared(tickets_db, adb)
        if action in ("status", "settings"):
            jb = desk_agent_store.settings(adb)
            st = desk_agent.status(adb)
            counts = {}
            for x in desk_agent.inbox(adb, status="pending"):
                counts[f"{x['kind']}:{x['stage']}"] = counts.get(f"{x['kind']}:{x['stage']}", 0) + 1
            out = {"enabled": bool(jb.get("agent_jb_enabled")), "practice": bool(jb.get("agent_jb_shadow")),
                   "route_enabled": bool(jb.get("agent_jb_rt_enabled")),
                   "route_practice": bool(jb.get("agent_jb_rt_shadow")),
                   "waiting": st["waiting"], "pending": st["pending"], "practice_results": st["practice"],
                   "provider": das.effective_provider(s, edition), "runs_on_its_own": st.get("runs_on_its_own"),
                   "ready_note": st.get("ready_note"), "by_stage": counts,
                   "spent_usd": st.get("spent_usd"), "budget_usd": st.get("budget_usd"),
                   "rated_good": st.get("rated_good"), "rated_not_right": st.get("rated_not_right"), "rated_by": st.get("rated_by"),
                   "can_change_settings": a["role"] == rules.OWNER and not rules.server_locked(edition)}
            if action == "settings":
                out.update(settings=jb, options=das.jb_ui_options(), jb_flow=das.jobs_flow(jb, edition),
                           rt_flow=das.route_flow(jb, edition), mode_colors=das.MODE_COLORS,
                           mode_labels=das.STAGE_MODE_LABELS)
            return ok(**out)
        if action in ("list", "practice"):
            st = "pending" if action == "list" else "practice"
            rows = desk_agent.inbox(adb, status=st, limit=100, unrated=st == "practice")
            if st == "pending":                       # 2026-11-03: paused while its agent is off (Reject only)
                rows = desk_agent.mark_paused(adb, rows)
            return ok(items=[dict(x, proposal_id=pid(x)) for x in rows])
        if action == "set":
            if a["role"] != rules.OWNER:
                return _json.dumps({"ok": False, "error": "Only the owner can change the Jobs agent's settings."})
            if rules.server_locked(edition):
                return _json.dumps({"ok": False, "error": rules.SERVER_LOCK_MSG})
            vals = _json.loads(settings) if isinstance(settings, str) else (settings or {})
            desk_agent_store.set_settings({str(k): v for k, v in vals.items()}, actor=actor, edition=edition,
                                          db=adb)                  # all or nothing (F-6)
            jb = desk_agent_store.settings(adb)
            return ok(settings=jb, jb_flow=das.jobs_flow(jb, edition), rt_flow=das.route_flow(jb, edition))
        if action == "flow":                                  # redraw for unsaved choices
            vals = _json.loads(settings) if isinstance(settings, str) else (settings or {})
            return ok(jb_flow=desk_agent_store.flow(edition, adb, vals),
                      rt_flow=desk_agent_store.flow(edition, adb, vals, which="route"))
        if action == "run_now":
            if a["role"] != rules.OWNER:
                return _json.dumps({"ok": False, "error": "Only the owner can start the agent."})
            desk_agent.retry_errors(adb)
            why = desk_agent.why_not_run(adb, s, edition=edition, now=desk_agent._now(), force=True)
            if why:
                return ok(started=False, why=why)
            started = desk_agent.run_in_background(adb, edition=edition, business=business, jobs_db=jobs_db, force=True)
            return ok(started=started, why="" if started else "a run is already going")
        if action in ("approve", "edit", "reject", "up", "down"):
            where, n = _split_id(proposal_id if str(proposal_id).upper().startswith(JOBS_PREFIX)
                                 else f"{JOBS_PREFIX}{proposal_id}")
            if isinstance(edits, str) and edits.strip():
                edits = _json.loads(edits)
            out = desk_agent.review(adb, n, action, actor_=actor, edition=edition, edits=edits or None,
                                    business=business, jobs_db=jobs_db)
            return ok(**dict(out, proposal_id=f"{JOBS_PREFIX}{n}"))
    except (desk_db.DeskError, ValueError) as e:
        return _json.dumps({"ok": False, "error": str(e)})
    return _json.dumps({"ok": False, "error": "action must be status, list, practice, approve, edit, reject, up, "
                                              "down, run_now, settings, set or flow"})


def desk_agent_run_now(db_path, actor, edition, *, business="") -> str:
    import desk_agent
    if rules.normalize_actor(actor)["role"] != rules.OWNER:
        return "❌ Only the owner can start the agent."
    jobs_note = ""
    adb = _jobs_agent_db()
    if adb:                                   # the Jobs agent's queue runs from its own database
        import desk_agent_store
        js = desk_agent_store.sync_shared(db_path, adb)
        desk_agent.retry_errors(adb)
        jwhy = desk_agent.why_not_run(adb, js, edition=edition, now=desk_agent._now(), force=True)
        if not jwhy and desk_agent.run_in_background(adb, edition=edition, business=business, force=True):
            jobs_note = " 🧰 The Jobs agent started too — its results show in the Jobs app's 🤖 Agent tab."
        else:
            jobs_note = f" 🧰 Jobs agent not started: {jwhy or 'a run is already going'}."
    desk_agent.retry_errors(db_path)
    why = desk_agent.why_not_run(db_path, desk_db.get_settings(db_path), edition=edition, now=desk_agent._now(),
                                 force=True)
    if why:
        return f"🤖 Not started: {why}." + jobs_note
    started = desk_agent.run_in_background(db_path, edition=edition, business=business, force=True)
    return ("🤖 Started — its results show in the Service Desk app's 🤖 Agent tab." if started else
            "🤖 A run is already going.") + jobs_note


# ── the one business Google Calendar (booking-spec.md §6; personal installs only) ──

def _calendar_ready(db_path, actor, edition, jobs_db):
    """(settings, jobs_db, error_text)."""
    import booking_calendar
    import desk_portal
    if edition == rules.BUSINESS:
        return None, None, "🏢 " + booking_calendar.ON_SERVER[0].upper() + booking_calendar.ON_SERVER[1:] + "."
    if rules.normalize_actor(actor)["role"] != rules.OWNER:
        return None, None, "❌ Only the owner can sync the business calendar."
    s = desk_db.get_settings(db_path)
    jobs_db = jobs_db or desk_portal._jobs_db()
    if not jobs_db:
        return None, None, "❌ The Jobs app isn't available on this AI-Prowler."
    if s.get("calendar_sync", "off") != "ai":
        return None, None, ("📅 Calendar sync is off. Turn it on in AI-Prowler → Service Desk → 🌐 Web forms → "
                            "Calendar & openings (or tickets_settings calendar_sync = ai).")
    return s, jobs_db, ""


def calendar_sync_busy(db_path, actor, edition, *, date_from, date_to, blocks=None, jobs_db=None) -> str:
    import booking_calendar
    s, jobs_db, err = _calendar_ready(db_path, actor, edition, jobs_db)
    if err:
        return err
    try:
        if isinstance(blocks, str):
            blocks = json.loads(blocks or "[]")
        out = booking_calendar.sync_busy(jobs_db, date_from, date_to, blocks or [], edition=edition,
                                         tickets_db=db_path, settings=s)
    except (booking_calendar.CalendarError, ValueError) as e:
        return f"❌ {e}"
    msg = f"✅ Busy times saved: {out['blocks']} block(s) for {date_from} – {date_to}"
    if out["skipped_own"]:
        msg += f" ({out['skipped_own']} of AI-Prowler's own events left out)"
    msg += "."
    if out["tickets"]:
        msg += f" ⚠️ {len(out['tickets'])} clash(es) with booked visits — ticket(s) {', '.join(out['tickets'])} opened."
    return msg + " Next: call calendar_pending_events."


def calendar_pending_events(db_path, actor, edition, *, jobs_db=None) -> str:
    import booking_calendar
    s, jobs_db, err = _calendar_ready(db_path, actor, edition, jobs_db)
    if err:
        return err
    items = booking_calendar.pending(jobs_db, edition=edition, settings=s)
    return json.dumps({"calendar": s.get("calendar_name") or "the business calendar", "items": items,
                       "next": ("For each item: new → create the event; update → change event_id; cancel → "
                                "delete event_id. Then call calendar_mark_synced with [{job_id, action, event_id}] "
                                "or [{job_id, error}]." if items else "Nothing to write — the calendar is up to date.")},
                      ensure_ascii=False)


def calendar_mark_synced(db_path, actor, edition, *, items=None, runner="ai", jobs_db=None) -> str:
    import booking_calendar
    s, jobs_db, err = _calendar_ready(db_path, actor, edition, jobs_db)
    if err:
        return err
    try:
        if isinstance(items, str):
            items = json.loads(items or "[]")
        out = booking_calendar.mark_synced(jobs_db, items or [], edition=edition, runner=runner)
    except (booking_calendar.CalendarError, ValueError) as e:
        return f"❌ {e}"
    msg = f"✅ {out['done']} calendar item(s) recorded."
    if out["errors"]:
        msg += f" {out['errors']} failed and will be offered again next sync."
    if out["unknown"]:
        msg += f" Not pending (ignored): {', '.join(out['unknown'][:10])}."
    return msg


def calendar_sync_status(db_path, actor, edition, *, jobs_db=None) -> str:
    import booking_calendar
    if edition == rules.BUSINESS:
        return "🏢 " + booking_calendar.ON_SERVER[0].upper() + booking_calendar.ON_SERVER[1:] + "."
    import desk_portal
    jobs_db = jobs_db or desk_portal._jobs_db()
    if not jobs_db:
        return "❌ The Jobs app isn't available on this AI-Prowler."
    s = desk_db.get_settings(db_path)
    st = booking_calendar.status(jobs_db, s, edition=edition)
    lines = [booking_calendar.status_line(st)]
    for e in st["errors"][:10]:
        lines.append(f"  • {e['job_id']} ({e['action']}): {e['error']}")
    for c in st["clashes"][:5]:
        lines.append(f"  • clash {c['job_id']} vs busy {c['start_at']}–{c['end_at'][11:]} → {c.get('ticket_id') or 'no ticket'}")
    if st["on"]:
        lines.append("To sync: \"" + booking_calendar.sync_prompt(s) + "\"")
    return "\n".join(lines)


def assign_ticket(db_path, actor, edition, *, ticket_id, assignee, expected_version=None) -> str:
    def go():
        t = desk_db.assign_ticket(db_path, ticket_id.strip().upper(), assignee.strip(),
                                  actor=actor, edition=edition,
                                  expected_version=expected_version)
        return f"✅ {t['ticket_id']} is assigned to {t['assignee']} ({t['state']})."
    return _run(go)


def set_ticket_state(db_path, actor, edition, *, ticket_id, state, reason="",
                     expected_version=None, approved_by=None) -> str:
    def go():
        want = next((s for s in rules.STATES if s.lower() == (state or "").strip().lower()), state)
        t = desk_db.change_state(db_path, ticket_id.strip().upper(), want, actor=actor,
                                 edition=edition, reason=reason,
                                 expected_version=expected_version, approved_by=approved_by)
        hint = ""
        if t["state"] == rules.FIXED and not t.get("resolution"):
            hint = (" Write a one-paragraph resolution for the record with "
                    "update_ticket(resolution=...) — read it back first.")
        return f"✅ {t['ticket_id']} is now {t['state']}.{hint}"
    return _run(go)


def add_ticket_note(db_path, actor, edition, *, ticket_id, note) -> str:
    def go():
        m = desk_db.add_message(db_path, ticket_id.strip().upper(), note, actor=actor,
                                edition=edition, visibility="internal", channel="claude")
        return f"✅ Internal note added to {m['ticket_id']} (never shown to customers or subcontractors)."
    return _run(go)


def reply_to_customer(db_path, actor, edition, *, ticket_id, message, preview=True) -> str:
    """Public reply to the ticket's customer or subcontractor. preview=True
    (default) shows exactly what would be sent and writes nothing."""
    def go():
        tid = ticket_id.strip().upper()
        t = desk_db.get_ticket(db_path, tid, actor=actor, edition=edition)
        if t is None:
            raise desk_db.NotFoundError(f"no ticket {tid} that you can see")
        d = rules.can(actor, "reply_customer", t, edition=edition)
        if not d:
            raise desk_db.DeskError(d.reason)
        body = (message or "").strip()
        if not body:
            return "❌ Nothing to send — give the message text."
        c = desk_db.get_contact(db_path, t["contact_id"]) if t.get("contact_id") else None
        who = (c.get("name") or c.get("phone") or c.get("email")) if c else "nobody (no contact on file)"
        via = "email" if c and c.get("email") else "text (SMS)" if c and c.get("phone") else "—"
        if preview:
            return (f"📝 PREVIEW — not sent yet.\nTo: {who} ({KIND_LABEL[t['kind']]}) by {via}\n"
                    f"Message: {body}\n(A link to their status page is added.)\n"
                    f"Read this back; call again with preview=false only after a clear yes.")
        desk_db.add_message(db_path, tid, body, actor=actor, edition=edition,
                            visibility="public", channel="claude", author_kind="claude")
        return f"✅ Sent to {who} by {via} on {tid}. Delivery status shows on the ticket."
    return _run(go)


def create_job_from_ticket(db_path, actor, edition, *, ticket_id, service_date, create_job_fn,
                           service_type="", customer_id="", notes="", notify_customer=True,
                           allow_unscheduled=False) -> str:
    """Turn a re-do or service request into a Jobs app job. create_job_fn(updates)
    is the Jobs app's create_job; it returns text with NEW_JOB_ID=JOB-####."""
    def go():
        tid = ticket_id.strip().upper()
        t = desk_db.get_ticket(db_path, tid, actor=actor, edition=edition)
        if t is None:
            raise desk_db.NotFoundError(f"no ticket {tid} that you can see")
        if not rules.can(actor, "edit", t, edition=edition):
            raise desk_db.DeskError("only the assignee, a manager or the owner can schedule work from this ticket")
        if not rules.feature_enabled(edition, "jobs_links"):
            raise desk_db.DeskError("jobs links are not available in this edition")
        cust = (customer_id or t.get("customer_id") or "").strip()
        if not cust:
            return ("❌ This ticket isn't linked to a customer in the Jobs app. Link it first "
                    "(update_ticket customer_id=CUST-####) or pass customer_id.")
        no_date = allow_unscheduled and not (service_date or "").strip()   # the agent's approved re-do with no date
        d = None if no_date else due_iso(service_date)      # validates the date
        day = (service_date or "").strip()[:10]
        updates = {"CustomerID": cust, "Job Status": "Unscheduled" if no_date else "Scheduled",
                   # 2026-11-04: this key was "Notes", which jobs don't have, so the text was silently dropped
                   "Service Details / Notes": (f"From Service Desk {tid}: {t['title']}" + (f" — {notes}" if notes else ""))[:500]}
        if not no_date:
            updates["Service Date"] = day
        if service_type:
            updates["Service Type"] = service_type
        out = str(create_job_fn(updates))
        import re as _re
        m = _re.search(r"NEW_JOB_ID=(JOB-\d+)", out)
        if not m:
            return f"❌ The Jobs app did not create the job: {out[:300]}"
        job = m.group(1)
        fields = {"customer_id": cust}
        if not t.get("job_id"):
            fields["job_id"] = job
        desk_db.update_ticket(db_path, tid, fields, actor=actor, edition=edition)
        desk_db.add_message(db_path, tid, (f"Created {job}, not scheduled yet" if no_date else f"Scheduled {job} for {day}")
                            + (f" ({service_type})" if service_type else ""),
                            actor=actor, edition=edition, visibility="internal", channel="claude")
        if no_date:
            return f"✅ Created {job} from {tid}, not scheduled yet."
        told = ""
        if notify_customer and t["kind"] == rules.EXTERNAL and t.get("contact_id"):
            desk_db.add_message(db_path, tid, f"We've scheduled a return visit for {day}.",
                                actor=actor, edition=edition, visibility="public", channel="claude",
                                author_kind="claude")
            told = " The customer was told the date."
        return f"✅ Created {job} for {day} from {tid}.{told}" + ("" if d else "")
    return _run(go)


# ── Phase 3: teams, reports, data ────────────────────────────────────────────

def manage_ticket_queues(db_path, actor, edition, *, action="list", queue_id="", name="",
                         members="", default_assignee="") -> str:
    import desk_routing as rt

    def go():
        if not rules.tool_available(edition, "manage_ticket_queues"):
            return "❌ Queues are a Business feature — on a personal install every ticket goes to you."
        if action == "list":
            qs = rt.list_queues(db_path)
            if not qs:
                return "No queues yet. Create one with action='save', queue_id, name and members."
            return "Queues:\n" + "\n".join(
                f"  • {q['queue_id']} — {q['name']}: {', '.join(q['members']) or 'no members'}"
                + (f" (default {q['default_assignee']})" if q['default_assignee'] else "") for q in qs)
        if action in ("save", "delete") and rules.server_locked(edition):
            return rules.SERVER_LOCK_MSG
        if action == "save":
            mem = [m.strip() for m in (members.split(",") if isinstance(members, str) else members or [])]
            q = rt.upsert_queue(db_path, queue_id, name=name, members=mem,
                                default_assignee=default_assignee or None, actor=actor, edition=edition)
            return f"✅ Saved queue {q['queue_id']} ({', '.join(q['members']) or 'no members'})."
        if action == "delete":
            rt.delete_queue(db_path, queue_id, actor=actor, edition=edition)
            return f"✅ Deleted queue {queue_id}."
        return "❌ action must be list, save or delete"
    return _run(go)


def manage_ticket_rules(db_path, actor, edition, *, action="list", rule_id="", match=None,
                        send_to_user="", send_to_queue="", order=100, enabled=True,
                        type_id="", type_name="", type_kind="external", default_queue="",
                        default_priority="P3") -> str:
    import desk_routing as rt

    def go():
        if action == "list":
            lines = []
            for r in rt.list_rules(db_path):
                lines.append(f"  {r['sort_order']:>3}. {r['rule_id']}: {r['match']} → {r['action']}"
                             + ("" if r["enabled"] else " (off)"))
            for t in rt.list_types(db_path):
                lines.append(f"  type {t['type_id']} ({t['name']}, {t['kind']}) → queue "
                             f"{t['default_queue'] or '—'}, {t['default_priority']}")
            return "Assignment rules and ticket types:\n" + ("\n".join(lines) or "  none yet")
        if rules.server_locked(edition):
            return rules.SERVER_LOCK_MSG
        if action == "save_rule":
            if not rules.feature_enabled(edition, "assignment_rules"):
                return "❌ Assignment rules are a Business feature."
            act = {"user": send_to_user} if send_to_user else {"queue": send_to_queue}
            m = match if isinstance(match, dict) else json.loads(match or "{}")
            r = rt.upsert_rule(db_path, rule_id, match=m, action=act, sort_order=int(order),
                               enabled=bool(enabled), actor=actor, edition=edition)
            return f"✅ Saved rule {r['rule_id']}: {r['match']} → {r['action']}."
        if action == "delete_rule":
            rt.delete_rule(db_path, rule_id, actor=actor, edition=edition)
            return f"✅ Deleted rule {rule_id}."
        if action == "save_type":
            t = rt.upsert_type(db_path, type_id, name=type_name, kind=type_kind,
                               default_queue=default_queue or None, default_priority=default_priority,
                               actor=actor, edition=edition)
            return f"✅ Saved ticket type {t['type_id']} ({t['name']})."
        return "❌ action must be list, save_rule, delete_rule or save_type"
    return _run(go)


def ticket_report(db_path, actor, edition, *, since="", until="", group_by="") -> str:
    import desk_reports

    def go():
        rep = desk_reports.report(db_path, actor=actor, edition=edition, since=(since or "").strip(),
                                  until=(until or "").strip(), group_by=group_by)
        return desk_reports.report_text(rep)
    return _run(go)


def exports_dir(db_path) -> "Path":
    from pathlib import Path
    p = Path(desk_db.root_for(db_path)) / "exports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def imports_dir(db_path) -> "Path":
    from pathlib import Path
    p = Path(desk_db.root_for(db_path)) / "imports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def export_tickets(db_path, actor, edition, *, format="xlsx", ticket_id="", since="", until="",
                   state="", kind="", customer_id="", include_internal=False) -> str:
    import desk_data

    def go():
        name, data, _mime = desk_data.export(
            db_path, format, actor=actor, edition=edition, ticket_id=ticket_id,
            include_internal=bool(include_internal),
            filters={"since": (since or "").strip(), "until": (until or "").strip(),
                     "state": state, "kind": kind, "customer_id": customer_id})
        path = exports_dir(db_path) / name
        path.write_bytes(data)
        return (f"✅ Exported {name} ({len(data) // 1024 or 1} KB) to {path}\n"
                f"Exports are a copy — editing the file never changes the live tickets.")
    return _run(go)


def import_tickets(db_path, actor, edition, *, filename="", dry_run=True, column_map=None,
                   undo_batch_id="", backup_fn=None) -> str:
    import desk_data

    def go():
        if (undo_batch_id or not dry_run) and rules.server_locked(edition):
            return rules.SERVER_LOCK_MSG              # a dry run changes nothing, so it's allowed
        if undo_batch_id:
            out = desk_data.undo_import(db_path, undo_batch_id, actor=actor, edition=edition)
            return f"✅ Undid import {undo_batch_id}: removed {len(out['removed'])} ticket(s)."
        from pathlib import Path
        base = imports_dir(db_path).resolve()
        p = (base / Path(filename).name).resolve()
        if p.parent != base or not p.is_file():
            return (f"❌ Put the file in the Service Desk imports folder first ({base}) — or upload it "
                    f"in the Service Desk app (Settings → Data) — then give its file name.")
        cmap = column_map if isinstance(column_map, dict) else json.loads(column_map or "{}")
        out = desk_data.import_tickets(db_path, p.read_bytes(), p.name, actor=actor, edition=edition,
                                       dry_run=bool(dry_run), column_map=cmap, backup_fn=backup_fn)
        head = "🔎 DRY RUN — nothing imported yet." if out["dry_run"] else \
            f"✅ Imported {len(out.get('added', []))} ticket(s) as batch {out.get('batch_id')} (no alerts sent; undo for 7 days)."
        lines = [head, f"Rows: {out['rows']}, to add: {out['to_add']}, duplicates: {len(out['duplicates'])}, "
                       f"invalid: {len(out['invalid'])}"]
        for b in out["invalid"][:10]:
            lines.append(f"  row {b.get('row')}: {', '.join(b['problems'])}")
        if out["dry_run"] and out["to_add"]:
            lines.append("Call again with dry_run=false to import (a backup is taken first).")
        return "\n".join(lines)
    return _run(go)


def tickets_backup_now(db_path, actor, edition) -> str:
    import desk_backup

    def go():
        if not rules.can(actor, "backup", edition=edition):
            return "❌ Only the owner can run Service Desk backups."
        b = desk_backup.backup_now(db_path, "manual")
        return (f"{'✅' if b['verified'] else '⚠️'} Backup {b['name']} — {b['bytes'] // 1024 or 1} KB, "
                f"{'verified' if b['verified'] else 'FAILED its integrity check'}."
                + (f" Second copy: {b['second_copy']}" if b["second_copy"] else ""))
    return _run(go)


def list_tickets_backups(db_path, actor, edition) -> str:
    import desk_backup

    def go():
        if not rules.can(actor, "backup", edition=edition):
            return "❌ Only the owner can see Service Desk backups."
        items = desk_backup.list_backups(db_path)
        if not items:
            return "No Service Desk backups yet."
        return "Service Desk backups (newest first):\n" + "\n".join(
            f"  • {b['name']} — {b['trigger']}, {b['bytes'] // 1024 or 1} KB, "
            f"{'verified' if b['verified'] else 'NOT verified'}" for b in items[:40])
    return _run(go)


BACKUP_KEYS = ("backup_enabled", "backup_frequency", "backup_hour", "backup_keep_daily",
               "backup_keep_weekly", "backup_keep_monthly", "backup_attachments", "backup_second_dir")


def tickets_backup_settings(db_path, actor, edition, **changes) -> str:
    def go():
        if not rules.can(actor, "backup", edition=edition):
            return "❌ Only the owner can change Service Desk backups."
        if rules.server_locked(edition) and any(v not in (None, "") for v in changes.values()):
            return rules.SERVER_LOCK_MSG
        for k, v in changes.items():
            if v is None or v == "":
                continue
            if k not in BACKUP_KEYS:
                return f"❌ unknown backup setting {k}"
            cur = desk_db.SETTING_DEFAULTS[k]
            if isinstance(cur, bool) and isinstance(v, str):
                v = v.strip().lower() in ("true", "on", "yes", "1")
            elif isinstance(cur, int) and not isinstance(cur, bool):
                v = int(v)
            desk_db.set_setting(db_path, k, v, actor=actor, edition=edition)
        s = desk_db.get_settings(db_path)
        return "Service Desk backups:\n" + "\n".join(f"  • {k} = {s[k]}" for k in BACKUP_KEYS)
    return _run(go)


def restore_tickets_database(db_path, actor, edition, *, backup_name, ticket_id="", confirm=False) -> str:
    import desk_backup

    def go():
        if rules.server_locked(edition):
            return rules.SERVER_LOCK_MSG
        out = desk_backup.restore(db_path, backup_name, actor=actor, edition=edition,
                                  confirm=bool(confirm), ticket_id=ticket_id)
        if not out["ok"]:
            return "⚠️ " + out["message"]
        return (f"✅ Restored {out['restored']} from {backup_name}. A safety backup of the data "
                f"as it was is {out['safety_backup']}.")
    return _run(go)


# ── Phase 4: AI assist ───────────────────────────────────────────────────────

def search_tickets(db_path, actor, edition, *, query, include_closed=True, limit=10) -> str:
    import desk_ai

    def go():
        hits = desk_ai.search(db_path, query, actor=actor, edition=edition,
                              include_closed=bool(include_closed), limit=int(limit or 10))
        if not hits:
            return "No tickets match those words."
        lines = [f"{len(hits)} match(es), best first:"]
        for h in hits:
            lines.append("  " + ticket_line(h) + (f" — fix: {h['resolution'][:120]}" if h.get("resolution") else ""))
        return "\n".join(lines)
    return _run(go)


def ticket_summary(db_path, actor, edition, *, ticket_id="", queue_id="", learnings=False) -> str:
    import desk_ai

    def go():
        if learnings:
            sug = desk_ai.learning_suggestions(db_path, actor=actor, edition=edition)
            if not sug:
                return "No repeated fixes yet (needs 3+ resolved tickets of the same kind)."
            return "Repeated fixes you might save as a learning (ask before calling record_learning):\n" + "\n".join(
                f"  • {s['topic']}: {s['count']} tickets ({', '.join(s['tickets'])}); common words: "
                f"{', '.join(s['common_words'])}. e.g. “{s['examples'][-1]}”" for s in sug)
        if ticket_id:
            return desk_ai.summary(db_path, ticket_id, actor=actor, edition=edition)
        return desk_ai.queue_summary(db_path, actor=actor, edition=edition, queue_id=queue_id)
    return _run(go)


def triage_inbox(db_path, actor, edition, *, limit=20) -> str:
    import desk_ai

    def go():
        items = desk_ai.triage(db_path, actor=actor, edition=edition, limit=int(limit or 20))
        if not items:
            return "Nothing to triage — every open ticket has an owner and a type."
        lines = [f"{len(items)} ticket(s) to triage. Suggestions only — nothing has changed. "
                 f"Read them back, adjust with the person, then call apply_triage with the approved ones."]
        for it in items:
            s, w, c = it["suggest"], it["why"], it["current"]
            lines.append(f"• {it['ticket_id']} “{it['title']}” — {it['description'][:140]}")
            lines.append(f"    priority {c['priority']}→{s['priority']} ({w['priority']}); "
                         f"type {c['type'] or '—'}→{s['type'] or '—'} ({w['type']}); "
                         f"assignee {c['assignee'] or '—'}→{s['assignee'] or '—'} ({w['assignee']})"
                         + (f"; possible duplicate of {', '.join(it['possible_duplicates'])}" if it['possible_duplicates'] else ""))
        return "\n".join(lines)
    return _run(go)


def apply_triage(db_path, actor, edition, *, items) -> str:
    import desk_ai

    def go():
        data = items if isinstance(items, list) else json.loads(items or "[]")
        if not data:
            return "❌ Pass the approved items, e.g. [{\"ticket_id\": \"T-0042\", \"priority\": \"P2\"}]."
        return "\n".join(desk_ai.apply_triage(db_path, data, actor=actor, edition=edition))
    return _run(go)


def link_ticket(db_path, actor, edition, *, ticket_id, kind, target) -> str:
    import desk_ai

    def go():
        t = desk_ai.link(db_path, ticket_id, kind, target, actor=actor, edition=edition)
        return f"✅ Linked {t['ticket_id']} → {kind} {target}."
    return _run(go)


def merge_tickets(db_path, actor, edition, *, primary_id, duplicate_id, confirm=False) -> str:
    import desk_ai

    def go():
        p = desk_db.get_ticket(db_path, primary_id.strip().upper(), actor=actor, edition=edition)
        d = desk_db.get_ticket(db_path, duplicate_id.strip().upper(), actor=actor, edition=edition)
        if p is None or d is None:
            raise desk_db.NotFoundError("one of those tickets doesn't exist or you can't see it")
        if not confirm:
            return (f"⚠️ Merge {d['ticket_id']} “{d['title']}” INTO {p['ticket_id']} “{p['title']}”? Its "
                    f"messages, photos and status links move to {p['ticket_id']} and {d['ticket_id']} is "
                    f"closed. Call again with confirm=true only after a clear yes.")
        out = desk_ai.merge(db_path, primary_id, duplicate_id, actor=actor, edition=edition)
        return f"✅ Merged {out['closed']} into {out['primary']} ({out['messages_moved']} message(s) moved)."
    return _run(go)


def ticket_updates_json(db_path, actor, edition, *, since="") -> str:
    try:
        out = desk_db.get_ticket_updates(db_path, since or "", actor=actor, edition=edition)
    except desk_db.DeskError as e:
        return json.dumps({"ok": False, "error": str(e)})
    return json.dumps({"ok": True, **out}, default=str)


def ticket_watchers(db_path, actor, edition, *, ticket_id, add="", remove="", directory_fn=None) -> str:
    """Show / add / remove the internal people emailed when a ticket changes
    state. add / remove: comma-separated names or emails — a name is looked up
    in the same address list the app suggests (team, saved contacts, Jobs
    customers, past ticket contacts)."""
    import desk_http

    def go():
        tid = ticket_id.strip().upper()
        if desk_db.get_ticket(db_path, tid, actor=actor, edition=edition) is None:
            raise desk_db.NotFoundError(f"no ticket {tid} that you can see")
        book = []

        def resolve(who):
            who = who.strip()
            if desk_db._EMAIL_RE.match(who.lower()):
                return who.lower(), ""
            if not book:
                book.extend(desk_http.directory(db_path, actor, {"directory": directory_fn} if directory_fn else {}))
            low = who.lower()
            hits = [e for e in book if e["name"].lower() == low] or \
                   [e for e in book if low in e["name"].lower()]
            if len(hits) == 1:
                return hits[0]["email"], hits[0]["name"]
            if not hits:
                raise desk_db.DeskError(f"no email on file for {who!r} — say the address instead")
            raise desk_db.DeskError(f"{who!r} could be " + ", ".join(
                f"{e['name']} <{e['email']}>" for e in hits[:6]) + " — which one?")
        done = []
        for who in [w for w in (add or "").split(",") if w.strip()]:
            em, nm = resolve(who)
            desk_db.set_watcher(db_path, tid, em, name=nm, actor=actor, edition=edition)
            done.append(f"added {nm or em}")
        for who in [w for w in (remove or "").split(",") if w.strip()]:
            em, nm = resolve(who)
            desk_db.set_watcher(db_path, tid, em, remove=True, actor=actor, edition=edition)
            done.append(f"removed {nm or em}")
        ws = desk_db.list_watchers(db_path, tid)
        listing = ", ".join(f"{w['name']} <{w['email']}>" if w["name"] else w["email"] for w in ws) or "nobody yet"
        return (("✅ " + "; ".join(done) + ". ") if done else "") + \
            f"Watching {tid} (emailed on every change of state): {listing}."
    return _run(go)


SETTING_HELP = {
    "customer_status_updates": "tell the customer, in one line, when their request is in progress and when it's closed",
    "own_tickets": "the Owner can file tickets to himself (Solo)",
    "subcontractor_tickets": "the Owner can open tickets about a subcontractor",
    "sms_fallback_default": "new tickets also alert by SMS",
    "alert_email": "where the owner's Service Desk alerts are emailed (personal installs)",
    "alert_phone": "the owner's mobile for SMS alerts (personal installs)",
    "portal_enabled": "customers can file requests online at /support/new",
    "sms_new_request_mode": "a text that isn't a reply: off, create (open a ticket), ask (reply YES/NO), link (send the form link)",
    "email_new_request_mode": "an email that isn't a reply: off or create",
    "email_intake": "read the AI-Prowler email account for ticket replies (IMAP)",
    "csat_enabled": "ask customers to rate a closed request",
    "auto_close_days": "close a Fixed customer ticket after this many days with no reply from the customer (0 = never)",
    "digest_hour": "hour of the morning digest email (0-23)",
    "booking_paths": "which choices the customer page offers: book (a service at an open time), buy (the Shop — products with photos/specs, paid online), new (Get a quote — a call-back request), problem (report a problem)",
    "booking_welcome": "one optional welcome line at the top of the customer page",
    "booking_approval": ("approve_all = every booking waits for an approver (default); preapprove = windows that "
                         "meet the rules are booked at once (instant booking); auto = confirm every open window"),
    "booking_approve_managers": "on a server, managers can approve bookings as well as the owner (default on)",
    "booking_crew_mode": ("who picks the crew when a booking is confirmed: approver (default), suggested "
                          "(the suggested crew automatically) or office (no crew yet)"),
    "booking_backups": "how many backup windows a customer may pick besides their first choice (0-3)",
    "booking_hold_hours": "remind approvers about a booking still waiting after this many hours",
    "booking_release_hours": "after this many hours an undecided booking frees its window and the customer is told you'll call",
    "booking_suggest_hours": "how long a time you suggested waits for the customer to answer",
    "booking_customer_changes": "customers can reschedule or cancel from their request page",
    "booking_change_hours": "customers can't reschedule or cancel within this many hours of the visit",
    "booking_area_zips": "ZIP codes you serve (empty list = everywhere); requests from other ZIPs are still taken and flagged for a call back",
    "booking_window_minutes": "length of the arrival windows customers book, in minutes (e.g. 120 = 8–10, 10–12)",
    "booking_lead_hours": "nothing can be booked sooner than this many hours from now",
    "booking_horizon_days": "nothing can be booked more than this many days ahead",
    "booking_max_per_day": "most online bookings per day (0 = no limit)",
    "agent_bk_enabled": "the agent's Booking & scheduling section on/off (needs agent_enabled too)",
    "agent_bk_shadow": "practice mode for the booking agent only: it shows what it would do, nothing is booked, offered or sent",
    "agent_bk_stage_check": "booking agent — Check new bookings/requests (address, area, duplicates, history): off | suggest | auto",
    "agent_bk_stage_decide": "booking agent — Decide: recommend approve / another time / decline and the crew: off | suggest | auto",
    "agent_bk_stage_offer": "booking agent — Offer times to requests with no date: off | suggest | auto",
    "agent_bk_stage_reply": "booking agent — Answer customers about their visit: off | suggest | auto",
    "agent_bk_stage_track": "booking agent — Keep on track (chase answers, fill openings, weather): off | suggest | auto",
    "agent_bk_stage_learn": "booking agent — Learn real job times and customer preferences (always needs a person's OK): off | suggest | auto",
    "agent_bk_can_confirm": "let the booking agent confirm bookings itself — only with Decide on auto, practice off and every guardrail passing",
    "agent_bk_confirm_per_day": "most bookings the agent may confirm itself in one day (1-50)",
    "agent_bk_weather": "booking agent checks tomorrow's weather for outdoor services and offers a new time if rain/wind is likely",
    "agent_bk_check_hour": "hour (0-23) the booking agent checks tomorrow's visits (weather, overfull days)",
    "page_logo": "the customer pages' logo / icon (set in AI-Prowler → Service Desk → Web forms → Page look)",
    "page_bg_mode": "customer pages' background: plain, color (page_bg_color) or picture (set in AI-Prowler)",
    "page_bg_color": "customer pages' background colour when page_bg_mode is color, like #e8f4f8",
    "page_background": "the customer pages' background picture (set in AI-Prowler → Web forms → Page look)",
    "page_accent": "customer pages' button / link colour, like #0b7fab (must be dark enough for white text)",
    "booking_pre_returning": "instant booking: only customers who've had a job with you before are booked on their own",
    "booking_pre_services": "instant booking: only these service codes are booked on their own (empty = every bookable service)",
    "booking_pre_min_days": "instant booking: only times at least this many days away are booked on their own (0 = any)",
    "booking_pre_per_day": "instant booking: at most this many bookings a day are confirmed on their own (0 = no limit)",
    "booking_reschedule_approval": "customers' reschedules wait for an approver (off: a move into an open time is confirmed at once, unless every booking needs approval)",
    "staff_booking": "the app's + → Customer request can book a visit or file a new service request for a customer who called (phone required)",
    "staff_booking_roles": "server: which roles besides the owner may book for customers (manager, staff, field_crew)",
    "staff_booking_approval": "bookings made by staff wait in 📅 To approve; bookings made by an approver are confirmed when made",
    "staff_booking_override": "who may book outside the rules (outside hours, past the daily cap, over a soft job): nobody, approvers or everyone who can book",
    "staff_booking_double_book": "an override may put a crew on two visits at the same time (with a warning)",
    "staff_booking_all_services": "staff can book any Services & Pricing item, not only the ones offered online",
    "staff_booking_notify": "'Send the customer a confirmation' starts ticked on the staff booking form",
    "booking_area_miles": "service area radius in miles from the Jobs app's Start/End Address (0 = no radius; a ZIP on booking_area_zips is always in)",
    "booking_full_pct": "a day this full (percent of the workday) shows no booking windows",
    "backup_dir": "folder where Service Desk backups are saved (blank = standard place) — changed only in AI-Prowler on this PC",
    # Service Desk Agent (2026-10-29) — a named VIRTUAL ASSISTANT, never shown as a person
    "agent_enabled": "the Service Desk Agent (virtual assistant) is on",
    "agent_provider": "which AI runs the agent: claude_api or grok_api",
    "agent_shadow": "practice mode: the agent only shows what it would do",
    "agent_stage_intake": "agent intake (type, priority, routing): off, suggest or auto",
    "agent_stage_first_reply": "agent's first reply to the customer: off, suggest or auto",
    "agent_stage_resolution": "agent's resolution help (internal note): off, suggest or auto",
    "agent_stage_follow_through": "agent nudges when a ticket goes quiet: off, suggest or auto",
    "agent_stage_learn": "agent proposes a learning when a ticket closes: off, suggest or auto",
    "agent_name": "the assistant's first name shown to customers, e.g. Sam (always with its label)",
    "agent_label": "how the assistant is labelled: Virtual assistant, AI assistant or Digital assistant",
    "agent_photo": "the assistant's photo — set it in the Service Desk app or AI-Prowler's Business tab",
    "agent_hours": "hours the agent's automatic runs work, [start, end] local time ([0, 24] = any time)",
    "agent_monthly_budget_usd": "monthly AI spend cap in dollars; headless runs stop when it's reached",
    "agent_budget_alert_pct": "the owner is alerted when the agents' spend reaches this % of the monthly budget (and at 100 %); 0 = no budget alerts",
    "agent_batch_seconds": "seconds to wait so a burst of messages is handled together",
    "agent_max_items": "most tickets the agent works per run",
    "agent_wait_hours": "hours a customer waits with no team reply before the agent nudges",
    "agent_reply_signoff": "words after the assistant's name in its sign-off (blank = business name)",
    "agent_include_service_link": "add the 'request service' link to the agent's first replies",
    # The public pages' Ask chat (2026-11-13: these settings had no help, so Claude, Muse or Grok couldn't explain them)
    "agent_ask_who": "who may ask the assistant on the public pages: anyone (no check), verified "
                     "(a 6-digit code by text or email first) or ticket (only on a ticket's own status page)",
    "agent_ask_services": "the Ask chat may answer questions about the services you offer (yes / no)",
    "agent_ask_products": "the Ask chat may answer questions about the products you sell (yes / no)",
    "agent_ask_per_hour": "questions one visitor may ask the chat per hour (0 = no limit)",
    "agent_ask_context_file": "path of a .txt or .md file on this PC with extra business information "
                              "(FAQs, policies) the Ask chat reads; blank = none",
    # Phase 5 — the one business Google Calendar (personal installs only)
    "calendar_sync": "personal installs: off, or ai = Claude, Muse or Grok syncs one business Google Calendar (busy times in, bookings out)",
    "calendar_name": "the business Google Calendar's name, e.g. Blue Wave Jobs (one calendar only)",
    "calendar_days": "days ahead to sync (0 = the booking horizon)",
    "calendar_fresh_hours": "if the calendar hasn't synced for this many hours, every booking waits for approval",
    # Phase 6 — embed, waitlist, reminders
    "booking_allowed_sites": "websites that may show the booking page inside their own page (frame) — set only in AI-Prowler on this PC",
    "booking_waitlist": "customers offered nothing early enough can ask to hear when an earlier time opens",
    "booking_waitlist_hold_hours": "an earlier opening offered to a waiting customer is held this many hours",
    "booking_waitlist_approval": "a customer taking an offered opening waits for an approver (off: follows the approval setting)",
    "booking_reminders": "reminders before a visit: off, email, text or both (text falls back to email when texting isn't set up)",
    "booking_reminder_hour": "the day-before reminder goes out at this local hour (6-21)",
    "booking_reminder_morning": "also send a short reminder the morning of the visit",
    # The Jobs agent (jobs-agent-spec.md) — kept in its own agent database (desk_agent_store)
    "agent_jb_enabled": "the Jobs agent on (its own switch; works with or without Service Desk)",
    "agent_jb_shadow": "practice mode for the Jobs agent only: it shows what it would do, nothing is changed or sent",
    "agent_jb_rt_enabled": "the Route flow on (its own switch, separate from the Jobs agent's)",
    "agent_jb_rt_shadow": "practice mode for the Route flow only: it shows what it would do, no job moved, no route sent",
    "agent_jb_stage_quotes": "Jobs agent — Quotes (follow up open quotes, job from an approved quote): off | suggest | auto",
    "agent_jb_stage_schedule": "Jobs agent — Schedule (suggests dates; never moves a fixed-time job or today's): off | suggest | auto",
    "agent_jb_stage_prep": "Jobs agent — Prep the day (tomorrow's route, details, weather): off | suggest | auto",
    "agent_jb_stage_onsite": "Jobs agent — On site (running long, still clocked in; notes only): off | suggest | auto",
    "agent_jb_stage_closeout": "Jobs agent — Close out & invoice (drafts the invoice): off | suggest | auto",
    "agent_jb_stage_collect": "Jobs agent — Get paid (reminders for unpaid invoices): off | suggest | auto",
    "agent_jb_stage_repeat": "Jobs agent — Repeat & win back (next recurring visit, quiet customers): off | suggest | auto",
    "agent_jb_stage_learn": "Jobs agent — Learn (real job times, customer notes; a person always approves): off | suggest | auto",
    "agent_jb_can_send_invoices": "let the Jobs agent send invoices itself — only with Close out on auto, practice off and every check passing",
    "agent_jb_invoice_max": "largest invoice ($) the Jobs agent may send itself",
    "agent_jb_invoices_per_day": "most invoices the Jobs agent may send itself in a day",
    "agent_jb_quote_days": "follow up a quote still open after this many days",
    "agent_jb_remind_days": "payment reminder days after the invoice, e.g. [7, 14, 30] (the last is firmer)",
    "agent_jb_prep_hour": "hour (0-23) the Jobs agent checks tomorrow's jobs",
    "agent_jb_weather": "Prep the day checks tomorrow's weather for outdoor jobs",
    "agent_jb_rt_stage_sort": "Route flow — Sort the week (which day each job goes on): off | suggest | auto",
    "agent_jb_rt_stage_plan": "Route flow — Schedule the week (put the sorted jobs on the calendar): off | suggest | auto",
    "agent_jb_rt_stage_route": "Route flow — Route (stop order for each day or the whole week): off | suggest | auto",
    "agent_jb_rt_stage_send": "Route flow — Send routes (approve and give each crew their route): off | suggest | auto",
    "agent_jb_rt_stage_replan": "Route flow — Re-plan the day (cancellations, running late): off | suggest | auto",
    "agent_jb_route_scope": "route each day on its own (day) or the whole week at once (week)",
    "agent_jb_sort_weekday": "day the coming week is sorted, 0 = Monday … 6 = Sunday (default 4 = Friday)",
    "agent_jb_route_send_hour": "hour (0-23) crews get tomorrow's route (18 = the evening before)",
    # The HR agent (hr-agent-spec.md) — kept in its own database inside the HR data folder
    "agent_hr_enabled": "the HR agent on (its own switch; runs only on a Claude API key or the Grok bot)",
    "agent_hr_shadow": "practice mode for the HR agent only: it shows what it would do, nothing is approved or sent",
    "agent_hr_stage_recruit": "HR agent — Recruit (acknowledge applicants; never ranks or rejects): off | suggest | auto",
    "agent_hr_stage_onboard": "HR agent — Onboard (I-9, W-4, new-hire report, checklist): off | suggest | auto",
    "agent_hr_stage_timeoff": "HR agent — Time off & schedules (recommends approve / deny): off | suggest | auto",
    "agent_hr_stage_timeclock": "HR agent — Time clock (missed punches, overtime; notes only): off | suggest | auto",
    "agent_hr_stage_compliance": "HR agent — Documents & training (expiring licences, training due): off | suggest | auto",
    "agent_hr_stage_answer": "HR agent — Employee questions (drafts answers; sensitive goes to a person): off | suggest | auto",
    "agent_hr_stage_incidents": "HR agent — Incidents (acknowledged, assigned, deadlines): off | suggest | auto",
    "agent_hr_stage_offboard": "HR agent — Offboard (final pay date, equipment, access, notices): off | suggest | auto",
    "agent_hr_stage_learn": "HR agent — Learn (handbook gaps; a person always decides): off | suggest | auto",
    "agent_hr_can_approve_timeoff": "let the HR agent approve simple time off itself — only with Time off on auto, practice off and every check passing",
    "agent_hr_timeoff_max_days": "longest time off (days) the HR agent may approve itself",
    "agent_hr_timeoff_notice_days": "least notice (days) for time off the HR agent approves itself",
    "agent_hr_timeoff_max_off": "most people off the same day (per team) for the HR agent to approve",
    "agent_hr_timeoff_per_day": "most time-off approvals the HR agent may make in a day",
    "agent_hr_reviewers": "who reviews the HR agent's suggestions: hr_admin (owner + HR Admin) | hr_admin_managers (managers too, for their team's time off)",
    "agent_hr_incidents_access": "what the HR agent sees of incident reports: type_only | read",
    "agent_hr_overtime_warn_hours": "warn when an hourly employee reaches this many hours in a week",
    "agent_hr_quiet_hours": "hours the HR agent may message employees, e.g. [8, 18]",
    "agent_hr_expiry_days": "days before a document expires to warn, e.g. [60, 30, 7]",
    "agent_hr_ack_sensitive": "sensitive employee messages get \"HR will get back to you\" and go to a person",
}


def tickets_settings(db_path, actor, edition, *, setting="", value=None) -> str:
    def go():
        v = value
        is_switch = isinstance(desk_db.SETTING_DEFAULTS.get(setting), bool)
        if isinstance(v, str) and is_switch:        # chat/voice often sends "on" / "false"
            low = v.strip().lower()
            if low in ("true", "on", "yes", "1"):
                v = True
            elif low in ("false", "off", "no", "0"):
                v = False
        default = desk_db.SETTING_DEFAULTS.get(setting)
        if isinstance(v, str) and type(default) is int and v.strip().lstrip("-").isdigit():
            v = int(v.strip())                       # "5" from chat / voice
        if setting and rules.server_locked(edition):
            return rules.SERVER_LOCK_MSG                  # reading the list is still fine
        if setting in desk_db.LOCAL_ONLY_SETTINGS:
            return ("🔒 The backup folder can only be changed in AI-Prowler on this PC "
                    "(🏢 Small Business tab → Service Desk → Data & backups)." if setting == "backup_dir" else
                    "🔒 Allowed websites can only be changed in AI-Prowler on this PC "
                    "(Service Desk → 🌐 Web forms → Share & embed).")
        if setting.startswith("agent_jb_"):           # the Jobs agent's own database
            import desk_agent_store
            desk_agent_store.set_setting(setting, v, actor=actor, edition=edition)
        elif setting.startswith("agent_hr_"):         # the HR agent's own database (HR data folder)
            import desk_agent_hr_store
            desk_agent_hr_store.set_setting(setting, v, actor=actor, edition=edition)
        elif setting:
            desk_db.set_setting(db_path, setting, v, actor=actor, edition=edition)
        s = desk_db.get_settings(db_path)
        try:
            import desk_agent_store
            s.update(desk_agent_store.settings())
        except Exception:  # noqa: BLE001
            pass
        try:
            import desk_agent_hr_store
            s.update(desk_agent_hr_store.settings())
        except Exception:  # noqa: BLE001
            pass
        lines = [f"Service Desk settings ({'Solo' if edition == rules.SOLO else 'Business'} edition):"]
        for k, v in s.items():
            lines.append(f"  • {k} = {'on' if v is True else 'off' if v is False else v} — "
                         f"{SETTING_HELP.get(k, '')}")
        return ("✅ Saved.\n" if setting else "") + "\n".join(lines)
    return _run(go)
