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
                           service_type="", customer_id="", notes="", notify_customer=True) -> str:
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
        d = due_iso(service_date)      # validates the date
        day = (service_date or "").strip()[:10]
        updates = {"CustomerID": cust, "Service Date": day, "Job Status": "Scheduled",
                   "Notes": (f"From Service Desk {tid}: {t['title']}" + (f" — {notes}" if notes else ""))[:500]}
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
        desk_db.add_message(db_path, tid, f"Scheduled {job} for {day}" + (f" ({service_type})" if service_type else ""),
                            actor=actor, edition=edition, visibility="internal", channel="claude")
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
        if setting:
            desk_db.set_setting(db_path, setting, v, actor=actor, edition=edition)
        s = desk_db.get_settings(db_path)
        lines = [f"Service Desk settings ({'Solo' if edition == rules.SOLO else 'Business'} edition):"]
        for k, v in s.items():
            lines.append(f"  • {k} = {'on' if v is True else 'off' if v is False else v} — "
                         f"{SETTING_HELP.get(k, '')}")
        return ("✅ Saved.\n" if setting else "") + "\n".join(lines)
    return _run(go)
