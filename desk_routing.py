"""
desk_routing.py — AI-Prowler Service Desk, Phase 3: queues, ticket types,
assignment rules and round-robin (Business edition).

choose() runs when a Business ticket is filed with no assignee; first match wins:
  1. linked job -> that job's crew lead (job_crew_fn, from the Jobs app)
  2. assignment rules, in order: match on type / kind / customer_id / keyword
     -> a user, or a queue
  3. the ticket type's default queue
  then a queue -> round-robin over members who are available (availability_fn:
  clocked in / not on approved time off, from HR), falling back to the
  queue's default assignee; nobody available -> stays Open in that queue.
  No match at all -> Open in the shared inbox (owner and managers alerted).

Hooks set by ai_prowler_mcp.py (both optional; default = everyone available,
no job lookup):
    availability_fn(user_id) -> bool
    job_crew_fn(job_id) -> user_id | None
"""
from __future__ import annotations

import json
import re

import desk_db
import desk_rules as rules
from db_access import utcnow_iso

availability_fn = None
job_crew_fn = None

_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")


def _available(uid: str) -> bool:
    if not uid:
        return False
    if availability_fn is None:
        return True
    try:
        return bool(availability_fn(uid))
    except Exception:  # noqa: BLE001 — an HR lookup problem must not block filing
        return True


def _gate(actor, edition, action="manage_queues"):
    d = rules.can(actor, action, edition=edition)
    if not d:
        raise desk_db.DeskError(d.reason)


def _slug(v: str, what: str) -> str:
    s = (v or "").strip().lower().replace(" ", "-")
    if not _ID.match(s):
        raise desk_db.DeskError(f"{what} id must be letters, digits, - or _ (got {v!r})")
    return s


# ── queues ───────────────────────────────────────────────────────────────────

def list_queues(db_path: str) -> list[dict]:
    conn = desk_db.get_connection(db_path)
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM queues ORDER BY name")]
    finally:
        conn.close()
    for r in rows:
        r["members"] = json.loads(r["members"] or "[]")
    return rows


def upsert_queue(db_path: str, queue_id: str, *, name: str = "", members=None,
                 default_assignee: str | None = None, response_sla_minutes=None,
                 resolve_sla_minutes=None, actor=None, edition=rules.BUSINESS) -> dict:
    _gate(actor, edition)
    qid = _slug(queue_id, "queue")
    members = [m.strip() for m in (members or []) if str(m).strip()]
    if default_assignee and default_assignee not in members:
        members.append(default_assignee)
    now, who = utcnow_iso(), rules.normalize_actor(actor)["id"]
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO queues (queue_id, name, default_assignee, members, response_sla_minutes, "
            "resolve_sla_minutes, created_at, version, last_edited_at, last_edited_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?) ON CONFLICT(queue_id) DO UPDATE SET "
            "name = excluded.name, default_assignee = excluded.default_assignee, "
            "members = excluded.members, response_sla_minutes = excluded.response_sla_minutes, "
            "resolve_sla_minutes = excluded.resolve_sla_minutes, version = queues.version + 1, "
            "last_edited_at = excluded.last_edited_at, last_edited_by = excluded.last_edited_by",
            (qid, (name or qid).strip(), default_assignee or None, json.dumps(members),
             response_sla_minutes, resolve_sla_minutes, now, now, who))
    finally:
        conn.close()
    return next(q for q in list_queues(db_path) if q["queue_id"] == qid)


def delete_queue(db_path: str, queue_id: str, *, actor=None, edition=rules.BUSINESS) -> None:
    _gate(actor, edition)
    conn = desk_db.get_connection(db_path)
    try:
        n = conn.execute("SELECT COUNT(*) FROM tickets WHERE queue_id = ? AND state != 'Closed'",
                         (queue_id,)).fetchone()[0]
        if n:
            raise desk_db.DeskError(f"{n} open ticket(s) are still in queue {queue_id}; move them first")
        conn.execute("DELETE FROM queues WHERE queue_id = ?", (queue_id,))
    finally:
        conn.close()


# ── ticket types ─────────────────────────────────────────────────────────────

def list_types(db_path: str) -> list[dict]:
    conn = desk_db.get_connection(db_path)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM ticket_types ORDER BY name")]
    finally:
        conn.close()


def upsert_type(db_path: str, type_id: str, *, name: str = "", kind: str = rules.EXTERNAL,
                default_queue: str | None = None, default_priority: str = "P3",
                actor=None, edition=rules.BUSINESS) -> dict:
    _gate(actor, edition, "manage_settings")
    tid = _slug(type_id, "type")
    if kind not in rules.KINDS:
        raise desk_db.DeskError(f"kind must be one of {', '.join(rules.KINDS)}")
    if default_priority not in rules.PRIORITIES:
        raise desk_db.DeskError("default_priority must be P1-P4")
    if default_queue and not rules.feature_enabled(edition, "queues"):
        raise desk_db.DeskError("queues are a Business feature")
    now, who = utcnow_iso(), rules.normalize_actor(actor)["id"]
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO ticket_types (type_id, name, kind, default_queue, default_priority, "
            "created_at, version, last_edited_at, last_edited_by) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?) "
            "ON CONFLICT(type_id) DO UPDATE SET name = excluded.name, kind = excluded.kind, "
            "default_queue = excluded.default_queue, default_priority = excluded.default_priority, "
            "version = ticket_types.version + 1, last_edited_at = excluded.last_edited_at, "
            "last_edited_by = excluded.last_edited_by",
            (tid, (name or tid).strip(), kind, default_queue or None, default_priority, now, now, who))
        return dict(conn.execute("SELECT * FROM ticket_types WHERE type_id = ?", (tid,)).fetchone())
    finally:
        conn.close()


# ── assignment rules ─────────────────────────────────────────────────────────

RULE_MATCH_KEYS = ("type", "kind", "customer_id", "keyword")


def list_rules(db_path: str) -> list[dict]:
    conn = desk_db.get_connection(db_path)
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM assignment_rules ORDER BY sort_order, rule_id")]
    finally:
        conn.close()
    for r in rows:
        r["match"] = json.loads(r.pop("match_json") or "{}")
        r["action"] = json.loads(r.pop("action_json") or "{}")
    return rows


def upsert_rule(db_path: str, rule_id: str, *, match: dict, action: dict, sort_order: int = 100,
                enabled: bool = True, actor=None, edition=rules.BUSINESS) -> dict:
    _gate(actor, edition)
    rid = _slug(rule_id, "rule")
    bad = [k for k in match if k not in RULE_MATCH_KEYS]
    if bad or not match:
        raise desk_db.DeskError(f"a rule matches on one or more of: {', '.join(RULE_MATCH_KEYS)}")
    if set(action) not in ({"user"}, {"queue"}) or not str(next(iter(action.values()))).strip():
        raise desk_db.DeskError('a rule sends a ticket to {"user": id} or {"queue": id}')
    now, who = utcnow_iso(), rules.normalize_actor(actor)["id"]
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO assignment_rules (rule_id, sort_order, match_json, action_json, enabled, "
            "created_at, version, last_edited_at, last_edited_by) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?) "
            "ON CONFLICT(rule_id) DO UPDATE SET sort_order = excluded.sort_order, "
            "match_json = excluded.match_json, action_json = excluded.action_json, "
            "enabled = excluded.enabled, version = assignment_rules.version + 1, "
            "last_edited_at = excluded.last_edited_at, last_edited_by = excluded.last_edited_by",
            (rid, int(sort_order), json.dumps(match), json.dumps(action), int(bool(enabled)),
             now, now, who))
    finally:
        conn.close()
    return next(r for r in list_rules(db_path) if r["rule_id"] == rid)


def delete_rule(db_path: str, rule_id: str, *, actor=None, edition=rules.BUSINESS) -> None:
    _gate(actor, edition)
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("DELETE FROM assignment_rules WHERE rule_id = ?", (rule_id,))
    finally:
        conn.close()


def _rule_matches(match: dict, t: dict) -> bool:
    for k, v in match.items():
        if k == "keyword":
            text = f"{t.get('title', '')} {t.get('description', '')}".lower()
            if str(v).strip().lower() not in text:
                return False
        elif str(t.get(k) or "").lower() != str(v).strip().lower():
            return False
    return True


# ── choosing an assignee ─────────────────────────────────────────────────────

def _round_robin(conn, queue_id: str, advance: bool = True) -> str | None:
    q = conn.execute("SELECT * FROM queues WHERE queue_id = ?", (queue_id,)).fetchone()
    if q is None:
        return None
    members = json.loads(q["members"] or "[]")
    n = len(members)
    for step in range(n):
        idx = (q["round_robin_cursor"] + step) % n
        if _available(members[idx]):
            if advance:
                conn.execute("UPDATE queues SET round_robin_cursor = ? WHERE queue_id = ?",
                             ((idx + 1) % n, queue_id))
            return members[idx]
    return q["default_assignee"] if _available(q["default_assignee"]) else None


def choose(db_path: str, fields: dict, *, preview: bool = False) -> tuple[str | None, str | None, str]:
    """(assignee, queue_id, why) for a new Business ticket with no assignee.
    preview=True (AI triage suggestions) changes nothing — not even the
    round-robin position."""
    job = fields.get("job_id")
    if job and job_crew_fn:
        try:
            lead = job_crew_fn(job)
        except Exception:  # noqa: BLE001
            lead = None
        if lead and _available(lead):
            return lead, fields.get("queue_id"), f"rule:job-crew ({job})"
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        queue = fields.get("queue_id")
        why = "queue given"
        if not queue:
            for r in conn.execute("SELECT * FROM assignment_rules WHERE enabled = 1 "
                                  "ORDER BY sort_order, rule_id"):
                if _rule_matches(json.loads(r["match_json"] or "{}"), fields):
                    act = json.loads(r["action_json"] or "{}")
                    if act.get("user"):
                        if _available(act["user"]):
                            conn.execute("COMMIT")
                            return act["user"], None, f"rule:{r['rule_id']}"
                        continue
                    queue, why = act.get("queue"), f"rule:{r['rule_id']}"
                    break
        if not queue and fields.get("type"):
            t = conn.execute("SELECT default_queue FROM ticket_types WHERE type_id = ? OR "
                             "lower(name) = lower(?)", (fields["type"], fields["type"])).fetchone()
            if t and t["default_queue"]:
                queue, why = t["default_queue"], f"type:{fields['type']}"
        who = _round_robin(conn, queue, advance=not preview) if queue else None
        conn.execute("ROLLBACK" if preview else "COMMIT")
        return who, queue, (why + (" -> round-robin" if who else " -> nobody available")) if queue else "no rule matched"
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
