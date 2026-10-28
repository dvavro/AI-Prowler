"""
desk_ai.py — AI-Prowler Service Desk, Phase 4: the AI-assist features.

AI-Prowler runs no language model itself: these functions hand Claude / Muse /
Grok well-organised material plus simple, explainable suggestions, and every
change they make goes through a person's approval and is logged with
actor = "claude" and approved_by = that person.

  triage()       Open / untyped tickets with suggested type, priority and
                 assignee (+ the reason for each); changes nothing
  apply_triage() applies the suggestions a person approved
  search()       ranked text search over tickets the caller may see
                 (title, details, resolution, messages)
  similar()      likely duplicates; flag_duplicate() notes them on new tickets
  merge()        folds a duplicate into the main ticket (thread, photos, links)
  link()         ticket <-> ticket / invoice links
  summary()      one-paragraph status of a ticket, or a queue digest
  learning_suggestions()  repeated fixes worth saving as a learning
"""
from __future__ import annotations

import datetime
import re
from collections import Counter

import desk_db
import desk_files
import desk_rules as rules
from db_access import utcnow_iso

UTC = datetime.timezone.utc
STOP = set("""a an and are as at be been but by can could did do does for from had has have he her his i
if in into is it its me my no not of on or our so than that the their them then there these they this to
too up us was we were what when which who will with would you your just please thanks thank hi hello
also get got need needs want there's it's i'm im again still""".split())
URGENT = {"flood", "flooding", "flooded", "leak", "leaking", "fire", "smoke", "injury", "injured",
          "emergency", "urgent", "asap", "dangerous", "gas", "sparking", "electrical", "shattered"}
HIGH = {"complaint", "unhappy", "damage", "damaged", "broken", "missed", "late", "refund", "wrong",
        "streaks", "streaky", "angry", "redo", "re-do", "cracked", "down", "stuck"}
DUP_THRESHOLD = 0.45
DUP_DAYS = 14


def tokens(text: str) -> set:
    return {w for w in re.findall(r"[a-z0-9][a-z0-9'-]{2,}", (text or "").lower()) if w not in STOP}


def similarity(a: str, b: str) -> float:
    ta, tb = tokens(a), tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _text(t: dict) -> str:
    return f"{t.get('title', '')} {t.get('description', '')}"


# ── triage ───────────────────────────────────────────────────────────────────

def suggest_priority(text: str, current: str = "P3") -> tuple[str, str]:
    tk = tokens(text)
    hit = sorted(tk & URGENT)
    if hit:
        return "P1", f"mentions {', '.join(hit[:3])}"
    hit = sorted(tk & HIGH)
    if hit:
        return "P2", f"mentions {', '.join(hit[:3])}"
    return current or "P3", "nothing urgent mentioned"


def suggest_type(db_path: str, text: str) -> tuple[str, str]:
    import desk_routing
    tk = tokens(text)
    best = ("", 0.0, "")
    for t in desk_routing.list_types(db_path):
        names = tokens(f"{t['type_id'].replace('-', ' ')} {t['name']}")
        score = len(tk & names) / max(len(names), 1)
        if score > best[1]:
            best = (t["type_id"], score, f"matches type “{t['name']}”")
    if best[1] > 0:
        return best[0], best[2]
    # past tickets with a type and similar wording
    votes = Counter()
    for t in desk_db.list_tickets(db_path, limit=500):
        if t["type"] and similarity(text, _text(t)) >= 0.3:
            votes[t["type"]] += 1
    if votes:
        typ, n = votes.most_common(1)[0]
        return typ, f"like {n} earlier ticket(s) of that type"
    return "", "no type matched"


def triage(db_path: str, *, actor=None, edition: str = rules.BUSINESS, limit: int = 20) -> list[dict]:
    d = rules.can(actor, "triage", edition=edition)
    if not d:
        raise desk_db.DeskError(d.reason)
    import desk_routing
    rows = [t for t in desk_db.list_tickets(db_path, actor=actor, edition=edition, open_only=True,
                                            limit=100000)
            if t["state"] == rules.OPEN or not t["type"]]
    rows.sort(key=lambda t: t["created_at"])
    out = []
    for t in rows[:limit]:
        pri, pri_why = suggest_priority(_text(t), t["priority"])
        typ, typ_why = (t["type"], "already set") if t["type"] else suggest_type(db_path, _text(t))
        who, why = t.get("assignee"), "already assigned"
        if not who and edition == rules.BUSINESS:
            who, _q, why = desk_routing.choose(db_path, {**t, "type": typ}, preview=True)
        dupes = [s["ticket_id"] for s in similar(db_path, t, actor=actor, edition=edition, limit=3)]
        out.append({"ticket_id": t["ticket_id"], "title": t["title"], "description": t["description"][:500],
                    "state": t["state"], "current": {"priority": t["priority"], "type": t["type"],
                                                     "assignee": t.get("assignee")},
                    "suggest": {"priority": pri, "type": typ, "assignee": who},
                    "why": {"priority": pri_why, "type": typ_why, "assignee": why},
                    "possible_duplicates": dupes, "version": t["version"]})
    return out


def apply_triage(db_path: str, items: list[dict], *, actor=None, edition: str = rules.BUSINESS) -> list[str]:
    """Apply approved suggestions: [{"ticket_id", "priority"?, "type"?, "assignee"?}]."""
    d = rules.can(actor, "triage", edition=edition)
    if not d:
        raise desk_db.DeskError(d.reason)
    results = []
    for it in items:
        tid = str(it.get("ticket_id", "")).strip().upper()
        try:
            fields = {k: it[k] for k in ("priority", "type") if it.get(k)}
            if fields:
                desk_db.update_ticket(db_path, tid, fields, actor=actor, edition=edition,
                                      reason="AI triage (approved)", via_claude=True)
            if it.get("assignee") and edition == rules.BUSINESS:
                desk_db.assign_ticket(db_path, tid, it["assignee"], actor=actor, edition=edition,
                                      via_claude=True)
            results.append(f"✅ {tid}: " + ", ".join(f"{k}={v}" for k, v in it.items() if k != "ticket_id"))
        except desk_db.DeskError as e:
            results.append(f"❌ {tid}: {e}")
    return results


# ── search and duplicates ────────────────────────────────────────────────────

def _corpus(db_path: str, ids: list[str], internal_ok: bool) -> dict:
    conn = desk_db.get_connection(db_path)
    try:
        out: dict = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            for r in conn.execute(f"SELECT ticket_id, body, visibility FROM ticket_messages WHERE ticket_id IN "
                                  f"({', '.join('?' for _ in chunk)})", chunk):
                if internal_ok or r["visibility"] == "public":
                    out.setdefault(r["ticket_id"], []).append(r["body"])
        return out
    finally:
        conn.close()


def search(db_path: str, query: str, *, actor=None, edition: str = rules.BUSINESS,
           include_closed: bool = True, limit: int = 10) -> list[dict]:
    q = tokens(query)
    if not q:
        raise desk_db.DeskError("give a few words to search for")
    rows = desk_db.list_tickets(db_path, actor=actor, edition=edition, open_only=not include_closed,
                                limit=100000)
    msgs = _corpus(db_path, [t["ticket_id"] for t in rows], not rules.is_external(actor))
    scored = []
    for t in rows:
        title = tokens(t["title"])
        body = tokens(f"{t['description']} {t.get('resolution') or ''} {t.get('close_reason') or ''} "
                      + " ".join(msgs.get(t["ticket_id"], [])))
        score = 2 * len(q & title) + len(q & body)
        if q & {t["ticket_id"].lower()}:
            score += 10
        if score:
            scored.append((score, t))
    scored.sort(key=lambda x: (-x[0], x[1]["created_at"]))
    return [{"score": s, **t} for s, t in scored[:limit]]


def similar(db_path: str, ticket: dict, *, actor=None, edition: str = rules.BUSINESS,
            limit: int = 5, threshold: float = DUP_THRESHOLD) -> list[dict]:
    since = (datetime.datetime.now(UTC) - datetime.timedelta(days=DUP_DAYS)).isoformat(timespec="seconds")
    out = []
    for t in desk_db.list_tickets(db_path, actor=actor, edition=edition, open_only=True, limit=100000):
        if t["ticket_id"] == ticket.get("ticket_id") or t["created_at"] < since:
            continue
        same_party = ((ticket.get("contact_id") and t.get("contact_id") == ticket.get("contact_id"))
                      or (ticket.get("customer_id") and t.get("customer_id") == ticket.get("customer_id")))
        s = similarity(_text(ticket), _text(t)) + (0.15 if same_party else 0.0)
        if s >= threshold:
            out.append({"ticket_id": t["ticket_id"], "title": t["title"], "score": round(s, 2)})
    out.sort(key=lambda x: -x["score"])
    return out[:limit]


def flag_duplicate(kind: str, ticket: dict, actor, *, edition: str = rules.BUSINESS, **info) -> None:
    """desk_db listener: on a new ticket, note likely duplicates (internal only)."""
    if kind != "created":
        return
    db_path = _db_path_fn() if _db_path_fn else None
    if not db_path:
        return
    hits = similar(db_path, ticket, edition=edition, limit=3)
    if not hits:
        return
    with desk_db.ticket_transaction(db_path) as (conn, touched):
        for h in hits:
            conn.execute("INSERT OR IGNORE INTO ticket_relations (ticket_id, kind, target, created_at, created_by) "
                         "VALUES (?, 'related', ?, ?, 'claude')", (ticket["ticket_id"], h["ticket_id"], utcnow_iso()))
        desk_db._event(conn, ticket["ticket_id"], "claude", "possible_duplicate",
                       to_value=", ".join(h["ticket_id"] for h in hits))
        conn.execute("INSERT INTO ticket_messages (ticket_id, at, author, author_kind, visibility, channel, body) "
                     "VALUES (?, ?, 'claude', 'claude', 'internal', 'system', ?)",
                     (ticket["ticket_id"], utcnow_iso(),
                      "Possible duplicate of " + ", ".join(f"{h['ticket_id']} ({h['title']})" for h in hits)
                      + ". Merge only if a person confirms."))
        touched.add(ticket["ticket_id"])


_db_path_fn = None


def enable_duplicate_flagging(db_path_fn) -> None:
    global _db_path_fn
    _db_path_fn = db_path_fn
    if flag_duplicate not in desk_db.listeners:
        desk_db.listeners.append(flag_duplicate)


def disable_duplicate_flagging() -> None:
    global _db_path_fn
    _db_path_fn = None
    if flag_duplicate in desk_db.listeners:
        desk_db.listeners.remove(flag_duplicate)


# ── merge and link ───────────────────────────────────────────────────────────

def merge(db_path: str, primary_id: str, duplicate_id: str, *, actor=None,
          edition: str = rules.BUSINESS) -> dict:
    a = rules.normalize_actor(actor)
    if a["role"] not in (rules.OWNER, rules.MANAGER):
        raise desk_db.DeskError("only the owner or a manager can merge tickets")
    pid, did = primary_id.strip().upper(), duplicate_id.strip().upper()
    if pid == did:
        raise desk_db.DeskError("pick two different tickets")
    root = desk_db.root_for(db_path)
    moved_files = []
    with desk_db.ticket_transaction(db_path) as (conn, touched):
        p = desk_db._load_visible(conn, pid, actor, edition)
        d = desk_db._load_visible(conn, did, actor, edition)
        if d["state"] == rules.CLOSED and (d.get("close_reason") or "").startswith("merged into"):
            raise desk_db.DeskError(f"{did} was already merged")
        pf = desk_files.ticket_folder(root, p) / desk_files.ATTACHMENTS_DIR
        df = desk_files.ticket_folder(root, d) / desk_files.ATTACHMENTS_DIR
        pf.mkdir(parents=True, exist_ok=True)
        import desk_attachments
        for att in [dict(r) for r in conn.execute("SELECT * FROM ticket_attachments WHERE ticket_id = ?", (did,))]:
            seq = desk_attachments._next_seq(pf)
            new_name = f"{seq:04d}_" + att["filename"].split("_", 1)[-1]
            src = df / att["filename"]
            if src.exists():
                (pf / new_name).write_bytes(src.read_bytes())
                moved_files.append(src)
            thumb = None
            if att.get("thumb_path"):
                tsrc = df.parent / att["thumb_path"]
                thumb_name = new_name.rsplit(".", 1)[0] + "_thumb.jpg"
                if tsrc.exists():
                    (pf / thumb_name).write_bytes(tsrc.read_bytes())
                    moved_files.append(tsrc)
                thumb = f"{desk_files.ATTACHMENTS_DIR}/{thumb_name}"
            conn.execute("UPDATE ticket_attachments SET ticket_id = ?, filename = ?, path = ?, thumb_path = ? "
                         "WHERE attachment_id = ?", (pid, new_name, f"{desk_files.ATTACHMENTS_DIR}/{new_name}",
                                                     thumb, att["attachment_id"]))
        n_msgs = conn.execute("UPDATE ticket_messages SET ticket_id = ? WHERE ticket_id = ?", (pid, did)).rowcount
        # status links follow the thread when the outside party is the same; otherwise retire them
        conn.execute("UPDATE ticket_links SET ticket_id = ? WHERE ticket_id = ? AND contact_id = ?",
                     (pid, did, p.get("contact_id") or ""))
        conn.execute("UPDATE ticket_links SET revoked = 1 WHERE ticket_id = ?", (did,))
        ts = utcnow_iso()
        conn.execute("UPDATE tickets SET state = ?, closed_at = ?, close_reason = ? WHERE ticket_id = ?",
                     (rules.CLOSED, ts, f"merged into {pid}", did))
        for tid, kind, target in ((did, "merged_into", pid), (pid, "related", did)):
            conn.execute("INSERT OR IGNORE INTO ticket_relations (ticket_id, kind, target, created_at, created_by) "
                         "VALUES (?, ?, ?, ?, ?)", (tid, kind, target, ts, a["id"]))
        desk_db._event(conn, did, a["id"], "state_change", d["state"], rules.CLOSED, reason=f"merged into {pid}", at=ts)
        desk_db._event(conn, pid, a["id"], "merged", to_value=did,
                       reason=f"{n_msgs} message(s) and attachments moved", at=ts)
        for tid in (pid, did):
            desk_db._touch(conn, tid, a["id"])
            touched.add(tid)
    for f in moved_files:
        try:
            f.unlink()
        except OSError:
            pass
    return {"ok": True, "primary": pid, "closed": did, "messages_moved": n_msgs}


LINK_KINDS = ("related", "duplicate_of", "invoice", "job", "customer")


def link(db_path: str, ticket_id: str, kind: str, target: str, *, actor=None,
         edition: str = rules.BUSINESS) -> dict:
    tid, target = ticket_id.strip().upper(), (target or "").strip()
    if kind not in LINK_KINDS:
        raise desk_db.DeskError(f"kind must be one of {', '.join(LINK_KINDS)}")
    if not target:
        raise desk_db.DeskError("say what to link to")
    if kind in ("job", "customer"):
        return desk_db.update_ticket(db_path, tid, {f"{kind}_id": target}, actor=actor, edition=edition)
    t = desk_db.get_ticket(db_path, tid, actor=actor, edition=edition)
    if t is None:
        raise desk_db.NotFoundError(f"no ticket {tid} that you can see")
    if not rules.can(actor, "edit", t, edition=edition):
        raise desk_db.DeskError("only the assignee, a manager or the owner can link this ticket")
    if kind in ("related", "duplicate_of"):
        target = target.upper()
        if desk_db.get_ticket(db_path, target, actor=actor, edition=edition) is None:
            raise desk_db.NotFoundError(f"no ticket {target} that you can see")
    with desk_db.ticket_transaction(db_path) as (conn, touched):
        conn.execute("INSERT OR IGNORE INTO ticket_relations (ticket_id, kind, target, created_at, created_by) "
                     "VALUES (?, ?, ?, ?, ?)", (tid, kind, target, utcnow_iso(), rules.normalize_actor(actor)["id"]))
        desk_db._event(conn, tid, rules.normalize_actor(actor)["id"], "linked", to_value=f"{kind}:{target}")
        desk_db._touch(conn, tid, rules.normalize_actor(actor)["id"])
        touched.add(tid)
        return desk_db._row(conn, tid)


# ── summaries ────────────────────────────────────────────────────────────────

def _ago(iso: str | None, now: datetime.datetime) -> str:
    if not iso:
        return ""
    dt = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    secs = (now - dt).total_seconds()
    if secs < 3600:
        return f"{max(1, int(secs // 60))} min ago"
    if secs < 86400 * 2:
        return f"{int(secs // 3600)} h ago"
    return f"{int(secs // 86400)} days ago"


NEXT_STEP = {rules.OPEN: "needs an owner", rules.ASSIGNED: "waiting to be started",
             rules.IN_PROGRESS: "being worked", rules.ON_HOLD: "on hold",
             rules.FIXED: "waiting for the customer to confirm", rules.CLOSED: "closed"}


def summary(db_path: str, ticket_id: str, *, actor=None, edition: str = rules.BUSINESS,
            now: datetime.datetime | None = None) -> str:
    now = now or datetime.datetime.now(UTC)
    d = desk_db.get_ticket_detail(db_path, ticket_id.strip().upper(), actor=actor, edition=edition)
    parts = [f"{d['ticket_id']} “{d['title']}” is {d['state']} ({NEXT_STEP.get(d['state'], '')}), "
             f"{d['priority']}, opened {_ago(d['created_at'], now)}"
             + (f", with {d['assignee']}" if d.get("assignee") else "") + "."]
    due = d.get("due_resolve_at")
    if due and d["state"] not in (rules.FIXED, rules.CLOSED):
        late = datetime.datetime.fromisoformat(due.replace("Z", "+00:00")) < now
        parts.append(f"{'OVERDUE since' if late else 'Due'} {due[:10]}.")
    pub = [m for m in d.get("messages", []) if m["visibility"] == "public"]
    if pub:
        m = pub[-1]
        who = "the customer" if m["author_kind"] in ("customer", "subcontractor") else "we"
        parts.append(f"Last public message ({_ago(m['at'], now)}, from {who}): “{m['body'][:160]}”.")
    notes = [m for m in d.get("messages", []) if m["visibility"] == "internal"]
    if notes:
        parts.append(f"Latest internal note: “{notes[-1]['body'][:160]}”.")
    if d.get("resolution"):
        parts.append(f"Resolution: {d['resolution'][:200]}")
    elif d["state"] == rules.FIXED:
        parts.append("No resolution written yet — add one with update_ticket(resolution=...).")
    return " ".join(parts)


def queue_summary(db_path: str, *, actor=None, edition: str = rules.BUSINESS, queue_id: str = "",
                  now: datetime.datetime | None = None) -> str:
    now = now or datetime.datetime.now(UTC)
    rows = desk_db.list_tickets(db_path, actor=actor, edition=edition, open_only=True,
                                queue_id=queue_id or None, limit=100000)
    if not rows:
        return "No open tickets" + (f" in {queue_id}" if queue_id else "") + "."
    by = Counter(t["state"] for t in rows)
    overdue = [t for t in rows if t.get("due_resolve_at") and t["state"] not in (rules.FIXED,)
               and datetime.datetime.fromisoformat(t["due_resolve_at"].replace("Z", "+00:00")) < now]
    oldest = min(rows, key=lambda t: t["created_at"])
    unassigned = [t for t in rows if not t.get("assignee")]
    return (f"{len(rows)} open ticket(s)" + (f" in {queue_id}" if queue_id else "") + ": "
            + ", ".join(f"{n} {s}" for s, n in by.most_common())
            + f". {len(overdue)} overdue, {len(unassigned)} unassigned. Oldest: {oldest['ticket_id']} "
              f"“{oldest['title']}” ({_ago(oldest['created_at'], now)}).")


def learning_suggestions(db_path: str, *, actor=None, edition: str = rules.BUSINESS,
                         min_count: int = 3) -> list[dict]:
    """Ticket types (or recurring words) fixed the same way several times."""
    d = rules.can(actor, "report", edition=edition)
    if not d:
        raise desk_db.DeskError(d.reason)
    done = [t for t in desk_db.list_tickets(db_path, actor=actor, edition=edition, limit=100000)
            if t.get("resolution")]
    groups: dict = {}
    for t in done:
        key = t["type"] or (sorted(tokens(t["title"]))[:1] or ["general"])[0]
        groups.setdefault(key, []).append(t)
    out = []
    for key, items in groups.items():
        if len(items) < min_count:
            continue
        common = Counter(w for t in items for w in tokens(t["resolution"]))
        shared = [w for w, n in common.most_common(8) if n >= min_count]
        if shared:
            out.append({"topic": key, "tickets": [t["ticket_id"] for t in items][-5:],
                        "count": len(items), "common_words": shared,
                        "examples": [t["resolution"][:200] for t in items[-3:]]})
    return sorted(out, key=lambda x: -x["count"])
