"""
desk_alerts.py — AI-Prowler Service Desk, Phase 1: alerts and outgoing replies.

Listens to desk_db change events (after commit) and:

  * alerts the right internal person — Solo: the Owner; Business: the
    assignee, or the owner and managers while a ticket has no owner;
  * delivers PUBLIC replies to the ticket's customer or subcontractor by
    email (if the contact has one) or SMS, and records the result on the
    message (sent / failed / no_contact);
  * never alerts people about their own actions.

Channels: email always (when the person has an address); SMS too when the
ticket has SMS fallback on (set per ticket, defaulted from Settings, always on
for P1). Web push arrives with the push subscriptions work.

Senders are injected by ai_prowler_mcp.py (its existing send_email /
send_sms), so this module has no AI-Prowler imports beyond desk_* and is
unit tested with fake senders.
"""
from __future__ import annotations

import logging
import threading

import desk_db
import desk_rules as rules

log = logging.getLogger("desk_alerts")

_cfg = {
    "email": None,       # fn(to, subject, body) -> bool
    "sms": None,         # fn(to, text) -> bool
    "team": None,        # fn() -> [{"id","name","role","email","phone"}]  (server)
    "db_path": None,     # fn() -> tickets db path
    "base_url": None,    # fn() -> "https://<tunnel>" or ""
    "business": None,    # fn() -> business name for customer messages
    "background": True,  # send in a background thread (tests: False)
    "push": None,        # fn(user_id, title, body, url, ticket_id) -> bool (web push)
}
_registered = False


def configure(**kw) -> None:
    """Install senders/lookups and start listening (idempotent)."""
    global _registered
    for k, v in kw.items():
        if k not in _cfg:
            raise KeyError(k)
        _cfg[k] = v
    if not _registered:
        desk_db.listeners.append(on_change)
        _registered = True
    import desk_portal
    desk_portal.send_fn = send_direct


def send_direct(channel: str, to: str, subject: str, text: str) -> bool:
    """One message to one address/number (portal codes and confirmations)."""
    if channel == "sms":
        return bool(_call("sms", to, text, default=False))
    return bool(_call("email", to, subject, text, default=False))


def reset() -> None:
    """Tests: stop listening and forget senders."""
    global _registered
    if on_change in desk_db.listeners:
        desk_db.listeners.remove(on_change)
    _registered = False
    for k in _cfg:
        _cfg[k] = None
    _cfg["background"] = True
    import desk_portal
    desk_portal.send_fn = None


def _call(name, *a, default=None):
    fn = _cfg.get(name)
    if not fn:
        return default
    try:
        return fn(*a)
    except Exception as e:  # noqa: BLE001
        log.warning("Service Desk alert %s failed: %s", name, e)
        return default


def _db():
    return _call("db_path", default=None) or desk_db.default_db_path()


def _link(ticket_id: str) -> str:
    base = (_call("base_url", default="") or "").rstrip("/")
    return f"{base}/desk/#{ticket_id}" if base else ""


# ── who hears about what ─────────────────────────────────────────────────────

def _owner_contact() -> dict:
    s = desk_db.get_settings(_db())
    return {"id": "owner", "name": "Owner", "email": s.get("alert_email") or "",
            "phone": s.get("alert_phone") or ""}


def _team() -> list:
    return list(_call("team", default=[]) or [])


def _person(user_id: str, edition: str) -> dict | None:
    if edition == rules.SOLO:
        return _owner_contact()
    return next((u for u in _team() if u.get("id") == user_id), None)


def _leads(edition: str) -> list:
    if edition == rules.SOLO:
        return [_owner_contact()]
    return [u for u in _team() if u.get("role") in (rules.OWNER, rules.MANAGER)]


def recipients(kind: str, ticket: dict, actor, edition: str, **info) -> tuple[list, str]:
    """([people], what-happened text) for an internal alert. Pure apart from
    the settings / team lookups."""
    a = rules.normalize_actor(actor)
    me = a.get("id")
    external = a["role"] in rules.EXTERNAL_ROLES
    tid, title = ticket["ticket_id"], ticket["title"]
    people, what = [], ""

    if kind == "created":
        if ticket.get("assignee"):
            people = [_person(ticket["assignee"], edition)]
            what = f"New ticket {tid} for you: {title}"
        else:
            people = _leads(edition)
            what = f"New unassigned ticket {tid}: {title}"
    elif kind == "assigned":
        people = [_person(ticket["assignee"], edition)]
        what = f"{tid} was assigned to you: {title}"
    elif kind == "state_changed":
        frm, to = info.get("from_state"), ticket["state"]
        if frm == rules.CLOSED:
            people = [_person(ticket.get("assignee"), edition)] + (_leads(edition) if not ticket.get("assignee") else [])
            what = f"{tid} was reopened: {info.get('reason') or title}"
        elif external and to == rules.FIXED:
            people = [_person(ticket.get("assignee"), edition)]
            what = f"{tid}: the {a['role']} marked their part done — {title}"
        elif external and frm == rules.FIXED and to == rules.IN_PROGRESS:
            people = [_person(ticket.get("assignee"), edition)]
            what = f"{tid}: the customer says it is NOT fixed — {info.get('reason') or title}"
    elif kind == "sla":
        flag = info.get("flag", "")
        if flag == "escalated":
            people = _leads(edition)
            what = f"ESCALATED: {tid} is well past its target — {title}"
        else:
            clock = "first reply" if flag.startswith("response") else "fix"
            late = flag.endswith("breach")
            people = [_person(ticket.get("assignee"), edition)] if ticket.get("assignee") else _leads(edition)
            what = (f"{tid} {clock} is OVERDUE — {title}" if late
                    else f"{tid} {clock} is due soon — {title}")
    elif kind == "message":
        msg = info.get("message") or {}
        if external:
            people = [_person(ticket.get("assignee"), edition)] if ticket.get("assignee") else _leads(edition)
            what = f"{tid}: new reply from the {a['role']} — {msg.get('body', '')[:140]}"

    # In Solo the owner never gets an alert about his own action.
    if edition == rules.SOLO and not external:
        people = []
    seen, out = set(), []
    for p in people:
        if not p:
            continue
        key = p.get("id")
        if key in seen or (key == me and not external):
            continue
        seen.add(key)
        out.append(p)
    return out, what


# ── delivery ─────────────────────────────────────────────────────────────────

def _send_alert(people: list, what: str, ticket: dict) -> list:
    sent = []
    link = _link(ticket["ticket_id"])
    body = what + (f"\n\nOpen it: {link}" if link else "")
    for p in people:
        if p.get("id") and _call("push", p["id"], "Service Desk", what[:200],
                                 f"/desk/#{ticket['ticket_id']}", ticket["ticket_id"], default=False):
            sent.append(("push", p.get("id")))
        if p.get("email") and _call("email", p["email"], f"[Service Desk] {what[:90]}", body,
                                    default=False):
            sent.append(("email", p.get("id")))
        if (ticket.get("sms_fallback") or ticket.get("priority") == "P1") and p.get("phone"):
            if _call("sms", p["phone"], f"Service Desk: {what[:300]}", default=False):
                sent.append(("sms", p.get("id")))
    return sent


def deliver_public_message(ticket: dict, msg: dict) -> str:
    """Send a staff/Claude public reply to the ticket's customer or
    subcontractor. Returns and records the delivery status."""
    contact = desk_db.get_contact(_db(), ticket["contact_id"]) if ticket.get("contact_id") else None
    status = "no_contact"
    if contact:
        biz = _call("business", default="") or "Service Desk"
        base = (_call("base_url", default="") or "").rstrip("/")
        url = ""
        if base:
            import desk_portal
            url = desk_portal.link_url(base, desk_portal.issue_link(
                _db(), ticket["ticket_id"], contact["contact_id"]))
        if contact.get("email") and _cfg.get("email"):
            ok = _call("email", contact["email"], f"Re: {ticket['title']} [{ticket['ticket_id']}]",
                       f"{msg['body']}\n\n"
                       + (f"See your request and reply: {url}\n\n" if url else "")
                       + f"— {biz} (ref {ticket['ticket_id']})", default=False)
            status = "sent" if ok else "failed"
        elif contact.get("phone") and _cfg.get("sms"):
            ok = _call("sms", contact["phone"],
                       f"{biz}: {msg['body']} (ref {ticket['ticket_id']})"
                       + (f" Details: {url}" if url else ""), default=False)
            status = "sent" if ok else "failed"
    desk_db.set_message_delivery(_db(), msg["message_id"], status)
    return status


def on_change(kind: str, ticket: dict, actor, *, edition: str = rules.BUSINESS, **info) -> None:
    def work():
        if kind == "message":
            msg = info.get("message") or {}
            if msg.get("visibility") == "public" and msg.get("author_kind") in ("staff", "claude"):
                deliver_public_message(ticket, msg)
        people, what = recipients(kind, ticket, actor, edition, **info)
        if people and what:
            _send_alert(people, what, ticket)

    if _cfg.get("background"):
        threading.Thread(target=work, name=f"desk-alert-{ticket.get('ticket_id')}",
                         daemon=True).start()
    else:
        work()
