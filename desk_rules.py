"""
desk_rules.py — AI-Prowler Service Desk, Phase 0.

Pure rules, no I/O and no AI-Prowler imports:

  * the ticket lifecycle (six states, allowed transitions, when a reason
    is required),
  * the ONE role gate, can(), that the PWA API, the HTTP routes and the
    MCP tools all ask — so the three paths can never disagree
    (spec: "Every role check is enforced server-side in one function"),
  * the edition feature matrix: Solo (Personal Mobile, personal mode) vs
    Business (server mode).

Ticket kinds:
  external       a customer's request (customer sees it via a status link)
  internal       an internal ticket; in Solo, the Owner's own to-do
  subcontractor  a ticket about a subcontractor's work, shared with that sub

Solo edition (spec, 2026-10-27): every ticket goes to the Owner; the Owner
is the only internal user. Customers file tickets; the Owner may also file
his own tickets and subcontractor tickets — each can be hidden with a
Settings switch (options own_tickets / subcontractor_tickets).

Usage:
    from desk_rules import can, check_transition, edition_for_mode

    d = can(actor, "change_state", ticket, edition="business",
            to_state="Fixed", reason="")
    if not d:
        return f"⛔ {d.reason}"
"""
from __future__ import annotations

import datetime
from typing import NamedTuple

# ── Lifecycle ────────────────────────────────────────────────────────────────

OPEN = "Open"
ASSIGNED = "Assigned"
IN_PROGRESS = "In Progress"
ON_HOLD = "On Hold"
FIXED = "Fixed"
CLOSED = "Closed"

STATES = (OPEN, ASSIGNED, IN_PROGRESS, ON_HOLD, FIXED, CLOSED)

# from-state -> states it may move to
TRANSITIONS = {
    OPEN:        frozenset({ASSIGNED, CLOSED}),
    ASSIGNED:    frozenset({IN_PROGRESS, OPEN, ON_HOLD, FIXED, CLOSED}),
    IN_PROGRESS: frozenset({ON_HOLD, FIXED, ASSIGNED, CLOSED}),
    ON_HOLD:     frozenset({IN_PROGRESS, CLOSED}),
    FIXED:       frozenset({CLOSED, IN_PROGRESS}),
    CLOSED:      frozenset({ASSIGNED}),          # reopen goes back to the last owner
}

REOPEN_WINDOW_DAYS = 7     # customer may reopen this long after close
AUTO_CLOSE_DAYS = 3        # Fixed -> Closed after this much customer silence

PRIORITIES = ("P1", "P2", "P3", "P4")
EXTERNAL = "external"
INTERNAL = "internal"
SUBCONTRACTOR_KIND = "subcontractor"
KINDS = (EXTERNAL, INTERNAL, SUBCONTRACTOR_KIND)
VISIBILITIES = ("normal", "private")


class Decision(NamedTuple):
    """Result of a rule check. Truthy when allowed; `reason` always explains."""
    ok: bool
    reason: str

    def __bool__(self) -> bool:  # lets callers write `if not d:`
        return self.ok


def _allow(reason: str = "allowed") -> Decision:
    return Decision(True, reason)


def _deny(reason: str) -> Decision:
    return Decision(False, reason)


def needs_reason(from_state: str, to_state: str) -> bool:
    """True when this move must carry a written reason (audit trail)."""
    if to_state == ON_HOLD:
        return True                                  # waiting on what?
    if to_state == CLOSED and from_state != FIXED:
        return True                                  # closed without the fix being confirmed
    if from_state == FIXED and to_state == IN_PROGRESS:
        return True                                  # "not fixed" — why?
    if from_state == CLOSED:
        return True                                  # reopen
    return False


def check_transition(from_state: str, to_state: str, reason: str = "") -> Decision:
    """Is from_state -> to_state a legal lifecycle move (ignoring who asks)?"""
    if from_state not in STATES:
        return _deny(f"unknown current state {from_state!r}")
    if to_state not in STATES:
        return _deny(f"unknown target state {to_state!r}; states are: {', '.join(STATES)}")
    if from_state == to_state:
        return _deny(f"ticket is already {to_state}")
    if to_state not in TRANSITIONS[from_state]:
        allowed = ", ".join(s for s in STATES if s in TRANSITIONS[from_state])
        return _deny(f"cannot move from {from_state} to {to_state}; from {from_state} "
                     f"a ticket can move to: {allowed}")
    if needs_reason(from_state, to_state) and not (reason or "").strip():
        return _deny(f"moving from {from_state} to {to_state} needs a reason")
    return _allow()


# ── Editions ─────────────────────────────────────────────────────────────────

SOLO = "solo"
BUSINESS = "business"
EDITIONS = (SOLO, BUSINESS)

_BOTH = frozenset({SOLO, BUSINESS})
_BIZ = frozenset({BUSINESS})

# feature -> editions that have it (spec: Solo edition feature table)
FEATURES = {
    "internal_tickets":      _BOTH,   # Solo: the Owner's own tickets
    "subcontractor_tickets": _BOTH,
    "queues":                _BIZ,
    "assignment_rules":      _BIZ,
    "round_robin":           _BIZ,
    "assign_to_others":      _BIZ,
    "sla_escalation":        _BIZ,
    "team_reports":          _BIZ,
    "customer_portal":       _BOTH,
    "customer_replies":      _BOTH,
    "attachments":           _BOTH,
    "jobs_links":            _BOTH,
    "due_reminders":         _BOTH,
    "export_import":         _BOTH,
    "backup":                _BOTH,
    "ai_tools":              _BOTH,
    "kanban":                _BOTH,
}

# Owner switches (Settings). Solo: both can be hidden. Business: only the
# subcontractor switch applies (internal tickets are core to a team).
DEFAULT_OPTIONS = {"own_tickets": True, "subcontractor_tickets": True}

# MCP tools that only make sense with a team (hidden and refused in Solo)
TEAM_ONLY_TOOLS = frozenset({"manage_ticket_queues"})


def edition_for_mode(mode: str) -> str:
    """personal mode -> Solo, server mode -> Business."""
    m = (mode or "").strip().lower()
    if m == "personal":
        return SOLO
    if m == "server":
        return BUSINESS
    raise ValueError(f"mode must be 'personal' or 'server', got {mode!r}")


def feature_enabled(edition: str, feature: str) -> bool:
    """Does this edition include the feature? Unknown names raise KeyError so a
    typo in a caller fails loudly in tests instead of silently hiding a feature."""
    if edition not in EDITIONS:
        raise ValueError(f"unknown edition {edition!r}")
    return edition in FEATURES[feature]


def tool_available(edition: str, tool_name: str) -> bool:
    """Is this Service Desk MCP tool offered in the edition?"""
    if edition not in EDITIONS:
        raise ValueError(f"unknown edition {edition!r}")
    return not (edition == SOLO and tool_name in TEAM_ONLY_TOOLS)


def kind_enabled(edition: str, kind: str, options: dict | None = None) -> Decision:
    """Can tickets of this kind be filed at all in this edition with these
    Owner switches? (Who may file them is decided by can().)"""
    opts = {**DEFAULT_OPTIONS, **(options or {})}
    if kind not in KINDS:
        return _deny(f"kind must be one of {', '.join(KINDS)}, got {kind!r}")
    if kind == INTERNAL:
        if not feature_enabled(edition, "internal_tickets"):
            return _deny("internal tickets are not available in this edition")
        if edition == SOLO and not opts["own_tickets"]:
            return _deny("own tickets are switched off in Service Desk settings")
    if kind == SUBCONTRACTOR_KIND:
        if not feature_enabled(edition, "subcontractor_tickets"):
            return _deny("subcontractor tickets are not available in this edition")
        if not opts["subcontractor_tickets"]:
            return _deny("subcontractor tickets are switched off in Service Desk settings")
    return _allow()


# ── Roles and the one gate ───────────────────────────────────────────────────

OWNER = "owner"
MANAGER = "manager"
STAFF = "staff"
FIELD_CREW = "field_crew"
CUSTOMER = "customer"
SUBCONTRACTOR = "subcontractor"

INTERNAL_ROLES = (OWNER, MANAGER, STAFF, FIELD_CREW)
EXTERNAL_ROLES = (CUSTOMER, SUBCONTRACTOR)
ROLES_BY_EDITION = {
    SOLO: frozenset({OWNER, CUSTOMER, SUBCONTRACTOR}),
    BUSINESS: frozenset({OWNER, MANAGER, STAFF, FIELD_CREW, CUSTOMER, SUBCONTRACTOR}),
}

ACTIONS = frozenset({
    "view", "create", "edit", "assign", "change_state", "note", "reply_customer",
    "attach", "delete", "manage_settings", "manage_queues", "report", "export",
    "import", "backup", "restore", "triage",
})


def normalize_actor(actor) -> dict:
    """None means the single owner of a personal install. Roles are lowercased;
    unknown roles fall to field_crew rights (most restricted internal role),
    matching _role_caps() in ai_prowler_mcp.py."""
    if actor is None:
        return {"id": "owner", "role": OWNER, "queues": []}
    a = dict(actor)
    role = (a.get("role") or "").strip().lower()
    if role not in INTERNAL_ROLES and role not in EXTERNAL_ROLES:
        role = FIELD_CREW
    a["role"] = role
    a["queues"] = list(a.get("queues") or [])
    return a


def is_external(actor) -> bool:
    return normalize_actor(actor)["role"] in EXTERNAL_ROLES


def _parse_iso(s):
    if not s:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _is_assignee(a: dict, t: dict) -> bool:
    return bool(t.get("assignee")) and t.get("assignee") == a.get("id")


def _is_filer(a: dict, t: dict) -> bool:
    return bool(t.get("filed_by")) and t.get("filed_by") == a.get("id")


def _in_my_queue(a: dict, t: dict) -> bool:
    return bool(t.get("queue_id")) and t.get("queue_id") in a.get("queues", [])


def _is_party(a: dict, t: dict) -> bool:
    """External actor named on the ticket (its contact)."""
    return bool(a.get("contact_id")) and t.get("contact_id") == a.get("contact_id")


def _can_view(a: dict, t: dict) -> Decision:
    role = a["role"]
    if role == OWNER:
        return _allow("owner sees every ticket")
    if role == CUSTOMER:
        if t.get("kind") == EXTERNAL and _is_party(a, t):
            return _allow("customer's own ticket")
        return _deny("customers can only see their own tickets")
    if role == SUBCONTRACTOR:
        if t.get("kind") == SUBCONTRACTOR_KIND and _is_party(a, t):
            return _allow("ticket shared with this subcontractor")
        return _deny("subcontractors can only see tickets shared with them")
    if t.get("visibility") == "private":
        if _is_filer(a, t):
            return _allow("filer of a private ticket")
        return _deny("private tickets are visible only to the person who filed them and the owner")
    if _is_assignee(a, t) or _is_filer(a, t):
        return _allow("assigned to or filed by you")
    # A ticket with no queue sits in the team's shared inbox: managers see it
    # (spec: "No match -> stays Open and alerts all managers"), and staff see it
    # while nobody owns it, so they can take it.
    if role == MANAGER and (_in_my_queue(a, t) or not t.get("queue_id")):
        return _allow("ticket is in one of your queues or the shared inbox")
    if role == STAFF and not t.get("assignee") and (_in_my_queue(a, t) or not t.get("queue_id")):
        return _allow("unassigned ticket in your queue or the shared inbox")
    return _deny(f"role '{role}' can only see tickets assigned to or filed by them"
                 + (" or in their queues" if role in (MANAGER, STAFF) else ""))


def can(actor, action: str, ticket: dict | None = None, *, edition: str = BUSINESS,
        options: dict | None = None, **kw) -> Decision:
    """THE permission check. Every Service Desk entry point calls this.

    actor:   None (personal-mode owner) or {"id", "role", "queues"?, "contact_id"?}
    action:  one of ACTIONS
    ticket:  the ticket row as a dict (needed for ticket-level actions)
    options: Owner switches (own_tickets, subcontractor_tickets); defaults on
    kw:      action details —
               create:        kind ("external"/"internal"/"subcontractor")
               assign:        assignee (target user id)
               change_state:  to_state, reason, now (datetime, for tests)
    """
    if action not in ACTIONS:
        raise ValueError(f"unknown action {action!r}")
    if edition not in EDITIONS:
        raise ValueError(f"unknown edition {edition!r}")
    a = normalize_actor(actor)
    role = a["role"]

    if role not in ROLES_BY_EDITION[edition]:
        return _deny(f"the {edition.title()} edition has no '{role}' role"
                     + ("; Solo has only the owner, customers and subcontractors"
                        if edition == SOLO else ""))

    # ── actions that don't need a ticket ──
    if action == "create":
        kind = kw.get("kind", EXTERNAL)
        enabled = kind_enabled(edition, kind, options)
        if not enabled:
            return enabled
        if role == SUBCONTRACTOR:
            return _deny("subcontractors reply on tickets shared with them; they cannot open tickets")
        if role == CUSTOMER and kind != EXTERNAL:
            return _deny("customers can only file customer (external) tickets")
        return _allow()
    if action in ("manage_settings", "import", "backup", "restore"):
        return _allow() if role == OWNER else _deny(f"only the owner can {action.replace('_', ' ')}")
    if action == "manage_queues":
        if not feature_enabled(edition, "queues"):
            return _deny("queues are a Business feature")
        return _allow() if role == OWNER else _deny("only the owner can manage queues")
    if action in ("report", "export", "triage"):
        return _allow() if role in (OWNER, MANAGER) else \
            _deny(f"only the owner or a manager can {action}")

    # ── ticket-level actions ──
    if ticket is None:
        raise ValueError(f"action {action!r} needs a ticket")
    t = ticket
    seen = _can_view(a, t)
    if action == "view":
        return seen
    if not seen:
        return seen

    if action == "delete":
        return _allow() if role == OWNER else _deny("only the owner can delete a ticket")

    if action in ("edit", "attach"):
        if role in (OWNER, MANAGER) or _is_assignee(a, t):
            return _allow()
        if action == "attach" and (role in EXTERNAL_ROLES or _is_filer(a, t)):
            return _allow("filer, customer or subcontractor may add attachments")
        return _deny("only the assignee, a manager or the owner can edit this ticket")

    if action == "note":
        if role in EXTERNAL_ROLES:
            return _deny("internal notes are for your team only")
        return _allow()

    if action == "reply_customer":          # a public message to the ticket's outside party
        if t.get("kind") == INTERNAL:
            return _deny("this is an internal ticket; there is no customer or subcontractor to message")
        if role in EXTERNAL_ROLES:
            return _allow("outside party replying on their own ticket")
        if role in (OWNER, MANAGER) or _is_assignee(a, t):
            return _allow()
        return _deny("only the assignee, a manager or the owner can message the outside party")

    if action == "assign":
        target = kw.get("assignee") or ""
        if role in EXTERNAL_ROLES:
            return _deny(f"{role}s cannot assign tickets")
        if edition == SOLO:
            if target and target != a["id"]:
                return _deny("in Solo every ticket goes to the owner")
            return _allow()
        if role in (OWNER, MANAGER):
            return _allow()
        # staff / field crew: self-assign an unassigned ticket only
        if target != a["id"]:
            return _deny(f"role '{role}' can only assign tickets to themselves")
        if t.get("assignee") and not _is_assignee(a, t):
            return _deny("this ticket already has an owner; ask a manager to reassign it")
        return _allow("self-assign")

    if action == "change_state":
        frm, to = t.get("state"), kw.get("to_state")
        reason = kw.get("reason", "")
        legal = check_transition(frm, to, reason)
        if not legal:
            return legal
        if role == OWNER:
            return _allow()
        if role == CUSTOMER:
            if frm == FIXED and to in (CLOSED, IN_PROGRESS):
                return _allow("customer confirms the fix or says it is not fixed")
            if frm == CLOSED and to == ASSIGNED:
                closed = _parse_iso(t.get("closed_at"))
                now = kw.get("now") or datetime.datetime.now(datetime.timezone.utc)
                if closed and now - closed <= datetime.timedelta(days=REOPEN_WINDOW_DAYS):
                    return _allow("customer reopen within the window")
                return _deny(f"customers can reopen a ticket only within {REOPEN_WINDOW_DAYS} days of closing")
            return _deny("customers can only confirm a fix, say it is not fixed, or reopen")
        if role == SUBCONTRACTOR:
            if to == FIXED and frm in (ASSIGNED, IN_PROGRESS):
                return _allow("subcontractor marks their part done")
            return _deny("subcontractors can only mark their part done")
        if role == MANAGER:
            return _allow()
        # staff / field crew
        if not _is_assignee(a, t):
            return _deny("only the assignee can change this ticket's state")
        if to == CLOSED:
            return _deny("only a manager or the owner can close a ticket")
        if frm == CLOSED:
            return _deny("only a manager or the owner can reopen a closed ticket")
        return _allow()

    raise ValueError(f"unhandled action {action!r}")  # pragma: no cover
