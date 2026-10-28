"""Service Desk Phase 0 — desk_rules: lifecycle, role gate, edition matrix."""
import datetime
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_rules as r  # noqa: E402

UTC = datetime.timezone.utc

# ── Lifecycle ────────────────────────────────────────────────────────────────

LEGAL = [(f, t) for f in r.STATES for t in r.TRANSITIONS[f]]
ILLEGAL = [(f, t) for f in r.STATES for t in r.STATES if f != t and t not in r.TRANSITIONS[f]]


@pytest.mark.parametrize("frm,to", LEGAL)
def test_every_legal_transition_passes_with_a_reason(frm, to):
    assert r.check_transition(frm, to, reason="because")


@pytest.mark.parametrize("frm,to", ILLEGAL)
def test_every_illegal_transition_is_refused(frm, to):
    d = r.check_transition(frm, to, reason="because")
    assert not d and "cannot move" in d.reason


@pytest.mark.parametrize("frm,to", [(f, t) for f, t in LEGAL if r.needs_reason(f, t)])
def test_reason_required_moves_refuse_a_blank_reason(frm, to):
    d = r.check_transition(frm, to, reason="   ")
    assert not d and "needs a reason" in d.reason


@pytest.mark.parametrize("frm,to", [(f, t) for f, t in LEGAL if not r.needs_reason(f, t)])
def test_routine_moves_need_no_reason(frm, to):
    assert r.check_transition(frm, to)


def test_reason_rules_match_the_spec():
    assert r.needs_reason(r.IN_PROGRESS, r.ON_HOLD)
    assert r.needs_reason(r.ASSIGNED, r.CLOSED)          # close without customer confirming
    assert not r.needs_reason(r.FIXED, r.CLOSED)         # customer confirmed
    assert r.needs_reason(r.FIXED, r.IN_PROGRESS)        # not fixed
    assert r.needs_reason(r.CLOSED, r.ASSIGNED)          # reopen


def test_same_state_and_unknown_states_are_refused():
    assert not r.check_transition(r.OPEN, r.OPEN)
    assert not r.check_transition("Bogus", r.OPEN)
    assert not r.check_transition(r.OPEN, "Done")


def test_every_state_can_eventually_reach_closed():
    for start in r.STATES:
        seen, todo = {start}, [start]
        while todo:
            for n in r.TRANSITIONS[todo.pop()]:
                if n not in seen:
                    seen.add(n)
                    todo.append(n)
        assert r.CLOSED in seen, start


# ── Editions ─────────────────────────────────────────────────────────────────

def test_mode_maps_to_edition():
    assert r.edition_for_mode("personal") == r.SOLO
    assert r.edition_for_mode("SERVER") == r.BUSINESS
    with pytest.raises(ValueError):
        r.edition_for_mode("desktop")


@pytest.mark.parametrize("feature", ["queues", "assignment_rules",
                                     "round_robin", "assign_to_others", "sla_escalation",
                                     "team_reports"])
def test_team_features_are_business_only(feature):
    assert r.feature_enabled(r.BUSINESS, feature)
    assert not r.feature_enabled(r.SOLO, feature)


@pytest.mark.parametrize("feature", ["internal_tickets", "subcontractor_tickets",
                                     "customer_portal", "customer_replies", "attachments",
                                     "jobs_links", "due_reminders", "export_import", "backup",
                                     "ai_tools", "kanban"])
def test_customer_features_are_in_both_editions(feature):
    assert r.feature_enabled(r.SOLO, feature) and r.feature_enabled(r.BUSINESS, feature)


def test_unknown_feature_fails_loudly():
    with pytest.raises(KeyError):
        r.feature_enabled(r.SOLO, "teleport")


def test_team_only_tools_hidden_in_solo():
    assert not r.tool_available(r.SOLO, "manage_ticket_queues")
    assert r.tool_available(r.BUSINESS, "manage_ticket_queues")
    assert r.tool_available(r.SOLO, "create_ticket")


# ── Actors and tickets used by the role matrix ───────────────────────────────

OWNER = None                                                   # personal-mode owner
OWNER_S = {"id": "dave", "role": "owner"}
MANAGER = {"id": "mgr", "role": "manager", "queues": ["field"]}
STAFF = {"id": "sam", "role": "staff", "queues": ["field"]}
CREW = {"id": "cris", "role": "field_crew"}
CREW2 = {"id": "other", "role": "field_crew"}
CUST = {"id": "c1", "role": "customer", "contact_id": "C-1"}
CUST2 = {"id": "c2", "role": "customer", "contact_id": "C-2"}


def T(**kw):
    t = {"ticket_id": "T-0001", "kind": "external", "state": r.ASSIGNED, "queue_id": "field",
         "assignee": "cris", "filed_by": "sam", "contact_id": "C-1", "visibility": "normal"}
    t.update(kw)
    return t


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        r.can(OWNER, "teleport", T())


def test_unknown_role_gets_most_restricted_internal_rights():
    assert r.normalize_actor({"id": "x", "role": "intern"})["role"] == r.FIELD_CREW


# view
@pytest.mark.parametrize("actor,ticket,ok", [
    (OWNER_S, T(), True),
    (MANAGER, T(), True),                                      # in their queue
    (MANAGER, T(queue_id="office", assignee="x", filed_by="y"), False),
    (MANAGER, T(queue_id=None, assignee="x", filed_by="y"), True),       # shared inbox
    (STAFF, T(queue_id=None, assignee=None, filed_by="y"), True),        # take from inbox
    (STAFF, T(queue_id=None, assignee="x", filed_by="y"), False),        # owned by someone
    (CREW2, T(queue_id=None, assignee=None, filed_by="y"), False),
    (STAFF, T(), True),                                        # filed it
    (STAFF, T(filed_by="x", assignee=None), True),             # unassigned in their queue
    (STAFF, T(filed_by="x", assignee="cris"), False),
    (CREW, T(), True),                                         # assigned
    (CREW2, T(), False),
    (CUST, T(), True),
    (CUST2, T(), False),
    (CUST, T(kind="internal"), False),
    (MANAGER, T(visibility="private", filed_by="cris"), False),
    (CREW, T(visibility="private", filed_by="cris"), True),
    (OWNER_S, T(visibility="private", filed_by="cris"), True),
])
def test_view_matrix(actor, ticket, ok):
    assert bool(r.can(actor, "view", ticket)) is ok


# change_state by role
def test_crew_can_work_their_ticket_up_to_fixed_but_not_close():
    assert r.can(CREW, "change_state", T(), to_state=r.IN_PROGRESS)
    assert r.can(CREW, "change_state", T(state=r.IN_PROGRESS), to_state=r.FIXED)
    d = r.can(CREW, "change_state", T(state=r.FIXED), to_state=r.CLOSED)
    assert not d and "manager or the owner" in d.reason


def test_crew_cannot_change_someone_elses_ticket():
    assert not r.can(CREW2, "change_state", T(filed_by="other"), to_state=r.IN_PROGRESS)


def test_manager_closes_unconfirmed_only_with_reason():
    assert not r.can(MANAGER, "change_state", T(state=r.IN_PROGRESS), to_state=r.CLOSED)
    assert r.can(MANAGER, "change_state", T(state=r.IN_PROGRESS), to_state=r.CLOSED,
                 reason="duplicate of T-0002")


def test_customer_confirms_or_rejects_fix():
    assert r.can(CUST, "change_state", T(state=r.FIXED), to_state=r.CLOSED)
    assert r.can(CUST, "change_state", T(state=r.FIXED), to_state=r.IN_PROGRESS,
                 reason="still streaky")
    assert not r.can(CUST, "change_state", T(state=r.IN_PROGRESS), to_state=r.FIXED)


def test_customer_reopen_window():
    closed = datetime.datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    t = T(state=r.CLOSED, closed_at=closed.isoformat())
    day6 = closed + datetime.timedelta(days=6)
    day8 = closed + datetime.timedelta(days=8)
    assert r.can(CUST, "change_state", t, to_state=r.ASSIGNED, reason="came back", now=day6)
    d = r.can(CUST, "change_state", t, to_state=r.ASSIGNED, reason="came back", now=day8)
    assert not d and "7 days" in d.reason


def test_staff_cannot_reopen_closed():
    t = T(state=r.CLOSED, assignee="sam", closed_at="2026-10-26T00:00:00+00:00")
    assert not r.can(STAFF, "change_state", t, to_state=r.ASSIGNED, reason="x")


# assign
def test_assignment_rules():
    assert r.can(MANAGER, "assign", T(), assignee="sam")
    assert r.can(STAFF, "assign", T(assignee=None, filed_by="x"), assignee="sam")      # self
    assert not r.can(STAFF, "assign", T(assignee=None, filed_by="x"), assignee="cris")
    assert not r.can(STAFF, "assign", T(assignee="cris"), assignee="sam")               # taken
    assert not r.can(CUST, "assign", T(), assignee="sam")


# replies and notes
def test_reply_and_note_rules():
    assert r.can(CREW, "reply_customer", T())
    assert not r.can(CREW, "reply_customer", T(kind="internal", contact_id=None))
    assert not r.can(CUST, "note", T())
    assert r.can(CUST, "reply_customer", T())


# owner-only and manager actions
@pytest.mark.parametrize("action", ["manage_settings", "import", "backup", "restore"])
def test_owner_only_actions(action):
    assert r.can(OWNER_S, action)
    assert not r.can(MANAGER, action)
    assert not r.can(CREW, action)


@pytest.mark.parametrize("action", ["report", "export", "triage"])
def test_owner_and_manager_actions(action):
    assert r.can(OWNER_S, action) and r.can(MANAGER, action)
    assert not r.can(STAFF, action)


def test_only_owner_deletes():
    assert r.can(OWNER_S, "delete", T())
    assert not r.can(MANAGER, "delete", T())


# ── Solo edition through the gate ────────────────────────────────────────────

def test_solo_has_only_owner_customers_and_subcontractors():
    for actor in (MANAGER, STAFF, CREW):
        d = r.can(actor, "view", T(), edition=r.SOLO)
        assert not d and "Solo has only the owner, customers and subcontractors" in d.reason
    assert r.can(OWNER, "view", T(), edition=r.SOLO)
    assert r.can(CUST, "view", T(), edition=r.SOLO)


def test_solo_owner_files_own_and_subcontractor_tickets_by_default():
    for kind in ("external", "internal", "subcontractor"):
        assert r.can(OWNER, "create", edition=r.SOLO, kind=kind), kind
    assert r.can(CUST, "create", edition=r.SOLO, kind="external")


def test_solo_switches_hide_own_and_subcontractor_tickets():
    off = {"own_tickets": False, "subcontractor_tickets": False}
    d = r.can(OWNER, "create", edition=r.SOLO, kind="internal", options=off)
    assert not d and "switched off" in d.reason
    d = r.can(OWNER, "create", edition=r.SOLO, kind="subcontractor", options=off)
    assert not d and "switched off" in d.reason
    assert r.can(OWNER, "create", edition=r.SOLO, kind="external", options=off)


def test_own_ticket_switch_does_not_limit_business_internal_tickets():
    assert r.can(OWNER_S, "create", edition=r.BUSINESS, kind="internal",
                 options={"own_tickets": False})


def test_unknown_kind_refused():
    assert not r.can(OWNER, "create", edition=r.SOLO, kind="memo")


# ── Subcontractors ───────────────────────────────────────────────────────────

SUB = {"id": "s1", "role": "subcontractor", "contact_id": "CT-0009"}
SUB2 = {"id": "s2", "role": "subcontractor", "contact_id": "CT-0010"}


def ST(**kw):
    return T(kind="subcontractor", contact_id="CT-0009", assignee="owner", filed_by="owner", **kw)


def test_subcontractor_sees_only_tickets_shared_with_them():
    assert r.can(SUB, "view", ST(), edition=r.SOLO)
    assert not r.can(SUB2, "view", ST(), edition=r.SOLO)
    assert not r.can(SUB, "view", T(contact_id="CT-0009"), edition=r.SOLO)   # a customer ticket


def test_subcontractor_actions():
    assert r.can(SUB, "reply_customer", ST(), edition=r.SOLO)
    assert r.can(SUB, "attach", ST(), edition=r.SOLO)
    assert not r.can(SUB, "note", ST(), edition=r.SOLO)
    assert not r.can(SUB, "create", edition=r.SOLO, kind="subcontractor")
    assert not r.can(SUB, "assign", ST(), edition=r.SOLO, assignee="s1")
    assert r.can(SUB, "change_state", ST(state=r.IN_PROGRESS), edition=r.SOLO, to_state=r.FIXED)
    assert not r.can(SUB, "change_state", ST(state=r.FIXED), edition=r.SOLO, to_state=r.CLOSED)


def test_internal_ticket_has_no_outside_party_to_message():
    d = r.can(OWNER, "reply_customer", T(kind="internal", contact_id=None), edition=r.SOLO)
    assert not d and "internal ticket" in d.reason


def test_solo_assigns_only_to_owner():
    assert r.can(OWNER, "assign", T(), edition=r.SOLO, assignee="owner")
    assert not r.can(OWNER, "assign", T(), edition=r.SOLO, assignee="somebody")


def test_solo_refuses_queue_management():
    assert not r.can(OWNER, "manage_queues", edition=r.SOLO)
    assert r.can(OWNER_S, "manage_queues", edition=r.BUSINESS)


def test_customers_never_file_internal_tickets():
    assert not r.can(CUST, "create", edition=r.BUSINESS, kind="internal")
    assert not r.can(CUST, "create", edition=r.BUSINESS, kind="subcontractor")
