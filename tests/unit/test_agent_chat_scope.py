"""David 2026-11-05: on a server the tools and screens that manage the agents follow the user's role and scope."""
from __future__ import annotations

import json
import pathlib
import sys

import desk_db
import desk_rules as r
import desk_tools as dt
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_desk_agent_core import customer_ticket, env, setv  # noqa: F401 (env is a fixture)

B = r.BUSINESS
OWNER = {"id": "owner", "role": "owner", "queues": []}
MIA = {"id": "mia", "role": "manager", "queues": ["q-mine"]}
LEO = {"id": "leo", "role": "manager", "queues": ["q-other"]}


def _queue(env, ticket, queue):
    conn = desk_db.get_connection(env[0])
    conn.execute("UPDATE tickets SET queue_id = ? WHERE ticket_id = ?", (queue, ticket["ticket_id"]))
    conn.commit()
    conn.close()


@pytest.fixture
def two(env):
    setv(env, agent_enabled=True, agent_shadow=False)
    a, b = customer_ticket(env), customer_ticket(env)
    _queue(env, a, "q-mine")
    _queue(env, b, "q-other")
    return env, a["ticket_id"], b["ticket_id"]


def _next(env, actor, limit=10):
    import desk_agent as ag
    items = ag.next_items(env[0], edition=B, limit=limit, jobs_db=env[1]).get("items") or []
    for i in items:
        i["ref"] = dt._agent_row(env[0], "agent_queue", "item_id", i["item_id"])["ref"]
    return items


@pytest.mark.parametrize("role", ["staff", "field_crew"])
def test_other_roles_are_refused_every_tool(two, role):
    env, *_ = two
    who = {"id": "sam", "role": role, "queues": ["q-mine"]}
    assert dt.desk_agent_review(env[0], who, B).startswith("❌")
    assert dt.desk_agent_status(env[0], who, B).startswith("❌")
    assert dt.desk_agent_run_now(env[0], who, B).startswith("❌")


def test_a_private_ticket_never_reaches_a_chat(env):
    setv(env, agent_enabled=True, agent_shadow=False)
    t = customer_ticket(env)
    conn = desk_db.get_connection(env[0])
    conn.execute("UPDATE tickets SET visibility = 'private' WHERE ticket_id = ?", (t["ticket_id"],))
    conn.commit()
    conn.close()
    assert t["ticket_id"] not in {i["ref"] for i in _next(env, OWNER)}


def _suggest(env, other):
    """A suggestion the agent made on the ticket in the other queue."""
    import desk_agent as ag
    for item in _next(env, OWNER):
        out = ag.submit(env[0], item["item_id"], [{"action": "set_type", "type": "Quality", "why": "x", "confidence": 0.9}],
                        edition=B, jobs_db=env[1])
        pid = out["results"][0].get("proposal_id")
        if pid and item["ref"] == other:
            return other, pid
    raise AssertionError("no suggestion was recorded")


def test_review_follows_the_same_scope(two):
    env, mine, other = two
    ref, pid = _suggest(env, other)
    assert pid, "no suggestion was recorded"
    assert ref not in dt.desk_agent_review(env[0], MIA, B)
    assert ref in dt.desk_agent_review(env[0], LEO, B)
    out = dt.desk_agent_review(env[0], MIA, B, action="approve", proposal_id=pid, jobs_db=env[1])
    assert out.startswith("❌") and "outside" in out, out


def test_bookings_follow_the_managers_booking_permission(env):
    desk_db.set_setting(env[0], "booking_approve_managers", True, edition=B)
    assert dt._agent_may(env[0], MIA, B, "booking", "JOB-1")
    desk_db.set_setting(env[0], "booking_approve_managers", False, edition=B)
    assert not dt._agent_may(env[0], MIA, B, "booking", "JOB-1")
    assert dt._agent_may(env[0], OWNER, B, "booking", "JOB-1")


def test_hr_never_goes_through_these_tools_for_a_manager(env):
    assert not dt._agent_may(env[0], MIA, B, "hr", "pto:1")


def test_a_personal_install_is_not_limited(two):
    env, mine, other = two
    assert dt._agent_may(env[0], None, r.SOLO, "ticket", other)


# ── the Service Desk app's 🤖 tab: the same scope ───────────────────────────
def _http(env, method, path, actor):
    import desk_http
    st, _ct, body = desk_http.route(method, path, query={}, body=b"{}", content_type="application/json", actor=actor,
                                    edition=B, db_path=env[0])
    return st, json.loads(body)


def test_the_app_tab_shows_a_manager_only_their_scope(two):
    env, mine, other = two
    ref, pid = _suggest(env, other)
    theirs = {p["ref"] for p in _http(env, "GET", "/desk-api/agent/inbox", LEO)[1]["pending"]}
    outside = {p["ref"] for p in _http(env, "GET", "/desk-api/agent/inbox", MIA)[1]["pending"]}
    assert ref in theirs and ref not in outside, (theirs, outside)
    assert ref in {p["ref"] for p in _http(env, "GET", "/desk-api/agent/inbox", OWNER)[1]["pending"]}


def test_the_app_refuses_approving_outside_a_managers_scope(two):
    env, mine, other = two
    ref, pid = _suggest(env, other)
    st, d = _http(env, "POST", f"/desk-api/agent/proposals/{pid}/approve", MIA)
    assert st != 200 and "outside" in str(d), (st, d)
    st, d = _http(env, "POST", f"/desk-api/agent/proposals/{pid}/approve", OWNER)
    assert st == 200, (st, d)


# ── practice cards: rating clears them, the rating stays ───────────────────
def _practice(env):
    import desk_agent as ag
    setv(env, agent_enabled=True, agent_shadow=True)
    customer_ticket(env)
    for _ in range(6):                     # the queue also holds other stages, where this action isn't allowed
        item = _next(env, OWNER, limit=1)[0]
        out = ag.submit(env[0], item["item_id"], [{"action": "set_type", "type": "Quality", "why": "x", "confidence": 0.9}],
                        edition=B, jobs_db=env[1])
        if out["results"][0].get("proposal_id"):
            return ag, out["results"][0]["proposal_id"]
    raise AssertionError(out)


def test_a_rated_practice_card_leaves_the_list_and_counts(env):
    ag, pid = _practice(env)
    assert pid in [p["proposal_id"] for p in ag.inbox(env[0], status="practice", unrated=True)]
    ag.review(env[0], pid, "down", actor_=None, edition=r.SOLO)
    assert pid not in [p["proposal_id"] for p in ag.inbox(env[0], status="practice", unrated=True)]
    assert pid in [p["proposal_id"] for p in ag.inbox(env[0], status="practice")]
    assert ag.status(env[0])["rated_not_right"] == 1 and ag.status(env[0])["rated_good"] == 0


def test_after_7_days_an_unrated_card_goes_but_a_rated_one_stays(env):
    ag, old = _practice(env)
    _, rated = _practice(env)
    ag.review(env[0], rated, "up", actor_=None, edition=r.SOLO)
    conn = ag._conn(env[0])
    conn.execute("UPDATE agent_proposals SET created_at = '2020-01-01T00:00:00Z' WHERE proposal_id IN (?, ?)", (old, rated))
    conn.commit()
    conn.close()
    ag.expire(env[0])
    assert dt._agent_row(env[0], "agent_proposals", "proposal_id", old)["status"] == "expired"
    assert dt._agent_row(env[0], "agent_proposals", "proposal_id", rated)["status"] == "practice"
    assert ag.status(env[0])["rated_good"] == 1


def test_ratings_are_kept_by_agent(env):
    import desk_agent as ag
    ag._conn(env[0]).close()
    conn = ag._conn(env[0])
    rows = [("ticket", "up"), ("ticket", "up"), ("ticket", "down"), ("booking", "down"), ("ticket", "")]
    for i, (kind, fb) in enumerate(rows):
        conn.execute("INSERT INTO agent_proposals (kind, ref, stage, action, payload_json, status, feedback, created_at) "
                     "VALUES (?, ?, 's', 'a', '{}', 'practice', ?, '2030-01-01T00:00:00Z')", (kind, f"r{i}", fb))
    conn.commit()
    conn.close()
    got = ag.ratings(env[0])
    assert got["rated_by"] == {"ticket": {"good": 2, "not_right": 1}, "booking": {"good": 0, "not_right": 1}}
    assert (got["rated_good"], got["rated_not_right"]) == (2, 2)


# ── David 2026-11-05: no saved key, no agent ─────────────────────────────────
@pytest.mark.no_agent_key
def test_no_key_nothing_is_queued_and_the_status_says_why(env, monkeypatch):
    import desk_agent as ag
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "_key", lambda p: "")
    monkeypatch.setattr(ag, "transport", None)
    setv(env, agent_enabled=True, agent_shadow=False)
    t = customer_ticket(env)
    s = desk_db.get_settings(env[0])
    assert s["agent_provider"] == "chat_only" and not ag._has_key(s) and not ag._any_on(s)
    assert ag.enqueue(env[0], ag.TICKET, t["ticket_id"], "first_reply", "x", settings=s) is None
    assert ag.status(env[0])["waiting"] == 0
    assert "no API key" in ag.why_not_run(env[0], s, edition=r.SOLO, now=ag._now())
    assert "off" in ag.next_items(env[0], edition=r.SOLO)["message"]


@pytest.mark.no_agent_key
@pytest.mark.parametrize("saved,want", [({"claude_api"}, "claude_api"), ({"grok_api"}, "grok_api"), ({"claude_api", "grok_api"}, "claude_api")])
def test_a_saved_key_is_all_it_takes(env, monkeypatch, saved, want):
    import desk_agent as ag
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "_key", lambda p: "k" if p in saved else "")
    setv(env, agent_enabled=True)
    s = desk_db.get_settings(env[0])
    assert s["agent_provider"] == want and ag._has_key(s) and ag._any_on(s)


@pytest.mark.no_agent_key
def test_a_key_for_a_different_ai_than_chosen_does_not_run(env, monkeypatch):
    import desk_agent as ag
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "_key", lambda p: "k" if p == "grok_api" else "")
    monkeypatch.setattr(ag, "transport", None)
    assert not ag._has_key({"agent_provider": "claude_api"})


def test_the_two_queue_tools_are_gone_from_a_chat():
    src = (pathlib.Path(__file__).parents[2] / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert "def desk_agent_next" not in src and "def desk_agent_submit" not in src
    cat = (pathlib.Path(__file__).parents[2] / "mcp_tool_catalog.py").read_text(encoding="utf-8")
    assert "desk_agent_next" not in cat and "desk_agent_submit" not in cat


def test_the_prompt_for_the_ai_names_no_chat_tools():
    import desk_agent as ag
    assert "desk_agent_next" not in ag.SYSTEM_PROMPT and "desk_agent_submit" not in ag.SYSTEM_PROMPT
    assert not hasattr(ag, "CHAT_PROMPT") and not hasattr(dt, "desk_agent_next") and not hasattr(dt, "desk_agent_submit")
    assert "chat_prompt" not in ag.status.__code__.co_consts
