"""
tests/mcp_tests/test_r042_supersedes_ownership.py
============================================
R-042 (was gap G-03, found by spec review 2026-09-26, fixed 2026-09-27):
record_learning(supersedes_id=X) marks learning X as deprecated — a change to
X — but used to do it for ANY caller. In server mode a field crew member could
retire the owner's or a co-worker's learning by "superseding" it.

Now superseding follows the same rules as update_learning / delete_learning
(_can_modify_learning):
  • owner            — may supersede any learning
  • manager          — any employee's, never the owner's
  • staff/field_crew — only their own (or an unattributed legacy one)
  • unknown id       — refused in server mode (nothing to check ownership of)
  • personal mode    — unchanged, no gate
A refused call records NOTHING (no new learning, old one untouched).
"""
from __future__ import annotations

import json

import pytest

OWNER_ID = "tok_owner"


class _Stub:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def _ctx(user):
    return None if user is None else _Stub(request_context=_Stub(request=_Stub(state=_Stub(user=user))))


def _user(uid, name, role, manager=False):
    return {"id": uid, "name": name, "role": role, "email": f"{uid}@example.com",
            "status": "active", "scopes": [], "private_collection_enabled": False,
            "can_manage_users": manager}


OWNER = _user(OWNER_ID, "Olive Owner", "owner", manager=True)
MANAGER = _user("tok_mgr", "Manny Manager", "manager", manager=True)
CREW_A = _user("tok_crew_a", "Casey CrewA", "field_crew")
CREW_B = _user("tok_crew_b", "Blake CrewB", "field_crew")


@pytest.fixture
def env(sl_mcp_env, monkeypatch):
    monkeypatch.setattr(sl_mcp_env.mcp, "_owner_user_id", lambda: OWNER_ID)
    return sl_mcp_env


def _all(env) -> list[dict]:
    if not env.learnings_file.exists():          # nothing recorded yet
        return []
    return json.loads(env.learnings_file.read_text(encoding="utf-8"))["learnings"]


def _record(env, author, title):
    env.mcp.record_learning(title=title, content=f"{title} content", ctx=_ctx(author))
    return next(l for l in _all(env) if l["title"] == title)


def _supersede(env, actor, old_id, title="Replacement"):
    return env.mcp.record_learning(title=title, content="replaces the old one",
                                   supersedes_id=old_id, ctx=_ctx(actor))


def _assert_refused(env, out, old_id, count_before):
    assert out.startswith("⛔") and "Nothing was recorded" in out, out
    rows = _all(env)
    assert len(rows) == count_before, "a refused supersede still recorded a new learning"
    old = next((l for l in rows if l["id"] == old_id), None)
    if old is not None:
        assert old["status"] == "active" and not old["superseded_by"], "the old learning was changed"


def _assert_superseded(env, out, old_id):
    assert not out.startswith(("⛔", "❌")), out
    old = next(l for l in _all(env) if l["id"] == old_id)
    assert old["status"] == "deprecated" and old["superseded_by"], old


# ── refused ───────────────────────────────────────────────────────────────────
def test_R042_01_crew_cannot_supersede_coworkers_learning(env):
    old = _record(env, CREW_B, "Blake's tip")
    n = len(_all(env))
    _assert_refused(env, _supersede(env, CREW_A, old["id"]), old["id"], n)


def test_R042_02_crew_cannot_supersede_owners_learning(env):
    old = _record(env, OWNER, "Owner's rule")
    n = len(_all(env))
    _assert_refused(env, _supersede(env, CREW_A, old["id"]), old["id"], n)


def test_R042_03_manager_cannot_supersede_owners_learning(env):
    old = _record(env, OWNER, "Owner's policy")
    n = len(_all(env))
    _assert_refused(env, _supersede(env, MANAGER, old["id"]), old["id"], n)


def test_R042_04_unknown_id_refused_in_server_mode(env):
    _record(env, CREW_A, "Something")
    n = len(_all(env))
    out = _supersede(env, CREW_A, "00000000-no-such-learning")
    _assert_refused(env, out, "00000000-no-such-learning", n)
    assert "not found" in out


def test_R042_05_refusal_message_names_the_learning(env):
    old = _record(env, CREW_B, "Blake's other tip")
    out = _supersede(env, CREW_A, old["id"])
    assert old["id"] in out and "another user" in out, out


# ── allowed ───────────────────────────────────────────────────────────────────
def test_R042_06_crew_can_supersede_own_learning(env):
    old = _record(env, CREW_A, "Casey's first try")
    _assert_superseded(env, _supersede(env, CREW_A, old["id"]), old["id"])


def test_R042_07_manager_can_supersede_crew_learning(env):
    old = _record(env, CREW_B, "Blake's outdated note")
    _assert_superseded(env, _supersede(env, MANAGER, old["id"]), old["id"])


def test_R042_08_owner_can_supersede_anyones_learning(env):
    for author, title in ((CREW_A, "Crew note"), (MANAGER, "Manager note"), (OWNER, "Owner note")):
        old = _record(env, author, title)
        _assert_superseded(env, _supersede(env, OWNER, old["id"], title=f"{title} v2"), old["id"])


def test_R042_09_crew_can_supersede_unattributed_legacy_learning(env):
    old = _record(env, None, "Legacy personal-mode learning")     # no recorded_by_id
    _assert_superseded(env, _supersede(env, CREW_A, old["id"]), old["id"])


def test_R042_10_personal_mode_unchanged(env):
    old = _record(env, None, "Personal learning")
    _assert_superseded(env, _supersede(env, None, old["id"]), old["id"])


def test_R042_11_no_supersedes_id_is_not_gated(env):
    n = len(_all(env))
    out = env.mcp.record_learning(title="Plain new learning", content="no supersede", ctx=_ctx(CREW_A))
    assert not out.startswith(("⛔", "❌")), out
    assert len(_all(env)) == n + 1
