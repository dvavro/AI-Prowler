"""Server mode — SRV-API-12 (R-042, was gap G-03): recording a learning that
"supersedes" another retires the old one, so it follows the same ownership
rules as editing/deleting it: crew only their own, manager any employee's but
never the owner's, owner any.

Set-up and clean-up are automatic since 2026-10-25 (Vicki: tests that couldn't
be written because of cleanup). The Jobs app can create learnings but not
delete them — the OWNER can, through Claude's tools (/mcp): this module
  before: deletes any "ZTEST E2E R-042 …" learnings an interrupted run left,
          then records the owner learning "ZTEST E2E R-042 owner learning";
  after:  deletes every "ZTEST E2E R-042 …" learning — active AND the retired
          (archived) ones a supersede leaves — and checks none is left.
The write guard lets the owner delete a learning only when its title starts
with "ZTEST E2E" (looked up, never guessed). record_learning goes straight to
/pwa-api (the guard blocks it outright). All learnings here are tagged "ztest".

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_learnings
"""
import json
import logging
import re

import pytest

from ai_client import AiClient
from api import http

log = logging.getLogger("e2e_srv")

OWNER_TITLE = "ZTEST E2E R-042 owner learning"
PREFIX = "ZTEST E2E R-042"


def _call(srv, key, tool, args):
    st, raw = http("POST", srv["origin"] + "/pwa-api", {"tool": tool, "args": args},
                   token=srv["users"][key].access_token, timeout=60)
    try:
        return st, str(json.loads(raw).get("result", ""))
    except ValueError:
        return st, raw[:200]


def _find_id(srv, title):
    """(id, block) of the ACTIVE learning with exactly this title, or (None, '')."""
    _, res = _call(srv, "U1", "search_learnings", {"query": title, "n_results": 5})
    for block in res.split("───"):
        if re.search(rf"\]\s+✅\s+{re.escape(title)}\s*$", block, re.M):
            m = re.search(r"ID\s*:\s*([0-9a-f-]{36})", block)
            if m:
                return m.group(1), block
    return None, ""


def _record(srv, key, title, supersedes=""):
    return _call(srv, key, "record_learning", {
        "title": title, "content": "Throw-away SRV-API-12 test learning. Safe to delete.",
        "tags": "ztest", "supersedes_id": supersedes})


def _owner_ai(srv, guard):
    return AiClient(srv["origin"], srv["owner"].token, guard, "U1")


def _test_learnings(srv, guard):
    """[(id, title)] of every ztest-tagged R-042 learning, any status (owner, /mcp)."""
    res = _owner_ai(srv, guard).call("list_learnings", {"status": "", "tag": "ztest", "limit": 500},
                                     expect_ok=False)
    out = []
    for block in re.split(r"\n\s*\n", res):
        m = re.search(r"^\[\d+\]\s+\S+\s+(.+?)\s*$", block, re.M)
        i = re.search(r"ID:\s*([0-9a-fA-F-]{36})", block)
        if m and i and m.group(1).strip().startswith(PREFIX):
            out.append((i.group(1), m.group(1).strip()))
    return out


def _delete_all(srv, guard) -> list:
    ai = _owner_ai(srv, guard)
    for lid, title in _test_learnings(srv, guard):
        out = ai.call("delete_learning", {"learning_id": lid}, expect_ok=False)
        log.info(f"[SRV-API-12] owner deletes {title!r} ({lid}) -> {out.splitlines()[0][:120] if out else ''}")
    return _test_learnings(srv, guard)


@pytest.fixture(scope="module")
def owner_learning(srv, owner_api, guard):
    # owner_api sets the guard's learning lookup (title by id) the delete rule needs
    left = _delete_all(srv, guard)
    assert not left, f"couldn't remove learnings an earlier run left: {left}"
    st, res = _record(srv, "U1", OWNER_TITLE)
    assert st == 200 and "✅" in res, f"owner couldn't record the set-up learning: {st} {res[:200]}"
    lid, _ = _find_id(srv, OWNER_TITLE)
    assert lid, "the owner's set-up learning isn't found as active after recording it"
    yield lid
    left = _delete_all(srv, guard)
    assert not left, f"SRV-API-12 learnings left after clean-up: {left}"


@pytest.mark.parametrize("key", ["U3", "U2"])     # field crew, manager
def test_SRV_API_12_cannot_retire_the_owners_learning(srv, owner_learning, key):
    title = f"ZTEST E2E R-042 attempt by {key}"
    st, res = _record(srv, key, title, supersedes=owner_learning)
    log.info(f"[SRV-API-12] {key} supersedes owner's learning -> HTTP {st}: {res.splitlines()[0][:160]}")
    assert st == 200 and res.lstrip().startswith("⛔") and "Nothing was recorded" in res, res[:200]
    assert _find_id(srv, OWNER_TITLE)[0] == owner_learning, "the owner's learning is no longer active"
    assert _find_id(srv, title)[0] is None, "a refused supersede still recorded a new learning"


def test_SRV_API_12_control_crew_can_retire_their_own_learning(srv, owner_learning):
    st, res = _record(srv, "U3", "ZTEST E2E R-042 crew original")
    assert st == 200 and "✅" in res, res[:200]
    old = re.search(r"ID\s*:\s*([0-9a-f-]{36})", res).group(1)
    st, res = _record(srv, "U3", "ZTEST E2E R-042 crew replacement", supersedes=old)
    log.info(f"[SRV-API-12] Samual supersedes his own learning -> HTTP {st}: {res.splitlines()[0][:160]}")
    assert st == 200 and not res.lstrip().startswith(("⛔", "❌")), res[:200]
    assert _find_id(srv, "ZTEST E2E R-042 crew original")[0] is None, "his own old learning is still active"
