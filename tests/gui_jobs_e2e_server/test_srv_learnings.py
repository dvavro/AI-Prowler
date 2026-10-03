"""Server mode — SRV-API-12 (R-042, was gap G-03): recording a learning that
"supersedes" another retires the old one, so it follows the same ownership
rules as editing/deleting it: crew only their own, manager any employee's but
never the owner's, owner any.

Setup / cleanup are done OUTSIDE this file, as the owner, because the Jobs app
can create learnings but not delete them:
  before: an owner learning titled "ZTEST E2E R-042 owner learning" exists
  after:  every learning titled "ZTEST E2E R-042 …" is deleted
Calls go straight to /pwa-api (the write guard blocks record_learning outright).
Everything this file creates is titled "ZTEST E2E R-042 …".

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_learnings
"""
import json
import logging
import re

import pytest

from api import http

log = logging.getLogger("e2e_srv")

OWNER_TITLE = "ZTEST E2E R-042 owner learning"


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


@pytest.fixture(scope="module")
def owner_learning(srv):
    lid, _ = _find_id(srv, OWNER_TITLE)
    if not lid:
        pytest.skip(f"setup missing: create an owner learning titled {OWNER_TITLE!r} first")
    return lid


@pytest.mark.parametrize("key", ["U3", "U2"])     # field crew, manager
def test_SRV_API_12_cannot_retire_the_owners_learning(srv, owner_learning, key):
    title = f"ZTEST E2E R-042 attempt by {key}"
    st, res = _record(srv, key, title, supersedes=owner_learning)
    log.info(f"[SRV-API-12] {key} supersedes owner's learning -> HTTP {st}: {res.splitlines()[0][:160]}")
    assert st == 200 and res.lstrip().startswith("⛔") and "Nothing was recorded" in res, res[:200]
    assert _find_id(srv, OWNER_TITLE)[0] == owner_learning, "the owner's learning is no longer active"
    assert _find_id(srv, title)[0] is None, "a refused supersede still recorded a new learning"


def test_SRV_API_12_control_crew_can_retire_their_own_learning(srv, owner_learning):
    # Takes owner_learning only so the control skips with the rest of SRV-API-12 when
    # David hasn't set it up — this test records 2 learnings the suite can't clean up.
    st, res = _record(srv, "U3", "ZTEST E2E R-042 crew original")
    assert st == 200 and "✅" in res, res[:200]
    old = re.search(r"ID\s*:\s*([0-9a-f-]{36})", res).group(1)
    st, res = _record(srv, "U3", "ZTEST E2E R-042 crew replacement", supersedes=old)
    log.info(f"[SRV-API-12] Samual supersedes his own learning -> HTTP {st}: {res.splitlines()[0][:160]}")
    log.warning("[SRV-API-12] leaves 2 learnings to delete by hand: 'ZTEST E2E R-042 crew original' / 'crew replacement'")
    assert st == 200 and not res.lstrip().startswith(("⛔", "❌")), res[:200]
    assert _find_id(srv, "ZTEST E2E R-042 crew original")[0] is None, "his own old learning is still active"
