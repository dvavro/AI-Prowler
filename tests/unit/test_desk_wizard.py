"""Service Desk 🧙 "How tickets move" wizard (desk/index.html, 2026-10-29).

David 2026-10-29: a wizard button top-right in /desk/ that demonstrates the
ticket flow and the state machine diagram.

The wizard works offline, so it carries its own copy of the rules (the
<script id="wizRules"> block). These tests fail the moment that copy and
desk_rules.py disagree, check every allowed move has an arrow, check the
walkthrough only makes moves the right person may make in each edition, and
check the wizard never talks to the server (demo only).

Run: run_tests.bat tests\\unit\\test_desk_wizard.py
"""
import datetime
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_rules as r  # noqa: E402

HTML = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
ROLE_ORDER = ["owner", "manager", "staff", "field_crew", "customer", "subcontractor"]
LEGAL = {f"{f}>{t}" for f in r.STATES for t in r.TRANSITIONS[f]}


def _rules() -> dict:
    m = re.search(r'<script type="application/json" id="wizRules">(.*?)</script>', HTML, re.S)
    assert m, "the wizard's rules block (#wizRules) is missing from desk/index.html"
    return json.loads(m.group(1))


def _wiz_js() -> str:
    m = re.search(r"/\*WIZ\*/(.*?)/\*WIZ_END\*/", HTML, re.S)
    assert m, "the wizard's script (/*WIZ*/ ... /*WIZ_END*/) is missing"
    return m.group(1)


def _who_can(edition, frm, to):
    """Every role that can make this move in its best case (the assignee, the
    ticket's own customer, a fresh close) — straight from the one gate, can()."""
    now = datetime.datetime.now(datetime.timezone.utc)
    out = []
    for role in ROLE_ORDER:
        if role not in r.ROLES_BY_EDITION[edition]:
            continue
        kind = "subcontractor" if role == "subcontractor" else "external"
        t = {"state": frm, "kind": kind, "assignee": "u1", "contact_id": "C1",
             "closed_at": (now - datetime.timedelta(days=1)).isoformat()}
        if r.can({"id": "u1", "role": role, "contact_id": "C1"}, "change_state", t,
                 edition=edition, to_state=to, reason="x", now=now):
            out.append(role)
    return out


# ── the copy of the rules matches desk_rules.py ─────────────────────────────────
def test_states_match_desk_rules():
    assert _rules()["states"] == list(r.STATES)


def test_moves_match_desk_rules():
    w = _rules()["transitions"]
    assert {s: set(v) for s, v in w.items()} == {s: set(r.TRANSITIONS[s]) for s in r.STATES}


def test_moves_needing_a_reason_match_desk_rules():
    w = {f"{f}>{t}" for f, t in _rules()["needs_reason"]}
    assert w == {k for k in LEGAL if r.needs_reason(*k.split(">"))}


@pytest.mark.parametrize("edition", r.EDITIONS)
def test_who_can_move_it_matches_the_permission_check(edition):
    who = _rules()["who"][edition]
    assert set(who) == LEGAL
    for k in LEGAL:
        assert who[k] == _who_can(edition, *k.split(">")), f"{edition} {k}"


def test_solo_shows_only_solo_people():
    for k, roles in _rules()["who"]["solo"].items():
        assert set(roles) <= r.ROLES_BY_EDITION["solo"], k


# ── the drawing ─────────────────────────────────────────────────────────────────
def test_every_allowed_move_has_exactly_one_arrow():
    edges = set(re.findall(r"'([A-Za-z ]+>[A-Za-z ]+)':\s*'M", _wiz_js()))
    assert edges == LEGAL


def test_every_state_is_drawn():
    nodes = re.search(r"const NODES = \{(.*?)\};", _wiz_js(), re.S).group(1)
    assert set(re.findall(r"'([A-Za-z ]+)':\s*\[", nodes)) == set(r.STATES)


# ── the walkthrough follows the rules ───────────────────────────────────────────
@pytest.mark.parametrize("edition", r.EDITIONS)
def test_walkthrough_makes_only_allowed_moves(edition):
    steps = _rules()["steps"]
    who = _rules()["who"][edition]
    assert steps[0]["state"] == r.OPEN and steps[0]["from"] is None
    for prev, s in zip(steps, steps[1:]):
        if s["from"]:
            assert s["from"] == prev["state"], s["title"]
        else:
            assert s["state"] == prev["state"], s["title"]
    for s in steps:
        role = s["by"][edition]
        assert role in r.ROLES_BY_EDITION[edition], (edition, s["title"], role)
        assert s["text"].get(edition) or s["text"].get("all"), s["title"]
        if s["from"]:
            k = f"{s['from']}>{s['state']}"
            assert k in LEGAL, k
            assert r.check_transition(s["from"], s["state"], s.get("reason", "")), \
                f"{k} needs a reason in the walkthrough"
            assert role in who[k], f"{edition}: {role} can't make {k}"
        if s.get("hint"):
            assert s["hint"] in LEGAL and role in who[s["hint"]], s["hint"]


def test_walkthrough_goes_from_request_to_fixed_to_customer_close():
    steps = _rules()["steps"]
    moves = [(s["from"], s["state"], s["by"]["solo"]) for s in steps if s["from"]]
    assert (r.IN_PROGRESS, r.FIXED, "owner") in moves
    assert (r.FIXED, r.CLOSED, "customer") in moves, "the customer confirms the fix"
    assert any("★" in (s["text"].get("all") or "") for s in steps), "the customer's rating is shown"
    assert any(s["from"] and r.needs_reason(s["from"], s["state"]) and s.get("reason") for s in steps), \
        "one step shows a move that needs a reason"


# ── the button, demo only, offline ──────────────────────────────────────────────
def test_wizard_button_is_in_the_top_bar_on_every_screen_size():
    bar = re.search(r'<div class="topbar">(.*?)</div>\s*<div class="tabs', HTML, re.S).group(1)
    m = re.search(r'<button class="ibtn" id="wizBtn"[^>]*>🧙</button>', bar)
    assert m, "🧙 button missing from the top bar (or hidden with the 'hide' class)"
    css = "".join(re.findall(r"<style[^>]*>(.*?)</style>", HTML, re.S))
    assert "#wizBtn" not in css, "the button looks like the other top-bar buttons on phone and desktop"
    js = HTML.split("/*WIZ*/")[0].split("<script>")[-1]
    assert "wizBtn" not in js, "nothing outside the wizard hides the button (e.g. at sign-in)"


@pytest.mark.parametrize("call", ["api(", "fetch(", "XMLHttpRequest", "sessionStorage", "localStorage",
                                  "sendBeacon", "/desk-api"])
def test_wizard_never_talks_to_the_server(call):
    assert call not in _wiz_js(), f"the wizard is a demo; it must not use {call}"


def test_wizard_ships_inside_the_cached_page():
    """No separate file to fetch: the service worker caches index.html for offline use."""
    sw = (ROOT / "desk" / "sw.js").read_text(encoding="utf-8")
    assert "'/desk/index.html'" in sw
    assert 'id="wiz"' in HTML and 'id="wizRules"' in HTML


# ── 📨 How to file (2026-10-29): who can open which kind, the two links ───────
@pytest.mark.parametrize("edition", r.EDITIONS)
def test_who_can_open_each_kind_matches_the_permission_check(edition):
    want = {k: [ro for ro in ROLE_ORDER if ro in r.ROLES_BY_EDITION[edition]
                and r.can({"id": "u", "role": ro}, "create", edition=edition, kind=k)] for k in r.KINDS}
    assert _rules()["create"][edition] == want


def test_owner_files_every_kind_in_both_editions():
    """Solo: the owner files for customers, for himself and about subs."""
    for ed in r.EDITIONS:
        for k in r.KINDS:
            assert "owner" in _rules()["create"][ed][k], (ed, k)


def test_every_employee_can_open_tickets_in_business():
    for ro in ("manager", "staff", "field_crew"):
        for k in r.KINDS:
            assert ro in _rules()["create"]["business"][k], (ro, k)


def test_how_to_file_tab_shows_both_links_and_never_fetches():
    js = _wiz_js()
    assert "tb('tab', 'file'" in js and "st.tab === 'file' ? filing()" in js
    assert "urlRow('wzUrlSupport', '/support/new')" in js and "urlRow('wzUrlDesk', '/desk/')" in js
    assert "location.origin" in js            # the link comes from the page's own address


def test_walkthrough_step_one_says_where_requests_come_from():
    t = _rules()["steps"][0]["text"]
    for ed in r.EDITIONS:
        assert "/support/new" in t[ed] and "+" in t[ed], ed
