"""Service Desk - many people filing new tickets at the same instant.

Customers go through the request page's API (/support-api/start then
/support-api/verify, the exact router the page calls) and employees through
the app's API (POST /desk-api/tickets). A barrier releases every submission
at once on its own thread, the way the web server's worker pool runs them.

Every ticket must arrive with its own number (no gaps, no repeats), carry
the right person's title and contact, have its ticket.json on disk, and the
customer must be texted their own number. A customer double-tapping Submit
must get one ticket, not two.
"""
import json
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_files  # noqa: E402
import desk_http  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402


@pytest.fixture
def desk(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    sent, lock = [], threading.Lock()

    def capture(ch, to, subj, text):
        with lock:
            sent.append((ch, to, subj, text))
        return True
    p.send_fn = capture
    yield path, sent
    p.send_fn = None


def _phone(i):
    return f"386-555-{1000 + i:04d}"


def _e164(i):
    return f"+1386555{1000 + i:04d}"


def _at_once(n, fn):
    """Run fn(i) for i in range(n) on n threads released together."""
    gate = threading.Barrier(n)

    def go(i):
        gate.wait()
        return fn(i)
    with ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(go, range(n)))


def _portal(db, path, payload, ip, edition):
    st, _ct, body = p.route("POST", path, query={}, body=json.dumps(payload).encode(),
                            content_type="application/json", ip=ip, db_path=db, edition=edition,
                            base_url="https://desk.example")
    return st, json.loads(body)


def _code_for(sent, i):
    for ch, to, _s, text in sent:
        if to == _e164(i) and "code is" in text:
            return re.search(r"\b(\d{6})\b", text).group(1)
    raise AssertionError(f"no code was texted to customer {i}")


def _customers_start(db, sent, idx, edition):
    starts = _at_once(len(idx), lambda k: _portal(
        db, "/support-api/start", {"name": f"Customer {idx[k]}", "phone": _phone(idx[k])},
        f"10.0.0.{idx[k]}", edition))
    assert all(st == 200 for st, _ in starts), starts
    return {i: s["contact_id"] for i, (_st, s) in zip(idx, starts)}


def _customer_verify(db, sent, i, cid, edition):
    return _portal(db, "/support-api/verify",
                   {"contact_id": cid, "code": _code_for(sent, i), "title": f"Request from customer {i}",
                    "description": f"details {i}"}, f"10.0.0.{i}", edition)


def _all_tickets(db):
    con = desk_db.get_connection(db)
    try:
        return [dict(x) for x in con.execute("SELECT * FROM tickets ORDER BY row_id")]
    finally:
        con.close()


def _assert_clean_set(db, expected_count):
    rows = _all_tickets(db)
    ids = [t["ticket_id"] for t in rows]
    assert len(rows) == expected_count, f"expected {expected_count} tickets, found {len(rows)}"
    assert len(set(ids)) == len(ids), f"duplicate ticket numbers: {ids}"
    assert ids == [f"T-{n:04d}" for n in range(1, expected_count + 1)], f"gaps or odd numbers: {ids}"
    root = desk_db.root_for(db)
    for t in rows:
        doc = desk_files.read_ticket_json(root / t["folder"] / desk_files.TICKET_JSON)
        assert doc["ticket_id"] == t["ticket_id"] and doc["title"] == t["title"]
    assert desk_files.verify(db) == []
    return rows


@pytest.mark.parametrize("edition", [r.SOLO, r.BUSINESS])
def test_many_customers_submit_the_request_page_at_the_same_instant(desk, edition):
    db, sent = desk
    n = 30
    cids = _customers_start(db, sent, list(range(n)), edition)
    assert len(set(cids.values())) == n, "two customers were merged into one contact"
    results = _at_once(n, lambda i: _customer_verify(db, sent, i, cids[i], edition))
    assert all(st == 201 for st, _ in results), [b for st, b in results if st != 201]
    got = {i: b["ticket_id"] for i, (_st, b) in enumerate(results)}
    assert len(set(got.values())) == n, f"two customers were told the same number: {got}"
    rows = _assert_clean_set(db, n)
    by_id = {t["ticket_id"]: t for t in rows}
    for i, tid in got.items():
        t = by_id[tid]
        assert t["title"] == f"Request from customer {i}" and t["contact_id"] == cids[i]
        assert t["source"] == "portal"
        confirm = [x for x in sent if x[1] == _e164(i) and "We got your request" in x[3]]
        assert len(confirm) == 1 and f"[{tid}]" in confirm[0][2], confirm


def test_customers_and_employees_file_at_the_same_instant(desk):
    db, sent = desk
    n_cust, n_staff = 15, 15
    cids = _customers_start(db, sent, list(range(n_cust)), r.BUSINESS)
    team = [{"id": "boss", "role": "owner"}, {"id": "mia", "role": "manager"},
            {"id": "sam", "role": "staff"}, {"id": "cris", "role": "field_crew"},
            {"id": "dee", "role": "field_crew"}]

    def one(i):
        if i < n_cust:
            st, b = _customer_verify(db, sent, i, cids[i], r.BUSINESS)
            return ("cust", i, st, b.get("ticket_id"), b)
        k = i - n_cust
        who = team[k % len(team)]
        st, _ct, body = desk_http.route(
            "POST", "/desk-api/tickets", query={}, body=json.dumps(
                {"title": f"Crew ticket {k}", "kind": r.INTERNAL, "description": "parallel"}).encode(),
            content_type="application/json", actor=who, edition=r.BUSINESS, db_path=db)
        b = json.loads(body)
        return ("staff", k, st, (b.get("ticket") or {}).get("ticket_id"), b)

    out = _at_once(n_cust + n_staff, one)
    bad = [o for o in out if o[2] != 201]
    assert not bad, bad
    ids = [o[3] for o in out]
    assert len(set(ids)) == len(ids), f"duplicate numbers handed out: {sorted(ids)}"
    rows = _assert_clean_set(db, n_cust + n_staff)
    by_id = {t["ticket_id"]: t for t in rows}
    for who, i, _st, tid, _b in out:
        want = f"Request from customer {i}" if who == "cust" else f"Crew ticket {i}"
        assert by_id[tid]["title"] == want


@pytest.mark.parametrize("taps", [2, 4])
def test_double_tapped_submit_files_one_ticket(desk, taps):
    """The same customer's Submit fires twice (double tap, flaky signal retry):
    the code is good for one ticket only."""
    db, sent = desk
    cid = _customers_start(db, sent, [7], r.SOLO)[7]
    code = _code_for(sent, 7)
    results = _at_once(taps, lambda _k: _portal(
        db, "/support-api/verify", {"contact_id": cid, "code": code, "title": "Gutters overflowing"},
        "10.0.0.7", r.SOLO))
    ok = [b for st, b in results if st == 201]
    assert len(ok) == 1, f"{len(ok)} tickets filed from one code: {results}"
    assert all(st == 400 for st, _ in results if st != 201)
    _assert_clean_set(db, 1)


def test_hourly_code_limit_holds_under_a_burst(desk):
    """Eight code requests from one address in the same instant: the
    5-an-hour limit lets exactly five through, not all eight."""
    db, sent = desk
    out = _at_once(8, lambda i: _portal(db, "/support-api/start",
                                        {"name": f"Burst {i}", "phone": _phone(200 + i)},
                                        "10.9.9.9", r.SOLO))
    assert sorted(st for st, _ in out) == [200] * 5 + [400] * 3, out
    assert len([x for x in sent if "code is" in x[3]]) == 5
