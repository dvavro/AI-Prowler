"""
Service Desk load test (release gate).

5,000 seeded tickets, 10 simulated people working at once through the same
code path the app uses (desk_http.route): list views, opening tickets, live
update polling, state changes and notes. Gates:
  * list views under 500 ms at the 95th percentile
  * zero "database is locked" (or any other) errors
Runs against a throwaway database in a temp folder.

    py tests\\load\\desk_load_test.py [seconds=60] [users=10] [tickets=5000]
"""
import json
import random
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_http  # noqa: E402

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 60
USERS = int(sys.argv[2]) if len(sys.argv) > 2 else 10
TICKETS = int(sys.argv[3]) if len(sys.argv) > 3 else 5000

tmp = Path(tempfile.mkdtemp(prefix="desk_load_"))
db = str(tmp / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
desk_db.init_db(db)
team = [{"id": f"u{i}", "role": "staff" if i else "manager"} for i in range(USERS)]

print(f"seeding {TICKETS} tickets ...", flush=True)
t0 = time.time()
conn = desk_db.get_connection(db)
now = desk_db.utcnow_iso()
conn.execute("BEGIN")
for i in range(1, TICKETS + 1):
    tid = f"T-{i:04d}"
    conn.execute("INSERT INTO tickets (row_id, ticket_id, title, description, kind, priority, state, assignee, "
                 "filed_by, created_at, version, last_edited_at, last_edited_by, folder) VALUES "
                 "(?, ?, ?, '', 'internal', ?, ?, ?, 'boss', ?, 1, ?, 'boss', ?)",
                 (i, tid, f"Seed ticket {i} pump hose ladder", random.choice(["P1", "P2", "P3", "P4"]),
                  random.choice(["Assigned", "In Progress", "On Hold", "Closed"]), f"u{i % USERS}",
                  now, now, f"tickets/{now[:4]}/{tid}"))
conn.execute("COMMIT")
conn.close()
print(f"seeded in {time.time() - t0:.1f}s", flush=True)

lat = {"list": [], "open": [], "updates": [], "write": []}
errors = []
lock = threading.Lock()
stop = time.time() + SECONDS


def call(actor, method, path, body=None, query=None):
    st, ct, out = desk_http.route(method, path, query=query or {},
                                  body=json.dumps(body).encode() if body else b"",
                                  content_type="application/json", actor=actor, edition="business",
                                  db_path=db)
    return st, json.loads(out) if ct == b"application/json" else out


def worker(actor):
    cursor = ""
    rnd = random.Random(actor["id"])
    while time.time() < stop:
        try:
            a = time.perf_counter()
            st, d = call(actor, "GET", "/desk-api/tickets", query={"mine": "1"})
            with lock:
                lat["list"].append(time.perf_counter() - a)
            if st != 200:
                raise RuntimeError(f"list {st} {d}")
            mine = d["tickets"]
            a = time.perf_counter()
            st, u = call(actor, "GET", "/desk-api/updates", query={"since": cursor})
            with lock:
                lat["updates"].append(time.perf_counter() - a)
            cursor = u.get("cursor", cursor)
            if mine:
                t = rnd.choice(mine)
                a = time.perf_counter()
                call(actor, "GET", f"/desk-api/tickets/{t['ticket_id']}")
                with lock:
                    lat["open"].append(time.perf_counter() - a)
                a = time.perf_counter()
                st, d = 200, {}
                if rnd.random() < 0.5:
                    st, d = call(actor, "POST", f"/desk-api/tickets/{t['ticket_id']}/messages",
                                 {"body": "load-test note", "visibility": "internal"})
                else:
                    nxt = {"Assigned": "In Progress", "In Progress": "On Hold",
                           "On Hold": "In Progress"}.get(t["state"])
                    if nxt:
                        st, d = call(actor, "POST", f"/desk-api/tickets/{t['ticket_id']}/state",
                                     {"to_state": nxt, "reason": "load", "expected_version": t["version"]})
                with lock:
                    lat["write"].append(time.perf_counter() - a)
                if st not in (200, 201, 409):          # 409 = someone else changed it: expected
                    raise RuntimeError(f"write {st} {d}")
        except Exception as e:  # noqa: BLE001
            with lock:
                errors.append(f"{actor['id']}: {type(e).__name__}: {e}")


threads = [threading.Thread(target=worker, args=(u,)) for u in team]
print(f"{USERS} users for {SECONDS}s ...", flush=True)
for t in threads:
    t.start()
for t in threads:
    t.join()


def p95(v):
    return statistics.quantiles(v, n=20)[18] * 1000 if len(v) >= 20 else (max(v) * 1000 if v else 0)


for k, v in lat.items():
    med = statistics.median(v) * 1000 if v else 0
    print(f"{k:8} n={len(v):6}  median={med:7.1f} ms  p95={p95(v):7.1f} ms")
locked = [e for e in errors if "locked" in e.lower()]
print(f"errors: {len(errors)} (database locked: {len(locked)})")
for e in errors[:10]:
    print("  ", e.encode("ascii", "replace").decode())
ok = p95(lat["list"]) < 500 and not errors
print("LOAD GATE:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
