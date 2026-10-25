"""Personal mode (owner) — the mileage tracker end to end, through the Jobs app
GUI typed like a person (--human), checked in the database (MCP tools over
/pwa-api) and back in the GUI. Realistic New Smyrna Beach driving: supply
runs, bank deposits, a permit pickup, an Orlando-area parts run with tolls, a
day of clocked jobs, a customer who cancels at the door, and a crew member's
own-car reimbursement. (2026-10-25, Vicki: "a test which actually checks E2E
GUI field edit entries in human mode and Database entries using the GUI and
MCP tools which covers all entries fields for the miles".)

  MI-01  Vehicles form, every field (VIN with a typo first — check digit —
         then the right one; business- and crew-owned) + the Odometer form
  MI-02  Add trip form, every field: date, category, from, to, purpose,
         miles, one-way / round trip, odometer start/end, vehicle, parking,
         tolls, notes — and a vague purpose ("business") refused
  MI-03  Edit sheet from Database → 🚗 Miles, every field A → B, reason
         required, audit history, reopened sheet + table show B; then
         business → personal
  MI-04  Add a stop (split), Remove (void) a duplicate, Show removed, search,
         Change history on a removed trip
  MI-05  Quick add by typed text (confirm → Save), and a ❓ when miles are missing
  MI-06  A clocked day: Recalculate a day builds the job legs; a hand edit
         survives a rebuild; Fix a missing clock-out; Cancelled on arrival
  MI-07  Crew own-car reimbursement: Claude submits for the crew member,
         owner Returns (note) in the app, crew fixes + resubmits, owner
         Approves, Marks paid (date, method, reference), paid trips locked,
         statement PDF
  MI-08  🤖 Review with AI: Fix a duplicate, Skip a long-leg finding
  MI-09  Export CSV / Excel / PDF from the Mileage tab and Reports
  MI-10  Reports → Mileage & deduction shows exactly what get_mileage_report says
  MI-11  Database → Settings: pay period, every reminder, tracking off = quiet
         (originals put back)
  MI-12  Claude logs and edits a trip with every field (incl. notes and
         times the app's sheet doesn't show) → the app shows it

Test data: trips carry "ZTEST E2E" in their notes (or are registered by the
guard when the app/Claude creates them), vehicles are nicknamed "ZTEST E2E …",
the crew member is "ZTEST E2E Driver …". The app never deletes mileage
records (IRS log: void / retire / locked once paid), so cleanup deletes the
test rows straight from the job database — trips (paid ones too), their edit
history, the reimbursement and its events, vehicles and odometer readings —
after checking the file is the database the Jobs app serves and saving a copy
in the run folder (mileage_purge.py). It runs at the end of this module and at
the start and end of every E2E run; a leftover fails the module's teardown and
shows in SUMMARY.txt.

Run:  run_tests_gui_jobs_e2e.bat --human -k test_mileage_e2e
Needs mileage tracking turned ON (Database → Settings → Mileage Tracking Enabled) — the
module is skipped if it's off. MI-11 turns it off and back on from the Settings
tab (the `toggles` fixture puts every mileage switch back even if it fails).
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import re
import time
import zipfile
import zlib

import pytest
from playwright.sync_api import expect

from ai_client import AiClient
from api import local_api_origin
from app_mileage import Mileage
from mileage_purge import leftovers, purge
from safety import SANDBOX_DATE, SANDBOX_DATES, ZTEST_PREFIX, sandbox_day

STAMP = time.strftime("%H%M%S")
DRIVER = f"{ZTEST_PREFIX} Driver Sam {STAMP}"      # crew member driving his own car
W0, W1 = min(SANDBOX_DATES), SANDBOX_DATE           # the window the tests look at (past 3 days .. today)
YESTERDAY = sandbox_day(-1)

OFFICE = "210 Sams Ave, New Smyrna Beach"
HOME_DEPOT = "Home Depot, 1998 SR-44, New Smyrna Beach"
LOWES = "Lowe's, 1971 SR-44, New Smyrna Beach"
CHASE = "Chase Bank, 1701 SR-44, New Smyrna Beach"
ACE = "Ace Hardware, 1300 S Dixie Fwy, New Smyrna Beach"
SANFORD = "Pressure Washer Parts Depot, 3801 S Orlando Dr, Sanford"
PERMITS = "Volusia County Permits, 123 W Indiana Ave, DeLand"
SUNBELT = "Sunbelt Rentals, 2400 S Ridgewood Ave, Edgewater"
SHERWIN = "Sherwin-Williams, 711 E 3rd Ave, New Smyrna Beach"


# ── VINs (unique per run, valid North-American check digit) ─────────────────
_TR = {**{str(i): i for i in range(10)},
       **dict(zip("ABCDEFGH", range(1, 9))), **dict(zip("JKLMN", range(1, 6))), "P": 7, "R": 9,
       **dict(zip("STUVWXYZ", range(2, 10)))}
_WT = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
_SERIAL = int(time.time()) % 900_000 + 100_000


def make_vin(prefix8: str, year_plant: str, n: int) -> str:
    v = prefix8 + "0" + year_plant + f"{(_SERIAL + n) % 1_000_000:06d}"
    cd = sum(_TR[c] * w for c, w in zip(v, _WT)) % 11
    return v[:8] + ("X" if cd == 10 else str(cd)) + v[9:]


def bad_check_digit(vin: str) -> str:
    wrong = "1" if vin[8] != "1" else "2"
    return vin[:8] + wrong + vin[9:]


# ── reading the database (MCP tools through /pwa-api, all reads) ─────────────
def mlog(api, start: str = W0, end: str = W1) -> dict:
    return json.loads(api.call("get_mileage_log", {"start_date": start, "end_date": end}, expect_ok=False))


def trip(api, tid: str) -> dict:
    t = next((x for x in mlog(api)["trips"] if x["trip_id"] == tid), None)
    assert t is not None, f"{tid} is not in the mileage log for {W0} .. {W1}"
    return t


def vehicle(api, vid: str) -> dict:
    v = next((x for x in mlog(api)["vehicles"] if x["vehicle_id"] == vid), None)
    assert v is not None, f"vehicle {vid} is not in the mileage log's vehicle list"
    return v


def history(api, tid: str) -> str:
    return api.call("update_mileage_trip", {"trip_id": tid, "reason": "view", "action": "history"}, expect_ok=False)


def reimb(api, rid: str) -> dict:
    rows = json.loads(api.call("mileage_reimbursement", {"action": "list", "as_json": True}, expect_ok=False))
    r = next((x for x in rows if x["reimbursement_id"] == rid), None)
    assert r is not None, f"{rid} not found"
    return r


def trip_ids(text: str) -> list[str]:
    return re.findall(r"TRIP-\d+", text or "")


def num(v):
    try:
        return round(float(v), 2)
    except (TypeError, ValueError):
        return None


def check_trip(t: dict, want: dict) -> list[str]:
    """Field-by-field differences between a stored trip and what was entered."""
    bad = []
    for k, w in want.items():
        g = t.get(k)
        if k in ("miles", "parking_usd", "tolls_usd"):
            ok = num(g) == num(w)
        else:
            ok = str(g or "").strip() == str(w or "").strip()
        if not ok:
            bad.append(f"{t.get('trip_id')} {k}: entered {w!r}, stored {g!r}")
    return bad


def api_trip(api, **f) -> list[str]:
    """Setup: log a trip the way the app's form does (add_mileage_trip)."""
    f.setdefault("date", SANDBOX_DATE)
    f.setdefault("notes", f"{ZTEST_PREFIX} setup")
    out = api.call("add_mileage_trip", f)
    ids = trip_ids(out)
    assert ids, f"setup trip not saved: {out}"
    return ids


# ── module setup / cleanup ───────────────────────────────────────────────────
def _ours(t: dict, guard) -> bool:
    return (t["trip_id"] in guard.created or str(t.get("crew") or "").startswith(ZTEST_PREFIX)
            or ZTEST_PREFIX in str(t.get("notes") or "") or str(t.get("job_id") or "") in guard.created
            or str(t.get("customer_name") or "").startswith(ZTEST_PREFIX))


def mileage_sweep(api, guard, why: str, log) -> dict:
    """Remove (void) every active test trip in the sandbox window and retire
    every active ZTEST vehicle. Paid trips are locked by design — counted, kept."""
    n = {"voided": 0, "locked_kept": 0, "vehicles_retired": 0}
    d = mlog(api, min(SANDBOX_DATES), max(SANDBOX_DATES))
    for t in d["trips"]:
        if t["status"] != "active" or not _ours(t, guard):
            continue
        guard.adopt(t["trip_id"], date=t["trip_date"], reason=f"mileage sweep ({why})")
        r = api.call("update_mileage_trip", {"trip_id": t["trip_id"], "action": "void",
                                             "reason": f"E2E cleanup ({why})"}, expect_ok=False)
        n["voided" if r.lstrip().startswith("✅") else "locked_kept"] += 1
    for v in d["vehicles"]:
        if v.get("active") and str(v.get("nickname") or "").startswith(ZTEST_PREFIX):
            guard.adopt(v["vehicle_id"], name=v["nickname"], reason=f"mileage sweep ({why})")
            api.call("manage_vehicles", {"action": "retire", "vehicle_id": v["vehicle_id"]}, expect_ok=False)
            n["vehicles_retired"] += 1
    log(f"mileage sweep ({why}): {n}")
    return n


@pytest.fixture(scope="module")
def mi_env(api, guard, data):
    log = api.log
    s = json.loads(api.call("mileage_settings", {"action": "get"}, expect_ok=False))
    if not s.get("enabled"):
        pytest.skip("Mileage tracking is off on this install (Database → Settings → Mileage Tracking Enabled). "
                    "The E2E suite never switches it on — turn it on and re-run.")
    saved = {"period": s["reimbursement"]["kind"], "reminders": dict(s.get("reminders") or {}),
             "reminder_types": dict(s.get("reminder_types") or {})}
    guard.mileage_settings_saved = saved
    # (leftovers of an earlier run were already deleted by the session's
    #  start-of-run mileage purge in conftest.py)
    env = {"saved": saved, "rates": s.get("rates") or []}
    for key, prefix, yp, n, extra in (
            ("van", "1GCWGAFP", "CB", 1, {"year": "2012", "make": "Chevrolet", "model": "Express 2500",
                                          "nickname": f"{ZTEST_PREFIX} Work Van", "plate": "NSB 2210",
                                          "odometer": "131200"}),
            ("truck", "1FTFW1ET", "DF", 2, {"year": "2013", "make": "Ford", "model": "F-150 XLT",
                                            "nickname": f"{ZTEST_PREFIX} White F-150", "plate": "NSB 4471",
                                            "odometer": "48210"})):
        vin = make_vin(prefix, yp, n)
        out = api.call("manage_vehicles", dict(extra, action="add", vin=vin, ownership="business",
                                               placed_in_service="2024-03-15"))
        env[key] = re.search(r"VEH-\d+", out).group(0)
        env[key + "_vin"] = vin
    yield env
    try:
        cur = json.loads(api.call("mileage_settings", {"action": "get"}, expect_ok=False))
        if cur["reimbursement"]["kind"] != saved["period"]:
            api.call("mileage_settings", {"action": "set_period", "pay_period": saved["period"]})
        for k, on in saved["reminders"].items():
            if bool((cur.get("reminders") or {}).get(k)) != bool(on):
                api.call("mileage_settings", {"action": "set_reminder", "reminder": k, "enabled": bool(on)})
    finally:
        guard.mileage_settings_saved = None
        if os.environ.get("E2E_KEEP_DATA", "") == "1":
            log("mileage data kept (--keep-data)")
        else:
            # Delete everything this module made (trips incl. the paid ones,
            # their history, the reimbursement, the vehicles). If the file
            # can't be reached (e.g. another database), fall back to the
            # app's own void / retire so nothing counts in totals.
            run_dir = os.environ.get("E2E_RUN_DIR") or os.path.join(os.path.dirname(__file__), "artifacts")
            os.makedirs(run_dir, exist_ok=True)
            n = purge(api, set(guard.created), run_dir, log, "end of test_mileage_e2e")
            if "skipped" in n:
                mileage_sweep(api, guard, "end (purge skipped)", log)
            left = leftovers()
            assert not left, f"mileage test data left in the database after cleanup: {left}"


@pytest.fixture
def mi(app, page, mi_env):
    page.set_default_timeout(30_000)
    return Mileage(page, app, app.log)


@pytest.fixture
def ai(guard, token):
    return AiClient(local_api_origin(), token, guard, "owner")


def open_window(mi: Mileage):
    """Mileage tab showing the whole test window (3 days ago .. today)."""
    mi.open("week")
    p = mi.page
    p.get_by_test_id("mi-range").select_option("custom")
    for el, v in (("miStart", W0), ("miEnd", W1)):
        p.locator(f"#{el}").fill(v)
        p.locator(f"#{el}").dispatch_event("change")
    mi.page.wait_for_timeout(300)
    mi.reload()
    return mi


def rate_for(env, d: str) -> float:
    rs = sorted(env["rates"], key=lambda r: r["from"])
    return float(next((r["cents"] for r in reversed(rs) if r["from"] <= d), 0))


# ── MI-01 vehicles ───────────────────────────────────────────────────────────
def test_MI_01_vehicle_form_every_field_and_odometer(mi, page, api, mi_env):
    p = page
    open_window(mi)
    vin = make_vin("1FTFW1ET", "EF", 11)                 # 2014 F-150
    business = {"miV_vin": bad_check_digit(vin), "miV_year": "2014", "miV_make": "Ford",
                "miV_model": "F-150 Lariat", "miV_plate": "NSB 9183",
                "miV_nick": f"{ZTEST_PREFIX} Blue F-150", "miV_own": "business", "miV_owner": "",
                "miV_driver": "Dave", "miV_pis": "2025-02-03", "miV_odo": "77410"}
    VFIELDS = [("miV_vin", "text"), ("miV_year", "text"), ("miV_make", "text"), ("miV_model", "text"),
               ("miV_plate", "text"), ("miV_nick", "text"), ("miV_own", "select"), ("miV_owner", "text"),
               ("miV_driver", "text"), ("miV_pis", "date"), ("miV_odo", "text")]

    def add_form():
        p.get_by_test_id("mi-vehicles").get_by_role("button", name=re.compile("Add")).click()
        mi.expect_sheet("Add a vehicle")

    # 1. a typo in the VIN: the check digit catches it, nothing is saved
    add_form()
    mi.fill(VFIELDS, business)
    out = mi.capture("manage_vehicles", lambda: p.get_by_test_id("mi-save-vehicle").click())
    assert out.startswith("❌") and "check digit" in out, out
    expect(p.locator("#miV_result")).to_contain_text("check digit")
    expect(p.locator("#miV_result").get_by_role("button")).to_be_visible()      # "It's correct (non-US VIN)"
    assert not [v for v in mlog(api)["vehicles"] if v["vin"] == bad_check_digit(vin)], "a bad VIN was saved"

    # 2. retype the VIN correctly and save
    mi.type("miV_vin", vin)
    out = mi.capture("manage_vehicles", lambda: p.get_by_test_id("mi-save-vehicle").click())
    assert out.startswith("✅ Added VEH-"), out
    vid = re.search(r"VEH-\d+", out).group(0)
    expect(mi.sheet).to_be_hidden()
    v = vehicle(api, vid)
    want = {"vin": vin, "year": 2014, "make": "Ford", "model": "F-150 Lariat", "plate": "NSB 9183",
            "nickname": business["miV_nick"], "ownership": "business", "default_user_name": "Dave",
            "placed_in_service": "2025-02-03", "last_odometer": 77410, "last_odometer_date": "2025-02-03"}
    bad = [f"{k}: entered {w!r}, stored {v.get(k)!r}" for k, w in want.items() if str(v.get(k)) != str(w)]
    assert not bad, "vehicle stored wrong:\n  " + "\n  ".join(bad)
    row = p.get_by_test_id("mi-vehicles").locator(".mi-gap", has_text=vid)
    expect(row).to_contain_text("Blue F-150")
    expect(row).to_contain_text("Odometer 77,410")

    # 3. the crew member's own car (reimbursable)
    cvin = make_vin("2T1BURHE", "JC", 12)                # 2018 Corolla
    add_form()
    mi.fill(VFIELDS, {"miV_vin": cvin, "miV_year": "2018", "miV_make": "Toyota", "miV_model": "Corolla LE",
                      "miV_plate": "QRT 551", "miV_nick": f"{ZTEST_PREFIX} Sam's Corolla", "miV_own": "crew",
                      "miV_owner": DRIVER, "miV_driver": DRIVER, "miV_pis": "2023-06-01", "miV_odo": "61500"})
    out = mi.capture("manage_vehicles", lambda: p.get_by_test_id("mi-save-vehicle").click())
    assert out.startswith("✅ Added VEH-") and "crew-owned" in out, out
    cv = vehicle(api, re.search(r"VEH-\d+", out).group(0))
    assert (cv["ownership"], cv["owner_name"], cv["default_user_name"], cv["last_odometer"]) == \
        ("crew", DRIVER, DRIVER, 61500), cv

    # 4. Odometer form on the business truck: a regular reading today
    p.get_by_test_id("mi-vehicles").locator(".mi-gap", has_text=vid).get_by_role("button", name="Odometer").click()
    mi.expect_sheet("Odometer")
    mi.type("miO_val", "77462").set("miO_date", SANDBOX_DATE).choose("miO_kind", "spot")
    out = mi.capture("manage_vehicles", lambda: mi.button("Save reading").click())
    assert out.startswith("✅ Odometer 77,462 recorded"), out
    v = vehicle(api, vid)
    assert (v["last_odometer"], v["last_odometer_date"]) == (77462, SANDBOX_DATE), v
    expect(p.get_by_test_id("mi-vehicles").locator(".mi-gap", has_text=vid)).to_contain_text("Odometer 77,462")


# ── MI-02 add trip form ──────────────────────────────────────────────────────
def test_MI_02_add_trip_form_every_field(mi, page, api, mi_env):
    p, van = page, mi_env["van"]
    open_window(mi)
    trips = {
        # one way, typed miles, no parking/tolls
        "home_depot": {"miF_date": SANDBOX_DATE, "miF_cat": "Supplies", "miF_from": OFFICE, "miF_to": HOME_DEPOT,
                       "miF_purpose": "Supplies – extension ladder and window squeegees", "miF_miles": "3.8",
                       "miF_rt": "0", "miF_vehicle": van, "miF_notes": f"{ZTEST_PREFIX} receipt #4471"},
        # round trip -> two legs
        "bank": {"miF_date": SANDBOX_DATE, "miF_cat": "Bank", "miF_from": OFFICE, "miF_to": CHASE,
                 "miF_purpose": "Bank – deposit customer checks", "miF_miles": "2.6", "miF_rt": "1",
                 "miF_vehicle": van, "miF_notes": f"{ZTEST_PREFIX} deposit slip in the folder"},
        # miles from the odometer, SR-417 tolls
        "sanford": {"miF_date": SANDBOX_DATE, "miF_cat": "Equipment", "miF_from": OFFICE, "miF_to": SANFORD,
                    "miF_purpose": "Equipment – pick up replacement pressure washer pump", "miF_miles": "",
                    "miF_rt": "0", "miF_os": "131250", "miF_oe": "131302", "miF_vehicle": van, "miF_toll": "3.25",
                    "miF_notes": f"{ZTEST_PREFIX} SunPass SR-417"},
        # yesterday, metered parking at the county office
        "permit": {"miF_date": YESTERDAY, "miF_cat": "Office errand", "miF_from": OFFICE, "miF_to": PERMITS,
                   "miF_purpose": "Permit pickup – commercial pressure-washing permit", "miF_miles": "27.4",
                   "miF_rt": "0", "miF_vehicle": van, "miF_park": "4.00", "miF_notes": f"{ZTEST_PREFIX} meter receipt"},
    }

    # A purpose the IRS wouldn't accept is refused, nothing saved, the form stays open
    mi.open_add_form()
    mi.fill(Mileage.ADD_FIELDS, dict(trips["home_depot"], miF_purpose="business"))
    out = mi.save_trip()
    assert out.startswith("❌") and "specific business purpose" in out, out
    expect(p.locator("#miF_result")).to_contain_text("specific business purpose")
    expect(mi.sheet).to_be_visible()
    assert not [t for t in mlog(api)["trips"] if t.get("notes") == trips["home_depot"]["miF_notes"]]

    saved = {}
    for i, (name, vals) in enumerate(trips.items()):
        if i == 0:
            mi.type("miF_purpose", vals["miF_purpose"])          # fix the purpose in the open form
        else:
            mi.open_add_form()
            mi.fill(Mileage.ADD_FIELDS, vals)
        out = mi.save_trip()
        assert out.startswith("✅ Saved TRIP-"), f"{name}: {out}"
        expect(mi.sheet).to_be_hidden()
        saved[name] = trip_ids(out)
    mi.loaded()

    def want(vals, **over):
        w = {"trip_date": vals["miF_date"], "category": vals["miF_cat"], "from_label": vals["miF_from"],
             "to_label": vals["miF_to"], "purpose": vals["miF_purpose"], "vehicle_id": vals["miF_vehicle"],
             "notes": vals["miF_notes"], "classification": "business", "status": "active", "origin": "manual",
             "parking_usd": vals.get("miF_park") or None, "tolls_usd": vals.get("miF_toll") or None}
        w.update(over)
        return w

    bad = []
    hd = saved["home_depot"]
    assert len(hd) == 1
    bad += check_trip(trip(api, hd[0]), want(trips["home_depot"], miles="3.8", distance_source="manual"))
    b = saved["bank"]
    assert len(b) == 2, f"a round trip should be two legs: {b}"
    bad += check_trip(trip(api, b[0]), want(trips["bank"], miles="2.6"))
    bad += check_trip(trip(api, b[1]), want(trips["bank"], miles="2.6", from_label=CHASE, to_label=OFFICE))
    sf = saved["sanford"]
    bad += check_trip(trip(api, sf[0]), want(trips["sanford"], miles="52", distance_source="odometer"))
    bad += check_trip(trip(api, saved["permit"][0]), want(trips["permit"], miles="27.4"))
    assert not bad, "stored trips differ from what was typed:\n  " + "\n  ".join(bad)
    assert trip(api, hd[0])["vehicle_label"].endswith(mi_env["van_vin"][-6:])

    # The Mileage tab shows every trip; Database → Miles has a row per trip
    for name, ids in saved.items():
        for tid in ids:
            card = mi.trip_card(tid)
            expect(card).to_be_visible()
            t = trip(api, tid)
            expect(card).to_contain_text(f"{float(t['miles']):.1f} mi")
            expect(card).to_contain_text(t["purpose"])
    mi.open_miles_tab()
    for name, ids in saved.items():
        for tid in ids:
            t, c = trip(api, tid), mi.miles_cells(tid)
            assert c["Date"].startswith(t["trip_date"]) and c["Trip"] == tid, c
            assert (c["From"], c["To"], c["Purpose"], c["Type"], c["Entry"]) == \
                (t["from_label"], t["to_label"], t["purpose"], "business", "added"), c
            assert c["Miles"] == f"{float(t['miles']):.1f}" and c["Driver"] == "Owner", c
            assert mi_env["van_vin"][-6:] in c["Vehicle"], c


# ── MI-03 edit every field from Database → Miles ─────────────────────────────
def test_MI_03_edit_sheet_every_field_from_database_miles(mi, page, api, mi_env):
    p, van, truck = page, mi_env["van"], mi_env["truck"]
    tid = api_trip(api, to_place=HOME_DEPOT, from_place=OFFICE, purpose="Supplies – ladder and squeegees",
                   miles="3.8", category="Supplies", vehicle_id=van, notes=f"{ZTEST_PREFIX} MI03")[0]
    mi.open_miles_tab()
    mi.open_miles_row(tid)
    shown = mi.read(Mileage.EDIT_FIELDS)
    assert (shown["miE_date"], num(shown["miE_miles"]), shown["miE_from"], shown["miE_to"], shown["miE_purpose"],
            shown["miE_cls"], shown["miE_cat"], shown["miE_vehicle"], shown["miE_park"], shown["miE_toll"]) == \
        (SANDBOX_DATE, 3.8, OFFICE, HOME_DEPOT, "Supplies – ladder and squeegees", "business", "Supplies",
         van, "", ""), f"the edit sheet doesn't show the stored trip: {shown}"

    # a change without a reason isn't sent
    mi.type("miE_miles", "5.1")
    sent = []
    p.on("request", lambda r: sent.append(r) if "update_mileage_trip" in (r.post_data or "") else None)
    p.get_by_test_id("mi-save-edit").click()
    expect(p.locator("#miE_result")).to_contain_text("reason")
    p.wait_for_timeout(500)
    assert not sent, "Save sent a change with no reason"

    B = {"miE_date": YESTERDAY, "miE_miles": "5.1", "miE_from": "105 S Riverside Dr, New Smyrna Beach",
         "miE_to": LOWES, "miE_purpose": "Equipment – replacement 24 ft extension ladder", "miE_cls": "business",
         "miE_cat": "Equipment", "miE_vehicle": truck, "miE_park": "1.25", "miE_toll": "0.50",
         "miE_reason": "Receipt shows Lowe's, not Home Depot; left from the Brannon Center job in the truck"}
    mi.fill(Mileage.EDIT_FIELDS, B)
    out = mi.save_edit()
    assert out.startswith(f"✅ {tid} updated"), out
    expect(mi.sheet).to_be_hidden()
    t = trip(api, tid)
    bad = check_trip(t, {"trip_date": YESTERDAY, "miles": "5.1", "from_label": B["miE_from"], "to_label": LOWES,
                         "purpose": B["miE_purpose"], "classification": "business", "category": "Equipment",
                         "vehicle_id": truck, "parking_usd": "1.25", "tolls_usd": "0.5"})
    assert not bad, "stored after edit:\n  " + "\n  ".join(bad)
    h = history(api, tid)
    for field in ("trip_date", "miles", "from_label", "to_label", "purpose", "category", "vehicle_id",
                  "parking_usd", "tolls_usd"):
        assert f": {field} " in h, f"history has no {field} change:\n{h}"
    assert h.count(B["miE_reason"]) >= 9, f"every change should carry the reason:\n{h}"

    # reopened from the table, the sheet shows B; the row shows B
    mi.open_miles_tab()
    c = mi.miles_cells(tid)
    assert c["Date"].startswith(YESTERDAY) and c["Miles"] == "5.1" and c["To"] == LOWES, c
    assert mi_env["truck_vin"][-6:] in c["Vehicle"] and c["Purpose"] == B["miE_purpose"], c
    mi.open_miles_row(tid)
    shown = mi.read(Mileage.EDIT_FIELDS)
    assert (shown["miE_date"], num(shown["miE_miles"]), shown["miE_from"], shown["miE_to"], shown["miE_cat"],
            shown["miE_vehicle"], num(shown["miE_park"]), num(shown["miE_toll"])) == \
        (YESTERDAY, 5.1, B["miE_from"], LOWES, "Equipment", truck, 1.25, 0.5), shown

    # business -> personal (not deductible)
    mi.choose("miE_cls", "personal").type("miE_reason", "Personal shopping on the same stop - not deductible")
    out = mi.save_edit()
    assert out.startswith(f"✅ {tid} updated (classification)"), out
    assert trip(api, tid)["classification"] == "personal"
    mi.open_miles_tab()
    assert mi.miles_cells(tid)["Type"] == "personal"


# ── MI-04 add a stop, remove a duplicate, show removed, search ───────────────
def test_MI_04_split_void_show_removed_search_history(mi, page, api, mi_env):
    p, van = page, mi_env["van"]
    out_leg, back_leg = api_trip(api, to_place=CHASE, from_place=OFFICE, purpose="Bank – deposit customer checks",
                                 miles="2.6", round_trip=True, category="Bank", vehicle_id=van,
                                 notes=f"{ZTEST_PREFIX} MI04 bank")
    permit = api_trip(api, to_place=PERMITS, from_place=OFFICE, purpose="Permit pickup – sign permit",
                      miles="27.4", category="Office errand", vehicle_id=van, parking_usd="4",
                      notes=f"{ZTEST_PREFIX} MI04 permit")[0]
    dup = api_trip(api, to_place=PERMITS, from_place=OFFICE, purpose="Permit pickup – sign permit",
                   miles="27.4", category="Office errand", vehicle_id=van, parking_usd="4",
                   notes=f"{ZTEST_PREFIX} MI04 permit (logged twice from the phone)")[0]

    # 1. a stop at Ace Hardware on the way to the bank
    mi.open_miles_tab()
    mi.open_miles_row(out_leg)
    mi.button("Add a stop").click()
    mi.expect_sheet("Add a stop to")
    mi.type("miS_via", ACE).type("miS_purpose", "Supplies – caulk and drop cloths")
    mi.type("miS_m1", "1.4").type("miS_m2", "1.9").type("miS_reason", "Stopped at Ace on the way to the bank")
    out = mi.capture("update_mileage_trip", lambda: mi.button("Add stop").click())
    assert out.startswith(f"✅ Split {out_leg}"), out
    new = [x for x in trip_ids(out) if x != out_leg]
    assert len(new) == 2, out
    old = trip(api, out_leg)
    assert old["status"] == "void" and ACE in (old["void_reason"] or ""), old
    a, b = trip(api, new[0]), trip(api, new[1])
    bad = check_trip(a, {"from_label": OFFICE, "to_label": ACE, "miles": "1.4",
                         "purpose": "Supplies – caulk and drop cloths", "vehicle_id": van, "trip_date": SANDBOX_DATE})
    bad += check_trip(b, {"from_label": ACE, "to_label": CHASE, "miles": "1.9",
                          "purpose": "Bank – deposit customer checks", "vehicle_id": van})
    assert not bad, "\n  ".join(bad)

    # 2. remove the duplicate permit trip (reason typed first, kept as the void reason)
    mi.open_miles_tab()
    mi.open_miles_row(dup)
    reason = f"Duplicate — logged twice from my phone (same as {permit})"
    mi.type("miE_reason", reason)
    out = mi.capture("update_mileage_trip", lambda: mi.button("Remove trip").click())
    assert out.startswith(f"✅ {dup} removed"), out
    d = trip(api, dup)
    assert (d["status"], d["void_reason"]) == ("void", reason), d
    assert trip(api, permit)["status"] == "active"

    # 3. removed rows are hidden until "Show removed"; search filters the table
    mi.open_miles_tab()
    expect(mi.miles_row(dup)).to_be_hidden()
    p.get_by_test_id("miles-show-void").check()
    expect(mi.miles_row(dup)).to_be_visible()
    expect(mi.miles_row(dup)).to_have_attribute("data-void", "1")
    assert "removed: " + reason in mi.miles_cells(dup)["Notes"]
    expect(mi.miles_row(out_leg)).to_be_visible()                       # the split leg, removed
    mi.type("milesSearch", "permit")
    expect(mi.miles_row(permit)).to_be_visible()
    expect(mi.miles_row(new[1])).to_be_hidden()
    for txt in p.locator("#sheetContent [data-testid='miles-row']:visible").evaluate_all(
            "rs => rs.map(r => r.getAttribute('data-text'))"):
        assert "permit" in txt, txt
    mi.type("milesSearch", "")
    p.get_by_test_id("miles-show-void").uncheck()

    # 4. a removed trip opens read-only; its history shows the removal and why
    p.get_by_test_id("miles-show-void").check()
    mi.open_miles_row(dup)
    expect(p.get_by_test_id("mi-save-edit")).to_have_count(0)
    mi.capture("update_mileage_trip", lambda: mi.button("Change history").click())
    expect(p.locator("#miE_result")).to_contain_text("status active → void")
    expect(p.locator("#miE_result")).to_contain_text("logged twice")
    mi.close_sheet()


# ── MI-05 quick add by typed text ────────────────────────────────────────────
def test_MI_05_quick_add_typed_text(mi, page, api, mi_env):
    p = page
    open_window(mi)
    box = p.get_by_test_id("mi-quick-text")
    mi.type("miQuickText", "Bank deposit at Chase, 6 miles")
    out = mi.capture("add_mileage_trip", lambda: box.press("Enter"))
    assert out.startswith("📝"), out
    expect(p.locator("#miQuickResult")).to_contain_text("Log this?")
    out = mi.capture("add_mileage_trip", lambda: p.locator("#miQuickResult").get_by_role("button", name="Save").click())
    assert out.startswith("✅ Saved TRIP-"), out
    t = trip(api, trip_ids(out)[0])
    assert (num(t["miles"]), t["category"], t["trip_date"], t["origin"], t["classification"]) == \
        (6.0, "Bank", SANDBOX_DATE, "manual", "business"), t
    assert "chase" in (t["to_label"] + t["purpose"]).lower(), t
    mi.loaded()
    expect(mi.trip_card(t["trip_id"])).to_be_visible()

    # missing miles -> it asks, saves nothing
    before = len(mlog(api)["trips"])
    mi.type("miQuickText", "Went to the post office to mail invoices")
    out = mi.capture("add_mileage_trip", lambda: box.press("Enter"))
    assert out.startswith("❓"), out
    expect(p.locator("#miQuickResult")).to_contain_text("need a bit more")
    assert len(mlog(api)["trips"]) == before


# ── MI-06 a clocked day ──────────────────────────────────────────────────────
def _clock(api, jid, action):
    out = api.call("log_time_entry", {"job_identifier": jid, "action": action})
    assert out.startswith("⏱"), out
    time.sleep(1.2)


def _hhmm_plus(clock_in: str, minutes: int):
    m = re.search(r"(\d{1,2}):(\d{2})(?::\d{2})?\s*([AaPp][Mm])?", clock_in or "")
    if not m:
        return None
    h, mm = int(m.group(1)), int(m.group(2))
    if m.group(3):
        h = h % 12 + (12 if m.group(3).lower() == "pm" else 0)
    tot = h * 60 + mm + minutes
    return None if tot >= 24 * 60 else f"{tot // 60:02d}:{tot % 60:02d}"


def test_MI_06_clocked_day_recalc_edit_fix_gap_cancelled(mi, page, api, data, mi_env):
    p = page
    j1 = data.job("MI06 City Hall", "city_hall")
    j2 = data.job("MI06 Brannon Center", "brannon")
    j3 = data.job("MI06 Library", "library")
    j4 = data.job("MI06 Flagler Ave shop", "flagler")
    for j in (j1, j2):
        _clock(api, j, "start")
        _clock(api, j, "stop")
    _clock(api, j3, "start")                    # phone dies here — never clocked out

    # 1. ⟳ Recalculate a day builds the job legs
    open_window(mi)
    p.get_by_role("button", name=re.compile("Recalculate a day")).click()
    mi.expect_sheet("Recalculate a day")
    mi.set("miR_date", SANDBOX_DATE)
    out = mi.capture("build_mileage_log", lambda: mi.button("Recalculate").click())
    assert not out.startswith("❌"), out
    legs = [t for t in mlog(api)["trips"] if t["job_id"] == j2 and t["status"] == "active"]
    assert legs, f"no trip was built to {j2} after clocking City Hall then Brannon Center: {out}"
    leg = legs[0]
    assert leg["origin"] == "auto" and leg["classification"] == "business", leg
    assert 0 < float(leg["miles"]) < 6, f"City Hall -> Brannon Center is under a mile or two, got {leg['miles']}"

    # 2. a hand edit of a built leg survives the next rebuild
    mi.reload()
    mi.open_trip(leg["trip_id"])
    new_miles = f"{float(leg['miles']) + 0.7:.1f}"
    mi.type("miE_miles", new_miles).type("miE_reason", "Detour — Flagler Ave bridge closed")
    out = mi.save_edit()
    assert out.startswith(f"✅ {leg['trip_id']} updated (miles)"), out
    mi.loaded()
    expect(mi.trip_card(leg["trip_id"])).to_contain_text("✎ edited")
    out = api.call("build_mileage_log", {"date": SANDBOX_DATE})
    t = trip(api, leg["trip_id"])
    assert (t["status"], num(t["miles"]), t["manually_edited"]) == ("active", num(new_miles), 1), t

    # 3. Fix the missing clock-out at the library. The app lists open
    #    clock-ins of PAST days only (today's may still be running), and the
    #    sandbox is today — so this one row is added to the list the page
    #    shows; the form, the fix_mileage_gap call and the result are real.
    def _open_entry(e):
        return str(e.get("Clock Out", "") or "").strip() in ("", "None", "—", "-")

    entry = next((e for e in api.read("TimeLog")
                  if str(e.get("JobID (JOB-####)", e.get("JobID", ""))) == j3 and _open_entry(e)), None)
    assert entry, f"no open clock-in for {j3} in TimeLog"
    eid, cin = entry.get("EntryID") or entry.get("Entry ID"), entry.get("Clock In", "")
    out_t = _hhmm_plus(cin, 2)
    if not out_t:
        pytest.skip(f"clock-in {cin!r} is too close to midnight to add a clock-out after it")
    real = mlog(api)
    real["gaps"] = [{"type": "missing_clock_out", "date": SANDBOX_DATE, "entry_id": eid, "driver": "owner",
                     "where": f"{ZTEST_PREFIX} MI06 Library", "clock_in": _hhmm_plus(cin, 0)}] + \
        list(real.get("gaps") or [])
    p.e2e_fakes["get_mileage_log"] = json.dumps(real)
    mi.reload()
    gaps = p.get_by_test_id("mi-gaps")
    expect(gaps).to_contain_text("MI06 Library")
    gaps.locator(".mi-gap", has_text="MI06 Library").get_by_role("button", name="Fix").click()
    mi.expect_sheet("Fix missing clock-out")
    del p.e2e_fakes["get_mileage_log"]
    mi.set("miG_time", out_t).type("miG_reason", "Phone died at the library job")
    out = mi.capture("fix_mileage_gap", lambda: mi.button("Save and rebuild the day").click())
    assert out.startswith(f"✅ Clock-out {out_t} added to {eid}"), out
    e = next(x for x in api.read("TimeLog") if (x.get("EntryID") or x.get("Entry ID")) == eid)
    assert e.get("Clock Out", "").strip() and "Phone died" in e.get("Notes", ""), e
    to_lib = [t for t in mlog(api)["trips"] if t["job_id"] == j3 and t["status"] == "active"]
    assert to_lib and any(t["corrected"] for t in to_lib), f"the library leg should be marked corrected: {to_lib}"

    # 4. The Flagler Ave customer cancels at the door
    p.evaluate("async () => { await loadJobs(); }")
    p.get_by_test_id("mi-cancelled").click()
    mi.expect_sheet("cancelled on arrival")
    mi.type("miC_note", "Customer not home - gate locked")
    row = mi.body.locator(".mi-gap", has_text=j4)
    expect(row).to_be_visible()
    out = mi.capture("job_cancelled_on_arrival",
                     lambda: mi.accepting(lambda: row.get_by_role("button", name="Cancelled", exact=True).click()))
    assert out.startswith(f"✅ {j4}") and "Cancelled on arrival" in out, out
    job = next(x for x in api.read("Jobs_Schedule") if x.get("JobID (JOB-####)") == j4)
    assert job.get("Job Status") == "Cancelled", job
    assert "Cancelled on arrival" in job.get("Service Details / Notes", "") and "gate locked" in \
        job.get("Service Details / Notes", ""), job
    there = [t for t in mlog(api)["trips"] if t["job_id"] == j4 and t["status"] == "active"]
    assert there and "cancelled on site" in there[0]["purpose"] and there[0]["classification"] == "business", there


# ── MI-07 crew own-car reimbursement ─────────────────────────────────────────
def test_MI_07_crew_reimbursement_return_approve_paid(mi, page, api, ai, mi_env):
    p = page
    out = ai.call("manage_vehicles", {"action": "add", "vin": make_vin("2T1BURHE", "JC", 21), "year": "2018",
                                      "make": "Toyota", "model": "Corolla", "ownership": "crew",
                                      "owner_name": DRIVER, "default_driver": DRIVER, "plate": "QRT 552",
                                      "nickname": f"{ZTEST_PREFIX} Sam's own Corolla", "odometer": "61500"})
    car = re.search(r"VEH-\d+", out).group(0)
    a = trip_ids(ai.call("add_mileage_trip", {
        "for_crew": DRIVER, "vehicle_id": car, "date": SANDBOX_DATE, "from_place": OFFICE, "to_place": SUNBELT,
        "purpose": "Supplies – pressure washer chemicals at Sunbelt Rentals", "miles": "8.2",
        "category": "Supplies", "notes": f"{ZTEST_PREFIX} MI07", "confirm": False}))[0]
    b = trip_ids(ai.call("add_mileage_trip", {
        "for_crew": DRIVER, "vehicle_id": car, "date": SANDBOX_DATE, "from_place": SUNBELT,
        "to_place": "Flagler Ave storefront, 401 Flagler Ave, New Smyrna Beach",
        "purpose": "Estimate – storefront windows on Flagler Ave", "miles": "4.6", "parking_usd": "2.00",
        "category": "Estimate/Quote", "notes": f"{ZTEST_PREFIX} MI07", "confirm": False}))[0]
    assert trip(api, a)["reimbursable"] and trip(api, b)["reimbursable"]
    out = ai.call("mileage_reimbursement", {"action": "submit", "crew": DRIVER})
    rid = re.search(r"REIM-\d+", out).group(0)
    assert reimb(api, rid)["status"] == "submitted"

    # owner returns it from the app
    open_window(mi)
    row = p.get_by_test_id("mi-reimb").locator("[data-testid='mi-reimb-row']", has_text=rid).last
    expect(row).to_contain_text("submitted")
    row.get_by_role("button", name="Return").click()
    mi.expect_sheet(f"Return {rid}")
    note = "The Flagler Ave estimate should be 4.1 mi - please fix"
    mi.type("miRt_note", note)
    out = mi.capture("mileage_reimbursement", lambda: mi.button("Return to crew member").click())
    assert f"{rid} returned" in out, out
    r = reimb(api, rid)
    assert (r["status"], r["return_note"]) == ("returned", note), r

    # the crew member (through Claude) fixes the trip and resubmits
    ai.call("update_mileage_trip", {"trip_id": b, "miles": "4.1", "reason": "Corrected per owner's note"})
    ai.call("mileage_reimbursement", {"action": "submit", "crew": DRIVER})
    assert reimb(api, rid)["status"] == "submitted"

    # owner approves, then marks it paid
    mi.reload()
    row = p.get_by_test_id("mi-reimb").locator("[data-testid='mi-reimb-row']", has_text=rid).last
    out = mi.capture("mileage_reimbursement",
                     lambda: mi.accepting(lambda: row.get_by_test_id("mi-reimb-approve").click()))
    assert out.startswith(f"✅ {rid} approved"), out
    r = reimb(api, rid)
    cents = rate_for(mi_env, SANDBOX_DATE)
    assert r["status"] == "approved" and num(r["miles"]) == 12.3, r
    assert num(r["amount_usd"]) == round(12.3 * cents / 100, 2) and num(r["parking_tolls_usd"]) == 2.0, r
    mi.loaded()
    row = p.get_by_test_id("mi-reimb").locator("[data-testid='mi-reimb-row']", has_text=rid).last
    row.get_by_test_id("mi-reimb-paid").click()
    mi.expect_sheet(f"Mark {rid} paid")
    mi.set("miPd_date", SANDBOX_DATE).choose("miPd_method", "check").type("miPd_ref", "1042")
    out = mi.capture("mileage_reimbursement", lambda: mi.button("Mark paid").click())
    assert out.startswith(f"✅ {rid} marked paid {SANDBOX_DATE} by check (ref 1042)"), out
    r = reimb(api, rid)
    assert (r["status"], r["paid_date"], r["paid_method"], r["paid_reference"]) == \
        ("paid", SANDBOX_DATE, "check", "1042"), r
    mi.loaded()
    expect(p.get_by_test_id("mi-reimb").locator("[data-testid='mi-reimb-row']", has_text=rid).last) \
        .to_contain_text("Paid " + SANDBOX_DATE)

    # paid trips are locked: the app shows the refusal, nothing changes
    mi.open_trip(a)
    mi.type("miE_miles", "9.9").type("miE_reason", "trying to change a paid trip")
    out = mi.save_edit()
    assert out.startswith("🔒"), out
    expect(p.locator("#miE_result")).to_contain_text("🔒")
    assert num(trip(api, a)["miles"]) == 8.2
    mi.close_sheet()

    # statement PDF downloads from the row
    row = p.get_by_test_id("mi-reimb").locator("[data-testid='mi-reimb-row']", has_text=rid).last
    with p.expect_download(timeout=60_000) as dl:
        row.get_by_role("button", name="PDF").click()
    pdf = open(dl.value.path(), "rb").read()
    assert pdf.startswith(b"%PDF") and rid.encode() in _pdf_text(pdf), "statement PDF missing or without its id"


# ── MI-08 AI review ──────────────────────────────────────────────────────────
def test_MI_08_ai_review_fix_duplicate_skip_long_leg(mi, page, api, mi_env):
    p, van = page, mi_env["van"]
    first = api_trip(api, to_place=HOME_DEPOT, from_place=OFFICE, purpose="Supplies – caulk and tape",
                     miles="3.8", category="Supplies", vehicle_id=van, notes=f"{ZTEST_PREFIX} MI08")[0]
    second = api_trip(api, to_place=HOME_DEPOT, from_place=OFFICE, purpose="Supplies – caulk and tape",
                      miles="3.8", category="Supplies", vehicle_id=van, notes=f"{ZTEST_PREFIX} MI08 again")[0]
    longleg = api_trip(api, to_place="Brannon Center, 105 S Riverside Dr", from_place="City Hall, 210 Sams Ave",
                       from_gps="29.0258,-80.9270", to_gps="29.0263,-80.9216", miles="9.5",
                       purpose="Client meeting – Brannon Center event windows", category="Client meeting",
                       vehicle_id=van, notes=f"{ZTEST_PREFIX} MI08 long")[0]
    open_window(mi)
    out = mi.capture("review_mileage_log", lambda: p.get_by_test_id("mi-review").click())
    findings = json.loads(out)["findings"]
    dup = next((f for f in findings if f["check"] == "duplicate" and f["trip_id"] in (first, second)), None)
    ll = next((f for f in findings if f["check"] == "long_leg" and f["trip_id"] == longleg), None)
    assert dup, f"no duplicate finding for {first}/{second}: {[f['id'] for f in findings]}"
    assert ll, f"no long-leg finding for {longleg}: {[f['id'] for f in findings]}"
    expect(p.get_by_test_id("mi-finding")).to_have_count(len(findings))

    def idx(fid):
        return p.evaluate("id => (MI._findings || []).findIndex(f => f.id === id)", fid)

    i = idx(dup["id"])
    out = mi.capture("apply_mileage_review_fix",
                     lambda: p.get_by_test_id("mi-finding").nth(i).get_by_test_id("mi-finding-fix").click())
    assert not out.lstrip().startswith(("❌", "🔒")), out
    gone, kept = trip(api, dup["trip_id"]), trip(api, first if dup["trip_id"] == second else second)
    assert gone["status"] == "void" and (gone["void_reason"] or "").startswith("AI review"), gone
    assert kept["status"] == "active", kept
    i = idx(ll["id"])
    out = mi.capture("apply_mileage_review_fix",
                     lambda: p.get_by_test_id("mi-finding").nth(i).get_by_test_id("mi-finding-skip").click())
    assert not out.startswith("❌"), out
    again = json.loads(api.call("review_mileage_log", {"start_date": W0, "end_date": W1, "as_json": True},
                                expect_ok=False))["findings"]
    assert ll["id"] not in [f["id"] for f in again], "a skipped finding came back"
    assert dup["id"] not in [f["id"] for f in again], "the fixed duplicate is still reported"
    assert trip(api, longleg)["status"] == "active" and num(trip(api, longleg)["miles"]) == 9.5
    mi.close_sheet()


# ── MI-09 exports ────────────────────────────────────────────────────────────
def _pdf_text(pdf: bytes) -> bytes:
    out = [pdf]
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.S):
        try:
            out.append(zlib.decompress(m.group(1)))
        except zlib.error:
            pass
    return b"\n".join(out)


def test_MI_09_exports_csv_excel_pdf(mi, page, api, mi_env):
    p, van = page, mi_env["van"]
    purpose = f"Bank deposit #{STAMP}"          # deposit-slip number: short enough for the PDF's column
    tid = api_trip(api, to_place=CHASE, from_place=OFFICE, purpose=purpose, miles="2.6", category="Bank",
                   vehicle_id=van, tolls_usd="1.25", notes=f"{ZTEST_PREFIX} MI09")[0]
    open_window(mi)
    card = p.get_by_test_id("mi-export")

    def download(btn, where=card):
        with p.expect_download(timeout=90_000) as dl:
            where.get_by_role("button", name=btn).click()
        return dl.value.suggested_filename, open(dl.value.path(), "rb").read()

    name, data_ = download("⬇ CSV")
    assert name == f"Mileage_{W0}_to_{W1}.csv", name
    rows = {r["Trip ID"]: r for r in csv.DictReader(io.StringIO(data_.decode("utf-8-sig")))}
    r = rows.get(tid)
    assert r, f"{tid} not in the CSV"
    assert (r["Purpose"], num(r["Miles"]), r["Category"], r["Classification"], r["To"], num(r["Tolls ($)"]),
            r["VIN"], r["Entry"], r["Status"]) == \
        (purpose, 2.6, "Bank", "business", CHASE, 1.25, mi_env["van_vin"], "manual", "active"), r

    name, data_ = download("⬇ Excel")
    assert name.endswith(".xlsx"), name
    z = zipfile.ZipFile(io.BytesIO(data_))
    wb = z.read("xl/workbook.xml").decode()
    for sheet in ("Trips", "Summary", "Reimbursement", "Vehicles"):
        assert f'name="{sheet}"' in wb, f"Excel has no {sheet} sheet"
    allxml = "".join(z.read(n).decode("utf-8", "replace") for n in z.namelist() if n.endswith(".xml"))
    assert tid in allxml and purpose in allxml, "the trip isn't in the Excel file"

    name, data_ = download("⬇ PDF")
    assert name.endswith(".pdf") and data_.startswith(b"%PDF"), name
    assert purpose.encode("cp1252") in _pdf_text(data_), "the trip isn't in the PDF's trip log"

    # Reports → Mileage & deduction → Export CSV (Jan 1 .. today) has it too
    p.get_by_test_id("nav-reports").click()
    rep = p.get_by_test_id("reports-mileage")
    expect(rep).to_be_visible(timeout=30_000)
    name, data_ = download("⬇ CSV", p.get_by_test_id("reports-mileage-export"))
    assert tid in {r["Trip ID"] for r in csv.DictReader(io.StringIO(data_.decode("utf-8-sig")))}


# ── MI-10 Reports card ───────────────────────────────────────────────────────
def test_MI_10_reports_card_matches_get_mileage_report(app, page, api, ai, mi_env):
    p = page
    api_trip(api, to_place=HOME_DEPOT, from_place=OFFICE, purpose="Supplies – window cleaning concentrate",
             miles="3.8", category="Supplies", vehicle_id=mi_env["van"], notes=f"{ZTEST_PREFIX} MI10")
    app.goto("reports")
    expect(p.get_by_test_id("reports-mileage")).to_be_visible(timeout=30_000)
    expect(p.locator("#mileageReport")).not_to_have_text("Loading…", timeout=40_000)   # its own first load
    p.locator("#miRepStart").fill(W0)
    p.locator("#miRepEnd").fill(W1)
    mi = Mileage(p, app, app.log)
    mi.capture("get_mileage_report",
               lambda: p.get_by_test_id("reports-mileage").get_by_role("button", name="Run", exact=True).click())
    want = ai.call("get_mileage_report", {"start_date": W0, "end_date": W1})
    norm = lambda s: re.sub(r"\s+", " ", s or "").strip()                                 # noqa: E731
    text = ""
    for _ in range(30):
        text = p.locator("#mileageReport").inner_text()
        if norm(text) == norm(want):
            break
        p.wait_for_timeout(500)
    assert norm(text) == norm(want), ("the Reports card doesn't show what Claude is told:\n--- app ---\n"
                                      f"{text[:1500]}\n--- get_mileage_report ---\n{want[:1500]}")
    assert W0 in text and W1 in text, text[:300]


# ── MI-11 Database → Settings: every mileage switch, and off = quiet ─────────
# (Vicki 2026-10-25: the Profile card is gone. Off is for a 100% work vehicle
#  tracked by yearly odometer — the app must not ask anyone for miles, but the
#  Mileage tab, Reports and Database → Miles stay.)
_REMINDER_ROWS = {"gaps": "Mileage Reminder - Daily Gaps", "weekly": "Mileage Reminder - Weekly Review",
                  "pay_period": "Mileage Reminder - Pay Period", "odometer": "Mileage Reminder - Odometer"}


def test_MI_11_settings_tab_period_reminders_and_tracking_off(app, page, api, mi_env, toggles, guard):
    from test_settings_toggles import _flip_in_app
    from test_database import _tab, _wait
    p = page
    mi = Mileage(p, app, app.log)
    saved = mi_env["saved"]

    def get():
        return json.loads(api.call("mileage_settings", {"action": "get"}, expect_ok=False))

    def settings_tab():
        app.goto("sheet")
        _wait(p)
        _tab(app, p, "Settings")
        expect(p.locator("#sheetContent")).to_contain_text("Mileage Tracking Enabled")

    def flip(key, value):
        guard.observe_setting(key, value, pending=True)
        _flip_in_app(app, p, key, value)
        guard.observe_setting(key, toggles.value(key))

    # the old Profile card is gone
    app.goto("profile")
    expect(p.get_by_test_id("mi-settings")).to_have_count(0)

    settings_tab()
    # pay period — a dropdown on the Settings row
    other = {"weekly": "biweekly", "biweekly": "monthly", "monthly": "weekly"}[saved["period"]]
    flip("Mileage Reimbursement Period", other)
    assert get()["reimbursement"]["kind"] == other
    flip("Mileage Reimbursement Period", saved["period"])
    assert get()["reimbursement"]["kind"] == saved["period"]

    # every reminder — Enabled/Disabled rows
    for k, key in _REMINDER_ROWS.items():
        was = bool(saved["reminders"].get(k))
        flip(key, "Disabled" if was else "Enabled")
        assert bool(get()["reminders"][k]) == (not was), f"reminder {k} didn't change"
        flip(key, "Enabled" if was else "Disabled")
        assert bool(get()["reminders"][k]) == was, f"reminder {k} didn't change back"

    # tracking OFF from the Settings tab → quiet, not gone
    flip("Mileage Tracking Enabled", "Disabled")
    assert get()["enabled"] is False
    expect(p.locator("#clockVehicleRow")).to_be_hidden()
    mi.open("week")
    expect(p.get_by_test_id("nav-mileage")).to_be_visible()
    expect(p.get_by_test_id("mi-off")).to_be_visible()
    expect(p.get_by_test_id("mi-off")).to_contain_text("route still shows miles driven")
    for gone in ("mi-entry", "mi-start", "mi-add", "mi-review", "mi-cancelled"):
        expect(p.get_by_test_id(gone)).to_be_hidden()
    for gone in ("mi-gaps", "mi-reminders", "mi-reimb", "mi-vehicles"):
        expect(p.get_by_test_id(gone)).to_have_count(0)
    log = mlog(api)
    assert log["enabled"] is False and log["gaps"] == [], "off must not ask anyone to fix miles"
    mi.open_miles_tab()
    expect(p.get_by_test_id("miles-off")).to_be_visible()
    expect(p.get_by_test_id("miles-add")).to_have_count(0)

    # back ON from the Settings tab
    settings_tab()
    flip("Mileage Tracking Enabled", "Enabled")
    assert get()["enabled"] is True
    mi.open("week")
    expect(p.get_by_test_id("mi-entry")).to_be_visible()
    expect(p.get_by_test_id("mi-off")).to_have_count(0)
    g = get()
    assert g["reimbursement"]["kind"] == saved["period"]
    assert {k: bool(v) for k, v in g["reminders"].items()} == {k: bool(v) for k, v in saved["reminders"].items()}


# ── MI-12 Claude logs + edits every field -> the app shows it ────────────────
def test_MI_12_claude_logs_and_edits_trip_app_shows_it(mi, page, api, ai, mi_env):
    p, van, truck = page, mi_env["van"], mi_env["truck"]
    n0 = len(mlog(api)["trips"])
    said = "Drove to Sherwin-Williams on 3rd Ave for 5 gallons of exterior paint, about 4 miles"
    out = ai.call("add_mileage_trip", {"text": said}, expect_ok=False)
    assert out.startswith(("📝", "❓")), out          # read back / asked — never saved yet
    assert len(mlog(api)["trips"]) == n0
    out = ai.call("add_mileage_trip", {
        "to_place": SHERWIN, "from_place": OFFICE, "purpose": "Supplies – 5 gal exterior paint", "miles": "4.2",
        "date": SANDBOX_DATE, "category": "Supplies", "vehicle_id": van, "start_time": "13:10", "end_time": "13:35",
        "notes": f"{ZTEST_PREFIX} paid with the company card", "confirm": False})
    tid = trip_ids(out)[0]
    edit = {"miles": "4.6", "purpose": "Supplies – 5 gal exterior paint and rollers", "to_place": SHERWIN,
            "from_place": "105 S Riverside Dr, New Smyrna Beach", "date": YESTERDAY, "vehicle_id": truck,
            "classification": "business", "category": "Job", "start_time": "13:20", "end_time": "13:50",
            "parking_usd": "1.00", "tolls_usd": "1.50", "notes": f"{ZTEST_PREFIX} receipt in the glovebox"}
    out = ai.call("update_mileage_trip", dict(edit, trip_id=tid, reason="Claude: corrected from the receipt"))
    assert out.startswith(f"✅ {tid} updated"), out
    t = trip(api, tid)
    bad = check_trip(t, {"miles": "4.6", "purpose": edit["purpose"], "to_label": SHERWIN,
                         "from_label": edit["from_place"], "trip_date": YESTERDAY, "vehicle_id": truck,
                         "classification": "business", "category": "Job", "start_time": "13:20",
                         "end_time": "13:50", "parking_usd": "1", "tolls_usd": "1.5", "notes": edit["notes"]})
    assert not bad, "\n  ".join(bad)

    # the app: Mileage tab card, Database → Miles row, the edit sheet, history
    open_window(mi)
    card = mi.trip_card(tid)
    expect(card).to_contain_text("4.6 mi")
    expect(card).to_contain_text(edit["purpose"])
    expect(card).to_contain_text("13:20")
    mi.open_miles_tab()
    c = mi.miles_cells(tid)
    assert (c["Date"], c["From"], c["To"], c["Miles"], c["Purpose"], c["Type"]) == \
        (f"{YESTERDAY} 13:20", edit["from_place"], SHERWIN, "4.6", edit["purpose"], "business"), c
    assert mi_env["truck_vin"][-6:] in c["Vehicle"], c
    mi.open_miles_row(tid)
    s = mi.read(Mileage.EDIT_FIELDS)
    assert (s["miE_date"], num(s["miE_miles"]), s["miE_from"], s["miE_to"], s["miE_purpose"], s["miE_cls"],
            s["miE_cat"], s["miE_vehicle"], num(s["miE_park"]), num(s["miE_toll"])) == \
        (YESTERDAY, 4.6, edit["from_place"], SHERWIN, edit["purpose"], "business", "Job", truck, 1.0, 1.5), s
    mi.capture("update_mileage_trip", lambda: mi.button("Change history").click())
    expect(p.locator("#miE_result")).to_contain_text("Claude: corrected from the receipt")
    expect(p.locator("#miE_result")).to_contain_text("notes")
