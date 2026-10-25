"""Server mode — the mileage tracker by role (2026-10-25; couldn't be written
before because the server's mileage test data can't be removed through the app).
U1 David = owner, U2 Vicki = manager, U3 Samual = field crew.

  SRV-MI-01  Samual, in the app: adds HIS OWN car (the form offers crew-owned
             only), logs a trip in it (no "for crew member" box for crew) →
             stored under his name, reimbursable; his Database → Miles shows
             only his trips
  SRV-MI-02  Scope: the owner logs a trip for Vicki. Samual's log doesn't show
             it; he can't change it, add a business vehicle, change mileage
             settings, or approve anything. Vicki (manager) sees his trips
  SRV-MI-03  Reimbursement by role: Samual submits his period in the app; can't
             approve it himself; Vicki (manager) returns it with a note in the
             app; he resubmits; David (owner) approves it in the app. Vicki
             submits her own and can't approve her own (another owner/manager
             must). Every reimbursement ends RETURNED — see "Live server" below.

Live server: a submitted or approved reimbursement freezes that person's trips
for the pay period. So a submit happens only after the owner's read shows the
period holds nothing but test trips, and the module ends every test
reimbursement in "returned" (not frozen), voids its test trips and retires its
vehicles — real trips Samual or Vicki log later this period are unaffected.
"Mark paid" (which locks trips for good) is covered by the personal suite.

Cleanup: mileage records can't be deleted through the app (IRS log). The
voided trips, retired vehicles and returned reimbursements are deleted ON THE
SERVER by tests\\server_cleanup\\run_ztest_server_cleanup.bat — this run notes
it, and every test run on David's PC reminds you until it's done.
E2E_SERVER_CLEANUP=off skips this module.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_mileage
"""
import json
import logging
import re
import time

import pytest
from playwright.sync_api import expect

from app_mileage import Mileage
from safety import SANDBOX_DATE, SANDBOX_DATES, ZTEST_PREFIX

log = logging.getLogger("e2e_srv")

OWNER, MANAGER, CREW = "David Vavro", "Vicki Vavro", "Samual Cronin"
W0, W1 = min(SANDBOX_DATES), SANDBOX_DATE
_TR = {**{str(i): i for i in range(10)}, **dict(zip("ABCDEFGH", range(1, 9))),
       **dict(zip("JKLMN", range(1, 6))), "P": 7, "R": 9, **dict(zip("STUVWXYZ", range(2, 10)))}
_WT = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
_SERIAL = int(time.time()) % 900_000 + 100_000


def make_vin(prefix8: str, year_plant: str, n: int) -> str:
    v = prefix8 + "0" + year_plant + f"{(_SERIAL + n) % 1_000_000:06d}"
    cd = sum(_TR[c] * w for c, w in zip(v, _WT)) % 11
    return v[:8] + ("X" if cd == 10 else str(cd)) + v[9:]


def mlog(api) -> dict:
    return json.loads(api.call("get_mileage_log", {"start_date": W0, "end_date": W1}, expect_ok=False))


def reimbs(owner_api) -> list:
    return json.loads(owner_api.call("mileage_reimbursement", {"action": "list", "as_json": True},
                                     expect_ok=False))


def _period_has_only_test_trips(owner_api, who: str) -> tuple[bool, str]:
    """The owner's read of `who`'s current pay period: (ok, why not)."""
    st = json.loads(owner_api.call("mileage_reimbursement", {"action": "status", "crew": who, "as_json": True},
                                   expect_ok=False))
    pv = st.get("preview") or {}
    ex = pv.get("existing") or {}
    if ex.get("status") in ("submitted", "approved", "paid"):
        return False, f"{who}'s reimbursement {ex.get('reimbursement_id')} for this period is already {ex.get('status')}"
    by_id = {t["trip_id"]: t for t in mlog(owner_api)["trips"]}
    real = [t["trip_id"] for t in pv.get("trips", [])
            if ZTEST_PREFIX not in str((by_id.get(t["trip_id"]) or {}).get("notes") or "")]
    if real:
        return False, f"{who} has real reimbursable trips this period ({', '.join(real[:5])}) — not touching them"
    return True, ""


@pytest.fixture(scope="module")
def mi(srv, owner_api, api_as, guard, server_script_cleanup, server_cleanup_note):
    if not server_script_cleanup:
        pytest.skip("E2E_SERVER_CLEANUP=off — server mileage tests leave records only the server script removes")
    s = json.loads(owner_api.call("mileage_settings", {"action": "get"}, expect_ok=False))
    if not s.get("enabled"):
        pytest.skip("Mileage tracking is off on the server (Database → Settings → Mileage Tracking Enabled)")
    server_cleanup_note("server mileage test records (trips, ZTEST vehicles, returned reimbursements)",
                        "test_srv_mileage")
    env = {"made_reimbs": []}
    yield env
    # ── end: nothing frozen, nothing counted; the server script deletes the rows
    for rid in env["made_reimbs"]:
        r = next((x for x in reimbs(owner_api) if x["reimbursement_id"] == rid), None)
        if r and r["status"] in ("submitted", "approved"):
            out = owner_api.call("mileage_reimbursement", {"action": "return", "reimbursement_id": rid,
                                                           "note": "E2E test finished"}, expect_ok=False)
            log.info(f"[SRV-MI] end: {rid} {r['status']} -> {out.splitlines()[0][:120]}")
    d = mlog(owner_api)
    for t in d["trips"]:
        if t["status"] == "active" and (t["trip_id"] in guard.created or ZTEST_PREFIX in str(t.get("notes") or "")):
            guard.adopt(t["trip_id"], date=t["trip_date"], reason="srv mileage end")
            owner_api.call("update_mileage_trip", {"trip_id": t["trip_id"], "action": "void",
                                                   "reason": "E2E test finished"}, expect_ok=False)
    for v in d["vehicles"]:
        if v.get("active") and str(v.get("nickname") or "").startswith(ZTEST_PREFIX):
            guard.adopt(v["vehicle_id"], name=v["nickname"], reason="srv mileage end")
            owner_api.call("manage_vehicles", {"action": "retire", "vehicle_id": v["vehicle_id"]}, expect_ok=False)
    left = [r["reimbursement_id"] for r in reimbs(owner_api)
            if r["reimbursement_id"] in env["made_reimbs"] and r["status"] in ("submitted", "approved", "paid")]
    assert not left, f"test reimbursements still freezing a real person's period: {left}"


def _signed_in(windows, key):
    (w,) = windows(key)
    w.log_in()
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    return w, Mileage(w.page, w.app, w.app.log)


def _open_window(m: Mileage):
    m.open("week")
    p = m.page
    p.get_by_test_id("mi-range").select_option("custom")
    for el, v in (("miStart", W0), ("miEnd", W1)):
        p.locator(f"#{el}").fill(v)
        p.locator(f"#{el}").dispatch_event("change")
    p.wait_for_timeout(300)
    m.reload()


# ── SRV-MI-01 ────────────────────────────────────────────────────────────────
def test_SRV_MI_01_crew_adds_own_car_and_logs_a_trip_in_the_app(mi, windows, owner_api, guard):
    w, m = _signed_in(windows, "U3")
    p = w.page
    _open_window(m)
    p.get_by_test_id("mi-vehicles").get_by_role("button", name=re.compile("Add")).click()
    m.expect_sheet("Add a vehicle")
    expect(p.locator("select#miV_own")).to_have_count(0)            # crew can't choose "business"
    expect(p.locator("#miV_own")).to_have_value("crew")
    expect(p.locator("#miV_owner")).to_have_count(0)
    vin = make_vin("2T1BURHE", "JC", 31)
    m.type("miV_vin", vin).type("miV_year", "2017").type("miV_make", "Toyota").type("miV_model", "Corolla SE")
    m.type("miV_plate", "QRT 553").type("miV_nick", f"{ZTEST_PREFIX} Samual's Corolla")
    m.set("miV_pis", "2022-05-01").type("miV_odo", "88410")
    out = m.capture("manage_vehicles", lambda: p.get_by_test_id("mi-save-vehicle").click())
    assert out.startswith("✅ Added VEH-") and "crew-owned" in out, out
    vid = re.search(r"VEH-\d+", out).group(0)
    v = next(x for x in mlog(owner_api)["vehicles"] if x["vehicle_id"] == vid)
    assert (v["ownership"], v["owner_name"], v["vin"], v["last_odometer"]) == ("crew", CREW, vin, 88410), v
    mi["crew_car"] = vid

    m.loaded()
    m.open_add_form()
    expect(p.locator("#miF_crew")).to_have_count(0)                 # crew log only their own trips
    m.fill(Mileage.ADD_FIELDS, {
        "miF_date": SANDBOX_DATE, "miF_cat": "Supplies", "miF_from": "210 Sams Ave, New Smyrna Beach",
        "miF_to": "Sunbelt Rentals, 2400 S Ridgewood Ave, Edgewater",
        "miF_purpose": "Supplies – pressure washer surface cleaner rental", "miF_miles": "8.2", "miF_rt": "0",
        "miF_vehicle": vid, "miF_park": "", "miF_toll": "", "miF_notes": f"{ZTEST_PREFIX} SRV-MI-01 rental receipt"})
    out = m.save_trip()
    assert out.startswith("✅ Saved TRIP-"), out
    tid = re.search(r"TRIP-\d+", out).group(0)
    t = next(x for x in mlog(owner_api)["trips"] if x["trip_id"] == tid)
    assert (t["crew"], t["vehicle_id"], bool(t["reimbursable"]), float(t["miles"])) == (CREW, vid, True, 8.2), t
    mi["crew_trip"] = tid

    m.open_miles_tab()
    drivers = set(p.locator("#sheetContent [data-testid='miles-row'] td:nth-child(3)").all_inner_texts())
    assert drivers <= {CREW}, f"Samual's Database → Miles shows other people's trips: {drivers}"
    expect(m.miles_row(tid)).to_be_visible()


# ── SRV-MI-02 ────────────────────────────────────────────────────────────────
def test_SRV_MI_02_crew_scope(mi, owner_api, api_as, guard):
    out = owner_api.call("add_mileage_trip", {
        "for_crew": MANAGER, "date": SANDBOX_DATE, "to_place": "Chase Bank, 1701 SR-44, New Smyrna Beach",
        "purpose": "Bank – deposit customer checks", "miles": "2.6", "category": "Bank",
        "notes": f"{ZTEST_PREFIX} SRV-MI-02 Vicki's trip"})
    vtid = re.search(r"TRIP-\d+", out).group(0)
    sam = api_as("U3")
    mine = {t["trip_id"]: t for t in mlog(sam)["trips"]}
    assert vtid not in mine, "Samual can see Vicki's trip"
    assert all(t["crew"] == CREW for t in mine.values()), {t["crew"] for t in mine.values()}
    res = sam.call("update_mileage_trip", {"trip_id": vtid, "miles": "9", "reason": "test"}, expect_ok=False)
    assert res.startswith("❌") and "only change your own" in res, res
    res = sam.call("manage_vehicles", {"action": "add", "vin": make_vin("1GCWGAFP", "CB", 32),
                                       "ownership": "business", "nickname": f"{ZTEST_PREFIX} not allowed"},
                   expect_ok=False)
    assert res.startswith("❌") and "crew-owned" in res, res
    guard.mileage_settings_saved = {"period": "(unchanged — refused)", "reminders": {}}
    try:
        res = sam.call("mileage_settings", {"action": "set_period", "pay_period": "weekly"}, expect_ok=False)
    finally:
        guard.mileage_settings_saved = None
    assert res.startswith("❌") and "owner or a manager" in res, res
    vicki = {t["trip_id"] for t in mlog(api_as("U2"))["trips"]}
    if mi.get("crew_trip"):
        assert mi["crew_trip"] in vicki, "Vicki (manager) can't see Samual's trip"
    assert vtid in vicki


# ── SRV-MI-03 ────────────────────────────────────────────────────────────────
def _submit_checked(owner_api, guard, who: str, action):
    ok, why = _period_has_only_test_trips(owner_api, who)
    if not ok:
        pytest.skip(why)
    guard.mileage_submit_ok = {who}
    try:
        return action()
    finally:
        guard.mileage_submit_ok = set()


def test_SRV_MI_03_reimbursement_roles(mi, windows, owner_api, api_as, guard):
    if not mi.get("crew_trip"):
        pytest.skip("needs SRV-MI-01's trip in Samual's own car")
    # 1. Samual submits in the app
    w3, m3 = _signed_in(windows, "U3")
    _open_window(m3)
    card = w3.page.get_by_test_id("mi-reimb")
    expect(card.get_by_test_id("mi-reimb-submit")).to_be_visible()
    out = _submit_checked(owner_api, guard, CREW, lambda: m3.capture(
        "mileage_reimbursement", lambda: m3.accepting(lambda: card.get_by_test_id("mi-reimb-submit").click())))
    assert out.startswith("✅ REIM-") and "submitted" in out, out
    rid = re.search(r"REIM-\d+", out).group(0)
    guard.created.add(rid)
    mi["made_reimbs"].append(rid)
    # 2. he can't approve it himself
    res = api_as("U3").call("mileage_reimbursement", {"action": "approve", "reimbursement_id": rid}, expect_ok=False)
    assert res.startswith("❌") and "owner or a manager" in res, res
    # 3. Vicki (manager) returns it in the app
    w2, m2 = _signed_in(windows, "U2")
    _open_window(m2)
    row = w2.page.get_by_test_id("mi-reimb").locator("[data-testid='mi-reimb-row']", has_text=rid).last
    expect(row).to_contain_text(CREW)
    row.get_by_role("button", name="Return").click()
    m2.expect_sheet(f"Return {rid}")
    m2.type("miRt_note", "Add the rental receipt number to the Sunbelt trip, then resubmit")
    out = m2.capture("mileage_reimbursement", lambda: m2.button("Return to crew member").click())
    assert f"{rid} returned" in out, out
    r = next(x for x in reimbs(owner_api) if x["reimbursement_id"] == rid)
    assert r["status"] == "returned" and "rental receipt" in r["return_note"], r
    # 4. he fixes the trip and resubmits
    api_as("U3").call("update_mileage_trip", {"trip_id": mi["crew_trip"], "reason": "receipt number added",
                                              "notes": f"{ZTEST_PREFIX} SRV-MI-03 Sunbelt receipt #R-55871"})
    out = _submit_checked(owner_api, guard, CREW,
                          lambda: api_as("U3").call("mileage_reimbursement", {"action": "submit"}))
    assert rid in out and "submitted" in out, out
    # 5. David (owner) approves it in the app
    w1, m1 = _signed_in(windows, "U1")
    _open_window(m1)
    row = w1.page.get_by_test_id("mi-reimb").locator("[data-testid='mi-reimb-row']", has_text=rid).last
    out = m1.capture("mileage_reimbursement",
                     lambda: m1.accepting(lambda: row.get_by_test_id("mi-reimb-approve").click()))
    assert out.startswith(f"✅ {rid} approved"), out
    assert next(x for x in reimbs(owner_api) if x["reimbursement_id"] == rid)["status"] == "approved"

    # 6. Vicki's own reimbursement: a manager can't approve her own
    out = api_as("U2").call("manage_vehicles", {
        "action": "add", "vin": make_vin("1HGCV1F3", "LA", 33), "year": "2020", "make": "Honda",
        "model": "Accord", "ownership": "crew", "owner_name": MANAGER, "default_driver": MANAGER,
        "nickname": f"{ZTEST_PREFIX} Vicki's Accord", "odometer": "41200"})
    vcar = re.search(r"VEH-\d+", out).group(0)
    api_as("U2").call("add_mileage_trip", {
        "date": SANDBOX_DATE, "vehicle_id": vcar, "to_place": "Volusia County Permits, 123 W Indiana Ave, DeLand",
        "purpose": "Permit pickup – commercial pressure-washing permit", "miles": "27.4", "category": "Office errand",
        "notes": f"{ZTEST_PREFIX} SRV-MI-03 Vicki's own car"})
    out = _submit_checked(owner_api, guard, MANAGER,
                          lambda: api_as("U2").call("mileage_reimbursement", {"action": "submit"}))
    vrid = re.search(r"REIM-\d+", out).group(0)
    guard.created.add(vrid)
    mi["made_reimbs"].append(vrid)
    res = api_as("U2").call("mileage_reimbursement", {"action": "approve", "reimbursement_id": vrid},
                            expect_ok=False)
    assert res.startswith("❌") and "can't approve your own" in res, res
    out = owner_api.call("mileage_reimbursement", {"action": "approve", "reimbursement_id": vrid})
    assert out.startswith(f"✅ {vrid} approved"), out
