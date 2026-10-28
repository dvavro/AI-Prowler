"""Service Desk E2E — EVERY data-entry box, typed in like a person (human mode).

David 2026-10-28: "Can you check if all the Data entry boxes work".

Each box / dropdown / checkbox / file picker in the Service Desk app and the
customer's pages is filled in the browser, and the server is then asked what
it saved — so a box that looks fine but never reaches the database fails.

D1  New ticket form: kind, title, details, customer name / phone / email, job
    id, priority, due date, "also alert by text" — and the empty-title check
D2  A ticket's page: assign to, internal note, reply to the customer, written
    resolution, file (internal only) and camera photo, the reason box for
    On Hold (cancelled = nothing changes)
D3  Settings: every switch, both "not a reply" dropdowns, auto-close days (and
    its 0-60 check), automatic-backup settings (on, how often, hour, keep
    daily / weekly / monthly, photos, second folder)
D4  Settings -> Team (Business): queue, assignment rule, ticket type — saved,
    then the delete buttons; Settings -> Data: import file, dry run, import,
    undo by batch id
D5  Solo settings: my alert email and mobile
D6  The customer's pages: request form checks (no title, no phone/email,
    wrong code), the email-code path, details, reply box, photo upload,
    "No, not yet" reason, confirm, stars + note

Run: tests\\run_desk_e2e.py -k D      (human mode is the default)
"""
from __future__ import annotations

import base64
import re
import time

import pytest

import desk_db

pytestmark = pytest.mark.e2e

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def _me(server, name=None):
    return server.api("GET", "/desk-api/me", name=name)[1]["actor"]["id"]


def _t(server, tid, name="Olive Owner"):
    st, d = server.api("GET", f"/desk-api/tickets/{tid}", name=name if server.kind == "business" else None)
    assert st == 200, (st, d)
    t = d["ticket"]
    for k, v in (t.get("sla") or {}).items():
        t.setdefault(k, v)
    return t


def _settings(server, name="Olive Owner"):
    return server.api("GET", "/desk-api/settings", name=name if server.kind == "business" else None)[1]["settings"]


def _until(fn, what, timeout=15):
    end = time.time() + timeout
    while True:
        v = fn()
        if v:
            return v
        if time.time() > end:
            raise AssertionError(f"timed out waiting for: {what}")
        time.sleep(0.3)


def _filed(p):
    p.toast("Filed")
    return re.search(r"T-\d{4,}", p.page.locator("#toast").inner_text()).group(0)


# ══════════════════════════════════════════════════════════════════════════════
def test_D1_new_ticket_form_every_field(business, people):
    o = people(business, "owner")
    o.sign_in("Olive Owner")
    o.click("#fab")
    o.click("#nGo")                                            # nothing typed yet
    o.toast("Give the ticket a title")
    o.page.select_option("#nKind", "external")
    o.type("#nTitle", "ZTEST D1 gutter overflowing")
    o.type("#nDesc", "Back corner, worst in heavy rain")
    o.type("#nName", "ZTEST Mr Hale")
    o.type("#nPhone", "555-010-0401")
    o.type("#nEmail", "hale@example.test")
    o.type("#nJob", "JOB-9001")
    o.page.select_option("#nPri", "P2")
    o.page.fill("#nDue", "2026-12-15")
    o.page.check("#nSms")
    o.click("#nGo")
    tid = _filed(o)
    o.page.locator(".id", has_text=tid).wait_for()
    o.page.locator(".chip", has_text="due ").first.wait_for()   # the due date shows on its page
    t = _t(business, tid)
    assert (t["kind"], t["title"], t["description"], t["priority"], t["job_id"]) == (
        "external", "ZTEST D1 gutter overflowing", "Back corner, worst in heavy rain", "P2", "JOB-9001")
    assert int(t["sms_fallback"]) == 1
    assert t["due_resolve_at"][:10] in ("2026-12-15", "2026-12-16"), t["due_resolve_at"]
    c = desk_db.get_contact(business.db, t["contact_id"])
    assert (c["name"], c["phone"], c["email"]) == ("ZTEST Mr Hale", "+15550100401", "hale@example.test"), c


def test_D2_ticket_page_every_box(business, people, tmp_path):
    st, d = business.api("POST", "/desk-api/tickets", {"kind": "external", "title": "ZTEST D2 screen torn",
                                                       "contact_name": "ZTEST Mrs Ruiz",
                                                       "contact_email": "ruiz@example.test"},
                         name="Olive Owner")
    tid = d["ticket"]["ticket_id"]
    sam = _me(business, "Sam Staff")
    m = people(business, "manager")
    m.sign_in("Mia Manager")
    m.tab("open")
    m.open_ticket(tid)
    m.type("#asg", sam)                                        # Assign to
    m.click("#asgGo")
    _until(lambda: _t(business, tid)["assignee"] == sam, "assigned to Sam")
    m.type("#msg", "ZTEST D2 internal: bring the spline roller")
    m.page.select_option("#msgVis", "internal")
    m.click("#msgGo")
    _until(lambda: any(x["body"].startswith("ZTEST D2 internal") and x["visibility"] == "internal"
                       for x in _t(business, tid)["messages"]), "the internal note")
    m.page.locator("#msg").wait_for()
    m.type("#msg", "ZTEST D2 We'll replace the screen Friday.")
    m.page.select_option("#msgVis", "public")
    m.click("#msgGo")
    _until(lambda: any(x["body"].startswith("ZTEST D2 We'll") and x["visibility"] == "public"
                       for x in _t(business, tid)["messages"]), "the customer reply")
    business.wait_message(lambda x: x["kind"] == "email" and x["to"] == "ruiz@example.test"
                          and "replace the screen Friday" in x["body"])
    m.answer("ZTEST D2 re-splined with new fiberglass mesh")   # the resolution box
    m.click("#resEdit")
    _until(lambda: _t(business, tid).get("resolution") == "ZTEST D2 re-splined with new fiberglass mesh",
           "the resolution")
    doc = tmp_path / "ztest_d2_quote.txt"
    doc.write_text("ZTEST quote", encoding="utf-8")
    m.page.locator("#attInternal").check()
    m.page.set_input_files("#file", str(doc))                 # 📎 File, internal only
    _until(lambda: any(a["filename"].endswith("ztest_d2_quote.txt") and a["visibility"] == "internal"
                       for a in _t(business, tid)["attachments"]), "the internal file")
    photo = tmp_path / "ztest_d2.png"
    photo.write_bytes(PNG)
    m.page.locator("#cam").wait_for(state="attached")
    m.page.set_input_files("#cam", str(photo))                # 📷 Camera, public
    _until(lambda: any(a["kind"] == "photo" and a["visibility"] == "public"
                       for a in _t(business, tid)["attachments"]), "the photo")
    m.click("[data-move='In Progress']")
    _until(lambda: _t(business, tid)["state"] == "In Progress", "In Progress")
    m.answer(False)                                            # cancel the reason box
    m.click("[data-move='On Hold']")
    m.toast("A reason is needed")
    assert _t(business, tid)["state"] == "In Progress", "a cancelled reason must change nothing"
    m.answer("ZTEST D2 waiting on the mesh delivery")
    m.click("[data-move='On Hold']")
    t = _until(lambda: (lambda t: t if t["state"] == "On Hold" else None)(_t(business, tid)), "On Hold")
    assert t["state_history"][-1].get("reason") == "ZTEST D2 waiting on the mesh delivery"


def test_D3_settings_switches_dropdowns_autoclose_backups(business, people, tmp_path):
    o = people(business, "owner")
    o.sign_in("Olive Owner")
    o.tab("settings")
    o.page.locator("[data-set]").first.wait_for()
    keys = o.page.locator("[data-set]").evaluate_all("els => els.map(e => e.dataset.set)")
    assert {"subcontractor_tickets", "sms_fallback_default", "portal_enabled", "csat_enabled"} <= set(keys), keys
    for key in keys:                                           # every switch, off and back
        before = _settings(business)[key]
        o.page.locator(f"[data-set='{key}']").click()
        _until(lambda: _settings(business)[key] == (not before), f"{key} flipped")
        o.page.locator(f"[data-set='{key}']").click()
        _until(lambda: _settings(business)[key] == before, f"{key} back")
    for key, values in (("sms_new_request_mode", ("ask", "link", "create", "off")),
                        ("email_new_request_mode", ("create", "off"))):
        for v in values:
            o.page.select_option(f"[data-mode='{key}']", v)
            _until(lambda: _settings(business)[key] == v, f"{key} = {v}")
    o.type("#acDays", "99")
    o.click("#acSave")
    o.toast("Enter 0 to 60 days")
    assert _settings(business)["auto_close_days"] == 3
    o.type("#acDays", "7")
    o.click("#acSave")
    _until(lambda: _settings(business)["auto_close_days"] == 7, "auto-close 7")
    o.page.locator("#bkSave").wait_for()
    o.page.locator("#bkOn").uncheck()
    o.page.select_option("#bkFreq", "weekly")
    o.type("#bkHour", "4")
    o.type("#bkD", "10")
    o.type("#bkW", "6")
    o.type("#bkM", "9")
    o.page.locator("#bkAtt").uncheck()
    second = tmp_path / "ztest_second_copy"
    o.type("#bkDir", str(second))
    o.click("#bkSave")
    want = {"backup_enabled": False, "backup_frequency": "weekly", "backup_hour": 4, "backup_keep_daily": 10,
            "backup_keep_weekly": 6, "backup_keep_monthly": 9, "backup_attachments": False,
            "backup_second_dir": str(second)}
    _until(lambda: all(_settings(business)[k] == v for k, v in want.items()), f"backup settings {want}")
    for k, v in (("auto_close_days", 3), ("backup_enabled", True), ("backup_frequency", "daily"),
                 ("backup_hour", 2), ("backup_keep_daily", 14), ("backup_keep_weekly", 8),
                 ("backup_keep_monthly", 12), ("backup_attachments", True), ("backup_second_dir", "")):
        business.api("POST", "/desk-api/settings", {"key": k, "value": v}, name="Olive Owner")


def test_D4_team_boxes_and_import_undo(business, people, tmp_path):
    sam = _me(business, "Sam Staff")
    o = people(business, "owner")
    o.sign_in("Olive Owner")
    o.tab("settings")
    o.page.locator("#qSave").wait_for()

    def team():
        return business.api("GET", "/desk-api/team", name="Olive Owner")[1]

    o.type("#qId", "ztest_d4")
    o.type("#qName", "ZTEST D4 Gutters")
    o.type("#qMem", sam)
    o.click("#qSave")
    _until(lambda: any(q["queue_id"] == "ztest_d4" and q["members"] == [sam] and q["name"] == "ZTEST D4 Gutters"
                       for q in team()["queues"]), "the queue")
    o.page.locator("#rSave").wait_for()
    o.type("#rId", "ztest_d4r")
    o.page.select_option("#rOn", "keyword")
    o.type("#rVal", "ztest d4 gutter")
    o.page.select_option("#rTo", "queue")
    o.type("#rTarget", "ztest_d4")
    o.type("#rOrder", "5")
    o.click("#rSave")
    _until(lambda: any(r["rule_id"] == "ztest_d4r" and r["match"] == {"keyword": "ztest d4 gutter"}
                       and r["action"] == {"queue": "ztest_d4"} and r["sort_order"] == 5
                       for r in team()["rules"]), "the rule")
    o.page.locator("#tSave").wait_for()
    o.type("#tId", "ztest_d4t")
    o.type("#tName", "ZTEST D4 Re-do")
    o.type("#tQueue", "ztest_d4")
    o.click("#tSave")
    _until(lambda: any(t["type_id"] == "ztest_d4t" and t["name"] == "ZTEST D4 Re-do"
                       and t["default_queue"] == "ztest_d4" for t in team()["types"]), "the type")
    # the rule really routes: a ticket mentioning it lands in the queue (round-robin -> Sam)
    st, d = business.api("POST", "/desk-api/tickets", {"kind": "internal", "title": "ZTEST D4 gutter seam split"},
                         name="Olive Owner")
    assert d["ticket"]["queue_id"] == "ztest_d4" and d["ticket"]["assignee"] == sam, d["ticket"]
    o.page.locator("[data-rdel='ztest_d4r']").wait_for()
    o.answer(True)
    o.click("[data-rdel='ztest_d4r']")
    _until(lambda: not any(r["rule_id"] == "ztest_d4r" for r in team()["rules"]), "rule deleted")
    o.page.locator("[data-qdel='ztest_d4']").wait_for()
    o.answer(True)
    o.click("[data-qdel='ztest_d4']")                         # refused: a ticket is still in it
    o.toast("still in queue")
    assert any(q["queue_id"] == "ztest_d4" for q in team()["queues"])
    routed = d["ticket"]["ticket_id"]
    business.api("POST", f"/desk-api/tickets/{routed}/state", {"to_state": "Closed", "reason": "ZTEST done"},
                 name="Olive Owner")
    o.answer(True)
    o.click("[data-qdel='ztest_d4']")
    _until(lambda: not any(q["queue_id"] == "ztest_d4" for q in team()["queues"]), "queue deleted")

    # Settings -> Data: import box, dry run, import, undo by batch id
    csv_f = tmp_path / "ztest_d4_import.csv"
    csv_f.write_text("Title,Description\nZTEST D4 imported one,from the old system\n", encoding="utf-8")
    o.page.locator("#impFile").wait_for(state="attached")
    o.page.set_input_files("#impFile", str(csv_f))
    o.click("#impDry")
    o.page.locator("#impOut", has_text="Dry run").wait_for()
    o.answer(True)
    o.click("#impGo")
    o.page.locator("#impOut", has_text="Imported as").wait_for()
    batch = re.search(r"Imported as (\S+) ", o.page.locator("#impOut").inner_text()).group(1)
    o.type("#undoId", batch)
    o.answer(True)
    o.click("#undoGo")
    o.toast("Removed 1 ticket(s)")


def test_D5_solo_alert_email_and_mobile(solo, people):
    o = people(solo, "owner")
    o.sign_in()
    o.tab("settings")
    o.type("#alEmail", "ztest.owner@example.test")
    o.type("#alPhone", "555-010-0499")
    o.click("#alSave")
    _until(lambda: (_settings(solo)["alert_email"], _settings(solo)["alert_phone"])
           == ("ztest.owner@example.test", "555-010-0499"), "alert contacts")
    for k in ("alert_email", "alert_phone"):
        solo.api("POST", "/desk-api/settings", {"key": k, "value": ""})


def test_D6_customer_pages_every_box(solo, people, tmp_path):
    c = people(solo, "customer", phone=True)
    c.page.goto(f"{solo.base}/support/new")
    c.click("#fSend")
    c.page.locator("#fErr", has_text="Tell us").wait_for()            # no title
    c.type("#fTitle", "ZTEST D6 patio pavers stained")
    c.click("#fSend")
    c.page.locator("#fErr", has_text="mobile number or an email").wait_for()
    c.type("#fName", "ZTEST Ms Park")
    c.type("#fEmail", "park@example.test")                            # the email-code path
    c.type("#fDesc", "Rust marks by the grill")
    c.click("#fSend")
    msg = solo.wait_message(lambda x: x["kind"] == "email" and x["to"] == "park@example.test"
                            and "code" in x["body"])
    code = re.search(r"\b(\d{6})\b", msg["body"]).group(1)
    c.type("#fCode", "000000" if code != "000000" else "111111")
    c.click("#fVerify")
    c.page.locator("#cErr", has_text="not right").wait_for()
    c.type("#fCode", code)
    c.click("#fVerify")
    c.page.wait_for_url(re.compile(r"/support/t/"))
    tid = re.search(r"T-\d{4,}", c.page.locator("#h1").inner_text()).group(0)
    t = _t(solo, tid)
    assert t["description"] == "Rust marks by the grill"
    assert desk_db.get_contact(solo.db, t["contact_id"])["email"] == "park@example.test"
    c.type("#reply", "ZTEST D6 The gate code is 4321")               # reply box
    c.click("#send")
    _until(lambda: any(m["body"] == "ZTEST D6 The gate code is 4321" and m["author_kind"] == "customer"
                       for m in _t(solo, tid)["messages"]), "the customer's reply")
    photo = tmp_path / "ztest_d6.png"
    photo.write_bytes(PNG)
    c.page.locator("#up").wait_for(state="attached")
    c.page.set_input_files("#up", str(photo))                        # 📷 Add photo
    _until(lambda: _t(solo, tid)["attachments"], "the customer's photo")
    for s in ("In Progress", "Fixed"):
        solo.api("POST", f"/desk-api/tickets/{tid}/state", {"to_state": s})
    c.page.reload()
    c.answer("ZTEST D6 one stain is still there")                    # "No, not yet" reason box
    c.click("#no")
    _until(lambda: _t(solo, tid)["state"] == "In Progress", "back In Progress")
    assert _t(solo, tid)["state_history"][-1].get("reason") == "ZTEST D6 one stain is still there"
    solo.api("POST", f"/desk-api/tickets/{tid}/state", {"to_state": "Fixed"})
    c.page.reload()
    c.click("#yes")
    _until(lambda: _t(solo, tid)["state"] == "Closed", "Closed")
    c.page.locator("[data-star='4']").click()
    c.type("#rateNote", "ZTEST D6 quick and tidy")
    c.click("#rateGo")
    _until(lambda: (_t(solo, tid)["csat_score"], _t(solo, tid)["csat_comment"]) == (4, "ZTEST D6 quick and tidy"),
           "the rating and note")
