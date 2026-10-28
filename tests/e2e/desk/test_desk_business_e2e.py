"""Service Desk E2E — Business edition (server mode), several people at once.

E1  crew files an internal ticket with a camera photo; manager assigns it to
    staff; staff works it to Fixed; manager closes it
E3  manager and staff act on the same ticket at the same moment — the stale
    change is refused, nothing is overwritten
E4  role gates: crew can't see each other's tickets; a private ticket is hidden
    from the manager; crew can't close — same answers from the app and the API
E10 manager drags a card on the board
E12 owner backs up, a ticket is changed, the owner restores that one ticket
"""
import base64
import re

import pytest

pytestmark = pytest.mark.e2e

PNG = base64.b64decode(  # 1x1 PNG
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def _me(business, name):
    st, d = business.api("GET", "/desk-api/me", name=name)
    return d["actor"]["id"]


def _filed_id(person):
    person.toast("Filed")
    return re.search(r"T-\d{4,}", person.page.locator("#toast").inner_text()).group(0)


def test_E1_file_with_photo_assign_work_close(business, people, tmp_path):
    staff_id = _me(business, "Sam Staff")
    crew = people(business, "crew", phone=True)
    crew.sign_in("Cris Crew")
    crew.click("#fab")
    crew.page.select_option("#nKind", "internal")
    crew.type("#nTitle", "Pump leaking oil")
    crew.page.select_option("#nPri", "P2")
    crew.click("#nGo")
    tid = _filed_id(crew)
    photo = tmp_path / "pump.png"
    photo.write_bytes(PNG)
    crew.page.set_input_files("#cam", str(photo))
    crew.page.locator("#thumbs img").first.wait_for()

    mgr = people(business, "manager")
    mgr.sign_in("Mia Manager")
    mgr.tab("open")
    mgr.open_ticket(tid)
    mgr.type("#asg", staff_id)
    mgr.click("#asgGo")
    mgr.toast("Saved")

    staff = people(business, "staff", phone=True)
    staff.sign_in("Sam Staff")
    staff.tab("mine")
    staff.open_ticket(tid)
    staff.click("[data-move='In Progress']")
    staff.toast("Saved")
    staff.click("[data-move='Fixed']")
    staff.toast("Saved")

    mgr.tab("open")
    mgr.open_ticket(tid)
    mgr.answer(True)                         # "Close this ticket?"
    mgr.click("[data-move='Closed']")
    mgr.toast("Saved")

    st, d = business.api("GET", f"/desk-api/tickets/{tid}", name="Olive Owner")
    t = d["ticket"]
    assert t["state"] == "Closed" and t["assignee"] == staff_id
    assert [h["to"] for h in t["state_history"]] == ["Open", "Assigned", "In Progress", "Fixed", "Closed"]
    assert t["attachments"][0]["kind"] == "photo" and t["attachments"][0]["thumb_path"]


def test_E3_stale_change_is_refused(business, people):
    staff_id = _me(business, "Sam Staff")
    st, d = business.api("POST", "/desk-api/tickets", {"kind": "internal", "title": "Hose split",
                                                       "assignee": staff_id}, name="Olive Owner")
    tid = d["ticket"]["ticket_id"]
    mgr = people(business, "manager")
    mgr.sign_in("Mia Manager")
    mgr.tab("open")
    mgr.open_ticket(tid)                     # manager is now looking at version 1
    staff = people(business, "staff", phone=True)
    staff.sign_in("Sam Staff")
    staff.tab("mine")
    staff.open_ticket(tid)
    staff.click("[data-move='In Progress']")
    staff.toast("Saved")
    mgr.answer("waiting on parts")
    mgr.click("[data-move='On Hold']")       # based on the old version
    mgr.toast("Someone else changed this ticket")
    st, d = business.api("GET", f"/desk-api/tickets/{tid}", name="Olive Owner")
    assert d["ticket"]["state"] == "In Progress"          # nothing overwritten


def test_E4_role_gates_match_in_app_and_api(business, people):
    st, d = business.api("POST", "/desk-api/tickets", {"kind": "internal", "title": "Cris only"},
                         name="Cris Crew")
    mine = d["ticket"]["ticket_id"]
    st, d = business.api("POST", "/desk-api/tickets", {"kind": "internal", "title": "HR matter",
                                                       "private": True}, name="Olive Owner")
    private = d["ticket"]["ticket_id"]
    dee = people(business, "crew2", phone=True)
    dee.sign_in("Dee Crew")
    dee.tab("open")
    dee.page.wait_for_timeout(800)
    assert dee.page.locator(f"[data-open='{mine}']").count() == 0
    assert business.api("GET", f"/desk-api/tickets/{mine}", name="Dee Crew")[0] == 404
    assert business.api("GET", f"/desk-api/tickets/{private}", name="Mia Manager")[0] == 404
    st, d = business.api("POST", f"/desk-api/tickets/{mine}/state",
                         {"to_state": "Closed", "reason": "done"}, name="Cris Crew")
    assert st == 403
    mgr = people(business, "manager")
    mgr.sign_in("Mia Manager")
    mgr.tab("open")
    mgr.page.locator(f"[data-open='{mine}']").first.wait_for()
    assert mgr.page.locator(f"[data-open='{private}']").count() == 0


def test_E10_board_drag(business, people):
    staff_id = _me(business, "Sam Staff")
    st, d = business.api("POST", "/desk-api/tickets", {"kind": "internal", "title": "Drag me",
                                                       "assignee": staff_id}, name="Olive Owner")
    tid = d["ticket"]["ticket_id"]
    mgr = people(business, "manager")
    mgr.sign_in("Mia Manager")
    mgr.tab("board")
    card = mgr.page.locator(f".col[data-col='Assigned'] [data-open='{tid}']")
    card.drag_to(mgr.page.locator(".col[data-col='In Progress']"))
    mgr.toast("In Progress")
    st, d = business.api("GET", f"/desk-api/tickets/{tid}", name="Olive Owner")
    assert d["ticket"]["state"] == "In Progress"


def test_E12_backup_then_restore_one_ticket(business, people):
    st, d = business.api("POST", "/desk-api/tickets", {"kind": "internal", "title": "Original title"},
                         name="Olive Owner")
    tid = d["ticket"]["ticket_id"]
    owner = people(business, "owner")
    owner.sign_in("Olive Owner")
    owner.tab("settings")
    owner.click("#bkNow")
    owner.toast("Backed up")
    business.api("POST", f"/desk-api/tickets/{tid}/update", {"fields": {"title": "CHANGED"}},
                 name="Olive Owner")
    owner.tab("settings")
    owner.answer(tid, True)                  # which ticket, then "Replace … ?"
    owner.page.locator("[data-rs]").first.click()
    owner.toast("Restored")
    st, d = business.api("GET", f"/desk-api/tickets/{tid}", name="Olive Owner")
    assert d["ticket"]["title"] == "Original title"
