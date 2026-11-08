"""Sprint 23 (Coder 1 part of planned Sprint 8, Phase 4): reviews with versions, highlighting, review-before-send,
and what is sent to the AI provider (S23-..). An electrical sheet with a rendered image is saved through the drawing
model (as the plan engine would), counted, reviewed, approved and cropped for the AI.
"""
import json
from decimal import Decimal
from pathlib import Path

import pytest

from estimator.bids import service as bids
from estimator.context import RequestContext, personal_context
from estimator.drawing_model import crops, store
from estimator.errors import (ConfirmationRequired, InvalidInput, NotAvailable, NotEditable, NotFound,
                              PermissionDenied)
from estimator.estimating import quick, service, validate
from estimator.mcp_tools import est_tools as t
from estimator.modules.registry import ModuleRegistry
from estimator.takeoff import measurements as m
from estimator.takeoff import reviews as rv

CTX = personal_context()
AGENT = RequestContext(role="estimator", agent="agent:takeoff")
FIELD = RequestContext(user_id="fred", role="field")
REVIEWER = RequestContext(user_id="rita", role="reviewer")
ESTIMATOR = RequestContext(user_id="ed", role="estimator")
OTHER = RequestContext(company_id="other-co", user_id="zed", role="owner")
REG = ModuleRegistry().load()


def j(text):
    return json.loads(text)


def _image(path: Path) -> str:
    from PIL import Image
    Image.new("RGB", (3600, 2400), "white").save(path)          # 36 x 24 in sheet at 100 px per inch
    return str(path)


def ELEC(image_path):
    pt = lambda x, y: {"type": "point", "points": [[x, y]]}
    outlets = [{"viewport": "plan", "kind": "symbol", "label": "OUTLET", "block_name": "DUPLEX", "source": "cad",
                "geometry": pt(2 + i, 3), "confidence": 0.9} for i in range(6)]
    return {"sheets": [{
        "page_no": 1, "sheet_no": "E-101", "title": "POWER PLAN", "discipline": "electrical", "units": "paper_in",
        "width": 36, "height": 24, "image_path": image_path,
        "viewports": [{"key": "plan", "label": "POWER PLAN", "scale_note": "1/4\" = 1'-0\""}],
        "objects": outlets + [
            {"viewport": "plan", "kind": "symbol", "label": "OUTLET", "block_name": "DUPLEX", "source": "cad",
             "geometry": pt(20, 10)},                                                   # the missed one
            {"viewport": "plan", "kind": "symbol", "label": "GFI", "block_name": "GFI", "source": "cad",
             "geometry": pt(5, 8)},
            {"viewport": "plan", "kind": "opening", "tag": "D1", "label": "door", "source": "cad",
             "geometry": pt(10, 12)},
            {"viewport": "plan", "kind": "opening", "tag": "D1", "label": "door", "source": "cad",
             "geometry": pt(14, 12)},
            {"viewport": "plan", "kind": "opening", "tag": "D2", "label": "door", "source": "cad",
             "geometry": pt(18, 12)},
            {"viewport": "plan", "kind": "polygon", "label": "SLAB", "source": "cad",
             "geometry": {"type": "polygon", "points": [[1, 1], [6, 1], [6, 5], [1, 5]]}},    # 20 x 16 ft = 320
            {"viewport": "plan", "kind": "polygon", "label": "PORCH", "source": "cad",
             "geometry": {"type": "polygon", "points": [[6, 1], [8, 1], [8, 5], [6, 5]]}},    # 8 x 16 ft = 128
        ],
        "schedules": [{"schedule_type": "door", "title": "DOOR SCHEDULE",
                       "rows": [{"mark": "D1", "fields": {"size": "3'-0\" x 6'-8\""}}]}]}]}


@pytest.fixture
def elec(db, tmp_path):
    est = service.create_estimate(db, CTX, "Lopez remodel")
    pdf = tmp_path / "power.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%%EOF\n")
    ps = store.upload(db, CTX, est["id"], str(pdf), confirm=True)["plan_set_id"]
    img = _image(tmp_path / "e101.png")
    store.save_results(db, CTX, ps, ELEC(img), "fake")
    db.execute("UPDATE sheets SET image_path = ? WHERE plan_set_id = ?", (img, ps))
    objs = {}
    for o in store.objects(db, CTX, plan_set_id=ps)["objects"]:
        objs.setdefault(o["label"] if o["kind"] != "opening" else o["tag"], []).append(o["id"])
    outlets = objs["OUTLET"][:6]
    count = m.propose(db, CTX, est["id"], "roofing", outlets, kind="count", label="duplex outlets",
                      confirm=True)["proposed"][0]["id"]
    sheet = store.sheets(db, CTX, ps)["sheets"][0]["id"]
    return {"est": est["id"], "ps": ps, "o": objs, "count": count, "outlets": outlets, "missed": objs["OUTLET"][6],
            "sheet": sheet, "img": img}


# ---------------------------------------------------------------- opening and saving

def test_start_keeps_the_original(db, elec):  # S23-R01
    assert rv.history(db, CTX, "count", elec["count"])["status"] == "unreviewed"
    out = rv.start(db, CTX, "count", elec["count"])
    assert out["review"]["version"] == 1 and out["review"]["status"] == "in_review" and out["status"] == "in_review"
    assert sum(s["count"] for s in out["highlight"]) == 6
    h = rv.history(db, CTX, "measurement", elec["count"])                     # either name finds the count
    assert [(v["version"], v["status"]) for v in h["versions"]] == [(0, "original"), (1, "in_review")]
    assert h["versions"][0]["result_qty"] == "6.00" and h["status"] == "in_review"
    again = rv.start(db, CTX, "count", elec["count"])
    assert again["already_open"] and again["review"]["id"] == out["review"]["id"]
    with pytest.raises(PermissionDenied):
        rv.start(db, FIELD, "count", elec["count"])
    with pytest.raises(NotFound):
        rv.start(db, OTHER, "count", elec["count"])


def test_save_makes_new_versions_and_prices_nothing(db, elec):  # S23-R02
    rid = rv.start(db, CTX, "count", elec["count"])["review"]["id"]
    out = rv.save(db, AGENT, rid, remove=elec["outlets"][:2], add=[elec["missed"]], note="two were GFIs")
    v = out["review"]
    assert v["version"] == 2 and v["result_qty"] == "5.00" and v["summary"] == "+1 added, −2 removed"
    assert out["was"] == "6.00" and out["now"] == "5.00" and v["note"] == "two were GFIs"
    assert m._load(db, CTX, elec["count"])["qty"] == "6.00"                     # nothing priced yet
    assert [x["status"] for x in rv.history(db, CTX, "count", elec["count"])["versions"]] == \
        ["original", "superseded", "in_review"]
    with pytest.raises(NotEditable):
        rv.save(db, CTX, rid, add=[elec["o"]["GFI"][0]])                        # that version is superseded now
    rid2 = v["id"]
    for bad in ({"remove": [elec["o"]["GFI"][0]]}, {"add": [elec["missed"]]}, {"add": [1], "remove": [1]}, {},
                {"qty": "7"}, {"relabel": {elec["outlets"][3]: ""}}, {"add": [999999]}):
        with pytest.raises((InvalidInput, NotFound)):
            rv.save(db, CTX, rid2, **bad)
    other = service.create_estimate(db, CTX, "Elsewhere")
    pdf = Path(elec["img"]).with_name("other.pdf")
    pdf.write_bytes(b"%PDF-1.7\n% other\n%%EOF\n")
    ps2 = store.upload(db, CTX, other["id"], str(pdf), confirm=True)["plan_set_id"]
    store.save_results(db, CTX, ps2, ELEC(None), "fake")
    stranger = store.objects(db, CTX, plan_set_id=ps2)["objects"][0]["id"]
    with pytest.raises(InvalidInput, match="another estimate"):
        rv.save(db, CTX, rid2, add=[stranger])
    back = rv.save(db, CTX, rid2, add=[elec["outlets"][0]])                    # removed, then put back
    assert back["review"]["changes"]["removed"] == [elec["outlets"][1]] and back["now"] == "6.00"


def test_relabel_and_relabel_matching(db, elec):  # S23-R03
    rid = rv.start(db, CTX, "count", elec["count"])["review"]["id"]
    one = rv.save(db, CTX, rid, relabel={str(elec["outlets"][5]): "FLOOR BOX"})
    assert one["now"] == "5.00" and one["review"]["summary"] == "1 relabelled"
    all_ = rv.save(db, CTX, one["review"]["id"], relabel={elec["outlets"][0]: "QUAD"}, relabel_matching=True)
    assert all_["now"] == "0.00" and len(all_["review"]["changes"]["relabelled"]) == 6
    with pytest.raises(InvalidInput, match="aren't in this count"):
        rv.save(db, CTX, all_["review"]["id"], relabel={elec["o"]["GFI"][0]: "X"})


def test_only_a_person_approves(db, elec):  # S23-A01
    rid = rv.start(db, CTX, "count", elec["count"])["review"]["id"]
    v = rv.save(db, AGENT, rid, remove=elec["outlets"][:2], add=[elec["missed"]],
                relabel={elec["outlets"][5]: "FLOOR BOX"})["review"]
    with pytest.raises(PermissionDenied):
        rv.approve(db, AGENT, v["id"], confirm=True)
    with pytest.raises(PermissionDenied):
        rv.approve(db, FIELD, v["id"], confirm=True)
    with pytest.raises(ConfirmationRequired) as ask:
        rv.approve(db, REVIEWER, v["id"])
    assert ask.value.details["was"] == "6.00" and ask.value.details["now"] == "4.00"
    out = rv.approve(db, REVIEWER, v["id"], confirm=True)
    assert out["status"] == "approved" and out["review"]["approver"] == "rita"
    row = m._load(db, CTX, elec["count"])
    assert row["qty"] == "4.00" and row["status"] == "approved" and row["locked"] and row["approved_by"] == "rita"
    assert sorted(json.loads(row["source_object_ids"])) == sorted(elec["outlets"][2:5] + [elec["missed"]])
    assert json.loads(row["calc_json"])["review"]["summary"] == "+1 added, −2 removed, 1 relabelled"
    assert db.execute("SELECT label FROM drawing_objects WHERE id = ?", (elec["outlets"][5],)).fetchone()[0] == \
        "FLOOR BOX"
    with pytest.raises(NotEditable):
        rv.approve(db, CTX, v["id"], confirm=True)                              # already approved
    with pytest.raises(PermissionDenied, match="someone other"):
        rv.approve(db, REVIEWER, v["id"], second_check=True, confirm=True)
    assert rv.approve(db, CTX, v["id"], second_check=True, confirm=True)["review"]["second_check_by"] == "owner"
    with pytest.raises(NotEditable):
        rv.approve(db, ESTIMATOR, v["id"], second_check=True, confirm=True)
    nxt = rv.start(db, CTX, "count", elec["count"])["review"]                   # a later review builds on it
    assert nxt["version"] == v["version"] + 1 and nxt["result_qty"] == "4.00"
    events = [r[0] for r in db.execute("SELECT action FROM estimate_events WHERE action LIKE 'review_%' ORDER BY id")]
    assert events == ["review_started", "review_saved", "review_approved", "review_second_check", "review_started"]


def test_area_review_feeds_pricing(db, elec):  # S23-A02
    mid = m.propose(db, CTX, elec["est"], "roofing", elec["o"]["SLAB"] + elec["o"]["PORCH"], feeds="roof_area_sqft",
                    confirm=True)["proposed"][0]["id"]
    assert m._load(db, CTX, mid)["qty"] == "448.00"
    rid = rv.start(db, CTX, "measurement", mid)["review"]["id"]
    v = rv.save(db, CTX, rid, remove=elec["o"]["PORCH"])["review"]
    assert v["result_qty"] == "320.00"
    v = rv.save(db, CTX, v["id"], qty="330", note="slab edge runs past the grid")["review"]
    assert v["result_qty"] == "330.00" and v["changes"]["edited"]["from"] == "320.00"
    rv.approve(db, CTX, v["id"], confirm=True)
    assert m.approved_answers(db, CTX, elec["est"])["roofing"]["roof_area_sqft"] == 330.0
    listed = {x["id"]: x["review_status"] for x in m.list_measurements(db, CTX, elec["est"])["measurements"]}
    assert listed == {elec["count"]: "unreviewed", mid: "approved"}
    with pytest.raises(InvalidInput):
        rv.start(db, CTX, "count", mid)                                          # an area isn't a count


def test_history_and_highlight(db, elec):  # S23-H01
    rid = rv.start(db, CTX, "count", elec["count"])["review"]["id"]
    v = rv.save(db, CTX, rid, remove=elec["outlets"][:1])["review"]
    rv.approve(db, CTX, v["id"], confirm=True)
    h = rv.history(db, CTX, "count", elec["count"])
    assert h["status"] == "approved" and h["approved_version"] == 2 and h["current_qty"] == "5.00"
    assert [x["summary"] for x in h["versions"]] == ["no changes", "no changes", "−1 removed"]
    hl = rv.highlight(db, CTX, "count", elec["count"])
    assert hl["total_hits"] == 5 and hl["by_sheet"] == {"E-101": 5} and hl["status"] == "approved"
    hits = hl["sheets"][0]["hits"]
    assert [x["n"] for x in hits] == [1, 2, 3, 4, 5] and hits[0]["bbox"] == [3.0, 3.0, 3.0, 3.0]
    assert hl["sheets"][0]["has_image"] and hl["sheets"][0]["width"] == "36"
    assert rv.highlight(db, CTX, "count", elec["count"], version=0)["total_hits"] == 6     # the original
    with pytest.raises(NotFound):
        rv.highlight(db, CTX, "count", elec["count"], version=9)


def test_schedule_row_review(db, elec):  # S23-S01
    row = store.schedules(db, CTX, elec["ps"])["schedules"][0]["rows"][0]
    assert sorted(row["linked_object_ids"]) == sorted(elec["o"]["D1"])
    rid = rv.start(db, CTX, "schedule", row["id"])["review"]["id"]
    v = rv.save(db, CTX, rid, remove=elec["o"]["D1"][:1], add=elec["o"]["D2"])["review"]
    assert v["result_qty"] == "2" and v["unit"] == "ea"
    rv.approve(db, REVIEWER, v["id"], confirm=True)
    after = store.schedules(db, CTX, elec["ps"])["schedules"][0]["rows"][0]
    assert sorted(after["linked_object_ids"]) == sorted(elec["o"]["D1"][1:] + elec["o"]["D2"])
    assert after["reviewed_by"] == "rita"


def test_targets_that_cant_be_reviewed(db, elec):  # S23-D01
    with pytest.raises(NotAvailable, match="symbol engine"):
        rv.start(db, CTX, "detection_set", 1)
    with pytest.raises(InvalidInput):
        rv.start(db, CTX, "teleport", 1)
    with pytest.raises(NotFound):
        rv.start(db, CTX, "schedule", 999)
    m.reject(db, CTX, elec["count"], "duplicate", confirm=True)
    with pytest.raises(NotEditable):
        rv.start(db, CTX, "count", elec["count"])


def test_validate_warns_about_open_reviews(db, elec):  # S23-V01
    rv.start(db, CTX, "count", elec["count"])
    codes = {f["code"] for f in validate.validate(db, CTX, elec["est"])["findings"]}
    assert "reviews_open" in codes


def test_require_reviews_before_send(db, fake_host):  # S23-B01
    e = service.create_estimate(db, CTX, "Smith clean")
    e = quick.answer(db, CTX, e["id"], "house_cleaning", {"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, e["rev"], REG)
    service.set_status(db, CTX, e["id"], e["rev"], "approved")
    b = bids.generate(db, CTX, e["id"], customer={"name": "Jane", "email": "jane@example.com"})
    typed = m.manual(db, AGENT, e["id"], "roofing", feeds="ridge_lf", qty="20", unit="lf", confirm=True)
    with pytest.raises(ConfirmationRequired):                                   # off by default: no check
        bids.send(db, CTX, b["id"])
    assert rv.require_before_send(db, CTX) is False
    with pytest.raises(PermissionDenied):
        rv.set_require_before_send(db, ESTIMATOR, True, confirm=True)
    with pytest.raises(ConfirmationRequired):
        rv.set_require_before_send(db, CTX, True)
    rv.set_require_before_send(db, CTX, True, confirm=True)
    with pytest.raises(NotEditable) as stop:
        bids.send(db, CTX, b["id"], confirm=True)
    assert "isn't approved" in stop.value.message and fake_host.named("send_email") == []
    m.confirm_measurements(db, CTX, [typed["measurement"]["id"]], confirm=True)
    with pytest.raises(ConfirmationRequired):                                   # all approved: back to the yes
        bids.send(db, CTX, b["id"])


# ---------------------------------------------------------------- what's sent to the AI

def test_crops_notice_and_log(db, elec):  # S23-P01
    s = crops.settings(db, CTX)
    assert s["crop_sending_enabled"] and s["notice_shown_at"] is None and s["sent_so_far"] == 0
    first = crops.prepare(db, AGENT, object_id=elec["outlets"][0], purpose="is this a duplex or a GFI?",
                          provider="claude_api")
    assert first["kind"] == "crop" and Path(first["file_path"]).is_file() and "notice" in first
    assert first["width_px"] <= crops.CROP_MAX_PX and first["sheet_no"] == "E-101"
    assert "ai_sent" in first["file_path"]
    inbox = db.execute("SELECT message FROM director_notices WHERE kind = 'privacy'").fetchall()
    assert len(inbox) == 1 and "small crops" in inbox[0][0]
    second = crops.prepare(db, CTX, elec["sheet"], bbox=[1, 1, 9, 6], purpose="what's this hatch?")
    assert "notice" not in second and second["bbox"] == [1.0, 1.0, 9.0, 6.0]
    with pytest.raises(InvalidInput, match="at most 15%"):
        crops.prepare(db, CTX, elec["sheet"], bbox=[0, 0, 20, 10], purpose="too much")
    with pytest.raises(InvalidInput, match="purpose"):
        crops.prepare(db, CTX, object_id=elec["outlets"][0])
    with pytest.raises(PermissionDenied):
        crops.prepare(db, CTX, elec["sheet"], whole_sheet=True, purpose="look at it")       # nobody asked
    with pytest.raises(PermissionDenied):
        crops.prepare(db, AGENT, elec["sheet"], whole_sheet=True, user_asked=True, purpose="look")
    with pytest.raises(PermissionDenied):
        crops.prepare(db, FIELD, object_id=elec["outlets"][0], purpose="x")
    whole = crops.prepare(db, CTX, elec["sheet"], whole_sheet=True, user_asked=True, purpose="the user asked")
    assert whole["kind"] == "full_sheet" and max(whole["width_px"], whole["height_px"]) <= crops.SHEET_MAX_PX
    log = crops.send_log(db, CTX, elec["est"])
    assert [r["kind"] for r in log["sent"]] == ["full_sheet", "crop", "crop"]
    assert log["sent"][2]["actor"] == "agent:takeoff" and log["sent"][2]["provider"] == "claude_api"
    assert log["sent"][0]["user_asked"] and log["sent"][1]["sha256"] and log["sent"][1]["bytes"] > 0
    with pytest.raises(PermissionDenied):
        crops.send_log(db, FIELD)


def test_crop_sending_off_sends_nothing(db, elec):  # S23-P02
    with pytest.raises(PermissionDenied):
        crops.set_enabled(db, ESTIMATOR, False, confirm=True)
    with pytest.raises(ConfirmationRequired):
        crops.set_enabled(db, CTX, False)
    assert crops.set_enabled(db, CTX, False, confirm=True)["crop_sending_enabled"] is False
    before = list(Path(elec["img"]).parent.rglob("*.png"))
    with pytest.raises(NotAvailable, match="turned off"):
        crops.prepare(db, AGENT, object_id=elec["outlets"][0], purpose="what is it")
    assert crops.settings(db, CTX)["sent_so_far"] == 0 and list(Path(elec["img"]).parent.rglob("*.png")) == before
    assert crops.set_enabled(db, CTX, True, confirm=True)["crop_sending_enabled"]
    assert crops.prepare(db, AGENT, object_id=elec["outlets"][0], purpose="what is it")["kind"] == "crop"


def test_crops_need_an_image(db, elec):  # S23-P03
    db.execute("UPDATE sheets SET image_path = NULL WHERE id = ?", (elec["sheet"],))
    with pytest.raises(NotAvailable, match="no image"):
        crops.prepare(db, CTX, object_id=elec["outlets"][0], purpose="x")
    with pytest.raises(NotFound):
        crops.prepare(db, OTHER, elec["sheet"], bbox=[1, 1, 2, 2], purpose="x")
    with pytest.raises(InvalidInput):
        crops.prepare(db, CTX, elec["sheet"], bbox=[5, 5, 1, 1], purpose="x")
    assert crops.settings(db, CTX)["sent_so_far"] == 0


def test_review_and_privacy_tools(db, elec):  # S23-T01
    st = j(t.review_start("count", elec["count"]))
    rid = st["review"]["id"]
    sv = j(t.review_save(rid, remove=str(elec["outlets"][0]), relabel=json.dumps({str(elec["outlets"][1]): "GFI"})))
    assert sv["now"] == "4.00"
    assert j(t.review_approve(sv["review"]["id"]))["error"] == "needs_confirmation"
    assert j(t.review_approve(sv["review"]["id"], confirm=True))["status"] == "approved"
    assert j(t.review_history("count", elec["count"]))["status"] == "approved"
    assert j(t.review_highlight("count", elec["count"]))["total_hits"] == 4
    assert j(t.review_highlight("count", elec["count"], 0))["total_hits"] == 6
    assert j(t.review_require_before_send())["require_reviews_before_send"] is False
    assert j(t.review_require_before_send(True, confirm=True))["require_reviews_before_send"] is True
    crop = j(t.plan_get_crop("what is this?", object_id=elec["outlets"][2]))
    assert crop["kind"] == "crop" and crop["show_notice"]
    p = j(t.est_ai_privacy(show_log=5))
    assert p["crop_sending_enabled"] and len(p["log"]) == 1 and p["notice_shown_at"]
    assert j(t.est_ai_privacy(crop_sending=False))["error"] == "needs_confirmation"
    assert j(t.plan_get_crop("x", sheet_id=elec["sheet"], bbox="[1,1,2,2]"))["kind"] == "crop"
    bad = {"review_start": ("count", 999), "review_save": (999,), "review_approve": (999,),
           "review_history": ("count", 999), "review_highlight": ("count", 999),
           "plan_get_crop": ("x",)}
    for name, args in bad.items():
        res = j(getattr(t, name)(*args))
        assert res["ok"] is False and res["error"] and res["message"], (name, res)
