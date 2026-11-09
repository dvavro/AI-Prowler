"""Sprint 24 (Coder 1 part of planned Sprint 11, Phase 7): plan revision comparison and Server mode compute limits
(S24-..). Revisions run in Personal mode; the server tests use two databases (the company server and Maria's
processing PC) sharing one exchange folder, as they would over a network share.
"""
import json
from pathlib import Path

import pytest

from estimator.context import RequestContext, personal_context
from estimator.database import open_database
from estimator.director import engine as director, watch
from estimator.drawing_model import engine, revisions, server_jobs as sj, store
from estimator.errors import ConfirmationRequired, InvalidInput, NotAvailable, NotFound, PermissionDenied
from estimator.estimating import service
from estimator.mcp_tools import est_tools as t
from estimator.takeoff import measurements as m

CTX = personal_context()
FIELD = RequestContext(user_id="fred", role="field")
MARIA = RequestContext(company_id="acme", user_id="maria", role="estimator", mode="server")
BOSS = RequestContext(company_id="acme", user_id="boss", role="owner", mode="server")
OTHER = RequestContext(company_id="other-co", user_id="zed", role="owner", mode="server")


@pytest.fixture(autouse=True)
def clean(monkeypatch, tmp_path):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    monkeypatch.setattr(engine, "ENGINE_MODULES", ("estimator.plan_engine_for_tests_only",))
    monkeypatch.setenv("ESTIMATOR_EXCHANGE_DIR", str(tmp_path / "share"))
    monkeypatch.setenv("ESTIMATOR_PC_ID", "maria-laptop")
    monkeypatch.setenv("ESTIMATOR_SERVER_USER", "maria")
    yield
    engine.clear_engine()


def j(text):
    return json.loads(text)


def pt(x, y):
    return {"type": "point", "points": [[x, y]]}


def poly(x0, y0, x1, y1):
    return {"type": "polygon", "points": [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]}


def PLAN(rev="A", image=None):
    """Rev A, or Rev B with: outlet 3 moved, slab bigger, the GFI removed, a new floor box, D1's size changed,
    a revision cloud, and a new sheet."""
    b = rev == "B"
    outlets = [{"viewport": "plan", "kind": "symbol", "label": "OUTLET", "block_name": "DUPLEX", "source": "cad",
                "geometry": pt(12 if (b and i == 3) else 2 + i, 3)} for i in range(5)]
    objs = outlets + [
        {"viewport": "plan", "kind": "polygon", "label": "SLAB", "source": "cad",
         "geometry": poly(1, 1, 7 if b else 6, 5)},                               # 20 x 16 ft → 24 x 16 ft
        {"viewport": "plan", "kind": "polygon", "label": "PORCH", "source": "cad", "geometry": poly(8, 1, 10, 5)},
        {"viewport": "plan", "kind": "opening", "tag": "D1", "label": "door", "source": "cad", "geometry": pt(10, 12)},
    ]
    if not b:
        objs.append({"viewport": "plan", "kind": "symbol", "label": "GFI", "block_name": "GFI", "source": "cad",
                     "geometry": pt(5, 8)})
    else:
        objs += [{"viewport": "plan", "kind": "symbol", "label": "FLOOR BOX", "block_name": "FBOX", "source": "cad",
                  "geometry": pt(15, 15)},
                 {"viewport": "plan", "kind": "polyline", "label": "REV CLOUD", "layer": "REVISION", "source": "cad",
                  "geometry": {"type": "polyline", "points": [[11, 2], [13, 2], [13, 4]]}}]
    sheets = [{"page_no": 1, "sheet_no": "E-101", "title": "POWER PLAN", "discipline": "electrical",
               "units": "paper_in", "width": 36, "height": 24, "image_path": image,
               "viewports": [{"key": "plan", "label": "POWER PLAN", "scale_note": "1/4\" = 1'-0\""}],
               "objects": objs,
               "schedules": [{"schedule_type": "door", "rows": [
                   {"mark": "D1", "fields": {"size": "3'-0\" x 7'-0\"" if b else "3'-0\" x 6'-8\""}}]}]}]
    if b:
        sheets.append({"page_no": 2, "sheet_no": "E-102", "title": "LIGHTING", "discipline": "electrical",
                       "units": "paper_in", "width": 36, "height": 24,
                       "viewports": [{"key": "p", "label": "LIGHTING", "scale_note": "1/4\" = 1'-0\""}],
                       "objects": [{"viewport": "p", "kind": "symbol", "label": "CAN", "source": "cad",
                                    "geometry": pt(3, 3)}]})
    return {"sheets": sheets}


def _pdf(path: Path, pages: int, note: str = "") -> str:
    body = b"".join(b"%d 0 obj << /Type /Page >> endobj\n" % (i + 3) for i in range(pages))
    path.write_bytes(b"%PDF-1.7\n1 0 obj << /Type /Pages >> endobj\n" + body + note.encode() + b"\n%%EOF\n")
    return str(path)


def _ids(conn, ctx, ps):
    out = {}
    for o in store.objects(conn, ctx, plan_set_id=ps)["objects"]:
        out.setdefault(o["label"] if o["kind"] != "opening" else o["tag"], []).append(o["id"])
    return out


@pytest.fixture
def revs(db, tmp_path):
    est = service.create_estimate(db, CTX, "Lopez remodel")["id"]
    a = store.upload(db, CTX, est, _pdf(tmp_path / "revA.pdf", 1, "A"), confirm=True)["plan_set_id"]
    store.save_results(db, CTX, a, PLAN("A"), "fake")
    o = _ids(db, CTX, a)
    keep = m.propose(db, CTX, est, "roofing", o["OUTLET"][:3], kind="count", label="outlets 1-3",
                     confirm=True)["proposed"][0]["id"]
    moved = m.propose(db, CTX, est, "roofing", o["OUTLET"][2:5], kind="count", label="outlets 3-5",
                      confirm=True)["proposed"][0]["id"]
    slab = m.propose(db, CTX, est, "roofing", o["SLAB"], feeds="roof_area_sqft", confirm=True)["proposed"][0]["id"]
    gfi = m.propose(db, CTX, est, "roofing", o["GFI"], kind="count", label="gfi", confirm=True)["proposed"][0]["id"]
    porch = m.propose(db, CTX, est, "roofing", o["PORCH"], kind="area", label="porch", confirm=True)["proposed"][0]["id"]
    typed = m.manual(db, CTX, est, "roofing", feeds="ridge_lf", qty="20", unit="lf", confirm=True)["measurement"]["id"]
    m.confirm_measurements(db, CTX, [keep, slab, porch], confirm=True)
    b = store.upload(db, CTX, est, _pdf(tmp_path / "revB.pdf", 2, "B"), supersedes_plan_set_id=a,
                     confirm=True)["plan_set_id"]
    store.save_results(db, CTX, b, PLAN("B"), "fake")
    return {"est": est, "a": a, "b": b, "o": o, "keep": keep, "moved": moved, "slab": slab, "gfi": gfi,
            "porch": porch, "typed": typed}


# ---------------------------------------------------------------- revisions

def test_compare_finds_every_change(db, revs):  # S24-C01
    with pytest.raises(ConfirmationRequired) as ask:
        revisions.compare(db, CTX, revs["b"])
    assert ask.value.details["totals"] == {"unchanged": 6, "moved": 1, "changed": 1, "removed": 1, "added": 3}
    assert ask.value.details["carry"] == 2 and ask.value.details["flag"] == 3
    r = revisions.compare(db, CTX, revs["b"], confirm=True)
    assert r["old_plan_set_id"] == revs["a"] and r["new_plan_set_id"] == revs["b"]
    sheet = r["sheets"][0]
    assert sheet["sheet_no"] == "E-101" and sheet["moved"] == 1 and sheet["removed"] == 1 and sheet["added"] == 2
    slab = sheet["changed_items"][0]
    assert slab["old"]["label"] == "SLAB" and slab["old"]["real_units"] != slab["new"]["real_units"]
    assert [x["old"]["label"] for x in sheet["removed_items"]] == ["GFI"]
    assert sorted(x["new"]["label"] for x in sheet["added_items"]) == ["FLOOR BOX", "REV CLOUD"]
    assert sheet["removed_items"][0]["old"]["bbox"] == [5.0, 8.0, 5.0, 8.0]                # red box for the overlay
    assert r["sheets_added"][0]["sheet_no"] == "E-102" and r["revision_marks"] == 1
    assert r["schedules"]["changed"][0]["mark"] == "D1" and "size" in r["schedules"]["changed"][0]["fields"]
    assert "Rev 1 → Rev 2" in r["said"]
    assert sorted(r["flagged_measurement_ids"]) == sorted([revs["moved"], revs["slab"], revs["gfi"]])
    assert sorted(r["carried_measurement_ids"]) == sorted([revs["keep"], revs["porch"]])
    assert revisions.compare(db, CTX, report_id=r["report_id"])["totals"] == r["totals"]


def test_measurements_carry_over_or_get_flagged(db, revs):  # S24-C02
    revisions.compare(db, CTX, revs["b"], confirm=True)
    new = _ids(db, CTX, revs["b"])
    keep = m._load(db, CTX, revs["keep"])
    assert keep["status"] == "approved" and keep["locked"] and not keep["needs_remeasure"]
    assert sorted(json.loads(keep["source_object_ids"])) == sorted(new["OUTLET"][:3])
    assert json.loads(keep["calc_json"])["carried_over"]["to_plan_set"] == revs["b"]
    new_sheet = store.sheets(db, CTX, revs["b"])["sheets"][0]["id"]
    assert keep["sheet_id"] == new_sheet
    slab = m._load(db, CTX, revs["slab"])
    assert slab["needs_remeasure"] and slab["qty"] == "320.00" and slab["status"] == "approved"   # flag only
    assert json.loads(slab["calc_json"])["revision"]["why"] == ["changed"]
    assert json.loads(m._load(db, CTX, revs["gfi"])["calc_json"])["revision"]["why"] == ["removed"]
    assert json.loads(m._load(db, CTX, revs["moved"])["calc_json"])["revision"]["why"] == ["moved"]
    typed = m._load(db, CTX, revs["typed"])
    calc = json.loads(typed["calc_json"] or "{}")
    assert not typed["needs_remeasure"] and "revision" not in calc and "carried_over" not in calc   # typed: untouched
    assert store.status(db, CTX, revs["a"])["status"] == "processed"                     # the old set stays on file
    acts = [r[0] for r in db.execute("SELECT action FROM estimate_events WHERE action IN ('measurement_carried_over',"
                                     " 'measurement_flagged', 'plan_revision_compared')")]
    assert acts.count("measurement_carried_over") == 2 and acts.count("measurement_flagged") == 3
    assert acts[-1] == "plan_revision_compared"


def test_compare_refusals(db, revs, tmp_path):  # S24-C03
    with pytest.raises(InvalidInput, match="doesn't replace"):
        revisions.compare(db, CTX, revs["a"])
    with pytest.raises(InvalidInput, match="same plan set"):
        revisions.compare(db, CTX, revs["a"], revs["a"])
    c = store.upload(db, CTX, revs["est"], _pdf(tmp_path / "revC.pdf", 1, "C"), supersedes_plan_set_id=revs["b"],
                     confirm=True)["plan_set_id"]
    with pytest.raises(InvalidInput, match="hasn't been read"):
        revisions.compare(db, CTX, c)
    other = service.create_estimate(db, CTX, "Elsewhere")["id"]
    d = store.upload(db, CTX, other, _pdf(tmp_path / "d.pdf", 1, "D"), confirm=True)["plan_set_id"]
    with pytest.raises(InvalidInput, match="same estimate"):
        revisions.compare(db, CTX, d, revs["a"])
    with pytest.raises(PermissionDenied):
        revisions.compare(db, FIELD, revs["b"])
    with pytest.raises(NotFound):
        revisions.compare(db, CTX, report_id=99)


def test_heavy_compare_refused_on_server(db, revs, monkeypatch):  # S24-C04
    server = RequestContext(mode="server")
    monkeypatch.setattr(revisions, "SERVER_OBJECT_CAP", 5)
    with pytest.raises(NotAvailable, match="processing PC"):
        revisions.compare(db, server, revs["b"], confirm=True)
    monkeypatch.setattr(revisions, "SERVER_OBJECT_CAP", 20000)
    assert revisions.compare(db, server, revs["b"], confirm=True)["totals"]["moved"] == 1


# ---------------------------------------------------------------- Server mode: queue, claim, publish

def _engine(tmp_path):
    seen = []

    def read(path, file_type, info):
        seen.append(info)
        img = Path(info["work_dir"]) / "p1.png"
        from PIL import Image
        Image.new("RGB", (360, 240), "white").save(img)
        return PLAN("A", str(img))
    engine.register_engine("fake-engine", read)
    return seen


@pytest.fixture
def two(tmp_path):
    server = open_database(tmp_path / "server.db")
    pc = open_database(tmp_path / "pc.db")
    for _ in range(3):                                  # keep the two installs' estimate numbers apart
        service.create_estimate(server, BOSS, "filler")
    est = service.create_estimate(server, MARIA, "Lopez remodel")["id"]
    yield {"server": server, "pc": pc, "est": est}
    server.close()
    pc.close()


def test_server_upload_is_queued(two, tmp_path):  # S24-Q01
    s = two["server"]
    up = store.upload(s, MARIA, two["est"], _pdf(tmp_path / "big.pdf", 25), confirm=True)
    assert up["queued_for"] == "maria" and up["pcs_online"] == 0 and "maria's PC" in up["next"]
    job = Path(tmp_path / "share" / "jobs" / f"acme__{up['plan_set_id']}")
    assert (job / "job.json").is_file() and (job / "plan.pdf").is_file()
    assert json.loads((job / "job.json").read_text())["preferred_user"] == "maria"
    st = store.status(s, MARIA, up["plan_set_id"])
    assert st["queue"]["state"] == "waiting" and "maria's PC" in st["say"]
    notices = [r[0] for r in s.execute("SELECT message FROM director_notices WHERE kind = 'plans'")]
    assert len(notices) == 1 and "none is online" in notices[0]
    _engine(tmp_path)
    out = engine.start(s, MARIA, up["plan_set_id"], confirm=True)        # the server never runs it
    assert out["status"] == "waiting_for_processing_pc" and "small plan processing is off" in out["why"]
    assert store.status(s, MARIA, up["plan_set_id"])["status"] == "uploaded"
    q = sj.queue(s, MARIA)
    assert q["count"] == 1 and q["jobs"][0]["state"] == "waiting" and q["pcs_online"] == 0
    with pytest.raises(InvalidInput, match="Personal mode"):
        sj.queue(two["pc"], CTX)


def test_processing_pc_claims_reads_and_publishes(two, tmp_path):  # S24-Q02
    s, pc = two["server"], two["pc"]
    ps = store.upload(s, MARIA, two["est"], _pdf(tmp_path / "lopez.pdf", 25), confirm=True)["plan_set_id"]
    seen = _engine(tmp_path)
    got = sj.claim_next(pc, CTX)
    assert got["claimed"] and got["server_plan_set_id"] == ps and got["file"] == "lopez.pdf"
    q = sj.queue(s, MARIA)
    assert q["jobs"][0]["state"] == "claimed" and q["jobs"][0]["pc"] == "maria-laptop" and q["pcs_online"] == 1
    assert "maria's PC" in store.status(s, MARIA, ps)["say"]
    assert sj.claim_next(pc, CTX)["claimed"] is False                      # nothing else waiting
    engine.start(pc, CTX, got["plan_set_id"], confirm=True)
    assert seen and store.status(pc, CTX, got["plan_set_id"])["status"] == "processed"
    o = _ids(pc, CTX, got["plan_set_id"])
    m.propose(pc, CTX, got["estimate_id"], "roofing", o["SLAB"], feeds="roof_area_sqft", confirm=True)
    with pytest.raises(ConfirmationRequired) as ask:
        sj.publish(pc, CTX, got["plan_set_id"])
    assert ask.value.details == {"sheets": 1, "objects": 9, "measurements": 1}
    pub = sj.publish(pc, CTX, got["plan_set_id"], confirm=True)
    assert pub["published"] and pub["images"] == 1
    q = sj.queue(s, MARIA)                                                  # the server takes it in
    assert q["count"] == 0 and q["imported"][0]["ok"] and q["imported"][0]["from_pc"] == "maria-laptop"
    st = store.status(s, MARIA, ps)
    assert st["status"] == "processed" and st["objects"] == 9 and st["queue"]["state"] == "published"
    assert "read on maria-laptop" in st["engine"]
    sheet = store.sheets(s, MARIA, ps)["sheets"][0]
    assert Path(store.sheet_image(s, MARIA, sheet["id"])["path"]).is_file()
    ms = m.list_measurements(s, MARIA, two["est"])["measurements"]
    assert len(ms) == 1 and ms[0]["qty"] == "320.00" and ms[0]["status"] == "proposed"
    assert ms[0]["proposed_by"] == "pc:maria-laptop"
    assert not (tmp_path / "share" / "jobs" / f"acme__{ps}").exists()
    msgs = [r[0] for r in s.execute("SELECT message FROM director_notices WHERE kind = 'plans'")]
    assert any("ready to review" in x for x in msgs)


def test_claim_order_and_races(two, tmp_path, monkeypatch):  # S24-Q03
    s, pc = two["server"], two["pc"]
    bob = RequestContext(company_id="acme", user_id="bob", role="estimator", mode="server")
    p_bob = store.upload(s, bob, two["est"], _pdf(tmp_path / "bob.pdf", 25, "bob"), confirm=True)["plan_set_id"]
    got = sj.claim_next(pc, CTX)
    assert got["claimed"] is False and "other people's PCs" in got["say"]   # Bob's job is for Bob's PC first
    p_mine = store.upload(s, MARIA, two["est"], _pdf(tmp_path / "mine.pdf", 25, "m"), confirm=True)["plan_set_id"]
    assert sj.claim_next(pc, CTX)["server_plan_set_id"] == p_mine
    assert sj.claim_next(pc, CTX, any_job=True)["server_plan_set_id"] == p_bob
    # another PC can't take a job that's already claimed, and can't publish someone else's
    monkeypatch.setenv("ESTIMATOR_PC_ID", "other-pc")
    assert sj.claim_next(pc, CTX, any_job=True)["claimed"] is False


def test_stale_claims_go_back(two, tmp_path):  # S24-Q04
    s, pc = two["server"], two["pc"]
    ps = store.upload(s, MARIA, two["est"], _pdf(tmp_path / "x.pdf", 25), confirm=True)["plan_set_id"]
    sj.claim_next(pc, CTX)
    job = tmp_path / "share" / "jobs" / f"acme__{ps}"
    old = "2020-01-01T00:00:00+00:00"
    (job / "claim.json").write_text(json.dumps({"pc": "maria-laptop", "user": "maria", "at": old}))
    (job / "progress.json").write_text(json.dumps({"state": "reading", "at": old}))
    q = sj.queue(s, MARIA)
    assert q["released"] == [ps] and q["jobs"][0]["state"] == "waiting"


def test_publish_checks(two, tmp_path, monkeypatch):  # S24-Q05
    s, pc = two["server"], two["pc"]
    ps = store.upload(s, MARIA, two["est"], _pdf(tmp_path / "y.pdf", 25), confirm=True)["plan_set_id"]
    _engine(tmp_path)
    got = sj.claim_next(pc, CTX)
    with pytest.raises(InvalidInput, match="hasn't been read"):
        sj.publish(pc, CTX, got["plan_set_id"], confirm=True)
    engine.start(pc, CTX, got["plan_set_id"], confirm=True)
    local = service.create_estimate(pc, CTX, "my own job")["id"]
    own = store.upload(pc, CTX, local, _pdf(tmp_path / "own.pdf", 1, "own"), confirm=True)["plan_set_id"]
    with pytest.raises(InvalidInput, match="isn't a server plan job"):
        sj.publish(pc, CTX, own, confirm=True)
    monkeypatch.setenv("ESTIMATOR_PC_ID", "other-pc")
    with pytest.raises(PermissionDenied, match="maria-laptop"):
        sj.publish(pc, CTX, got["plan_set_id"], confirm=True)
    monkeypatch.setenv("ESTIMATOR_PC_ID", "maria-laptop")
    sj.publish(pc, CTX, got["plan_set_id"], confirm=True)
    # a result made from a different file, or for another company, is refused and set aside with the reason
    inbox = tmp_path / "share" / "inbox"
    bundle = json.loads((inbox / f"acme__{ps}.json").read_text())
    bundle["sha256"] = "0" * 64
    (inbox / f"acme__{ps}.json").write_text(json.dumps(bundle))
    q = sj.queue(s, MARIA)
    assert q["imported"][0]["ok"] is False and "different file" in q["imported"][0]["error"]
    assert (tmp_path / "share" / "failed" / f"acme__{ps}.json.why.txt").is_file()
    with pytest.raises(PermissionDenied):
        sj.receive(s, OTHER, dict(bundle, company_id="acme"))


def test_small_processing_on_the_server(two, tmp_path):  # S24-G01
    s = two["server"]
    assert sj.settings(s, BOSS)["small_processing_on_server"] is False
    with pytest.raises(PermissionDenied):
        sj.set_settings(s, MARIA, True, confirm=True)
    with pytest.raises(ConfirmationRequired):
        sj.set_settings(s, BOSS, True)
    with pytest.raises(InvalidInput):
        sj.set_settings(s, BOSS, True, 80, confirm=True)
    sj.set_settings(s, BOSS, True, 10, confirm=True)
    _engine(tmp_path)
    small = store.upload(s, MARIA, two["est"], _pdf(tmp_path / "small.pdf", 8), confirm=True)["plan_set_id"]
    big = store.upload(s, MARIA, two["est"], _pdf(tmp_path / "big.pdf", 25, "b"), confirm=True)["plan_set_id"]
    png = tmp_path / "scan.png"
    from PIL import Image
    Image.new("RGB", (2000, 1500), "white").save(png, dpi=(200, 200))
    scan = store.upload(s, MARIA, two["est"], str(png), confirm=True)["plan_set_id"]
    assert engine.start(s, MARIA, big, confirm=True)["status"] == "waiting_for_processing_pc"
    assert "more than the server's limit of 10" in engine.start(s, MARIA, big, confirm=True)["why"]
    assert "always read on a processing PC" in engine.start(s, MARIA, scan, confirm=True)["why"]
    s.execute("UPDATE plan_sets SET status = 'processing' WHERE id = ?", (big,))        # one at a time
    assert "one at a time" in engine.start(s, MARIA, small, confirm=True)["why"]
    s.execute("UPDATE plan_sets SET status = 'uploaded' WHERE id = ?", (big,))
    out = engine.start(s, MARIA, small, confirm=True)
    assert out["status"] == "processed"
    assert store.status(s, MARIA, small)["queue"] is None
    assert not (tmp_path / "share" / "jobs" / f"acme__{small}").exists()
    assert sj.page_count(tmp_path / "small.pdf", "pdf") == 8 and sj.page_count(png, "png") is None


def test_director_waits_for_the_processing_pc(two, tmp_path):  # S24-D01
    s, pc = two["server"], two["pc"]
    job = director.start(s, MARIA, "bid the Lopez plans: framing, drywall and a new roof", has_plans=True)
    est = job["job"]["estimate_id"]
    ps = store.upload(s, MARIA, est, _pdf(tmp_path / "house.pdf", 25), confirm=True)["plan_set_id"]
    s.execute("UPDATE director_jobs SET stage = 'read_plans' WHERE id = ?", (job["job"]["id"],))   # plans arrive now
    s.execute("DELETE FROM director_steps WHERE job_id = ? AND stage = 'read_plans'", (job["job"]["id"],))
    nxt = director.next_step(s, MARIA, job["job"]["id"])
    assert nxt["job"]["waiting_on"] == "processing_pc" and "maria's PC" in nxt["next_step"]["say"]
    _engine(tmp_path)
    got = sj.claim_next(pc, CTX)
    engine.start(pc, CTX, got["plan_set_id"], confirm=True)
    sj.publish(pc, CTX, got["plan_set_id"], confirm=True)
    tick = watch.tick(s, watch.director_context("acme"))                   # the watcher takes it in
    assert tick["plans_published"][0]["plan_set_id"] == ps
    nxt = director.next_step(s, MARIA, job["job"]["id"])
    assert nxt["job"]["waiting_on"] != "processing_pc"


def test_revision_and_server_tools(db, revs, tmp_path):  # S24-T01
    assert j(t.plan_compare_revisions(revs["b"]))["error"] == "needs_confirmation"
    r = j(t.plan_compare_revisions(revs["b"], confirm=True))
    assert r["totals"]["removed"] == 1
    assert j(t.plan_compare_revisions(report_id=r["report_id"]))["report_id"] == r["report_id"]
    assert j(t.est_server_compute())["mode"] == "personal"
    assert j(t.est_server_compute(True, 5))["error"] == "needs_confirmation"
    assert j(t.plan_processing_queue())["error"] == "invalid_input"            # Personal mode has no server queue
    assert j(t.plan_processing_queue(claim=True))["claimed"] is False
    assert j(t.plan_publish_to_server(revs["b"]))["error"] == "invalid_input"
    for name, args in {"plan_compare_revisions": (999,), "plan_publish_to_server": (999,)}.items():
        res = j(getattr(t, name)(*args))
        assert res["ok"] is False and res["error"] and res["message"], (name, res)
