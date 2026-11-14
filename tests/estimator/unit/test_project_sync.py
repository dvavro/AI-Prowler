"""Sending a project from a PC to the company server (project_sync.py): the bundle, taking it in on the server with
every id renumbered, sending again (replaces in place, or keeps both when the server copy was changed), and the
office-network inbox. The "server" here is a second company in the same throwaway database."""
import json
import zipfile
from pathlib import Path

import pytest

from estimator import project_sync
from estimator.context import RequestContext, personal_context
from estimator.errors import InvalidInput, PermissionDenied
from estimator.estimating import service

NOW = "2026-11-12T12:00:00+00:00"
PC = personal_context()
SERVER = RequestContext(company_id="acme", user_id="dana", role="estimator", mode="server")


def _ins(db, sql, args=()):
    return db.execute(sql, args).lastrowid


def _seed(db, data: Path) -> dict:
    est = service.create_estimate(db, PC, "Smith house", address="12 Oak St")["id"]
    db.execute("UPDATE estimates SET customer_id = 77 WHERE id = ?", (est,))
    plans = data / "projects" / f"estimate_{est:04d}" / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    plan_file = plans / "1_smith plans.pdf"
    plan_file.write_bytes(b"%PDF-fake plans")
    ps = _ins(db, "INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                  " sha256, revision, status, uploaded_by, created_at, queue_state) VALUES"
                  " (?,?,?,?,?,?,?,?,'processed',?,?,?)",
              ("default", est, str(plan_file), "smith plans.pdf", "pdf", 15, "aa", 1, "owner", NOW, "done"))
    work = plans / f"{ps}_sheets"
    work.mkdir()
    img = work / "sheet_001.png"
    img.write_bytes(b"PNG-fake")
    (work / "symbol_dictionary.json").write_text('{"x": 1}', encoding="utf-8")
    s1 = _ins(db, "INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, units, width, height,"
                  " image_path) VALUES (?,?,?,?,?,?,?,?,?)",
              ("default", ps, 1, "S-1", "FOUNDATION PLAN", "paper_in", "17", "11", str(img)))
    v1 = _ins(db, "INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, scale_method) VALUES (?,?,?,?,?)",
              ("default", s1, "FOUNDATION PLAN", "48", "note"))
    o1 = _ins(db, "INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json, source)"
                  " VALUES (?,?,?,?,?,?)", ("default", s1, v1, "polygon", "{}", "vector"))
    sch = _ins(db, "INSERT INTO schedules (company_id, sheet_id, schedule_type, title) VALUES (?,?,?,?)",
               ("default", s1, "other", "FOOTINGS"))
    _ins(db, "INSERT INTO schedule_rows (company_id, schedule_id, mark, linked_object_ids) VALUES (?,?,?,?)",
         ("default", sch, "F1", json.dumps([o1])))
    section = _ins(db, "INSERT INTO trade_sections (estimate_id, module_id, created_at) VALUES (?,?,?)",
                   (est, "concrete", NOW))
    m1 = _ins(db, "INSERT INTO measurements (company_id, estimate_id, module_id, trade_section_id, sheet_id,"
                  " viewport_id, kind, label, qty, unit, source_object_ids, method, status, proposed_by, created_at,"
                  " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              ("default", est, "concrete", section, s1, v1, "area", "slab", "2123.42", "sqft", json.dumps([o1]), "ai",
               "approved", "owner", NOW, NOW))
    au = _ins(db, "INSERT INTO assembly_uses (company_id, estimate_id, trade_section_id, assembly_id, module_id,"
                  " params_json, sources_json, measurement_ids, applied_by, applied_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
              ("default", est, section, "concrete@1", "concrete", "{}",
               json.dumps({"slab_sqft": {"from": "measured", "measurement_ids": [m1]}}), json.dumps([m1]), "owner",
               NOW))
    _ins(db, "INSERT INTO line_items (trade_section_id, assembly_use_id, kind, description, quantity, unit,"
             " unit_cost_cents, total_cents, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
         (section, au, "material", "Concrete", "46.2", "cy", 15000, 693000, "owner", NOW, NOW))
    _ins(db, "INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at) VALUES (?,?,?,?,?)",
         ("default", s1, "concrete", 1, NOW))
    bids = data / "projects" / f"estimate_{est:04d}" / "bids"
    bids.mkdir(parents=True)
    pdf = bids / "Q-1001.pdf"
    pdf.write_bytes(b"%PDF-quote")
    _ins(db, "INSERT INTO bids (company_id, estimate_id, version, number, customer_id, snapshot_json, total_cents,"
             " pdf_path, status, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
         ("default", est, 1, "Q-1001", 77, "{}", 693000, str(pdf), "draft", "owner", NOW, NOW))
    return {"estimate_id": est, "plan_set": ps, "sheet": s1, "object": o1, "measurement": m1}


@pytest.fixture
def seeded(db, estimator_sandbox):
    return _seed(db, estimator_sandbox)


def _send(db, seeded, **kw):
    built = project_sync.build_bundle(db, PC, seeded["estimate_id"])
    return project_sync.receive_bundle(db, SERVER, built["path"], **kw)


def _one(db, sql, args=()):
    return db.execute(sql, args).fetchone()


def test_bundle_holds_the_project_and_its_files(db, seeded):
    built = project_sync.build_bundle(db, PC, seeded["estimate_id"])
    with zipfile.ZipFile(built["path"]) as z:
        names = set(z.namelist())
        manifest = json.loads(z.read("manifest.json"))
    assert {"manifest.json", "data.json"} <= names
    assert f"files/plan/{seeded['plan_set']}/smith plans.pdf" in names
    assert f"files/sheet/{seeded['sheet']}/sheet_001.png" in names
    assert f"files/dict/{seeded['plan_set']}/symbol_dictionary.json" in names
    assert any(n.startswith("files/bid/") and n.endswith("Q-1001.pdf") for n in names)
    assert manifest["format"] == project_sync.FORMAT and manifest["title"] == "Smith house"
    assert manifest["counts"]["measurements"] == 1 and manifest["counts"]["line_items"] == 1


def test_server_takes_it_in_with_new_numbers(db, seeded):
    out = _send(db, seeded)
    assert out["mode"] == "new" and out["files"] == 4
    eid = out["estimate_id"]
    assert eid != seeded["estimate_id"]
    e = _one(db, "SELECT * FROM estimates WHERE id = ?", (eid,))
    assert e["company_id"] == "acme" and e["title"] == "Smith house" and e["address"] == "12 Oak St"
    assert e["customer_id"] is None                                  # the PC's customer number means nothing here
    ps = _one(db, "SELECT * FROM plan_sets WHERE estimate_id = ?", (eid,))
    assert ps["id"] != seeded["plan_set"] and ps["company_id"] == "acme" and ps["queue_state"] is None
    assert Path(ps["file_path"]).read_bytes() == b"%PDF-fake plans"
    assert f"estimate_{eid:04d}" in ps["file_path"]
    sheet = _one(db, "SELECT * FROM sheets WHERE plan_set_id = ?", (ps["id"],))
    assert Path(sheet["image_path"]).is_file() and f"{ps['id']}_sheets" in sheet["image_path"]
    assert (Path(sheet["image_path"]).parent / "symbol_dictionary.json").is_file()
    obj = _one(db, "SELECT * FROM drawing_objects WHERE sheet_id = ?", (sheet["id"],))
    vp = _one(db, "SELECT * FROM viewports WHERE sheet_id = ?", (sheet["id"],))
    assert obj["viewport_id"] == vp["id"]
    row = _one(db, "SELECT r.* FROM schedule_rows r JOIN schedules s ON s.id = r.schedule_id WHERE s.sheet_id = ?",
               (sheet["id"],))
    assert json.loads(row["linked_object_ids"]) == [obj["id"]]
    m = _one(db, "SELECT * FROM measurements WHERE estimate_id = ?", (eid,))
    assert m["sheet_id"] == sheet["id"] and m["viewport_id"] == vp["id"] and m["qty"] == "2123.42"
    assert json.loads(m["source_object_ids"]) == [obj["id"]]
    sec = _one(db, "SELECT * FROM trade_sections WHERE estimate_id = ?", (eid,))
    assert m["trade_section_id"] == sec["id"]
    au = _one(db, "SELECT * FROM assembly_uses WHERE estimate_id = ?", (eid,))
    assert json.loads(au["measurement_ids"]) == [m["id"]]
    assert json.loads(au["sources_json"])["slab_sqft"]["measurement_ids"] == [m["id"]]
    li = _one(db, "SELECT * FROM line_items WHERE trade_section_id = ?", (sec["id"],))
    assert li["assembly_use_id"] == au["id"] and li["total_cents"] == 693000
    bid = _one(db, "SELECT * FROM bids WHERE estimate_id = ?", (eid,))
    assert bid["number"] == "Q-1001" and bid["customer_id"] is None and Path(bid["pdf_path"]).is_file()
    assert _one(db, "SELECT active FROM sheet_trade_active WHERE company_id = 'acme' AND sheet_id = ?",
                (sheet["id"],))["active"] == 1
    sync = project_sync.received(db, SERVER)
    assert len(sync) == 1 and sync[0]["estimate_id"] == eid and sync[0]["source_estimate_id"] == seeded["estimate_id"]
    # the PC's own copy is untouched
    assert _one(db, "SELECT COUNT(*) FROM measurements WHERE estimate_id = ?", (seeded["estimate_id"],))[0] == 1


def test_sending_again_updates_the_same_server_estimate(db, seeded):
    first = _send(db, seeded)
    old_plan = Path(_one(db, "SELECT file_path FROM plan_sets WHERE estimate_id = ?", (first["estimate_id"],))[0])
    db.execute("UPDATE measurements SET qty = '2200' WHERE id = ?", (seeded["measurement"],))   # work on the PC
    again = _send(db, seeded)
    assert again["mode"] == "replaced" and again["estimate_id"] == first["estimate_id"]
    eid = first["estimate_id"]
    assert _one(db, "SELECT COUNT(*) FROM plan_sets WHERE estimate_id = ?", (eid,))[0] == 1
    assert _one(db, "SELECT COUNT(*) FROM trade_sections WHERE estimate_id = ?", (eid,))[0] == 1
    assert _one(db, "SELECT COUNT(*) FROM bids WHERE estimate_id = ?", (eid,))[0] == 1
    assert _one(db, "SELECT qty FROM measurements WHERE estimate_id = ?", (eid,))[0] == "2200"
    new_plan = Path(_one(db, "SELECT file_path FROM plan_sets WHERE estimate_id = ?", (eid,))[0])
    assert new_plan.is_file()                                        # even when SQLite reused the plan set's number
    assert new_plan == old_plan or not old_plan.exists()             # the old copy's files are cleaned up
    sheet = _one(db, "SELECT s.image_path FROM sheets s JOIN plan_sets p ON p.id = s.plan_set_id"
                     " WHERE p.estimate_id = ?", (eid,))
    assert Path(sheet[0]).is_file()
    assert _one(db, "SELECT COUNT(*) FROM estimates WHERE company_id = 'acme'")[0] == 1


def test_changes_made_on_the_server_are_never_overwritten_silently(db, seeded):
    first = _send(db, seeded)
    eid = first["estimate_id"]
    db.execute("UPDATE measurements SET qty = '9', updated_at = '2999-01-01T00:00:00+00:00' WHERE estimate_id = ?",
               (eid,))                                               # the crew fixed something on the server
    kept = _send(db, seeded)
    assert kept["mode"] == "kept_both" and kept["estimate_id"] != eid
    assert kept["server_changes"] and "sent again" in _one(db, "SELECT title FROM estimates WHERE id = ?",
                                                             (kept["estimate_id"],))[0]
    assert _one(db, "SELECT qty FROM measurements WHERE estimate_id = ?", (eid,))[0] == "9"
    forced = _send(db, seeded, replace_anyway=True)
    assert forced["mode"] == "replaced" and forced["estimate_id"] == eid
    assert _one(db, "SELECT qty FROM measurements WHERE estimate_id = ?", (eid,))[0] == "2123.42"


def test_who_may_send_and_receive(db, seeded):
    field = RequestContext(company_id="default", user_id="sam", role="field")
    with pytest.raises(PermissionDenied):
        project_sync.build_bundle(db, field, seeded["estimate_id"])
    built = project_sync.build_bundle(db, PC, seeded["estimate_id"])
    with pytest.raises(PermissionDenied):
        project_sync.receive_bundle(db, RequestContext(company_id="acme", user_id="x", role="reviewer"), built["path"])


def test_bad_files_are_refused(db, seeded, tmp_path):
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip")
    with pytest.raises(InvalidInput):
        project_sync.receive_bundle(db, SERVER, junk)
    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as z:
        z.writestr("manifest.json", json.dumps({"format": "something-else"}))
        z.writestr("data.json", json.dumps({"tables": {}, "estimate": {}}))
    with pytest.raises(InvalidInput):
        project_sync.receive_bundle(db, SERVER, other)
    assert _one(db, "SELECT COUNT(*) FROM estimates WHERE company_id = 'acme'")[0] == 0


def test_office_network_inbox(db, seeded, tmp_path, monkeypatch):
    share = tmp_path / "server_share" / "exchange"
    share.mkdir(parents=True)
    monkeypatch.setenv("ESTIMATOR_EXCHANGE_DIR", str(share))
    sent = project_sync.send_to_share(db, PC, seeded["estimate_id"], str(share))
    assert sent["via"] == "network" and Path(sent["path"]).is_file()
    assert Path(sent["path"]).parent == share / "projects" / "inbox"
    got = project_sync.take_in_inbox(db, SERVER)
    assert len(got) == 1 and got[0]["ok"] and got[0]["mode"] == "new"
    assert not list((share / "projects" / "inbox").glob("*.zip"))
    assert list((share / "projects" / "done").glob("*.zip"))
    with pytest.raises(InvalidInput):
        project_sync.send_to_share(db, PC, seeded["estimate_id"], str(tmp_path / "Z_not_mapped"))


def test_picking_the_servers_estimator_folder_finds_its_exchange(tmp_path):
    root = tmp_path / "Estimator"
    (root / "exchange").mkdir(parents=True)
    assert project_sync.inbox_dir(root) == root / "exchange" / "projects" / "inbox"


def test_server_address_rules():
    assert project_sync.server_base("acme.example.com/jobs/") == "https://acme.example.com"
    assert project_sync.server_base("https://acme.example.com/estimator") == "https://acme.example.com"
    with pytest.raises(InvalidInput):
        project_sync.server_base("http://acme.example.com")         # a password must not go over plain http
    with pytest.raises(InvalidInput):
        project_sync.server_base("")


def test_this_pcs_own_address_is_refused(tmp_path, monkeypatch):
    (tmp_path / ".ai-prowler").mkdir()
    (tmp_path / ".ai-prowler" / "config.json").write_text('{"tunnel_domain": "ap-me-123.ai-prowler.com"}',
                                                           encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    with pytest.raises(InvalidInput, match="THIS PC's own"):
        project_sync.server_base("https://ap-me-123.ai-prowler.com/jobs/")
    assert project_sync.server_base("ap-server-9.ai-prowler.com") == "https://ap-server-9.ai-prowler.com"


def test_requests_name_themselves_for_cloudflare(monkeypatch):
    """Cloudflare answers Python's default user agent with 403 error 1010 (seen 2026-11-13)."""
    import io
    import urllib.error
    import urllib.request
    seen = []

    def fake_open(req, timeout=60):
        seen.append(req.get_header("User-agent"))
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"error code: 1010\n"))
    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    status, body = project_sync._http("https://x.example.com/estimator-api/health", method="GET")
    assert seen == [project_sync.USER_AGENT] and "python" not in seen[0].lower()
    assert status == 403 and "error code: 1010" in body["message"]


def test_settings_keep_no_password(estimator_sandbox):
    project_sync.save_settings("https://acme.example.com", "dana", r"Z:\AI-Prowler\Estimator\exchange")
    s = project_sync.load_settings()
    assert s == {"server_url": "https://acme.example.com", "username": "dana",
                 "share_path": r"Z:\AI-Prowler\Estimator\exchange"}
    assert "password" not in project_sync.settings_path().read_text(encoding="utf-8")
