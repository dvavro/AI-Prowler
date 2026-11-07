"""Sprint 19 (Coder 1, without the Plan Engine): moving a company's Estimator data to AI-Prowler Server or another PC
(est_data_export / est_data_import) (S19-..)."""
import json
import zipfile
from contextlib import closing

import pytest

from estimator import data_move, practice
from estimator.bids import service as bids
from estimator.context import RequestContext, personal_context
from estimator.database import open_database
from estimator.director import engine
from estimator.errors import ConfirmationRequired, InvalidInput, PermissionDenied
from estimator.estimating import quick, service, setup
from estimator.learning import history
from estimator.mcp_tools import est_tools as t
from estimator.modules.registry import ModuleRegistry
from estimator.pricing.price_book import get_price, set_price

CTX = personal_context()
REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
ACME = RequestContext(company_id="acme", user_id="jamie", role="owner", mode="server")


def _personal_company(db):
    """A small but complete Personal-mode company: profile, prices, a won roof with a quote and job costs, a revision,
    a Director job, and a practice project."""
    setup.setup_step(db, CTX, "company_profile", {"name": "Vavro Roofing", "phone": "480-555-0100"})
    service.save_markups(db, CTX, overhead_pct="0.10", profit_pct="0.15")
    set_price(db, "default", "rf_arch_sq", description="Architectural shingles", kind="material", unit="sq",
              cost_cents=13150, effective_date="2026-11-01")
    e = service.create_estimate(db, CTX, "Garcia roof")
    e = quick.answer(db, CTX, e["id"], "roofing", ROOF, e["rev"], REG)
    e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
    b = bids.generate(db, CTX, e["id"], customer={"name": "Garcia"}, registry=REG)
    shingles = next(ln for s in service.get_estimate(db, CTX, e["id"])["sections"] for ln in s["lines"]
                    if ln["price_key"] == "rf_arch_sq")
    history.record_actuals(db, CTX, e["id"], [{"line_id": shingles["id"], "cost": "3300"}, {"total": "9000"}])
    rev = service.create_revision(db, CTX, e["id"], "customer added gutters")
    engine.start(db, CTX, "pressure wash the driveway 900 sq ft", registry=REG)
    practice.create(db, CTX, REG)
    return {"estimate": e, "bid": b, "revision": rev}


def _fresh(monkeypatch, tmp_path, name="server"):
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(tmp_path / name))
    return closing(open_database())


def test_export_bundle(db):  # S19-D01
    made = _personal_company(db)
    out = data_move.export_data(db, CTX)
    z = zipfile.ZipFile(out["path"])
    manifest = json.loads(z.read("manifest.json"))
    assert manifest["format"] == "ai-prowler-estimator-data" and manifest["company_name"] == "Vavro Roofing"
    assert manifest["schema_version"] >= 10 and manifest["include_practice"] is False
    c = out["counts"]
    assert c["estimates"] == 3 and c["bids"] == 1 and c["estimate_actuals"] == 2 and c["director_jobs"] == 1
    assert c["price_book"] >= 1 and c["company_profile"] == 1
    assert out["bid_files"] >= 1 and any(n.startswith(f"files/{made['bid']['id']}/") for n in z.namelist())
    with_practice = data_move.export_data(db, CTX, include_practice=True)
    assert with_practice["counts"]["estimates"] == 4


def test_move_to_a_server_company(db, monkeypatch, tmp_path):  # S19-D02
    made = _personal_company(db)
    src_est = service.get_estimate(db, CTX, made["estimate"]["id"])
    path = data_move.export_data(db, CTX)["path"]
    with _fresh(monkeypatch, tmp_path) as srv:
        with pytest.raises(ConfirmationRequired) as ask:
            data_move.import_data(srv, ACME, path)
        assert ask.value.details["counts"]["estimates"] == 3 and "replaced" in ask.value.details["settings"]
        out = data_move.import_data(srv, ACME, path, confirm=True)
        assert out["imported"]["estimates"] == 3 and out["bid_files"] >= 1
        new_id = out["estimate_numbers"][str(src_est["id"])]
        moved = service.get_estimate(srv, ACME, new_id)
        assert moved["title"] == "Garcia roof" and moved["status"] == "approved"
        assert moved["totals"]["total_cents"] == src_est["totals"]["total_cents"]
        assert [ln["description"] for s in moved["sections"] for ln in s["lines"]] == \
               [ln["description"] for s in src_est["sections"] for ln in s["lines"]]
        rev_new = out["estimate_numbers"][str(made["revision"]["id"])]
        assert service.get_estimate(srv, ACME, rev_new)["parent_estimate_id"] == new_id        # revision chain kept
        row = srv.execute("SELECT * FROM bids WHERE company_id = 'acme'").fetchone()
        assert row["number"] == made["bid"]["number"] and row["estimate_id"] == new_id           # quote number kept
        assert row["html_path"] and str(tmp_path / "server") in row["html_path"]
        assert open(row["html_path"], encoding="utf-8").read().count("Garcia") >= 1
        acts = history.job_actuals(srv, ACME, new_id)
        assert acts["job"]["actual_cost"] == "$9,000.00"
        line = srv.execute("SELECT line_item_id FROM estimate_actuals WHERE company_id = 'acme' AND line_item_id IS NOT NULL"
                           ).fetchone()[0]
        assert srv.execute("SELECT s.estimate_id FROM line_items l JOIN trade_sections s ON s.id = l.trade_section_id"
                           " WHERE l.id = ?", (line,)).fetchone()[0] == new_id                  # costs point at the new line
        assert get_price(srv, "acme", "rf_arch_sq").cost_cents == 13150
        prof = srv.execute("SELECT name FROM company_profile WHERE company_id = 'acme'").fetchone()
        assert prof["name"] == "Vavro Roofing"
        assert srv.execute("SELECT COUNT(*) FROM director_jobs WHERE company_id = 'acme'").fetchone()[0] == 1
        assert srv.execute("SELECT COUNT(*) FROM estimates WHERE is_practice = 1").fetchone()[0] == 0
        assert srv.execute("SELECT COUNT(*) FROM estimates WHERE company_id = 'default'").fetchone()[0] == 0


def test_import_into_a_busy_company_keeps_its_settings(db, monkeypatch, tmp_path):  # S19-D03
    _personal_company(db)
    path = data_move.export_data(db, CTX)["path"]
    with _fresh(monkeypatch, tmp_path) as srv:
        setup.setup_step(srv, ACME, "company_profile", {"name": "Acme Builders"})
        set_price(srv, "acme", "rf_arch_sq", description="Shingles", kind="material", unit="sq", cost_cents=12000,
                  effective_date="2026-11-01")
        e = service.create_estimate(srv, ACME, "Acme's own job")
        with pytest.raises(ConfirmationRequired) as ask:
            data_move.import_data(srv, ACME, path)
        assert ask.value.details["your_estimates_now"] == 1 and ask.value.details["settings"].startswith("kept")
        data_move.import_data(srv, ACME, path, confirm=True)
        assert srv.execute("SELECT name FROM company_profile WHERE company_id = 'acme'").fetchone()[0] == "Acme Builders"
        assert get_price(srv, "acme", "rf_arch_sq").cost_cents == 12000                 # theirs stays
        assert service.get_estimate(srv, ACME, e["id"])["title"] == "Acme's own job"
        assert service.list_estimates(srv, ACME)["count"] == 4


def test_import_safety(db, monkeypatch, tmp_path):  # S19-D04
    _personal_company(db)
    path = data_move.export_data(db, CTX)["path"]
    with pytest.raises(PermissionDenied):
        data_move.export_data(db, RequestContext(user_id="maria", role="estimator"))
    with _fresh(monkeypatch, tmp_path) as srv:
        with pytest.raises(PermissionDenied):
            data_move.import_data(srv, RequestContext(company_id="acme", user_id="olga", role="office"), path)
        with pytest.raises(InvalidInput, match="zip"):
            data_move.import_data(srv, ACME, str(tmp_path / "nope.zip"))
        newer = tmp_path / "newer.zip"
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(newer, "w") as dst:
            m = json.loads(src.read("manifest.json"))
            m["schema_version"] = 999
            dst.writestr("manifest.json", json.dumps(m))
            dst.writestr("data.json", src.read("data.json"))
        with pytest.raises(InvalidInput, match="newer Estimator"):
            data_move.import_data(srv, ACME, str(newer), confirm=True)
        odd = tmp_path / "odd.zip"
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(odd, "w") as dst:
            dst.writestr("manifest.json", src.read("manifest.json"))
            d = json.loads(src.read("data.json"))
            d["tables"]["users"] = [{"id": 1}]
            dst.writestr("data.json", json.dumps(d))
        with pytest.raises(InvalidInput, match="doesn't know"):
            data_move.import_data(srv, ACME, str(odd), confirm=True)
        evil = tmp_path / "evil.zip"
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(evil, "w") as dst:
            for n in src.namelist():
                dst.writestr(n, src.read(n))
            dst.writestr("../../outside.html", "<h1>nope</h1>")
        data_move.import_data(srv, ACME, str(evil), confirm=True)
        assert not (tmp_path / "outside.html").exists()                                 # never written outside
        assert srv.execute("SELECT COUNT(*) FROM estimates").fetchone()[0] == 3
        junk = tmp_path / "junk.zip"
        with zipfile.ZipFile(junk, "w") as dst:
            dst.writestr("hello.txt", "hi")
        with pytest.raises(InvalidInput, match="isn't an Estimator data file"):
            data_move.import_data(srv, ACME, str(junk))


def test_a_failed_import_changes_nothing(db, monkeypatch, tmp_path):  # S19-D05
    _personal_company(db)
    path = data_move.export_data(db, CTX)["path"]
    broken = tmp_path / "broken.zip"
    with zipfile.ZipFile(path) as src, zipfile.ZipFile(broken, "w") as dst:
        dst.writestr("manifest.json", src.read("manifest.json"))
        d = json.loads(src.read("data.json"))
        d["tables"]["line_items"][0]["trade_section_id"] = 99999                        # points nowhere
        dst.writestr("data.json", json.dumps(d))
    with _fresh(monkeypatch, tmp_path) as srv:
        with pytest.raises(InvalidInput, match="inconsistent"):
            data_move.import_data(srv, ACME, str(broken), confirm=True)
        assert srv.execute("SELECT COUNT(*) FROM estimates").fetchone()[0] == 0
        assert srv.execute("SELECT COUNT(*) FROM price_book WHERE company_id = 'acme'").fetchone()[0] == 0


def test_tools(db, monkeypatch, tmp_path):  # S19-T01
    _personal_company(db)
    r = json.loads(t.est_data_export())
    assert r["ok"] and r["file"].endswith(".zip")
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(tmp_path / "pc2"))
    ask = json.loads(t.est_data_import(r["path"]))
    assert ask["error"] == "needs_confirmation"
    done = json.loads(t.est_data_import(r["path"], confirm=True))
    assert done["imported"]["estimates"] == 3


def test_tab_buttons_logic(db, monkeypatch, tmp_path):  # S19-U01
    from estimator.ui import model
    _personal_company(db)
    ok, msg = model.data_export()
    assert ok and "Packed 3 estimate(s) and 1 quote(s)" in msg
    path = msg.split(" into ")[1].split(". Copy")[0]
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(tmp_path / "pc2"))
    ok, preview = model.data_import_preview(path)
    assert ok and "From Vavro Roofing" in preview and "3 estimate(s)" in preview and "replaced" in preview
    ok, msg = model.data_import(path)
    assert ok and "Loaded 3 estimate(s)" in msg
    ok, msg = model.data_import_preview(str(tmp_path / "missing.zip"))
    assert not ok and "zip" in msg
