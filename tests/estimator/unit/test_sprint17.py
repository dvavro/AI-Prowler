"""Sprint 17 (Coder 1 part of planned Sprint 17, the parts that don't need the Plan Engine): the actual-vs-estimate
learning loop, price book import with column mapping, and estimate export (S17-..)."""
import csv
import json

import pytest

from estimator import exports
from estimator.context import RequestContext, personal_context
from estimator.errors import ConfirmationRequired, InvalidInput, NotFound, PermissionDenied
from estimator.estimating import quick, service
from estimator.learning import history
from estimator.mcp_tools import est_tools as t
from estimator.modules.registry import ModuleRegistry
from estimator.pricing import importer
from estimator.pricing.price_book import get_price

CTX = personal_context()
REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
FIELD = RequestContext(user_id="fred", role="field")
REVIEWER = RequestContext(user_id="rita", role="reviewer")


def _roof(db, status="won", answers=ROOF):
    e = service.create_estimate(db, CTX, "roof")
    e = quick.answer(db, CTX, e["id"], "roofing", answers, e["rev"], REG)
    if status != "draft":
        e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
        if status != "approved":
            e = service.set_status(db, CTX, e["id"], e["rev"], status)
    return service.get_estimate(db, CTX, e["id"])


def _line(est, key):
    return next(ln for s in est["sections"] for ln in s["lines"] if ln["price_key"] == key)


# ---------------------------------------------------------------- actuals

def test_record_actuals_every_way(db):  # S17-A01
    est = _roof(db)
    shingles = _line(est, "rf_arch_sq")                         # 21.66 sq, $125, 10% waste: cost $2,978.25
    out = history.record_actuals(db, CTX, est["id"], [
        {"line_id": shingles["id"], "cost": "3,300.00", "quantity": "24"},
        {"price_key": "rf_permit_ea", "cost": "$350"},
        {"kind": "labor", "cost": "3500", "hours": "48"},
        {"total": "8600"}], note="Garcia roof")
    assert out["recorded"] == 4
    a = {x["description"]: x for x in out["actuals"]}
    assert a[shingles["description"]]["estimated"] == "$2,978.25" and a[shingles["description"]]["over_by_pct"] == "10.8%"
    assert a["All labor"]["estimated"] == "$3,032.40" and a["All labor"]["hours"] == "48"
    assert out["job"]["estimated_cost"] == "$7,817.10" and out["job"]["actual_cost"] == "$8,600.00"
    assert out["job"]["over_by_pct"] == "10.0%"
    row = db.execute("SELECT * FROM estimate_actuals WHERE price_key = 'rf_arch_sq'").fetchone()
    assert row["est_quantity"] == "23.826" and row["note"] == "Garcia roof"      # 21.66 sq + 10% waste, as bought
    assert service.get_estimate(db, CTX, est["id"])["rev"] == est["rev"]            # the estimate itself is untouched


def test_record_actuals_replace_and_margin(db):  # S17-A02
    service.save_markups(db, CTX, overhead_pct="0.10", profit_pct="0.15")
    est = _roof(db, "draft")
    est = service.get_estimate(db, CTX, service.calculate(db, CTX, est["id"], est["rev"])["id"])
    est = service.set_status(db, CTX, est["id"], est["rev"], "approved")
    history.record_actuals(db, CTX, est["id"], [{"total": "9000"}])
    out = history.record_actuals(db, CTX, est["id"], [{"total": "7000"}], replace=True)
    assert len(out["actuals"]) == 1 and out["job"]["actual_cost"] == "$7,000.00"
    assert out["job"]["estimated_margin"] == "21.0%" and out["job"]["real_margin"] == "29.2%"


@pytest.mark.parametrize("items, words", [
    ([{"line_id": 9999, "cost": "1"}], "isn't on estimate"),
    ([{"cost": "1"}], "needs line_id"),
    ([{"kind": "snacks", "cost": "1"}], "kind must be"),
    ([{"total": "-5"}], "negative"),
    ([{"total": "lots"}], "dollars"),
    ([{"line_id": 1, "cost": "1", "hours": "-2"}], "negative"),
    ([], "list"),
])
def test_bad_actuals(db, items, words):  # S17-A03
    est = _roof(db)
    with pytest.raises((InvalidInput, NotFound), match=words):
        history.record_actuals(db, CTX, est["id"], items)


def test_actuals_need_a_sold_job_and_the_right_role(db):  # S17-A04
    draft = _roof(db, "draft")
    with pytest.raises(InvalidInput, match="approved, sent or won"):
        history.record_actuals(db, CTX, draft["id"], [{"total": "100"}])
    won = _roof(db)
    with pytest.raises(PermissionDenied):
        history.record_actuals(db, FIELD, won["id"], [{"total": "100"}])
    with pytest.raises(PermissionDenied):
        history.record_actuals(db, REVIEWER, won["id"], [{"total": "100"}])


# ---------------------------------------------------------------- comparing

def test_history_suggests_a_price_change(db):  # S17-H01
    for cost in ("3300", "3400"):                                 # two jobs paid about $140/sq for $125/sq shingles
        est = _roof(db)
        history.record_actuals(db, CTX, est["id"], [{"line_id": _line(est, "rf_arch_sq")["id"], "cost": cost}])
    out = history.compare_history(db, CTX)
    assert out["jobs_with_actuals"] == 2
    p = next(x for x in out["prices"] if x["price_key"] == "rf_arch_sq")
    assert p["actual_unit_cost"] == "$140.60" and p["jobs_run"].endswith("over the estimate")
    s = out["suggestions"][0]
    assert s["pricebook_update"] == {"rf_arch_sq": "140.60"} and "12.5% more" in s["message"]
    assert get_price(db, "default", "rf_arch_sq").cost_cents == 12500                 # nothing changed by itself


def test_one_job_is_not_enough_to_suggest(db):  # S17-H02
    est = _roof(db)
    history.record_actuals(db, CTX, est["id"], [{"line_id": _line(est, "rf_arch_sq")["id"], "cost": "3400"}])
    out = history.compare_history(db, CTX, price_key="rf_arch_sq")
    assert out["prices"][0]["jobs_with_actuals"] == 1 and out["suggestions"] == []


def test_estimate_lines_against_history(db):  # S17-H03
    for _ in range(3):
        _roof(db, "sent")
    big = _roof(db, "draft", {**ROOF, "material": "architectural"})
    shingles = _line(big, "rf_arch_sq")
    db.execute("UPDATE line_items SET unit_cost_cents = 20000 WHERE id = ?", (shingles["id"],))   # $200/sq this time
    out = history.compare_history(db, CTX, estimate_id=big["id"])
    row = next(r for r in out["lines"] if r["price_key"] == "rf_arch_sq")
    assert row["flag"] == "higher_than_usual" and row["usual_unit_cost"] == "$125.00" and "60.0% above" in row["message"]
    assert next(r for r in out["lines"] if r["price_key"] == "rf_permit_ea")["flag"] is None
    assert out["flagged"] == 1


def test_lines_under_what_jobs_really_paid(db):  # S17-H04
    old = _roof(db)
    history.record_actuals(db, CTX, old["id"], [{"line_id": _line(old, "rf_lab_shingle_sq")["id"], "cost": "2600"}])
    new = _roof(db, "draft")
    row = next(r for r in history.compare_history(db, CTX, estimate_id=new["id"])["lines"]
               if r["price_key"] == "rf_lab_shingle_sq")
    assert row["flag"] == "under_real_cost" and row["jobs_really_paid"] == "$120.04"


def test_empty_history(db):  # S17-H05
    out = history.compare_history(db, CTX)
    assert out["jobs_with_actuals"] == 0 and "est_record_actuals" in out["note"]
    with pytest.raises(NotFound):
        history.compare_history(db, CTX, price_key="nope_key")


# ---------------------------------------------------------------- price book import

PRICE_LIST = """Item Code,Description,UOM,Unit Price,Vendor
rf_arch_sq,Architectural shingles,SQ,$131.50,ABC Supply
rf_drip_lf,Drip edge,LF,2.75,ABC Supply
,Synthetic underlayment per square,sq,27.00,ABC Supply
rf_ridge_lf,Ridge cap,box,58.00,ABC Supply
,Ice and water shield roll,roll,95.00,ABC Supply
rf_permit_ea,Permit,ea,call,ABC Supply
"""


def test_import_preview_then_save(db):  # S17-I01
    with pytest.raises(ConfirmationRequired) as ask:
        importer.import_prices(db, CTX, csv_text=PRICE_LIST)
    d = ask.value.details
    assert d["columns_used"] == {"price_key": "Item Code", "cost": "Unit Price", "description": "Description",
                                 "unit": "UOM", "supplier": "Vendor"}
    assert (d["updates"], d["new"], d["skipped"]) == (3, 0, 3)
    reasons = " | ".join(s["reason"] for s in d["skipped_rows"])
    assert "unit 'box' doesn't match" in reasons and "no matching price" in reasons and "isn't a dollar amount" in reasons
    assert get_price(db, "default", "rf_arch_sq") is None                       # nothing saved yet
    out = importer.import_prices(db, CTX, csv_text=PRICE_LIST, confirm=True, effective_date="2026-11-01")
    assert out["saved"] == 3
    p = get_price(db, "default", "rf_arch_sq")
    assert p.cost_cents == 13150 and not p.is_sample and p.effective_date == "2026-11-01"
    assert get_price(db, "default", "rf_underlay_sq").cost_cents == 2700           # matched by its description
    assert db.execute("SELECT supplier FROM price_book WHERE price_key = 'rf_drip_lf'").fetchone()[0] == "ABC Supply"
    assert db.execute("SELECT COUNT(*) FROM estimate_events WHERE action = 'prices_imported'").fetchone()[0] == 1


def test_import_adds_new_prices(db):  # S17-I02
    out = importer.import_prices(db, CTX, csv_text=PRICE_LIST, add_new=True, confirm=True)
    assert out["new"] == 1
    p = get_price(db, "default", "custom_ice_and_water_shield_roll")
    assert p.cost_cents == 9500 and p.unit == "roll" and p.kind == "material"


def test_import_with_a_mapping_and_odd_headers(db):  # S17-I03
    text = "Part;What;Net\nhc_labor_hr;House cleaning labor;48\n"
    with pytest.raises(InvalidInput, match="which column has the cost"):
        importer.import_prices(db, CTX, csv_text=text)
    out = importer.import_prices(db, CTX, csv_text=text, mapping={"price_key": "Part", "cost": "Net"}, confirm=True)
    assert out["saved"] == 1 and get_price(db, "default", "hc_labor_hr").cost_cents == 4800
    with pytest.raises(InvalidInput, match="columns are"):
        importer.import_prices(db, CTX, csv_text=text, mapping={"cost": "Price"})
    with pytest.raises(InvalidInput, match="mapping fields"):
        importer.import_prices(db, CTX, csv_text=text, mapping={"colour": "Net"})


def test_import_from_files(db, tmp_path):  # S17-I04
    f = tmp_path / "prices.csv"
    f.write_text(PRICE_LIST, encoding="utf-8")
    assert importer.import_prices(db, CTX, file_path=str(f), confirm=True)["saved"] == 3
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Roofing"
    ws.append([])                                                # a blank row before the header is fine
    ws.append(["SKU", "Price"])
    ws.append(["rf_starter_lf", 1.35])
    x = tmp_path / "prices.xlsx"
    wb.save(x)
    assert importer.import_prices(db, CTX, file_path=str(x), sheet="Roofing", confirm=True)["saved"] == 1
    assert get_price(db, "default", "rf_starter_lf").cost_cents == 135
    with pytest.raises(InvalidInput, match="no sheet"):
        importer.import_prices(db, CTX, file_path=str(x), sheet="Nope")


@pytest.mark.parametrize("kwargs, words", [
    ({}, "either file_path"),
    ({"file_path": "C:/nope/prices.csv"}, "can't find"),
    ({"file_path": "C:/Windows/notepad.exe"}, ".csv or .xlsx"),
    ({"csv_text": "Item Code,Unit Price\n", "effective_date": "11/01/2026"}, "YYYY-MM-DD"),
])
def test_import_bad_requests(db, kwargs, words):  # S17-I05
    with pytest.raises(InvalidInput, match=words):
        importer.import_prices(db, CTX, **kwargs)


def test_import_safety(db):  # S17-I06
    with pytest.raises(PermissionDenied):
        importer.import_prices(db, FIELD, csv_text=PRICE_LIST)
    dup = "Item Code,Unit Price\nrf_drip_lf,2.75\nrf_drip_lf,3.00\n"
    out = importer.import_prices(db, CTX, csv_text=dup, confirm=True)
    assert out["saved"] == 1 and "more than once" in out["skipped_rows"][0]["reason"]
    assert get_price(db, "default", "rf_drip_lf").cost_cents == 275
    same = importer.import_prices(db, CTX, csv_text="Item Code,Unit Price\nrf_drip_lf,2.75\n")
    assert same["saved"] == 0 and same["unchanged"] == 1                        # already that price: nothing to do


# ---------------------------------------------------------------- export

def test_export_one_estimate_csv(db):  # S17-E01
    est = _roof(db, "approved")
    out = exports.export(db, CTX, est["id"])
    rows = list(csv.reader(open(out["path"], encoding="utf-8-sig")))
    assert rows[0] == ["Line items"] and rows[1] == list(exports.LINE_COLUMNS)
    shingles = next(r for r in rows if r and r[-1] == "rf_arch_sq")
    assert shingles[:7] == ["roofing", "material", shingles[2], "21.66", "sq", "125.00", "10"] and shingles[7] == "2978.25"
    assert ["Total", "7817.10"] in rows and out["file"].startswith(f"estimate_{est['id']}_v1_")


def test_export_list_and_excel(db):  # S17-E02
    _roof(db, "won")
    _roof(db, "draft")
    out = exports.export(db, CTX, status="won")
    rows = list(csv.reader(open(out["path"], encoding="utf-8-sig")))
    assert rows[0] == list(exports.LIST_COLUMNS) and len(rows) == 2 and rows[1][2] == "won"
    openpyxl = pytest.importorskip("openpyxl")
    x = exports.export(db, CTX, fmt="xlsx")
    wb = openpyxl.load_workbook(x["path"])
    assert wb.sheetnames == ["Estimates"] and wb["Estimates"].max_row == 3
    with pytest.raises(InvalidInput):
        exports.export(db, CTX, fmt="pdf")


# ---------------------------------------------------------------- tools

def test_tools(db):  # S17-T01
    est = _roof(db)
    j = lambda s: json.loads(s)                                                      # noqa: E731
    r = j(t.est_record_actuals(est["id"], json.dumps([{"total": "8000"}])))
    assert r["ok"] and r["job"]["actual_cost"] == "$8,000.00"
    assert j(t.est_record_actuals(est["id"], {"total": "8100"}, replace=True))["recorded"] == 1
    assert j(t.est_compare_history())["jobs_with_actuals"] == 1
    assert j(t.est_compare_history(estimate_id=est["id"]))["this_job"]["job"]["actual_cost"] == "$8,100.00"
    r = j(t.pricebook_import(csv_text=PRICE_LIST))
    assert r["error"] == "needs_confirmation" and r["updates"] == 3
    r = j(t.pricebook_import(csv_text=PRICE_LIST, mapping='{"cost": "Unit Price"}', confirm=True))
    assert r["saved"] == 3
    r = j(t.est_export(est["id"], format="csv"))
    assert r["ok"] and r["path"].endswith(".csv")
    assert j(t.est_export(format="doc"))["error"] == "invalid_input"


def test_reviewer_agent_sees_history_flags(db):  # S17-R01
    from estimator.agents import queue
    old = _roof(db)
    history.record_actuals(db, CTX, old["id"], [{"line_id": _line(old, "rf_lab_shingle_sq")["id"], "cost": "2600"}])
    new = _roof(db, "draft")
    pack = queue.build_pack(db, CTX, {"id": 1, "role": "reviewer", "estimate_id": new["id"], "job_id": None}, REG)
    assert any("really paid $120.04" in h for h in pack["history"])
