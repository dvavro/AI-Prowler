"""Multi-trade auto-run strategies (Phase 2): per-trade sheet picking, results dispatch, and the runner's dispatch.

The electrical reader (estimator/takeoff/llm_electrical.py) and the plumbing reader
(estimator/takeoff/llm_plumbing.py, the first quantity trade) are used as they are - the runner tests fake
their readers the way the concrete ones fake llm_takeoff, so no test calls a real LLM.
"""
import json

import pytest

from estimator import config
from estimator.agents import llm_takeoff_runner as runner
from estimator.api import autorun_api
from estimator.api.router import _Refuse
from estimator.context import personal_context
from estimator.estimating import service
from estimator.takeoff import llm_takeoff as lt

CTX = personal_context()
NOW = "2026-11-12T10:00:00+00:00"


@pytest.fixture
def plans(db, tmp_path):
    """An estimate with one plan set: S-1 FOUNDATION PLAN, E-1 ELECTRICAL PLAN, A-101 FLOOR PLAN - all with images."""
    est = service.create_estimate(db, CTX, "House")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img = tmp_path / "s.png"
    img.write_bytes(b"png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'S-1', 'FOUNDATION PLAN', ?)", (ps, str(img))).lastrowid
    e1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'E-1', 'ELECTRICAL PLAN', ?)", (ps, str(img))).lastrowid
    a1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 3, 'A-101', 'FLOOR PLAN', ?)", (ps, str(img))).lastrowid
    vp_s = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                      " VALUES ('default', ?, 'Foundation plan', '84.3225', 0)", (s1,)).lastrowid
    vp_e = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                      " VALUES ('default', ?, 'Electrical plan', '48', 0)", (e1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "e1": e1, "a1": a1, "vp_s": vp_s, "vp_e": vp_e}


def _measurement(db, est, sheet, vp, **kw):
    vals = {"module_id": "concrete", "kind": "area", "qty": "2123.42", "unit": "sqft",
            "proposed_by": "llm-takeoff", "status": "proposed", "calc": None, "label": "Slab (AI)"}
    vals.update(kw)
    return db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, sheet_id, viewport_id, kind, label,"
        " qty, unit, source_object_ids, calc_json, method, status, proposed_by, created_at, updated_at)"
        " VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, 'ai', ?, ?, ?, ?)",
        (est, vals["module_id"], sheet, vp, vals["kind"], vals["label"], vals["qty"], vals["unit"],
         json.dumps(vals["calc"]) if vals["calc"] is not None else None,
         vals["status"], vals["proposed_by"], NOW, NOW)).lastrowid


# ------------------------------------------------------------------ the registry

ALL_TRADES = ["concrete", "demolition", "drywall", "electrical", "fencing", "flooring", "framing",
              "hvac", "insulation", "landscaping", "painting", "plumbing", "roofing", "siding",
              "windows_doors"]
QUANTITY_TRADES = [t for t in ALL_TRADES if t not in ("concrete", "electrical")]


def test_strategies_list_all_fifteen_trades():                                              # AS-01
    assert sorted(autorun_api.STRATEGIES) == ALL_TRADES
    concrete, electrical = autorun_api.STRATEGIES["concrete"], autorun_api.STRATEGIES["electrical"]
    assert concrete["label"] == "Concrete" and electrical["label"] == "Electrical"
    assert concrete["geometric"] is True and electrical["geometric"] is False  # electrical is LLM-only
    assert electrical["find_candidates"](None, "default", 1) == {"candidates": []}
    assert "count the devices" in electrical["llm_off"]
    for mid in QUANTITY_TRADES:          # every quantity trade: the full entry, LLM-only, named in its refusal
        s = autorun_api.STRATEGIES[mid]
        for key in ("label", "sheet_phrase", "pick_sheet", "pick_viewport", "find_candidates",
                    "results", "geometric", "llm_off"):
            assert key in s, f"{mid} is missing {key}"
        assert s["geometric"] is False
        assert s["find_candidates"](None, "default", 1) == {"candidates": []}
        assert "turn LLM takeoff on" in s["llm_off"]


def test_trade_label_uses_the_manifest_name_or_the_id():                                    # AS-02
    assert autorun_api._trade_label("plumbing") == "Plumbing"
    assert autorun_api._trade_label("hvac") == "HVAC"
    assert autorun_api._trade_label("warp-drive") == "warp-drive"


# ------------------------------------------------------------------ picking the sheet

def test_pick_foundation_sheets_scores_each_trades_rules(db, plans):                        # AS-03
    ranked = lt.pick_foundation_sheets(db, "default", plans["ps"])
    assert [s["id"] for s in ranked] == [plans["s1"], plans["a1"], plans["e1"]]  # concrete default: S-1 first
    assert ranked[0]["score"] == 3 and ranked[1]["score"] == 1 and ranked[2]["score"] == 0
    ranked = lt.pick_foundation_sheets(db, "default", plans["ps"], module_id="electrical")
    assert [s["id"] for s in ranked] == [plans["e1"], plans["s1"], plans["a1"]]  # E-1 first (title 2 + prefix 1)
    assert ranked[0]["score"] == 3 and ranked[1]["score"] == 0 and ranked[2]["score"] == 0


def test_pick_run_sheet_per_trade(db, plans):                                               # AS-04
    assert autorun_api.pick_run_sheet(db, CTX, plans["est"], "concrete") == plans["s1"]
    assert autorun_api.pick_run_sheet(db, CTX, plans["est"], "electrical") == plans["e1"]


def test_pick_run_sheet_all_off_names_the_trade(db, plans):                                 # AS-05
    from estimator.takeoff import sheet_trades
    for s in (plans["s1"], plans["e1"], plans["a1"]):
        sheet_trades.set_active(db, CTX, s, "electrical", False)
    with pytest.raises(_Refuse, match="every sheet is switched off for Electrical"):
        autorun_api.pick_run_sheet(db, CTX, plans["est"], "electrical")
    with pytest.raises(_Refuse, match="switch the electrical sheet on"):
        autorun_api.pick_run_sheet(db, CTX, plans["est"], "electrical")
    # Concrete is untouched: its sheets are still on.
    assert autorun_api.pick_run_sheet(db, CTX, plans["est"], "concrete") == plans["s1"]


# ------------------------------------------------------------------ results dispatch

def test_run_results_concrete_shape_unchanged(db, plans):                                   # AS-06
    run = autorun_api.create_run(db, CTX, plans["est"], plans["s1"], plans["vp_s"], "concrete", [])
    calc = {"source": "llm", "auto_run_id": run, "candidate_id": "llm", "footer_size": "12x20"}
    a = _measurement(db, plans["est"], plans["s1"], plans["vp_s"], qty="2123.42", calc=calc)
    db.execute("UPDATE measurements SET feeds = 'area_sqft' WHERE id = ?", (a,))
    f = _measurement(db, plans["est"], plans["s1"], plans["vp_s"], kind="length", label="Footer (AI)",
                     qty="184.33", unit="lf", calc=calc)
    db.execute("UPDATE measurements SET feeds = 'footing_lf' WHERE id = ?", (f,))
    autorun_api.update_run(db, run, status="done", step="done", measurement_ids=[a, f])
    res = autorun_api.run_results(db, CTX, autorun_api._load_run(db, CTX, run))
    assert [x["label"] for x in res["lines"]] == ["Slab (AI)", "Footer (AI)"]
    assert res["concrete"]["total_cuyd"] == "35.13" and res["concrete"]["slab_cuyd"] == "26.22"


def test_run_results_electrical_shape_from_the_reader(db, plans):                           # AS-07
    counts = {"outlets": 12, "switches": 4, "gfci": 0, "lights": 6, "fans": 1,
              "circuits_15a": 1, "appliance_circuits": 1, "low_voltage": 0}
    cand = {"id": "llm", "source": "llm", "counts": counts,
            "evidence": {"outlets": "12 duplex receptacles", "gfci": "none seen"},
            "confidence": 0.9, "notes": "clear plan", "sheet_id": plans["e1"],
            "provider": "claude_api", "model": "claude-sonnet-5-5"}
    run = autorun_api.create_run(db, CTX, plans["est"], plans["e1"], plans["vp_e"], "electrical", [cand])
    calc = {"source": "llm", "auto_run_id": run, "candidate_id": "llm",
            "how": "12 duplex receptacles", "qty": "12"}
    o = _measurement(db, plans["est"], plans["e1"], plans["vp_e"], module_id="electrical", kind="count",
                     label="Outlets (AI)", qty="12", unit="ea", calc=calc)
    db.execute("UPDATE measurements SET feeds = 'outlets' WHERE id = ?", (o,))
    autorun_api.update_run(db, run, status="done", step="done", measurement_ids=[o])
    res = autorun_api.run_results(db, CTX, autorun_api._load_run(db, CTX, run))
    assert [x["label"] for x in res["lines"]] == ["Outlets (AI)"]
    got = {c["feeds"]: c for c in res["electrical"]["counts"]}
    assert len(got) == 8 and got["outlets"]["qty"] == 12 and got["gfci"]["qty"] == 0
    assert got["outlets"]["evidence"] == "12 duplex receptacles"
    assert res["electrical"]["sheet_id"] == plans["e1"] and res["electrical"]["confidence"] == 0.9


def test_run_results_unknown_module_returns_none(db, plans):                                # AS-08
    run = autorun_api.create_run(db, CTX, plans["est"], plans["s1"], plans["vp_s"], "warp-drive", [])
    mid = _measurement(db, plans["est"], plans["s1"], plans["vp_s"], module_id="warp-drive")
    autorun_api.update_run(db, run, status="done", step="done", measurement_ids=[mid])
    assert autorun_api.run_results(db, CTX, autorun_api._load_run(db, CTX, run)) is None


# ------------------------------------------------------------------ the runner's dispatch

def _canned_run(db, plans, module_id):
    rid = autorun_api.create_run(db, CTX, plans["est"], plans["s1"], plans["vp_s"], module_id, [])
    db.commit()                       # the runner reads the row through its own connection
    return rid


def test_runner_dispatches_concrete_to_the_concrete_reader(db, plans, monkeypatch, capsys):  # AS-09
    rid = _canned_run(db, plans, "concrete")
    seen = {}

    def fake_read(conn, ctx, run, on_step=None):
        seen["run"] = run["id"]
        return {"candidate": {"id": "llm", "source": "llm", "label": "45'-7\" x 46'-7\" (read by the AI)"},
                "measurement_ids": [11, 12],
                "summary": f"read 45'-7\" x 46'-7\" on sheet {run['sheet_id']}; measurements [11, 12]"}

    monkeypatch.setattr(lt, "run_llm_takeoff", fake_read)
    assert runner.LlmTakeoffRun(db_path=str(config.db_path()), run_id=rid).run() == 0
    assert seen["run"] == rid
    row = db.execute("SELECT status, candidate_id, measurement_ids_json FROM auto_runs WHERE id = ?",
                     (rid,)).fetchone()
    assert row["status"] == "done" and row["candidate_id"] == "llm"
    assert json.loads(row["measurement_ids_json"]) == [11, 12]
    assert (f"done: read 45'-7\" x 46'-7\" on sheet {plans['s1']}; measurements [11, 12]"
            in capsys.readouterr().out)


def test_runner_dispatches_electrical_to_the_electrical_reader(db, plans, monkeypatch, capsys):  # AS-10
    from estimator.takeoff import llm_electrical
    rid = _canned_run(db, plans, "electrical")

    def fake_read(conn, ctx, run, on_step=None):
        return {"candidate": {"id": "llm", "source": "llm", "counts": {"outlets": 12}},
                "measurement_ids": [21],
                "summary": f"counted 12 devices on sheet {run['sheet_id']} (12 outlets); measurements 21"}

    monkeypatch.setattr(llm_electrical, "run_llm_electrical", fake_read)
    assert runner.LlmTakeoffRun(db_path=str(config.db_path()), run_id=rid).run() == 0
    row = db.execute("SELECT status, candidate_id, measurement_ids_json FROM auto_runs WHERE id = ?",
                     (rid,)).fetchone()
    assert row["status"] == "done" and row["candidate_id"] == "llm"
    assert json.loads(row["measurement_ids_json"]) == [21]
    assert (f"done: counted 12 devices on sheet {plans['s1']} (12 outlets); measurements 21"
            in capsys.readouterr().out)


def test_runner_refuses_an_unknown_trade(db, plans):                                        # AS-11
    rid = _canned_run(db, plans, "warp-drive")
    assert runner.LlmTakeoffRun(db_path=str(config.db_path()), run_id=rid).run() == 1
    row = db.execute("SELECT status, error FROM auto_runs WHERE id = ?", (rid,)).fetchone()
    assert row["status"] == "failed" and row["error"] == "auto-run isn't built for warp-drive yet"


# ------------------------------------------------------------------ the quantity trades (Phase 2)

@pytest.fixture
def plans13(db, tmp_path):
    """An estimate with one plan set: one sheet per discipline, all with images -
    S-1 FOUNDATION, E-1 ELECTRICAL, A-101 FLOOR PLAN, P-1 PLUMBING, M-1 MECHANICAL,
    A-201 ROOF PLAN, A-301 ELEVATIONS, C-1 SITE PLAN, L-1 LANDSCAPE, D-1 DEMOLITION."""
    est = service.create_estimate(db, CTX, "House")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img = tmp_path / "s.png"
    img.write_bytes(b"png")
    sheets = {}
    for page, (no, title) in enumerate([
            ("S-1", "FOUNDATION PLAN"), ("E-1", "ELECTRICAL PLAN"), ("A-101", "FLOOR PLAN"),
            ("P-1", "PLUMBING PLAN"), ("M-1", "MECHANICAL PLAN"), ("A-201", "ROOF PLAN"),
            ("A-301", "ELEVATIONS"), ("C-1", "SITE PLAN"), ("L-1", "LANDSCAPE PLAN"),
            ("D-1", "DEMOLITION PLAN")], start=1):
        sheets[no] = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                                " VALUES ('default', ?, ?, ?, ?, ?)",
                                (ps, page, no, title, str(img))).lastrowid
    vps = {}
    for no in ("P-1", "M-1", "A-201", "C-1"):
        vps[no] = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                             " VALUES ('default', ?, ?, '48', 0)", (sheets[no], no)).lastrowid
    return {"est": est, "ps": ps, "sheets": sheets, "vps": vps}


def test_pick_foundation_sheets_scores_each_quantity_trades_rules(db, plans13):            # AS-12
    """Each quantity trade's sheet rules pick its own sheet first (titles 2, prefix 1)."""
    first = {"plumbing": "P-1", "hvac": "M-1", "flooring": "A-101", "roofing": "A-201",
             "framing": "A-101", "windows_doors": "A-301", "insulation": "A-101",
             "demolition": "D-1", "drywall": "A-101", "siding": "A-301", "fencing": "C-1",
             "landscaping": "L-1", "painting": "A-301"}
    for mid, no in first.items():
        ranked = lt.pick_foundation_sheets(db, "default", plans13["ps"], module_id=mid)
        assert ranked[0]["id"] == plans13["sheets"][no], mid
    # Insulation has no title match in this set, so the first A-sheet wins on page order.
    ranked = lt.pick_foundation_sheets(db, "default", plans13["ps"], module_id="insulation")
    assert ranked[0]["score"] == 1


def test_pick_run_sheet_per_quantity_trade(db, plans13):                                    # AS-13
    for mid, no in (("plumbing", "P-1"), ("hvac", "M-1"), ("roofing", "A-201"), ("fencing", "C-1")):
        assert autorun_api.pick_run_sheet(db, CTX, plans13["est"], mid) == plans13["sheets"][no]


def test_run_results_quantity_shape_from_the_reader(db, plans13):                           # AS-14
    """A quantity run's results come through the trade's reader: the generic quantities
    block, all seven plumbing questions including the zeros."""
    values = {"toilets": 2, "sinks": 3, "kitchen_sinks": 1, "showers": 2,
              "dishwashers": 1, "washers": 1, "hose_bibs": 0}
    cand = {"id": "llm", "source": "llm", "values": values,
            "evidence": {"toilets": "2 water closets", "hose_bibs": "none seen"},
            "confidence": 0.9, "notes": "clear plan", "sheet_id": plans13["sheets"]["P-1"],
            "provider": "claude_api", "model": "claude-sonnet-5-5"}
    run = autorun_api.create_run(db, CTX, plans13["est"], plans13["sheets"]["P-1"],
                                 plans13["vps"]["P-1"], "plumbing", [cand])
    calc = {"source": "llm", "auto_run_id": run, "candidate_id": "llm",
            "how": "2 water closets", "qty": "2"}
    o = _measurement(db, plans13["est"], plans13["sheets"]["P-1"], plans13["vps"]["P-1"],
                     module_id="plumbing", kind="count", label="Toilets (AI)", qty="2", unit="ea", calc=calc)
    db.execute("UPDATE measurements SET feeds = 'toilets' WHERE id = ?", (o,))
    autorun_api.update_run(db, run, status="done", step="done", measurement_ids=[o])
    res = autorun_api.run_results(db, CTX, autorun_api._load_run(db, CTX, run))
    assert [x["label"] for x in res["lines"]] == ["Toilets (AI)"]
    assert res["quantities"]["trade"] == "plumbing" and res["quantities"]["label"] == "Plumbing"
    got = {c["feeds"]: c for c in res["quantities"]["items"]}
    assert len(got) == 7 and got["toilets"]["qty"] == 2 and got["hose_bibs"]["qty"] == 0
    assert got["toilets"]["evidence"] == "2 water closets"
    assert got["hose_bibs"]["evidence"] == "none seen"          # zero: the candidate's evidence
    assert res["quantities"]["sheet_id"] == plans13["sheets"]["P-1"]
    assert res["quantities"]["confidence"] == 0.9


def test_runner_dispatches_a_quantity_trade_to_its_reader(db, plans, monkeypatch, capsys):  # AS-15
    from estimator.takeoff import llm_plumbing
    rid = _canned_run(db, plans, "plumbing")

    def fake_read(conn, ctx, run, on_step=None):
        return {"candidate": {"id": "llm", "source": "llm", "values": {"toilets": 2}},
                "measurement_ids": [31],
                "summary": f"read the Plumbing quantities on sheet {run['sheet_id']} (2 toilets); measurements [31]"}

    monkeypatch.setattr(llm_plumbing, "run_llm_plumbing", fake_read)
    assert runner.LlmTakeoffRun(db_path=str(config.db_path()), run_id=rid).run() == 0
    row = db.execute("SELECT status, candidate_id, measurement_ids_json FROM auto_runs WHERE id = ?",
                     (rid,)).fetchone()
    assert row["status"] == "done" and row["candidate_id"] == "llm"
    assert json.loads(row["measurement_ids_json"]) == [31]
    assert (f"done: read the Plumbing quantities on sheet {plans['s1']} (2 toilets); measurements [31]"
            in capsys.readouterr().out)
