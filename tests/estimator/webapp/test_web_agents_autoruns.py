"""The Agents page lists the 🤖 AI Auto Runs, every trade (2026-11-21, David: "Why were there no measured runs?" -
"make sure it works for all trades"). Only the Director's runs were listed; AI Auto Run's own runs are the measuring
most people do."""
import re

from estimator.api import router
from estimator.context import personal_context
from estimator.estimating import service
from estimator.modules import get_registry

API = "/estimator-api"
REVIEW = (router.WEB_DIR / "review.js").read_text(encoding="utf-8")
VERIFY = (router.WEB_DIR / "verify.js").read_text(encoding="utf-8")
NOW = "2026-11-21T15:00:00+00:00"


def _trades() -> list[str]:
    block = REVIEW[REVIEW.index("const AUTO_RUN_TRADES"):]
    return re.findall(r'"(\w+)"', block[:block.index(";")])


def _run(db, est_id, trade, status, error=None, mids="[]", done_at=NOW):
    return db.execute(
        "INSERT INTO auto_runs (company_id, estimate_id, sheet_id, viewport_id, module_id, status, step, error,"
        " measurement_ids_json, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (personal_context().company_id, est_id, 1, 1, trade, status, "reading the plan", error, mids, "owner",
         "2026-11-21T14:58:00+00:00", done_at)).lastrowid


def test_every_trades_auto_runs_are_listed(call, db):                                   # AG-01
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Auto run house")
    trades = _trades()
    assert len(trades) == 15
    ids = {}
    for i, t in enumerate(trades):
        status = ("done", "failed", "running")[i % 3]
        ids[t] = _run(db, est["id"], t, status, error="the AI didn't answer" if status == "failed" else None,
                      mids="[1, 2, 3]" if status == "done" else "[]")
    # Two AI calls on the first trade's run: $0.42 and $0.08.
    for micros in (420000, 80000):
        db.execute("INSERT INTO ai_log (company_id, created_at, provider, model, role, purpose, auto_run_id, estimate_id,"
                   " system_prompt, user_prompt, cost_micros, ok) VALUES (?,?,?,?,?,?,?,?,?,?,?,1)",
                   (ctx.company_id, NOW, "claude", "m", "llm_takeoff", "measure", ids[trades[0]], est["id"], "s", "u", micros))
    db.commit()
    r = call("GET", f"{API}/agents")
    assert r.status == 200, r.body
    autos = {a["module_id"]: a for a in r.json()["auto_runs"]}
    assert set(autos) == set(trades)                                                    # every trade, none missing
    reg = get_registry()
    for t in trades:
        a = autos[t]
        assert a["id"] == ids[t] and a["estimate_id"] == est["id"] and a["estimate_title"] == "Auto run house"
        assert a["trade"] == reg.get(t).name                                            # the trade's own name
    first = autos[trades[0]]
    assert first["status"] == "done" and first["proposed"] == 3 and first["seconds"] == 120
    assert first["ai_calls"] == 2 and first["cost_cents"] == 50.0
    failed = autos[trades[1]]
    assert failed["status"] == "failed" and failed["error"] == "the AI didn't answer" and failed["ai_calls"] == 0
    assert autos[trades[2]]["status"] == "running" and autos[trades[2]]["seconds"] is None
    newest_first = [a["id"] for a in r.json()["auto_runs"]]
    assert newest_first == sorted(newest_first, reverse=True)


def test_a_trade_no_longer_installed_still_lists(call, db):                              # AG-02
    est = service.create_estimate(db, personal_context(), "Old trade")
    _run(db, est["id"], "old_trade_x", "done")
    db.commit()
    a = next(x for x in call("GET", f"{API}/agents").json()["auto_runs"] if x["module_id"] == "old_trade_x")
    assert a["trade"] == "Old Trade X"


def test_the_guides_name_real_buttons():                                                # AG-04
    """2026-11-21 (David: "review the help and check if it's still correct with all the changes"): the guides updated
    today name the buttons as the screens say them."""
    from estimator.ui import help as guides
    js = "".join(p.read_text(encoding="utf-8") for p in router.WEB_DIR.glob("*.js"))
    wiring = guides.get_guide("run_the_wiring")
    assert wiring["screen"] == "takeoffs" and wiring["steps"] >= 6
    for label in ("Wiring options", "Save as my defaults", "Through the studs", "From below", "From the ceiling",
                  "Slab on grade", "Crawlspace", "Accept the new lengths", "Approve the cable and counts",
                  "Keep approved items on rerun", "Upper floors fed from",
                  # 2026-11-21: the drawings are shown on the screen, the DXF download in the viewer
                  "📐 Wiring schematic", "👁 View wiring drawing", "👁 View schematic", "⬇ Download DXF", "Fit"):
        assert label in js, label
        assert label in wiring["text"], label
    measure = guides.get_guide("measure_and_approve_on_the_plans")["text"]
    for label in ("AI Auto Run", "Keep approved items on rerun", "Audit & clean up", "✕ Reject"):
        assert label in js and label in measure, label
    replace = guides.get_guide("compare_plan_revisions")
    assert replace["screen"] == "plans"
    for label in ("(removes the old one)", "Replace the old plans and read the new ones", "Update from the plans"):
        assert label in js and label in replace["text"], label
    agents = guides.get_guide("manage_trade_agents")["text"]
    for label in ("🤖 AI Auto Runs", "Director measure runs", "Open its Measure page", "📋 Its AI calls"):
        assert label in js and label in agents, label


def test_the_page_shows_them():                                                         # AG-03
    for needed in ("🤖 AI Auto Runs", "function autoRunCard(", 'id: "auto-runs-list"', 'id: "auto-runs-empty"',
                   "Why it failed: ", '"#/takeoffs/" + a.estimate_id', '"#/agents/ai-log?auto_run_id=" + a.id',
                   "Director measure runs", "(🤖 AI Auto Runs from the Measure screen are listed above.)"):
        assert needed in VERIFY, needed
