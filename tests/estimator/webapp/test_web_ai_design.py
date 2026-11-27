"""AI design's web calls (Measure screen, 2026-11-21, David: "type in a command like here's my shed drawings, I want to
add electricity to it"). A fake provider stands in for the AI; the job runs in the request (RUN_INLINE)."""
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("ezdxf")
from estimator.agents import providers, roles  # noqa: E402
from estimator.context import personal_context  # noqa: E402
from estimator.design import runs  # noqa: E402
from estimator.drawing_model import store  # noqa: E402
from estimator.estimating import service  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from test_ai_design import shed_design  # noqa: E402
from test_ai_design_runs import ASK, Fake, _walls_dxf  # noqa: E402

API = "/estimator-api"


@pytest.fixture
def shed(db, tmp_path, monkeypatch):
    ctx = personal_context()
    f = Fake()
    providers.set_provider(f)
    monkeypatch.setattr(runs, "RUN_INLINE", True)
    est = service.create_estimate(db, ctx, "NSB Shed electrical")["id"]
    ps = store.upload(db, ctx, est, _walls_dxf(tmp_path / "shed.dxf"), confirm=True)["plan_set_id"]
    db.commit()
    yield {"est": est, "ps": ps, "fake": f, "db": db, "ctx": ctx}
    providers.set_provider(None)


def test_design_start_view_change_approve(call, shed):                                    # WAD-01
    est, ps, fake = shed["est"], shed["ps"], shed["fake"]
    r = call("GET", f"{API}/design/{est}").json()
    assert r["ai_on"] is False and "AI measuring is off" in r["why_off"]
    assert r["designs"] == {"electrical": None, "plans": None}          # 2026-11-24: plans from a description
    assert [p["id"] for p in r["plan_sets"]] == [ps] and r["trades"][0]["id"] == "electrical"
    assert [t["ready"] for t in r["trades"]] == [True, False, False, False, True]          # ... and plans, no plan set
    assert [t["no_plans"] for t in r["trades"]] == [False, False, False, False, True]
    roles.update_role(shed["db"], shed["ctx"], "llm_takeoff", {"provider": "claude_api"}, confirm=True)
    shed["db"].commit()
    assert call("GET", f"{API}/design/{est}").json()["ai_on"] is True

    fake.text = [json.dumps(shed_design())]
    r = call("POST", f"{API}/design/{est}/electrical", {"request": ASK, "plan_set_id": ps})
    assert r.status == 200, r.body
    d = r.json()["design"]
    assert d["status"] == "proposed" and d["counts"]["total"] == 46 and d["can_approve"] is True
    assert "building" in d and "floors" not in d["building"]                       # a summary, not the whole model

    for what in ("plan", "panel"):
        pic = call("GET", f"{API}/design/{est}/electrical/{what}/svg")
        assert pic.status == 200 and pic.content_type == "image/svg+xml" and b"<svg" in pic.body[:500]
        dxf = call("GET", f"{API}/design/{est}/electrical/{what}")
        assert dxf.status == 200 and dxf.content_type == "application/dxf"
        assert "AI design - electrical" in dxf.headers["Content-Disposition"]

    fake.text = [json.dumps({**shed_design(), "changes": ["moved nothing"]})]
    d = call("POST", f"{API}/design/{est}/electrical/change", {"text": "keep it as is"}).json()["design"]
    assert d["rev"] == 2 and d["design"]["changes"] == ["moved nothing"]

    q = call("POST", f"{API}/design/{est}/electrical/approve", {}).json()
    assert q["needs_confirmation"] is True and "46 devices on 6 circuits" in q["question"]
    a = call("POST", f"{API}/design/{est}/electrical/approve", {"confirm": True}).json()
    assert a["status"] == "approved" and len(a["approved_plan_set_ids"]) == 2 and a["say"].startswith("Approved")
    assert a["approval"]["counted"] > 0 and a["approval"]["wired"] > 0         # measured right away (2026-11-23)


def test_design_refusals(call, shed):                                                     # WAD-02
    est, ps = shed["est"], shed["ps"]
    r = call("POST", f"{API}/design/{est}/electrical", {"request": "x", "plan_set_id": ps})
    assert r.status == 400 and "say what you want" in r.json()["message"]
    assert call("POST", f"{API}/design/{est}/plumbing", {"request": ASK, "plan_set_id": ps}).status == 400
    assert call("GET", f"{API}/design/{est}/electrical/plan/svg").status == 404          # nothing drawn yet
    assert call("POST", f"{API}/design/{est}/electrical/approve", {"confirm": True}).status == 400
    assert call("GET", f"{API}/design/999999").status == 404
    assert call("GET", f"{API}/design/{est}/electrical/reference").status == 404         # no numbered plan yet


def test_design_with_screenshots(call, shed):                                             # WAD-03
    """2026-11-23: screenshots ride along with a change, and the numbered plan is served as a PNG."""
    import base64
    import io
    from PIL import Image
    est, ps, fake = shed["est"], shed["ps"], shed["fake"]
    roles.update_role(shed["db"], shed["ctx"], "llm_takeoff", {"provider": "claude_api"}, confirm=True)
    shed["db"].commit()
    fake.text = [json.dumps(shed_design())]
    assert call("POST", f"{API}/design/{est}/electrical", {"request": ASK, "plan_set_id": ps}).status == 200
    ref = call("GET", f"{API}/design/{est}/electrical/reference")
    assert ref.status == 200 and ref.content_type == "image/png" and ref.body[:4] == b"\x89PNG"
    assert "numbered plan" in ref.headers["Content-Disposition"]
    b = io.BytesIO()
    Image.new("RGB", (80, 60), (255, 0, 0)).save(b, "PNG")
    shot = "data:image/png;base64," + base64.b64encode(b.getvalue()).decode("ascii")
    fake.vision = [json.dumps({**shed_design(), "changes": ["moved device 3"]})]
    r = call("POST", f"{API}/design/{est}/electrical/change", {"text": "move this here", "images": [shot]})
    assert r.status == 200, r.body
    assert fake.calls[-1][0] == "vision" and fake.calls[-1][2] == 2
    assert r.json()["design"]["revisions"][-1]["screenshots"] == 1
    bad = call("POST", f"{API}/design/{est}/electrical/change", {"text": "move this here", "images": ["nope"]})
    assert bad.status == 400 and "isn't a picture" in bad.json()["message"]
