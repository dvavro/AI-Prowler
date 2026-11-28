"""POST /quick/photo-fill (2026-11-27, Jamie: "Upload your drawing - let's get an estimate", services only).
A fake provider stands in for the AI."""
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("PIL")
from estimator.agents import providers, roles  # noqa: E402
from estimator.context import personal_context  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from test_photo_fill import YARD, Fake, picture  # noqa: E402

API = "/estimator-api"


@pytest.fixture
def ai(db):
    f = Fake()
    providers.set_provider(f)
    roles.update_role(db, personal_context(), "llm_takeoff", {"provider": "claude_api"}, confirm=True)
    db.commit()
    yield f
    providers.set_provider(None)


def test_photo_fill_answers_the_questions(call, ai):                                      # WPF-01
    ai.replies = [json.dumps(YARD)]
    r = call("POST", f"{API}/quick/photo-fill", {"module_id": "landscaping_maintenance", "images": [picture(300, 200)],
                                                  "note": "back yard"})
    assert r.status == 200, r.body
    got = r.json()
    assert got["answers"]["palm_qty"] == 4 and got["why"]["yard_size"].startswith("drawing says")
    assert "visits" in got["not_shown"]


def test_photo_fill_refuses_trades_and_bad_files(call, ai):                               # WPF-02
    r = call("POST", f"{API}/quick/photo-fill", {"module_id": "garage_doors", "images": [picture(30, 30)]})
    assert r.status == 400 and "is a trade" in r.json()["message"]
    r = call("POST", f"{API}/quick/photo-fill", {"module_id": "pool_service", "images": ["not a picture"]})
    assert r.status == 400 and "isn't a picture" in r.json()["message"]
    assert ai.calls == []


def test_the_page_has_the_upload_box_for_services_only():                                 # WPF-03
    js = (Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web" / "app.js").read_text(encoding="utf-8")
    assert "Upload your drawing — let's get an estimate" in js
    assert 'q.module.category === "service" ? drawingBox(' in js
    assert '"/quick/photo-fill"' in js
    # 2026-11-27: the result box showed the word "null" when nothing was left out - its empty parts are dropped now
    fill = js.split("function fillFromDrawing")[1].split("function showQuickResult")[0]
    assert ".filter(Boolean)" in fill
    # 2026-11-27 (Jamie): see the picture yourself - big, or pinned beside the questions
    box = js.split("function drawingBox")[1].split("function fillFromDrawing")[0]
    assert "🖼 View picture" in box and "📌 Keep it on screen" in box and "showDrawingViewer(" in box
    assert "URL.createObjectURL" in box and "URL.revokeObjectURL" in box
    css = (Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web" / "app.css").read_text(encoding="utf-8")
    assert ".drawing-viewer" in css and ".drawing-pin" in css
