"""AI design with screenshots (2026-11-23, David: "add screenshots to the AI Design to give geometric guidance to the AI,
for example move this here"): the numbered reference picture, checking the person's pictures, and a start or change that
sends them to the AI with the reference first. A fake provider stands in for Claude - no real API calls."""
import base64
import io
import json

import pytest

pytest.importorskip("ezdxf")
PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

from estimator.design import electrical, reference, runs  # noqa: E402
from estimator.errors import InvalidInput  # noqa: E402
from test_ai_design import SHED, shed_design  # noqa: E402
from test_ai_design_runs import ASK, CTX, _on, fake, shed  # noqa: E402,F401 - fixtures


def _png(w=200, h=120, color=(250, 40, 40)):
    b = io.BytesIO()
    Image.new("RGB", (w, h), color).save(b, "PNG")
    return "data:image/png;base64," + base64.b64encode(b.getvalue()).decode("ascii")


def test_the_numbered_reference_picture():                                              # SH-01
    png = reference.render(SHED, shed_design())
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    with Image.open(io.BytesIO(png)) as im:
        assert im.width > 400 and im.height > 300
    assert reference.render(SHED)[:4] == b"\x89PNG"                          # the building alone, before a design
    note = electrical.images_note(2, True)
    assert "PICTURES" in note and "5 ft grid" in note and "numbered dot" in note and "next 2 picture" in note
    assert "numbered dot" not in electrical.images_note(1, False)


def test_screenshots_are_checked_and_shrunk(tmp_path):                                  # SH-02
    assert runs.save_shots(990001, "electrical", [], "t") == []
    with pytest.raises(InvalidInput, match="up to 3"):
        runs.save_shots(990001, "electrical", [_png()] * 4, "t")
    with pytest.raises(InvalidInput, match="isn't a picture"):
        runs.save_shots(990001, "electrical", ["data:text/html;base64,PGI+"], "t")
    with pytest.raises(InvalidInput, match="couldn't be read"):
        runs.save_shots(990001, "electrical", ["data:image/png;base64," + base64.b64encode(b"not a png").decode()], "t")
    paths = runs.save_shots(990001, "electrical", [_png(3000, 1000)], "t")
    assert len(paths) == 1 and paths[0].endswith("electrical_t_shot1.jpg")
    with Image.open(paths[0]) as im:
        assert im.format == "JPEG" and max(im.size) == runs.SHOT_MAX_PX


def test_a_change_with_a_screenshot_sends_the_reference_first(db, fake, shed):           # SH-03
    _on(db)
    fake.text = [json.dumps(shed_design())]
    runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"])
    moved = shed_design()
    moved["changes"] = ["moved device 3 to x 30, y 44"]
    fake.vision = [json.dumps(moved)]
    job = runs.change(db, CTX, shed["est"], "electrical", "move this outlet here", images=[_png(), _png(color=(0, 0, 255))])
    kind, prompt, n = fake.calls[-1]
    assert kind == "vision" and n == 3                                        # the reference + 2 screenshots
    assert "PICTURES" in prompt and "numbered dot" in prompt and "move this outlet here" in prompt
    assert job["rev"] == 2 and job["revisions"][-1]["screenshots"] == 2 and job["error"] is None
    assert "pending_shots" not in runs.load(shed["est"], "electrical")


def test_a_new_design_with_a_screenshot_is_a_picture_call(db, fake, shed):              # SH-04
    _on(db)
    fake.vision = [json.dumps(shed_design())]
    job = runs.start(db, CTX, shed["est"], "electrical", ASK + " Lights where I marked.", shed["ps"], images=[_png()])
    kind, prompt, n = fake.calls[-1]
    assert kind == "vision" and n == 2 and "PICTURES" in prompt and "numbered dot" not in prompt
    assert job["status"] == "proposed" and job["revisions"][-1]["screenshots"] == 1
    # a typed "device 12" works without a picture too: the change prompt says how devices are numbered
    fake.text = [json.dumps(shed_design())]
    runs.change(db, CTX, shed["est"], "electrical", "move device 12 to x 30, y 44")
    assert fake.calls[-1][0] == "ask" and "1-based" in fake.calls[-1][1]


def test_bad_screenshots_stop_before_any_ai_call(db, fake, shed):                       # SH-05
    _on(db)
    with pytest.raises(InvalidInput):
        runs.start(db, CTX, shed["est"], "electrical", ASK, shed["ps"], images=["nope"])
    assert fake.calls == []
