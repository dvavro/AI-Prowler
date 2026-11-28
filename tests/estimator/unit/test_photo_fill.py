"""Quick estimate from a drawing (estimator/estimating/photo_fill.py, 2026-11-27, Jamie: "Upload your drawing - let's
get an estimate", services only). A fake provider stands in for the AI - no real API calls, no token cost."""
import base64
import io
import json

import pytest

from estimator.agents import ai_log, providers, roles
from estimator.context import personal_context
from estimator.errors import InvalidInput, NotAvailable
from estimator.estimating import photo_fill

PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

CTX = personal_context()


def picture(w=2400, h=1200, color=(40, 160, 60)) -> str:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


class Fake:
    def __init__(self):
        self.replies, self.calls = [], []

    def ready(self, provider):
        return True, ""

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3", "muse_api": "muse-spark-1.3"}[provider]

    def ask(self, provider, system, user, model=""):
        raise AssertionError("photo fill always sends the picture")

    def ask_vision(self, provider, system, user, images, model=""):
        self.calls.append({"system": system, "user": user, "images": images, "model": model})
        return (self.replies.pop(0) if self.replies else "{}"), {"input": 3000, "output": 400}

    def cost(self, model, usage):
        return round((usage["input"] * 3 + usage["output"] * 15) / 1_000_000, 5)


@pytest.fixture
def fake():
    f = Fake()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


def _on(db):
    roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api"}, confirm=True)


YARD = {"summary": "A back yard with grass, a rock strip and four palms along the back wall.",
        "answers": {"yard_size": {"value": "standard", "why": "drawing says 90 x 120 ft lot, mostly grass"},
                    "palm_height": {"value": "mid", "why": "palms drawn about 30 ft tall"},
                    "palm_qty": {"value": 4, "why": "4 palms along the back wall"},
                    "rock_area": {"value": "small", "why": "rock strip along the side"},
                    "edging": {"value": True, "why": "sidewalk and beds to edge"},
                    "hedges": {"value": "a lot", "why": "made-up choice"},           # not a choice: dropped
                    "trees_qty": {"value": 999, "why": "too many"},                   # out of range: dropped
                    "unicorns": {"value": 3}},                                         # not a question: ignored
        "not_shown": ["visits"]}


def test_the_ai_fills_a_service_from_a_drawing(db, fake):                                 # PF-01
    _on(db)
    fake.replies = ["Here you go:\n```json\n" + json.dumps(YARD) + "\n```"]
    r = photo_fill.fill(db, CTX, "landscaping_maintenance", [picture()], note="back yard only")
    assert r["ok"] and r["module_id"] == "landscaping_maintenance"
    assert r["answers"] == {"yard_size": "standard", "palm_height": "mid", "palm_qty": 4, "rock_area": "small",
                            "edging": True}
    assert r["why"]["palm_qty"] == "4 palms along the back wall" and "palms" in r["summary"]
    assert {d["id"] for d in r["dropped"]} == {"hedges", "trees_qty"}
    assert "visits" in r["not_shown"] and "palm_qty" not in r["not_shown"]
    assert r["provider"] == "claude_api" and r["cost_usd"] > 0

    call = fake.calls[0]
    assert len(call["images"]) == 1 and call["images"][0]["media_type"] == "image/jpeg"
    with Image.open(io.BytesIO(base64.b64decode(call["images"][0]["data"]))) as im:
        assert max(im.size) == photo_fill.PHOTO_MAX_PX                          # shrunk for the AI
    assert '"palm_qty": Palm trees' in call["user"] and '"mid" = 20 to 40 ft' in call["user"]
    assert "back yard only" in call["user"] and "Landscaping Maintenance" in call["user"]

    log = ai_log.list_entries(db, CTX, role="llm_takeoff")["entries"][0]
    assert log["purpose"] == "Quick estimate from a drawing: Landscaping Maintenance" and log["image_count"] == 1


def test_the_filled_answers_price_like_typed_ones(db, fake):                              # PF-02
    from estimator.estimating import quick
    from estimator.modules import get_registry
    _on(db)
    fake.replies = [json.dumps(YARD)]
    r = photo_fill.fill(db, CTX, "landscaping_maintenance", [picture()])
    mod = get_registry().get("landscaping_maintenance")
    _, variables = quick.resolve_answers(mod, r["answers"])         # the same check a typed answer gets
    lines = {ln["rule"].id for ln in quick.build_lines(mod, variables)}
    assert {"mow_standard", "rock_small", "edging", "palm_mid"} <= lines or {"mow_standard", "rock_small", "edging"} <= lines


def test_a_hedge_by_the_foot_with_no_length_warns(db):                                    # PF-08
    """2026-11-27 (Jamie): Q-0042 charged the 42 ft hedge minimum with no length typed and no warning."""
    from estimator.estimating import quick, service
    est = service.create_estimate(db, CTX, "Hedge check")
    r = quick.answer(db, CTX, est["id"], "landscaping_maintenance", {"yard_size": "standard", "hedges": "ft_low"},
                     est["rev"])
    assert any("42 ft minimum" in w for w in r["warnings"])
    r = quick.answer(db, CTX, est["id"], "landscaping_maintenance",
                     {"yard_size": "standard", "hedges": "ft_low", "hedge_ft": 60}, r["rev"])
    assert not any("42 ft minimum" in w for w in r["warnings"])


def test_services_only_not_trades(db, fake):                                              # PF-03
    _on(db)
    with pytest.raises(InvalidInput, match="is a trade"):
        photo_fill.fill(db, CTX, "garage_doors", [picture()])
    assert fake.calls == []


def test_the_ai_must_be_on(db, fake):                                                     # PF-04
    with pytest.raises(NotAvailable, match="AI is off"):
        photo_fill.fill(db, CTX, "pressure_washing", [picture()])
    assert fake.calls == []


def test_only_real_pictures_and_up_to_three(db, fake):                                    # PF-05
    _on(db)
    with pytest.raises(InvalidInput, match="upload a drawing"):
        photo_fill.fill(db, CTX, "pool_service", [])
    with pytest.raises(InvalidInput, match="up to 3"):
        photo_fill.fill(db, CTX, "pool_service", [picture(20, 20)] * 4)
    with pytest.raises(InvalidInput, match="isn't a picture"):
        photo_fill.fill(db, CTX, "pool_service", ["data:text/plain;base64,aGVsbG8="])
    with pytest.raises(InvalidInput, match="couldn't be read as a picture"):
        photo_fill.fill(db, CTX, "pool_service", ["data:image/png;base64,aGVsbG8="])
    assert fake.calls == []


def test_an_unreadable_answer_says_so(db, fake):                                          # PF-06
    _on(db)
    fake.replies = ["Sorry, I can't see a yard in this picture."]
    with pytest.raises(InvalidInput, match="couldn't be read"):
        photo_fill.fill(db, CTX, "landscaping_maintenance", [picture(20, 20)])
    log = ai_log.list_entries(db, CTX, role="llm_takeoff")["entries"][0]
    assert log["ok"] is False or log.get("error")


def test_every_service_can_be_asked(db, fake):                                            # PF-07
    """Every service's questions make a prompt the AI can answer (each id and each choice value is in it)."""
    from estimator.modules import get_registry
    services = [m for m in get_registry().list() if m.category == "service"]
    assert len(services) == 10
    for mod in services:
        text = photo_fill.prompt_for(mod)
        for q in mod.questions:
            assert f'"{q.id}"' in text, (mod.id, q.id)
            for c in q.choices:
                assert f'"{c["value"]}"' in text, (mod.id, q.id, c["value"])
