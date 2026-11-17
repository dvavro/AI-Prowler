"""Muse (Meta Model API) as an Estimator agent runner (2026-11-17).

estimator/agents/providers.py lists muse_api alongside Claude and Grok; a role
can run on it, fall back to it, and pin a Muse model. A fake provider stands in
for the Meta API: no real API calls.
"""
import json

import pytest

from estimator.agents import providers, queue, roles
from estimator.context import personal_context
from estimator.director import engine
from estimator.errors import InvalidInput
from estimator.estimating import service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


class FakeProvider:
    """Answers like Muse would. replies[provider] is a list of texts (or exceptions) used in order."""

    def __init__(self):
        self.keys = {"claude_api": True, "grok_api": True, "muse_api": True}
        self.replies = {"claude_api": [], "grok_api": [], "muse_api": []}
        self.calls = []

    def ready(self, provider):
        return (True, "") if self.keys.get(provider) else (False, "no API key saved")

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3",
                "muse_api": "muse-spark-1.3"}[provider]

    def light_model(self):
        return "claude-haiku-5-5"

    def ask(self, provider, system, user, model=""):
        try:
            parsed = json.loads(user)
        except ValueError:
            parsed = user
        self.calls.append({"provider": provider, "system": system, "user": parsed, "model": model})
        r = self.replies[provider].pop(0) if self.replies[provider] else '{"actions": [{"action": "no_action"}]}'
        if isinstance(r, Exception):
            raise r
        return r, {"input": 2000, "output": 500}

    def ask_vision(self, provider, system, user, images, model=""):
        self.calls.append({"provider": provider, "system": system, "user": user, "images": images,
                           "model": model})
        r = self.replies[provider].pop(0) if self.replies[provider] else '{"ok": true}'
        if isinstance(r, Exception):
            raise r
        return r, {"input": 2000, "output": 500}

    def cost(self, model, usage):           # the real price table, with no config overrides
        import desk_agent_providers as prov

        return prov.cost(model, usage, {})

    def token_cost(self, model, new_input, cache_write, cache_read, output):
        import desk_agent_providers as prov

        return prov.token_cost(model, new_input, cache_write, cache_read, output, {})


@pytest.fixture
def fake():
    f = FakeProvider()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


def _on(db, role, provider="muse_api", **extra):
    return roles.update_role(db, CTX, role, {"provider": provider, **extra}, confirm=True)


def say(*actions, summary="ok"):
    return json.dumps({"actions": list(actions), "summary": summary})


# ---------------------------------------------------------------- the provider list

def test_muse_is_listed_with_claude_and_grok():
    assert providers.API_PROVIDERS == ("claude_api", "grok_api", "muse_api")
    assert providers.PROVIDERS == ("off", "chat_only", "claude_api", "grok_api", "muse_api")
    assert providers.PROVIDER_LABELS["muse_api"] == "Muse API key"


@pytest.mark.parametrize("provider,model,want", [
    ("muse_api", "muse-spark-1.3", True),
    ("muse_api", "muse-wonder-1.0", True),
    ("muse_api", "muse-ember-1.0", True),
    ("muse_api", "MUSE-SPARK-1.3", True),            # the name is matched case-insensitively
    ("muse_api", "grok-4.3", False),
    ("muse_api", "claude-sonnet-5-5", False),
    ("muse_api", None, False),
    ("muse_api", "", False),
    ("grok_api", "muse-spark-1.3", False),
    ("claude_api", "muse-spark-1.3", False),
    ("claude_api", "claude-sonnet-5-5", True),       # the other runners still match their own models
    ("grok_api", "grok-4.3", True),
])
def test_fits_matches_a_model_to_its_runner(provider, model, want):
    assert providers.fits(provider, model) is want


def test_ready_and_ask_go_through_the_muse_key(fake):
    assert providers.ready("muse_api") == (True, "")
    fake.keys["muse_api"] = False
    assert providers.ready("muse_api") == (False, "no API key saved")
    fake.keys["muse_api"] = True
    fake.replies["muse_api"] = ['{"actions": [{"action": "no_action"}]}']
    text, usage = providers.ask("muse_api", "sys", '{"a": 1}', model="muse-spark-1.3")
    assert fake.calls[0]["provider"] == "muse_api" and fake.calls[0]["model"] == "muse-spark-1.3"
    assert usage == {"input": 2000, "output": 500} and "no_action" in text
    with pytest.raises(providers.ProviderError):
        providers.ask("off", "s", "u")
    with pytest.raises(providers.ProviderError):
        providers.ask("chat_only", "s", "u")


def test_ask_vision_reaches_muse(fake):
    fake.replies["muse_api"] = ['{"ok": true}']
    text, _ = providers.ask_vision("muse_api", "read the plan", "how big?", [{"media_type": "image/png",
                                                                             "data": "iVBORw0KGgo="}])
    assert fake.calls[0]["provider"] == "muse_api"
    assert fake.calls[0]["images"] == [{"media_type": "image/png", "data": "iVBORw0KGgo="}]
    assert text == '{"ok": true}'


def test_cost_micros_uses_the_muse_prices(fake):
    assert providers.cost_micros("muse-spark-1.3", {"input": 2000, "output": 400}) == 4200
    assert providers.cost_micros("muse-wonder-1.0", {"input": 2000, "output": 400}) == 16000
    assert providers.cost_micros("muse-ember-1.0", {"input": 2000, "output": 400}) == 400


# ---------------------------------------------------------------- models per step

def test_a_pinned_muse_model_wins_on_muse_and_is_ignored_elsewhere(fake):
    assert providers.model_for_step("muse_api", "llm_takeoff", "read", "muse-wonder-1.0") == "muse-wonder-1.0"
    assert providers.model_for_step("muse_api", "llm_takeoff", "read", "claude-opus-5-5") == "muse-spark-1.3"
    assert providers.model_for_step("claude_api", "llm_takeoff", "read", "muse-wonder-1.0") == "claude-sonnet-5-5"
    assert providers.model_for_step("muse_api", "llm_takeoff", "classify") == "muse-spark-1.3"


def test_agents_flow_names_the_muse_models(fake):
    from estimator.ui import agents_flow as af

    assert af.model_choices("muse_api") == [("muse-spark-1.3", "Muse Spark 1.3"),
                                            ("muse-wonder-1.0", "Muse Wonder"),
                                            ("muse-ember-1.0", "Muse Ember")]
    assert af.mode_of("muse_api") == "on"
    assert af.model_line("llm_takeoff", "muse_api", "muse-wonder-1.0") == \
        "complex step → Muse Wonder (set for this agent)"
    assert af.model_line("reviewer", "muse_api") == "internal step → Muse Spark 1.3"


# ---------------------------------------------------------------- roles on Muse

def test_a_role_runs_on_muse_and_can_fall_back_to_it(db, fake):
    out = _on(db, "reviewer")
    assert out["role"]["provider"] == "muse_api" and out["role"]["ready"]
    assert out["role"]["model"] == "muse-spark-1.3"
    out = _on(db, "bid_writer", provider="claude_api", fallback_provider="muse_api")
    assert out["role"]["fallback_provider"] == "muse_api" and out["role"]["fallback_ready"]
    with pytest.raises(InvalidInput, match="different"):
        _on(db, "reviewer", fallback_provider="muse_api")        # the backup must differ from the main one
    with pytest.raises(InvalidInput):
        _on(db, "reviewer", provider="gpt_api")
    ov = roles.overview(db, "default")
    assert ov["api_keys_saved"] == {"claude_api": True, "grok_api": True, "muse_api": True}
    assert "muse_api" in ov["providers"]


def test_reviewer_runs_on_the_muse_key(db, fake):
    _on(db, "reviewer")
    r = engine.start(db, CTX, "replace the roof", answers=ROOF, registry=REG)      # $7,817.10 waits for review
    fake.replies["muse_api"] = [say({"action": "review_note", "body": "Check the pitch on sheet A3."})]
    out = queue.run(db, CTX)
    assert len(out["queued"]) == 1 and out["ran"][0]["state"] == "done" and out["ran"][0]["provider"] == "muse_api"
    assert fake.calls[0]["provider"] == "muse_api" and fake.calls[0]["model"] == "muse-spark-1.3"
    assert fake.calls[0]["user"]["estimate"]["total"] == "$7,817.10"
    usage = db.execute("SELECT provider, ok FROM agent_usage ORDER BY id").fetchall()
    assert [(u["provider"], u["ok"]) for u in usage] == [("muse_api", 1)]
    s = roles.spent(db, "default")
    assert s["today"]["calls"] == 1 and s["today"]["micros"] == 4625     # 2,000 x $1.25 + 500 x $4.25 per 1M
    ev = [e for e in service.events(db, CTX, r["estimate"]["id"]) if e["action"] == "agent_task_done"]
    assert ev and json.loads(ev[0]["after_json"])["provider"] == "muse_api"
