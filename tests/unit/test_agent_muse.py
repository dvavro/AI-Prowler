"""Muse (Meta Model API) as an agent runner (2026-11-17, David).

The agents' own Muse key (agent_muse_api_key.txt), the three Muse models and
their prices, ask()/ask_vision() through the Meta API, the cost estimates and
the live analysis, and the settings that pick Muse as the runner.

No network: the HTTP layer (_post) is mocked in every test that would call it.
No real keys: AGENT_KEY_DIR and the Task Queue config point at tmp_path.

Run: run_tests.bat tests\\unit\\test_agent_muse.py
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_agent_budget as ab  # noqa: E402
import desk_agent_providers as prov  # noqa: E402
import desk_agent_settings as das  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import task_queue_automation as tqa  # noqa: E402

MUSE_MODELS = ("muse-spark-1.3", "muse-wonder-1.0", "muse-ember-1.0")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """The agents' key files and the Task Queue config live in tmp — never the real ~/.ai-prowler."""
    monkeypatch.setattr(prov, "AGENT_KEY_DIR", tmp_path / "agent_keys")
    monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / "task_automation_config.json")
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path)
    return tmp_path


def _save_muse_key(key="muse-test-key"):
    prov.store_agent_key(key, "muse")


def _meta_reply(text="ok", inp=10, out=5):
    """What the Meta Model API returns (OpenAI-compatible shape)."""
    return {"choices": [{"message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": inp, "completion_tokens": out}}


# ── the key ──────────────────────────────────────────────────────────────────

def test_muse_key_round_trip_and_file_name():
    assert prov.agent_key_path("muse").name == "agent_muse_api_key.txt"
    assert prov.agent_key_path("muse_api").name == "agent_muse_api_key.txt"
    assert not prov.has_agent_key("muse")
    prov.store_agent_key("  muse-test-key  ", "muse")          # pasted with spaces: trimmed
    assert prov.load_agent_key("muse") == "muse-test-key"
    assert prov.load_agent_key("muse_api") == "muse-test-key"   # both spellings read the same file
    assert prov.has_agent_key("muse_api")
    assert prov._key("muse_api") == "muse-test-key"
    prov.delete_agent_key("muse_api")
    assert not prov.has_agent_key("muse") and prov.load_agent_key("muse") == ""
    prov.delete_agent_key("muse")                              # deleting twice is fine
    with pytest.raises(ValueError):
        prov.agent_key_path("gpt")


def test_ready_needs_the_muse_key():
    ok, why = prov.ready("muse_api")
    assert not ok and why.startswith("no Muse API key saved") and "Agent API Key" in why
    _save_muse_key()
    assert prov.ready("muse_api") == (True, "")


# ── models and prices ────────────────────────────────────────────────────────

def test_muse_models_and_default():
    assert prov.MUSE_URL == "https://api.meta.ai/v1/chat/completions"
    assert prov.DEFAULT_MUSE_MODEL == "muse-spark-1.3"
    assert [m for m, _ in prov.AGENT_MODELS["muse_api"]] == list(MUSE_MODELS)
    assert prov.model_for("muse_api", {}) == "muse-spark-1.3"
    assert prov.model_for("muse_api", {"agent_muse_model": "muse-wonder-1.0"}) == "muse-wonder-1.0"


def test_muse_model_choice_is_saved_and_used(isolated):
    labels = [lab for _, lab in prov.model_choices("muse_api")]
    assert [m for m, _ in prov.model_choices("muse_api")] == list(MUSE_MODELS)
    assert any("Spark" in x and "$1.25 / $4.25" in x for x in labels)
    assert any("Wonder" in x and "$4 / $20" in x for x in labels)
    assert any("Ember" in x and "$0.1 / $0.5" in x for x in labels)
    assert prov.model_for("muse_api") == "muse-spark-1.3"           # default
    prov.set_agent_model("muse_api", "muse-ember-1.0")
    assert prov.model_for("muse_api") == "muse-ember-1.0"
    assert json.loads((isolated / "task_automation_config.json").read_text())["agent_muse_model"] == \
        "muse-ember-1.0"
    with pytest.raises(ValueError):
        prov.set_agent_model("muse_api", "gpt-9")
    with pytest.raises(ValueError):
        prov.set_agent_model("muse_api", "grok-4.3")               # another runner's model


def test_muse_prices_are_current():
    # Meta Model API, Standard tier, checked 2026-11-17: no free tier, no Contributor tier.
    assert prov.price_for("muse-spark-1.3", {}) == [1.25, 4.25]
    assert prov.price_for("muse-wonder-1.0", {}) == [4.0, 20.0]
    assert prov.price_for("muse-ember-1.0", {}) == [0.10, 0.50]
    assert prov.price_for("muse-9", {}) == [1.25, 4.25]            # any other muse-* model
    assert prov.price_for("muse-spark-1.3", {"agent_prices": {"muse-spark-1.3": [1, 2]}}) == [1, 2]


def test_muse_cost_for_a_million_tokens_each_way():
    assert prov.cost("muse-spark-1.3", {"input": 1_000_000, "output": 1_000_000}, {}) == pytest.approx(5.50)
    assert prov.cost("muse-wonder-1.0", {"input": 1_000_000, "output": 1_000_000}, {}) == pytest.approx(24.00)
    assert prov.cost("muse-ember-1.0", {"input": 1_000_000, "output": 1_000_000}, {}) == pytest.approx(0.60)
    assert prov.cost("muse-spark-1.3", {"input": 2000, "output": 400}, {}) == pytest.approx(0.0042)


# ── the calls (HTTP mocked — no tokens spent) ────────────────────────────────

def test_ask_calls_the_meta_api(monkeypatch):
    _save_muse_key()
    seen = {}

    def fake_post(url, body, headers):
        seen.update(url=url, body=body, headers=headers)
        return _meta_reply('{"actions": []}', 2000, 400)

    monkeypatch.setattr(prov, "_post", fake_post)
    text, usage = prov.ask("muse_api", "be brief", "hello", model="muse-spark-1.3")
    assert text == '{"actions": []}' and usage == {"input": 2000, "output": 400}
    assert seen["url"] == "https://api.meta.ai/v1/chat/completions"
    assert seen["headers"] == {"Content-Type": "application/json", "Authorization": "Bearer muse-test-key"}
    assert seen["body"] == {"model": "muse-spark-1.3",
                            "messages": [{"role": "system", "content": "be brief"},
                                         {"role": "user", "content": "hello"}]}


def test_ask_uses_the_saved_muse_model_when_none_is_given(monkeypatch):
    _save_muse_key()
    prov.set_agent_model("muse_api", "muse-wonder-1.0")
    seen = {}
    monkeypatch.setattr(prov, "_post", lambda url, body, headers: seen.update(body=body) or _meta_reply("hi"))
    prov.ask("muse_api", "s", "u")
    assert seen["body"]["model"] == "muse-wonder-1.0"


def test_ask_without_a_key_says_so(monkeypatch):
    def no_call(*a):
        raise AssertionError("must not call out")

    monkeypatch.setattr(prov, "_post", no_call)
    with pytest.raises(prov.ProviderError, match="no Muse API key saved"):
        prov.ask("muse_api", "s", "u", model="muse-spark-1.3")


def test_ask_vision_sends_image_url_parts(monkeypatch):
    _save_muse_key()
    seen = {}
    monkeypatch.setattr(prov, "_post", lambda url, body, headers: seen.update(body=body) or _meta_reply("a slab"))
    text, usage = prov.ask_vision("muse_api", "read the plan", "how big is the slab?",
                                  [{"media_type": "image/png", "data": "iVBORw0KGgo="}],
                                  model="muse-spark-1.3")
    assert text == "a slab" and usage == {"input": 10, "output": 5}
    content = seen["body"]["messages"][1]["content"]
    assert content[0] == {"type": "image_url",
                          "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}
    assert content[1] == {"type": "text", "text": "how big is the slab?"}
    with pytest.raises(prov.ProviderError, match="at least one image"):
        prov.ask_vision("muse_api", "s", "u", [], model="muse-spark-1.3")
    with pytest.raises(prov.ProviderError, match="base64 text"):
        prov.ask_vision("muse_api", "s", "u", [{"media_type": "image/gif", "data": "x"}],
                        model="muse-spark-1.3")


# ── the cost analysis ────────────────────────────────────────────────────────

def test_estimates_include_all_three_muse_models():
    est = {e["model"]: e for e in ab.estimates(10, (2000, 400), 0.5, cfg={})}
    assert est["muse-spark-1.3"]["per_call"] == pytest.approx(0.0042)    # 2000×$1.25 + 400×$4.25 per 1M
    assert est["muse-wonder-1.0"]["per_call"] == pytest.approx(0.016)    # 2000×$4 + 400×$20 per 1M
    assert est["muse-ember-1.0"]["per_call"] == pytest.approx(0.0004)    # 2000×$0.10 + 400×$0.50 per 1M
    assert est["muse-spark-1.3"]["per_day"] == pytest.approx(0.042)
    assert est["muse-spark-1.3"]["per_month"] == pytest.approx(1.26)
    assert "Muse Spark 1.3" in est["muse-spark-1.3"]["label"]
    assert est["claude-sonnet-5-5"]["per_call"] == pytest.approx(0.008)  # the other runners are still there
    assert est["grok-4.3"]["per_call"] == pytest.approx(0.0035)


def test_live_runner_uses_muse_when_only_a_muse_key_is_saved(monkeypatch):
    monkeypatch.setattr(desk_db, "default_db_path", lambda *a, **k: "dummy.db")

    def run(chosen, saved, broken_settings=False):
        def no_settings(path):
            raise RuntimeError("no db")

        if broken_settings:
            monkeypatch.setattr(desk_db, "get_settings", no_settings)
        else:
            monkeypatch.setattr(desk_db, "get_settings", lambda path: {"agent_provider": chosen})
        monkeypatch.setattr(prov, "has_agent_key", lambda p: p in saved)
        return dga._live_runner("solo")

    assert run("muse_api", {"muse"}) == "muse_api"
    assert run("claude_api", {"muse"}) == "muse_api"        # the chosen runner has no key: any key will do
    assert run("muse_api", {"anthropic"}) == "claude_api"   # Muse chosen but no Muse key: Claude first
    assert run("muse_api", {"grok"}) == "grok_api"
    assert run("muse_api", set()) is None                   # no key at all: no live analysis
    assert run("chat_only", {"muse"}, broken_settings=True) == "muse_api"   # no settings yet: keys decide


def test_measure_sends_a_muse_model_to_the_muse_runner():
    assert ab._runner_for_model("muse-spark-1.3") == "muse_api"
    assert ab._runner_for_model("muse-wonder-1.0") == "muse_api"
    assert ab._runner_for_model("muse-ember-1.0") == "muse_api"
    assert ab._runner_for_model("grok-4.3") == "grok_api"
    assert ab._runner_for_model("claude-sonnet-5-5") == "claude_api"
    assert ab._runner_for_model("mystery-model") == "claude_api"        # unknown model: the old behaviour
    calls = []

    def fake(provider, system, user, *, model=""):
        calls.append((provider, model))
        return json.dumps({"actions": [{"action": "note", "body": "x", "why": "y", "confidence": 1}]}), \
            {"input": 2000, "output": 400}

    res = ab.measure(["muse-spark-1.3", "claude-sonnet-5-5"], "sys", [("ticket / intake", "{}", False)],
                     ask_fn=fake)
    assert calls == [("muse_api", "muse-spark-1.3"), ("claude_api", "claude-sonnet-5-5")]
    assert res["per_model"]["muse-spark-1.3"] == {"tokens": (2000, 400), "per_call": pytest.approx(0.0042)}
    assert res["rows"][0]["answer"] == "note"


# ── settings: Muse as the runner ─────────────────────────────────────────────

def test_muse_is_a_runner_in_settings(monkeypatch):
    assert "muse_api" in [p for p, _ in das.PROVIDERS]
    assert "muse_api" in [p for p, _ in das.providers_for("solo")]
    assert "muse_api" in [p for p, _ in das.providers_for("business")]
    assert "muse_api" in das.HR_RUNNERS
    for ed in ("solo", "business"):
        assert das.effective_provider({"agent_provider": "muse_api"}, ed) == "muse_api"


def test_an_old_value_falls_back_to_the_muse_key(monkeypatch):
    monkeypatch.setattr(prov, "_key", lambda p: "k" if p == "muse_api" else "")
    assert das.runner_for_removed() == "muse_api"
    assert das.effective_provider({"agent_provider": "claude_code"}, "solo") == "muse_api"
    assert das.effective_provider({"agent_provider": "chat_only"}, "business") == "muse_api"
    monkeypatch.setattr(prov, "_key", lambda p: "k" if p in ("grok_api", "muse_api") else "")
    assert das.runner_for_removed() == "grok_api"               # Claude first, then Grok, then Muse
    monkeypatch.setattr(prov, "_key", lambda p: "")
    assert das.runner_for_removed() == "chat_only"
