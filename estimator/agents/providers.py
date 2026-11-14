"""The AI providers for unattended Estimator agents, borrowed from AI-Prowler's own agent code.

AI-Prowler's desk_agent_providers.py already does everything an unattended agent needs: the agents' own API
keys (🔑 Agent API Key at the top of the Small Business tab, ~/.ai-prowler/agent_*_api_key.txt), the model
for each provider (task_automation_config.json), prices, and the HTTP calls. The Estimator uses it as is, so:

- keys are never stored in estimator.db, never logged and never returned (only "a key is saved: yes/no");
- the same models and prices drive the budget meter;
- the Task Queue keys and environment variables are never used, matching AI-Prowler's rule.

Outside AI-Prowler (tests, or a host without desk_agent_providers) nothing runs on its own until set_provider()
supplies one.
"""
from __future__ import annotations

import sys

API_PROVIDERS = ("claude_api", "grok_api")
PROVIDERS = ("off", "chat_only", *API_PROVIDERS)
PROVIDER_LABELS = {"off": "Off", "chat_only": "From chat only (nothing runs on its own)",
                   "claude_api": "Claude API key", "grok_api": "Grok API key"}
_OVERRIDE: dict = {}


class ProviderError(RuntimeError):
    """The provider couldn't answer (no key, HTTP error, bad reply). The message is safe to show."""


def set_provider(fake) -> None:
    """Tests: an object with ask(provider, system, user, model) -> (text, usage),
    ask_vision(provider, system, user, images, model) -> (text, usage), ready(provider) -> (ok, why),
    model_for(provider) -> str, cost(model, usage) -> float. None goes back to AI-Prowler's."""
    _OVERRIDE.clear()
    if fake is not None:
        _OVERRIDE["p"] = fake


def _host():
    if "p" in _OVERRIDE:
        return _OVERRIDE["p"]
    mod = sys.modules.get("desk_agent_providers")
    if mod is None:
        try:
            import desk_agent_providers as mod   # noqa: PLC0415 - lives in the AI-Prowler folder
        except Exception:  # noqa: BLE001
            return None
    return mod


def ready(provider: str) -> tuple[bool, str]:
    """(True, '') when this provider can run now, else (False, why) in plain words. Never shows a key."""
    if provider == "off":
        return False, "turned off"
    if provider == "chat_only":
        return False, "runs from a chat (Claude, Muse or Grok): nothing runs on its own"
    h = _host()
    if h is None:
        return False, "AI-Prowler's agent providers aren't available here (is the Estimator running inside AI-Prowler?)"
    try:
        return h.ready(provider)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:200]


def model_for(provider: str, model: str | None = None) -> str:
    if model:
        return model
    h = _host()
    try:
        return h.model_for(provider) if h else ""
    except Exception:  # noqa: BLE001
        return ""


# Which model each Estimator AI step uses (2026-11-13, David: "assign complex estimator flows to use a complex AI and
# less complex flows use less complex AI ... that is already configured at the top of the Business Tab"). The same
# two Claude models Jobs and the Service Desk use: "complex & customer" (agent_claude_model) and "internal steps"
# (agent_claude_model_light). Reading plans, calibrating and checking a takeoff are complex - a misread dimension
# is a wrong price; what a customer reads is a customer message; picking a sheet or noting for a reviewer is an
# internal step. An unknown step counts as complex (the safe side), like desk_agent_providers.
STEP_GROUPS: dict[str, dict[str, str]] = {
    "llm_takeoff": {"classify": "simple", "read": "complex", "check": "complex"},
    "auto_calibrate": {"find": "complex", "pinpoint": "complex"},
    "plan_reader": {"classify": "simple"},
    "takeoff": {"measure": "complex"},
    "reviewer": {"notes": "simple"},
    "bid_writer": {"scope": "customer"},
    "follow_up": {"email": "customer"},
}
GROUP_LABELS = {"complex": "complex step", "customer": "customer message", "simple": "internal step"}


def step_group(role: str, step: str | None = None) -> str:
    """'complex' | 'customer' | 'simple' for one Estimator AI step."""
    steps = STEP_GROUPS.get(role) or {}
    if step is None and len(set(steps.values())) == 1:
        return next(iter(steps.values()))
    return steps.get(step or "", "complex")


def fits(provider: str, model: str | None) -> bool:
    """A model name that belongs to this runner (a Claude model on the Claude key, a Grok one on Grok)."""
    m = (model or "").lower()
    return bool(m) and ((provider == "claude_api" and m.startswith("claude")) or
                        (provider == "grok_api" and m.startswith("grok")))


def model_for_step(provider: str, role: str, step: str | None = None, pinned: str | None = None) -> str:
    """The model for one Estimator AI step. The model the agent was set to itself in the Estimator tab (pinned) wins
    when it belongs to this runner (2026-11-13, David: "select the AI Model type for each agent"); otherwise the
    internal-steps model for an internal step (when one is chosen at the top of the Small Business tab), else the
    complex & customer model. Grok has one model."""
    if fits(provider, pinned):
        return pinned  # type: ignore[return-value]
    main = model_for(provider)
    if provider != "claude_api" or step_group(role, step) != "simple":
        return main
    h = _host()
    try:
        light = h.light_model() if h is not None and hasattr(h, "light_model") else ""
    except Exception:  # noqa: BLE001
        light = ""
    return light or main


def ask(provider: str, system: str, user: str, model: str = "") -> tuple[str, dict]:
    """(text, {input, output}) or ProviderError with the provider's own message."""
    if provider not in API_PROVIDERS:
        raise ProviderError(f"{provider} doesn't run on its own")
    h = _host()
    if h is None:
        raise ProviderError("AI-Prowler's agent providers aren't available here")
    try:
        return h.ask(provider, system, user, model=model)
    except Exception as exc:  # noqa: BLE001 - desk_agent_providers.ProviderError and friends
        raise ProviderError(str(exc)[:400]) from None


def ask_vision(provider: str, system: str, user: str, images: list, model: str = "") -> tuple[str, dict]:
    """(text, {input, output}) with images [{media_type, data (base64)}] - the LLM takeoff
    reads plan sheets this way. ProviderError when the host can't show the AI pictures."""
    if provider not in API_PROVIDERS:
        raise ProviderError(f"{provider} doesn't run on its own")
    h = _host()
    if h is None:
        raise ProviderError("AI-Prowler's agent providers aren't available here")
    fn = getattr(h, "ask_vision", None)
    if fn is None:
        raise ProviderError("this AI-Prowler can't show the AI plan images yet (ask_vision is missing)")
    try:
        return fn(provider, system, user, images, model=model)
    except Exception as exc:  # noqa: BLE001 - desk_agent_providers.ProviderError and friends
        raise ProviderError(str(exc)[:400]) from None


def cost_micros(model: str, usage: dict) -> int:
    """Millionths of a dollar for one call, from AI-Prowler's price table."""
    h = _host()
    try:
        usd = h.cost(model, usage) if h else 0.0
    except Exception:  # noqa: BLE001
        usd = 0.0
    return int(round(float(usd) * 1_000_000))
