"""
desk_agent_providers.py — the self-running agent (desk-agent-spec §3, §4.3, Phase 3; David
2026-10-30 "continue with ... the self-running part").

One call per queued item: the AI gets the item's context pack (from desk_agent.next_items) and
answers with JSON actions, which go through desk_agent.submit — the same policy as a chat run.
The AI never gets tools that could change anything, so it can't reach around the policy.

    claude_api   Anthropic Messages API with the agents' own Claude API key — 🔑 Agent API Key at the top of the Small Business tab
                 (~/.ai-prowler/agent_claude_api_key.txt). The Task Queue runs on this same key.
    grok_api     the xAI API with the agents' own Grok key (same box; agent_grok_api_key.txt)
    chat_only    no API key is saved: the agents don't run

Models and prices are in ~/.ai-prowler/task_automation_config.json ("agent_claude_model",
"agent_grok_model", "agent_prices" = {model: [usd per 1M input, usd per 1M output]}).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

CLAUDE_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_CLAUDE_MODEL = "claude-sonnet-5-5"
DEFAULT_PRICES = {                       # USD per 1M tokens [input, output]; override in config "agent_prices"
    # Checked 2026-11-01 against published API prices (Anthropic: Sonnet 5.5 $2/$10, Haiku 5.5 $0.10/$0.50 for
    # prompts up to 100K tokens, Opus 5.5 $4/$20; xAI: Grok 4.3 $1.25/$2.50). The old $3/$15 and $1/$5 made the
    # budget meter read about 1.5x (Sonnet) and 10x (Haiku) high, so agents stopped early.
    "claude-haiku-5-5": [0.10, 0.50],
    "claude-sonnet-5-5": [2.0, 10.0],
    "claude-opus-5-5": [4.0, 20.0],
    "grok-4.3": [1.25, 2.50],
    "grok": [1.25, 2.50],                # any other grok-* model
}
# Prompt caching (2026-11-03, live cost test: AI-Prowler recorded 6-25 % more than the API charged because cached
# tokens were priced as plain input). Cache writes (5-minute) cost 1.25x input; cache reads 0.1x input — except
# Sonnet 5.5, whose cache reads were cut to $0.10 per 1M (0.05x) in Oct 2026. Haiku 5.5 charges 5x on everything
# when one prompt is over 100,000 tokens (counting cache reads and writes).
CACHE_WRITE_X = 1.25
CACHE_READ_X = {"claude-sonnet-5-5": 0.05}
DEFAULT_CACHE_READ_X = 0.10
LONG_PROMPT = {"claude-haiku-5-5": (100_000, 5.0)}
HTTP_TIMEOUT = 120
MAX_TOKENS = 1500

HEADLESS_RULES = """
You are running on your own (no person is watching). You get ONE item as JSON. Decide what to do
using only the actions in "allowed_actions". Reply with ONLY one JSON object, nothing else:
{"actions": [{"action": "...", ...fields..., "why": "one line", "confidence": 0.0-1.0}], "summary": "one line"}
Fields by action: set_type{type} set_priority{priority} route{assignee} note{body} reply{body}
ask_customer{body} nudge_team{body} flag_duplicate{of_ticket_id} propose_job{notes,service_date(optional, after today)} propose_merge{primary_id}
propose_learning{title,body} bk_note{body} bk_flag{flag,detail} bk_recommend{choice,window_key,crew}
bk_suggest_time{window_key,note} bk_offer_times{window_keys,note} bk_approve{window_key,crew}
bk_decline{body,keep_request} bk_reply{body} bk_job_note{body} bk_nudge{body} bk_customer_note{body}
bk_set_minutes{service_code,minutes} bk_offer_opening{window_key} no_action{}.
Jobs and route items (kind "job" / "route") list their own fields in "action_fields" and their rules in "rules".
When the item has a "hint", follow it; "weather", "opening" and "time_on_site" are facts worked out for you.
If nothing is worth doing, return {"actions": [{"action": "no_action", "why": "...", "confidence": 1}]}.
"""


class ProviderError(RuntimeError):
    pass


def _cfg() -> dict:
    try:
        import task_queue_automation as tqa
        return tqa.load_config() or {}
    except Exception:  # noqa: BLE001
        return {}


AGENT_KEY_DIR = Path.home() / ".ai-prowler"
AGENT_KEY_FILES = {"anthropic": "agent_claude_api_key.txt", "grok": "agent_grok_api_key.txt"}


def agent_key_path(provider: str) -> Path:
    """The agents' own key files (2026-11-01, David: "the Agents use the API Keys in the small business tab
    only"). Separate from the Task Queue's claude_api_key.txt / grok_api_key.txt — those, and the
    ANTHROPIC_API_KEY / XAI_API_KEY environment variables, are never used by the agents."""
    p = {"claude": "anthropic", "claude_api": "anthropic", "xai": "grok", "grok_api": "grok"}.get(provider, provider)
    if p not in AGENT_KEY_FILES:
        raise ValueError(f"Unknown agent key provider: {provider!r}")
    return Path(AGENT_KEY_DIR) / AGENT_KEY_FILES[p]


def load_agent_key(provider: str) -> str:
    path = agent_key_path(provider)
    try:
        return path.read_text(encoding="utf-8").strip() if path.exists() else ""
    except OSError:
        return ""


def has_agent_key(provider: str) -> bool:
    """Presence only — never returns or logs the key."""
    return bool(load_agent_key(provider))


def store_agent_key(key: str, provider: str) -> None:
    path = agent_key_path(provider)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        from safe_save import atomic_write_text
        atomic_write_text(path, key.strip())
    except ImportError:
        path.write_text(key.strip(), encoding="utf-8")


def delete_agent_key(provider: str) -> None:
    path = agent_key_path(provider)
    if path.exists():
        path.unlink()


def _key(provider: str) -> str:
    if provider == "claude_api":
        return load_agent_key("anthropic")
    if provider == "grok_api":
        return load_agent_key("grok")
    return ""


def model_for(provider: str, cfg: dict | None = None) -> str:
    cfg = cfg if cfg is not None else _cfg()
    if provider == "claude_api":
        return (cfg.get("agent_claude_model") or DEFAULT_CLAUDE_MODEL).strip()
    if provider == "grok_api":
        try:
            import task_queue_automation as tqa
            default = tqa.GROK_MODEL
        except Exception:  # noqa: BLE001
            default = "grok-4.3"
        return (cfg.get("agent_grok_model") or cfg.get("grok_model") or default).strip()
    return ""


def ready(provider: str, edition: str | None = None) -> tuple:
    """(True, '') when this runner can work now, else (False, what's missing in plain words)."""
    if provider == "chat_only":
        return False, ("no API key is saved, so the agents don't run — the apps and your chat work as usual. To turn "
                       "them on, save a Claude or Grok key in 🔑 Agent API Key at the top of the Small Business tab")
    if provider in ("claude_api", "grok_api"):
        if not _key(provider):
            where = "🔑 Agent API Key at the top of the Small Business tab"
            return False, (f"no Claude API key saved ({where})" if provider == "claude_api"
                           else f"no Grok API key saved ({where})")
        return True, ""
    return False, f"unknown runner {provider}"


# ── which model the agents use (2026-11-01, David: "add controls which AI Model is used in the API") ──
AGENT_MODELS = {
    "claude_api": (("claude-haiku-5-5", "Claude Haiku 5.5 — fastest, cheapest"),
                   ("claude-sonnet-5-5", "Claude Sonnet 5.5 — recommended"),
                   ("claude-opus-5-5", "Claude Opus 5.5 — most capable, costs more")),
    "grok_api": (("grok-4.3", "Grok 4.3 — recommended"),),
}
MODEL_CFG_KEY = {"claude_api": "agent_claude_model", "grok_api": "agent_grok_model"}


LIGHT_CFG_KEY = "agent_claude_model_light"
# Which steps get the complex-work model (2026-11-01, David: "use expensive models on complex jobs like routing
# and lower cost models on lower complex agent calls"). Everything else is a simple step and uses the
# simple-steps model when one is chosen. An unknown kind counts as complex (the safe side).
COMPLEX_STEPS = {
    "route": None,                                 # every Route-flow step: sort, schedule, route, send, re-plan
    "job": {"schedule"},                           # picking dates for unscheduled jobs
    "booking": {"decide", "offer"},                # approve / another time / decline; offering times
    "ticket": {"resolution"},                      # working out the likely fix
    "hr": {"timeoff", "incidents", "answer"},      # people decisions and employee answers
}
# Customer messages — their own group, always on the stronger model, in practice / Suggest / Auto alike
# (2026-11-01, David: "make customer messages their own group on the stronger model and even in practice mode,
# we want at some point the user to trust the AI agents and eventually select AUTO mode" — the drafts the owner
# judges in practice mode must be the same quality the agent will later send on its own).
CUSTOMER_STEPS = {
    "ticket": {"first_reply", "follow_through"},   # first reply; asking the customer / nudges when it goes quiet
    "booking": {"reply", "track"},                 # answering about the visit; chasing answers, offering times
    "job": {"quotes", "collect", "repeat"},        # quote follow-ups, payment reminders, repeat & win-back
}
GROUP_LABELS = {"complex": "complex step", "customer": "customer message", "simple": "internal step"}
COMPLEX_HELP = ("The stronger model handles two groups. Complex steps: every Route step (sort the week, schedule the "
                "week, route, send routes, re-plan the day), Schedule (picking dates), booking Decide and Offer times, "
                "ticket Resolution help, and HR time off, incidents and employee answers. Customer messages — always, "
                "in practice mode too, so what you judge now is what Auto will send: first replies and follow-ups to "
                "customers, answers about their visit and chasing answers, quote follow-ups, payment reminders, and "
                "repeat & win-back messages. Everything else is an internal step and can use the cheaper model: "
                "sorting and prioritizing new tickets, internal notes, prep and on-site checks, close-out drafts and "
                "learning.")


def is_complex(kind, stage) -> bool:
    if kind not in COMPLEX_STEPS:
        return True
    steps = COMPLEX_STEPS[kind]
    return steps is None or stage in steps


def step_group(kind, stage) -> str:
    """'complex' | 'customer' | 'simple' (internal). Unknown kinds count as complex."""
    if is_complex(kind, stage):
        return "complex"
    if stage in CUSTOMER_STEPS.get(kind, ()):
        return "customer"
    return "simple"


def uses_strong_model(kind, stage) -> bool:
    return step_group(kind, stage) != "simple"


def light_model(cfg: dict | None = None) -> str:
    """The simple-steps Claude model, or '' (= same as complex work)."""
    cfg = cfg if cfg is not None else _cfg()
    m = (cfg.get(LIGHT_CFG_KEY) or "").strip()
    return m if m in {x for x, _ in AGENT_MODELS["claude_api"]} else ""


def model_for_item(provider: str, item: dict | None, cfg: dict | None = None) -> str:
    """The model for one queued item: the simple-steps model for a simple step, else the main model."""
    cfg = cfg if cfg is not None else _cfg()
    main = model_for(provider, cfg)
    if provider != "claude_api":
        return main
    light = light_model(cfg)
    it = item or {}
    if not light or uses_strong_model(it.get("kind"), it.get("stage")):
        return main
    return light


def set_light_model(model: str) -> None:
    """'' = simple steps use the complex-work model too."""
    if model and model not in {m for m, _ in AGENT_MODELS["claude_api"]}:
        raise ValueError(f"unknown model {model!r}")
    import task_queue_automation as tqa
    cfg = tqa.load_config()
    cfg[LIGHT_CFG_KEY] = model
    tqa.save_config(cfg)


def model_choices(provider: str) -> list:
    """[(model, "label — $in / $out per 1M tokens")] for the drop-down."""
    out = []
    for m, lab in AGENT_MODELS.get(provider, ()):
        pr = price_for(m, {})
        out.append((m, f"{lab}  (${pr[0]:g} / ${pr[1]:g} per 1M tokens)" if pr else lab))
    return out


def set_agent_model(provider: str, model: str) -> None:
    """Save the model the agents use for this runner (task_automation_config.json, read by model_for)."""
    if provider not in MODEL_CFG_KEY or model not in {m for m, _ in AGENT_MODELS[provider]}:
        raise ValueError(f"unknown model {model!r} for {provider}")
    import task_queue_automation as tqa
    cfg = tqa.load_config()
    cfg[MODEL_CFG_KEY[provider]] = model
    tqa.save_config(cfg)


def price_for(model: str, cfg: dict | None = None):
    """[usd per 1M input, usd per 1M output] or None."""
    cfg = cfg if cfg is not None else _cfg()
    prices = dict(DEFAULT_PRICES, **(cfg.get("agent_prices") or {}))
    return prices.get(model) or (prices["grok"] if (model or "").startswith("grok") else None)


def token_cost(model: str, new_input: int, cache_write: int, cache_read: int, output: int,
               cfg: dict | None = None) -> float:
    """USD for one call's tokens: new input, cache writes (1.25x), cache reads (0.1x, Sonnet 5.5 0.05x), output;
    Haiku 5.5's long-prompt rate when the whole prompt is over 100K tokens. Unrounded."""
    cfg = cfg if cfg is not None else _cfg()
    p = price_for(model, cfg)
    if not p:
        return 0.0
    pin, pout = float(p[0]), float(p[1])
    lim = LONG_PROMPT.get(model)
    if lim and new_input + cache_write + cache_read > lim[0]:
        pin, pout = pin * lim[1], pout * lim[1]
    return (new_input * pin + cache_write * pin * CACHE_WRITE_X
            + cache_read * pin * CACHE_READ_X.get(model, DEFAULT_CACHE_READ_X) + output * pout) / 1_000_000


def cost(model: str, usage: dict, cfg: dict | None = None) -> float:
    """USD for one call. usage["input"] counts ALL input tokens; the optional "cache_read" / "cache_write" say how
    many of them came from / went into the prompt cache (priced at the cache rates, not the input rate)."""
    cr, cw = int(usage.get("cache_read", 0) or 0), int(usage.get("cache_write", 0) or 0)
    new = max(int(usage.get("input", 0) or 0) - cr - cw, 0)
    return round(token_cost(model, new, cw, cr, int(usage.get("output", 0) or 0), cfg), 5)


# ── the calls ────────────────────────────────────────────────────────────────

def ask(provider: str, system: str, user: str, *, model: str = "") -> tuple:
    """(text, usage{input, output}). Raises ProviderError with the provider's own message."""
    model = model or model_for(provider)
    if provider == "claude_api":
        return _claude_api(system, user, model)
    if provider == "grok_api":
        return _grok_api(system, user, model)
    raise ProviderError(f"{provider} doesn't run on its own")


def _post(url, body, headers):
    import urllib.error as ue
    import urllib.request as ur
    req = ur.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with ur.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except ue.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")[:400]
        except Exception:  # noqa: BLE001
            detail = str(e)
        raise ProviderError(f"HTTP {e.code}: {detail}") from None
    except Exception as e:  # noqa: BLE001
        raise ProviderError(f"request failed: {e}") from None


def _claude_api(system, user, model):
    key = _key("claude_api")
    if not key:
        raise ProviderError("no Claude API key saved")
    data = _post(CLAUDE_URL, {"model": model, "max_tokens": MAX_TOKENS,
                              "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                              "messages": [{"role": "user", "content": user}]},
                 {"Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"})
    text = "".join(b.get("text", "") for b in data.get("content") or [] if b.get("type") == "text")
    u = data.get("usage") or {}
    cr, cw = int(u.get("cache_read_input_tokens", 0) or 0), int(u.get("cache_creation_input_tokens", 0) or 0)
    return text, {"input": int(u.get("input_tokens", 0)) + cr + cw, "cache_read": cr, "cache_write": cw,
                  "output": int(u.get("output_tokens", 0))}


def _grok_api(system, user, model):
    key = _key("grok_api")
    if not key:
        raise ProviderError("no Grok API key saved")
    try:
        import task_queue_automation as tqa
        url = tqa.XAI_API_URL
    except Exception:  # noqa: BLE001
        url = "https://api.x.ai/v1/chat/completions"
    data = _post(url, {"model": model, "messages": [{"role": "system", "content": system},
                                                    {"role": "user", "content": user}]},
                 {"Content-Type": "application/json", "Authorization": "Bearer " + key})
    ch = (data.get("choices") or [{}])[0].get("message") or {}
    u = data.get("usage") or {}
    return str(ch.get("content") or ""), {"input": int(u.get("prompt_tokens", 0)),
                                          "output": int(u.get("completion_tokens", 0))}


# 2026-11-01 (David: "Remove CLI everywhere"): the claude_code runner (_claude_exe, _claude_code) is gone —
# the agents run on an API key. A saved "claude_code" choice reads as the saved key's runner
# (desk_agent_settings.runner_for_removed).


def parse_actions(text: str) -> tuple:
    """(actions, summary) from the AI's reply — tolerant of code fences and chatter around the JSON."""
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?|```$", "", t, flags=re.M).strip()
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end <= start:
        raise ProviderError("the AI didn't answer with JSON")
    try:
        obj = json.loads(t[start:end + 1])
    except ValueError as e:
        raise ProviderError(f"the AI's JSON couldn't be read: {e}") from None
    acts = obj.get("actions")
    if not isinstance(acts, list):
        raise ProviderError("the AI's answer has no actions list")
    return [a for a in acts if isinstance(a, dict)][:8], str(obj.get("summary") or "")[:300]
