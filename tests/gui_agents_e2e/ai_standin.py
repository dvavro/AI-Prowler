"""The stand-in AI for the agents GUI suite (AGENTS_GUI_E2E_TEST_SPEC.md §1.4).

Runs INSIDE the sandbox server (ag_server.py): install() replaces desk_agent_providers._post, the one
place the agents' Claude and Grok calls go out. Every request is recorded (agent kind, stage, model,
the whole prompt) and answered with a Claude- or Grok-shaped reply built from the active script.
No network, no key, no cost.

Scripts (set with POST /ai-script {"name": ...} on the control port):
  good    a believable action for the stage, confidence 0.9 (the normal path)
  low     the same with confidence 0.55 (under the 0.6 minimum)
  low75   confidence 0.75 (under the 0.8 booking-confirm minimum)
  noop    "no_action" for every stage
  messy   bad answers in turn: not JSON, no actions list, an action the stage doesn't allow, an empty reply
  error   the "API" answers HTTP 500
  slow    the "API" times out
A rule can also be set for one stage (POST /ai-script {"name": "good", "rules": {"ticket:first_reply": [...]}}):
the actions listed there are returned for that stage instead.
"""
from __future__ import annotations

import json
import threading

CALLS: list[dict] = []
SCRIPT: dict = {"name": "good", "rules": {}}
_lock = threading.Lock()
_messy_turn = {"n": 0}

# The note action each kind has (route steps have none — see _route_action).
NOTE = {"ticket": "note", "booking": "bk_note", "job": "jb_note", "hr": "hr_note"}
TEXT = "ZAG stand-in: checked this and left a note for the owner."


def reset(name: str = "good", rules: dict | None = None) -> None:
    with _lock:
        CALLS.clear()
        SCRIPT.update(name=name, rules=dict(rules or {}))
        _messy_turn["n"] = 0


def set_script(name: str, rules: dict | None = None) -> None:
    with _lock:
        SCRIPT.update(name=name, rules=dict(rules or {}))
        _messy_turn["n"] = 0


def calls() -> list[dict]:
    with _lock:
        return [dict(c, prompt=c["prompt"][:400]) for c in CALLS]


def _pack(user: str) -> dict:
    try:
        d = json.loads(user)
        return d if isinstance(d, dict) else {}
    except (TypeError, ValueError):
        return {}


def _route_action(stage: str, conf: float) -> dict:
    # The Route flow has no note action; "no_action" is always allowed and changes nothing.
    return {"action": "no_action", "why": "ZAG stand-in: nothing to move", "confidence": conf}


def actions_for(kind: str, stage: str, pack: dict, script: str) -> list[dict]:
    rule = SCRIPT["rules"].get(f"{kind}:{stage}")
    if rule is not None:
        return rule
    conf = {"low": 0.55, "low75": 0.75}.get(script, 0.9)
    if script == "noop":
        return [{"action": "no_action", "why": "ZAG stand-in: nothing to do", "confidence": conf}]
    allowed = pack.get("allowed_actions") or []
    if kind == "route" or NOTE.get(kind) not in allowed:
        return [_route_action(stage, conf)]
    return [{"action": NOTE[kind], "body": TEXT, "note": TEXT, "why": f"ZAG stand-in for {kind} {stage}",
             "confidence": conf}]


def _messy_text(kind, stage) -> str:
    with _lock:
        n = _messy_turn["n"]
        _messy_turn["n"] += 1
    return ["I looked at it and it seems fine.",                                  # not JSON
            json.dumps({"summary": "no list"}),                                    # no actions list
            json.dumps({"actions": [{"action": "delete_everything", "confidence": 0.99, "why": "x"}]}),
            ""][n % 4]


class StandInError(Exception):
    pass


def answer(url: str, body: dict, headers: dict) -> dict:
    """What desk_agent_providers._post returns, for a Claude (api.anthropic.com) or Grok (api.x.ai) call."""
    claude = "anthropic" in url
    model = str(body.get("model") or "")
    if claude:
        sysp = "".join(b.get("text", "") for b in body.get("system") or [] if isinstance(b, dict))
        user = str((body.get("messages") or [{}])[-1].get("content") or "")
    else:
        msgs = body.get("messages") or []
        sysp = str(msgs[0].get("content") or "") if msgs else ""
        user = str(msgs[-1].get("content") or "") if msgs else ""
    pack = _pack(user)
    kind, stage = str(pack.get("kind") or "?"), str(pack.get("stage") or "?")
    script = SCRIPT["name"]
    rec = {"n": len(CALLS) + 1, "api": "claude" if claude else "grok", "url": url, "model": model, "kind": kind,
           "stage": stage, "item_id": pack.get("item_id"), "mode": pack.get("mode"), "script": script,
           "key_kind": "x-api-key" if "x-api-key" in headers else ("bearer" if "Authorization" in headers else ""),
           "prompt": user}
    with _lock:
        CALLS.append(rec)
    import desk_agent_providers as prov
    if script == "error":
        raise prov.ProviderError("HTTP 500: stand-in server error")
    if script == "slow":
        raise prov.ProviderError("request failed: timed out (stand-in)")
    text = _messy_text(kind, stage) if script == "messy" else json.dumps(
        {"actions": actions_for(kind, stage, pack, script), "summary": f"ZAG stand-in {kind}/{stage}"})
    tin, tout = max(1, (len(sysp) + len(user)) // 4), max(1, len(text) // 4)
    rec["reply"] = text[:400]
    if claude:
        return {"id": f"msg_zag_{rec['n']}", "type": "message", "role": "assistant", "model": model,
                "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                "usage": {"input_tokens": tin, "output_tokens": tout,
                          "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}}
    return {"id": f"chatcmpl-zag-{rec['n']}", "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": tin, "completion_tokens": tout}}


def install() -> None:
    """Replace desk_agent_providers._post — every agent AI call now lands in answer()."""
    import desk_agent_providers as prov
    prov._post = answer
