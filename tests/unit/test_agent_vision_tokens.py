"""How long a Claude answer may be, and what happens when one is cut off.

2026-11-19 (David): the Electrical AI Auto Run, 17 counts with evidence, failed as "didn't answer with JSON".
2026-11-20 (David: "let's don't put limits on AI for tokens, that is done with the day limit"): an Inspection review
on Opus 5.5 was "cut off at the 1500-token limit (0 characters came back)" - the model reasons first. Every Claude
call now gets the model's full output room (the daily budget caps the spend), and a cut-off call's tokens are counted.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import desk_agent_providers as prov  # noqa: E402


@pytest.fixture
def sent(monkeypatch):
    class Calls(list):
        reply = None
        fail_over = None              # max_tokens above which the fake API answers 400
    calls = Calls()

    def fake_post(url, body, headers):
        calls.append(body)
        if calls.fail_over and body["max_tokens"] > calls.fail_over:
            raise prov.ProviderError('HTTP 400: {"type":"error","error":{"type":"invalid_request_error",'
                                     '"message":"max_tokens: 32000 > 16000, which is the maximum allowed"}}')
        return calls.reply

    calls.reply = {"content": [{"type": "text", "text": '{"ok": 1}'}], "stop_reason": "end_turn",
                   "usage": {"input_tokens": 10, "output_tokens": 5}}
    monkeypatch.setattr(prov, "_post", fake_post)
    monkeypatch.setattr(prov, "_key", lambda name: "sk-test")
    monkeypatch.setattr(prov, "_cfg", lambda: {})
    return calls


IMG = [{"media_type": "image/png", "data": "aGk="}]


def test_every_claude_call_gets_the_full_room(sent):
    prov._claude_api("sys", "count", "claude-opus-5-5", images=IMG)
    prov._claude_api("sys", "hello", "claude-opus-5-5")
    assert [c["max_tokens"] for c in sent] == [32000, 32000]          # no 1500 / 4096 caps any more
    assert prov.HTTP_TIMEOUT >= 600                                  # a long answer has time to come back


def test_a_cut_off_answer_says_so_and_carries_what_it_cost(sent):
    sent.reply = {"content": [{"type": "thinking", "thinking": "..."}], "stop_reason": "max_tokens",
                  "usage": {"input_tokens": 10, "output_tokens": 32000}}
    with pytest.raises(prov.ProviderError, match=r"cut off at the 32000-token limit \(0 characters came back\)") as e:
        prov._claude_api("sys", "count", "claude-opus-5-5", images=IMG)
    assert e.value.usage == {"input": 10, "cache_read": 0, "cache_write": 0, "output": 32000}


def test_a_model_with_less_room_is_asked_again_with_less(sent):
    sent.fail_over = 16000
    text, usage = prov._claude_api("sys", "hello", "claude-haiku-5-5")
    assert text == '{"ok": 1}' and [c["max_tokens"] for c in sent] == [32000, prov.FALLBACK_MAX_TOKENS]


def test_a_limit_can_still_be_set_in_the_config(sent, monkeypatch):
    monkeypatch.setattr(prov, "_cfg", lambda: {"agent_max_tokens": 4000})
    prov._claude_api("sys", "hello", "claude-opus-5-5")
    assert sent[-1]["max_tokens"] == 4000
