"""Claude calls stream (2026-11-21, David: AI Auto Measure/Count on the rev2 electrical plan "timed out" - the AI thought for
over 10 minutes without sending a byte, and the 600 s read timeout gave up). Streamed, the answer arrives in pieces
with pings, and _post still hands back the same whole message as before."""
import io
import json
import urllib.request

import pytest

import desk_agent_providers as prov

EVENTS = [
    ("message_start", {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant",
                                                             "content": [], "model": "claude-opus-5-5",
                                                             "stop_reason": None,
                                                             "usage": {"input_tokens": 1200, "output_tokens": 1,
                                                                       "cache_read_input_tokens": 300}}}),
    ("ping", {"type": "ping"}),
    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking",
                                                                                         "thinking": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0,
                             "delta": {"type": "thinking_delta", "thinking": "counting outlets…"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": '{"outl'}}),
    ("ping", {"type": "ping"}),
    ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": 'ets": 41}'}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 1}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 950}}),
    ("message_stop", {"type": "message_stop"}),
]


def _sse(events):
    out = []
    for name, data in events:
        out += [f"event: {name}\n", f"data: {json.dumps(data)}\n", "\n"]
    return out


def test_a_streamed_answer_is_put_back_together():                                  # CS-01
    msg = prov._read_claude_stream(_sse(EVENTS))
    assert msg["stop_reason"] == "end_turn"
    assert [b["type"] for b in msg["content"]] == ["thinking", "text"]
    assert msg["content"][1]["text"] == '{"outlets": 41}'
    assert msg["usage"] == {"input_tokens": 1200, "output_tokens": 950, "cache_read_input_tokens": 300}


def test_a_stream_that_stops_early_or_errors_says_so():                              # CS-02
    with pytest.raises(prov.ProviderError, match="connection dropped"):
        prov._read_claude_stream(_sse(EVENTS[:8]))
    with pytest.raises(prov.ProviderError, match="overloaded_error"):
        prov._read_claude_stream(_sse(EVENTS[:2] + [("error", {"type": "error", "error": {
            "type": "overloaded_error", "message": "Overloaded"}})]))
    with pytest.raises(prov.ProviderError, match="empty"):
        prov._read_claude_stream([])


def test_claude_calls_stream_and_return_the_whole_message(monkeypatch):            # CS-03
    sent = {}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        sent["body"], sent["headers"], sent["timeout"] = json.loads(req.data), dict(req.header_items()), timeout
        return Resp("".join(_sse(EVENTS)).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(prov, "_key", lambda p: "sk-test")
    text, usage = prov._claude_api("system", "read the plan", "claude-opus-5-5",
                                   images=[{"media_type": "image/png", "data": "aGk="}])
    assert sent["body"]["stream"] is True and sent["timeout"] == prov.HTTP_TIMEOUT
    assert text == '{"outlets": 41}'
    assert usage == {"input": 1500, "cache_read": 300, "cache_write": 0, "output": 950}


GROK = ['data: {"id":"c1","model":"grok-5","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}\n', "\n",
        'data: {"id":"c1","model":"grok-5","choices":[{"index":0,"delta":{"reasoning_content":"hmm"}}]}\n', "\n",
        'data: {"id":"c1","model":"grok-5","choices":[{"index":0,"delta":{"content":"{\\"actions\\": "}}]}\n', "\n",
        'data: {"id":"c1","model":"grok-5","choices":[{"index":0,"delta":{"content":"[]}"},"finish_reason":"stop"}]}\n',
        "\n", 'data: {"id":"c1","model":"grok-5","choices":[],"usage":{"prompt_tokens":800,"completion_tokens":40}}\n',
        "\n", "data: [DONE]\n"]


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_grok_and_muse_answers_stream_too(monkeypatch):                                # CS-05
    msg = prov._read_openai_stream(GROK)
    assert msg["choices"][0]["message"]["content"] == '{"actions": []}'                 # reasoning left out
    assert msg["choices"][0]["finish_reason"] == "stop" and msg["usage"]["completion_tokens"] == 40
    with pytest.raises(prov.ProviderError, match="connection dropped"):
        prov._read_openai_stream(GROK[:4])
    with pytest.raises(prov.ProviderError, match="rate limited"):
        prov._read_openai_stream(['data: {"error": {"message": "rate limited"}}\n'])
    sent = []

    def fake_urlopen(req, timeout):
        sent.append(json.loads(req.data))
        return _Resp("".join(GROK).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(prov, "_key", lambda p: "key")
    for provider in ("grok_api", "muse_api"):
        text, usage = prov.ask_vision(provider, "system", "read it", [{"media_type": "image/png", "data": "aGk="}])
        assert text == '{"actions": []}' and usage == {"input": 800, "output": 40}
    assert all(b["stream"] is True and b["stream_options"] == {"include_usage": True} for b in sent)
    assert len(sent) == 2


def test_a_service_that_wont_stream_is_asked_the_old_way(monkeypatch):                # CS-06
    import urllib.error
    sent = []

    def fake_urlopen(req, timeout):
        body = json.loads(req.data)
        sent.append(body)
        if body.get("stream"):
            raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {}, io.BytesIO(b"stream not supported"))
        return _Resp(json.dumps({"choices": [{"message": {"content": "ok"}}],
                                 "usage": {"prompt_tokens": 5, "completion_tokens": 1}}).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(prov, "_key", lambda p: "key")
    assert prov.ask("muse_api", "s", "u") == ("ok", {"input": 5, "output": 1})
    assert [b["stream"] for b in sent] == [True, False]


def test_other_providers_and_stand_ins_are_unchanged(monkeypatch):                    # CS-04
    calls = []
    monkeypatch.setattr(prov, "_post_claude_stream", lambda *a: calls.append("stream"))

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: Resp(b'{"choices": []}'))
    assert prov._post("https://api.x.ai/v1/chat/completions", {"model": "grok"}, {}) == {"choices": []}
    assert prov._post(prov.CLAUDE_URL, {"model": "m", "stream": False}, {}) == {"choices": []}   # asked not to stream
    assert calls == []
