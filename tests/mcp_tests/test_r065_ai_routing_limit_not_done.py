"""R-065 (2026-09-29, found by E2E MILES-04): when Claude refused the AI
Routing run ("You've hit your session limit · resets 8:50am"), the worker
still finished with "✅ DONE" and the Route tab showed success over an
unchanged route. Now a usage-limit / is_error reply with no route saved by
this run finishes as an error with Claude's own words."""
import pathlib
import re

SRC = (pathlib.Path(__file__).resolve().parents[2] / "ai_prowler_mcp.py").read_text(encoding="utf-8")
BODY = SRC[SRC.index("def _ai_routing_worker("):SRC.index("def start_ai_routing(")]


def _limit_re():
    m = re.search(r'_re_auth\.search\(\s*r"(hit your.*?)"\s*r"(.*?)",', BODY, re.S)
    assert m, "limit pattern not found in _ai_routing_worker"
    return re.compile(m.group(1) + m.group(2), re.I)


def test_limit_messages_match():
    rx = _limit_re()
    for msg in ("You've hit your session limit · resets 8:50am (America/New_York)",
                "You've hit your weekly limit", "Claude usage limit reached",
                "Your credit balance is too low to access the Anthropic API"):
        assert rx.search(msg), msg


def test_normal_ai_summary_does_not_match():
    rx = _limit_re()
    ok = ("Route applied for 2026-09-29 with no violations. All three jobs that day are Soft type "
          "with no fixed time windows, so the order was chosen purely on real drive times.")
    assert not rx.search(ok)


def test_error_only_when_no_route_saved_and_before_done():
    i_err = BODY.index("AI Routing did not run")
    i_done = BODY.index('_finish("done", final_text)')
    assert i_err < i_done
    assert "if not _route_saved and (_run_is_error or" in BODY
    assert '_run_is_error = bool(parsed.get("is_error"))' in BODY
