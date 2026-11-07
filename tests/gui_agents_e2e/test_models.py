"""AG-MD (AGENTS_GUI_E2E_TEST_SPEC.md §5.4) — which AI model each step uses. The table is written out here on purpose, not
imported from the code, so a change to the code's mapping fails here and gets seen. Every one of the 33 stages is checked
against the code's mapping; the live runs go through the stand-in AI for one stage per agent (a live run of all 33 needs
the AG-ST stage grid's triggers).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import desk_agent_providers as prov
from test_matrix import KIND, TARGET, _api_calls, all_off, setup, trigger

SONNET, HAIKU, OPUS = "claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5-5"
COMPLEX = [("ticket", "resolution"), ("booking", "decide"), ("booking", "offer"), ("job", "schedule"),
           *[("route", s) for s in ("sort", "plan", "route", "send", "replan")],
           ("hr", "timeoff"), ("hr", "answer"), ("hr", "incidents")]
CUSTOMER = [("ticket", "first_reply"), ("ticket", "follow_through"), ("booking", "reply"), ("booking", "track"),
            ("job", "quotes"), ("job", "collect"), ("job", "repeat")]
INTERNAL = [("ticket", "intake"), ("ticket", "learn"), ("booking", "check"), ("booking", "learn"), ("job", "prep"),
            ("job", "onsite"), ("job", "closeout"), ("job", "learn"), ("hr", "recruit"), ("hr", "onboard"),
            ("hr", "timeclock"), ("hr", "compliance"), ("hr", "offboard"), ("hr", "learn")]
STRONG = set(COMPLEX + CUSTOMER)


def _config(box, **vals):
    """The models live in the sandbox's task_automation_config.json, read fresh on every call: no restart (AG-MD-07)."""
    p = Path(box.control("GET", "/state")["sandbox"]) / "task_automation_config.json"
    cfg = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    cfg.update(vals)
    p.write_text(json.dumps(cfg), encoding="utf-8")


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    _config(b, agent_claude_model=SONNET, agent_claude_model_light=HAIKU)
    yield b
    _config(b, agent_claude_model=SONNET, agent_claude_model_light=HAIKU)
    all_off(b)


def test_md_the_table_covers_33_stages_once():
    assert (len(COMPLEX), len(CUSTOMER), len(INTERNAL)) == (12, 7, 14)
    assert len(set(COMPLEX + CUSTOMER + INTERNAL)) == 33


@pytest.mark.parametrize("kind,stage", COMPLEX + CUSTOMER + INTERNAL, ids=lambda x: str(x))
def test_md_01_02_each_stage_gets_the_written_down_model(kind, stage):
    cfg = {"agent_claude_model": OPUS, "agent_claude_model_light": HAIKU}
    want = OPUS if (kind, stage) in STRONG else HAIKU
    assert prov.model_for_item("claude_api", {"kind": kind, "stage": stage}, cfg) == want


@pytest.mark.parametrize("kind,stage", COMPLEX + CUSTOMER + INTERNAL, ids=lambda x: str(x))
def test_md_03_04_light_blank_and_grok_use_one_model(kind, stage):
    item = {"kind": kind, "stage": stage}
    assert prov.model_for_item("claude_api", item, {"agent_claude_model": SONNET, "agent_claude_model_light": ""}) == SONNET
    assert prov.model_for_item("grok_api", item, {"agent_grok_model": "grok-4.3"}) == "grok-4.3"


LIVE = [(s, "HAIKU" if (KIND[s], TARGET[s]) in INTERNAL else "MAIN") for s in ("SD", "BK", "JB", "RT")]


def _models(box, section):
    setup(box, section, "SUG")
    trigger(box, section)
    box.agents_pass()
    return {c["model"] for c in _api_calls(box, KIND[section])}


@pytest.mark.parametrize("section,group", LIVE)
def test_md_01_live_model_in_the_ai_log(box, section, group):
    assert _models(box, section) == {HAIKU if group == "HAIKU" else SONNET}


def test_md_01_live_hr(business):
    all_off(business)
    assert _models(business, "HR") == {HAIKU}
    all_off(business)


def test_md_04_live_grok(box):
    box.settings(desk={"agent_provider": "grok_api"})
    assert _models(box, "SD") == {"grok-4.3"}
    assert {c["api"] for c in _api_calls(box, "ticket")} == {"grok"}


def test_md_05_no_key_makes_no_api_call(solo):
    all_off(solo)
    setup(solo, "SD", "SUG")
    solo.no_key()
    try:
        trigger(solo, "SD")
        solo.agents_pass()
        assert not _api_calls(solo, "ticket")
    finally:
        solo.no_key(False)
        all_off(solo)


@pytest.mark.parametrize("state", ["PRAC", "SUG", "AUTO"])
def test_md_06_same_model_in_every_mode(box, state):
    setup(box, "SD", state)
    trigger(box, "SD")
    box.agents_pass()
    assert {c["model"] for c in _api_calls(box, "ticket")} == {SONNET}    # a customer message: never the light model


def test_md_07_a_model_change_needs_no_restart(box):
    assert _models(box, "SD") == {SONNET}
    box.ai_reset("good")
    _config(box, agent_claude_model=OPUS)
    assert _models(box, "SD") == {OPUS}


@pytest.mark.parametrize("state", ["OFF"])
def test_md_09_off_makes_no_ai_call(box, state):
    setup(box, "SD", state)
    trigger(box, "SD")
    box.agents_pass()
    assert not _api_calls(box, "ticket")
