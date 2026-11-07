"""David 4 Nov: Settings said 0 of 39, Home and Small Business said on. A group's switch and its tool list can't disagree."""
import json

import pytest

import mcp_tool_catalog as tc


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    import importlib
    import tool_config_store as tcs
    importlib.reload(tcs)
    tcs.test_dir = tmp_path
    yield tcs
    monkeypatch.delenv("AIPROWLER_TEST_STATE_DIR")
    importlib.reload(tcs)


def _tools(group, mode="personal"):
    return [n for n in tc.tools_in_category(group) if mode in tc.modes_of(n) and not tc.is_locked(n)]


def _write(store, group_on, listed, mode="personal"):
    (store.test_dir / "tool_config.json").write_text(json.dumps({
        "schema_version": 1, "optional_groups": {mode: {"service_desk": group_on}}, mode: {"disabled_tools": listed}}), encoding="utf-8")


def _listed(store, mode="personal"):
    return set(json.loads((store.test_dir / "tool_config.json").read_text(encoding="utf-8"))[mode]["disabled_tools"])


@pytest.mark.parametrize("mode", ["personal", "server"])
def test_davids_file_reads_as_off_and_stays_that_way(store, mode):
    _write(store, True, _tools("service_desk", mode) + ["send_sms"], mode)
    assert store.group_enabled(mode, "service_desk") is False
    assert store.saved_group_choice(mode, "service_desk") is False


def test_turning_on_from_setup_lists_the_tools_on_again(store):
    keep = "send_sms"
    _write(store, False, _tools("service_desk") + [keep])
    store.set_group_enabled("personal", "service_desk", True)
    assert store.group_enabled("personal", "service_desk") is True
    assert _listed(store) == {keep}


def test_one_tool_turned_off_by_hand_stays_off(store):
    one = _tools("service_desk")[0]
    _write(store, True, [one])
    store.set_group_enabled("personal", "service_desk", True)
    assert store.group_enabled("personal", "service_desk") is True and _listed(store) == {one}


def test_turning_off_leaves_the_list_alone(store):
    _write(store, True, [])
    store.set_group_enabled("personal", "service_desk", False)
    assert store.group_enabled("personal", "service_desk") is False


def test_the_other_mode_is_untouched(store):
    tools = _tools("service_desk", "server")
    (store.test_dir / "tool_config.json").write_text(json.dumps({
        "schema_version": 1, "optional_groups": {"server": {"service_desk": False}, "personal": {"service_desk": False}},
        "server": {"disabled_tools": tools}, "personal": {"disabled_tools": _tools("service_desk")}}), encoding="utf-8")
    store.set_group_enabled("personal", "service_desk", True)
    assert _listed(store, "server") == set(tools) and store.group_enabled("server", "service_desk") is False
