"""
tests/test_tool_config_store.py
===============================
Regression tests for the MCP Tool Configuration save/reset guarantee:

    Saving and Reset to Defaults must NEVER remove (or modify, or create)
    any config.json setting -- they may only update tool_config.json.

Each test snapshots every file in the state directory before and after
the operation and asserts byte-identical contents for everything except
tool_config.json (and its timestamped backups).
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tool_config_store import (
    _checked_write,
    load_tool_config,
    reset_disabled_tools,
    save_disabled_tools,
    tool_config_path,
)


@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    return tmp_path


def _seed_settings(state_dir):
    """Populate a realistic state dir, mimicking David's real settings."""
    (state_dir / "config.json").write_text(
        json.dumps(
            {
                "owner": "David",
                "theme": "dark",
                "remote_access": {"enabled": True, "port": 8000},
                "nested": {"a": 1, "b": [1, 2, 3]},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (state_dir / "remote_access.json").write_text('{"token": "abc123"}', encoding="utf-8")
    (state_dir / "claude_mcp_config.json").write_text('{"x": 1}', encoding="utf-8")
    (state_dir / "setup_progress.json").write_text('{"done": true}', encoding="utf-8")
    (state_dir / "scheduler_config.json").write_text('{"jobs": []}', encoding="utf-8")


def _snapshot(state_dir):
    return {
        p.name: p.read_bytes()
        for p in state_dir.iterdir()
        if p.is_file() and not p.name.startswith("tool_config.json.bak_")
    }


def _assert_only_tool_config_changed(before, state_dir):
    after = _snapshot(state_dir)
    for name, content in before.items():
        if name == "tool_config.json":
            continue  # the one file we are allowed to change
        assert name in after, "file %r was DELETED by save/reset!" % name
        assert after[name] == content, "file %r was MODIFIED by save/reset!" % name
    # No new files except tool_config.json and its backups.
    for name in after:
        assert name in before or name in ("tool_config.json",) or name.startswith(
            "tool_config.json.bak_"
        ), "unexpected new file %r created by save/reset!" % name


def test_save_never_touches_config_json(state_dir):
    _seed_settings(state_dir)
    before = _snapshot(state_dir)

    save_disabled_tools(["tool_%d" % i for i in range(55)], mode="personal")

    _assert_only_tool_config_changed(before, state_dir)
    data = json.loads(tool_config_path().read_text(encoding="utf-8"))
    assert len(data["personal"]["disabled_tools"]) == 55
    assert data["server"]["disabled_tools"] == []


def test_reset_never_touches_config_json(state_dir):
    _seed_settings(state_dir)
    save_disabled_tools(["a", "b", "c"], mode="personal")
    before = _snapshot(state_dir)

    reset_disabled_tools(mode="personal")

    _assert_only_tool_config_changed(before, state_dir)
    assert load_tool_config()["personal"]["disabled_tools"] == []


def test_save_preserves_other_mode_and_unknown_keys(state_dir):
    _seed_settings(state_dir)
    save_disabled_tools(["server_tool_1"], mode="server")
    # Simulate a future/unknown key added by a newer version.
    raw = json.loads(tool_config_path().read_text(encoding="utf-8"))
    raw["future_key"] = {"hello": "world"}
    tool_config_path().write_text(json.dumps(raw, indent=2), encoding="utf-8")
    before = _snapshot(state_dir)

    save_disabled_tools(["p1", "p2"], mode="personal")

    _assert_only_tool_config_changed(before, state_dir)
    data = load_tool_config()
    assert data["server"]["disabled_tools"] == ["server_tool_1"]
    assert data["future_key"] == {"hello": "world"}
    assert data["personal"]["disabled_tools"] == ["p1", "p2"]


def test_checked_write_refuses_protected_files(state_dir, monkeypatch):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(state_dir))
    from tool_config_store import _state_dir

    with pytest.raises(RuntimeError):
        _checked_write(_state_dir() / "config.json", {})
    # config.json must not have been created.
    assert not (_state_dir() / "config.json").exists()


def test_round_trip_and_backup(state_dir):
    tools = ["create_job", "build_daily_route"]
    save_disabled_tools(tools, mode="personal")
    assert load_tool_config()["personal"]["disabled_tools"] == sorted(tools)
    # Second save creates a timestamped backup of the first.
    save_disabled_tools(tools + ["extra"], mode="personal")
    backups = list(state_dir.glob("tool_config.json.bak_*"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8"))["personal"][
        "disabled_tools"
    ] == sorted(tools)


def test_load_missing_or_corrupt_returns_blank(state_dir):
    assert load_tool_config()["personal"]["disabled_tools"] == []
    tool_config_path().write_text("{not valid json", encoding="utf-8")
    assert load_tool_config()["personal"]["disabled_tools"] == []
    # A corrupt file must not cause a save to wipe other settings files.
    _seed_settings(state_dir)
    before = _snapshot(state_dir)
    save_disabled_tools(["x"], mode="personal")
    _assert_only_tool_config_changed(before, state_dir)


# ── 2026-10-01 (Vicki): post-save check puts damaged settings back ──────────

def test_save_restores_config_json_if_wiped_during_save(state_dir, monkeypatch):
    """If anything empties or deletes config.json while Save runs, Save puts
    the user's settings back exactly as they were."""
    import tool_config_store as tcs
    _seed_settings(state_dir)
    (state_dir / "email_config.json").write_text('{"username": "v@x.com"}', encoding="utf-8")
    before = _snapshot(state_dir)

    real_write = tcs._checked_write

    def _write_then_damage(path, data):
        real_write(path, data)
        (state_dir / "config.json").write_text("", encoding="utf-8")   # emptied
        (state_dir / "email_config.json").unlink()                      # deleted

    monkeypatch.setattr(tcs, "_checked_write", _write_then_damage)
    save_disabled_tools(["a"], mode="personal")

    _assert_only_tool_config_changed(before, state_dir)


def test_save_failure_still_leaves_settings_intact(state_dir, monkeypatch):
    import tool_config_store as tcs
    _seed_settings(state_dir)
    before = _snapshot(state_dir)

    def _boom(path, data):
        (state_dir / "config.json").write_text("{broken", encoding="utf-8")
        raise OSError("disk full")

    monkeypatch.setattr(tcs, "_checked_write", _boom)
    with pytest.raises(OSError):
        save_disabled_tools(["a"], mode="personal")
    _assert_only_tool_config_changed(before, state_dir)


def test_restore_leaves_legitimately_changed_valid_settings_alone(state_dir):
    """A valid change made by another part of AI-Prowler during the save is kept."""
    import tool_config_store as tcs
    _seed_settings(state_dir)
    snap = tcs._protected_snapshot()
    (state_dir / "config.json").write_text('{"owner": "Vicki"}', encoding="utf-8")
    assert tcs._restore_if_damaged(snap) == []
    assert json.loads((state_dir / "config.json").read_text())["owner"] == "Vicki"


def test_gui_save_uses_tool_config_store_only():
    """The Settings panel's Save must go through tool_config_store, never a raw write."""
    src = (Path(__file__).resolve().parent.parent / "rag_gui.py").read_text(encoding="utf-8")
    i = src.index("def _save_tool_config():")
    body = src[i:src.index("def _reset_tool_config_defaults():", i)]
    assert "_tcs.save_disabled_tools(" in body
    assert "write_text" not in body and "open(" not in body
