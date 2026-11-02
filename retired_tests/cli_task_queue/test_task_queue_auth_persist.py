"""
GUI — picking an Auth option takes effect at once (2026-10-12, David's bug):
it's saved to the queue settings, and Test Setup checks the selected method.
Uses the shared `gui` fixture; credential paths are isolated by tests/conftest.py.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import task_queue_automation as tqa  # noqa: E402


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    h = tmp_path / ".ai-prowler"
    h.mkdir()
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", h)
    monkeypatch.setattr(tqa, "CONFIG_PATH", h / "task_automation_config.json")
    monkeypatch.setattr(tqa, "STATUS_PATH", h / "task_automation_last_run.json")


def _pump(gui):
    gui.root.update()
    gui.root.update_idletasks()


def test_selecting_subscription_saves_it(gui):
    gui.app._tqa_auth_var.set("api_key_grok")
    _pump(gui)
    c = tqa.load_config()
    assert c["use_api_key"] is True and c["api_key_provider"] == "grok"
    gui.app._tqa_auth_var.set("oauth")
    _pump(gui)
    assert tqa.load_config()["use_api_key"] is False


def test_test_setup_checks_the_selected_method(gui, monkeypatch):
    seen = {}

    def _fake(auth=None):
        seen["auth"] = auth
        return {"all_ok": True, "checks": []}
    monkeypatch.setattr(tqa, "dry_run_check", _fake)
    monkeypatch.setattr(tqa, "generate_mcp_config", lambda *a, **k: (False, "skip"))
    gui.app._tqa_auth_var.set("oauth")
    _pump(gui)
    gui.app._tqa_test_setup()
    _pump(gui)
    assert seen.get("auth") == "oauth"
