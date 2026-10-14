"""
GUI tests — Grok API-key auth in the Autonomous Task Queue panel (2026-10-12).

Drives the real panel through the shared `gui` fixture (see
tests/gui/conftest.py), following the patterns in test_task_queue_panel.py.
The `_isolate_tqa_paths` autouse fixture in that module also covers this
file (same directory), so the Grok key file is isolated too.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import task_queue_automation as tqa


def _pump(gui):
    gui.root.update()
    gui.root.update_idletasks()


# ── Grok radio ─────────────────────────────────────────────────────────────

def test_grok_radio_selects_and_shows_key_row(gui):
    gui.app._tqa_auth_var.set("api_key_grok")
    _pump(gui)
    assert gui.app._tqa_auth_var.get() == "api_key_grok"
    assert gui.app._tqa_row4.winfo_ismapped()
    assert gui.app._tqa_btn_get_api_key.winfo_ismapped()
    assert not gui.app._tqa_btn_get_token.winfo_ismapped()


def test_grok_hint_mentions_xai_console(gui):
    gui.app._tqa_auth_var.set("api_key_grok")
    _pump(gui)
    hint = gui.app._tqa_hint_var.get()
    assert "console.x.ai" in hint
    assert "Grok" in hint


def test_get_key_button_label_follows_provider(gui):
    gui.app._tqa_auth_var.set("api_key_grok")
    _pump(gui)
    assert "Grok" in gui.app._tqa_btn_get_api_key.cget("text")
    gui.app._tqa_auth_var.set("api_key")
    _pump(gui)
    assert "Claude" in gui.app._tqa_btn_get_api_key.cget("text")


def test_masked_field_reflects_selected_provider(gui):
    tqa.save_api_key("grok-secret", "grok")
    gui.app._tqa_auth_var.set("api_key")
    _pump(gui)
    # Anthropic has no key saved — field must be empty, not grok's dots.
    assert gui.app._tqa_apikey_var.get() == ""
    gui.app._tqa_auth_var.set("api_key_grok")
    _pump(gui)
    assert gui.app._tqa_apikey_var.get() == "\u2022" * 8


# ── Save / clear are provider-scoped ───────────────────────────────────────

def test_save_key_writes_grok_file_not_anthropic(gui, dialogs):
    gui.app._tqa_auth_var.set("api_key_grok")
    _pump(gui)
    gui.app._tqa_apikey_var.set("xai-test-key")
    gui.app._tqa_save_api_key()
    _pump(gui)
    assert tqa.load_api_key("grok") == "xai-test-key"
    assert tqa.has_api_key("anthropic") is False


def test_clear_key_removes_only_grok_key(gui, dialogs):
    tqa.save_api_key("anthropic-key", "anthropic")
    tqa.save_api_key("grok-key", "grok")
    gui.app._tqa_auth_var.set("api_key_grok")
    _pump(gui)
    dialogs.set_response("askyesno", True)
    dialogs.reset()
    gui.app._tqa_clear_api_key()
    _pump(gui)
    assert tqa.has_api_key("grok") is False
    assert tqa.has_api_key("anthropic") is True


# ── Provider persists through Save & Apply ─────────────────────────────────

def test_switching_to_grok_persists_provider_on_save(gui, monkeypatch):
    monkeypatch.setattr(tqa, "uninstall_scheduled_task",
                        lambda: (True, "not present"))
    gui.app._tqa_auth_var.set("api_key_grok")
    gui.app._tqa_save_and_apply()
    _pump(gui)
    saved = tqa.load_config()
    assert saved["use_api_key"] is True
    assert saved["api_key_provider"] == "grok"


def test_status_display_names_grok_provider(gui, monkeypatch):
    monkeypatch.setattr(tqa, "uninstall_scheduled_task",
                        lambda: (True, "not present"))
    tqa.save_api_key("xai-k", "grok")
    gui.app._tqa_auth_var.set("api_key_grok")
    gui.app._tqa_save_and_apply()
    gui.app._tqa_refresh_status_display()
    _pump(gui)
    assert "Grok (xAI)" in gui.app._tqa_token_var.get()
