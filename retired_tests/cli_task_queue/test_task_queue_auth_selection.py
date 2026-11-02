"""
Test Setup checks only the credential the SELECTED auth method needs
(David's bug report, 2026-10-12: Subscription selected + token OK, yet the dry
run failed on "Grok API key not set" — it used the previously SAVED method).

  oauth     -> Claude Code CLI + Claude Code token   (no API key)
  anthropic -> Claude Code CLI + Claude API key      (no token)
  grok      -> xAI reachable   + Grok API key        (no CLI, no token)

No network, no real files (fake HOME). Run:
  run_tests.bat tests\\analysis\\test_task_queue_auth_selection.py -v
"""
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import task_queue_automation as tqa  # noqa: E402


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    h = tmp_path / ".ai-prowler"
    monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
    for name, rel in (("AI_PROWLER_HOME", ""), ("CONFIG_PATH", "task_automation_config.json"),
                      ("STATUS_PATH", "task_automation_last_run.json"),
                      ("AUDIT_LOG_PATH", "autonomous_run_audit.log"),
                      ("API_KEY_PATH", "claude_api_key.txt"), ("GROK_API_KEY_PATH", "grok_api_key.txt")):
        monkeypatch.setattr(tqa, name, h / rel if rel else h)
    h.mkdir(parents=True)
    # the SAVED setting is Grok — the bug scenario
    tqa.save_config({**tqa.DEFAULT_CONFIG, "use_api_key": True, "api_key_provider": "grok"})

    def _net(req, timeout=None):
        raise urllib.error.HTTPError(getattr(req, "full_url", str(req)), 401, "nope", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", _net)
    monkeypatch.setattr(tqa.shutil, "which", lambda name: r"C:\fake\claude.exe")

    class _R:
        returncode, stdout, stderr = 0, "1.0.0 (Claude Code)", ""
    monkeypatch.setattr(tqa.subprocess, "run", lambda *a, **k: _R())
    monkeypatch.setattr(tqa, "check_token_expiry", lambda: {"status": "ok", "detail": "Token OK"})


def _names(report):
    return {c["name"] for c in report["checks"]}


def test_subscription_needs_no_api_key_even_when_grok_was_saved():
    r = tqa.dry_run_check(auth="oauth")
    n = _names(r)
    assert "Claude Code auth token" in n and "Claude Code CLI on PATH" in n
    assert not {"Grok API key (xAI)", "Claude API key", "xAI API reachable"} & n, n
    tok = next(c for c in r["checks"] if c["name"] == "Claude Code auth token")
    assert tok["ok"] is True


def test_claude_api_key_needs_no_token_or_grok():
    tqa.save_api_key("sk-ant-x", "anthropic")
    r = tqa.dry_run_check(auth="anthropic")
    n = _names(r)
    assert "Claude API key" in n and "Claude Code CLI on PATH" in n
    assert not {"Claude Code auth token", "Grok API key (xAI)", "xAI API reachable"} & n, n
    assert next(c for c in r["checks"] if c["name"] == "Claude API key")["ok"] is True


def test_grok_needs_no_cli_or_token():
    tqa.save_api_key("xai-x", "grok")
    r = tqa.dry_run_check(auth="grok")
    n = _names(r)
    assert {"xAI API reachable", "Grok API key (xAI)"} <= n
    assert not {"Claude Code CLI on PATH", "Claude Code auth token", "Claude API key",
                "AI-Prowler Skill file"} & n, n


def test_no_argument_still_uses_the_saved_setting():
    assert "Grok API key (xAI)" in _names(tqa.dry_run_check())


def test_panel_saves_the_auth_choice_and_tests_the_selection():
    src = (Path(__file__).resolve().parents[2] / "rag_gui.py").read_text(encoding="utf-8")
    assert "report = _tqa.dry_run_check(auth=_tqa_selected_provider())" in src
    i = src.index("def _tqa_on_auth_change(")
    assert "_tqa_persist_auth(_prov)" in src[i:i + 4000]
    j = src.index("def _tqa_persist_auth(prov):")
    body = src[j:j + 2500]
    assert '_tqa.save_config(cfg)' in body and "_tqa.install_wrapper_script(" in body
