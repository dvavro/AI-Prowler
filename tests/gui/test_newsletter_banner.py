"""
tests/gui/test_newsletter_banner.py
====================================
Tests for the Home tab newsletter opt-in banner (v8.1).

Covers:
  NL-01  _should_show_newsletter_banner — pure decision logic (no Tk needed)
  NL-02  _load_newsletter_state / _save_newsletter_state — round-trip, and
         graceful handling of a missing/corrupt state file
  NL-03  _build_newsletter_banner — banner renders when not subscribed,
         is absent when subscribed, reappears after a session-only dismiss
  NL-04  _newsletter_do_subscribe — success path persists state and hides
         the banner; failure path leaves the banner up and re-enables the
         button; network payload shape sent to the Worker

Run:  run_tests.bat tests\\gui\\test_newsletter_banner.py -v
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import rag_gui as gui_mod


# ─────────────────────────────────────────────────────────────────────────────
# NL-01 — pure decision logic, no GUI/display needed at all
# ─────────────────────────────────────────────────────────────────────────────

class TestShouldShowNewsletterBanner:

    def test_NL_01_shows_when_never_subscribed_and_not_dismissed(self):
        state = {'subscribed': False, 'email': ''}
        assert gui_mod.RAGGui._should_show_newsletter_banner(state, False) is True

    def test_NL_01_hidden_when_subscribed(self):
        state = {'subscribed': True, 'email': 'david@example.com'}
        # Even if not dismissed this session — subscribed always wins.
        assert gui_mod.RAGGui._should_show_newsletter_banner(state, False) is False

    def test_NL_01_hidden_when_dismissed_this_session_and_not_subscribed(self):
        state = {'subscribed': False, 'email': ''}
        assert gui_mod.RAGGui._should_show_newsletter_banner(state, True) is False

    def test_NL_01_subscribed_wins_even_if_also_marked_dismissed(self):
        state = {'subscribed': True, 'email': 'david@example.com'}
        assert gui_mod.RAGGui._should_show_newsletter_banner(state, True) is False

    def test_NL_01_missing_subscribed_key_defaults_to_show(self):
        # Defensive: a malformed state dict should still resolve to "show",
        # matching _load_newsletter_state()'s own default of subscribed=False.
        assert gui_mod.RAGGui._should_show_newsletter_banner({}, False) is True


# ─────────────────────────────────────────────────────────────────────────────
# NL-02 — local state persistence
# ─────────────────────────────────────────────────────────────────────────────

class TestNewsletterStatePersistence:

    def test_NL_02_load_defaults_when_no_file_exists(self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        state = gui.app._load_newsletter_state()
        assert state == {'subscribed': False, 'email': ''}

    def test_NL_02_save_then_load_round_trips(self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._save_newsletter_state(True, 'david@example.com')

        state = gui.app._load_newsletter_state()
        assert state == {'subscribed': True, 'email': 'david@example.com'}

        # File actually landed where expected.
        expected_path = tmp_path / '.ai-prowler' / 'newsletter_subscription.json'
        assert expected_path.exists()
        on_disk = json.loads(expected_path.read_text(encoding='utf-8'))
        assert on_disk['subscribed'] is True
        assert on_disk['email'] == 'david@example.com'

    def test_NL_02_corrupt_file_falls_back_to_defaults_without_raising(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        p = tmp_path / '.ai-prowler' / 'newsletter_subscription.json'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{not valid json", encoding='utf-8')

        state = gui.app._load_newsletter_state()
        assert state == {'subscribed': False, 'email': ''}


# ─────────────────────────────────────────────────────────────────────────────
# NL-03 — banner rendering (real Tk widgets via the `gui` fixture)
# ─────────────────────────────────────────────────────────────────────────────

class TestNewsletterBannerRendering:

    def test_NL_03_banner_visible_by_default_on_fresh_install(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()

        children = gui.app._newsletter_frame.winfo_children()
        assert len(children) > 0, "banner should render for a never-subscribed install"

    def test_NL_03_banner_absent_when_already_subscribed(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._save_newsletter_state(True, 'david@example.com')
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()

        children = gui.app._newsletter_frame.winfo_children()
        assert len(children) == 0, "banner must not show once the user has subscribed"

    def test_NL_03_dismiss_hides_for_this_session_only(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()
        assert len(gui.app._newsletter_frame.winfo_children()) > 0

        # Simulate clicking dismiss.
        gui.app._newsletter_dismissed_this_session = True
        gui.app._build_newsletter_banner()
        gui.pump()
        assert len(gui.app._newsletter_frame.winfo_children()) == 0

        # Per spec: a NEW session (fresh dismissed flag) shows it again —
        # dismiss is not a permanent "never ask again."
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()
        assert len(gui.app._newsletter_frame.winfo_children()) > 0

    def test_NL_03_rebuild_is_idempotent_no_duplicate_widgets(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()
        first_count = len(gui.app._newsletter_frame.winfo_children())

        gui.app._build_newsletter_banner()
        gui.pump()
        second_count = len(gui.app._newsletter_frame.winfo_children())

        assert first_count == second_count > 0


# ─────────────────────────────────────────────────────────────────────────────
# NL-04 — subscribe flow (network mocked — no real HTTP call)
# ─────────────────────────────────────────────────────────────────────────────

def _fake_urlopen_success(*args, **kwargs):
    resp = MagicMock()
    resp.read.return_value = json.dumps(
        {'ok': True, 'email': 'david@example.com', 'status': 'active'}
    ).encode('utf-8')
    resp.__enter__ = lambda self: resp
    resp.__exit__ = lambda self, *a: False
    return resp


def _fake_urlopen_failure(*args, **kwargs):
    resp = MagicMock()
    resp.read.return_value = json.dumps(
        {'ok': False, 'reason': 'invalid_email'}
    ).encode('utf-8')
    resp.__enter__ = lambda self: resp
    resp.__exit__ = lambda self, *a: False
    return resp


class TestNewsletterSubscribeFlow:

    def test_NL_04_successful_subscribe_persists_state_and_hides_banner(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()

        with patch('urllib.request.urlopen', side_effect=_fake_urlopen_success):
            # Call the worker function directly (synchronously) rather than
            # through threading.Thread, so the test doesn't need to poll/wait.
            gui.app._newsletter_do_subscribe('david@example.com')
        gui.pump()

        state = gui.app._load_newsletter_state()
        assert state['subscribed'] is True
        assert state['email'] == 'david@example.com'
        assert len(gui.app._newsletter_frame.winfo_children()) == 0

    def test_NL_04_failed_subscribe_keeps_banner_and_does_not_persist(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()

        with patch('urllib.request.urlopen', side_effect=_fake_urlopen_failure):
            gui.app._newsletter_do_subscribe('not-a-real-email')
        gui.pump()

        state = gui.app._load_newsletter_state()
        assert state['subscribed'] is False
        # Banner must still be present — this is the whole point of the
        # "keeps showing until they actually subscribe" design.
        assert len(gui.app._newsletter_frame.winfo_children()) > 0

    def test_NL_04_network_exception_does_not_crash_and_keeps_banner(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()

        with patch('urllib.request.urlopen', side_effect=OSError("network down")):
            # Must not raise.
            gui.app._newsletter_do_subscribe('david@example.com')
        gui.pump()

        state = gui.app._load_newsletter_state()
        assert state['subscribed'] is False
        assert len(gui.app._newsletter_frame.winfo_children()) > 0

    def test_NL_04_payload_sent_to_worker_has_expected_shape(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # Give the install a known install_id so we can assert it's included.
        gui.app._install_id_path = tmp_path / '.ai-prowler' / 'install_id'
        gui.app._install_id_path.parent.mkdir(parents=True, exist_ok=True)
        gui.app._install_id_path.write_text('abc123deadbeef00', encoding='utf-8')

        captured = {}

        def _capture_urlopen(req, timeout=None):
            captured['url'] = req.full_url
            captured['body'] = json.loads(req.data.decode('utf-8'))
            return _fake_urlopen_success()

        with patch('urllib.request.urlopen', side_effect=_capture_urlopen):
            gui.app._newsletter_do_subscribe('david@example.com')
        gui.pump()

        assert captured['url'].endswith('/newsletter/subscribe')
        assert captured['body']['email'] == 'david@example.com'
        assert captured['body']['install_id'] == 'abc123deadbeef00'
        assert captured['body']['source'] == 'home_tab_banner'
        assert 'version' in captured['body']
        assert 'os' in captured['body']
