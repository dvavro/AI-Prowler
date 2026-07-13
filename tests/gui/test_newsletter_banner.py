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
        assert state == {'subscribed': False, 'email': '', 'awaiting_confirmation': False}

    def test_NL_02_save_then_load_round_trips(self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._save_newsletter_state(True, 'david@example.com', awaiting_confirmation=True)

        state = gui.app._load_newsletter_state()
        assert state == {'subscribed': True, 'email': 'david@example.com',
                         'awaiting_confirmation': True}

        # File actually landed where expected.
        expected_path = tmp_path / '.ai-prowler' / 'newsletter_subscription.json'
        assert expected_path.exists()
        on_disk = json.loads(expected_path.read_text(encoding='utf-8'))
        assert on_disk['subscribed'] is True
        assert on_disk['email'] == 'david@example.com'
        assert on_disk['awaiting_confirmation'] is True

    def test_NL_02_awaiting_confirmation_defaults_false_for_old_state_files(
            self, gui, tmp_path, monkeypatch):
        # A state file written before v8.1.1 (double opt-in) has no
        # awaiting_confirmation key at all — must default to False, not
        # crash, and must NOT retroactively show the pending card for
        # someone who subscribed under the old single-opt-in behavior.
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        p = tmp_path / '.ai-prowler' / 'newsletter_subscription.json'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({'subscribed': True, 'email': 'old@example.com'}),
                     encoding='utf-8')

        state = gui.app._load_newsletter_state()
        assert state == {'subscribed': True, 'email': 'old@example.com',
                         'awaiting_confirmation': False}

    def test_NL_02_corrupt_file_falls_back_to_defaults_without_raising(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        p = tmp_path / '.ai-prowler' / 'newsletter_subscription.json'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{not valid json", encoding='utf-8')

        state = gui.app._load_newsletter_state()
        assert state == {'subscribed': False, 'email': '', 'awaiting_confirmation': False}


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
        {'ok': True, 'email': 'david@example.com', 'status': 'pending',
         'email_sent': True}
    ).encode('utf-8')
    resp.__enter__ = lambda self: resp
    resp.__exit__ = lambda self, *a: False
    return resp


def _fake_urlopen_success_email_not_sent(*args, **kwargs):
    resp = MagicMock()
    resp.read.return_value = json.dumps(
        {'ok': True, 'email': 'david@example.com', 'status': 'pending',
         'email_sent': False}
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


def _fake_urlopen_success_missing_email_sent_key(*args, **kwargs):
    # Simulates the OLD (pre-double-opt-in) Worker response shape — no
    # email_sent key at all. This is exactly what caused the real bug:
    # the client used to default a missing key to True ("assume it sent"),
    # showing "check your email" even though the live Worker never had
    # any email-sending code at all. Regression guard for that fix.
    resp = MagicMock()
    resp.read.return_value = json.dumps(
        {'ok': True, 'email': 'david@example.com', 'status': 'active'}
    ).encode('utf-8')
    resp.__enter__ = lambda self: resp
    resp.__exit__ = lambda self, *a: False
    return resp


class TestNewsletterSubscribeFlow:

    def test_NL_04_missing_email_sent_key_defaults_to_false_not_true(
            self, gui, tmp_path, monkeypatch):
        # Regression test for a real production bug (2026-07-13): an
        # un-deployed Worker's response has no email_sent key. Must be
        # treated as "don't know it sent" (False), not silently assumed
        # to have succeeded (True) — a false "check your email" message
        # is worse than an honest "couldn't be sent" one.
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()

        with patch('urllib.request.urlopen',
                   side_effect=_fake_urlopen_success_missing_email_sent_key):
            gui.app._newsletter_do_subscribe('david@example.com')
        gui.pump()

        found_honest_warning = False
        def _walk(w):
            nonlocal found_honest_warning
            txt = str(w.cget('text')) if 'text' in w.keys() else ''
            if "couldn't be" in txt.lower():
                found_honest_warning = True
            for c in w.winfo_children():
                _walk(c)
        _walk(gui.app._newsletter_frame)
        assert found_honest_warning, (
            "a response missing email_sent must show the honest "
            "send-failure message, not silently claim success")

    def test_NL_04_successful_subscribe_persists_state_and_shows_pending_card(
            self, gui, tmp_path, monkeypatch):
        # v8.1.1 — double opt-in: a successful subscribe no longer hides
        # the whole banner outright. It persists subscribed=True (so the
        # original form never comes back) AND awaiting_confirmation=True
        # (so the "check your email" card shows instead of nothing).
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
        assert state['awaiting_confirmation'] is True
        # The pending card IS rendered (not zero children) — that's the
        # whole point of double opt-in: the user isn't done yet, they
        # still need to check their inbox.
        assert len(gui.app._newsletter_frame.winfo_children()) > 0

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


# ─────────────────────────────────────────────────────────────────────────────
# NL-05 — the "check your email" pending card (v8.1.1, double opt-in)
# ─────────────────────────────────────────────────────────────────────────────

class TestShouldShowPendingCard:

    def test_NL_05_hidden_when_never_subscribed(self):
        state = {'subscribed': False, 'email': '', 'awaiting_confirmation': False}
        assert gui_mod.RAGGui._should_show_pending_card(state) is False

    def test_NL_05_shown_when_subscribed_and_awaiting_confirmation(self):
        state = {'subscribed': True, 'email': 'david@example.com',
                 'awaiting_confirmation': True}
        assert gui_mod.RAGGui._should_show_pending_card(state) is True

    def test_NL_05_hidden_once_dismissed_even_though_still_subscribed(self):
        # This is the "Dismiss" checkbox's persisted end state — subscribed
        # stays True forever (the form must never come back), but
        # awaiting_confirmation flips to False so the reminder card is gone.
        state = {'subscribed': True, 'email': 'david@example.com',
                 'awaiting_confirmation': False}
        assert gui_mod.RAGGui._should_show_pending_card(state) is False

    def test_NL_05_mutually_exclusive_with_original_banner(self):
        # Whenever the pending card would show, the original subscribe-form
        # banner must NOT also show — verified against the real (unchanged)
        # _should_show_newsletter_banner logic, not just asserted by design.
        state = {'subscribed': True, 'email': 'david@example.com',
                 'awaiting_confirmation': True}
        assert gui_mod.RAGGui._should_show_pending_card(state) is True
        assert gui_mod.RAGGui._should_show_newsletter_banner(state, False) is False


class TestNewsletterPendingCardRendering:

    def test_NL_05_pending_card_renders_after_subscribe(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._save_newsletter_state(True, 'david@example.com',
                                       awaiting_confirmation=True)
        gui.app._build_newsletter_banner()
        gui.pump()

        assert len(gui.app._newsletter_frame.winfo_children()) > 0

    def test_NL_05_email_sent_true_shows_check_email_message(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._save_newsletter_state(True, 'david@example.com',
                                       awaiting_confirmation=True)
        gui.app._build_newsletter_banner(email_sent=True)
        gui.pump()

        # Walk the widget tree for the expected message text.
        found = False
        def _walk(w):
            nonlocal found
            txt = str(w.cget('text')) if 'text' in w.keys() else ''
            if 'check your email' in txt.lower():
                found = True
            for c in w.winfo_children():
                _walk(c)
        _walk(gui.app._newsletter_frame)
        assert found, "expected the 'check your email' message to render"

    def test_NL_05_email_sent_false_shows_honest_failure_message(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._save_newsletter_state(True, 'david@example.com',
                                       awaiting_confirmation=True)
        gui.app._build_newsletter_banner(email_sent=False)
        gui.pump()

        found = False
        def _walk(w):
            nonlocal found
            txt = str(w.cget('text')) if 'text' in w.keys() else ''
            if "couldn't be" in txt.lower():
                found = True
            for c in w.winfo_children():
                _walk(c)
        _walk(gui.app._newsletter_frame)
        assert found, "expected an honest send-failure message, not the generic one"

    def test_NL_05_dismiss_checkbox_persists_and_hides_card(
            self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._save_newsletter_state(True, 'david@example.com',
                                       awaiting_confirmation=True)
        gui.app._build_newsletter_banner()
        gui.pump()
        assert len(gui.app._newsletter_frame.winfo_children()) > 0

        # Find and invoke the dismiss checkbox rather than calling the
        # internal handler directly — exercises the actual widget wiring.
        def _find_checkbutton(w):
            for c in w.winfo_children():
                if c.winfo_class() == 'TCheckbutton':
                    return c
                found = _find_checkbutton(c)
                if found is not None:
                    return found
            return None

        cb = _find_checkbutton(gui.app._newsletter_frame)
        assert cb is not None, "expected a Checkbutton in the pending card"
        cb.invoke()
        gui.pump()

        # Persisted — not session-only like the original form's ✕.
        state = gui.app._load_newsletter_state()
        assert state['subscribed'] is True
        assert state['awaiting_confirmation'] is False
        assert len(gui.app._newsletter_frame.winfo_children()) == 0

    def test_NL_05_dismissal_survives_a_fresh_banner_rebuild(
            self, gui, tmp_path, monkeypatch):
        # Simulates relaunching the app — unlike the original form's ✕
        # (session-only), a dismissed pending card must stay dismissed.
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        gui.app._save_newsletter_state(True, 'david@example.com',
                                       awaiting_confirmation=False)
        gui.app._newsletter_dismissed_this_session = False
        gui.app._build_newsletter_banner()
        gui.pump()

        assert len(gui.app._newsletter_frame.winfo_children()) == 0
