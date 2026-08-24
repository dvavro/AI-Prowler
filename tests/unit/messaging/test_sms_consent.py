"""
tests/unit/messaging/test_sms_consent.py
==========================================
Unit tests for sms_consent.py — keyword classification and consent
lifecycle storage.

Covers the STOP/START keyword edge cases from the SMS consent feature
plan (Phase 1.5), section "3. STOP / START opt-out lifecycle tests":
  3b — case/whitespace normalization
  3d — re-subscribe preserves original signup data
  3e — HELP is info-only, no consent-state change
  3f — substring false-positive guard ("stop by the office")
  3g — full opt-out synonym set (STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT)

Follows the same isolated-state-dir pattern as test_sms_inbox.py so no
test ever touches the real ~/.ai-prowler/sms_consent.json.
"""
from __future__ import annotations

import sys
import importlib
from pathlib import Path

import pytest

_HERE       = Path(__file__).resolve()
_AI_PROWLER = _HERE.parents[3]
sys.path.insert(0, str(_AI_PROWLER))


# ─── Fixture: isolated temp state dir (matches test_sms_inbox.py) ───────────

@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Give each test its own ~/.ai-prowler directory so tests don't share state."""
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    import sms_consent as _mod
    importlib.reload(_mod)
    yield tmp_path


@pytest.fixture
def consent():
    import sms_consent
    return sms_consent


# ─── classify_keyword() — pure logic, no storage involved ──────────────────

class TestClassifyKeywordOptOut:
    """3g: full opt-out synonym set, each in canonical uppercase form."""

    @pytest.mark.parametrize("word", [
        "STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT",
    ])
    def test_canonical_opt_out_keywords(self, consent, word):
        assert consent.classify_keyword(word) == "opt_out"


class TestClassifyKeywordOptIn:
    @pytest.mark.parametrize("word", ["START", "YES", "UNSTOP"])
    def test_canonical_opt_in_keywords(self, consent, word):
        assert consent.classify_keyword(word) == "opt_in"


class TestClassifyKeywordInfo:
    """3e: HELP must classify as info, never opt_out/opt_in."""

    @pytest.mark.parametrize("word", ["help", "HELP", " Help ", "Help\n"])
    def test_help_variants_are_info(self, consent, word):
        assert consent.classify_keyword(word) == "info"


class TestClassifyKeywordCaseAndWhitespace:
    """3b: lowercase, mixed case, and surrounding whitespace must still match."""

    @pytest.mark.parametrize("word,expected", [
        ("stop",   "opt_out"),
        ("Stop",   "opt_out"),
        ("StOp",   "opt_out"),
        (" STOP ", "opt_out"),
        ("STOP\n", "opt_out"),
        ("\tstop", "opt_out"),
        ("start",  "opt_in"),
        ("Start",  "opt_in"),
        (" START ", "opt_in"),
    ])
    def test_case_and_whitespace_normalized(self, consent, word, expected):
        assert consent.classify_keyword(word) == expected


class TestClassifyKeywordSubstringFalsePositive:
    """3f: the word appearing INSIDE a longer sentence must NOT trigger a
    match — a substring match would incorrectly opt someone out of a
    normal conversational reply."""

    @pytest.mark.parametrize("body", [
        "please stop by the office",
        "stop by later today",
        "can you stop the car",
        "yes please send more info",       # contains "yes" but isn't exactly "YES"
        "let's start the project tomorrow",
        "quit playing games with me",
    ])
    def test_keyword_as_substring_does_not_match(self, consent, body):
        assert consent.classify_keyword(body) is None


class TestClassifyKeywordOrdinaryMessages:
    @pytest.mark.parametrize("body", [
        "Thanks!",
        "See you at 3pm",
        "",
        "   ",
    ])
    def test_ordinary_messages_return_none(self, consent, body):
        assert consent.classify_keyword(body) is None

    def test_none_body_returns_none(self, consent):
        assert consent.classify_keyword(None) is None


class TestClassifyKeywordTrailingPunctuation:
    """Twilio's own STOP handling is punctuation-tolerant ("Stop." is
    treated as an opt-out on their platform). Documents current behavior
    of our local classifier so a gap is visible rather than silent."""

    @pytest.mark.parametrize("body", ["stop.", "STOP!", "Stop,"])
    def test_trailing_punctuation_current_behavior(self, consent, body):
        result = consent.classify_keyword(body)
        if result is None:
            pytest.xfail(
                "classify_keyword() does not strip trailing punctuation "
                "before matching — 'stop.' is NOT currently recognized as "
                "an opt-out, unlike Twilio's own platform-level handling. "
                "Flagged for a product decision, not silently fixed."
            )
        assert result == "opt_out"


# ─── Consent lifecycle storage (signup → STOP → START round trip) ──────────

class TestConsentSignup:
    def test_signup_creates_record(self, consent):
        rec = consent.consent_signup_upsert(
            name="Jane Smith", phone="+13865550101", consented=True,
            source_domain="https://example.com", ip="1.2.3.4",
        )
        assert rec["consented"] is True
        assert rec["phone"] == "+13865550101"
        assert rec["source"] == "web_form"
        assert rec["opted_out_at"] is None

        records = consent.consent_list()
        assert len(records) == 1

    def test_duplicate_phone_updates_not_duplicates(self, consent):
        consent.consent_signup_upsert(name="Jane", phone="+13865550101", consented=True)
        consent.consent_signup_upsert(name="Jane Updated", phone="+13865550101", consented=False)

        records = consent.consent_list()
        assert len(records) == 1
        assert records[0]["name"] == "Jane Updated"
        assert records[0]["consented"] is False


class TestConsentStopStartRoundTrip:
    """3a/3d: the core round trip this whole phase exists for."""

    def test_stop_flips_consented_false(self, consent):
        consent.consent_signup_upsert(name="Jane", phone="+13865550101", consented=True)
        updated = consent.consent_set_state("+13865550101", consented=False)

        assert updated is True
        rec = consent.consent_list()[0]
        assert rec["consented"] is False
        assert rec["opted_out_at"] is not None

    def test_start_after_stop_restores_and_preserves_original_data(self, consent):
        original = consent.consent_signup_upsert(
            name="Jane", phone="+13865550101", consented=True,
            source_domain="https://example.com",
        )
        original_timestamp = original["timestamp"]

        consent.consent_set_state("+13865550101", consented=False)
        consent.consent_set_state("+13865550101", consented=True)

        rec = consent.consent_list()[0]
        assert rec["consented"] is True
        assert rec["opted_out_at"] is None
        assert rec["resubscribed_at"] is not None
        # Original signup data must survive the round trip untouched.
        assert rec["timestamp"] == original_timestamp
        assert rec["name"] == "Jane"
        assert rec["source_domain"] == "https://example.com"

    def test_stop_from_unknown_number_creates_minimal_record(self, consent):
        """3c: a STOP reply from a number with no prior web-form signup
        must still be recorded, not silently discarded."""
        updated = consent.consent_set_state("+15555550199", consented=False)

        assert updated is False  # no existing record — a new one was created
        records = consent.consent_list()
        assert len(records) == 1
        assert records[0]["phone"] == "+15555550199"
        assert records[0]["consented"] is False
        assert records[0]["source"] == "sms_reply"
        assert records[0]["name"] is None


class TestConsentListFiltering:
    def test_consented_only_excludes_opted_out(self, consent):
        consent.consent_signup_upsert(name="A", phone="+13865550101", consented=True)
        consent.consent_signup_upsert(name="B", phone="+13865550102", consented=False)

        all_records = consent.consent_list()
        consented = consent.consent_list(consented_only=True)

        assert len(all_records) == 2
        assert len(consented) == 1
        assert consented[0]["name"] == "A"

    def test_consented_only_reflects_stop_state_change(self, consent):
        """5b: filter must reflect CURRENT state, not just initial signup —
        someone who signed up then later STOPped must be excluded."""
        consent.consent_signup_upsert(name="A", phone="+13865550101", consented=True)
        consent.consent_set_state("+13865550101", consented=False)

        assert consent.consent_list(consented_only=True) == []


class TestConsentDelete:
    def test_delete_by_phone(self, consent):
        consent.consent_signup_upsert(name="A", phone="+13865550101", consented=True)
        removed = consent.consent_delete("+13865550101")

        assert removed is True
        assert consent.consent_list() == []

    def test_delete_by_id(self, consent):
        rec = consent.consent_signup_upsert(name="A", phone="+13865550101", consented=True)
        removed = consent.consent_delete(rec["id"])

        assert removed is True
        assert consent.consent_list() == []

    def test_delete_nonexistent_returns_false(self, consent):
        assert consent.consent_delete("+19995550000") is False
