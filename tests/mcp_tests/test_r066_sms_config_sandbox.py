"""R-066 (2026-09-29): sms_backends.load_sms_config read the REAL
~/.ai-prowler/config.json even inside the test sandbox, so a sandboxed
process had the owner's real Twilio credentials. It now honours
AIPROWLER_TEST_STATE_DIR like every other state file."""
import json

import sms_backends


def test_reads_sandbox_config(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({"sms_provider": "sandbox-check"}), encoding="utf-8")
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    assert sms_backends.load_sms_config() == {"sms_provider": "sandbox-check"}


def test_empty_sandbox_means_not_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    assert sms_backends.load_sms_config() == {}
