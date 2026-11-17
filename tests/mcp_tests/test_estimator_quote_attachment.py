"""
tests/mcp_tests/test_estimator_quote_attachment.py
===================================================
(2026-11-16, David) "Why did it get this error with the PDF not sent?" - send_email refused the Estimator's quote PDF
("Access denied ... not under any tracked root or access-only folder"), so every emailed quote went out without it.

A quote the Estimator made - a .pdf or .html directly in <Estimator data>/projects/estimate_NNNN/bids/ - may now
always be attached. Nothing else in the Estimator's data folder, and nothing outside it.

Run: run_tests.bat tests\\mcp_tests\\test_estimator_quote_attachment.py -v
"""
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def ap():
    import ai_prowler_mcp as _ap
    _ap._prewarm_event.set()
    return _ap


@pytest.fixture()
def est_data(ap, tmp_path, monkeypatch):
    """An Estimator data folder with one quote, nothing tracked or access-only."""
    data = tmp_path / "estimator"
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(data))
    monkeypatch.setattr(ap, "_ACCESS_ONLY_DIRS_FILE", tmp_path / ".rag_access_only_dirs.json")
    monkeypatch.setattr(ap, "_telemetry_increment_tool_count", lambda *a, **k: None)
    import rag_preprocessor as _rag
    monkeypatch.setattr(_rag, "load_auto_update_list", lambda: [])
    monkeypatch.setattr(ap, "load_auto_update_list", lambda: [])
    bids = data / "projects" / "estimate_0004" / "bids"
    bids.mkdir(parents=True)
    (bids / "Q-0004-2.pdf").write_bytes(b"%PDF-1.4 quote")
    (bids / "Q-0004-2.html").write_text("<html>quote</html>", encoding="utf-8")
    (data / "estimator.db").write_bytes(b"db")
    (data / "projects" / "estimate_0004" / "plans.pdf").write_bytes(b"%PDF plans")
    (bids / "notes.txt").write_text("x", encoding="utf-8")
    return data


def test_a_quote_the_estimator_made_can_be_attached(ap, est_data):
    pdf = est_data / "projects" / "estimate_0004" / "bids" / "Q-0004-2.pdf"
    assert ap._resolve_allowlisted_path(str(pdf))[1]                     # still not on the allowlist...
    assert ap._estimator_quote_file(str(pdf)) == str(pdf.resolve())      # ...but a quote may be attached
    html = pdf.with_suffix(".html")
    assert ap._estimator_quote_file(str(html)) == str(html.resolve())


@pytest.mark.parametrize("rel", ["estimator.db", "projects/estimate_0004/plans.pdf",
                                 "projects/estimate_0004/bids/notes.txt", "projects/estimate_0004/bids/missing.pdf",
                                 "projects/estimate_0004/bids/../plans.pdf"])
def test_nothing_else_in_the_estimator_folder(ap, est_data, rel):
    assert ap._estimator_quote_file(str(est_data / rel)) is None


def test_nothing_outside_the_estimator_folder(ap, est_data, tmp_path):
    other = tmp_path / "elsewhere" / "projects" / "estimate_0001" / "bids"
    other.mkdir(parents=True)
    (other / "Q-0001-1.pdf").write_bytes(b"%PDF")
    assert ap._estimator_quote_file(str(other / "Q-0001-1.pdf")) is None


def test_send_email_attaches_the_quote(ap, est_data, monkeypatch):
    sent = {}

    def fake_send(to, subject, body, attachment_path=None, **kw):
        sent.update(to=to, attachment=attachment_path)
        return True, f"✅ Email sent to {to}"
    monkeypatch.setattr(ap, "_send_smtp", fake_send)
    monkeypatch.setattr(ap, "_email_config_load", lambda: {"backend": "smtp", "smtp_host": "smtp.example.com",
                                                            "username": "me@example.com", "from_name": "Me"})
    pdf = est_data / "projects" / "estimate_0004" / "bids" / "Q-0004-2.pdf"
    out = ap.send_email(to="pat@example.com", subject="Your quote", body="Hi", attachment_path=str(pdf))
    assert "❌" not in out and sent["attachment"] == str(pdf.resolve())
    # Anything else is still refused.
    out = ap.send_email(to="pat@example.com", subject="x", body="x", attachment_path=str(est_data / "estimator.db"))
    assert out.startswith("❌ Attachment")
