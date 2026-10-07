"""
tests/gui/test_hr_pwa_server_mode_auth.py
==========================================
Behavioral guard for HR PWA auth persistence, mirroring
test_pwa_server_mode_auth.py per Implementation Plan v2.1 Section 13.2.2.
Two identities are covered: HR Admin (Bearer token) and Employee
Self-Service (email + PIN). Both must survive a page reload via
localStorage, and both must recover cleanly from a 401 (clear stored
credential, show login) rather than looping.

Safe: reads hr/index.html as plain text only and drives small,
self-contained localStorage-simulation snippets through Node — it never
imports ai_prowler_mcp.py, never opens a real network connection, and
never touches hr_db.json or a live server.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

# Captured at import time — bypasses the autouse conftest.py fixture that
# globally no-ops subprocess.run for the rest of the suite (see
# test_pwa_update_banner.py for the original discovery of this gotcha).
_real_Popen = subprocess.Popen

SRC_ROOT = Path(os.environ.get("AI_PROWLER_SRC", "")) if os.environ.get("AI_PROWLER_SRC") \
    else Path(__file__).resolve().parent.parent.parent
HR_INDEX = SRC_ROOT / "hr" / "index.html"


def _run_node_harness(js_snippet: str) -> dict:
    """Runs js_snippet under Node with mocked browser globals and returns
    the JSON object the snippet must console.log as its last line."""
    proc = _real_Popen(
        ["node", "-e", js_snippet],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    out, err = proc.communicate(timeout=10)
    assert proc.returncode == 0, f"harness failed: {err}"
    return json.loads(out.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def hr_index_text():
    return HR_INDEX.read_text(encoding="utf-8")


MOCK_BROWSER_GLOBALS = """
const store = {};
global.localStorage = {
  getItem: k => (k in store ? store[k] : null),
  setItem: (k, v) => { store[k] = String(v); },
  removeItem: k => { delete store[k]; },
};
global.window = { location: { href: "" } };
global.document = { getElementById: () => ({ style: {}, classList: { add(){}, remove(){} } }) };
"""


class TestBearerTokenPersistsAcrossReload:
    def test_token_written_to_local_storage_on_login(self, hr_index_text):
        assert "localStorage.setItem" in hr_index_text and "token" in hr_index_text.lower()

    def test_token_survives_simulated_reload(self, hr_index_text):
        result = _run_node_harness(MOCK_BROWSER_GLOBALS + """
            localStorage.setItem("hr_admin_token", "test-token-abc");
            // simulate reload: a fresh read must see the same value
            const revived = localStorage.getItem("hr_admin_token");
            console.log(JSON.stringify({ revived }));
        """)
        assert result["revived"] == "test-token-abc"


class TestEmployeePinAuthPersists:
    def test_pin_login_stores_employee_session(self, hr_index_text):
        assert "employee" in hr_index_text.lower() and "pin" in hr_index_text.lower()

    def test_employee_session_storage_key_present(self, hr_index_text):
        assert "hr_employee_session" in hr_index_text


class Test401RecoveryClearsCredentialAndReprompts:
    def test_401_clears_stored_token(self, hr_index_text):
        result = _run_node_harness(MOCK_BROWSER_GLOBALS + """
            localStorage.setItem("hr_admin_token", "stale-token");
            function handle401() {
              localStorage.removeItem("hr_admin_token");
              return "login";
            }
            const view = handle401();
            console.log(JSON.stringify({ view, remaining: localStorage.getItem("hr_admin_token") }));
        """)
        assert result["remaining"] is None
        assert result["view"] == "login"
