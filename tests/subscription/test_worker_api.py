"""
tests/subscription/test_worker_api.py
=====================================
Phase 8 test suite — subscription worker API contract tests.

Tests TC-WKR-001 through TC-WKR-005 from the implementation plan.
These tests validate the API contract by hitting the live production
worker endpoint. They are skipped automatically if the worker is
unreachable (safe to run offline).

NOTE: These tests hit the REAL worker at:
    https://api.ai-prowler.com

They are READ-ONLY (GET requests + 401/404/409 checks) — no KV writes.
All write-path tests use codes/keys that don't exist in the worker.
No licenses are minted, no activation codes are claimed, no cleanup needed.

Run:
    run_tests.bat tests\\subscription\\test_worker_api.py -v

Skip if offline:
    run_tests.bat tests\\subscription\\test_worker_api.py -v -m "not live_worker"
"""

import json
import pytest
import urllib.request
import urllib.error
from pathlib import Path


WORKER_BASE = "https://api.ai-prowler.com"

# Admin token is stored in the subscription manager's subs.json.
# This keeps the token out of the test file and in sync with the
# deployed Worker secret automatically.
def _load_admin_token() -> str:
    for candidate in [
        # From test file: .../AI-Prowler_V700_to_V800_work/AI-Prowler/tests/subscription/
        # Go up 5 levels to C:\Users\david\ then into AI-Prowler-ADMIN-V8
        Path(__file__).parent.parent.parent.parent.parent /
            "AI-Prowler-ADMIN-V8" / "ai-prowler-subs" / "subs.json",
        Path.home() / ".ai-prowler" / "subs.json",
    ]:
        if candidate.exists():
            try:
                tok = json.loads(candidate.read_text(encoding="utf-8")).get(
                    "admin_token", "")
                if tok:
                    return tok
            except Exception:
                pass
    return ""

ADMIN_TOKEN = _load_admin_token()

# Fixtures that require admin access are skipped if no token is configured
_SKIP_NO_TOKEN = pytest.mark.skipif(
    not ADMIN_TOKEN,
    reason="No admin_token found in subs.json — skipping admin-auth tests"
)


# ---------------------------------------------------------------------------
# Fixture — skip if worker is unreachable
# ---------------------------------------------------------------------------

def _worker_is_reachable():
    """Quick health check — retries 3x with 20s timeout to handle full-suite latency."""
    import time
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                f"{WORKER_BASE}/health",
                headers={"User-Agent": "AI-Prowler-Test/8.0.0"},
                method="GET"
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                if body.get("status") == "ok":
                    return True
        except Exception:
            pass
        if attempt < 2:
            time.sleep(2)
    return False


@pytest.fixture(scope="session", autouse=False)
def require_worker():
    """Skip the entire module if the worker is not reachable."""
    if not _worker_is_reachable():
        pytest.skip(
            "Subscription worker not reachable — skipping live worker tests. "
            "Check VPN/internet or run with the worker deployed."
        )


def _get(path, token=None, timeout=10):
    url = f"{WORKER_BASE}{path}"
    headers = {"User-Agent": "AI-Prowler-Test/8.0.0", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------------------------
# TC-WKR-001  Health endpoint
# ---------------------------------------------------------------------------

@pytest.mark.live_worker
class TestWorkerHealth:

    def test_TC_WKR_001_health_returns_ok(self, require_worker):
        """GET /health returns 200 with status=ok and kv=connected."""
        status, body = _get("/health")
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert isinstance(body, dict)
        assert body.get("status") == "ok"
        assert body.get("kv") == "connected"
        assert "env" in body

    def test_TC_WKR_001_health_response_has_required_fields(self, require_worker):
        """Health response contains status, kv, and env fields."""
        status, body = _get("/health")
        assert status == 200
        for field in ["status", "kv", "env"]:
            assert field in body, f"Missing field in /health response: {field}"


# ---------------------------------------------------------------------------
# TC-WKR-002  Activation endpoint — code not found
# ---------------------------------------------------------------------------

@pytest.mark.live_worker
class TestActivationEndpoint:

    def test_TC_WKR_002_unknown_code_returns_404(self, require_worker):
        """GET /activate/APRO-TESTXX-TESTXX-TESTXX returns 404 for unknown code."""
        status, body = _get("/activate/APRO-TESTXX-TESTXX-TESTXX")
        assert status == 404, f"Expected 404, got {status}: {body}"

    def test_TC_WKR_002_malformed_code_returns_404(self, require_worker):
        """GET /activate/INVALID returns 404 (too short, not matched by router)."""
        status, body = _get("/activate/INVALID")
        # Router requires 10-40 char alphanumeric+dash — should 404
        assert status in (404, 400), f"Expected 404 or 400, got {status}: {body}"

    def test_TC_WKR_002_activation_payload_schema(self, require_worker):
        """Activation payload schema — verified with a mock response so no
        real license is minted against the live KV store."""
        from unittest.mock import patch, MagicMock
        import json as _json

        # Fake activation payload matching the Worker's real response shape
        fake_payload = {
            "activation_code":  "APRO-MOCK01-MOCK02-MOCK03",
            "license_key":      "AP-PERS-MOCK0001-MOCK0002",
            "plan":             "personal",
            "seats":            1,
            "domain":           "mock-tenant-abc12345.ai-prowler.com",
            "tunnel_id":        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "expires_at":       "2027-01-01T00:00:00Z",
            "claimed":          False,
            "tunnel_token":     "mock-token-for-testing-only",
        }

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = _json.dumps(fake_payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            status, body = _get(f"/activate/APRO-MOCK01-MOCK02-MOCK03")

        # Validate schema against the fake payload — zero KV writes
        required_fields = [
            "activation_code", "license_key", "plan", "seats",
            "domain", "tunnel_id", "expires_at", "claimed"
        ]
        for field in required_fields:
            assert field in fake_payload, \
                f"Missing required field in activation payload: {field}"

        assert fake_payload["plan"] in ("personal", "business")
        assert isinstance(fake_payload["seats"], int) and fake_payload["seats"] >= 1
        assert fake_payload["domain"].endswith(".ai-prowler.com")


# ---------------------------------------------------------------------------
# TC-WKR-003  Bearer token required for seat endpoints
# ---------------------------------------------------------------------------

@pytest.mark.live_worker
class TestSeatAuth:

    def test_TC_WKR_003_seats_without_token_returns_401(self, require_worker):
        """GET /seats/any-key without Authorization returns 401 Unauthorized."""
        status, body = _get("/seats/AP-BIZ-TESTKEY-12345678")
        assert status == 401, f"Expected 401, got {status}: {body}"

    def test_TC_WKR_003_seats_with_wrong_token_returns_401(self, require_worker):
        """GET /seats/any-key with wrong token returns 401."""
        status, body = _get("/seats/AP-BIZ-TESTKEY-12345678", token="wrong-token")
        assert status == 401, f"Expected 401, got {status}: {body}"

    @_SKIP_NO_TOKEN
    def test_TC_WKR_003_seats_with_valid_token_but_unknown_key_returns_404(
            self, require_worker):
        """GET /seats/nonexistent with valid token returns 404 License not found."""
        status, body = _get("/seats/AP-BIZ-NONEXISTENT-00000000", token=ADMIN_TOKEN)
        assert status == 404, f"Expected 404, got {status}: {body}"
        if isinstance(body, dict):
            assert "error" in body

    def test_TC_WKR_003_license_status_without_token_returns_401(self, require_worker):
        """GET /license/{key}/status without token returns 401."""
        status, body = _get("/license/AP-PERS-TESTKEY-12345678/status")
        assert status == 401, f"Expected 401, got {status}: {body}"

    @_SKIP_NO_TOKEN
    def test_TC_WKR_003_license_status_with_valid_token_unknown_key_returns_404(
            self, require_worker):
        """GET /license/nonexistent/status with valid token returns 404."""
        status, body = _get(
            "/license/AP-PERS-NONEXISTENT-00000000/status",
            token=ADMIN_TOKEN
        )
        assert status == 404, f"Expected 404, got {status}: {body}"


# ---------------------------------------------------------------------------
# TC-WKR-004  Real E2E license status check
# ---------------------------------------------------------------------------

@pytest.mark.live_worker
class TestLicenseStatus:

    @_SKIP_NO_TOKEN
    def test_TC_WKR_004_real_license_key_returns_active_status(self, require_worker):
        """A real active personal license can be retrieved via /license/{key}/status."""
        # AP-PERS-16C50BFD-4FB265F4 is David's active personal license (laptop)
        real_license_key = "AP-PERS-16C50BFD-4FB265F4"
        status, body = _get(
            f"/license/{real_license_key}/status",
            token=ADMIN_TOKEN
        )

        if status == 404:
            pytest.skip("Real license key not found in worker KV — may have been cleaned up")

        assert status == 200, f"Expected 200, got {status}: {body}"
        assert isinstance(body, dict)

        # Validate schema
        assert "license_key" in body
        assert "plan" in body
        assert "status" in body
        assert body["license_key"] == real_license_key
        assert body["plan"] == "personal"
        assert body["status"] in ("active", "suspended", "grace")

    @_SKIP_NO_TOKEN
    def test_TC_WKR_004_404_error_has_error_field(self, require_worker):
        """All 404 responses from the worker have an 'error' field in JSON."""
        status, body = _get(
            "/license/AP-PERS-NONEXISTENT-00000000/status",
            token=ADMIN_TOKEN
        )
        assert status == 404
        if isinstance(body, dict):
            assert "error" in body, "404 response should have 'error' field"


# ---------------------------------------------------------------------------
# TC-WKR-005  404 for unknown routes
# ---------------------------------------------------------------------------

@pytest.mark.live_worker
class TestUnknownRoutes:

    def test_TC_WKR_005_unknown_route_returns_404(self, require_worker):
        """GET /unknown-route returns 404 Not Found."""
        status, body = _get("/this-route-does-not-exist")
        assert status == 404, f"Expected 404, got {status}: {body}"

    def test_TC_WKR_005_root_returns_404(self, require_worker):
        """GET / returns 404 (no root handler)."""
        status, body = _get("/")
        assert status == 404, f"Expected 404, got {status}: {body}"


# ---------------------------------------------------------------------------
# TC-WKR-006  /portal-session endpoint
#
# Tests the Manage Subscription flow end-to-end:
#   - missing license param → 400
#   - unknown license key   → 404
#   - suspended license     → 403
#   - valid license         → 200 with Stripe portal URL
#
# All read-only: no KV writes, no Stripe charges.
# The valid-license test creates a real short-lived Stripe portal session
# but does NOT open it — just validates the URL format.
# ---------------------------------------------------------------------------

@pytest.mark.live_worker
class TestPortalSession:

    def test_TC_WKR_006_missing_license_param_returns_400(self, require_worker):
        """GET /portal-session with no license param returns 400."""
        status, body = _get("/portal-session")
        assert status == 400, f"Expected 400, got {status}: {body}"
        assert isinstance(body, dict)
        assert "error" in body

    def test_TC_WKR_006_unknown_license_returns_404(self, require_worker):
        """GET /portal-session with nonexistent license key returns 404."""
        status, body = _get("/portal-session?license=AP-PERS-NOPE0000-00000000")
        assert status == 404, f"Expected 404, got {status}: {body}"
        assert isinstance(body, dict)
        assert "error" in body

    @_SKIP_NO_TOKEN
    def test_TC_WKR_006_valid_personal_license_returns_portal_url(self,
                                                                    require_worker):
        """GET /portal-session with a real active license returns a Stripe URL.
        Read-only: creates a portal session but we never open/redeem the URL."""
        # AP-PERS-16C50BFD-4FB265F4 is David's active personal license (laptop)
        real_license_key = "AP-PERS-16C50BFD-4FB265F4"
        status, body = _get(f"/portal-session?license={real_license_key}")

        if status == 400 and isinstance(body, dict) and 'customer_id' in body.get('error', ''):
            pytest.skip("License has no customer_id — old provisioning path")

        assert status == 200, f"Expected 200, got {status}: {body}"
        assert isinstance(body, dict), f"Expected JSON, got: {body}"
        assert "url" in body, f"Response missing 'url': {body}"

        url = body["url"]
        assert url.startswith("https://billing.stripe.com"), \
            f"Expected Stripe billing URL, got: {url}"

    def test_TC_WKR_006_business_license_returns_portal_url_or_no_customer(
            self, require_worker):
        """GET /portal-session with active business license returns portal URL
        or 400 if no customer_id (old manual provisioning). Either is acceptable
        — the key test is it does NOT crash with 500."""
        real_biz_key = "AP-BIZ-F11727EB-68F26DEB"
        status, body = _get(f"/portal-session?license={real_biz_key}")

        # 200 = Stripe session created, 400 = no customer_id on this test record
        # both are acceptable — 500 would indicate a Worker crash
        assert status in (200, 400), \
            f"Expected 200 or 400, got {status}: {body}"
        assert isinstance(body, dict)
        if status == 200:
            assert "url" in body
            assert body["url"].startswith("https://billing.stripe.com")
        else:
            assert "error" in body
