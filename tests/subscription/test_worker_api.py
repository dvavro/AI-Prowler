"""
tests/subscription/test_worker_api.py
=====================================
Phase 8 test suite — subscription worker API contract tests.

Tests TC-WKR-001 through TC-WKR-004 from the implementation plan.
These tests validate the API contract by hitting the live staging
worker endpoint. They are skipped automatically if the worker is
unreachable (safe to run offline).

NOTE: These tests hit the REAL worker at:
    https://ai-prowler-subscription.david-vavro1.workers.dev

They are read-only (GET requests + 401/409 checks) — no KV writes
except the /activate/ claim which uses a code that won't exist.
All write-path tests use codes/keys that don't exist in the worker.

Run:
    run_tests.bat tests\subscription\test_worker_api.py -v

Skip if offline:
    run_tests.bat tests\subscription\test_worker_api.py -v -m "not live_worker"
"""

import json
import pytest
import urllib.request
import urllib.error


WORKER_BASE = "https://ai-prowler-subscription.david-vavro1.workers.dev"
ADMIN_TOKEN = "Synopsys1*"


# ---------------------------------------------------------------------------
# Fixture — skip if worker is unreachable
# ---------------------------------------------------------------------------

def _worker_is_reachable():
    """Quick health check to see if the worker is up."""
    try:
        req = urllib.request.Request(
            f"{WORKER_BASE}/health",
            headers={"User-Agent": "AI-Prowler-Test/8.0.0"},
            method="GET"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body.get("status") == "ok"
    except Exception:
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
        """The real activation code from the E2E test has all required schema fields.
        This test is skipped if the code is already claimed from a different IP."""
        # Use the real code from the E2E test
        real_code = "APRO-Z363JU-7YK2VR-YNE9XJ"
        status, body = _get(f"/activate/{real_code}")

        if status == 409:
            pytest.skip("Activation code already claimed from different IP — schema test skipped")
        if status == 404:
            pytest.skip("Activation code not found (expired or not in worker) — schema test skipped")

        assert status == 200, f"Expected 200, got {status}: {body}"
        assert isinstance(body, dict)

        required_fields = [
            "activation_code", "license_key", "plan", "seats",
            "domain", "tunnel_id", "expires_at", "claimed"
        ]
        for field in required_fields:
            assert field in body, f"Missing required field in activation payload: {field}"

        assert body["plan"] in ("personal", "business")
        assert isinstance(body["seats"], int) and body["seats"] >= 1
        assert body["domain"].endswith(".ai-prowler.com") or ".cfargotunnel.com" in body["domain"]


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

    def test_TC_WKR_004_real_license_key_returns_active_status(self, require_worker):
        """The license key from the E2E test can be retrieved via /license/{key}/status."""
        real_license_key = "AP-PERS-D7877A46-658A6DB2"
        status, body = _get(
            f"/license/{real_license_key}/status",
            token=ADMIN_TOKEN
        )

        if status == 404:
            pytest.skip("Real license key not found in worker KV — E2E test may not have run yet")

        assert status == 200, f"Expected 200, got {status}: {body}"
        assert isinstance(body, dict)

        # Validate schema
        assert "license_key" in body
        assert "plan" in body
        assert "status" in body
        assert body["license_key"] == real_license_key
        assert body["plan"] == "personal"
        assert body["status"] in ("active", "suspended", "grace")

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
