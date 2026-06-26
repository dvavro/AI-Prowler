"""
subscription_client.py
======================
Python client for the AI-Prowler Subscription Worker API.
Used by mobile_activator.py, rag_gui.py, and the CLI.

Worker base URL: https://ai-prowler-subscription.david-vavro1.workers.dev

Public endpoints (no auth):
    GET /health
    GET /activate/{code}

Admin bearer endpoints:
    GET  /license/{key}/status
    GET  /admin/licenses
    GET  /seats/{key}
    POST /seats/{key}/assign
    POST /seats/{key}/unassign
    POST /seats/{key}/revoke
    POST /seats/{key}/add
    POST /seats/{key}/sync
    POST /admin/license/mint
"""

import json
import os
import urllib.request
import urllib.error
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WORKER_URL = "https://ai-prowler-subscription.david-vavro1.workers.dev"
REQUEST_TIMEOUT = 15  # seconds

# The admin token is stored in config.json as "subscription_admin_token".
# It is only present on David's admin machine — never on customer installs.
# Customer installs use the activation code flow (no bearer token needed).

CONFIG_PATH = Path.home() / ".ai-prowler" / "config.json"


def _load_admin_token():
    """Read subscription_admin_token from config.json if present."""
    try:
        if CONFIG_PATH.exists():
            cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            return cfg.get("subscription_admin_token", "")
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

def _get(path, bearer=None, timeout=REQUEST_TIMEOUT):
    """
    HTTP GET to the worker.
    Returns (status_code, dict_or_str).
    Never raises — returns (0, error_message) on network failure.
    """
    url = WORKER_URL.rstrip("/") + path
    headers = {
        "Accept": "application/json",
        "User-Agent": "AI-Prowler/8.0.0 (Windows; subscription-client)",
    }
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body
    except Exception as e:
        return 0, str(e)


def _post(path, payload, bearer=None, timeout=REQUEST_TIMEOUT):
    """
    HTTP POST JSON to the worker.
    Returns (status_code, dict_or_str).
    Never raises — returns (0, error_message) on network failure.
    """
    url = WORKER_URL.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "AI-Prowler/8.0.0 (Windows; subscription-client)",
    }
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def health_check():
    """
    Check that the subscription worker is reachable and KV is connected.
    Returns dict: {"status": "ok", "kv": "connected", "env": "production"}
    Raises RuntimeError on failure.
    """
    status, body = _get("/health")
    if status == 200 and isinstance(body, dict) and body.get("status") == "ok":
        return body
    raise RuntimeError(f"Worker health check failed (HTTP {status}): {body}")


def fetch_activation(code):
    """
    Fetch the activation payload for an activation code.
    Called during the "Configure Mobile Access" flow — no auth required.

    Returns the activation payload dict on success.
    Raises:
        ValueError  — code not found (404) or already used from different machine (409)
        RuntimeError — network error or unexpected response
    """
    code = code.strip().upper()
    status, body = _get(f"/activate/{code}")

    if status == 200 and isinstance(body, dict):
        return body
    if status == 404:
        raise ValueError("Activation code not found or expired. "
                         "Check the code and try again, or contact support.")
    if status == 409:
        raise ValueError("This activation code has already been used on a different machine. "
                         "Contact support if you need to transfer your license.")
    raise RuntimeError(f"Activation request failed (HTTP {status}): {body}")


def mint_license(customer_email, plan, customer_name="", seats=1,
                 tier="standard", admin_token=None):
    """
    Manually mint a new license WITHOUT going through Stripe checkout.

    v8.0.0: the one-button Stripe flow is the normal path to a new license —
    this is an admin override for special cases that don't go through Stripe
    at all (a comped partner deal, manually onboarding a beta tester who
    didn't use the promo-code checkout, support recovery, etc.). The
    resulting license is provisioned through the exact same code path the
    Stripe webhook uses, so it's indistinguishable from a real purchase —
    same KV shape, same activation email sent to the customer, same ongoing
    /license/{key}/validate behavior.

    Args:
        customer_email: required — where the activation email is sent.
        plan:           'personal' or 'business'.
        customer_name:  optional display name.
        seats:          Business only; ignored for personal (always 1).
        tier:           'standard' or 'beta'. Beta licenses behave
                        identically — it's a cosmetic/tracking tag only.
        admin_token:    optional override; defaults to config.json's
                        subscription_admin_token.

    Returns dict: the newly-created license record (license_key, plan,
    tier, status, expires_at, customer_email, ...).
    Raises ValueError on bad input, RuntimeError on auth/network errors.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available.")
    if plan not in ("personal", "business"):
        raise ValueError("plan must be 'personal' or 'business'.")
    if not customer_email:
        raise ValueError("customer_email is required.")
    status, body = _post(
        "/admin/license/mint",
        {
            "customer_email": customer_email,
            "customer_name":  customer_name,
            "plan":           plan,
            "seats":          seats,
            "tier":           tier,
        },
        bearer=token,
    )
    if status == 200 and isinstance(body, dict) and body.get("ok"):
        return body
    if status == 400:
        raise ValueError(f"Bad request: {body}")
    if status == 401:
        raise RuntimeError("Admin token rejected.")
    raise RuntimeError(f"License mint failed (HTTP {status}): {body}")


def list_all_licenses(prefix="licenses:", cursor=None, admin_token=None):
    """
    Browse ALL licenses on the Worker — the enumeration view that
    get_license_status()/get_seats() don't provide (those require you to
    already know a specific key). Backed by Cloudflare KV's list(), which
    is paginated (max ~200/page here) and key-prefix-filterable only — it
    cannot filter by customer email or any other field value, only by key
    name. Useful prefixes (matching the actual key-naming conventions used
    by provisionSubscription() and the seat-add/mint endpoints):
        "licenses:"            — everything (personal + business + child seats)
        "licenses:AP-PERS-"    — personal licenses only
        "licenses:AP-BIZ-"     — business PARENT licenses only
        "licenses:AP-CHLD-"    — child seat licenses only

    To find a specific customer by email/name rather than by key, call this
    repeatedly (paging via the returned cursor) and filter the results
    client-side — there is no server-side search-by-email endpoint.

    Args:
        prefix:      KV key prefix to filter by (see above). Default "licenses:"
                     returns every license type in one paginated stream.
        cursor:      pagination cursor from a previous call's response, or
                     None to start from the beginning.
        admin_token: optional override; defaults to config.json's
                     subscription_admin_token.

    Returns dict: {"licenses": [...], "cursor": str|None, "list_complete": bool}.
    "cursor" is None once "list_complete" is True — keep calling with the
    returned cursor until then to walk the whole list.
    Raises RuntimeError on auth/network errors.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available.")
    import urllib.parse as _urlp
    qs = {"prefix": prefix}
    if cursor:
        qs["cursor"] = cursor
    status, body = _get(f"/admin/licenses?{_urlp.urlencode(qs)}", bearer=token)
    if status == 200 and isinstance(body, dict):
        return body
    if status == 401:
        raise RuntimeError("Admin token rejected.")
    raise RuntimeError(f"List licenses failed (HTTP {status}): {body}")


def list_all_licenses_paged(prefix="licenses:", admin_token=None, max_pages=25):
    """
    Convenience wrapper around list_all_licenses() that walks every page
    automatically and returns the complete, flat list of license records.

    Stops after max_pages pages (default 25, i.e. up to ~5000 licenses at
    200/page) as a safety bound against an unbounded loop if the Worker
    ever returns a malformed cursor that never reaches list_complete.

    Raises RuntimeError on auth/network errors (same as list_all_licenses).
    """
    all_licenses = []
    cursor = None
    for _ in range(max_pages):
        page = list_all_licenses(prefix=prefix, cursor=cursor, admin_token=admin_token)
        all_licenses.extend(page.get("licenses", []))
        if page.get("list_complete"):
            break
        cursor = page.get("cursor")
        if not cursor:
            break
    return all_licenses


def get_license_status(license_key, admin_token=None):
    """
    Get the current status of a license key.
    Requires admin bearer token.
    Returns license record dict.
    Raises ValueError if not found, RuntimeError on other errors.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available for license status check.")
    status, body = _get(f"/license/{license_key}/status", bearer=token)
    if status == 200:
        return body
    if status == 404:
        raise ValueError(f"License key not found: {license_key}")
    if status == 401:
        raise RuntimeError("Admin token rejected. Check subscription_admin_token in config.json.")
    raise RuntimeError(f"License status check failed (HTTP {status}): {body}")


def get_seats(license_key, admin_token=None):
    """
    Get all seat records for a business license.
    Returns dict with seats_total, seats_assigned, seats_unassigned, seats list.
    Raises ValueError if license not found, RuntimeError on other errors.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available for seat lookup.")
    status, body = _get(f"/seats/{license_key}", bearer=token)
    if status == 200:
        return body
    if status == 404:
        raise ValueError(f"License key not found: {license_key}")
    if status == 401:
        raise RuntimeError("Admin token rejected.")
    raise RuntimeError(f"Seat list failed (HTTP {status}): {body}")


def assign_seat(license_key, seat_id, email, admin_token=None):
    """
    Assign a seat to an email address.
    Returns updated seat record dict.
    Raises ValueError on conflict/not found, RuntimeError on other errors.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available.")
    status, body = _post(
        f"/seats/{license_key}/assign",
        {"seat_id": seat_id, "email": email},
        bearer=token,
    )
    if status == 200 and isinstance(body, dict) and body.get("ok"):
        return body.get("seat", body)
    if status == 404:
        raise ValueError(f"Seat {seat_id} not found on license {license_key}.")
    if status == 409:
        err = body.get("error", str(body)) if isinstance(body, dict) else str(body)
        raise ValueError(f"Seat conflict: {err}")
    if status == 401:
        raise RuntimeError("Admin token rejected.")
    raise RuntimeError(f"Seat assign failed (HTTP {status}): {body}")


def unassign_seat(license_key, seat_id, admin_token=None):
    """
    Release a seat back to the unassigned pool.
    Returns updated seat record dict.
    Raises ValueError if not found, RuntimeError on other errors.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available.")
    status, body = _post(
        f"/seats/{license_key}/unassign",
        {"seat_id": seat_id},
        bearer=token,
    )
    if status == 200 and isinstance(body, dict) and body.get("ok"):
        return body.get("seat", body)
    if status == 404:
        raise ValueError(f"Seat {seat_id} not found on license {license_key}.")
    if status == 401:
        raise RuntimeError("Admin token rejected.")
    raise RuntimeError(f"Seat unassign failed (HTTP {status}): {body}")


def revoke_seats(license_key, seat_ids, admin_token=None):
    """
    Explicitly revoke one or more specific seats — the owner's OWN choice
    of which employee(s) to remove, independent of whatever quantity a
    Stripe seat-count downgrade might separately request. Immediately
    suspends each seat's own child license key (the employee's machine
    picks this up on its next validation call and starts the normal
    30-day grace countdown — same soft-cancellation behavior as an
    ordinary subscription cancellation, not an instant cutoff).

    Use this from the Admin tab when an owner wants to name specific
    people to remove, rather than letting the Worker's downgrade logic
    auto-pick oldest-unassigned-first.

    Args:
        license_key: the BUSINESS PARENT license key.
        seat_ids:    list of seat_id strings to revoke (e.g.
                     ["AP-BIZ-XXXX-S002", "AP-BIZ-XXXX-S005"]).
        admin_token: optional override; defaults to config.json's
                     subscription_admin_token.

    Returns dict: {"revoked": [...], "not_found": [...]}
    Raises ValueError on bad input, RuntimeError on auth/network errors.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available.")
    if not seat_ids:
        raise ValueError("seat_ids must be a non-empty list.")
    status, body = _post(
        f"/seats/{license_key}/revoke",
        {"seat_ids": list(seat_ids)},
        bearer=token,
    )
    if status == 200 and isinstance(body, dict) and body.get("ok"):
        return {"revoked": body.get("revoked", []),
                "not_found": body.get("not_found", [])}
    if status == 404:
        raise ValueError(f"License key not found: {license_key}")
    if status == 401:
        raise RuntimeError("Admin token rejected.")
    raise RuntimeError(f"Seat revoke failed (HTTP {status}): {body}")


def add_seats(license_key, count, admin_token=None):
    """
    Manually mint N additional seats under an existing Business parent
    license — the admin-override equivalent of a customer increasing their
    quantity in the Stripe Customer Portal. Each new seat gets its own
    real, independently-revocable child license key.

    Args:
        license_key: the BUSINESS PARENT license key.
        count:       number of seats to add (positive integer).
        admin_token: optional override; defaults to config.json's
                     subscription_admin_token.

    Returns dict: {"added": [...new seat records...], plus the full
    updated seats_total/seats_assigned/etc. summary}.
    Raises ValueError on bad input, RuntimeError on auth/network errors.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available.")
    if not count or count < 1:
        raise ValueError("count must be a positive integer.")
    status, body = _post(
        f"/seats/{license_key}/add",
        {"count": count},
        bearer=token,
    )
    if status == 200 and isinstance(body, dict) and body.get("ok"):
        return body
    if status == 404:
        raise ValueError(f"License key not found: {license_key}")
    if status == 401:
        raise RuntimeError("Admin token rejected.")
    raise RuntimeError(f"Add seats failed (HTTP {status}): {body}")


def sync_seats(license_key, admin_token=None):
    """
    Pull the authoritative seat list from the worker and return it.
    Also writes license_seats.json to ~/.ai-prowler/ for local GUI use.
    Returns the full seat summary dict.
    """
    token = admin_token or _load_admin_token()
    if not token:
        raise RuntimeError("No admin token available.")
    status, body = _post(f"/seats/{license_key}/sync", {}, bearer=token)
    if status == 200 and isinstance(body, dict):
        # Write local cache
        seats_path = Path.home() / ".ai-prowler" / "license_seats.json"
        seats_path.write_text(
            json.dumps(body, indent=2), encoding="utf-8"
        )
        return body
    if status == 404:
        raise ValueError(f"License key not found: {license_key}")
    if status == 401:
        raise RuntimeError("Admin token rejected.")
    raise RuntimeError(f"Seat sync failed (HTTP {status}): {body}")


def validate_activation_code_format(code):
    """
    Quick local format check before making a network call.
    Returns (True, cleaned_code) or (False, error_message).
    Expected format: APRO-XXXXXX-XXXXXX-XXXXXX (22 chars with dashes)
    """
    import re
    code = code.strip().upper()
    if re.match(r'^APRO-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}$', code):
        return True, code
    return False, (
        "Activation code format is invalid.\n"
        "Expected format: APRO-XXXXXX-XXXXXX-XXXXXX\n"
        f"Got: {code}"
    )


def validate_license(license_key, install_id=None):
    """
    Validate a license key against the Subscription Worker (public endpoint,
    no admin token required — the license key itself is the credential).

    Called by rag_gui.py to drive the subscription status light.

    Args:
        license_key:  The AP-PERS-... or AP-BIZ-... key stored in config.json
                      after activation.
        install_id:   Optional machine identifier — used for last-seen analytics
                      on the Worker side (non-blocking, best-effort).

    Returns dict from the Worker:
        { valid: bool, reason?: str, edition?: str, expires_at?: str,
          status?: str, tier?: str }

    Raises RuntimeError on network failure or unexpected HTTP status.
    Caller (rag_gui.py) should catch and treat as offline/unmanaged.
    """
    qs = f"?install_id={install_id}" if install_id else ""
    status, body = _get(f"/license/{license_key}/validate{qs}")
    if status == 200 and isinstance(body, dict):
        return body
    raise RuntimeError(f"License validation failed (HTTP {status}): {body}")
