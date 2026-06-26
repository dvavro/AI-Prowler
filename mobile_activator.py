"""
mobile_activator.py
===================
Fetches an activation payload from the subscription worker and configures
the local AI-Prowler installation for remote (mobile) access.

What it does:
  1. Calls subscription_client.fetch_activation(code)
  2. Writes tunnel credentials to ~/.cloudflared/{tunnel_id}.json
  3. Updates ~/.ai-prowler/config.json with tunnel_domain, tunnel_token,
     license_key, plan, and seats (preserving all existing fields)
  4. Writes ~/.ai-prowler/remote_access.json with the full activation record
  5. For business plans: writes ~/.ai-prowler/license_seats.json
  6. Installs/restarts the cloudflared Windows service with the new token
  7. Returns a result dict for the GUI to display

Called by:
  rag_gui.py  -> _activate_mobile()  when user clicks "Configure Mobile Access"
  CLI usage:  python mobile_activator.py --code APRO-XXXXXX-XXXXXX-XXXXXX
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import subscription_client as sc

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

AI_PROWLER_DIR  = Path.home() / ".ai-prowler"
CLOUDFLARED_DIR = Path.home() / ".cloudflared"
CONFIG_PATH     = AI_PROWLER_DIR / "config.json"
REMOTE_PATH     = AI_PROWLER_DIR / "remote_access.json"
SEATS_PATH      = AI_PROWLER_DIR / "license_seats.json"

# cloudflared.exe — bundled in the AI-Prowler install directory
CLOUDFLARED_EXE = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "AI-Prowler" / "cloudflared.exe"

# Windows service name — must match what rag_gui.py uses for Start/Stop Tunnel
CLOUDFLARED_SERVICE = "cloudflared"


# ---------------------------------------------------------------------------
# Public API — called by rag_gui.py
# ---------------------------------------------------------------------------

def activate_from_code(code, progress_cb=None):
    """
    Full activation flow from an activation code string.

    Args:
        code        str  — the activation code (e.g. APRO-XXXXXX-XXXXXX-XXXXXX)
        progress_cb callable(str) — optional callback for status messages to show
                                    in the GUI during the multi-step process

    Returns:
        dict with keys:
            ok          bool   — True on success
            domain      str    — the tunnel domain (e.g. abc123.cfargotunnel.com)
            plan        str    — "personal" or "business"
            seats       int    — seat count
            license_key str    — the license key
            message     str    — human-readable summary for the GUI

    Raises:
        ValueError   — bad code format, code not found, already claimed elsewhere
        RuntimeError — network failure, cloudflared install failure
    """
    def _cb(msg):
        if progress_cb:
            progress_cb(msg)

    # Step 1 — validate format locally before hitting the network
    _cb("Validating activation code format...")
    valid, result = sc.validate_activation_code_format(code)
    if not valid:
        raise ValueError(result)
    code = result  # cleaned uppercase version

    # Step 2 — fetch payload from worker
    _cb("Contacting AI-Prowler activation server...")
    payload = sc.fetch_activation(code)

    # Step 3 — write all local files
    _cb("Writing tunnel configuration...")
    activate_from_payload(payload)

    # Step 4 — install / restart cloudflared service
    _cb("Configuring cloudflared tunnel service...")
    _install_cloudflared_service(payload["tunnel_token"])

    domain      = payload.get("domain", "")
    plan        = payload.get("plan", "personal")
    seats       = payload.get("seats", 1)
    license_key = payload.get("license_key", "")

    _cb(f"Activation complete — tunnel live at {domain}")

    return {
        "ok":          True,
        "domain":      domain,
        "plan":        plan,
        "seats":       seats,
        "license_key": license_key,
        "message":     (
            f"Mobile access activated successfully!\n"
            f"Plan: {plan.title()}  |  Seats: {seats}\n"
            f"Domain: {domain}\n"
            f"License: {license_key}"
        ),
    }


def activate_from_payload(payload):
    """
    Write all local config files from an already-fetched activation payload.
    Safe to call multiple times — re-activation overwrites cleanly.

    Args:
        payload  dict  — the activation payload returned by fetch_activation()
    """
    AI_PROWLER_DIR.mkdir(parents=True, exist_ok=True)
    CLOUDFLARED_DIR.mkdir(parents=True, exist_ok=True)

    tunnel_id    = payload["tunnel_id"]
    tunnel_token = payload["tunnel_token"]
    domain       = payload["domain"]
    license_key  = payload["license_key"]
    plan         = payload.get("plan", "personal")
    seats        = payload.get("seats", 1)
    expires_at   = payload.get("expires_at", "")
    account_tag  = payload.get("cloudflare_account_tag", "")

    # -- 1. Tunnel credentials file (~/.cloudflared/{tunnel_id}.json) ----------
    # cloudflared reads this when configured with --credentials-file.
    # The token-based flow (cloudflared tunnel run --token ...) doesn't need
    # this file, but we write it for reference and potential future use.
    cred_file = CLOUDFLARED_DIR / f"{tunnel_id}.json"
    cred_data = {
        "AccountTag":   account_tag,
        "TunnelID":     tunnel_id,
        "TunnelSecret": "",       # not available via token flow; token is self-contained
        "TunnelName":   f"ap-tunnel-{tunnel_id[:8]}",
    }
    _write_json(cred_file, cred_data)

    # -- 2. config.json — update tunnel fields, preserve all others -------------
    cfg = _load_json(CONFIG_PATH, default={})
    cfg["tunnel_domain"]  = domain
    cfg["tunnel_token"]   = tunnel_token
    cfg["license_key"]    = license_key
    cfg["plan"]           = plan
    cfg["seats"]          = seats
    cfg["expires_at"]     = expires_at
    # Keep remote_token (bearer) untouched — user sets that independently
    _write_json(CONFIG_PATH, cfg)

    # -- 3. remote_access.json — full activation record for the GUI -----------
    remote = {
        "activation_code":        payload.get("activation_code", ""),
        "license_key":            license_key,
        "plan":                   plan,
        "seats":                  seats,
        "domain":                 domain,
        "tunnel_id":              tunnel_id,
        "cloudflare_account_tag": account_tag,
        "expires_at":             expires_at,
        "activated_at":           _now_iso(),
        "worker_url":             sc.WORKER_URL,
    }
    _write_json(REMOTE_PATH, remote)

    # -- 4. license_seats.json — for business plans only ----------------------
    if plan == "business" and seats > 0:
        existing = _load_json(SEATS_PATH, default=None)
        # _load_json returns {} (empty dict) when file is missing/corrupt.
        # Treat a missing 'seats' list as a fresh first-activation.
        if existing is None or not existing.get("seats"):
            # First activation — create empty seat records
            seat_records = [
                {
                    "seat_id":     f"{license_key}-S{str(i+1).zfill(3)}",
                    "status":      "unassigned",
                    "assigned_to": None,
                    "assigned_at": None,
                }
                for i in range(seats)
            ]
            seats_data = {
                "license_key":      license_key,
                "seats_total":      seats,
                "seats_assigned":   0,
                "seats_unassigned": seats,
                "seats":            seat_records,
                "synced_at":        _now_iso(),
            }
            _write_json(SEATS_PATH, seats_data)
        else:
            # Re-activation — update header fields but preserve existing assignments
            existing["license_key"]  = license_key
            existing["seats_total"]  = seats
            existing["synced_at"]    = _now_iso()
            _write_json(SEATS_PATH, existing)


# ---------------------------------------------------------------------------
# cloudflared service management
# ---------------------------------------------------------------------------

def _install_cloudflared_service(tunnel_token):
    """
    Install cloudflared as a Windows service using the tunnel token.
    If the service already exists, stop it, update the token, and restart.

    Requires the process to be running with admin rights, OR for cloudflared
    to already be installed as a service (in which case we just update config).

    Note: sc.exe service operations require elevation. If AI-Prowler is not
    running elevated, we write the token to a pending file and show a UAC
    prompt via PowerShell to complete the install. This matches the existing
    "Activate Tunnel Service" pattern in rag_gui.py.
    """
    if not CLOUDFLARED_EXE.exists():
        raise RuntimeError(
            f"cloudflared.exe not found at {CLOUDFLARED_EXE}.\n"
            "Please reinstall AI-Prowler to restore cloudflared."
        )

    service_exists = _service_exists(CLOUDFLARED_SERVICE)

    if service_exists:
        # Stop existing service before reconfiguring
        _run_sc("stop", CLOUDFLARED_SERVICE, ignore_errors=True)
        time.sleep(2)

    # Write the token to a known location so the service startup script can read it
    token_file = AI_PROWLER_DIR / "tunnel_token.txt"
    token_file.write_text(tunnel_token, encoding="utf-8")

    if service_exists:
        # Service already installed — just update the token file and restart
        _run_sc("start", CLOUDFLARED_SERVICE, ignore_errors=True)
    else:
        # Install the service via cloudflared's built-in service command.
        # This requires elevation — launch via PowerShell runas if needed.
        _install_service_elevated(tunnel_token)


def _install_service_elevated(tunnel_token):
    """
    Run cloudflared service install with a UAC elevation prompt.
    Uses the same PowerShell Start-Process -Verb RunAs pattern as rag_gui.py.
    """
    cmd = (
        f'"{CLOUDFLARED_EXE}" tunnel run --token "{tunnel_token}"'
    )
    # First try direct install (works if already elevated)
    install_cmd = f'"{CLOUDFLARED_EXE}" service install'
    rc = subprocess.call(install_cmd, shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if rc == 0:
        return

    # Not elevated — use PowerShell RunAs
    ps_cmd = (
        f"Start-Process -FilePath '{CLOUDFLARED_EXE}' "
        f"-ArgumentList 'service','install' "
        f"-Verb RunAs -Wait"
    )
    subprocess.Popen(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    # Give UAC and install a moment
    time.sleep(4)

    # Start the service
    _run_sc("start", CLOUDFLARED_SERVICE, ignore_errors=True)


def _service_exists(name):
    """Return True if a Windows service with this name exists."""
    r = subprocess.run(
        ["sc", "query", name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return r.returncode == 0


def _run_sc(action, name, ignore_errors=False):
    """Run sc.exe to control a Windows service."""
    r = subprocess.run(
        ["sc", action, name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if r.returncode != 0 and not ignore_errors:
        err = r.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"sc {action} {name} failed: {err}")
    return r.returncode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path, default=None):
    """Load JSON from path, returning default if file missing or invalid."""
    try:
        if Path(path).exists():
            return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        pass
    return default if default is not None else {}


def _write_json(path, data):
    """Write data as indented JSON to path, creating parent dirs if needed."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def _now_iso():
    """Return current UTC time as ISO 8601 string."""
    import datetime
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Activate AI-Prowler mobile access from an activation code."
    )
    parser.add_argument("--code", required=True,
                        help="Activation code (format: APRO-XXXXXX-XXXXXX-XXXXXX)")
    parser.add_argument("--no-service", action="store_true",
                        help="Write config files only, skip cloudflared service install")
    args = parser.parse_args()

    def _print_progress(msg):
        print(f"  {msg}")

    print(f"\nAI-Prowler Mobile Activator")
    print(f"Code: {args.code.strip().upper()}")
    print()

    try:
        if args.no_service:
            # Config-only mode — useful for testing without admin rights
            valid, code = sc.validate_activation_code_format(args.code)
            if not valid:
                print(f"ERROR: {code}")
                sys.exit(1)
            payload = sc.fetch_activation(code)
            activate_from_payload(payload)
            print(f"Config files written (service install skipped).")
            print(f"Domain:  {payload.get('domain')}")
            print(f"Plan:    {payload.get('plan')}")
            print(f"License: {payload.get('license_key')}")
        else:
            result = activate_from_code(args.code, progress_cb=_print_progress)
            print()
            print(result["message"])
        sys.exit(0)

    except ValueError as e:
        print(f"\nActivation failed: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"\nError: {e}")
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)
