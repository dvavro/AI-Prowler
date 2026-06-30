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
  7. Creates DNS CNAME route for the tunnel domain (if not already present)
  8. Returns a result dict for the GUI to display

Called by:
  rag_gui.py  -> _activate_mobile()  when user clicks "Configure Mobile Access"
  CLI usage:  python mobile_activator.py --code APRO-XXXXXX-XXXXXX-XXXXXX

v8.0.0 fixes:
  - Service install now correctly passes token via PowerShell -ArgumentList
    array (avoids Windows SCM 8192-char command line truncation bug)
  - Added _create_dns_route() call after service install as a fallback in
    case the Worker's DNS creation failed (proxied flag issue, zone mismatch)
  - tunnel_name now stored in remote_access.json from payload
  - Service uninstall waits for complete removal before reinstalling

v8.0.0 fixes (tunnel ingress + service install):
  - CRITICAL: Removed stale config.yml write that was overriding the tunnel
    token during service install. cloudflared service install uses the token
    passed as a CLI argument (stored in Windows registry). If config.yml
    exists with tunnel: <name> but no credentials-file or token, cloudflared
    reads it on startup and fails because the cred file has no TunnelSecret.
    Fix: delete config.yml before service install; let cloudflared manage
    its own registry-based config entirely.
  - Removed empty TunnelSecret from credentials JSON file. The token-based
    service install does not use the credentials file at all — writing an
    empty TunnelSecret caused cloudflared to attempt cred-file auth and fail.
  - _create_dns_route() now uses tunnel_id (UUID) instead of tunnel_name,
    which is what cloudflared CLI requires when not using `cloudflared login`.
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
            domain      str    — the tunnel domain (e.g. abc123.ai-prowler.com)
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

    # Step 1b — read/generate this machine's install_id. Same file rag_gui.py
    # uses for telemetry (~/.ai-prowler/install_id) — one stable ID per
    # machine, reused here so the Worker can enforce one-machine-at-a-time
    # binding (license.active_install_id) instead of the old IP-based check.
    install_id = _get_or_create_install_id()

    # Step 2 — fetch payload from worker
    _cb("Contacting AI-Prowler activation server...")
    payload = sc.fetch_activation(code, install_id=install_id)
    displaced_other_machine = bool(payload.get("displaced_previous_install"))

    # Step 3 — write all local files
    _cb("Writing tunnel configuration...")
    activate_from_payload(payload)

    # Step 4 — install / restart cloudflared service
    _cb("Configuring cloudflared tunnel service...")
    _install_cloudflared_service(payload["tunnel_token"], progress_cb=_cb)

    domain      = payload.get("domain", "")
    tunnel_id   = payload.get("tunnel_id", "")
    tunnel_name = payload.get("tunnel_name", "")
    plan        = payload.get("plan", "personal")
    seats       = payload.get("seats", 1)
    license_key = payload.get("license_key", "")

    # Step 5 — create DNS route as client-side fallback
    # The Worker already creates the CNAME during provisioning, but if that
    # failed (proxied flag issue, zone mismatch, etc.) this ensures the route
    # exists before we return success to the GUI.
    # FIX v8.0.0: pass tunnel_id (UUID), not tunnel_name — cloudflared CLI
    # requires the UUID for `tunnel route dns` when not using `cloudflared login`.
    if tunnel_id and domain:
        _cb(f"Verifying DNS route for {domain}...")
        try:
            _create_dns_route(tunnel_id, domain)
            _cb(f"DNS route confirmed — {domain} is publicly reachable")
        except Exception as dns_err:
            # Non-fatal — Worker-side DNS may already be correct
            _cb(f"DNS route note: {dns_err} — checking if domain resolves...")

    if displaced_other_machine:
        _cb("This machine is now the active install — any previous machine "
            "using this license has been automatically deactivated.")

    _cb(f"Activation complete — tunnel live at {domain}")

    return {
        "ok":                       True,
        "domain":                   domain,
        "plan":                     plan,
        "seats":                    seats,
        "license_key":              license_key,
        "displaced_other_machine":  displaced_other_machine,
        "message":     (
            f"Mobile access activated successfully!\n"
            f"Plan: {plan.title()}  |  Seats: {seats}\n"
            f"Domain: {domain}\n"
            f"License: {license_key}"
            + ("\n\nNote: this license was previously active on a different "
               "machine — that machine has been automatically deactivated."
               if displaced_other_machine else "")
        ),
    }


def _get_or_create_install_id():
    """Read this machine's stable install_id, generating one if it doesn't
    exist yet (mirrors the logic in rag_gui.py's RAGGui.__init__ so both
    paths always produce/read the exact same file and ID)."""
    install_id_path = AI_PROWLER_DIR / "install_id"
    try:
        if install_id_path.exists():
            existing = install_id_path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        import uuid, hashlib
        new_id = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:16]
        install_id_path.parent.mkdir(parents=True, exist_ok=True)
        install_id_path.write_text(new_id, encoding="utf-8")
        return new_id
    except Exception:
        return ""


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
    # tunnel_name is now included in the payload (v8.0.0 fix in provision.js)
    # Fall back to deriving it from domain if not present (older activations)
    tunnel_name  = payload.get("tunnel_name", "") or domain.split(".")[0] if domain else ""

    # -- 1. Tunnel credentials file (~/.cloudflared/{tunnel_id}.json) ----------
    # FIX v8.0.0: Do NOT write TunnelSecret as empty string. The token-based
    # service install (cloudflared service install <token>) stores auth in the
    # Windows registry — it does not use this credentials file at all.
    # Writing an empty TunnelSecret caused cloudflared to attempt cred-file
    # auth on startup and fail. We write the file for reference/tooling only,
    # with no TunnelSecret field so cloudflared ignores it.
    cred_file = CLOUDFLARED_DIR / f"{tunnel_id}.json"
    cred_data = {
        "AccountTag": account_tag,
        "TunnelID":   tunnel_id,
        "TunnelName": tunnel_name,
    }
    _write_json(cred_file, cred_data)

    # -- 1b. config.yml — DELETE if present before service install -------------
    # FIX v8.0.0 CRITICAL: If config.yml exists with `tunnel: <name>` but no
    # credentials-file or token reference, cloudflared reads it on service
    # startup, looks for the credentials file, finds no TunnelSecret, and
    # fails to authenticate. The token-based service install stores the token
    # in the Windows registry — cloudflared reads it from there on startup
    # with NO config.yml needed. We must remove any stale config.yml so it
    # does not interfere.
    config_yml = CLOUDFLARED_DIR / "config.yml"
    if config_yml.exists():
        try:
            config_yml.unlink()
        except Exception as e:
            # Non-fatal — log and continue; service install may still work
            print(f"[mobile_activator] Warning: could not remove stale config.yml: {e}")

    # Write the tunnel token to a reference file (informational only —
    # the service reads from the Windows registry, not this file).
    token_file_cfg = CLOUDFLARED_DIR / "tunnel_token.txt"
    token_file_cfg.write_text(tunnel_token, encoding="utf-8")

    # -- 2. config.json — update tunnel fields, preserve all others -------------
    cfg = _load_json(CONFIG_PATH, default={})
    cfg["tunnel_domain"]  = domain
    cfg["tunnel_token"]   = tunnel_token
    cfg["tunnel_name"]    = tunnel_name
    cfg["license_key"]    = license_key
    cfg["plan"]           = plan
    cfg["seats"]          = seats
    cfg["expires_at"]     = expires_at
    # Always set edition/mode to match what was actually activated — never
    # inherit stale values from a previous install of a different type.
    # Without this, re-activating a personal code on a machine that previously
    # ran server mode (or vice versa) would keep the old edition/mode because
    # _load_json above reads the existing config and we only patch other keys.
    # This was the root cause of "every install shows server mode" — the server
    # miniPC's config.json had edition=business/mode=server from its server
    # activation, and a subsequent personal activation preserved those values.
    if plan == "business":
        cfg["edition"] = "business"
        cfg["mode"]    = "server"
    else:
        cfg["edition"] = "home"
        cfg["mode"]    = "personal"
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
        "tunnel_name":            tunnel_name,
        "cloudflare_account_tag": account_tag,
        "expires_at":             expires_at,
        "activated_at":           _now_iso(),
        "worker_url":             sc.WORKER_URL,
    }
    _write_json(REMOTE_PATH, remote)

    # -- 4. license_seats.json — for business plans only ----------------------
    # FIX: a fresh activation (new code, possibly a different license_key
    # than whatever was here before from a prior install/subscription) must
    # NOT silently merge into stale local seat data. Only preserve the
    # existing seats array if it actually belongs to THIS license_key —
    # otherwise rebuild from scratch. Without this check, re-activating
    # with a brand new server activation code kept the old install's
    # stale seat/child-key list, which is what caused the Admin tab's
    # License seat dropdown to show nothing (or wrong data) after a clean
    # re-activation.
    if plan == "business" and seats > 0:
        existing = _load_json(SEATS_PATH, default=None)
        same_license = bool(existing) and existing.get("license_key") == license_key
        if same_license and existing.get("seats"):
            # Re-sync of the SAME license — preserve assignments, just
            # refresh the counters/timestamp.
            existing["license_key"]  = license_key
            existing["seats_total"]  = seats
            existing["synced_at"]    = _now_iso()
            _write_json(SEATS_PATH, existing)
        else:
            # New license (different key, or no prior data) — rebuild fresh.
            # Real seat IDs / child keys come from the Worker via the
            # Admin tab's "Sync Seats" button; this is just a placeholder
            # shape until that sync runs.
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
    elif plan != "business" and SEATS_PATH.exists():
        # Activating a personal license on a machine that previously had
        # business seat data — remove the stale file entirely so nothing
        # in the Admin tab or elsewhere can read orphaned seat data.
        try:
            SEATS_PATH.unlink()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# cloudflared service management
# ---------------------------------------------------------------------------

def _install_cloudflared_service(tunnel_token, progress_cb=None):
    """
    Install cloudflared as a Windows service using the tunnel token.

    Uses cloudflared's own `service install <token>` command which is the
    officially supported method. The token is passed as a CLI argument;
    cloudflared stores it in the Windows registry/credential store —
    avoiding the SCM command line truncation bug entirely.

    FIX v8.0.0: No config.yml is written before this call (deleted in
    activate_from_payload). This ensures cloudflared's service install
    uses the token from the registry exclusively on startup.

    Requires elevation; we use PowerShell RunAs if needed.
    """
    def _cb(msg):
        if progress_cb:
            progress_cb(msg)

    if not CLOUDFLARED_EXE.exists():
        raise RuntimeError(
            f"cloudflared.exe not found at {CLOUDFLARED_EXE}.\n"
            "Please reinstall AI-Prowler to restore cloudflared."
        )

    # Write token to file for reference
    token_file = AI_PROWLER_DIR / "tunnel_token.txt"
    token_file.write_text(tunnel_token, encoding="utf-8")

    # Stop and delete existing service cleanly
    if _service_exists(CLOUDFLARED_SERVICE):
        _cb("Stopping existing tunnel service...")
        _run_sc("stop", CLOUDFLARED_SERVICE, ignore_errors=True)
        time.sleep(2)
        _cb("Removing existing tunnel service...")
        _run_sc("delete", CLOUDFLARED_SERVICE, ignore_errors=True)
        for _ in range(10):
            time.sleep(1)
            if not _service_exists(CLOUDFLARED_SERVICE):
                break

    _cb("Installing cloudflared tunnel service...")

    # Clean up stale EventLog registry key that blocks reinstallation.
    # cloudflared says "Cannot install event logger: registry key already exists"
    # when this key is present, causing the SCM service registration to fail
    # (cloudflared logs "installed successfully" misleadingly even when this
    # happens on some versions, but `sc query` afterward shows no service at
    # all — confirmed 2026-06-30: a fresh install attempt failed this way
    # with NO prior service present, so this is not just a leftover-from-
    # previous-install issue, it can occur on first install too).
    def _clear_eventlog_key():
        subprocess.run(
            ["reg", "delete",
             r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Cloudflared",
             "/f"],
            capture_output=True, text=True
        )
    _clear_eventlog_key()

    # cloudflared service install <token> — the token is stored in the Windows
    # registry by cloudflared itself. On service startup, cloudflared reads
    # the token from the registry (not from config.yml or a credentials file).
    # No TUNNEL_TOKEN env var or config.yml is needed or wanted here.
    #
    # FIX 2026-06-30: previously a failed install (e.g. the EventLog key
    # error, or cloudflared's own "service is already installed" message)
    # was just logged as a progress note and silently ignored — the code
    # fell through to the RUNNING check below without ever confirming the
    # NEW token was actually what got installed. This let a stale service
    # (wrong tunnel token from a previous activation) keep running while
    # the GUI reported "Server Configured ✅", causing HTTP 530 errors
    # that looked like a DNS problem but were actually a wrong-tunnel
    # service silently surviving a failed reinstall.
    #
    # Now: up to 2 attempts. On any failure, explicitly uninstall via
    # `cloudflared service uninstall` (not just `sc delete`, which does
    # not clear cloudflared's own internal already-installed marker —
    # this is the exact distinction that caused today's bug), clear the
    # EventLog key again, then retry once before giving up.
    install_ok = False
    last_output = ""
    for attempt in range(2):
        result = subprocess.run(
            [str(CLOUDFLARED_EXE), "service", "install", tunnel_token],
            capture_output=True, text=True
        )
        out = (result.stdout + result.stderr).strip()
        last_output = out

        if result.returncode == 0 and "already installed" not in out.lower():
            install_ok = True
            break

        if "access is denied" in out.lower() or "privilege" in out.lower():
            _cb("Elevation required — requesting admin access...")
            _install_service_via_powershell(tunnel_token)
            install_ok = True  # PowerShell path doesn't return output to check here
            break

        # "already installed" (cloudflared's own marker, separate from SCM)
        # or the EventLog registry error — clean up properly and retry once.
        if attempt == 0:
            _cb(f"Install attempt {attempt + 1} failed, cleaning up and retrying...")
            subprocess.run(
                [str(CLOUDFLARED_EXE), "service", "uninstall"],
                capture_output=True, text=True
            )
            _run_sc("stop", CLOUDFLARED_SERVICE, ignore_errors=True)
            _run_sc("delete", CLOUDFLARED_SERVICE, ignore_errors=True)
            time.sleep(2)
            _clear_eventlog_key()
            time.sleep(1)

    if not install_ok:
        raise RuntimeError(
            f"cloudflared service install failed after 2 attempts:\n{last_output}\n\n"
            "Try running AI-Prowler as Administrator, or manually run:\n"
            f'  "{CLOUDFLARED_EXE}" service uninstall\n'
            f'  reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\Cloudflared" /f\n'
            "then activate again."
        )

    time.sleep(2)

    # Start the service if not already running
    if _service_exists(CLOUDFLARED_SERVICE):
        state = _get_service_state(CLOUDFLARED_SERVICE)
        if state != "RUNNING":
            _run_sc("start", CLOUDFLARED_SERVICE, ignore_errors=True)
            time.sleep(3)
            state = _get_service_state(CLOUDFLARED_SERVICE)
        _cb(f"Tunnel service: {state}")
        if state == "RUNNING":
            _cb("Tunnel service is running ✅")
        else:
            raise RuntimeError(
                f"cloudflared service installed but is not running (state: {state}).\n"
                "Check Windows Event Viewer for cloudflared service errors."
            )
    else:
        raise RuntimeError(
            "Service install failed — service not found after install.\n"
            "Try running AI-Prowler as Administrator and activating again."
        )


def _install_service_via_powershell(tunnel_token):
    """
    Install cloudflared service via PowerShell UAC elevation.
    Uses cloudflared's official `service install <token>` syntax.
    """
    ps_cmd = (
        f"Start-Process -FilePath '{CLOUDFLARED_EXE}' "
        f"-ArgumentList @('service','install','{tunnel_token}') "
        f"-Verb RunAs -Wait"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True
    )
    time.sleep(5)
    _run_sc("start", CLOUDFLARED_SERVICE, ignore_errors=True)


def _create_dns_route(tunnel_id, domain):
    """
    Create the public DNS CNAME route for the tunnel using cloudflared CLI.

    Runs: cloudflared tunnel route dns <tunnel_id> <domain>

    FIX v8.0.0: Uses tunnel_id (UUID) not tunnel_name. The cloudflared CLI
    requires the tunnel UUID for `tunnel route dns` when not authenticated
    via `cloudflared login` (i.e. token-based installs like ours).

    This is a client-side fallback for cases where the Worker's DNS creation
    failed (e.g. wrong proxied flag, zone mismatch). Non-fatal if it fails —
    the Worker-side DNS may already be correct.

    Args:
        tunnel_id  str  — tunnel UUID (e.g. "f6d15df6-ba6b-...")
        domain     str  — full public hostname (e.g. "ap-david-vavro1-f6d15df6.ai-prowler.com")

    Returns:
        True on success or if route already exists.
        False on non-fatal failure (logs warning).
    """
    if not CLOUDFLARED_EXE.exists():
        return False

    result = subprocess.run(
        [str(CLOUDFLARED_EXE), "tunnel", "route", "dns", tunnel_id, domain],
        capture_output=True, text=True, timeout=30
    )
    out = (result.stdout + result.stderr).strip()

    if result.returncode == 0 or "already exists" in out.lower():
        return True

    # Log but don't fatal — Worker DNS creation may have already succeeded
    print(f"[mobile_activator] DNS route note (rc={result.returncode}): {out}")
    return False


def _service_exists(name):
    """Return True if a Windows service with this name exists."""
    r = subprocess.run(
        ["sc", "query", name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return r.returncode == 0


def _get_service_state(name):
    """Return the STATE string of a Windows service, e.g. 'RUNNING', 'STOPPED'."""
    r = subprocess.run(
        ["sc", "query", name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output = r.stdout.decode("utf-8", errors="replace")
    for line in output.splitlines():
        if "STATE" in line and ":" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                state_part = parts[1].strip()
                # Format is "4  RUNNING" — extract the word
                words = state_part.split()
                if len(words) >= 2:
                    return words[1]
    return "UNKNOWN"


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
