"""Server mode — SRV-API-01 role matrix (+ SRV-API-02 / -07 / -10 / -11).

Direct /pwa-api calls as each user (U1 David · owner, U2 Vicki · manager,
U3 Samual · field_crew). READ-ONLY probes only — every call here reads, or is
one the server must refuse outright; nothing is created, changed or sent. The
expected result for each (tool, role) comes from spec §6.11.1's role table.
The whole observed table is written to artifacts\\<run>\\server_role_matrix.md;
the test fails on any cell that differs from what's expected.

Cell values:  ok      the call ran (no ❌)
              denied  the tool ran and refused (❌ …)
              unknown HTTP 400 "Unknown tool" (not on the Jobs app allow-list)
              error   anything else (HTTP 5xx, other 4xx) — never expected

Tier A probes (run_script / check_sms_inbox / read_file_lines / write_file)
go straight to the server (the write guard would stop them first); their
arguments are harmless even if a probe were ever wrongly allowed: a script
path that doesn't exist, a 1-hour inbox read, a file read of the Jobs app's
own manifest, and write_file is sent with an empty path.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_api_matrix
"""
import json
import os
from pathlib import Path

import pytest

from api import http

KEYS = ["U1", "U2", "U3"]
ROLE = {"U1": "owner", "U2": "manager", "U3": "field_crew"}
ALL, CREW_NO, OWNER_ONLY, OWNER_MGR, NOBODY = "all", "crew_no", "owner_only", "owner_mgr", "nobody"


def _expect(rule: str, key: str) -> str:
    if rule == ALL:
        return "ok"
    if rule == CREW_NO:
        return "denied" if ROLE[key] == "field_crew" else "ok"
    if rule == OWNER_ONLY:
        return "ok" if ROLE[key] == "owner" else "denied"
    if rule == OWNER_MGR:
        return "ok" if ROLE[key] in ("owner", "manager") else "denied"
    return "unknown"          # NOBODY: not on the Jobs app allow-list for any role


SHEETS = ["Jobs_Schedule", "Customers", "TimeLog", "Route_Planner",
          "Invoices", "Quotes", "Services_Pricing", "Settings"]
BLOCKED = {"Invoices", "Quotes", "Services_Pricing", "Settings"}

# (label, tool, args, rule)
PROBES = (
    [(f"read {s}", "read_job_spreadsheet", {"sheet_name": s, "max_rows": 5},
      CREW_NO if s in BLOCKED else ALL) for s in SHEETS]
    + [(f"board feed {s}", "get_board_updates", {"since": "2099-01-01T00:00:00", "sheet_name": s},
        CREW_NO if s in BLOCKED else ALL) for s in ("Jobs_Schedule", "Customers", "Invoices", "Settings")]
    + [(f"columns {s}", "get_sheet_columns", {"sheet_name": s}, ALL) for s in ("Jobs_Schedule", "Customers")]
    + [
        ("status", "check_ai_prowler_status", {}, ALL),
        ("SMS configured?", "check_sms_configured", {}, ALL),
        ("email configured?", "check_email_configured", {}, ALL),
        ("route start options", "get_route_start_options", {}, ALL),
        # R-069 (David 2026-09-29): Customer Reminders list = owner, managers, staff
        ("stale customers (Reports)", "find_stale_customers", {}, CREW_NO),
        # R-068 (David 2026-09-29): AR aging report = owner and managers
        ("AR aging report (Reports)", "get_ar_aging_report", {}, OWNER_MGR),
        # SRV-API-10 / -11 (G-06): suspected to fail with HTTP 400 in server mode
        ("search learnings (G-06)", "search_learnings", {"query": "ZTEST matrix probe", "n_results": 1}, ALL),
        ("geocode address (G-06)", "geocode_address", {"address": "Canal Street, New Smyrna Beach, FL 32168"}, ALL),
        # SRV-API-02: Tier A — hidden in server mode for EVERY role, owner included
        ("Tier A run_script", "run_script", {"script_path": "C:\\ZTEST\\does_not_exist.bat"}, NOBODY),
        ("Tier A check_sms_inbox", "check_sms_inbox", {"since_hours": 1}, NOBODY),
        ("Tier A read_file_lines", "read_file_lines", {"filepath": "manifest.json", "start_line": 1}, NOBODY),
        ("Tier A write_file", "write_file", {"filepath": "", "content": ""}, NOBODY),
        # SRV-API-07: a made-up tool name → clear refusal, not a 500
        ("made-up tool", "ztest_no_such_tool", {}, NOBODY),
    ]
)


def _probe(srv, key, tool, args) -> tuple[str, str]:
    """(cell, excerpt) — straight HTTP as this user, no guard (probes are read-only / refused)."""
    status, raw = http("POST", srv["origin"] + "/pwa-api", {"tool": tool, "args": args},
                       token=srv["users"][key].access_token)
    try:
        data = json.loads(raw)
    except Exception:
        data = {}
    err = str(data.get("error", ""))
    res = str(data.get("result", ""))
    if status == 400 and "Unknown tool" in err:
        return "unknown", err[:120]
    if status >= 400 or not data.get("ok"):
        return "error", f"HTTP {status}: {(err or raw)[:120]}"
    # get_board_updates answers errors as a JSON object inside the result
    if tool == "get_board_updates" and res.lstrip().startswith("{") and '"error"' in res:
        return ("denied" if "access" in res.lower() else "error"), res[:120]
    # geocode_address reports a geocoder miss with ❌ too, but that's the tool
    # running, not a role refusal (found 2026-09-27: the old probe address
    # wasn't in OpenStreetMap and all three roles read as "denied").
    if tool == "geocode_address" and "Address not found" in res:
        return "ok", res[:120]
    return ("denied" if res.lstrip().startswith("❌") else "ok"), res[:120]


def test_SRV_API_01_role_matrix(srv):
    missing = [k for k in KEYS if k not in srv["users"]]
    if missing:
        pytest.skip(f"users not configured: {missing}")
    for k in KEYS:
        assert srv["users"][k].role == ROLE[k], f"{k} is {srv['users'][k].role}, matrix expects {ROLE[k]}"

    rows, diffs = [], []
    for label, tool, args, rule in PROBES:
        cells = []
        for k in KEYS:
            got, excerpt = _probe(srv, k, tool, args)
            want = _expect(rule, k)
            mark = "✅" if got == want else "❌"
            cells.append(f"{mark} {got}")
            if got != want:
                diffs.append(f"{label} as {k} ({ROLE[k]}): expected {want}, got {got} — {excerpt}")
        rows.append(f"| {label} | `{tool}` | " + " | ".join(cells) + " |")

    run_dir = Path(os.environ.get("E2E_RUN_DIR") or ".")
    table = ("| Probe | Tool | U1 owner | U2 manager | U3 field_crew |\n|---|---|---|---|---|\n"
             + "\n".join(rows) + "\n")
    (run_dir / "server_role_matrix.md").write_text(
        "# Server role matrix (SRV-API-01)\n\n" + table
        + ("\n## Differences from spec §6.11.1\n\n" + "\n".join(f"- {d}" for d in diffs) + "\n" if diffs else
           "\nNo differences from spec §6.11.1.\n"),
        encoding="utf-8")
    assert not diffs, "role matrix differs from spec §6.11.1:\n  " + "\n  ".join(diffs)
