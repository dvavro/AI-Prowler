"""Zip codes: the place a job is in, and which NEC edition governs it.

Zippopotam.us (https://api.zippopotam.us/us/<zip>) answers a zip code with the
city, state and state abbreviation - free, no API key. It does NOT return a
county, so nothing here pretends it does. Results are cached in zip_cache, so
a zip looked up once never touches the network again; when the API is
unreachable the lookup returns None and the caller carries on with just the
zip, flagged as unverified - the inspection review works offline.

The NEC edition is set by the permit application date, so the review uses the
current date to pick the edition and says so. Florida is the only state in the
local table (David's jobs are in Florida); any other state gets a fallback
telling the user to confirm the edition with the AHJ. code_edition() generalizes
nec_edition() per trade: electrical gets the NEC year, the other construction
trades get the Florida Building Code edition (Plumbing and Mechanical for those
two trades), all on the same December 31, 2026 switch.
"""
from __future__ import annotations

import json
import re
import sqlite3
import urllib.error
import urllib.request
from datetime import date, datetime, timezone

ZIP_RE = re.compile(r"\b\d{5}\b")
_API = "https://api.zippopotam.us/us/"
_TIMEOUT = 10  # seconds; a slow lookup must not hold up the review

# Florida Building Code: the 8th Edition adopts the 2020 NEC until
# December 30, 2026; the 9th Edition adopts the 2023 NEC from December 31, 2026.
_FLORIDA_SWITCH = date(2026, 12, 31)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_zip_from_address(address: str | None) -> str | None:
    """The zip code in an address: the LAST 5-digit number (the zip is conventionally last)."""
    found = ZIP_RE.findall(address or "")
    return found[-1] if found else None


def _valid(zip_code) -> str | None:
    z = str(zip_code or "").strip()
    return z if re.fullmatch(r"\d{5}", z) else None


def lookup_zip(zip_code, conn=None) -> dict | None:
    """{zip, city, state, state_abbr} for a zip code, or None.

    A bad zip (not exactly 5 digits) is rejected before any network call. When
    conn is given, the zip_cache table is checked first and a fresh result is
    stored (and committed) - a cache hit never touches the network. A zip the
    API doesn't know (HTTP 404) returns None, as does an unreachable API
    (timeout, any error): the caller treats that as an unverified jurisdiction.
    """
    z = _valid(zip_code)
    if z is None:
        return None
    if conn is not None:
        try:
            row = conn.execute(
                "SELECT city, state, state_abbr FROM zip_cache WHERE zip_code = ?", (z,)).fetchone()
        except sqlite3.OperationalError:
            row = None  # a pre-v28 database has no cache table yet
        if row:
            return {"zip": z, "city": row["city"], "state": row["state"],
                    "state_abbr": row["state_abbr"]}
    try:
        req = urllib.request.Request(_API + z, headers={"User-Agent": "AI-Prowler-Estimator/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - 404, timeout, DNS: all mean "no place for this zip"
        return None
    places = payload.get("places") or []
    if not places:
        return None
    place = places[0]
    out = {"zip": z, "city": place.get("place name"), "state": place.get("state"),
           "state_abbr": place.get("state abbreviation")}
    if not out["city"] or not out["state_abbr"]:
        return None
    if conn is not None:
        try:
            conn.execute("INSERT OR REPLACE INTO zip_cache (zip_code, city, state, state_abbr, looked_up_at)"
                         " VALUES (?,?,?,?,?)", (z, out["city"], out["state"], out["state_abbr"], _now()))
            conn.commit()
        except sqlite3.OperationalError:
            pass  # a pre-v28 database has no cache table yet
    return out


def _as_date(on_date) -> date:
    if on_date is None:
        return date.today()
    if isinstance(on_date, date):
        return on_date
    return date.fromisoformat(str(on_date).strip())


def nec_edition(state_abbr: str | None, on_date=None) -> dict:
    """{edition, code, note} for a state on a date (today by default).

    Florida: 2020 NEC under the FBC 8th Edition until December 30, 2026, then
    2023 NEC under the FBC 9th Edition from December 31, 2026. Any other state
    is not in the local table: edition None, and a note to confirm with the AHJ.
    """
    if (state_abbr or "").strip().upper() == "FL":
        if _as_date(on_date) < _FLORIDA_SWITCH:
            return {"edition": "2020", "code": "FBC 8th Edition",
                    "note": "Florida Building Code 8th Edition adopts the 2020 NEC until December 30, 2026."}
        return {"edition": "2023", "code": "FBC 9th Edition",
                "note": "Florida Building Code 9th Edition adopts the 2023 NEC from December 31, 2026."}
    return {"edition": None, "code": None,
            "note": "not in the local table — confirm the edition with the AHJ."}


def code_edition(state_abbr: str | None, module_id: str, on_date=None) -> dict:
    """{edition, code, note} for a trade in a state on a date (today by default).

    Electrical delegates to nec_edition (the NEC year under the FBC edition).
    The other Florida construction trades get the Florida Building Code
    edition on the same switch: 8th Edition until December 30, 2026, 9th
    Edition from December 31, 2026 — plumbing under the Florida Plumbing Code
    and HVAC under the Florida Mechanical Code. Any other state is not in the
    local table: edition None, and a note to confirm with the AHJ.
    """
    if (state_abbr or "").strip().upper() != "FL":
        return {"edition": None, "code": None,
                "note": "not in the local table — confirm the edition with the AHJ."}
    if module_id == "electrical":
        return nec_edition(state_abbr, on_date)
    if _as_date(on_date) < _FLORIDA_SWITCH:
        edition, num, when = "8th Edition", "8th", "until December 30, 2026"
    else:
        edition, num, when = "9th Edition", "9th", "from December 31, 2026"
    if module_id == "plumbing":
        code = f"Florida Plumbing Code {num} Edition"
    elif module_id == "hvac":
        code = f"Florida Mechanical Code {num} Edition"
    else:
        code = f"Florida Building Code {num} Edition"
    return {"edition": edition, "code": code,
            "note": f"{code} in effect {when}."}
