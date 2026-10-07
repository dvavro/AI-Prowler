"""Parses the 'Route Map URL' the app saves onto each routed job (spec
§6.5.5). Format, from ai_prowler_mcp.py's _google_url():

    https://www.google.com/maps/dir/?api=1[&origin=<enc>]&destination=<enc>
        &travelmode=driving&dir_action=navigate[&waypoints=<enc>%7C<enc>...]

Waypoints are every stop except the last; the destination is the last stop.
"""
from __future__ import annotations

from urllib.parse import unquote_plus, urlparse, parse_qs


class ParsedMapsLink:
    def __init__(self, url: str):
        self.url = url
        p = urlparse(url)
        if p.netloc not in ("www.google.com", "google.com") or "/maps/dir/" not in p.path:
            raise ValueError(f"not a Google Maps directions link: {url}")
        q = parse_qs(p.query, keep_blank_values=True)
        self.origin = (q.get("origin") or [""])[0]
        self.destination = (q.get("destination") or [""])[0]
        self.travelmode = (q.get("travelmode") or [""])[0]
        raw_wp = (q.get("waypoints") or [""])[0]
        # Google's own separator is a literal "|", but the app percent-encodes
        # it (%7C) per spec — parse_qs already decoded %XX once, so a literal
        # "|" is what should be left if encoding was correct (PL-04/PL-07
        # regressions are about the STOPS matching, not this encoding step).
        self.waypoints = [unquote_plus(w) for w in raw_wp.split("|")] if raw_wp else []

    @property
    def stops_in_order(self) -> list[str]:
        """Every stop this link visits, in visit order (waypoints, then the
        final destination — the destination is never itself a waypoint)."""
        return self.waypoints + ([self.destination] if self.destination else [])

    @property
    def has_origin(self) -> bool:
        return bool(self.origin)

    @property
    def waypoint_count(self) -> int:
        return len(self.waypoints)

    def consecutive_duplicate(self):
        """PL-04 / R-001: index + address of the first stop that is the same
        place as the one immediately before it, or None if there isn't one."""
        stops = self.stops_in_order
        for i in range(1, len(stops)):
            if stops[i] and stops[i] == stops[i - 1]:
                return i, stops[i]
        return None


def parse(url: str) -> ParsedMapsLink:
    return ParsedMapsLink(url)


def extract_url(field_value: str) -> str:
    """The 'Route Map URL' column (and build_maps_url's own text reply) wraps
    the URL in explanatory text — pull out the first https://...maps... URL."""
    for tok in (field_value or "").split():
        if tok.startswith("https://") and "maps" in tok:
            return tok.rstrip(").,")
    raise ValueError(f"no maps URL found in: {field_value!r}")
