"""How the Estimator web app plugs into the running AI-Prowler (Coder 2, Sprint 1).

ai_prowler_mcp.py calls start_from_ai_prowler() once, from the process that
owns AI-Prowler's own HTTP server (never from a stdio copy started by Claude
Desktop, never under pytest). This module keeps the glue out of that 37k-line
file so it can be tested on its own.

Server mode sign-in uses AI-Prowler's accounts (users.json), the same check
the Service Desk app's /desk-api/auth/login does: the user types their name
and their AI-Prowler password (their access token); the token must belong to
an active user whose name matches.

AI-Prowler roles are not Estimator roles, so they are mapped (least access
first; Jamie owns the final mapping, see the spec's Change log):

    owner      -> owner
    manager    -> office      (quotes and customers, no hand-entered lines)
    staff      -> office
    field_crew -> field       (totals only, never costs or margins)

A user can be given a different Estimator role with "estimator_role" in
users.json (owner, estimator, reviewer, office or field). "none" keeps them
out of the Estimator.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Callable

from estimator.context import PERSONAL_COMPANY_ID, ROLES

log = logging.getLogger("estimator.api.prowler_link")

ROLE_MAP = {"owner": "owner", "manager": "office", "staff": "office", "field_crew": "field"}
NO_ACCESS = "none"


def estimator_role(user: dict) -> str:
    """The Estimator role for an AI-Prowler user, or "" for no access."""
    override = str(user.get("estimator_role") or "").strip().lower()
    if override == NO_ACCESS:
        return ""
    if override in ROLES:
        return override
    return ROLE_MAP.get(str(user.get("role") or "").strip().lower(), "")


def make_server_verifier(load_users: Callable[[], "dict | None"],
                         resolve_user: Callable[["dict | None", str], "dict | None"]):
    """A verifier for auth.configure(): (name, password) -> who, or None.

    load_users():                 AI-Prowler's users.json (re-read each time, so
                                  a revoked user is out at once).
    resolve_user(data, token):    AI-Prowler's own lookup (active users only,
                                  adds the stable "id").
    """
    def verify(username: str, password: str) -> "dict | None":
        name = (username or "").strip()
        if not name or not password:
            return None
        data = load_users()
        user = resolve_user(data, password) if data else None
        if not user or str(user.get("name") or "").strip().lower() != name.lower():
            return None
        role = estimator_role(user)
        if not role:
            return None
        return {"user_id": str(user.get("id") or name), "role": role, "name": str(user.get("name") or name),
                "company_id": str((data or {}).get("company_id") or PERSONAL_COMPANY_ID)}
    return verify


def should_start(is_http_server: bool) -> tuple[bool, str]:
    """Whether this process should run the web app, and why not."""
    if not is_http_server:
        return False, "not AI-Prowler's own HTTP server process (stdio copy or imported module)"
    if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
        return False, "running under pytest"
    if os.environ.get("ESTIMATOR_WEB", "").strip().lower() in ("off", "0", "false", "no"):
        return False, "ESTIMATOR_WEB=off"
    return True, ""


def start_from_ai_prowler(*, is_http_server: bool, server_mode: bool,
                          load_users: Callable[[], "dict | None"] | None = None,
                          resolve_user: Callable | None = None) -> str:
    """Configure sign-in for this AI-Prowler and start the web app. Never raises.
    Returns the local URL, or "" when it didn't start."""
    try:
        ok, why = should_start(is_http_server)
        if not ok:
            log.info("Estimator web app not started: %s", why)
            return ""
        from estimator.api import auth, server
        if server_mode:
            if load_users is None or resolve_user is None:
                log.warning("Estimator web app not started: Server mode needs AI-Prowler's account lookup")
                return ""
            # users.json is read at each sign-in (not here): this runs while ai_prowler_mcp.py is
            # still loading, and the company id comes back with each verified user.
            auth.configure(mode="server", verifier=make_server_verifier(load_users, resolve_user))
        else:
            auth.configure(mode="personal")
        return server.start_with_ai_prowler()
    except Exception as e:  # noqa: BLE001 - the Estimator must never stop AI-Prowler starting
        log.warning("Estimator web app not started: %s", e)
        return ""
