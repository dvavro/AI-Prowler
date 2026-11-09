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
    manager    -> office      (quotes and customers; approves measurements and symbols)
    staff      -> office
    field_crew -> field       (totals only, never costs or margins; looks at symbols, never approves)

A manager or staff member with the Estimating scope (Admin -> Manage Scopes) is an estimator instead: they
build and edit estimates, prices and takeoffs (David, 2026-11-09). Field crews stay field with or without it.

A user can still be given a different Estimator role with "estimator_role" in
users.json (owner, estimator, reviewer, office or field); it wins over the scope. "none" keeps them
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
# The Estimating scope (David, 2026-11-09): a manager or staff member with it, ticked in AI-Prowler's
# Admin -> Manage Scopes, builds and edits estimates, prices and takeoffs (Estimator role "estimator").
# It doesn't change owners, and field crews stay field.
ESTIMATING_SCOPES = ("estimating", "estimator")
SCOPE_ROLES = ("manager", "staff")


def _scope_names(user: dict) -> set[str]:
    """The user's scopes, bare and lower case ('scope:Estimating' -> 'estimating'), like scope_lookup."""
    raw = user.get("scopes") or []
    if isinstance(raw, str):
        raw = [raw]
    out = set()
    for s in raw:
        s = str(s or "").strip().lower()
        if s.startswith(("scope:", "role:")):
            s = s.split(":", 1)[1]
        out.add(s.strip())
    return out


def has_estimating_scope(user: dict) -> bool:
    return bool(_scope_names(user) & set(ESTIMATING_SCOPES))


def estimator_role(user: dict) -> str:
    """The Estimator role for an AI-Prowler user, or "" for no access."""
    override = str(user.get("estimator_role") or "").strip().lower()
    if override == NO_ACCESS:
        return ""
    if override in ROLES:
        return override
    role = str(user.get("role") or "").strip().lower()
    if role in SCOPE_ROLES and has_estimating_scope(user):
        return "estimator"
    return ROLE_MAP.get(role, "")


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


def personal_app_token_resolver(is_valid: Callable[[str], bool], owner_name: Callable[[], str] | None = None):
    """Personal mode: a valid AI-Prowler app token (the Jobs app's Bearer) is the owner."""
    def resolve(token: str) -> "dict | None":
        if not token or not is_valid(token):
            return None
        name = ""
        if owner_name is not None:
            try:
                name = owner_name() or ""
            except Exception:  # noqa: BLE001 - the name is only for display
                name = ""
        return {"user_id": "owner", "role": "owner", "name": name or "Owner", "company_id": PERSONAL_COMPANY_ID}
    return resolve


def server_app_token_resolver(raw_token_for: Callable[[str], "str | None"],
                              load_users: Callable[[], "dict | None"],
                              resolve_user: Callable[["dict | None", str], "dict | None"]):
    """Server mode: the Jobs app's access token -> its users.json user (active only) -> Estimator role.
    raw_token_for(access_token) is AI-Prowler's own lookup (it also applies the Jobs app's idle timeout)."""
    def resolve(token: str) -> "dict | None":
        raw = raw_token_for(token) if token else None
        if not raw:
            return None
        data = load_users()
        user = resolve_user(data, raw) if data else None
        if not user:
            return None
        role = estimator_role(user)
        if not role:
            return None
        return {"user_id": str(user.get("id") or ""), "role": role, "name": str(user.get("name") or ""),
                "company_id": str((data or {}).get("company_id") or PERSONAL_COMPANY_ID)}
    return resolve


def connect_app_tokens(resolver) -> None:
    """Called from AI-Prowler's port-8000 router once its token store exists. Never raises."""
    try:
        from estimator.api import auth
        auth.set_app_token_resolver(resolver)
    except Exception as e:  # noqa: BLE001
        log.warning("Estimator: app sign-in not connected: %s", e)


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
        if not ok and "ESTIMATOR_WEB" not in why:
            log.info("Estimator web app not started: %s", why)
            return ""
        # Sign-in is set up even with ESTIMATOR_WEB=off: AI-Prowler's own port-8000 server also serves the
        # Estimator (/estimator, /estimator-api) for the Jobs app and Remote Access.
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
        if not ok:
            log.info("Estimator web app on its own port not started (%s); still served by AI-Prowler", why)
            return ""
        return server.start_with_ai_prowler()
    except Exception as e:  # noqa: BLE001 - the Estimator must never stop AI-Prowler starting
        log.warning("Estimator web app not started: %s", e)
        return ""
