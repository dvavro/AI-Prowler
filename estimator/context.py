"""Who is making a request.

Every service call takes a RequestContext so the same code serves Personal mode
(one user who owns everything) and Server mode (many users with roles), and so
the audit log always records who acted, or which agent acted on whose behalf.
"""
from __future__ import annotations

from dataclasses import dataclass

PERSONAL_COMPANY_ID = "default"
PERSONAL_USER_ID = "owner"

ROLES = ("owner", "estimator", "reviewer", "office", "field")


@dataclass(frozen=True)
class RequestContext:
    company_id: str = PERSONAL_COMPANY_ID
    user_id: str = PERSONAL_USER_ID
    role: str = "owner"
    mode: str = "personal"            # "personal" | "server"
    agent: str | None = None          # e.g. "agent:quick_pricer" when an API-key agent acts

    @property
    def actor(self) -> str:
        return self.agent or self.user_id


def personal_context() -> RequestContext:
    """Context for Personal mode: one user who can do everything."""
    return RequestContext()
