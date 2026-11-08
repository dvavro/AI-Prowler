"""Errors the Estimator returns to the web app, MCP tools and agents.

Every error has a short machine code plus a plain-English message, so the AI
and the web app can both explain what went wrong.
"""
from __future__ import annotations


class EstimatorError(Exception):
    code = "error"

    def __init__(self, message: str, **details):
        super().__init__(message)
        self.message = message
        self.details = details

    def as_dict(self) -> dict:
        return {"ok": False, "error": self.code, "message": self.message, **self.details}


class NotFound(EstimatorError):
    code = "not_found"


class InvalidInput(EstimatorError):
    code = "invalid_input"


class StaleRevision(EstimatorError):
    """The estimate changed since the caller last read it (another user, chat or agent)."""
    code = "stale_revision"


class NotEditable(EstimatorError):
    """The estimate is finalized (approved/sent/won/lost); changes need a new revision."""
    code = "not_editable"


class PermissionDenied(EstimatorError):
    code = "permission_denied"


class ConfirmationRequired(EstimatorError):
    """The action reaches a customer, changes money or creates records: ask the user, then call again with confirm."""
    code = "needs_confirmation"


class NotAvailable(EstimatorError):
    """A part of the Estimator that isn't installed yet (for example the plan engine) was asked to do something."""
    code = "not_available"
