"""Calls into AI-Prowler's own tools: create_customer, create_quote, create_job, send_email.

The Estimator never writes AI-Prowler's job database directly; it calls the same
tools the AI uses, so AI-Prowler's own rules (customer-before-job, field-crew
limits, audit, backups) keep applying. The tools are found in the running
AI-Prowler server module; tests (or another host) can supply their own with
set_host().

AI-Prowler tools return text starting with "✅" or "❌", with machine-readable
lines like NEW_CUST_ID=CUST-0012.
"""
from __future__ import annotations

import re
import sys

from estimator.errors import EstimatorError

HOST_TOOLS = ("create_customer", "create_quote", "create_job", "send_email")
_HOST: dict = {}


class HostUnavailable(EstimatorError):
    code = "host_unavailable"


class HostError(EstimatorError):
    code = "host_error"


def set_host(funcs: dict | None) -> None:
    """Supply the host's tool functions (tests, or a host that isn't ai_prowler_mcp)."""
    _HOST.clear()
    if funcs:
        _HOST.update(funcs)


def _find(name: str):
    if name in _HOST:
        return _HOST[name]
    for modname in ("ai_prowler_mcp", "__main__"):
        mod = sys.modules.get(modname)
        fn = getattr(mod, name, None) if mod is not None else None
        if callable(fn) and getattr(mod, "create_quote", None) is not None:
            return fn
    return None


def available() -> dict:
    return {name: _find(name) is not None for name in HOST_TOOLS}


def call(name: str, **kwargs) -> str:
    fn = _find(name)
    if fn is None:
        raise HostUnavailable(f"AI-Prowler's {name} tool isn't available here (is the Estimator running inside AI-Prowler?)",
                              tool=name)
    result = fn(**kwargs)
    text = result if isinstance(result, str) else str(result)
    if text.lstrip().startswith("❌"):
        raise HostError(f"AI-Prowler {name} failed: {text.strip()[:500]}", tool=name)
    return text


def extract_id(text: str, prefix: str) -> str | None:
    m = re.search(rf"NEW_{prefix}_ID\s*=\s*({prefix}-\d+)", text) or re.search(rf"\b({prefix}-\d+)\b", text)
    return m.group(1) if m else None
