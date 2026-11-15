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


CUSTOMER_COLUMNS = ("customer_id", "customer_type", "company_name", "first_name", "last_name", "phone", "email",
                    "street_address", "city", "state", "zip", "status")


def _job_db_path() -> str | None:
    for modname in ("ai_prowler_mcp", "__main__"):
        mod = sys.modules.get(modname)
        fn = getattr(mod, "_resolve_job_db_path", None) if mod is not None else None
        if callable(fn):
            return fn(None)
    return None


def find_customers(query: str = "", limit: int = 25, customer_id: str | None = None) -> list[dict]:
    """AI-Prowler's customers matching a search (name, company, phone, email, address, ID), newest first.
    Read only - creating customers still goes through create_customer (2026-11-14: pick an existing customer
    when a quote becomes a job, instead of always making a new one)."""
    if "find_customers" in _HOST:
        return _HOST["find_customers"](query=query, limit=limit, customer_id=customer_id)
    if _HOST:
        # A supplied host (tests, another host) without a customer list: never fall back to the real database.
        raise HostUnavailable("this host has no customer list", tool="customers")
    import sqlite3
    path = _job_db_path()
    if not path:
        raise HostUnavailable("AI-Prowler's customer list isn't available here (is the Estimator running inside AI-Prowler?)",
                              tool="customers")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(customers)")}
        cols = [c for c in CUSTOMER_COLUMNS if c in have]
        sql = f"SELECT {', '.join(cols)} FROM customers"
        args: list = []
        if customer_id:
            sql += " WHERE customer_id = ?"
            args.append(customer_id)
        else:
            words = [w for w in (query or "").lower().split() if w][:5]
            text = ("lower(coalesce(customer_id,'') || ' ' || coalesce(company_name,'') || ' ' || coalesce(first_name,'')"
                    " || ' ' || coalesce(last_name,'') || ' ' || coalesce(phone,'') || ' ' || coalesce(email,'') || ' ' ||"
                    " coalesce(street_address,'') || ' ' || coalesce(city,''))")
            if words:
                sql += " WHERE " + " AND ".join(f"{text} LIKE ?" for _ in words)
                args += [f"%{w}%" for w in words]
        order = "last_edited_at DESC, " if "last_edited_at" in have else ""
        sql += f" ORDER BY {order}rowid DESC LIMIT ?"
        args.append(max(1, min(int(limit or 25), 100)))
        return [{k: (r[k] or "") for k in cols} for r in conn.execute(sql, args)]
    finally:
        conn.close()


def extract_id(text: str, prefix: str) -> str | None:
    # The whole ID, e.g. CUST-2026-616 (2026-11-14): "-\d+" alone stopped at CUST-2026, a customer that doesn't
    # exist, so the quote that followed failed with "FOREIGN KEY constraint failed".
    one = rf"{prefix}-\d+(?:-\d+)*"
    m = re.search(rf"NEW_{prefix}_ID\s*=\s*({one})", text) or re.search(rf"\b({one})\b", text)
    return m.group(1) if m else None
