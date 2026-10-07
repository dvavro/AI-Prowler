"""Small helpers shared by the server-mode suite's conftest and tests."""
from __future__ import annotations

import json

from api import http


def srv_login(origin: str, name: str, token: str) -> tuple[int, dict]:
    """POST /pwa-login exactly as the Jobs app does. Returns (status, reply)."""
    st, raw = http("POST", origin + "/pwa-login", {"name": name, "token": token}, timeout=30)
    try:
        return st, json.loads(raw)
    except ValueError:
        return st, {"raw": raw[:200]}
