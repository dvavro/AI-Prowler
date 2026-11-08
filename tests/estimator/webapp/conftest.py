"""Fixtures for the Estimator Web App tests (Coder 2 track).

The parent conftest already gives every test a throwaway data folder. Here:
- sign-in state is reset before and after each test (sessions live in memory),
- `call` sends one request through router.route() the way the HTTP host does,
- `ctx_for` makes a RequestContext for any role/company (Server-mode users).
"""
import json

import pytest


@pytest.fixture(autouse=True)
def fresh_auth(monkeypatch, tmp_path):
    from estimator.api import auth
    auth.reset()
    monkeypatch.delenv("ESTIMATOR_MODE", raising=False)
    monkeypatch.delenv("ESTIMATOR_OWNER_PASSWORD", raising=False)
    # Never read this PC's real AI-Prowler config for the owner password.
    fake_cfg = tmp_path / "ai_prowler_config.json"
    monkeypatch.setattr(auth, "_config_files", lambda: [fake_cfg])
    yield
    auth.reset()


SAME_PC = {"Host": "localhost:8770"}
WRITE = {"X-Estimator-Request": "1"}


class Caller:
    def __init__(self):
        from estimator.api import router
        self.router = router

    def __call__(self, method, path, body=None, *, headers=None, ip="127.0.0.1", write_header=True, raw=None):
        h = dict(SAME_PC)
        if method.upper() != "GET" and write_header:
            h.update(WRITE)
        h.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        return self.router.route(self.router.Request(method, path, h, data, ip))


@pytest.fixture
def call():
    return Caller()


@pytest.fixture
def ctx_for():
    from estimator.context import RequestContext

    def make(role="owner", user="owner", company="default", mode="server"):
        return RequestContext(company_id=company, user_id=user, role=role, mode=mode)
    return make


@pytest.fixture
def session_for(ctx_for):
    """Bearer headers for a signed-in user with the given role (skips the password step)."""
    from estimator.api import auth

    def make(role="owner", user=None, company="default"):
        tok = auth.create_session(ctx_for(role, user or role, company), (user or role).title())
        return {"Authorization": f"Bearer {tok}"}
    return make
