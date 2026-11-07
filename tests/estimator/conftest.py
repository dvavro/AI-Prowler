"""Estimator test fixtures.

Every Estimator test runs against a throwaway data folder so a real install's
estimator.db is never touched.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def estimator_sandbox(tmp_path, monkeypatch):
    data = tmp_path / "estimator_data"
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(data))
    monkeypatch.setenv("ESTIMATOR_PDF_BROWSER", "none")   # tests don't launch a browser unless they ask to
    monkeypatch.setenv("ESTIMATOR_WATCHER", "off")        # no background thread unless a test starts one
    return data


@pytest.fixture
def db(estimator_sandbox):
    from estimator.database import open_database

    conn = open_database()
    yield conn
    conn.close()


class FakeHost:
    """Stands in for AI-Prowler's create_customer / create_quote / create_job / send_email tools."""

    def __init__(self):
        self.calls = []
        self.counters = {"CUST": 0, "QTE": 0, "JOB": 0}
        self.fail = {}

    def _make(self, name, prefix):
        def fn(**kwargs):
            self.calls.append((name, kwargs))
            if name in self.fail:
                return self.fail[name]
            if prefix is None:
                return f"✅ Email sent to {kwargs.get('to')}"
            self.counters[prefix] += 1
            new = f"{prefix}-{self.counters[prefix]:04d}"
            return f"✅ Created {new}\nNEW_{prefix}_ID={new}"
        return fn

    def funcs(self):
        return {"create_customer": self._make("create_customer", "CUST"),
                "create_quote": self._make("create_quote", "QTE"),
                "create_job": self._make("create_job", "JOB"),
                "send_email": self._make("send_email", None)}

    def named(self, name):
        return [kw for n, kw in self.calls if n == name]


@pytest.fixture
def fake_host():
    from estimator.integrations import host
    fh = FakeHost()
    host.set_host(fh.funcs())
    yield fh
    host.set_host(None)
