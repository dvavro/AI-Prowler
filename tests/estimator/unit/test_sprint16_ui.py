"""Sprint 16: the Estimator's desktop screens - the logic behind the 🏗 Estimator tab (S16-..)."""
import sys
import types

import pytest

from estimator.ui import model


@pytest.fixture
def db_home(tmp_path, monkeypatch):
    """The tab opens estimator.db from the data folder; point that at a temp folder."""
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(tmp_path / "est"))
    yield tmp_path


@pytest.fixture
def switch(monkeypatch):
    """A stand-in for AI-Prowler's tool_config_store switch (no entry means on)."""
    store = {}
    fake = types.SimpleNamespace(feature_on=lambda n: store.get(n, True),
                                 set_feature_on=lambda n, on: store.__setitem__(n, on))
    monkeypatch.setitem(sys.modules, "tool_config_store", fake)
    return store


def test_switch_follows_ai_prowler(switch):  # S16-M01
    assert model.is_on()                                    # no entry means on, like AI-Prowler's other features
    ok, msg = model.set_on(False)
    assert ok and not model.is_on() and "kept" in msg
    ok, msg = model.set_on(True)
    assert ok and model.is_on() and "Restart" in msg


def test_overview(db_home):  # S16-M02
    ov = model.overview()
    assert len(ov["trades"]) == 15 and len(ov["services"]) == 8 and ov["tools"] >= 55
    assert ov["db_version"] >= 8 and ov["setup"]["total"] == 10 and ov["module_errors"] == {}


def test_company_basics_and_setup_light(db_home, switch):  # S16-M03
    assert model.setup_light() is None
    ok, msg = model.save_profile({"name": "Vavro Pressure Washing", "phone": "480-555-0100", "tax_pct": "8.6",
                                  "overhead_pct": "10", "profit_pct": "15%", "minimum_charge": "$150"})
    assert ok, msg
    p = model.profile()
    assert p["name"] == "Vavro Pressure Washing" and p["tax_pct"] == "8.6" and p["profit_pct"] == "15"
    assert p["minimum_charge"] == "150.00" and model.setup_light() is True
    switch["estimator"] = False
    assert model.setup_light() is None                     # off: nothing to set up


@pytest.mark.parametrize("values, words", [({"name": ""}, "name"), ({"name": "X", "tax_pct": "abc"}, "Sales tax"),
                                           ({"name": "X", "profit_pct": "150"}, "between 0 and 100")])
def test_bad_company_basics(db_home, values, words):  # S16-M04
    ok, msg = model.save_profile(values)
    assert not ok and words in msg


def test_steps_trades_agents_director(db_home):  # S16-M05
    assert model.mark_step("bid_template", "skipped")[0]
    st = {s["step"]: s["status"] for s in model.overview()["setup"]["steps"]}
    assert st["bid_template"] == "skipped"
    assert model.set_trade("roofing", False)[0]
    assert {t["module_id"]: t["enabled"] for t in model.trades()}["roofing"] is False
    ok, msg = model.save_role("reviewer", "chat_only")
    assert ok and next(r for r in model.agents()["roles"] if r["role"] == "reviewer")["provider"] == "chat_only"
    assert model.save_budget("1.50", "10")[0] and model.agents()["budget"] == {"daily_cents": 150, "monthly_cents": 1000}
    assert not model.save_budget("20", "10")[0]            # daily more than monthly
    assert not model.save_budget("lots", "10")[0]
    assert model.save_director({"follow_up_days": 7})[0] and model.director_settings()["follow_up_days"] == 7
    ok, msg = model.save_director({"follow_up_days": 0})
    assert not ok and "between" in msg


def test_backup_now(db_home):  # S16-M06
    model.overview()                                         # makes the database
    ok, msg = model.backup_now()
    assert ok and "Backed up" in msg and model.recent_backups()
