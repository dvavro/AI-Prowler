"""
tests/unit/test_builtin_analysis_settings.py
==============================================
Tests for custom_tasks_manager's builtin-analysis settings storage — v8.1.6.
Backs the persistent Queue/NOW/Edit settings for the 5 fixed Common
Business AI Analysis buttons (analyze_business, weekly_advisor,
find_problems, growth_opportunities), mirroring how custom tasks already
persist their own settings, so Queue/NOW no longer require reopening a
popup every time.
"""

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def ctm(tmp_path, monkeypatch):
    import custom_tasks_manager as _ctm
    monkeypatch.setattr(_ctm, "BUILTIN_ANALYSIS_CONFIG_PATH",
                         tmp_path / "builtin_analysis_config.json")
    return _ctm


class TestDefaults:

    def test_unconfigured_type_returns_sane_defaults(self, ctm):
        settings = ctm.get_builtin_analysis_settings("analyze_business")
        assert settings["scope_dirs"] == []
        assert settings["output_learnings"] is True
        assert settings["output_report"] is False
        assert settings["report_folder"] == ctm.DEFAULT_REPORT_FOLDER
        assert settings["schedule"] == "none"
        assert settings["first_due"] is None

    def test_load_config_returns_empty_dict_when_file_absent(self, ctm):
        assert ctm.load_builtin_analysis_config() == {}


class TestSaveAndLoad:

    def test_save_then_get_roundtrips(self, ctm):
        ctm.save_builtin_analysis_settings("find_problems", {
            "scope_dirs": ["C:\\Jobs"],
            "output_learnings": False,
            "output_report": True,
            "report_folder": "C:\\Reports",
            "schedule": "weekly",
            "first_due": "2026-08-01",
        })
        settings = ctm.get_builtin_analysis_settings("find_problems")
        assert settings["scope_dirs"] == ["C:\\Jobs"]
        assert settings["output_learnings"] is False
        assert settings["output_report"] is True
        assert settings["report_folder"] == "C:\\Reports"
        assert settings["schedule"] == "weekly"
        assert settings["first_due"] == "2026-08-01"

    def test_saving_one_type_does_not_affect_another(self, ctm):
        ctm.save_builtin_analysis_settings("analyze_business",
                                            {"output_report": True})
        untouched = ctm.get_builtin_analysis_settings("weekly_advisor")
        assert untouched["output_report"] is False  # still default

    def test_save_returns_true_on_success(self, ctm):
        assert ctm.save_builtin_analysis_settings("growth_opportunities", {}) is True

    def test_corrupt_file_falls_back_to_defaults_not_crash(self, ctm):
        ctm.BUILTIN_ANALYSIS_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ctm.BUILTIN_ANALYSIS_CONFIG_PATH.write_text("{not valid json", encoding="utf-8")
        settings = ctm.get_builtin_analysis_settings("analyze_business")
        assert settings["output_learnings"] is True  # default, didn't crash

    def test_non_dict_file_content_falls_back_to_empty(self, ctm):
        ctm.BUILTIN_ANALYSIS_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ctm.BUILTIN_ANALYSIS_CONFIG_PATH.write_text("[1, 2, 3]", encoding="utf-8")
        assert ctm.load_builtin_analysis_config() == {}


class TestMissingFieldsUseDefaults:

    def test_partial_saved_settings_fills_in_missing_keys(self, ctm):
        # Simulates an older/partial save (e.g. from a future settings
        # field this version doesn't know about, or a hand-edited file).
        ctm.save_builtin_analysis_config({
            "analyze_business": {"output_report": True}
        })
        settings = ctm.get_builtin_analysis_settings("analyze_business")
        assert settings["output_report"] is True
        assert settings["output_learnings"] is True   # filled from default
        assert settings["scope_dirs"] == []            # filled from default
        assert settings["report_folder"] == ctm.DEFAULT_REPORT_FOLDER
