"""Sprint 28: the setup wizard's Team and approvals step, and the Estimator tab's CAD and tools
section + refreshed Phone and web app content (S28-W.., S28-T..)."""
import pytest

from pathlib import Path

from estimator.context import personal_context
from estimator.director import settings as director_settings
from estimator.errors import InvalidInput
from estimator.estimating import setup
from estimator.ui import model

CTX = personal_context()


def test_step_is_listed(db):  # S28-W01
    s = setup.setup_status(db, CTX)
    assert s["total"] == 10
    row = next(x for x in s["steps"] if x["step"] == "team_approvals")
    assert "Team and approvals" in row["label"] and row["status"] == "not_started"


def test_review_threshold_is_applied(db):  # S28-W02
    s = setup.setup_step(db, CTX, "team_approvals", {"review_required_over": "750"})
    assert s["applied"]["director_settings"]["review_required_over_cents"] == 75000
    assert director_settings.get_settings(db, CTX.company_id)["review_required_over_cents"] == 75000
    row = next(x for x in s["steps"] if x["step"] == "team_approvals")
    assert row["status"] == "done"


def test_record_only_and_validation(db):  # S28-W03
    s = setup.setup_step(db, CTX, "team_approvals", {})
    assert s["applied"]["director_settings"] == {}
    assert director_settings.get_settings(db, CTX.company_id)["review_required_over_cents"] == 50000
    with pytest.raises(InvalidInput):
        setup.setup_step(db, CTX, "team_approvals", {"launch_codes": "1"})
    with pytest.raises(InvalidInput):
        setup.setup_step(db, CTX, "team_approvals", {"review_required_over": "lots"})


def test_tools_all_present():  # S28-T01
    tools = model.tool_status(which=lambda name: "C:\\tools\\" + name + ".exe",
                              find_spec=lambda name: object())
    assert [t["tool"] for t in tools] == ["DXF drawings", "DWG converter (ODA File Converter)",
                                          "Tesseract OCR (reads scanned plans)"]
    assert all(t["ok"] for t in tools)


def test_tools_missing_gives_guidance():  # S28-T02
    tools = model.tool_status(which=lambda name: None, find_spec=lambda name: None)
    assert not any(t["ok"] for t in tools)
    dwg = next(t for t in tools if "DWG" in t["tool"])
    assert "ODA" in dwg["detail"] and "free" in dwg["detail"].lower()


def test_dwg_missing_gives_install_steps():  # S28-T04
    tools = model.tool_status(which=lambda name: None, find_spec=lambda name: None)
    dwg = next(t for t in tools if "DWG" in t["tool"])
    assert not dwg["ok"]
    assert "opendesign.com/guestfiles/oda_file_converter" in dwg["detail"]
    assert "Download the Windows version" in dwg["detail"]
    assert "Restart AI-Prowler" in dwg["detail"]


def test_web_app_access(monkeypatch):  # S28-T03
    monkeypatch.delenv("ESTIMATOR_WEB_PORT", raising=False)
    a = model.web_app_access()
    assert a["url"] == "http://localhost:8770/estimator/"
    text = " ".join(a["lines"])
    assert "Estimating scope" in text and "field crew" in text
    monkeypatch.setenv("ESTIMATOR_WEB_PORT", "9999")
    assert model.web_app_access()["url"] == "http://localhost:9999/estimator/"


def test_phone_section_has_open_estimator_button():  # S28-T05
    src = (Path(__file__).resolve().parents[3] / "estimator" / "ui" / "gui_tab.py").read_text(encoding="utf-8")
    phone = src.split("def _phone_section")[1].split("def _cad_section")[0]
    assert "Open Estimator in browser" in phone
    assert '_open_folder(model.web_app_access()["url"])' in phone
