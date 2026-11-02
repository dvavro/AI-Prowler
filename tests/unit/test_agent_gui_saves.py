"""Agent settings saves on AI-Prowler's Small Business tab never put back values saved elsewhere
(Vicki 2026-10-31: "when I select auto in some fields and save the setting it undoes the autos saved
in the other agent setting"). Each Save writes only what changed on its own form.
Run: run_tests.bat tests\\unit\\test_agent_gui_saves.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent_hr_store as hstore  # noqa: E402
import desk_agent_settings as das  # noqa: E402
import desk_agent_store as store  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import pytest  # noqa: E402

MODES = [(m, das.STAGE_MODE_LABELS[m]) for m in das.STAGE_MODES]
AUTO, SUG = das.STAGE_MODE_LABELS["auto"], das.STAGE_MODE_LABELS["suggest"]


@pytest.fixture
def dbs(tmp_path):
    store.PATH_OVERRIDE = tmp_path / "agent.db"
    hstore.PATH_OVERRIDE = tmp_path / "hr" / "agent" / "hr_agent.db"
    yield tmp_path
    store.PATH_OVERRIDE = hstore.PATH_OVERRIDE = None


def jobs_form():
    s = store.settings()
    lab = dict(MODES)
    f = {k: s[k] for k in ("agent_jb_enabled", "agent_jb_shadow", "agent_jb_can_send_invoices", "agent_jb_weather",
                           "agent_jb_invoice_max", "agent_jb_invoices_per_day", "agent_jb_quote_days",
                           "agent_jb_prep_hour", "agent_jb_route_send_hour")}
    f.update({f"agent_jb_stage_{k}": lab[s[f"agent_jb_stage_{k}"]] for k, _ in das.JB_STAGES})
    f.update({f"agent_jb_rt_stage_{k}": lab[s[f"agent_jb_rt_stage_{k}"]] for k, _ in das.RT_STAGES})
    f["agent_jb_remind_days"] = ", ".join(str(d) for d in s["agent_jb_remind_days"])
    f["agent_jb_route_scope"] = dict(das.RT_SCOPES)[s["agent_jb_route_scope"]]
    f["agent_jb_sort_weekday"] = das.WEEKDAYS[s["agent_jb_sort_weekday"]]
    return f


def test_changed_only():
    assert dga.changed_only({"a": 1, "b": 2, "c": [1, 2]}, {"a": 1, "b": 3, "c": [1, 2]}) == {"b": 2}


def test_jobs_save_keeps_newer_saves_made_elsewhere(dbs):
    loaded = jobs_form()                                      # the GUI form opens
    store.set_setting("agent_jb_stage_quotes", "auto")        # the Jobs app sets Quotes to Auto meanwhile
    form = dict(loaded, agent_jb_stage_learn=AUTO)            # here: Learn -> Auto, Quotes untouched
    ok, _ = dga.save_jobs(form, MODES, "solo", baseline=loaded)
    s = store.settings()
    assert ok and s["agent_jb_stage_learn"] == "auto" and s["agent_jb_stage_quotes"] == "auto"
    ok, msg = dga.save_jobs(form, MODES, "solo", baseline=form)
    assert ok and msg == "Nothing changed."


def test_hr_save_keeps_newer_saves_made_elsewhere(dbs):
    s = hstore.settings()
    lab = dict(MODES)
    loaded = {**{k: s[k] for k in dga.HR_BOOLS + dga.HR_INTS},
              **{f"agent_hr_stage_{k}": lab[s[f"agent_hr_stage_{k}"]] for k, _ in das.HR_STAGES},
              "agent_hr_reviewers": dict(das.HR_REVIEWERS)[s["agent_hr_reviewers"]],
              "agent_hr_incidents_access": dict(das.HR_INCIDENTS)[s["agent_hr_incidents_access"]],
              "agent_hr_quiet_hours": "8-18", "agent_hr_expiry_days": "60, 30, 7"}
    hstore.set_setting("agent_hr_stage_recruit", "auto")       # HR Admin sets Recruit to Auto meanwhile
    form = dict(loaded, agent_hr_stage_onboard=AUTO)
    ok, _ = dga.save_hr(form, MODES, "solo", baseline=loaded)
    s = hstore.settings()
    assert ok and s["agent_hr_stage_onboard"] == "auto" and s["agent_hr_stage_recruit"] == "auto"


def test_service_desk_agent_save_writes_only_what_changed(tmp_path):
    db = str(tmp_path / "tickets.db")
    desk_db.init_db(db)
    loaded = {"agent_stage_learn": "suggest", "agent_bk_stage_check": "suggest", "agent_provider": "chat_only"}
    desk_db.set_setting(db, "agent_bk_stage_check", "auto", edition="solo")   # the app, meanwhile
    form = dict(loaded, agent_stage_learn="auto")
    ok, _ = dga.save(db, dga.changed_only(form, loaded), edition="solo")
    s = desk_db.get_settings(db)
    assert ok and s["agent_stage_learn"] == "auto" and s["agent_bk_stage_check"] == "auto"
