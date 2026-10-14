"""2026-10-12: HF-18 (R-091 fixed) — no longer xfail; last day in the past ->
Terminated at once, offboarding tasks created, the open portal session refused."""
import re
from pathlib import Path

p = Path(__file__).resolve().parents[2] / "tests/gui_jobs_e2e_server/test_srv_hr_features.py"
s = p.read_text(encoding="utf-8")
start = s.index('@pytest.mark.xfail(strict=True, reason="R-091')
end = s.index("# ── HF-19", start)
new = '''def test_HF_18_termination_ends_portal_access_and_starts_offboarding(team):
    """R-091 (fixed 2026-10-12). Last day already passed -> Terminated at once."""
    d = team["david"]
    sess_before = team["vicki"].session
    # exactly what HR Admin's Terminations screen sends (hr_admin/index.html)
    r = _ok(d("PATCH", f"/employees/{team['emp2']}", {"status": "terminated", "termination_type": "voluntary",
                                                      "end_date": D(-1), "termination_notes": "ZTEST"}),
            "terminate")
    assert r.get("offboarding_tasks_created", 0) >= 5, r
    e = _ok(d("GET", f"/employees/{team['emp2']}"), "re-read")
    assert (e.get("employee", e))["status"] == "Terminated"
    tasks = _ok(d("GET", f"/tasks?employee_id={team['emp2']}"), "tasks")["tasks"]
    assert any((t.get("template_id") or "").startswith("TMPL-TERM") for t in tasks)
    st, _, _ = _http("GET", team["o"] + f"/hr-api/employees/{team['emp2']}",
                     headers={"X-Employee-Session": sess_before})
    assert st in (401, 403), f"the terminated employee's open portal session still works (HTTP {st})"
    hr = team["hr"]
    st, _, _ = _http("POST", team["o"] + "/hr-api/auth/aiprowler", {"name": hr["manager"].name,
                                                                      "token": hr["manager"].token})
    assert st != 200, "the terminated employee can still sign in to the HR Portal"


'''
s = s[:start] + new + s[end:]
s = re.sub(r"\(R-091, xfail until fixed\)", "(R-091, fixed 2026-10-12)", s)
compile(s, str(p), "exec")
p.write_text(s, encoding="utf-8")
print("HF-18 updated")
