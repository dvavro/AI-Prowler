"""Dev helper (2026-10-11): do the features the 5 /hr/-app tests check also exist
in hr_admin/index.html (so the tests can move there when /hr/ is retired)?
For each test: the markers it looks for, and whether each is found in hr/ and
hr_admin/. Also: how similar the two apps are. ASCII output."""
import difflib
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
hr = (REPO / "hr" / "index.html").read_text(encoding="utf-8", errors="replace")
adm = (REPO / "hr_admin" / "index.html").read_text(encoding="utf-8", errors="replace")
hr_sw = (REPO / "hr" / "sw.js").read_text(encoding="utf-8", errors="replace")
adm_sw = (REPO / "hr_admin" / "sw.js").read_text(encoding="utf-8", errors="replace")


def p(s=""):
    print(str(s).encode("ascii", "backslashreplace").decode("ascii"))


MARKERS = {
    "test_hr_setup_wizard_captures_all_steps": ["WIZARD_STEPS", "function wizardNext", "wizardData"],
    "test_hr_schedule_reminders": ["reminder", "/hr-api/reminders", "/calendar/reminders"],
    "test_hr_task_status_vocabulary_and_edit_form": ["Not Started", "In Progress", "Waived", "Blocked", "Overdue"],
    "test_hr_pwa_update_banner": ["SKIP_WAITING", "update-banner", "applyUpdate"],
    "test_hr_pwa_server_mode_auth": ["auth-token", "loginAdmin", "showAuthScreen", "X-Employee-Session"],
}
for test, marks in MARKERS.items():
    p(f"\n{test}:")
    for m in marks:
        p(f"   {m:24} hr/={'yes' if m in hr else 'NO ':3}  hr_admin/={'yes' if m in adm else 'NO'}")
p(f"\nsizes: hr/index.html {len(hr):,} B, hr_admin/index.html {len(adm):,} B")
r = difflib.SequenceMatcher(None, hr.splitlines()[:4000], adm.splitlines()[:4000], autojunk=False).quick_ratio()
p(f"line similarity (first 4000 lines, quick ratio): {r:.2f}")
p(f"sw.js identical: {hr_sw == adm_sw}")
p("hr_admin registers sw: " + str(re.findall(r"serviceWorker\.register\('([^']+)'", adm)))
p("hr registers sw:       " + str(re.findall(r"serviceWorker\.register\('([^']+)'", hr)))
man = (REPO / "hr_admin" / "manifest.json").read_text(encoding="utf-8")
p("hr_admin manifest start_url/scope: " + str(re.findall(r'"(start_url|scope)":\s*"([^"]+)"', man)))
p("hr_admin sw.js /hr/ refs: " + str(re.findall(r"'/hr/[^']*'", adm_sw)))
