"""2026-10-11 (David): the original /hr/ app (hr/index.html) is retired; HR Admin
(hr_admin/) is the same app. Point Jamie's 6 desktop tests that read hr/ at
hr_admin/ instead. Only the file-path lines change. ASCII output."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ["test_hr_pwa_asset_paths_match_hr_route.py", "test_hr_pwa_server_mode_auth.py",
         "test_hr_pwa_update_banner.py", "test_hr_schedule_reminders.py",
         "test_hr_setup_wizard_captures_all_steps.py", "test_hr_task_status_vocabulary_and_edit_form.py"]
for name in FILES:
    f = ROOT / "tests" / "gui" / name
    s = f.read_text(encoding="utf-8")
    n = s.count('SRC_ROOT / "hr" / ')
    s = s.replace('SRC_ROOT / "hr" / ', 'SRC_ROOT / "hr_admin" / ')
    f.write_text(s, encoding="utf-8")
    print(f"{name}: {n} path(s) -> hr_admin/")
