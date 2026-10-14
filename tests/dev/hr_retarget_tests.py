"""2026-10-11 (David): the original /hr/ app is retired; HR Admin (hr_admin/)
is the same app. Point Jamie's 5 page-level HR tests at hr_admin/index.html and
hr_admin/sw.js (paths, the SW registration string, docstrings). Prints what
changed per file; refuses a file where nothing matched. ASCII output."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ["test_hr_pwa_server_mode_auth.py", "test_hr_pwa_update_banner.py",
         "test_hr_schedule_reminders.py", "test_hr_setup_wizard_captures_all_steps.py",
         "test_hr_task_status_vocabulary_and_edit_form.py"]
SUBS = [
    ('SRC_ROOT / "hr" / "index.html"', 'SRC_ROOT / "hr_admin" / "index.html"'),
    ('SRC_ROOT / "hr" / "sw.js"', 'SRC_ROOT / "hr_admin" / "sw.js"'),
    ('SRC_ROOT / "hr" / "manifest.json"', 'SRC_ROOT / "hr_admin" / "manifest.json"'),
    ("register('/hr/sw.js')", "register('/hr_admin/sw.js')"),
    ("hr/index.html", "hr_admin/index.html"),
    ("hr/sw.js", "hr_admin/sw.js"),
]
NOTE = ("# 2026-10-11 (David): the original /hr/ app is retired \u2014 HR Admin (hr_admin/) is\n"
        "# the same app, so this test now reads hr_admin/. HR is AI-Prowler server only.\n")
for name in FILES:
    f = ROOT / "tests" / "gui" / name
    s = f.read_text(encoding="utf-8")
    before = s
    for old, new in SUBS:
        s = s.replace(old, new)
    s = s.replace("hr_admin_admin", "hr_admin")          # in case a path already said hr_admin
    if s == before:
        raise SystemExit(f"{name}: nothing to change — stopping")
    if NOTE not in s:
        i = s.index('"""', s.index('"""') + 3) + 3       # after the module docstring
        s = s[:i] + "\n" + NOTE + s[i:]
    compile(s, name, "exec")
    f.write_text(s, encoding="utf-8")
    print(f"{name}: {sum(before.count(o) for o, _ in SUBS)} reference(s) moved to hr_admin/")
