"""Shared helpers for tests/gui_hr_timemachine."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

USERS = {   # key -> (name, token, role, email) - throwaway, sandbox only
    "owner":    ("ZTEST Owner",    "ZTEST_HRTM_OWNER_0001",    "owner",   "owner+hrtest@example.com"),
    "manager":  ("ZTEST Manager",  "ZTEST_HRTM_MANAGER_0002",  "manager", "manager+hrtest@example.com"),
    "newhire":  ("ZTEST Newhire",  "ZTEST_HRTM_NEWHIRE_0003",  "staff",   "newhire+hrtest@example.com"),
    "coworker": ("ZTEST Coworker", "ZTEST_HRTM_COWORKER_0004", "staff",   "coworker+hrtest@example.com"),
}
HR_EMAIL = "hr+hrtest@example.com"
HIRE_DAY = dt.date(2026, 11, 2)            # Monday - the time machine starts here
START_DAY = dt.date(2026, 11, 16)          # the new hire's first day
TERM_NOTICE_DAY = dt.date(2027, 1, 4)      # HR records the resignation
TERM_DAY = dt.date(2027, 1, 15)            # last day of work


class Watch:
    def __init__(self, page, label):
        self.errors = []
        page.on("pageerror", lambda e: self.errors.append(f"{label} pageerror: {e}"))
        page.on("console", lambda m: self.errors.append(f"{label} console: {m.text}")
                if m.type == "error" and "favicon" not in m.text and "status of 4" not in m.text else None)


def new_page(browser, label):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, service_workers="block",
                              timezone_id="America/New_York")
    page = ctx.new_page()
    return ctx, page, Watch(page, label)


def sign_in_admin(page, tm, who="manager"):
    page.goto(f"{tm.base}/hr_admin/")
    page.fill("#auth-name", USERS[who][0])
    page.fill("#auth-token", USERS[who][1])
    page.click("button.auth-btn")
    page.wait_for_selector("#app", state="visible", timeout=20000)
    page.wait_for_timeout(1500)


def sign_in_portal(page, tm, who):
    """Returns '' when signed in, else the sign-in error shown."""
    page.add_init_script("try{localStorage.setItem('hr_gs_seen','1')}catch(e){}")
    page.goto(f"{tm.base}/hr_portal/")
    page.fill("#login-name", USERS[who][0])
    page.fill("#login-pass", USERS[who][1])
    page.click("#login-btn")
    for _ in range(40):
        page.wait_for_timeout(500)
        if page.evaluate("typeof authState !== 'undefined' && !!(authState && authState.session)"):
            page.wait_for_timeout(1500)
            return ""
        if page.is_visible("#login-err"):
            return page.inner_text("#login-err")
    return "timed out"


def expected_tasks(group: str, work_state: str, anchors: dict) -> dict:
    """template_id -> due date, from hr_task_templates.json and the app's own rule."""
    import sys
    sys.path.insert(0, str(ROOT))
    import ai_prowler_mcp as ap
    tmpls = json.loads((ROOT / "hr_task_templates.json").read_text(encoding="utf-8"))[group]
    out = {}
    for t in tmpls:
        if not ap._hr_template_applies(t, work_state):
            continue
        merged = {**t, **((t.get("state_overrides") or {}).get(work_state, {}))}
        anchor = anchors.get(t.get("due_anchor") or "default", anchors["default"])
        out[t["template_id"]] = (anchor + dt.timedelta(days=int(merged.get("due_offset_days", 0)))).isoformat()
    return out


def mails_for(outbox, task, kind):
    key = {"48h": "Task due in 48 hours", "today": "Task due today",
           "overdue": "Task overdue", "esc": "ESCALATION"}[kind]
    return [m for m in outbox if m.get("source") == "hr_scheduler" and key in m["subject"]
            and m["subject"].endswith(task["name"])]
