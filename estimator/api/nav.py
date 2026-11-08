"""Left-menu screens, which roles see them, and the MCP tools each one mirrors.

Design spec "Navigation" and "Screens and controls". The `tools` list on each
screen is the parity contract: every web-app action has an MCP tool and the
other way round (tests/estimator/webapp checks the names exist once the tools
are built). `status` says whether the screen is built yet, so the shell can show
a "coming in Sprint N" page instead of a broken one.

Roles (spec "Multi-user behaviour"): owner (everything), estimator (estimates,
takeoffs, bids), reviewer (review and approve counts and measurements),
office (bids, follow-up, jobs; no margin editing), field (quick estimates,
photos, mobile reviews; margins hidden).
"""
from __future__ import annotations

ALL = ("owner", "estimator", "reviewer", "office", "field")

SCREENS = (
    {"id": "dashboard", "label": "Dashboard", "icon": "🏠", "roles": ALL, "status": "ready", "sprint": 1,
     "tools": ["est_project_status", "est_list_estimates", "runner_status", "est_setup_status"]},
    {"id": "projects", "label": "Projects", "icon": "📁", "roles": ALL, "status": "ready", "sprint": 1,
     "tools": ["est_create_estimate", "est_list_estimates", "est_add_trade", "est_remove_trade",
               "est_project_status"]},
    {"id": "plans", "label": "Plans", "icon": "📐", "roles": ("owner", "estimator", "reviewer", "field"),
     "status": "coming", "sprint": 5,
     "tools": ["plan_upload", "plan_process", "plan_status", "plan_get_sheets", "plan_get_viewports",
               "plan_set_scale", "plan_get_legends", "plan_get_schedules", "plan_update_schedule_row",
               "plan_compare_revisions"]},
    {"id": "takeoffs", "label": "Takeoffs", "icon": "📏", "roles": ("owner", "estimator", "reviewer"),
     "status": "coming", "sprint": 7,
     "tools": ["takeoff_propose", "takeoff_list", "takeoff_detail", "takeoff_confirm", "takeoff_edit",
               "takeoff_delete", "takeoff_manual", "takeoff_suggest_change", "plan_get_objects"]},
    {"id": "reviews", "label": "Reviews", "icon": "✅", "roles": ("owner", "estimator", "reviewer", "field"),
     "status": "coming", "sprint": 11,
     "tools": ["review_highlight", "symbol_detections_list", "symbol_detection_review", "symbol_find_similar",
               "review_start", "review_save", "review_approve", "review_history"]},
    {"id": "estimates", "label": "Estimates", "icon": "🧮", "roles": ALL, "status": "coming", "sprint": 8,
     "tools": ["est_get_estimate", "est_apply_assembly", "est_add_line_item", "est_update_line_item",
               "est_calculate", "est_validate", "est_scenarios", "est_compare_history", "est_create_revision"]},
    {"id": "bids", "label": "Bids", "icon": "📨", "roles": ("owner", "estimator", "office"), "status": "ready",
     "sprint": 4, "tools": ["bid_generate", "bid_preview", "bid_send", "bid_set_status", "bid_convert_to_job",
                            "bid_list"]},
    {"id": "price_book", "label": "Price Book", "icon": "💲", "roles": ("owner", "estimator"), "status": "ready",
     "sprint": 3, "tools": ["pricebook_get", "pricebook_update", "pricebook_import"]},
    {"id": "symbol_library", "label": "Symbol Library", "icon": "🔣", "roles": ("owner", "estimator", "reviewer"),
     "status": "coming", "sprint": 11, "tools": ["symbol_library_list", "symbol_define"]},
    {"id": "agents", "label": "Agents", "icon": "🤖", "roles": ("owner", "estimator"), "status": "coming",
     "sprint": 11, "tools": ["agent_config_get", "agent_config_update", "runner_start", "runner_status",
                             "runner_retry_task"]},
    {"id": "reports", "label": "Reports", "icon": "📊", "roles": ("owner", "estimator", "reviewer", "office"),
     "status": "coming", "sprint": 17, "tools": ["est_export", "est_compare_history"]},
    {"id": "settings", "label": "Settings", "icon": "⚙️", "roles": ("owner",), "status": "coming", "sprint": 17,
     "tools": ["est_setup_step"]},
    {"id": "help", "label": "Help", "icon": "❓", "roles": ALL, "status": "ready", "sprint": 4,
     "tools": ["how_to_estimate", "est_sample_project"]},
)

# Pages opened from a screen rather than the left menu (Sprint 2). Same parity contract as SCREENS.
PAGES = (
    {"id": "project", "label": "Project", "from": "projects", "sprint": 2,
     "tools": ["est_project_status", "est_get_estimate", "plan_upload", "plan_status"]},
    {"id": "quick", "label": "Quick estimate", "from": "dashboard", "sprint": 2,
     "tools": ["est_list_modules", "est_quick_questions", "est_quick_answer", "est_create_estimate",
               "est_director_start"]},
    # Sprint 4: the Director's Jobs board (quick lane first) and one job's next step.
    {"id": "jobs", "label": "Jobs board", "from": "dashboard", "sprint": 4, "tools": ["est_jobs_board"]},
    {"id": "job", "label": "Job", "from": "jobs", "sprint": 4,
     "tools": ["est_job_status", "est_director_start", "est_director_next"]},
    {"id": "bid", "label": "Quote", "from": "bids", "sprint": 4,
     "tools": ["bid_preview", "bid_send", "bid_set_status", "bid_convert_to_job"]},
    {"id": "guide", "label": "How-to guide", "from": "help", "sprint": 4, "tools": ["how_to_estimate"]},
)

# What each role may do, sent to the browser so it can hide buttons. The server
# never trusts this: the service layer checks the role on every call.
PERMISSIONS = {
    "owner":     {"create_estimate": True, "edit_estimate": True, "see_margins": True, "edit_margins": True,
                  "approve": True, "send_bids": True, "settings": True},
    "estimator": {"create_estimate": True, "edit_estimate": True, "see_margins": True, "edit_margins": True,
                  "approve": True, "send_bids": True, "settings": False},
    "reviewer":  {"create_estimate": False, "edit_estimate": False, "see_margins": True, "edit_margins": False,
                  "approve": True, "send_bids": False, "settings": False},
    "office":    {"create_estimate": True, "edit_estimate": False, "see_margins": True, "edit_margins": False,
                  "approve": False, "send_bids": True, "settings": False},
    "field":     {"create_estimate": True, "edit_estimate": False, "see_margins": False, "edit_margins": False,
                  "approve": False, "send_bids": False, "settings": False},
}
# Sprint 2: the same role lists the service layer enforces (store.UPLOAD_ROLES, service.QUICK_ROLES), so the
# page never shows a button the server will refuse. Tests check they stay equal.
UPLOAD_PLANS = ("owner", "estimator", "office")
QUICK_ESTIMATE = ("owner", "estimator", "office", "field")
for _role, _perms in PERMISSIONS.items():
    _perms["upload_plans"] = _role in UPLOAD_PLANS
    _perms["quick_estimate"] = _role in QUICK_ESTIMATE


def menu_for(role: str) -> list[dict]:
    return [{k: s[k] for k in ("id", "label", "icon", "status", "sprint", "tools")}
            for s in SCREENS if role in s["roles"]]


def permissions(role: str) -> dict:
    return dict(PERMISSIONS.get(role, {k: False for k in PERMISSIONS["field"]}))


def can_open(role: str, screen_id: str) -> bool:
    return any(s["id"] == screen_id and role in s["roles"] for s in SCREENS)


def all_tools() -> set[str]:
    return {t for s in SCREENS + PAGES for t in s["tools"]}
