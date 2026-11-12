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
    # Office see the plans they approve from (and already upload); scales and fixes stay store.EDIT_ROLES.
    {"id": "plans", "label": "Plans", "icon": "📐", "roles": ("owner", "estimator", "reviewer", "office", "field"),
     "status": "ready", "sprint": 5,
     "tools": ["plan_upload", "plan_process", "plan_status", "plan_get_sheets", "plan_get_viewports",
               "plan_set_scale", "plan_get_legends", "plan_get_schedules", "plan_update_schedule_row",
               "plan_compare_revisions"]},
    # Office (the Jobs app's managers and staff) approve measurements and symbols too; field crews look at symbols
    # only (David, 2026-11-09).
    {"id": "takeoffs", "label": "Takeoffs", "icon": "📏", "roles": ("owner", "estimator", "reviewer", "office"),
     "status": "ready", "sprint": 7,
     "tools": ["takeoff_propose", "takeoff_list", "takeoff_detail", "takeoff_confirm", "takeoff_edit",
               "takeoff_delete", "takeoff_manual", "takeoff_suggest_change", "plan_get_objects"]},
    {"id": "reviews", "label": "Reviews", "icon": "✅", "roles": ("owner", "estimator", "reviewer", "office", "field"),
     "status": "ready", "sprint": 11,
     "tools": ["review_highlight", "symbol_detections_list", "symbol_detection_review", "symbol_find_similar",
               "review_start", "review_save", "review_approve", "review_history"]},
    {"id": "estimates", "label": "Estimates", "icon": "🧮", "roles": ALL, "status": "ready", "sprint": 8,
     "tools": ["est_get_estimate", "est_apply_assembly", "est_add_line_item", "est_update_line_item",
               "est_calculate", "est_validate", "est_scenarios", "est_compare_history", "est_create_revision"]},
    # Field staff send quotes too (David, 2026-11-08: the same roles as bid_send, service.QUICK_ROLES); they see
    # prices, never costs or margins.
    {"id": "bids", "label": "Bids", "icon": "📨", "roles": ("owner", "estimator", "office", "field"), "status": "ready",
     "sprint": 4, "tools": ["bid_generate", "bid_preview", "bid_send", "bid_set_status", "bid_convert_to_job",
                            "bid_list"]},
    # Sprint 17: the full Price Book adds each price's history against job costs (est_compare_history).
    {"id": "price_book", "label": "Price Book", "icon": "💲", "roles": ("owner", "estimator"), "status": "ready",
     "sprint": 3, "tools": ["pricebook_get", "pricebook_update", "pricebook_import", "est_compare_history"]},
    {"id": "symbol_library", "label": "Symbol Library", "icon": "🔣", "roles": ("owner", "estimator", "reviewer"),
     "status": "ready", "sprint": 11, "tools": ["symbol_library_list", "symbol_define"]},
    {"id": "agents", "label": "Agents", "icon": "🤖", "roles": ("owner", "estimator"), "status": "ready",
     "sprint": 11, "tools": ["agent_config_get", "agent_config_update", "runner_start", "runner_status",
                             "runner_retry_task"]},
    {"id": "reports", "label": "Reports", "icon": "📊", "roles": ("owner", "estimator", "reviewer", "office"),
     "status": "ready", "sprint": 17, "tools": ["est_export", "est_compare_history", "takeoff_list",
                                                "plan_compare_revisions"]},
    {"id": "settings", "label": "Settings", "icon": "⚙️", "roles": ("owner",), "status": "ready", "sprint": 17,
     "tools": ["est_setup_step", "est_setup_status", "est_ai_privacy", "est_director_settings_get",
               "est_director_settings_update", "pricebook_update"]},
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
    # 2026-11-12: the Director's "Start a new quote or estimate" - what's the job, plans or not, who's it for.
    {"id": "start", "label": "Start a quote or estimate", "from": "dashboard", "sprint": 20,
     "tools": ["est_director_start", "est_create_estimate", "est_director_next"]},
    # Sprint 4: the Director's Jobs board (quick lane first) and one job's next step.
    {"id": "jobs", "label": "Jobs board", "from": "dashboard", "sprint": 4, "tools": ["est_jobs_board"]},
    {"id": "job", "label": "Job", "from": "jobs", "sprint": 4,
     "tools": ["est_job_status", "est_director_start", "est_director_next"]},
    {"id": "bid", "label": "Quote", "from": "bids", "sprint": 4,
     "tools": ["bid_preview", "bid_send", "bid_set_status", "bid_convert_to_job"]},
    {"id": "guide", "label": "How-to guide", "from": "help", "sprint": 4, "tools": ["how_to_estimate"]},
    # Sprint 5: a plan set's sheets (read by the plan engine) and one sheet with its viewports, scales and calibration.
    {"id": "plan_set", "label": "Plan set", "from": "plans", "sprint": 5,
     "tools": ["plan_status", "plan_get_sheets", "plan_process"]},
    {"id": "sheet", "label": "Sheet", "from": "plans", "sprint": 5,
     "tools": ["plan_get_viewports", "plan_get_sheet_image", "plan_set_scale"]},
    # Sprint 7: Blueprint Review for one project - tiled sheet viewer, overlays, tools, layers, measurement list,
    # detail panel, approve/correct.
    {"id": "takeoff", "label": "Blueprint Review", "from": "takeoffs", "sprint": 7,
     "tools": ["takeoff_list", "takeoff_detail", "takeoff_manual", "takeoff_propose", "takeoff_confirm",
               "takeoff_edit", "takeoff_delete", "takeoff_suggest_change", "plan_get_objects",
               "plan_get_sheet_image", "plan_set_scale"]},
    # Sprint 8: one estimate - trades and lines linked both ways to their measurements, options, checks, revisions.
    {"id": "estimate", "label": "Estimate", "from": "estimates", "sprint": 8,
     "tools": ["est_get_estimate", "est_add_line_item", "est_calculate", "est_validate", "est_scenarios",
               "est_choose_scenario", "est_compare_history", "est_create_revision", "est_quick_answer", "takeoff_list"]},
    # Sprint 11: one plan set's detection panel - thumbnails, filters, approve / take out / relabel, find similar.
    {"id": "symbol_review", "label": "Check symbols", "from": "reviews", "sprint": 11,
     "tools": ["symbol_detections_list", "symbol_detection_review", "symbol_find_similar", "plan_status"]},
    # Sprint 12: one project's plan quantities - the shared wall-and-room model and each trade's answers from it.
    {"id": "quantities", "label": "Plan quantities", "from": "takeoffs", "sprint": 12,
     "tools": ["plan_get_rooms_walls", "plan_trade_answers"]},
    # Sprint 13: reviews on a phone or tablet (the Jobs app's Estimates tab) - symbols and measurements by touch.
    {"id": "mobile_reviews", "label": "Reviews (phone)", "from": "reviews", "sprint": 13,
     "tools": ["symbol_detections_list", "symbol_detection_review", "takeoff_list", "takeoff_confirm", "takeoff_delete",
               "review_highlight"]},
    # Sprint 17: one plan revision report drawn over the sheets (red removed, green added, orange changed or moved).
    {"id": "revision", "label": "Plan revision", "from": "reports", "sprint": 17,
     "tools": ["plan_compare_revisions", "plan_get_sheet_image", "takeoff_detail"]},
    # The AI Log: every LLM call, what was sent and what came back - opened from the Agents screen.
    # No MCP tool yet: the log is web-only for now, so the tools list stays empty (the parity tests
    # check listed tools exist; an empty list lists nothing).
    {"id": "ai_log", "label": "AI Log", "from": "agents", "sprint": 19, "tools": []},
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
                  "approve": False, "send_bids": True, "settings": False},
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
