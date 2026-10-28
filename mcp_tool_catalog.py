"""
mcp_tool_catalog.py
====================
Single source of truth for every @mcp.tool() registered in
ai_prowler_mcp.py: which category it belongs to (for the Settings tab's
tool-configuration panel), a short label/description (shown in that panel's
info popups), which mode(s) it can ever be registered in, whether it is
locked (cannot be disabled by the user under any configuration), and
whether disabling it would break a live GUI or PWA feature
(pwa_dependency) rather than just silently narrowing what Claude, Muse, or Grok can do.

Imported by BOTH:
  - ai_prowler_mcp.py   (registration-time filtering via _counting_mcp_tool)
  - rag_gui.py          (Settings tab tool-configuration panel)

REVISED 2026-09-24 per a GUI-simplification pass: most categories are now
LOCKED (always-on) by deliberate product decision — Core Knowledge Base &
Search, Self-Learning, Email, Agentic Analysis Task Queue, and File & Code
Tools (which absorbed Remote File Transfer) are all things a typical
AI-Prowler owner would not want to accidentally disable and confuse
themselves with. Route & Schedule Advisor, AI Routing, and Data
Portability were folded into a single combined "job_tracker" category
alongside the original Job Tracker Core tools. The only two genuinely
optional (toggleable) categories left are "job_tracker" (the whole
small-business/service-job feature) and "sms_whatsapp" (messaging) —
matching the idea that most owners either run their whole business through
AI-Prowler's job tracker or don't, and either use SMS/WhatsApp or don't,
while the rest (search, self-learning, email, the analysis queue, and dev
tools) are treated as baseline infrastructure nobody should be able to
switch off by accident.

Deliberately has NO import of ai_prowler_mcp (avoids a circular import —
ai_prowler_mcp.py imports this, never the reverse). Pure data + lookup
helpers only.

Drift prevention: tools/generate_tool_catalog_report.py (see spec) AST-scans
ai_prowler_mcp.py for every @mcp.tool() name and diffs it against
TOOL_CATALOG.keys() — any mismatch fails the release gate. This module is
the thing that check verifies against, so keep it in sync by hand until
that script exists, and treat any new @mcp.tool() as incomplete work until
it has a row here.
"""

from dataclasses import dataclass
from typing import FrozenSet, Optional, List, Dict


@dataclass(frozen=True)
class ToolMeta:
    category: str
    label: str
    description: str
    modes: FrozenSet[str]
    locked: bool = False
    locked_reason: Optional[str] = None
    pwa_dependency: bool = False
    pwa_dependency_note: Optional[str] = None


@dataclass(frozen=True)
class CategoryMeta:
    key: str
    label: str
    description: str
    locked: bool = False


PERSONAL: FrozenSet[str] = frozenset({"personal"})
SERVER: FrozenSet[str] = frozenset({"server"})
BOTH: FrozenSet[str] = frozenset({"personal", "server"})


CATEGORY_ORDER: List[CategoryMeta] = [
    CategoryMeta(
        "status_system", "Status & System",
        "Always-on health checks and Claude/Muse/Grok's own usage guide — not a real "
        "choice, shown for transparency only.",
        locked=True,
    ),
    CategoryMeta(
        "core_kb", "Core Knowledge Base & Search",
        "Document search, indexing, and reindexing — the core Agentic RAG "
        "feature. Always on.",
        locked=True,
    ),
    CategoryMeta(
        "self_learning", "Self-Learning System",
        "Recording and searching business lessons, fact corrections, and "
        "client preferences in the Learnings tab. Always on.",
        locked=True,
    ),
    CategoryMeta(
        "job_tracker", "Job Tracker & Routing",
        "Customers, jobs, quotes, invoices, billing, reminders, mileage, AR "
        "aging, route building and scheduling, AI Routing, and data "
        "export/backup — the whole small-business / service-job feature "
        "set, combined into one optional bundle.",
    ),
    CategoryMeta(
        "sms_whatsapp", "SMS & WhatsApp",
        "Two-way SMS and WhatsApp messaging with customers and crew.",
    ),
    CategoryMeta(
        "email", "Email",
        "Sending email, configuring SMTP, and multi-account Outlook "
        "support. Always on.",
        locked=True,
    ),
    CategoryMeta(
        "agentic_analysis", "Agentic Analysis Task Queue",
        "The Quick Links tab's Common Business AI Analysis and My Custom "
        "AI Analyses scheduling system (Personal installs only). Always on.",
        locked=True,
    ),
    CategoryMeta(
        "file_code_tools", "File & Code Tools",
        "Letting Claude, Muse, or Grok create/edit files, run scripts, check code, and "
        "use the Remote Control PWA's file transfer bridge (Personal "
        "installs only, where applicable). Always on.",
        locked=True,
    ),
    # 2026-10-11 (David): the HR apps are AI-Prowler SERVER only and optional —
    # this group's tick box in Settings → MCP Tool Configuration (server mode)
    # is the one switch for BOTH HR Admin and HR Portal and all hr_* tools.
    # Off until the owner turns it on (tool_config_store.hr_apps_enabled()).
    CategoryMeta(
        "hr", "HR apps (HR Admin + HR Portal)",
        "Employee records, onboarding tasks, documents, time off, time clock "
        "and HR compliance — the HR Admin app (owners and managers) and the "
        "HR Portal app (employees), plus Claude/Muse/Grok's hr_* tools. AI-Prowler "
        "server only. Off until you turn it on; one switch covers both apps.",
    ),
    # 2026-10-27 (David): AI-Prowler Service Desk — tickets for customer
    # requests, internal tickets and subcontractor tickets. Both modes
    # (personal = Solo edition, server = Business edition). Starts off on a new
    # install like Job Tracker; tool_config_store.DEFAULT_OFF_GROUPS.
    CategoryMeta(
        "service_desk", "Service Desk (tickets)",
        "Customers file requests that are tracked from Open to Closed, plus "
        "internal and subcontractor tickets, photos and documents on every "
        "ticket — the Service Desk app and Claude/Muse/Grok's ticket tools. "
        "Personal installs get the Solo edition (every ticket goes to the "
        "owner); servers get the team edition.",
    ),
]


# -----------------------------------------------------------------------
# _RAW: (name, category, label, description, modes,
#        locked, locked_reason, pwa_dependency, pwa_dependency_note)
# -----------------------------------------------------------------------
_RAW = [
    ('how_to_use_ai_prowler', 'status_system', 'Agentic RAG workflow guide',
     "Claude/Muse/Grok's own bootstrap guide for how to use AI-Prowler.", BOTH,
     True, 'Required for Claude, Muse, or Grok to use AI-Prowler at all.', False, None),
    ('check_ai_prowler_status', 'status_system', 'RAG health check',
     'ChromaDB connectivity, embedding model status, chunk count.', BOTH,
     True, 'The only way to explain why nothing else is working.', True, "Used by the Remote Control PWA's status screen."),
    ('check_tools_status', 'status_system', 'Action tools health check',
     'Reports which action tools are configured and ready to use.', BOTH,
     True, 'Needed to explain why a disabled/misconfigured tool is unavailable.', False, None),
    ('get_knowledge_base_overview', 'core_kb', 'Knowledge base overview',
     'Document count, file types, chunk count, tracked directories.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('search_documents', 'core_kb', 'Search documents',
     'Primary semantic search over indexed documents.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", True, 'Used by the Remote Control PWA.'),
    ('multi_query_search', 'core_kb', 'Multi-query search',
     'Runs several search queries in parallel, deduplicated results.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('search_within_directory', 'core_kb', 'Search within a directory',
     'Semantic search restricted to one folder/case/project tree.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('expand_search_result', 'core_kb', 'Expand search result',
     'Fetches chunks before/after a result cut off at a boundary.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('read_document', 'core_kb', 'Read full document',
     'Reads an entire indexed document in sequential chunk order.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('list_indexed_documents', 'core_kb', 'List indexed documents',
     'Browses all indexed documents grouped by file type.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", True, 'Used by the Remote Control PWA.'),
    ('list_indexed_directories', 'core_kb', 'List indexed directories',
     'Directory tree of indexed content with per-folder counts.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", True, 'Used by the Remote Control PWA.'),
    ('index_path', 'core_kb', 'Index a folder or file',
     'Adds a folder/file to the knowledge base and tracking list.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('update_tracked_directories', 'core_kb', 'Update tracked directories',
     'Re-scans tracked paths, re-indexing only new/changed files.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('list_tracked_directories', 'core_kb', 'List tracked directories',
     'Lists every path currently registered for auto-update tracking.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", True, 'Used by the Remote Control PWA.'),
    ('untrack_directory', 'core_kb', 'Untrack a directory',
     'Removes a path from tracking and deletes its indexed chunks.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('get_database_stats', 'core_kb', 'Knowledge base statistics',
     'Chunk count, unique document count, file-type breakdown.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", True, 'Used by the Remote Control PWA.'),
    ('reindex_file', 'core_kb', 'Reindex one file',
     'Purges and rebuilds the index for a single file.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('reindex_directory', 'core_kb', 'Reindex a directory',
     'Fully purges and rebuilds the index for one tracked directory.', BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('reindex_all', 'core_kb', 'Reindex everything',
     "Wipes and rebuilds the entire knowledge base index from scratch. NOTE: not role-gated by design (indexing isn't a confidentiality boundary) — see the spec's grounding notes.", BOTH,
     True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
      ('cancel_indexing', 'core_kb', 'Stop indexing',
       'Requests a running index/reindex to stop after the current file finishes.', BOTH,
       True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
      ('indexing_status', 'core_kb', 'Indexing status',
       'Shows whether an index/reindex is running and its current progress.', BOTH,
       True, "Part of AI-Prowler's core Agentic RAG search/indexing feature — always available.", False, None),
    ('record_learning', 'self_learning', 'Record a learning',
     'Saves a new business lesson, fact correction, or client preference.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", True, 'Used by the Remote Control PWA.'),
    ('search_learnings', 'self_learning', 'Search learnings',
     'Semantic search of the learnings store.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", True, 'Used by the Remote Control PWA.'),
    ('list_learnings', 'self_learning', 'List learnings',
     'Browses learnings with exact-match filters on category/status/tag.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", True, 'Used by the Remote Control PWA.'),
    ('get_learning', 'self_learning', 'Get one learning',
     'Returns one learning\u2019s full record (every editable field) as JSON \u2014 read-only.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", True, 'Used by the Remote Control PWA.'),
    ('update_learning', 'self_learning', 'Edit a learning',
     'Edits fields of an existing learning.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", True, 'Used by the Remote Control PWA.'),
    ('delete_learning', 'self_learning', 'Delete a learning',
     'Permanently removes a learning.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", True, 'Used by the Remote Control PWA.'),
    ('get_learning_stats', 'self_learning', 'Learning statistics',
     'Totals by category, source, outcome, and status.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", True, 'Used by the Remote Control PWA.'),
    ('get_learnings_report', 'self_learning', 'Learnings report (in-chat)',
     'Returns learnings as formatted text in the conversation.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", False, None),
    ('send_learnings_report', 'self_learning', 'Email learnings report',
     'Emails a formatted HTML learnings report.', BOTH,
     True, "Part of AI-Prowler's always-on Self-Learning system.", False, None),
    ('export_learnings_file', 'self_learning', 'Export learnings to file',
     'Exports learnings to a JSON pack or spreadsheet.', PERSONAL,
     True, "Part of AI-Prowler's always-on Self-Learning system.", False, None),
    ('rebuild_learnings_index', 'self_learning', 'Rebuild learnings index',
     'Rebuilds the ChromaDB learnings index from the JSON data file.', PERSONAL,
     True, "Part of AI-Prowler's always-on Self-Learning system.", False, None),
    ('get_weather', 'job_tracker', 'Weather forecast',
     'Current conditions and multi-day forecast for field scheduling.', BOTH,
     False, None, False, None),
    ('geocode_address', 'job_tracker', 'Geocode an address',
     'Converts a street address to GPS coordinates.', BOTH,
     False, None, False, None),
    ('get_home_address', 'job_tracker', 'Get home/business address',
     "Returns the owner's configured home/business address.", PERSONAL,
     False, None, False, None),
    ('optimize_route', 'job_tracker', 'Optimize a route',
     'Solves the best visit order for a list of job stops.', BOTH,
     False, None, False, None),
    ('build_maps_url', 'job_tracker', 'Build maps link',
     'Generates a tap-to-navigate Google/Apple Maps URL.', BOTH,
     False, None, False, None),
    ('read_job_spreadsheet', 'job_tracker', 'Read job tracker data',
     'Reads customers, jobs, invoices, quotes from the job tracker.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Board/Jobs/Database tabs."),
    ('update_job_spreadsheet', 'job_tracker', 'Update a job tracker row',
     'Edits an existing row after a job is completed or changed.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Database tab and edit forms."),
    ('get_sheet_columns', 'job_tracker', 'Get sheet columns',
     "Lists a table's exact column headers for building edit forms.", BOTH,
     False, None, True, "Used by the Jobs PWA's row-edit form."),
    ('get_board_updates', 'job_tracker', 'Job Board live updates',
     "Polling query behind the admin Job Board's ~60-second refresh.", BOTH,
     False, None, True, "Powers the Job Board's live refresh — disabling this means the board only updates on manual reload."),
    ('create_job', 'job_tracker', 'Create a job',
     'Appends a new job to the schedule for an existing customer.', BOTH,
     False, None, False, None),
    ('create_customer', 'job_tracker', 'Create a customer',
     'Appends a new customer to the customer list.', BOTH,
     False, None, False, None),
    ('create_quote', 'job_tracker', 'Create a quote',
     'Appends a new quote/estimate.', BOTH,
     False, None, False, None),
    ('create_invoice', 'job_tracker', 'Create an invoice',
     'Generates an invoice from a job and links them together.', BOTH,
     False, None, True, "Used by the Jobs PWA's invoicing screen."),
    ('create_setting', 'job_tracker', 'Create a setting',
     'Appends a new business-configuration key/value.', BOTH,
     False, None, False, None),
    ('create_service_pricing', 'job_tracker', 'Create a priced service',
     'Appends a new service-catalog entry with pricing.', BOTH,
     False, None, False, None),
    ('delete_customer', 'job_tracker', 'Delete a customer',
     'Permanently deletes an inactive customer and all linked records.', BOTH,
     False, None, False, None),
    ('delete_job', 'job_tracker', 'Delete a job',
     'Permanently deletes a cancelled job.', BOTH,
     False, None, False, None),
    ('delete_quote', 'job_tracker', 'Delete a quote',
     'Permanently deletes a quote.', BOTH,
     False, None, False, None),
    ('delete_service_pricing', 'job_tracker', 'Delete a priced service',
     'Permanently deletes a service-catalog entry.', BOTH,
     False, None, False, None),
    # rename_customer (2026-10-08) -- registered @mcp.tool() 2026-10-04 with
    # no catalog row; the Jobs PWA calls it via pwa-api (jobs/index.html:8418).
    ('rename_customer', 'job_tracker', 'Rename a customer number',
     "Changes a customer ID's trailing number; repoints all referencing rows.", BOTH,
     False, None, False, None),
    ('email_invoice', 'job_tracker', 'Email an invoice',
     'Emails a branded HTML invoice to the customer.', BOTH,
     False, None, True, "Used by the Jobs PWA's Invoices screen."),
    ('text_invoice', 'job_tracker', 'Text an invoice',
     'Sends an SMS invoice notification (amount due + payment link).', BOTH,
     False, None, False, None),
    ('email_receipt', 'job_tracker', 'Email a payment receipt',
     'Emails a thank-you/proof-of-payment receipt.', BOTH,
     False, None, False, None),
    ('text_receipt', 'job_tracker', 'Text a payment receipt',
     'Texts a thank-you/proof-of-payment receipt.', BOTH,
     False, None, False, None),
    ('save_contact', 'job_tracker', 'Save a personal contact',
     'Saves a phone/email so future send_sms/send_email resolve by name.', BOTH,
     False, None, False, None),
    ('schedule_next_recurring_job', 'job_tracker', 'Schedule next recurring job',
     'Auto-creates the next occurrence of a recurring job.', BOTH,
     False, None, False, None),
    ('find_stale_customers', 'job_tracker', 'Find stale customers',
     'Lists active customers overdue for service.', BOTH,
     False, None, False, None),
    ('send_customer_reminders', 'job_tracker', 'Send customer reminders',
     'Sends a check-in reminder to specific overdue customers.', BOTH,
     False, None, False, None),
    ('log_time_entry', 'job_tracker', 'Clock in / out',
     'Clocks in or out for a job and computes elapsed time.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Clock screen."),
    ('get_daily_mileage', 'job_tracker', 'Daily mileage estimate',
     'Estimates miles driven from clock-in/clock-out GPS points.', BOTH,
     False, None, False, None),
    # Mileage tracker (2026-10-24) — IRS-ready mileage log; the Jobs app's
    # Mileage tab calls these through /pwa-api.
    ('get_mileage_log', 'job_tracker', 'Mileage log',
     'Trips, gaps to fix, vehicles, rates, and totals for a date range (JSON).', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('build_mileage_log', 'job_tracker', 'Build / backfill mileage',
     'Builds trips from clock-ins and home/company legs; backfills past dates with a preview.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('add_mileage_trip', 'job_tracker', 'Add a business trip',
     'Logs a non-job business trip by form, Start/End buttons, text, or voice.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('update_mileage_trip', 'job_tracker', 'Edit / remove / split a trip',
     'Audited edits to a mileage trip; void with reason; insert a stop.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('fix_mileage_gap', 'job_tracker', 'Fix a missing clock-out',
     'Fills a missing clock-out (dead phone) with a reason and rebuilds the day.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('manage_vehicles', 'job_tracker', 'Vehicles (VIN) and odometer',
     'Add vehicles by VIN, crew-owned cars, odometer readings, day vehicle.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('get_mileage_report', 'job_tracker', 'Mileage report and deduction',
     'Miles by driver/vehicle/month, deduction by IRS rate period, reimbursement, Form 4562 sheet.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Reports screen."),
    ('mileage_settings', 'job_tracker', 'Mileage settings',
     'Tracking on/off, IRS rate table, lock periods, reimbursement pay period, reminders.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('export_mileage_log', 'job_tracker', 'Export mileage log',
     'IRS mileage log as PDF, Excel (Trips/Summary/Reimbursement/Vehicles) or CSV; save, email, or download.',
     BOTH, False, None, True, "Used by the Jobs PWA App's Reports screen."),
    ('mileage_reimbursement', 'job_tracker', 'Crew mileage reimbursement',
     'Submit, approve, return, and mark paid crew-car mileage per pay period; PDF statements.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('review_mileage_log', 'job_tracker', 'AI mileage review',
     'Finds route/odometer mismatches, long legs, duplicates, vague purposes, misclassified commutes; '
     'proposes fixes without changing anything.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('apply_mileage_review_fix', 'job_tracker', 'Apply a mileage review fix',
     'Accepts (audited edit) or dismisses one AI mileage review finding.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('job_cancelled_on_arrival', 'job_tracker', 'Customer cancelled on arrival',
     'Records the visit so the drive still counts, marks the job Cancelled, rebuilds the day.', BOTH,
     False, None, True, "Used by the Jobs PWA App's Mileage tab."),
    ('get_ar_aging_report', 'job_tracker', 'AR aging report',
     'Accounts-receivable aging report from unpaid invoices.', BOTH,
     False, None, False, None),
    ('build_daily_route', 'job_tracker', 'Build daily route',
     'Full route builder: geocodes, orders stops, writes Route_Planner.', BOTH,
     False, None, False, None),
    ('suggest_route_schedule', 'job_tracker', 'Suggest a route (free heuristic)',
     'Fast, free, deterministic route-ordering suggestion.', BOTH,
     False, None, False, None),
    ('prescreen_route_jobs', 'job_tracker', 'Pre-check jobs before routing',
     "Read-only check of a day's jobs (missing address/coordinates, duplicates) run before Route Today / Run AI Route. Added to the catalog 2026-09-28 (R-049) — it shipped 2026-09-25 without a row.", BOTH,
     False, None, False, None),
    ('apply_route_order', 'job_tracker', 'Apply a reasoned route order',
     'Writes a caller-reasoned visit order into Route_Planner.', BOTH,
     False, None, False, None),
    ('get_route_drive_matrix', 'job_tracker', 'Get drive-time matrix',
     "Real drive-time/distance matrix between a day's jobs.", BOTH,
     False, None, False, None),
    ('reorder_route_stop', 'job_tracker', 'Reorder a route stop',
     "Moves one stop's position and re-plans the whole day.", BOTH,
     False, None, False, None),
    ('pin_route_stop', 'job_tracker', 'Pin a route stop',
     'Fixes a stop at its position across rebuilds.', BOTH,
      False, None, False, None),
      ('pause_job', 'job_tracker', 'Pause or resume a job',
       'Pauses a job so it is never routed until resumed. Trash on a paused job still clears its dates.', BOTH,
       False, None, False, None),
    ('replan_route_day', 'job_tracker', 'Re-plan a route day',
     'Recomputes arrival times/warnings for the current stop order.', BOTH,
     False, None, False, None),
     ('approve_route_schedule', 'job_tracker', 'Approve a route',
      "Approves the route: allows emailing it and pins its link as viewable on the Jobs/Calendar pages. Never changes any job's Start/End Time.", BOTH,
      False, None, False, None),
     ('unapprove_route_schedule', 'job_tracker', 'Un-approve a route',
      "Fully undoes approval: clears the approval flag, unpins the route link, and revokes email eligibility.", BOTH,
      False, None, False, None),
    ('email_route_now', 'job_tracker', "Email today's route",
     'Emails the currently-saved route right now, on request.', BOTH,
     False, None, False, None),
    ('get_approved_route_stops', 'job_tracker', 'Get approved route stops',
     'Approved-route ETAs and drive legs per date, for the Jobs/Board job cards.', BOTH,
     False, None, False, None),
    ('get_working_days', 'job_tracker', 'Get working days',
     'Reports the Working Days setting (which days multi-day jobs are worked).', BOTH,
     False, None, False, None),
    ('list_team_members', 'job_tracker', 'List team members',
     "Names and roles of the team's active users, for the Jobs app's Crew / Technician picker (server mode). Never tokens, emails or phones.", BOTH,
     False, None, False, None),
    ('delete_route', 'job_tracker', 'Delete a whole route',
     "Permanently deletes an entire day's route (all stops).", BOTH,
     False, None, False, None),
    ('delete_route_stop', 'job_tracker', 'Delete one route stop',
     'Permanently deletes a single route stop.', BOTH,
     False, None, False, None),
    ('get_ai_route_prompt', 'job_tracker', 'Copy AI Route prompt',
     "Builds a prompt that plans a day's route in any AI chat connected to this AI-Prowler, with a one-time route code.", BOTH,
     False, None, False, None),
    ('confirm_route_code', 'job_tracker', 'Confirm route code',
     'Tells a pasted AI Route prompt whether this AI-Prowler made its route code (MATCH / NO MATCH).', BOTH,
     False, None, False, None),
    ('get_week_plan_prompt', 'job_tracker', 'Copy Plan Week prompt',
     "Builds a prompt asking any connected AI chat to suggest moving soft jobs so nearby jobs share a day.", BOTH,
     False, None, False, None),
    ('get_week_plan_data', 'job_tracker', 'Get week plan data',
     "A week's jobs, which may move and where, and nearby pairs — for a pasted Plan Week prompt.", BOTH,
     False, None, False, None),
    ('propose_week_moves', 'job_tracker', 'Propose week moves',
     'Saves checked soft-job date moves as a suggestion for the user to approve. Changes no job.', BOTH,
     False, None, False, None),
    ('get_week_proposal', 'job_tracker', 'Get week plan suggestion',
     "The newest Plan Week suggestion waiting for approval.", BOTH,
     False, None, False, None),
    ('apply_week_moves', 'job_tracker', 'Approve week moves',
     "Moves the approved jobs of a Plan Week suggestion to their suggested dates (re-checked first).", BOTH,
     False, None, False, None),
    ('dismiss_week_proposal', 'job_tracker', 'Dismiss week plan suggestion',
     'Closes a Plan Week suggestion without moving anything.', BOTH,
     False, None, False, None),
    ('export_to_excel', 'job_tracker', 'Export to Excel',
     'One-way workbook snapshot of the whole job tracker. Server mode: owner, managers and staff only — field crew are always refused.', BOTH,
     False, None, False, None),
    ('export_to_csv', 'job_tracker', 'Export to CSV',
     'One-way CSV export, per table. Server mode: owner, managers and staff only — field crew are always refused.', BOTH,
     False, None, False, None),
    ('export_to_quickbooks_csv', 'job_tracker', 'Export for QuickBooks',
     "CSV export pre-labeled with QuickBooks Online's own field names. Server mode: owner, managers and staff only — field crew are always refused.", BOTH,
     False, None, False, None),
    ('backup_job_database', 'job_tracker', 'Backup job database',
     'Full, lossless copy of the job tracker database. Server mode: owner, managers and staff only — field crew are always refused.', BOTH,
     False, None, True, "Used by the Settings tab's Backup Now button and scheduled-backup automation."),
    ('restore_job_database', 'job_tracker', 'Restore job database',
     "Replaces the live job tracker database with a backup — meant for moving to a new PC. A safety backup is always made first. Server mode: owner, managers and staff only (field crew are always refused), and if the live database already has records the restore is refused unless the caller explicitly says to wipe them.", BOTH,
     False, None, True, "Used by the Settings tab's Restore from Backup button."),
    ('check_sms_configured', 'sms_whatsapp', 'Check SMS is configured',
     'Lightweight yes/no check for whether an SMS provider is set up.', BOTH,
     False, None, False, None),
    ('send_sms', 'sms_whatsapp', 'Send an SMS',
     'Sends a text message to a user, customer, or saved contact.', BOTH,
     False, None, False, None),
    ('check_sms_inbox', 'sms_whatsapp', 'Check full SMS inbox',
     'Reads the entire local SMS/WhatsApp inbox, unscoped.', PERSONAL,
     False, None, False, None),
    ('check_sms_replies', 'sms_whatsapp', 'Check my SMS replies',
     'Checks inbound SMS replies, scoped to threads you personally sent.', SERVER,
     False, None, False, None),
    ('check_whatsapp_replies', 'sms_whatsapp', 'Check WhatsApp replies',
     'Checks inbound WhatsApp messages, per-user scoped in server mode.', BOTH,
     False, None, False, None),
    ('send_whatsapp', 'sms_whatsapp', 'Send a WhatsApp message',
     "Sends a WhatsApp message via Twilio's WhatsApp Business API.", BOTH,
     False, None, False, None),
    ('list_sms_consents', 'sms_whatsapp', 'List SMS consent records',
     'Lists opt-in records captured via the consent-signup widget.', BOTH,
     False, None, False, None),
    ('delete_sms_consent', 'sms_whatsapp', 'Delete an SMS consent record',
     'Permanently deletes a consent record (CCPA/GDPR-style requests).', BOTH,
     False, None, False, None),
    ('get_sms_thread', 'sms_whatsapp', 'Get a conversation thread',
     'Returns the full two-way SMS/WhatsApp thread with a contact.', BOTH,
     False, None, False, None),
    ('list_sms_contacts_with_replies', 'sms_whatsapp', 'List contacts with replies',
     'Lists recently-texted contacts with unread reply counts.', BOTH,
     False, None, False, None),
    ('check_email_configured', 'email', 'Check email is configured',
     'Lightweight yes/no check for whether SMTP email is set up.', BOTH,
     True, 'Email is a core communication channel — always available.', False, None),
    ('configure_email', 'email', 'Configure email (personal)',
     'Saves SMTP credentials for a personal install.', PERSONAL,
     True, 'Email is a core communication channel — always available.', False, None),
    ('send_email', 'email', 'Send an email',
     'Sends a plain-text email, with optional attachment.', BOTH,
     True, 'Email is a core communication channel — always available.', False, None),
    ('send_alert', 'email', 'Send a quick alert email',
     'Fires a one-line alert email, subject auto-generated.', BOTH,
     True, 'Email is a core communication channel — always available.', False, None),
    ('send_file', 'email', 'Email a file attachment',
     'Sends any tracked file as an email attachment.', PERSONAL,
     True, 'Email is a core communication channel — always available.', False, None),
    ('list_outlook_accounts', 'email', 'List Outlook accounts',
     'Lists configured Outlook accounts so send_email can pick one. Personal installs only (R-049: Tier A in server mode — it reads the local Outlook profile, and already refused to run there).', PERSONAL,
     True, 'Email is a core communication channel — always available.', False, None),
    ('create_analysis_task', 'agentic_analysis', 'Create a custom analysis task',
     'Defines a new recurring or one-off AI analysis task.', PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", False, None),
    ('list_analysis_tasks', 'agentic_analysis', 'List analysis tasks',
     'Lists the full custom-analysis task definition list.', PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", True, 'Used by the Remote Control PWA.'),
    ('get_pending_analysis_tasks', 'agentic_analysis', 'Get due analysis tasks',
     'Returns tasks that are due right now.', PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", True, 'Used by the Remote Control PWA.'),
    ('queue_single_task', 'agentic_analysis', 'Queue one task now',
     'Queues one specific custom task for immediate execution. Fixed 2026-09-24: previously missing from _TIER_A_SUPPRESSED, which orphaned it in server mode with no other tool in this category available there to act on what it queued.', PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", True, 'Used by the Remote Control PWA.'),
    ('get_all_queued_tasks', 'agentic_analysis', 'List everything queued',
     'Returns every queue entry, due or not. Fixed 2026-09-24: same orphaned-in-server-mode issue as queue_single_task, same fix.', PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", True, 'Used by the Remote Control PWA.'),
    ('complete_analysis_task', 'agentic_analysis', 'Complete a queued task',
     'Marks a queued task done and re-arms it if recurring.', PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", False, None),
    ('delete_analysis_task', 'agentic_analysis', 'Delete an analysis task',
     'Removes a task definition or a single queue entry.', PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", True, 'Used by the Remote Control PWA.'),
    ('update_analysis_task', 'agentic_analysis', 'Edit an analysis task',
     "Edits an existing custom task's schedule/prompt/outputs.", PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", True, 'Used by the Remote Control PWA.'),
    ('save_analysis_report', 'agentic_analysis', 'Save an analysis report',
     'Saves a full analysis as a Word (.docx) document.', PERSONAL,
     True, "Part of AI-Prowler's always-on Agentic Analysis task queue (Personal installs only).", False, None),
    ('create_file', 'file_code_tools', 'Create a file',
     'Creates a new file. Fails if it already exists.', BOTH,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('write_file', 'file_code_tools', 'Overwrite a file',
     'Overwrites an existing file, auto-backing up first.', BOTH,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('str_replace_in_file', 'file_code_tools', 'Surgical file edit',
     'Replaces one exact text match in a file.', BOTH,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('line_replace_in_file', 'file_code_tools', 'Line-range file edit',
     'Replaces a range of lines by line number.', BOTH,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('create_directory', 'file_code_tools', 'Create a directory',
     'Creates a directory and any missing parents.', BOTH,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('grep_documents', 'file_code_tools', 'Grep tracked files',
     'Exact text/regex search across tracked files with line numbers.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('read_file_lines', 'file_code_tools', 'Read exact file lines',
     'Reads an exact line range from a file.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", True, 'Used by the Remote Control PWA.'),
    ('list_directory', 'file_code_tools', 'List a directory',
     "Lists a directory's files, subdirectories, and backups.", PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", True, 'Used by the Remote Control PWA.'),
    ('copy_to_backup', 'file_code_tools', 'Snapshot a file',
     'Takes a manual .bakN snapshot without modifying the file.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('list_backups', 'file_code_tools', 'List file backups',
     'Lists all .bakN backups for a given file.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('restore_backup', 'file_code_tools', 'Restore a file backup',
     'Overwrites a file with a specified .bakN backup.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('cleanup_backups', 'file_code_tools', 'Clean up file backups',
     'Finds and optionally deletes old .bakN backup files.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('cleanup_job_logs', 'file_code_tools', 'Clean up background job logs',
     'Deletes old run_script_start job files past retention.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('reset_write_counter', 'file_code_tools', 'Reset write circuit breaker',
     'Resets the per-session write-count safety limit.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('diff_files', 'file_code_tools', 'Diff two files',
     'Compares two files and returns a unified diff. Registered in both modes (server mode: all roles, scoped to their own assigned files).', BOTH,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('compile_check', 'file_code_tools', 'Python syntax check',
     'Byte-compiles a Python file to catch syntax errors.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('check_python_import', 'file_code_tools', 'Python import check',
     'Imports a module in a separate process to catch load-time errors.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('syntax_check', 'file_code_tools', 'Multi-language syntax check',
     'Syntax checker for many languages beyond Python.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('lint_check', 'file_code_tools', 'Multi-language lint check',
     'Linter for unused imports, undefined names, style issues.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('run_script', 'file_code_tools', 'Run a script (sync)',
     'Runs a script and returns combined stdout+stderr.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('run_script_start', 'file_code_tools', 'Run a script (background)',
     'Launches a script as a background job, returns a job_id.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('run_script_status', 'file_code_tools', 'Check background job status',
     'Checks status and tails the log of a background job.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('run_script_kill', 'file_code_tools', 'Kill a background job',
     'Terminates a running background job.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('grant_write_access', 'file_code_tools', 'Grant write access',
     'Adds a directory to the write-zone allowlist.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", True, 'Used by the Remote Control PWA.'),
    ('revoke_write_access', 'file_code_tools', 'Revoke write access',
     'Removes a directory from the write-zone allowlist.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", True, 'Used by the Remote Control PWA.'),
    # Access-only folders: personal mode only (2026-10-09, David) — hidden on a
    # server (Tier A), used by the Remote Control PWA's Permissions screen.
    ('grant_access', 'file_code_tools', 'Grant access-only folder',
     'Adds a directory to the access-only list \u2014 readable, never indexed.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", True, 'Used by the Remote Control PWA.'),
    ('revoke_access', 'file_code_tools', 'Revoke access-only folder',
     'Removes a directory from the access-only list.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", True, 'Used by the Remote Control PWA.'),
    ('list_writable_directories', 'file_code_tools', 'List writable directories',
     'Lists the current write-zone allowlist.', BOTH,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", True, 'Used by the Remote Control PWA.'),
    ('get_file_download_url', 'file_code_tools', 'Get file download link',
     'Signed URL for the Remote/Jobs PWA to download a tracked file.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('get_file_upload_url', 'file_code_tools', 'Get file upload link',
     'Signed URL for the Remote PWA/artifact to upload a file.', PERSONAL,
     True, "Part of AI-Prowler's always-on File & Code Tools feature (Personal installs only, where applicable).", False, None),
    ('hr_backup_now', 'hr', 'HR backup now',
     'Trigger an immediate HR data backup.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_complete_task', 'hr', 'Complete HR task',
     'Mark an HR task as complete.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_create_employee', 'hr', 'Create employee',
     'Add a new employee record.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_get_backup_settings', 'hr', 'Get HR backup settings',
     'Retrieve HR backup configuration.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_get_employee', 'hr', 'Get employee',
     'Retrieve an employee record.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_get_form', 'hr', 'Get HR form',
     'Retrieve an HR form template.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_get_report', 'hr', 'Get HR report',
     'Generate an HR report.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_get_setup_status', 'hr', 'Get HR setup status',
     'Check HR system setup completion.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_get_state_rules', 'hr', 'Get state rules',
     'Retrieve state-specific HR compliance rules.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_get_task_digest', 'hr', 'Get task digest',
     'Get a summary of HR tasks.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_initiate_termination', 'hr', 'Initiate termination',
     'Start the employee termination workflow.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_list_backups', 'hr', 'List HR backups',
     'List available HR data backups.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_list_documents', 'hr', 'List HR documents',
     'List HR documents.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_list_employees', 'hr', 'List employees',
     'List all employee records.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_list_tasks', 'hr', 'List HR tasks',
     'List HR tasks.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_restore_employee', 'hr', 'Restore employee',
     'Restore an archived employee record.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_send_notification', 'hr', 'Send HR notification',
     'Send an HR notification.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_set_backup_settings', 'hr', 'Set backup settings',
     'Configure HR backup settings.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_update_employee', 'hr', 'Update employee',
     'Update an employee record.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    ('hr_verify_document', 'hr', 'Verify document',
     'Verify an HR document.', SERVER,
     False, None, True, 'Used by the HR Admin / HR Portal apps (server).'),
    # ── Service Desk (2026-10-27) ──
    ('create_ticket', 'service_desk', 'Create ticket',
     'File a customer, internal or subcontractor ticket by chat or voice.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('get_ticket', 'service_desk', 'Get ticket',
     'Show one ticket with its messages, attachments and history.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('list_tickets', 'service_desk', 'List tickets',
     'List and filter the tickets the caller may see.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('my_tickets', 'service_desk', 'My tickets',
     "Open tickets assigned to the caller, soonest due first.", BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('update_ticket', 'service_desk', 'Update ticket',
     'Change ticket fields with stale-edit protection.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('assign_ticket', 'service_desk', 'Assign ticket',
     'Assign or take a ticket.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('set_ticket_state', 'service_desk', 'Set ticket state',
     'Move a ticket Open → Assigned → In Progress → Fixed → Closed (and On Hold).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('add_ticket_note', 'service_desk', 'Add ticket note',
     'Add an internal note to a ticket.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('reply_to_customer', 'service_desk', 'Reply to customer',
     'Send a previewed reply to the ticket\'s customer or subcontractor by email or text.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('create_job_from_ticket', 'service_desk', 'Create job from ticket',
     'Turn a re-do or service request into a scheduled Jobs app job.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('manage_ticket_queues', 'service_desk', 'Ticket queues',
     'Create and edit Service Desk queues and their members (Business).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('manage_ticket_rules', 'service_desk', 'Assignment rules & types',
     'Assignment rules and ticket types (owner).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('ticket_report', 'service_desk', 'Ticket report',
     'Volume, reply and fix times, SLA breaches and ratings.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('export_tickets', 'service_desk', 'Export tickets',
     'Excel, CSV, full JSON or one-ticket PDF export.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('import_tickets', 'service_desk', 'Import tickets',
     'Import tickets with a dry run first; undo a batch for 7 days.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('tickets_backup_now', 'service_desk', 'Back up Service Desk',
     'Verified backup of tickets, photos and settings.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('backup_tickets_database', 'service_desk', 'Back up tickets database',
     'Same as Back up Service Desk.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('list_tickets_backups', 'service_desk', 'List Service Desk backups',
     'Backups with date, size and verified status.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('tickets_backup_settings', 'service_desk', 'Service Desk backup settings',
     'Backup schedule, retention and second destination.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('restore_tickets_database', 'service_desk', 'Restore Service Desk',
     'Restore everything or one ticket from a backup (owner, confirmed).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('search_tickets', 'service_desk', 'Search tickets',
     'Find past tickets and fixes by words.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('ticket_summary', 'service_desk', 'Ticket summary',
     'Short status of a ticket or a queue; repeated fixes to learn from.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('triage_inbox', 'service_desk', 'Triage inbox',
     'Suggested priority, type and assignee for new tickets (changes nothing).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('apply_triage', 'service_desk', 'Apply triage',
     'Apply approved triage suggestions.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('link_ticket', 'service_desk', 'Link ticket',
     'Link a ticket to another ticket, an invoice, a job or a customer.', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('merge_tickets', 'service_desk', 'Merge tickets',
     'Merge a duplicate into the main ticket (confirmed).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('get_ticket_updates', 'service_desk', 'Ticket live updates',
     'Tickets changed since a cursor (Service Desk app polling).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('tickets_settings', 'service_desk', 'Service Desk settings',
     'Show or change Service Desk settings (owner).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
    ('ticket_watchers', 'service_desk', 'Ticket watchers',
     'Show, add or remove the internal people emailed whenever a ticket changes state '
     '(by name or email; names come from the team, saved contacts, customers and past contacts).', BOTH,
     False, None, True, 'Used by the Service Desk app.'),
]

TOOL_CATALOG: Dict[str, ToolMeta] = {
    row[0]: ToolMeta(
        category=row[1], label=row[2], description=row[3], modes=row[4],
        locked=row[5], locked_reason=row[6], pwa_dependency=row[7],
        pwa_dependency_note=row[8],
    )
    for row in _RAW
}

# R-049 (2026-09-28): every tool the Jobs app (phone app) calls through
# /pwa-api — the union of ai_prowler_mcp.py's two allow-lists (server mode's
# _srv_pa_allowed and personal mode's _allowed_tools). Turning any of these off
# in the Settings panel now also turns that feature off in the Jobs app (the
# server refuses the call), so each one is marked pwa_dependency and the panel
# warns before disabling it. Before R-049 only 7 of these were marked.
# tests/mcp_tests/test_r049_jobs_app_honours_tool_panel.py fails if this list and
# the two allow-lists ever drift apart.
JOBS_APP_TOOLS: FrozenSet[str] = frozenset({
    "read_job_spreadsheet", "get_board_updates", "get_sheet_columns",
    "update_job_spreadsheet", "log_time_entry", "record_learning",
    "search_learnings", "check_ai_prowler_status",
    "create_job", "create_customer", "create_quote", "create_invoice",
    "create_setting", "create_service_pricing",
    "delete_job", "delete_customer", "delete_quote", "delete_service_pricing",
    "email_invoice", "text_invoice", "email_receipt", "text_receipt",
    "send_sms", "check_sms_configured", "check_email_configured",
    "check_sms_replies", "check_sms_inbox",
    "build_daily_route", "suggest_route_schedule", "prescreen_route_jobs",
    "approve_route_schedule", "unapprove_route_schedule",
      "reorder_route_stop", "pin_route_stop", "pause_job", "replan_route_day", "delete_route_stop",
    "delete_route", "email_route_now", "geocode_address",
    "find_stale_customers", "send_customer_reminders",
    "get_ar_aging_report",           # R-068 (2026-09-29): Reports → AR Aging card
    # start_ai_routing / poll_ai_routing / get_route_start_options and the four
    # *_cli_signin / save_my_cli_token tools left the Jobs app 2026-10-22 with the
    # "🧠 Run AI Route" (Claude CLI) button — replaced by "📋 Copy AI Route":
    "get_ai_route_prompt",           # (2026-10-22): Route tab "📋 Copy AI Route"
    "get_week_plan_prompt", "get_week_proposal",      # (2026-10-22): Route tab "🗓️ Plan Week"
    "apply_week_moves", "dismiss_week_proposal",
    "get_week_plan_data", "propose_week_moves",
      "get_approved_route_stops",
    "get_working_days",              # Working Days setting (2026-10-02): Calendar
    "list_team_members",
      "cancel_indexing", "indexing_status",  # R-069 (2026-10-08): stop button + status readout
      "rename_customer",  # (2026-10-08): Jobs app customer screen via pwa-api
    # Mileage tracker (2026-10-24): Mileage tab, Clock-screen vehicle picker,
    # Reports mileage card.
    "get_mileage_log", "build_mileage_log", "add_mileage_trip", "update_mileage_trip",
    "fix_mileage_gap", "manage_vehicles", "get_mileage_report", "mileage_settings",
    # Mileage Phases 4–5 (2026-10-24): export, reimbursement, AI review,
    # cancelled on arrival.
    "export_mileage_log", "mileage_reimbursement", "review_mileage_log",
    "apply_mileage_review_fix", "job_cancelled_on_arrival",
})

_JOBS_APP_NOTE = "Used by the Jobs app — turning it off also turns that feature off in the app."

import dataclasses as _dc  # noqa: E402

for _name in JOBS_APP_TOOLS:
    _m = TOOL_CATALOG.get(_name)
    if _m is not None and not _m.pwa_dependency:
        TOOL_CATALOG[_name] = _dc.replace(_m, pwa_dependency=True,
                                          pwa_dependency_note=_JOBS_APP_NOTE)

_CATEGORY_BY_KEY: Dict[str, CategoryMeta] = {c.key: c for c in CATEGORY_ORDER}


def is_locked(tool_name: str) -> bool:
    meta = TOOL_CATALOG.get(tool_name)
    return bool(meta and meta.locked)


def category_of(tool_name: str) -> Optional[str]:
    meta = TOOL_CATALOG.get(tool_name)
    return meta.category if meta else None


def tools_in_category(category_key: str) -> List[str]:
    return [name for name, meta in TOOL_CATALOG.items()
            if meta.category == category_key]


def modes_of(tool_name: str) -> FrozenSet[str]:
    meta = TOOL_CATALOG.get(tool_name)
    return meta.modes if meta else frozenset()


def all_tool_names() -> List[str]:
    return list(TOOL_CATALOG.keys())


def tools_available_in_mode(mode: str) -> List[str]:
    """mode is 'personal' or 'server'."""
    return [name for name, meta in TOOL_CATALOG.items() if mode in meta.modes]


def category_label(category_key: str) -> str:
    c = _CATEGORY_BY_KEY.get(category_key)
    return c.label if c else category_key


def category_description(category_key: str) -> str:
    c = _CATEGORY_BY_KEY.get(category_key)
    return c.description if c else ""


def category_is_locked(category_key: str) -> bool:
    """True if every tool in this category is locked (no toggle needed at
    all for this category — used by the GUI to skip rendering Enable-all/
    Disable-all buttons for a category with nothing to toggle)."""
    c = _CATEGORY_BY_KEY.get(category_key)
    if c is not None and c.locked:
        return True
    tools = tools_in_category(category_key)
    return bool(tools) and all(TOOL_CATALOG[n].locked for n in tools)


def pwa_dependents() -> Dict[str, str]:
    """{tool_name: note} for every tool marked pwa_dependency=True."""
    return {
        name: (meta.pwa_dependency_note or "")
        for name, meta in TOOL_CATALOG.items()
        if meta.pwa_dependency
    }
