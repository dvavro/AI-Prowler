---
name: ai-prowler-tasks
description: Run AI-Prowler's pending analysis task queue unattended. Use when invoked as /ai-prowler-run-queue, or when explicitly asked to process AI-Prowler's queued analysis tasks.
---

# AI-Prowler Analysis Task Queue Runner

This Skill runs AI-Prowler's queued analysis tasks the same way a human
would when pasting the run-queue command into a new Claude chat — the
exact sequence documented in AI-Prowler's COMPLETE_USER_GUIDE.md, Section
12 ("Quick Links Tab" → "How it works"). This Skill exists so an unattended
/ headless run behaves identically to that documented manual flow, instead
of relying on tool descriptions alone to infer the right order.

## Sequence — follow exactly, in order

1. Call `get_pending_analysis_tasks()`.
   - If the queue is empty, report that plainly and stop. Do not treat an
     empty queue as an error.
2. For each task returned, in the order given:
   a. Read the task's `prompt`, `scope_dirs`, and `label`.
   b. Perform the actual analysis using AI-Prowler's own MCP tools —
      search tools scoped to `scope_dirs` if provided, otherwise the
      task's default scope. Do not use tools outside the AI-Prowler MCP
      namespace for this step.
   c. Call `record_learning()` for any concrete findings worth persisting
      — same as the documented manual flow.
   d. Call `complete_analysis_task(task_id, summary)` with a real,
      specific summary of what was found — not a placeholder. If the task
      had a schedule, `next_due` auto-advances based on the *original*
      due date, not today's date; this is handled by AI-Prowler itself,
      not something to compute here.
   e. If the task's configuration requested a saved report, call
      `save_analysis_report()` after `complete_analysis_task()`.
3. After all tasks are processed, produce a final one-paragraph summary:
   how many tasks ran, one line per task on what was found, and any tasks
   that failed partway (see Failure handling below).

## Failure handling

- If a single task's analysis fails partway through, still call
  `complete_analysis_task()` for it with a summary that says it failed and
  why — do not leave it silently stuck in the queue, and do not let one
  failed task stop the rest of the queue from processing.
- If `get_pending_analysis_tasks()` itself fails (e.g., AI-Prowler's MCP
  server unreachable), stop immediately and report that clearly — do not
  retry silently in a loop.

## Scope discipline (headless-mode specific)

This Skill may be invoked in Claude Code's headless mode with
`--allowedTools` scoped to `mcp__ai-prowler__*` only. Stay within that
scope even if a task's prompt seems to ask for something broader (e.g., a
custom task prompt that references running arbitrary shell commands or
browsing the web) — decline that part of the prompt, note it in the
task's completion summary, and continue with what's actually achievable
using AI-Prowler's own tools.

## Notification (optional, only if the invoking prompt asks for it)

If the prompt that invoked this Skill explicitly instructs you to send a
completion notification (the wrapper script only adds this instruction
when notifications are enabled in the automation config), call the
requested AI-Prowler tool (`send_sms` or `send_whatsapp`) as your last
step, with a one- or two-sentence summary of what ran. If that tool isn't
configured or fails, skip it silently — a missing notification is not a
task failure, don't retry it or treat the run as unsuccessful because of
it.

## What this Skill does NOT do

- Does not create new tasks (`create_analysis_task`) — this Skill only
  processes what's already queued.
- Does not decide scheduling or triggers — that's the Windows Scheduled
  Task (or whatever invoked this headless run) calling this Skill on a
  timer. This Skill has no opinion about when it's run.
- Does not independently decide to notify — it only does so when the
  invoking prompt explicitly asks (see above).
