---
name: ai-prowler-tasks
description: Run AI-Prowler's pending analysis task queue unattended. Use when invoked as /ai-prowler-run-queue, or when explicitly asked to process AI-Prowler's queued analysis tasks.
---

# AI-Prowler Analysis Task Queue Runner

> **v8.1.11 note:** the Windows Scheduled Task wrapper no longer invokes
> this file via `/ai-prowler-run-queue` — Skills and slash commands turned
> out to be two different Claude Code mechanisms, and this project never
> had a `.claude/commands/` directory, so that invocation always silently
> failed with "Unknown command" even after the directory it runs from was
> fixed. The headless wrapper now embeds the same instructions below
> directly as its prompt text (see `QUEUE_RUNNER_PROMPT` in
> `task_queue_automation.py`) instead of relying on this file being
> discovered at all. This file is kept as human-facing documentation of
> the sequence, and is still genuinely useful if you're running these
> steps manually or interactively in a Claude Code session — just know
> that editing this file alone will NOT change what the scheduled/headless
> run actually does; `QUEUE_RUNNER_PROMPT` is the source of truth for that.

This Skill runs AI-Prowler's queued analysis tasks the same way a human
would when pasting the run-queue command into a new Claude chat — the
exact sequence documented in AI-Prowler's COMPLETE_USER_GUIDE.md, Section
12 ("Quick Links Tab" → "How it works"). This Skill exists so an unattended
/ headless run behaves identically to that documented manual flow, instead
of relying on tool descriptions alone to infer the right order.

## Sequence — follow exactly, in order

<!-- v9.0.2: sync_due_tasks_to_queue removed from this sequence. The queue
     is user-controlled only — the user manually queues tasks. Custom tasks
     are a saved library; the runner must never auto-promote them. -->

1. Call `get_pending_analysis_tasks()`.
   - This only returns entries that are actually DUE right now
     (`is_queue_entry_ready()`) — it will NOT return a recurring task
     that's queued but not yet due. That's expected, not a bug.
   - If nothing is returned, report that plainly and stop. Do not treat
     an empty/not-yet-due result as an error.
2. For each task returned, in the order given:
   a. Read the task's `prompt`, `scope_dirs`, and `label`.
   b. Perform the actual analysis using AI-Prowler's own MCP tools —
      search tools scoped to `scope_dirs` if provided, otherwise the
      task's default scope. Do not use tools outside the AI-Prowler MCP
      namespace for this step.
   c. Call `record_learning()` for any concrete findings worth persisting
      ONLY IF the task's prompt explicitly includes an Output instruction
      to save key insights as learnings — do not call record_learning if
      the task prompt does not ask for it.
   d. Call `complete_analysis_task(task_id, summary)` with a real,
      specific summary of what was found — not a placeholder. If the task
      has a schedule, `next_due` auto-advances based on the *original*
      due date, not today's date, and the entry RE-ARMS (status resets to
      "pending" rather than closing) so it will surface again on its own
      next cycle — this is handled by AI-Prowler itself, not something to
      compute here. A one-shot task (no schedule) closes permanently.
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

Use AI-Prowler's own tools as the first choice for anything they can
answer. When AI-Prowler itself has no tool or data for something a task's
prompt asks for — current weather details its own weather tool omits,
sunrise/sunset times, local event listings, and similar — fall back to
your own general knowledge where that's enough, and to WebSearch or
WebFetch for anything current or specific that needs looking up. Use
these rather than declining that part of a task and noting it as
unavailable.

If the task's prompt explicitly requires a connected third-party tool
(such as Gmail, QuickBooks, Slack, or any other MCP connector the user
has set up), use it — the user queued this task knowing what tools it
needs. Do not use tools that are clearly outside the scope of what the
task asks for.

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

- Does not create new task DEFINITIONS (`create_analysis_task`) — it only
  processes tasks that are already sitting in the queue.
- Does not auto-promote custom task definitions into the queue —
  `sync_due_tasks_to_queue` is never called here. Queuing is a manual,
  user-controlled action only.
- Does not decide scheduling or triggers — that's the Windows Scheduled
  Task (or whatever invoked this headless run) calling this Skill on a
  timer. This Skill has no opinion about when it's run.
- Does not independently decide to notify — it only does so when the
  invoking prompt explicitly asks (see above).
