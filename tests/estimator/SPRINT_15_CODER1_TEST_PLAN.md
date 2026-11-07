# Sprint 15 — Coder 1 (Jamie) test plan

**Scope:** The Coder 1 part of planned Sprint 10: **API-key agents** (each role runs on Claude or Grok with the agents' own keys, with a backup provider, or from chat, or off), the **budget meter**, the **agent task queue** run by the watcher, and the **role prompts** with `how_to_estimate`. The stall watcher and daily briefing were already built in Sprint 9.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. The database upgrades itself to version 8. There are 55 Estimator tools (9 new).

## What was built

**Providers** (`estimator/agents/providers.py`): uses AI-Prowler's own `desk_agent_providers.py`, so the agents use the keys saved under 🔑 Agent API Key in the Small Business tab, the same models (task_automation_config.json) and the same price table. Keys are never stored in estimator.db, never logged and never shown, only "saved: yes/no".

**Roles** (`agent_roles_get` / `agent_roles_update`, owner only, confirm needed)

| Role | Works now? | What it does |
|---|---|---|
| Reviewer | Yes | Notes for the human reviewer on estimates waiting for review (never approves, never changes prices) |
| Bid Writer | Yes | Drafts scope, inclusions and exclusions for approved estimates; the draft goes on the quote when it's made, and a person previews it before sending |
| Follow-up | Yes | Drafts a follow-up email for quotes due one; a person sends it (`est_agent_apply`, confirm=true) |
| Plan Reader, Takeoff | Waits for the Plan Engine | Can be set up now; no work until then |

Each role: off (default, so nothing runs or costs money until the owner turns it on), chat_only (work waits for an AI in chat: `est_agent_next` / `est_agent_submit`), claude_api or grok_api, an optional model, and an optional backup provider.

**Budget** (`agent_budget_update`): $2.00 a day and $20.00 a month to start. Every call's tokens and cost are logged; agents pause at a limit (with a notice) and pick up again the next day, month or when the budget is raised.

**Agent task queue** (`estimator/agents/queue.py`): the watcher queues work once per estimate version or quote, then runs up to 5 tasks per check. Each task gets one context pack and answers with JSON actions only, which are checked before anything happens:
- only that role's actions (review_note, flag, draft_bid, draft_message, no_action)
- **no dollar amount that isn't in the estimate or quote** (agents never invent numbers)
- the backup provider is tried if the main one fails; after 3 failed tries the task stops with a notice
- a problem in the agents never stops the watcher

**Role prompts** (`estimator/agents/prompts/`): rules for every agent plus 10 role prompts (director, intake, quick pricer, plan reader, takeoff, estimate runner, pricer, reviewer, bid writer, follow-up). `how_to_estimate(role)` returns them.

**Database v8:** `agent_roles`, `agent_budgets`, `agent_tasks`, `agent_usage`.

## Test cases (a fake provider stands in for Claude and Grok, so no money is spent)

| ID | Test | Expected |
|---|---|---|
| S15-R01 | Roles start off | All 5 roles off, $2/$20 budget, nothing queued |
| S15-R02 | Role settings | Confirm needed; model and backup set; same backup refused; unknown provider or odd model name refused; owner only; warns when a key is missing or the role waits for the Plan Engine |
| S15-R03 | Budget settings | Confirm needed; daily can't exceed monthly; bad values refused; owner only |
| S15-R04 | Outside AI-Prowler | Not ready, with a plain reason; calls refused |
| S15-A01 | Reviewer on Claude | Notes and a flag land in the inbox; the prompt has the rules; the context has the $7,817.10 estimate; runs once per version; cost logged (0.9 cents) |
| S15-A02 | Backup provider | Claude overloaded → Grok does it; notice says why; both calls logged |
| S15-A03 | Bad answers | Chatter, a disallowed "approve", a bad key → gives up after 3 tries with a notice |
| S15-A04 | Budget | 1-cent day pauses after 2 calls with a notice; raising it lets work go on |
| S15-A05 | Invented numbers | A note claiming $9,999 is refused; the real $7,817.10 is fine |
| S15-A06/07 | Watcher | Runs the agents each check; an agent crash doesn't stop the watcher |
| S15-C01 | Chat only | Waits for an AI in chat; next task gives prompt, context and allowed actions; disallowed actions refused; a reviewer can submit notes |
| S15-B01 | Bid Writer draft on the bid | The quote gets the drafted scope and exclusions, with a note to check the preview; the draft is used once |
| S15-B02 | Draft applied later | A new quote version with the scope; the old unsent draft is voided; can't apply twice |
| S15-F01 | Follow-up | Not queued until due; draft uses the customer's first name and quote number; shown first, sent only with confirm=true; reviewer can't send |
| S15-P01 | Role prompts | All 10 load with the shared rules |
| S15-T01 | MCP tools | how_to_estimate, roles, budget, run now, next, submit, tasks, apply |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 563 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 563 passed in 26.5 s (2026-11-07) |
| File check | All Estimator files on the PC match, now including the prompt files (test_database.py differs only by blank lines, as before) |

## Manual live check (when you're ready, low-budget key)

1. Save a Claude key in 🔑 Agent API Key (Small Business tab).
2. In chat: "set the AI budget to $1 a day and $5 a month" → `agent_budget_update(..., confirm=true)`.
3. "turn on the reviewer agent with Claude" → `agent_roles_update("reviewer", {"provider": "claude_api", "model": "claude-haiku-5-5"}, confirm=true)`.
4. Start a roof estimate over $500, then `est_agent_run_now`. Expect reviewer notes in `est_director_inbox` and a cost of about a cent in `agent_roles_get`.

## Self-review checklist

- [ ] Every role starts off; nothing costs money until the owner turns it on
- [ ] Keys never leave AI-Prowler's key files
- [ ] Agents can't approve, change prices or send anything; drafts with made-up dollar amounts are refused
- [ ] Every call is logged with tokens and cost; the budget pauses work
