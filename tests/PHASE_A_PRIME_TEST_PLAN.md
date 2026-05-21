# AI-Prowler v7.0.0 Phase A' (Mobile Tier) — Test Plan & Validation Checklist

**Scope:** The Mobile-tier / install-id-binding work (Phase A' of the
v7.0.0 Multi-User build). Covers the edition/mode model, install_id
binding, the 2-active-install rule, the D1-backed activation endpoint,
and the GUI License panel.

**Companion docs:**
- `AI-Prowler_v6_5_MultiUser_Architecture_FINAL.md` (where v6.5 == v7.0)
- `AI-Prowler_v6_5_MultiUser_Implementation_Plan.md`

**Baseline:** The existing suite is ~294 tests + 6 CRLF regression tests
(C-MCP-WRITE-83..88) added this cycle = ~300. Phase A' adds the edition /
activation tests described in section 4 once the hoist in section 4.0 is done.

---

## 0. What was built in Phase A' (units 1-7)

| Unit | Area | Files touched |
|---|---|---|
| 1 | EDITION/MODE model: config loader, constants, startup enforcement | ai_prowler_mcp.py |
| 2 | install_id wiring (MCP server reads ~/.ai-prowler/install_id) | ai_prowler_mcp.py |
| 3 | Edition added to all 6 _check_subscription return paths | ai_prowler_mcp.py |
| 4 | 2-active-install rule: pure _evaluate_activation + startup binding | ai_prowler_mcp.py |
| 5 | D1-backed activation: schema table, Worker endpoints, client POST | schema.sql, worker.js, ai_prowler_mcp.py |
| 6 | GUI: status-light awareness + Settings->License panel | rag_gui.py |
| 7 | CLI: mobile plan name, individual kept as synonym | manage_subscriptions.py |

**Decisions locked this cycle:**
- Backwards-compat grandfathering: client treats plan="individual" ==
  mobile on READ. No live subs.json record is rewritten. Zero lockout
  risk for the 9 active beta testers.
- Activation storage: D1 (existing telemetry Worker), NOT GitHub-write.
- Fail-open: if the activation endpoint is unreachable, the client falls
  back to local evaluation and ultimately ALLOWS access -- a network blip
  must never lock out a paying customer.

---

## 1. Pre-flight (static checks -- no Worker/network needed)

- [ ] Work folder is C:\Users\david\AI-Prowler_V602_to_V700_work\AI-Prowler
- [ ] All three core files compile:
      ```
      cd C:\Users\david\AI-Prowler_V602_to_V700_work\AI-Prowler
      python -m py_compile ai_prowler_mcp.py rag_gui.py
      cd C:\Users\david\AI-Prowler-ADMIN-V7\ai-prowler-subs
      python -m py_compile manage_subscriptions.py
      ```
      Expected: silent (no output) for all three.
- [ ] ai_prowler_mcp.py imports cleanly:
      ```
      cd C:\Users\david\AI-Prowler_V602_to_V700_work\AI-Prowler
      python -c "import ai_prowler_mcp"
      ```
      Expected: returns to prompt (an Ollama model-config notice line is
      normal startup chatter, not an error).
- [ ] Worker JS parses:
      ```
      node --check C:\Users\david\AI-Prowler-ADMIN-V7\ai-prowler-telemetry\src\worker.js
      ```
      Expected: silent.
- [ ] Existing test suite still green (regression guard):
      ```
      cd C:\Users\david\AI-Prowler_V602_to_V700_work\AI-Prowler
      py -m pytest tests
      ```
      Expected: ~300 passed (294 baseline + 6 CRLF). No failures.

---

## 2. Worker + D1 deployment (required before the activation path works end-to-end)

> The client degrades gracefully (fail-open) until this is done -- but the
> /license/activate and /license/release_install routes return 404 until
> the Worker is deployed. "Check Activations" reporting HTTP 404 in the GUI
> is the EXPECTED state pre-deploy and confirms graceful failure.

- [ ] Apply the D1 schema migration (idempotent -- safe to re-run):
      ```
      cd C:\Users\david\AI-Prowler-ADMIN-V7\ai-prowler-telemetry
      wrangler d1 execute ai-prowler-telemetry --file=schema.sql --remote
      ```
      Expected: creates license_activations + its two indexes; existing
      tables untouched (IF NOT EXISTS guards).
- [ ] Deploy the Worker:
      ```
      wrangler deploy
      ```
- [ ] Smoke-test the new routes with curl (replace HASH with any 16-hex):
      ```
      curl -X POST https://ai-prowler-telemetry.david-vavro1.workers.dev/license/activate ^
        -H "Content-Type: application/json" ^
        -d "{\"license_key_hash\":\"abcdef0123456789\",\"install_id\":\"1111111111111111\"}"
      ```
      Expected: { "ok": true, "decision": "admissible", "active_count": 1, ... }
- [ ] Repeat with a 2nd then 3rd distinct install_id for the same hash:
      - 2nd -> decision: "admissible", active_count: 2
      - 3rd -> decision: "rejected", active_count: 2, lists the 2 active ids
- [ ] Release one, then retry the 3rd:
      ```
      curl -X POST .../license/release_install -H "Content-Type: application/json" ^
        -d "{\"license_key_hash\":\"abcdef0123456789\",\"install_id\":\"1111111111111111\"}"
      ```
      Expected: released: true; the previously-rejected 3rd now admissible.
- [ ] Confirm edition: "mobile" heartbeats are accepted (they were rejected
      as "bad edition" before the v7 ALLOWED_EDITIONS fix):
      ```
      curl -X POST .../heartbeat -H "Content-Type: application/json" ^
        -d "{\"install_id\":\"1111111111111111\",\"version\":\"7.0.0\",\"edition\":\"mobile\",\"os\":\"Windows-11\"}"
      ```
      Expected: { "ok": true, ... } (NOT invalid: bad edition).

---

## 3. Manual GUI verification (Settings -> Remote Access)

- [ ] Launch the GUI:
      ```
      cd C:\Users\david\AI-Prowler_V602_to_V700_work\AI-Prowler
      python rag_gui.py
      ```
- [ ] Open Settings -> the "Remote Access" section.
- [ ] A new "Machine Activations (Mobile licenses: max 2 machines)"
      subsection appears BETWEEN the License Key field and the HTTP MCP
      Server controls.
- [ ] It shows "This machine: <16-hex install_id>" (not "unavailable").
- [ ] With NO bearer token saved, clicking "Check Activations" shows
      "Save a Bearer Token first..." -- no crash, no network call.
- [ ] With a bearer token saved AND the Worker deployed (section 2), clicking
      "Check Activations" shows "Active on N of 2 machines (this machine: ...)".
- [ ] Pre-deploy only: "Check Activations" shows "Activation server returned
      HTTP 404" -- confirms the button is wired and fails gracefully.
      (This is a PASS pre-deploy.)
- [ ] "Release Other Machine" with no second machine -> info dialog
      "No other active machine was found."
- [ ] The GUI does not freeze during either button's network call (work runs
      on a daemon thread; UI updates via root.after).
- [ ] Subscription status light: when an install is activation-rejected, the
      light shows "Mobile disabled -- in use elsewhere" (yellow), distinct
      from the renewal-warning and blocked states.

---

## 4. Automated tests (edition + activation logic)

### 4.0 PREREQUISITE -- hoist the pure helpers to module level

The pure-logic functions are currently defined INSIDE _run_http() in
ai_prowler_mcp.py, so a test cannot import and call them without launching
the HTTP server. Before the tests in tests/mcp/test_edition_activation.py
can run, hoist these to MODULE level (and re-point _run_http to call the
module-level versions):

- _plan_to_edition(plan)
- _enforce_edition_mode(edition, mode, sub_status)
- _load_runtime_config()
- _evaluate_activation(entry, install_id, now=None)
- Constants: _VALID_EDITIONS, _VALID_MODES, _MOBILE_PLAN_SYNONYMS,
  _BUSINESS_PLAN_SYNONYMS, _ACTIVE_WINDOW_DAYS, _MAX_ACTIVE_INSTALLS,
  _CONFIG_PATH, _INSTALL_ID_PATH

Dependencies to satisfy at module level: _log (already module-level),
datetime (use module-level import datetime rather than the local _dt
alias), and Path (already imported). The call sites inside _run_http
already use these names, so they will resolve to the module-level
definitions once the locals are removed.

**Verify the hoist immediately** with python -c "import ai_prowler_mcp"
and then run the suite below. The hoist is a pure refactor -- behaviour
must be unchanged.

### 4.1 Test file

tests/mcp/test_edition_activation.py (provided) contains, under test IDs
C-MCP-EDITION-NN and C-MCP-ACTIVATION-NN:

**Edition mapping (_plan_to_edition):**
- individual -> mobile (grandfather)
- mobile -> mobile
- business / small_business / enterprise -> business
- unknown / empty -> mobile (fail-open default)

**Edition/mode enforcement (_enforce_edition_mode):**
- (home, server, ok) -> (home, personal)   [home can't be server]
- (mobile, server, ok) -> (mobile, personal) [mobile can't be server]
- (business, server, ok) -> (business, server) [valid]
- (mobile, personal, blocked) -> (home, personal) [no entitlement]
- (mobile, personal, unmanaged) -> (home, personal)
- (mobile, personal, ok) -> (mobile, personal) [valid]

**2-active-install rule (_evaluate_activation):**
- empty install_id -> "unbound" (fail-open)
- 0 activations -> "admissible"
- this install already active -> "active"
- 1 other active, this new -> "admissible"
- 2 others active, this new -> "rejected"
- 2 others active but 1 stale (>14d) -> "admissible" (stale auto-releases)
- this install active + 1 other -> "active" (this machine wins)
- malformed activation entries are skipped, not crashed on
- Z-suffixed and naive ISO timestamps both parse
- clock injected via now= so tests are deterministic

### 4.2 Run

```
cd C:\Users\david\AI-Prowler_V602_to_V700_work\AI-Prowler
py -m pytest tests/mcp/test_edition_activation.py -v
```
Expected (after hoist): all C-MCP-EDITION-* and C-MCP-ACTIVATION-* pass.
Before hoist: the file skips with a clear reason.

### 4.3 Worker logic (JS)

The Worker's /license/activate decision mirrors _evaluate_activation
exactly (same 14-day window, same max-2, same active/admissible/rejected).
The section 2 curl sequence is the authoritative Worker test. A wrangler dev
local run with the same curl calls is the offline equivalent.

---

## 5. Phase A' acceptance criteria (from Implementation Plan section 3.4)

- [ ] All existing beta-test subscribers (the 9 active individual records)
      continue to work without manual intervention.
- [ ] A subscriber's plan="individual" is read as the mobile edition.
- [ ] New subscribers added via the CLI default to plan="mobile".
- [ ] Installing the same token on a 2nd machine works (admissible).
- [ ] Installing on a 3rd machine triggers the 2-install rejection and the
      client soft-reverts to Home edition (remote access disabled,
      everything else functional).
- [ ] The Settings -> License panel shows active installs and the
      "Release Other Machine" button works against the deployed Worker.
- [ ] After releasing one machine, the 3rd activates correctly.
- [ ] Activation endpoint unreachable -> client fails OPEN (access allowed).

---

## 6. Known deferred items (NOT in Phase A')

- **Hoist** of the pure helpers (see section 4.0) -- prerequisite for the
  section 4 automated tests.
- **GUI subscription-manager dropdowns** (subscription_manager_gui.py) not
  yet updated to show the mobile plan name (CLI is done; GUI dropdown is
  cosmetic).
- **D1-activations viewer CLI command** -- viewing activations from the CLI
  would require authenticated calls to the Worker; deferred to the Phase B
  admin dashboard.
- **Release-endpoint auth** -- /license/release_install is currently public
  (matches the public /heartbeat). For Phase B's admin Active-Installs panel,
  consider gating release behind the admin bearer token.
- **All of Phase B** (server mode, multi-user, Admin tab, parent/child
  licenses) -- separate, larger phase.

---

## 7. Rollback

Every edit this cycle created a numbered .bak backup alongside the file
(e.g. ai_prowler_mcp.py.bak1 ... .bak14). To revert any single file, copy
its earliest relevant .bak back over the active file. Cleaner: git checkout
<file> if the work tree is under git.