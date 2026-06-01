# AI-Prowler v7.0.0 — Phase B Resume Checklist

**Purpose:** A scripted pickup for the next DESKTOP session. Everything below
the "Built this session" line is done in code and self-verified (compile +
import clean) but has NOT been pytest-run, deployed, or integrated. This doc is
the turnkey sequence to bank it, prove it, and continue.

---

## A. State at end of the mobile session (2026-05-21)

### Built + self-verified (compile + import OK). NOT pytest'd / deployed / wired.

**Block 1 — D1 Business licensing**
- `ai-prowler-telemetry/schema.sql` — `licenses` table (parent/child + indexes),
  idempotent `mode` handling for heartbeats
- `ai-prowler-telemetry/src/worker.js` — `/license/validate` (public),
  `/issue` `/revoke` `/list` (admin), `requireAdmin` + key helpers (node --check OK)
- `ai-prowler-subs/manage_subscriptions.py` — `business-add` / `business-revoke`
  / `business-list` CLI
- `ai-prowler-subs/BLOCK1_BUSINESS_LICENSING_TEST_PLAN.md` — live deploy+verify steps
- `ai-prowler-subs/test_business_cli.py` — pure CLI tests

**Block 2 — client license validation** (`ai_prowler_mcp.py`)
- `_evaluate_license_grace` (pure) + `_validate_business_license` (I/O):
  §3.3/§3.4 cache + 24h/7d/14d grace ladder

**Block 3 — multi-user security spine** (`ai_prowler_mcp.py`, all PURE)
- `_resolve_user`, `_allowed_collections`, `_can_index`, `_role_caps` + role matrix
- `_user_has_role`, `_is_admin` (admin gate)
- `_format_audit_entry`, `_filter_audit_entries` (audit helpers)

**Tests** — all appended to `tests/mcp/test_edition_activation.py`, skip-if-absent:
- 14 license-grace (C-MCP-LICENSE-01..14)
- 27 multi-user (C-MCP-MU-01..29)
- ~12 admin/audit (C-MCP-ADMIN-01..16)
- Plus Block 1's `test_business_cli.py` in the subs repo (~15 cases)

### NOT done — needs a keyboard (in dependency order)
1. Commit/push Phase A' (still unpushed) + this Phase B batch.
2. Run `python -m pytest tests` — expect 1–3 first-run failures to fix.
3. Deploy Block 1 (schema + worker) + run its test plan.
4. **Integration** (the real work): wire Block 2 grace into Business startup;
   wire Block 3 auth/scoping into a uvicorn ASGI middleware (spec §5.1). NONE done.
5. Block 4 (Admin tab GUI), Block 5 (onboarding/docs) — entirely ahead.

**Honest progress estimate:** Phase B ~35–40% by effort. The pure logic core is
in and tested; the server-mode integration + Admin UI are the bulk of what remains.

---

## B. Step 1 — Commit & push (do FIRST, banks everything)

Run `git status` in each repo, then add the SPECIFIC changed files (avoid
`git add -A` — the work tree has python-*.exe, __pycache__, Output/, *.bak).

### Work tree: C:\Users\david\AI-Prowler_V602_to_V700_work\AI-Prowler
Changed: `ai_prowler_mcp.py`, `rag_gui.py`, `tests/mcp/test_write_tools.py`,
`tests/mcp/test_edition_activation.py`, `tests/PHASE_A_PRIME_TEST_PLAN.md`
(Note: ai_prowler_mcp.py now also has the dev-check tools + Block 2/3 helpers,
beyond the Phase A' commit message drafted earlier — re-draft the message.)
Also delete scratch: `tests/_crlf_live_check.py`, `tests/_fix_verify.py` (+ .bak)

### Subs repo: C:\Users\david\AI-Prowler-ADMIN-V7\ai-prowler-subs
Changed: `manage_subscriptions.py`, plus new `test_business_cli.py`,
`BLOCK1_BUSINESS_LICENSING_TEST_PLAN.md`, and the DOCS/*.md set.

### Telemetry repo: C:\Users\david\AI-Prowler-ADMIN-V7\ai-prowler-telemetry
Changed: `schema.sql`, `src/worker.js`.

Suggested: commit telemetry first (matches what gets deployed), then work tree,
then subs. Push each.

---

## C. Step 2 — Run the suite

```
cd C:\Users\david\AI-Prowler_V602_to_V700_work\AI-Prowler
python -m pytest tests -v
```
Expected baseline + new: ~326 (Phase A' era) + ~53 new (grace/MU/admin) here.
The Block 1 CLI tests run separately in the subs repo:
```
cd C:\Users\david\AI-Prowler-ADMIN-V7\ai-prowler-subs
python -m pytest test_business_cli.py -v
```
First-run failures are EXPECTED for never-executed logic. Paste them; they'll be
precise (boundary off-by-one, dict-key mismatch). Fix, re-run, green.

---

## D. Step 3 — Deploy + verify Block 1

Follow `ai-prowler-subs/BLOCK1_BUSINESS_LICENSING_TEST_PLAN.md` exactly. Summary:
```
cd C:\Users\david\AI-Prowler-ADMIN-V7\ai-prowler-telemetry
npx wrangler d1 execute ai-prowler-telemetry --file=schema.sql --remote
npx wrangler deploy
```
Then the mint → list → validate → revoke-cascade → re-validate curl/CLI sequence,
then clean up `WHERE company_id='test-co'`.

---

## E. Step 4 — Integration (the heavy server-mode work, NEXT build focus)

This is where the pure helpers get CALLED. Spec §5.1 / §6.4. None built yet.

1. **Business startup branch** in `_run_http` (or a new MODE=server branch):
   when `_EFFECTIVE_EDITION == 'business'` and a license_key is configured, call
   `_validate_business_license(...)` at startup; apply effective edition; surface
   the grace banner. (Wires Block 2.)
2. **uvicorn ASGI app + auth middleware** (`server_app` module, spec §5.1/§6.4):
   extract bearer → `_resolve_user(users.json, token)` → attach request.state.user
   → 401 if None. (Wires Block 3 resolve.)
3. **Collection scoping**: tool dispatch reads request.state.user, calls
   `_allowed_collections(user, all_role_cols)`, constrains ChromaDB to that list;
   indexing tools gate on `_can_index(user, target)`. ChromaDB calls wrapped in
   `asyncio.to_thread()` (sync client). (Wires Block 3 scoping.)
4. **users.json I/O**: load on startup, deferred last_seen writes.
5. **Audit append**: per-request `_format_audit_entry(...)` → append JSONL;
   `view_audit_log` admin tool uses `_filter_audit_entries`.
6. **Admin MCP tools** (`add_user`, `list_users`, `revoke_user`, ...) gated by
   `_is_admin(request.state.user)`.

**Why this is keyboard-only:** failure mode is "runs but misbehaves" (wrong
collection returned, middleware ordering, async/sync deadlock) — only a live
server launch + real requests reveal it. Build incrementally, launch between steps.

---

## F. Step 5 — Remaining blocks
- **Block 4 — Admin tab** (Tk in rag_gui.py): user list, add/edit/revoke,
  audit-log table, collection management, server status panel. (spec §10)
- **Block 5 — onboarding/docs**: white-glove runbook, Enable-Remote-Support
  button (DWService, 4h auto-expire), installer cloudflared service. (§9.6, items 12–14)

---

## G. Known gaps carried forward
- Seat-cap enforcement on later `/license/issue` calls (Block 1 mints initial
  children only; no running total vs `seats`).
- `/license/issue` always mints a NEW parent; "add seat to existing company" is
  an Admin-tab concern.
- `/license/release_install` is public (matches /heartbeat); consider admin-gating
  for the Admin Active-Installs panel.
- Dev-check tools (`compile_check`/`check_python_import`) are available in all editions; confirm
  they're OFF on any Business deploy.
