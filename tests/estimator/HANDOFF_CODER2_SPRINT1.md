# Hand-off prompt: Estimator Coder 2, Sprint 1 (paste into a new chat)

I'm Vicki: Coder 2 and Tester 2 on the AI-Prowler Estimator. Jamie Vavro is Coder 1 and Tester 1. Continue my Coder 2 work.

**Where things are** (on my PC through the AI-Prowler_Daves_PC tools):
- Work folder: `C:\Users\david\AI-Prowler_V971_to_V1000_work\AI-Prowler`
- Spec: `docs\estimator\AI-Prowler Estimator Design Spec.md`. Plan: `docs\estimator\AI-Prowler Estimator Implementation Plan.md`. Read the Coder 2 rows, the progress log and the Change log.
- Jamie finished Coder 1 Sprints 1–16. His code includes the service layer `estimator/estimating/service.py` with `RequestContext` from `estimator/context.py`, plus 55 MCP tools in `estimator/mcp_tools/est_tools.py`. Don't change his files without a reason. Note any change in the Change log.
- **Estimator tests run only with `run_tests_estimator.bat`, not `run_tests.bat`.** Usage: `run_tests_estimator.bat` (all), `coder1`, `coder2`/`webapp`, plus any pytest args. It uses a sandbox data folder and writes a log to `test_logs\`.

**Coder 2 Sprint 1 is built and passing:** 661 passed (580 Jamie + 81 new) on Windows / Python 3.11.8, 2026-11-07. This is the web app shell, which follows the `desk_http.route()` pattern:
- `estimator/api/auth.py`: In Personal mode on the same PC there is no login. To count as the same PC, a request needs a loopback address, **no proxy or tunnel headers** (cloudflared connects from localhost) and a localhost Host header (blocks DNS rebinding). Every other request logs in. Sessions are kept in memory: HttpOnly SameSite=Strict cookie or Bearer token, 12-hour sliding expiry. 5 failed logins lock out for 5 minutes. A pluggable `set_verifier()` handles Server-mode accounts. The Personal password is `ESTIMATOR_OWNER_PASSWORD` or AI-Prowler's `remote_token`. Writes need the header `X-Estimator-Request: 1` (CSRF protection).
- `estimator/api/nav.py`: the 13 menu screens in spec order, which roles see each, the MCP tools behind each screen (parity), and a permissions map per role.
- `estimator/api/live.py`: live updates follow the `estimate_events` audit table by id, scoped to the company. That table catches changes from chat, agents and other processes. It sends pointers only.
- `estimator/api/router.py`: `/estimator-api/{health, auth/login, auth/logout, me, dashboard, estimates (GET/POST), estimates/<id>, estimates/<id>/events, updates}` plus static files from `/estimator/`. Fields with cost or margin words are hidden for roles that can't see margins (field). Errors map to HTTP codes. Errors return a generic 500 with no internals. The security headers include a strict CSP.
- `estimator/api/server.py`: ThreadingHTTPServer plus the SSE stream at `/estimator-api/events` (Last-Event-ID, pings). Default port 8770 (`ESTIMATOR_WEB_PORT`). It binds to 127.0.0.1 in Personal mode, or 0.0.0.0 with `ESTIMATOR_WEB_NETWORK=1` or in Server mode. Includes `start_with_ai_prowler()` (never raises; `ESTIMATOR_WEB=off`) and `python -m estimator.api.server`.
- `estimator/ui/web/{index.html, app.css, app.js}`: a self-contained SPA with no CDN and no inline script. It has sign-in, a role-filtered left menu, Dashboard and Projects screens, "coming in Sprint N" pages that list the MCP tools, live updates over SSE with polling fallback, and a phone layout.
- Tests: `tests/estimator/webapp/` (conftest, test_web_auth, test_web_router, test_web_server, test_web_parity).

**Still to do to close Sprint 1, in order:**
1. **Hook into AI-Prowler.** Add a guarded call to `estimator.api.server.start_with_ai_prowler()` in `ai_prowler_mcp.py` right after the Estimator tools registration block (around line 7144). Skip it under pytest. Wire `auth.set_verifier()` and Server mode to AI-Prowler's account/edition system (look at how the `/desk-api` middleware resolves the user). Check that `install_estimator.py` copies `estimator/api` and `estimator/ui/web`. Add an "Open Estimator" link or status in Jamie's GUI tab (`estimator/ui/gui_tab.py`, "phone/web placeholder") only after agreeing it with Jamie.
2. **Manual checks on the PC:** run `python -m estimator.api.server`, open http://localhost:8770/estimator/ and create a project. Run `est_create_estimate` from chat and confirm the page updates live. Check the login screen from another device with `--network`.
3. **Docs** (Definition of Done):
   - `tests/estimator/SPRINT_1_CODER2_TEST_PLAN.md`, in the same style as Jamie's `SPRINT_*_CODER1_TEST_PLAN.md`, with automated and manual checks.
   - A Change log line in the spec (Sprint 1 Coder 2: new `estimator/api/` package, port 8770, in-memory sessions, live updates from `estimate_events`, CSRF header, `run_tests_estimator.bat`).
   - A progress-log row in the Implementation Plan.
   - The Getting started / web app section of `docs/Estimator User Guide.md`, if it exists.
4. Then **Coder 2 Sprint 2**: documents (upload and validation, file storage in the project folder), plus fuller Dashboard, Projects and Quick estimate screens.

Open decisions for Jamie (spec owner):
- Sessions in memory vs a table (needs a migration).
- The `est_add_trade` / `est_remove_trade` tools the spec lists for Projects don't exist yet (`PENDING` in test_web_parity.py).
- Field role sees totals but no costs or margins.
