# Sprint 1 — Coder 2 (David) test plan: Estimator web app shell, hooked into AI-Prowler

**Scope:** The Coder 2 Sprint 1 work. This covers the Estimator web app shell (sign-in, role-filtered menu, Dashboard and Projects, live updates), its JSON API, the small HTTP host, the hook that starts it with AI-Prowler, and the Estimator-only test runner. The Plan Engine and the other screens come in later Coder 2 sprints.

## How to run

```
cd /d "C:\Users\david\AI-Prowler_V971_to_V1000_work\AI-Prowler"
run_tests_estimator.bat            all Estimator tests (Coder 1 + Coder 2)
run_tests_estimator.bat coder2     just the web app (tests\estimator\webapp)
install_estimator.bat              copy to the installed AI-Prowler and add the hooks
```
Then close AI-Prowler completely and start it again. The web app is at http://localhost:8770/estimator/. Estimator tests run **only** through `run_tests_estimator.bat`, never `run_tests.bat`; `release_gate.bat` Suite 5 runs the same `tests\estimator` folder through Jamie's `run_tests_estimate.bat`.

## What was built

**JSON API** (`estimator/api/router.py`, `/estimator-api/...`). The endpoints are `health`, `auth/login`, `auth/logout`, `me`, `dashboard`, `estimates` (list, create), `estimates/<id>`, `estimates/<id>/events` and `updates`. Every call goes through Jamie's service layer with a `RequestContext`, so the web app and chat get the same results and the same permission denials. Cost and margin fields are removed for roles that can't see margins (field). Errors map to HTTP codes; unexpected errors return a generic 500 with no internals. The security headers include a strict CSP with no inline script.

**Sign-in** (`estimator/api/auth.py`):
- **Personal mode, same PC: no login.** A request counts as "same PC" only when it has a loopback address, **no proxy or tunnel headers** (cloudflared also connects from localhost) and a localhost Host header (this blocks DNS rebinding). Every other request must log in.
- Sessions are kept in memory, as an HttpOnly SameSite=Strict cookie or a Bearer token, with a 12-hour sliding expiry. 5 wrong passwords lock that name and address out for 5 minutes.
- Writes need the header `X-Estimator-Request: 1` (CSRF protection).
- The Personal password is `ESTIMATOR_OWNER_PASSWORD` or AI-Prowler's remote-access token.

**Server mode sign-in with AI-Prowler accounts** (`estimator/api/prowler_link.py`). This is the same check as the Service Desk app's `/desk-api/auth/login`: your name plus your AI-Prowler access token, which must belong to an active user in `users.json` whose name matches. `users.json` is read at every sign-in, so a revoked user is locked out at once. The company comes from `users.json`. Roles are mapped least-access first: owner → owner, manager → office, staff → office, field_crew → field. `"estimator_role"` in `users.json` can give someone estimator, reviewer, office, field or owner, and `"none"` keeps them out. *(Open for Jamie: final mapping.)*

**Live updates** (`estimator/api/live.py`, `server.py`). These follow the `estimate_events` table by id, scoped to the company, so changes from chat, agents or another process show up. The browser gets server-sent events at `/estimator-api/events` (with Last-Event-ID resume and pings), with polling of `/updates` as the fallback. They send pointers only, never whole estimates.

**HTTP host** (`estimator/api/server.py`). It is a ThreadingHTTPServer on port 8770 (`ESTIMATOR_WEB_PORT`). In Personal mode it binds to 127.0.0.1 only. It binds to all addresses with `ESTIMATOR_WEB_NETWORK=1` / `--network`, or in Server mode. You can run it on its own with `python -m estimator.api.server [--port] [--network] [--server-mode]`.

**Hook into AI-Prowler.** A guarded block in `ai_prowler_mcp.py`, right after the Estimator tools registration, calls `prowler_link.start_from_ai_prowler()`.
- It only starts in AI-Prowler's own HTTP server process (`_IS_HTTP_SERVER`), never in a stdio copy started by Claude Desktop, never in a module that just imports the file, and never under pytest.
- `ESTIMATOR_WEB=off` turns it off.
- It never raises. A busy port is logged, and Server mode without the account lookup refuses to start rather than run unprotected.
- `install_estimator.py` copies the whole `estimator\` folder (including `api\` and `ui\web\`) and adds this hook. An install that already has the tools hook gets only the web hook. Running it again changes nothing.

**Fix to `install_estimator.bat`** (Jamie's file). It had Jamie's Python path hard-coded and fell back to `python`, which isn't on the PATH in the admin window, so on David's PC it failed with `'"python"' is not recognized`. It now finds Python 3.11 *before* asking for admin rights (`%LocalAppData%`, then `py -3.11`, then `where python`, skipping the Windows Store stub) and passes it to the admin window as a short 8.3 path.

**Web page** (`estimator/ui/web/`). It is a self-contained single-page app with no CDN and no inline script. It has sign-in, a role-filtered left menu with the 13 screens in spec order, and Dashboard and Projects screens. The other screens show "coming in Sprint N" and list the MCP tools behind them (parity). It also has live updates and a phone layout.

## Test cases (tests/estimator/webapp/)

| ID | File | Checks |
|---|---|---|
| C2S1-A | test_web_auth.py | same-PC rules (loopback + no proxy headers + local Host); tunnel/proxy headers, DNS-rebinding hosts and other PCs need login; health needs none; owner password, falling back to the remote-access token, none anywhere = nobody; cookie then Bearer; wrong password, 5-fail lockout and its end; logout; idle expiry; made-up token; Server mode needs login on the server PC too, says so when accounts aren't connected, uses the accounts, refuses unknown roles; a broken verifier lets nobody in; CSRF header on writes and login; Secure cookie over HTTPS |
| C2S1-R | test_web_router.py | every endpoint; create/list/get estimates; chat and web see the same project; bad input 400, unknown 404, reviewer can't create; quoting roles can; company scoping; field never sees costs or margins (recursive); menus per role in spec order; dashboard counts and setup; updates feed sees chat and agent changes, batched; generic 500; static files and path traversal refused; page has no CDN or inline script |
| C2S1-S | test_web_server.py | real HTTP round trip on the same PC; login cookie round trip; oversized request refused; SSE pushes changes made anywhere, resumes from Last-Event-ID, needs login off this PC, stops with the server; start is idempotent and stop frees the port; Personal binds to 127.0.0.1; port setting; starting with AI-Prowler never raises |
| C2S1-P | test_web_parity.py | ready screens' MCP tools exist in Jamie's registry; the `PENDING` list (`est_add_trade`, `est_remove_trade`) is still missing (fails when Jamie adds them, so they get wired); tool names follow the spec prefixes; ready screens are the ones the page can draw |
| C2S1-L | test_web_prowler_link.py | role mapping least access first; `estimator_role` override and `"none"`; unknown override ignored; Server verifier: name + token, wrong token, someone else's token, empty, revoked, opted out; users.json re-read each sign-in; Server login end to end through the router (company, user id, role) and no same-PC pass in Server mode; broken users.json lets nobody in; never starts outside the HTTP server or under pytest; `ESTIMATOR_WEB=off`; configures Personal/Server and starts; never raises; Server mode without the lookup refuses to start |
| C2S1-I | test_web_prowler_link.py | the dev `ai_prowler_mcp.py` has exactly the installer's web hook, after the tools hook, and the names it uses exist; installer adds both hooks to a fresh copy (and it compiles), only the web hook to an older install, nothing the second time, and reports a missing anchor |

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), before the hook | 661 passed (580 Jamie + 81 new) (2026-11-07) |
| Windows 11, Python 3.11.8 (David's PC), after pulling Jamie's Sprints 21–23 | 754 passed (2026-11-08) |
| Windows 11, Python 3.11.8 (David's PC), with the hook and link tests | **781 passed, 0 failed** (108 Coder 2) (2026-11-08) |

## Manual checks (David, on the PC)

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | `python -m estimator.api.server`, open http://localhost:8770/estimator/ | opens with no login; left menu shows all 13 screens | |
| M2 | Projects → New project | project appears; Dashboard count goes up | |
| M3 | With the page open, ask Claude "create an estimate for a test customer" (`est_create_estimate`) | the new project appears on the page within a few seconds without reloading | |
| M4 | `python -m estimator.api.server --network`, open http://<PC's IP>:8770/estimator/ from a phone on the same Wi-Fi | sign-in screen; owner + remote-access token signs in; a wrong password 5 times locks for 5 minutes | |
| M5 | `install_estimator.bat`, restart AI-Prowler, check `mcp_server.log` | "Estimator web app: http://localhost:8770/estimator/"; Claude Desktop's stdio copy logs "not started: not AI-Prowler's own HTTP server process" | |
| M6 | Start AI-Prowler with `ESTIMATOR_WEB=off` | no web app, AI-Prowler and the est_ tools work normally | |
| M7 | Server box: sign in as a field_crew user | field menu only; totals but no costs or margins | |

## Open for Jamie (spec owner)

- AI-Prowler → Estimator role mapping (above), and whether `estimator_role` in `users.json` is the right place for exceptions.
- Sessions in memory (sign in again after a restart) vs a table (needs a migration).
- `est_add_trade` / `est_remove_trade` are listed for Projects in the spec but don't exist yet.
- An "Open Estimator" link or status on the Estimator tab's phone/web placeholder (`estimator/ui/gui_tab.py`, your file), not added until you agree.
- Two runners: `run_tests_estimate.bat` (yours, used by the release gate) and `run_tests_estimator.bat` (mine, track options). Both run `tests\estimator`. Should we keep one?
- Remote Access: the tunnel goes to AI-Prowler on port 8000, so phones outside the office can't reach port 8770 yet. Should we proxy `/estimator/` and `/estimator-api/` through the 8000 server like `/desk/`?
