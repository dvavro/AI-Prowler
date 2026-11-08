# Sprint 3 — Coder 2 (David) test plan: Price Book screen (basic)

**Scope:** The Coder 2 Sprint 3 row is "Estimator tab in the AI-Prowler GUI v1 …; Price Book screen (basic); PWA Estimates tab (quick estimates)". Jamie built the Estimator tab in his Sprint 16, so it's done. This sprint builds the **Price Book screen** and the **PWA Estimates tab**, by serving the Estimator from AI-Prowler's own port-8000 server (see the end).

## How to run

```
run_tests_estimator.bat coder2
install_estimator.bat            then restart AI-Prowler
```
Open the web app, then 💲 Price Book in the left menu (owner and estimator only). There are no new tools or tables.

## What was built

**Price Book screen** (`#/price_book`; router `/price-book`, `/price-book/import`):
- **The list.** Every price key the company has, plus each trade's samples (`pricebook_get`). It shows the description, the key, the kind, the unit, the cost per unit, and whether the price is yours or a sample (with the "from" date when there is one). You can filter by trade or service, show samples only, and use the find box. A warning shows how many prices are still samples.
- **Editing.** Type new costs in the table. Changed cells are highlighted. "Save changes…" sends only the changed ones to `pricebook_update`, which asks first. The page shows old → new per price (and "was a sample"), and **Yes, save** sends confirm=true. You can give an optional "takes effect" date. Bids already made keep their prices.
- **Import a supplier list.** Paste the CSV rows (header first) and click "Check the list…" (`pricebook_import`, csv_text). It previews the changes, the new prices (with "add rows that don't match"), the unchanged rows and the skipped rows with reasons, then **Yes, save**.
- **Roles.** Costs are only sent to the roles that open the screen (owner, estimator). Reviewer, office and field get 403 on read and write, and the menu hides the screen. The service layer itself already limits changes to owner and estimator.
- **Confirmation.** confirm must be literally `true`; "yes" or 1 doesn't count. The question shown to the user has the "call again with confirm=true" part for the AI removed. `_ask_first()` is the shared helper for any write that asks first.

## Test cases (tests/estimator/webapp/test_web_sprint3.py)

| ID | Test | Checks |
|---|---|---|
| C2S3-L01 | List | everything is a sample at first; filter by trade and samples only; unknown trade 404 |
| C2S3-E01 | Asks first | old → new in cents; nothing saved until confirm; then "yours" |
| C2S3-E02 | Confirm | only `true` confirms |
| C2S3-E03 | Bad changes | empty, not an object, "lots", negative, unknown key, bad date |
| C2S3-E04 | Future date | a 2099 price isn't in effect yet |
| C2S3-E05 | Logged | `prices_changed` reaches live updates |
| C2S3-I01 | Import | preview counts, ready-made change lines, skipped row number; nothing saved until confirm; then saved |
| C2S3-I02 | Add new | unmatched row skipped by default; with add_new it becomes `custom_…` |
| C2S3-I03 | Bad import | empty text, mapping not an object, no cost column |
| C2S3-R01 | Roles | reviewer, office, field: 403 on read, change and import; not in their menu; estimator can change |
| C2S3-R02 | Company | another company still sees the sample |
| C2S3-R03 | CSRF | no app header → refused, nothing saved |
| C2S3-W01 | Page | screen ready and drawn; question text without the AI instructions |

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), Coder 2 track | 162 passed (17 new) (2026-11-08) |

## Manual checks

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | 💲 Price Book → Pressure Washing → change driveway to 0.18 → Save changes… | old → new shown; Yes, save → "yours", sample count drops by one | |
| M2 | Quick estimate for 1000 sq ft driveway afterwards | priced at the new cost; no sample warning for that line | |
| M3 | Paste a 3-row CSV with one unknown item → Check the list… | 2 changes, 1 skipped with the reason; Yes, save | |
| M4 | Sign in as an office or field user (Server mode or a test session) | no Price Book in the menu; /estimator-api/price-book answers 403 | |

## Notes for Jamie

- **`pricebook_get` has no role check.** In chat any role can read company costs. The web screen limits it to owner and estimator. Should the MCP tool do the same (same rule as the screen's roles), or should `see_margins` roles (reviewer, office) see costs too?
- No changes to your files this sprint.

## PWA Estimates tab and the Estimator on port 8000 (built; David chose "serve it through 8000")

**Why:** the Jobs app and Remote Access (Cloudflare tunnel) reach AI-Prowler on port 8000; the Estimator's own port 8770 isn't reachable from outside.

**What was built:**
- **`estimator/api/asgi_bridge.py`.** AI-Prowler's two port-8000 routers (Personal `_run_http`, Server `_run_server_mode`) hand `/estimator`, `/estimator/…` and `/estimator-api/…` to `asgi_bridge.handle()`, just before Service Desk.
  - Every call still goes through `router.route()`, so sign-in, same-PC, the CSRF header, roles and hidden margins are identical to 8770. Through the tunnel, Cloudflare headers mean it is never "same PC".
  - Plan uploads stream from the ASGI receive channel to disk in a worker thread (`ReceiveReader`).
  - Live updates (`/estimator-api/events`) are streamed here. Each poll uses its own database connection in a worker thread.
  - The router always runs off the event loop.
  - `ESTIMATOR_WEB=off` turns off port 8770 only; port 8000 keeps serving, and sign-in is still set up. The Estimator switch in Setup AI-Prowler turns both off (404).
- **Jobs app token = Estimator sign-in.** `auth.set_app_token_resolver()`: a valid AI-Prowler app token sent as `Authorization: Bearer` (never as a cookie, so CSRF can't use it) signs the person in.
  - Personal: any token in `_access_tokens` (the same Bearer Token the Jobs, Remote and Desk apps use) is the owner.
  - Server: the Jobs access token goes through `_srv_raw_token_for` (with the Jobs idle timeout), then users.json (active users only, re-read each time), then the role mapping from Sprint 1.
  - A broken resolver, unknown role or empty user id lets nobody in.
- **Estimator page.** It reads the Jobs app's `localStorage['ap_auth']` (same site on 8000) and sends it as a Bearer token on fetch and upload calls. On a 401 it drops the token, so the Estimator's own sign-in cookie works. With a token it polls instead of using SSE, because EventSource can't send headers. Inside a frame it hides its own brand, search and user bar. It may now be framed by its own site only (`X-Frame-Options: SAMEORIGIN`, `frame-ancestors 'self'`).
- **Jobs app (`jobs/index.html`, AI-Prowler file).** A new "Estimates" tab before Profile, hidden until `/estimator-api/health` answers. It frames `/estimator/?embed=1#/quick`, loaded the first time the tab opens. Existing AI-Prowler tests were updated: the nav-tab count is now 4–13 with a dated note, and the new ids are in the E2E list.

**Deploy:** use `deploy_to_install.bat` (it copies `ai_prowler_mcp.py`, `jobs/` and `estimator/`), then restart AI-Prowler. `install_estimator.bat` only adds the Sprint 1 hooks.

### Test cases (tests/estimator/webapp/test_web_bridge.py)

| ID | Test | Checks |
|---|---|---|
| C2S3-B01 | Paths | `/estimator…` and `/estimator-api…` only |
| C2S3-B02 | Page | served on 8000; SAMEORIGIN framing; health through the tunnel |
| C2S3-B03 | Same PC / tunnel | localhost:8000 opens with no login; tunnel headers → 401 |
| C2S3-B04 | Jobs token | owner signed in by the Jobs token (name shown, can't sign out here); wrong token 401 |
| C2S3-B05 | Writes | CSRF header still required with the token; project created |
| C2S3-B06 | Phone quote | quick estimate through the tunnel with the token |
| C2S3-B07 | Upload | PDF arriving in 3 chunks streams through, asks, attaches |
| C2S3-B08 | Limits | 3 MB JSON → 413 |
| C2S3-B09 | Switch off | Estimator off → 404 for page and API |
| C2S3-B10 | Live | SSE through the bridge delivers a change made by "chat"; tunnel without sign-in 401 |
| C2S3-B11 | Resolver safety | broken / bad role / no user / None → nobody; token never read from a cookie |
| C2S3-B12 | Server resolver | field_crew → field with company; opted out, expired or unknown → none |
| C2S3-B13 | Web off | ESTIMATOR_WEB=off still configures Server sign-in, doesn't start 8770 |
| C2S3-B14 | Wiring | both AI-Prowler routers call the bridge before Service Desk; both resolvers installed |
| C2S3-B15 | Jobs app | Estimates tab, screen, frame, hidden until health, opens `#/quick` |
| C2S3-B16 | Page | reads `ap_auth`, sends Bearer, drops it on 401, polls instead of SSE |

AI-Prowler tests run for the Jobs app change (targeted, `run_tests.bat` with paths): test_pwa_features, test_jobs_pwa_testids, test_pwa_layout_structure, test_pwa_bottomnav_scroll, test_pwa_sheet, test_pwa_sms_feature: **187 passed**. The real `ai_prowler_mcp.py` was also imported with a sandbox: the paths route, nothing starts on import, and the resolver turns a token into the owner.

### Manual checks (after deploy_to_install.bat and a restart)

| ID | Step | Expected | Result |
|---|---|---|---|
| P1 | On the PC: http://localhost:8000/estimator/ | opens with no login (same PC), same as port 8770 | |
| P2 | Phone, Jobs app (Remote Access) → 🧮 Estimates | tab is there; opens Quick estimate already signed in; price a driveway | |
| P3 | In that tab → Open the project → Upload plans (a phone photo of a plan) | progress, question, Attach works | |
| P4 | Chat creates an estimate while the phone shows Dashboard | phone list updates within ~5 s (polling) | |
| P5 | Phone browser (not the Jobs app): https://<tunnel>/estimator/ | sign-in form; owner + Remote Access token signs in | |
| P6 | Turn the Estimator off in Setup AI-Prowler, restart | Estimates tab gone; /estimator/ says turned off | |
| P7 | Server box: crew member's Jobs app → Estimates | signed in as field: quick quotes, no costs, no Price Book | |
