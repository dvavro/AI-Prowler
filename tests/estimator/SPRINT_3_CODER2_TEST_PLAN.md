# Sprint 3 — Coder 2 (David) test plan: Price Book screen (basic)

**Scope:** The Coder 2 Sprint 3 row is "Estimator tab in the AI-Prowler GUI v1 …; Price Book screen (basic); PWA Estimates tab (quick estimates)". Jamie built the Estimator tab in his Sprint 16, so it's done. This sprint builds the **Price Book screen**. The **PWA Estimates tab** waits on one decision: how phones reach the Estimator API through Remote Access (see the end).

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

## PWA Estimates tab: waiting on a decision

The Jobs app (`jobs/index.html`) is served by AI-Prowler on port 8000 and through Remote Access. The Estimator API is on port 8770, which the tunnel doesn't reach, and a page on 8000 can't call 8770 without cross-site rules. The proposed fix: AI-Prowler's 8000 server passes `/estimator-api/*` (and `/estimator/`) through to the Estimator router in-process, the way it serves `/desk-api`, and signs the caller in with the Jobs app's own token. This also answers the "Remote Access through port 8000" open question. It changes AI-Prowler's request handling and the Jobs app, so David decides before it's built.
