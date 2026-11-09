# Sprint 13 — Coder 2 (David) test plan: reviews on a phone or tablet

**Scope:** The Coder 2 Sprint 13 row is "PWA mobile reviews (review queue, highlight, approve/relabel by touch)". The spec's PWA Estimates tab adds: measurement approval too, laid out for touch; drawing new shapes and calibrating scale stay on the desktop.

- **Review queue:** one list of symbols to check and measurements waiting, least sure first.
- **Highlight:** each item shown in place on its sheet, outlined in red, without the tiled viewer.
- **By touch:** one item at a time; big Approve / Take out / Relabel / Skip; swipe right to approve, left to take out.
- **Jobs app:** the Estimates tab gets **Quick estimate | Reviews (n)**.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat browser         Playwright, including a 390 x 844 touch phone (add --human to watch)
run_tests.bat tests\mcp_tests\test_jobs_pwa_testids.py    the Jobs app ids the E2E suite uses
deploy_to_install.bat                   then restart AI-Prowler
```
- **No new database migration, tables or MCP tools.** Decisions go through the existing calls and services, so the same rules hold: asks first, people only (never an agent), logged.
- **No new libraries** (Pillow draws the outline).

## What was built

**Queue** (`estimator/mobile/queue.py`, `GET /mobile/reviews?estimate_id=&kind=&limit=`):
- **Symbols:** status proposed (to check), from the Reviews screen's roles. Field staff see them but can't decide (`can.review_symbols` false).
- **Measurements:** status proposed, from the Takeoffs screen's roles (owner, estimator, reviewer).
- **Order:** least sure first (confidence, then kind and id); `limit` up to 200.
- **Each item:** title in sentence case (legend text is often in capitals), what and where (quantity, trade, room, project, sheet), confidence, picture URL (none for typed measurements), and a link to Blueprint Review (`#/takeoffs/<estimate>?sheet=&symbol=` or `?m=`). Measurements with a suggested change or marked to re-measure say so.
- **Also returned:** counts (`symbols`, `measurements`, `waiting`), the projects in the list, what this role can see and decide (`can`), and the standard item types for Relabel.

**Pictures in place** (`estimator/mobile/view.py`):
- `GET /mobile/symbols/<id>/view.png`, `GET /mobile/measurements/<id>/view.png`.
- At least 6 x 6 sheet inches round the item, at most 900 px across, cut from the sheet image the plan engine saved; the item outlined in red (a box for a symbol; area, line or points for a measurement; a measurement's own shape, or the drawing objects it came from).
- Cached in the data folder (`review_views/`), keyed by the shape and the sheet image. Local only; nothing is sent to an AI provider.
- 404 for a typed measurement, another company's item, or a sheet with no picture; field staff get 403 on measurement pictures.

**Touch page** (`estimator/ui/web/mobile.js`, `#/m/reviews?kind=&estimate=&i=`, page `mobile_reviews` from Reviews):
- Waiting count, Symbols / Measurements chips, project list, ◀ position ▶.
- The picture, title, confidence, details, notes; **✓ Approve**, **✗ Take out**, **Relabel…** (symbols: a list of item types by trade, and "every identical match on this plan set"), **Skip ▶**.
- Swipe right to approve and left to take out: each still asks first (`askThen`). After a decision the queue reloads and the next item shows.
- Buttons at least 56 px high; the page fits a 390 px screen with no sideways scroll.
- Roles that can't decide see "You can look at these here…" instead of the buttons.

**Pictures with the Jobs app's token** (`apiImage` in `app.js`):
- Inside the Jobs app the Estimator is signed in by that app's token (an `Authorization` header, no cookie), and an `<img src>` can't send it. So over Remote Access the Reviews thumbnails (Sprint 11) didn't load.
- `apiImage(img, url)` fetches the picture with the token and shows it from a `blob:` URL (the CSP already allows `blob:`); without a token it sets `src` as before. Used by the phone page and the Reviews thumbnails. **Not yet:** Blueprint Review's sheet tiles (desktop page) still use plain `src`.

**Jobs app** (`jobs/index.html`): **Quick estimate | Reviews (n)** above the Estimator frame. Reviews opens `/estimator/?embed=1#/m/reviews`; the count comes from `/estimator-api/mobile/reviews?limit=1` with the app's token (the same rule as the Estimator's `appToken()`). Test ids `est-mode-quick`, `est-mode-reviews`, `est-review-count`.

**Guide:** "Check symbols and measurements on your phone" (screen: reviews).

## Automated tests

`tests/estimator/webapp/test_web_sprint13.py` (Smith house: a 12 x 12 ft KITCHEN with three measurements waiting, from the room, drawn and typed; Jones power: 3 receptacles and 2 unnamed symbols):

| ID | Test | Checks |
| --- | --- | --- |
| C2S13-Q01 | test_one_queue_least_sure_first | 5 symbols + 3 measurements; confidences in order; titles in sentence case; picture and plan links; a typed measurement has no picture; what the owner can do; item types for Relabel |
| C2S13-Q02 | test_filters | kind, project, limit; bad values 400; POST refused |
| C2S13-Q03 | test_who_sees_what | Field: symbols only, can't decide; reviewer: both; office 403; another company sees nothing |
| C2S13-V01 | test_each_item_in_place_outlined | Symbol picture larger than its thumbnail with red outline; measurement from a room object and a drawn one; cached |
| C2S13-V02 | test_pictures_are_refused_where_they_should_be | Typed 404; unknown ids 404; another company 404; field: symbol yes, measurement 403 |
| C2S13-D01 | test_decisions_leave_the_queue | Approve, relabel, approve a measurement, take one out: they leave the queue; field's decision refused 403 |
| C2S13-W01 | test_the_touch_page_is_wired | nav page, PAGES.mobile_reviews, parseHash, buttons, swipe, askThen, apiImage (also for thumbnails), script order, no inline styles, 56 px buttons |
| C2S13-W02 | test_the_jobs_app_estimates_tab_has_reviews | The switch, its ids, the Reviews page URL, the count call and its token rule |

`tests/estimator/browser/test_browser_sprint13.py` (the new `phone` fixture: 390 x 844, touch, mobile):

| ID | Test | Checks |
| --- | --- | --- |
| C2S13-B01 | test_approve_a_symbol_by_tapping | Picture loads; fits the screen; Approve ≥ 56 px; tap, Yes, next item; counts go down |
| C2S13-B02 | test_take_out_by_swiping_left | Swipe left asks to take it out; Yes; next item |
| C2S13-B03 | test_relabel_and_skip | Skip changes nothing; back; relabel as a floor box |
| C2S13-B04 | test_approve_a_measurement_and_see_a_typed_one | Measurement picture, typed one says so; approve the room measurement |
| C2S13-B05 | test_pictures_load_with_the_jobs_app_token | Server mode, signed in only by the Jobs app's token: the page and its picture load (blob URL) |
| C2S13-B06 | test_empty_queue | "All checked" and "Nothing waiting" |

Also updated: `tests/estimator/browser/conftest.py` (the `phone` fixture), `tests/mcp_tests/test_jobs_pwa_testids.py` (the 3 new Jobs app ids).

## Manual checks (Tester 2)

| # | Check | Expected |
| --- | --- | --- |
| M1 | On a real phone, through Remote Access: Jobs app → Estimates → Reviews | The count shows; the page opens signed in; pictures load |
| M2 | Approve 10 symbols in a row by thumb | Each asks once; the next item comes up; nothing scrolls sideways |
| M3 | Swipe left and right | Swiping asks first; a vertical scroll doesn't trigger a swipe |
| M4 | Relabel a symbol with "every identical match" | All matches change; the Reviews screen on the desktop agrees |
| M5 | Approve a measurement on the phone | Locked on the desktop's Blueprint Review; priced on the Estimate page |
| M6 | A tablet, portrait and landscape | Picture and buttons fit; nothing cut off |
| M7 | Field staff sign-in | Symbols only, no buttons, "You can look at these here" |
| M8 | Reviews thumbnails on the desktop Reviews screen through Remote Access | They load (they didn't before this sprint) |

## Questions for David / Jamie

- **Field staff and mobile reviews:** the spec's role list says Field does "mobile reviews", but symbol review roles are owner, estimator and reviewer (Sprint 11, Jamie's services). Field staff can look but not decide. Should Field approve on the phone? That would change `REVIEW_ROLES` and `APPROVE_ROLES`.
- **Blueprint Review tiles** inside the Jobs app frame still use plain `<img src>`; the tiled viewer is a desktop page, but if it's opened in the frame over Remote Access the tiles won't load. Fix when needed (same `apiImage` approach, or a short-lived signed URL).
