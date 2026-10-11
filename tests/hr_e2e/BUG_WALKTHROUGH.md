# 🐞 Bug Walkthrough — what the HR E2E tests have caught and fixed

This is a plain-English tour of every real bug the automated tests found in **HR Admin** and the **Employee Portal**, what you would have seen, how it was fixed, and how to check it yourself. It is updated as testing continues.

**Watch any of these live:** in a Command Prompt, `cd C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\tests\hr_e2e`, then run `run_tests_hr_e2e.py --test "<test name>"` (e.g. `--test "E2E-06"`). Two Chrome windows open side by side and do everything in slow motion, with a red dot on each click. Add `--slow 800` to go even slower.

---

## What kinds of bugs do the tests catch?

| Kind of bug | What the tests do to catch it | Example below |
|---|---|---|
| **Broken page layout** | Open every page; check it sits inside the app next to the sidebar, isn't blank, doesn't scroll sideways | #1 |
| **Missing or wrong data on screen** | Look for "undefined", "NaN", dashes where real info should be; compare the screen with the server | #2, #8 |
| **Page crashes** (JavaScript errors) | Record every red error in the browser console, labeled with the page it happened on | #5 |
| **Server refusing the right person** (403/404) | Record every failed call to the HR server | #3 |
| **Security / privacy holes** | Try things *without* signing in, or as the wrong person, and make sure the server says no | #6, #7 |
| **Two apps out of sync** | Do something in one app, check the other app **and** the server show the same thing | #8 |
| **Data left behind / not saved** | After every action, ask the server what it actually saved; after every test, delete test data and **prove** it's gone | all tests |

---

## Bugs fixed

### #1 — Pages pushed below the sidebar (Portal) — *Sept 23*
- **Where:** Employee Portal → Documents, Messages, Help, Deposits, Calendar, HR Handbook, Trainings, Incident Reports…
- **What you saw:** the sidebar shrank into a small box at the top and the page appeared underneath it instead of beside it.
- **Cause:** two stray `</div>` tags in the page's HTML closed the main area too early.
- **Fix:** removed both stray tags.
- **Guarded by:** `PRT-LAY-01` (opens all 24 Portal pages every run).

### #2 — Portfolio full of dashes; sidebar said "Employee" (Portal) — *Sept 24*
- **Where:** Employee Portal → Portfolio, and the name in the sidebar.
- **What you saw:** every box on Portfolio showed "—", and the sidebar said "Employee" instead of your name.
- **Cause:** start-up code tried to show an old floating chat bubble that had been removed; it crashed before loading your details.
- **Fix:** start-up and Sign out skip the missing bubble.
- **Guarded by:** `PRT-LAY-01`, `AUTH-05`, `AUTH-06`.

### #3 — Birthdays refused by the server (Portal) — *found by PRT-LAY-01, Sept 25*
- **Where:** Employee Portal calendars (birthdays).
- **What you saw:** birthdays missing; a red "403" error in the browser console.
- **Cause:** the server's "get one employee by ID" route also caught `/employees/birthdays` and treated the word **"birthdays"** as an employee ID — then refused because it wasn't *your* ID.
- **Fix:** that route now skips named sub-routes like "birthdays".
- **Check it yourself:** Portal → Calendar — birthdays show; press F12 → Console — no red 403.
- **Guarded by:** `PRT-LAY-01` (fails on any failed server call).

### #4 — PTO page existed twice (Portal) — *found by PRT-LAY-01, Sept 25*
- **Where:** Employee Portal → PTO / Time Off.
- **What you saw:** nothing visible — but the page's HTML contained two copies, which confuses future edits.
- **Fix:** removed the unused second copy.
- **Guarded by:** `PRT-LAY-01` (reports any page that exists twice).

### #5 — Training page crashed every time it opened (HR Admin) — *found by ADM-LAY-01, Sept 28*
- **Where:** HR Admin → ☰ Menu → 📚 Training.
- **What you saw:** the new "Training Portfolios" page still showed, so it looked fine — but a crash happened in the background every time (red error in the console).
- **Cause:** the Training page was rebuilt, but the **old** training-list code still ran on open and tried to write into a box that no longer exists.
- **Fix:** the old code quietly skips itself when its box isn't on the page.
- **Check it yourself:** HR Admin → 📚 Training → F12 → Console — no red "Cannot set properties of null".
- **Guarded by:** `ADM-LAY-01` (opens all 21 HR Admin pages, labels every error with its page).

### #6 — 🔒 Incident reports readable without signing in (server) — *confirmed by PRT-SEC-02, Sept 28*
- **Where:** the server behind "My Submitted Reports".
- **What was wrong:** anyone who could reach the website — **no sign-in** — could ask for incident reports by name. Name matching was partial, so even one letter ("a") matched most people. Other employees' incident reports could have been read.
- **Fix:** sign-in required; each employee gets **only their own** reports.
- **Guarded by:** `PRT-SEC-02` (tries it without signing in — must be refused).

### #7 — 🔒 Anyone could message HR as anyone (server) — *confirmed by PRT-SEC-03, Sept 28*
- **What was wrong:** messages to HR could be sent **without signing in, under any name** (someone could pretend to be another employee). HR's broadcast messages could also be read without signing in.
- **Fix:** sign-in required; the sender's name/ID now come **from their sign-in**, not from what the page claims. **Anonymous feedback stays anonymous** (no name, email, or ID saved). The Portal now automatically sends the employee's sign-in with every HR request — 7 features (messages, replies, incident reports, feedback, IT requests, payroll emails, report list) had been sending none.
- **Guarded by:** `PRT-SEC-03`, `PRT-SEC-04`, and `X-MSG-01` (proves messaging still works).

### #8 — Employees never saw HR's progress on incident reports (Portal) — *found by E2E-06, Sept 28*
- **Where:** Employee Portal → 🚨 Incident Reports → My Submitted Reports.
- **What you saw:** after HR marked a report **Under Review** or **Resolved**, the employee still saw **"Pending"** forever.
- **Cause:** the Portal's badge only knew two labels — "Pending" and "↩ HR Replied" — and never read HR's status.
- **Fix:** the badge shows HR's real status — **Pending** (blue), **Under Review** (orange), **Resolved** (green) — plus "↩ HR Replied" when HR answered. The report's detail box shows "HR status" too.
- **Check it yourself:** file a test report in the Portal → in HR Admin 🚨 Incident Reports open it → click **Under Review** → back in the Portal the badge turns orange.
- **Guarded by:** `E2E-06` (runs the whole round trip in two windows).

### #9 — Getting Started pop-up reopened right after closing it (Portal) — *found by the watch-mode run, Sept 28*
- **Where:** Employee Portal → the 🚀 Getting Started pop-up, after refreshing the page.
- **What you saw:** close the pop-up with ✕, and a moment later it popped back open, blocking whatever you clicked next.
- **Cause:** on a page refresh, the Portal's start-up routine runs twice (once right away, once after your profile loads). Each run set its own timer to show the pop-up — so closing it only got rid of the first one.
- **Fix:** the pop-up can only be scheduled once per page load, and it re-checks "Don't show again" right before opening.
- **Check it yourself:** in the Portal, refresh → close the pop-up with ✕ → wait a few seconds — it stays closed.
- **Guarded by:** `REG-17` (closes it, waits 3 seconds to prove it stays closed, then proves "Don't show again" sticks after a refresh).

### #10 — Recruiting bounced you back to Positions (HR Admin) — *found by ADM-REC-04, Sept 28*
- **Where:** HR Admin → 🎯 Recruiting → the tabs (Positions, Candidates, Pipeline, Interviews, Offers, Calendar).
- **What you saw:** open Recruiting and quickly click **Interviews** — a second later you're thrown back to **Positions**.
- **Cause:** Recruiting loads its data from the server when it opens, and when the load finished it always switched to Positions, ignoring the tab you'd picked.
- **Fix:** when loading finishes it stays on whichever tab is selected (and redraws it with the loaded data).
- **Check it yourself:** open Recruiting and immediately click Interviews — it stays on Interviews.
- **Guarded by:** `ADM-REC-04` (clicks Interviews right away, waits 2 seconds, checks it's still on Interviews).

### #11 — Pop-ups opened from an employee's record appeared *underneath* it (HR Admin) — *found by ADM-OFF, Sept 28*
- **Where:** HR Admin → open any employee → pop-ups started from inside their record (e.g. **Offboarding → Initiate Termination**, and other pop-ups that share the same box: documents, attendance, tasks).
- **What you saw:** the screen dimmed, but the pop-up was hidden behind the employee's record — so you couldn't click **Confirm Termination** (or the pop-up's other buttons).
- **Cause:** HR Admin draws things in layers. The shared pop-up box was on layer 300, but the employee record panel is on layer 400 — so the record sat on top of the pop-up.
- **Fix:** the pop-up box now sits on layer 600 — above the employee record (400) and the task panel (500), still below the sign-in screen and setup wizard. Notifications (layer 9999) still show on top of everything.
- **Check it yourself:** open an employee → Offboarding → Initiate Termination → the box is on top and **Cancel** / **Confirm Termination** are clickable. *(Click Cancel on a real employee!)*
- **Guarded by:** `ADM-OFF` (terminates a ZZTEST helper through exactly this pop-up).

### #12 — "+ Add Event → Time off" crashed and saved nothing (HR Admin) — *found by code review, Sept 28*
- **Where:** HR Admin → 📋 Scheduled Task (Time Off) → **+ Add Event to Calendar** → type **Time off** → pick an employee → Save.
- **What you saw:** nothing happened — no message, the box stayed open, nothing saved.
- **Cause:** it called a save step (`saveTimeOffRequests`) that doesn't exist anywhere — left behind when time off moved to the server.
- **Fix:** it now creates a **real time-off request on the server** for that employee (shows under Pending and in their Portal). The server now lets HR create a request on an employee's behalf.
- **Guarded by:** `ADM-TOF-10`.

### #13 — PTO Balances always showed "0 days used" (HR Admin) — *found by code review, Sept 28*
- **Where:** HR Admin → 📋 Scheduled Task → **Balances**.
- **What you saw:** every employee showed 0/10 vacation, 0/5 sick, 0/3 personal used — even with approved time off.
- **Cause:** it counted requests named exactly "vacation", "sick", "personal", but real requests are saved as "PTO (Vacation)", "Sick Day", "Personal Day" — nothing matched.
- **Fix:** it recognizes the real names (and half days count as 0.5).
- **Guarded by:** `ADM-TOF-09` (approves 3 vacation days, checks the Balances tab says 3/10).

### #14 — Time-off day counts were off by a day in Arizona (HR Admin) — *found by ADM-TOF-09, Sept 29*
- **Where:** HR Admin → time-off day counts (Balances, "N days" on requests) and dates on an employee's **Timeline** tab.
- **What you saw:** a Monday–Wednesday vacation counted as **2 days** instead of 3; Timeline dates showed **one day early**.
- **Cause:** a plain date like "2026-10-19" was read as **midnight in London (UTC)** — which in Arizona is **5 PM the day before**. So every range started a day early (Mon–Wed became Sun–Tue, and Sunday doesn't count).
- **How the test caught it:** after the Balances fix (#13), Balances showed **4/10** when the answer should have been **6/10** (3 days from the test + 3 left over from an earlier run cut off by a restart) — two 3-day stretches each counted as 2.
- **Fix:** dates are read at **local midnight**, so the right weekdays are counted and shown.
- **Guarded by:** `REG-20` inside `ADM-TOF-09` (Mon–Wed = 3, Fri–Mon = 2, single Tuesday = 1).

### #15 — On a phone, the Portal had no menu at all (Portal) — *found building MOB-LAY-01, Sept 29*
- **Where:** Employee Portal on any phone (any screen under 700 px wide).
- **What you saw:** no sidebar and no ☰ button — so from the page you landed on, most pages (Time Clock, PTO, Messages, Schedule…) couldn't be reached. Only the ← Back button and the Welcome page's cards went anywhere.
- **Cause:** the phone layout hid the sidebar (`display: none`) to save space, but nothing replaced it.
- **Fix:** a **☰ Menu** button in the top bar (phones only, 44 px — easy to tap) slides the sidebar in as a drawer; picking a page or tapping outside closes it. Desktop is unchanged.
- **Check it yourself:** open the Portal on your phone → tap ☰ → pick any page.
- **Guarded by:** `MOB-LAY-01` (iPhone 14 + Pixel 7: opens every page through ☰, checks nothing scrolls sideways).

### #16 — On a phone, the Getting Started pop-up's ✕ couldn't be tapped (Portal) — *found by MOB-LAY-01, Sept 29*
- **Where:** Employee Portal on a phone → first sign-in → 🚀 Getting Started pop-up.
- **What you saw:** tapping ✕ did nothing. (Employees weren't completely stuck — scrolling to the bottom and tapping **"Got it, let's go!"** still closed it — but ✕ is the obvious thing to tap.)
- **Cause:** the ✕ sat inside the pop-up's scrolling content. On small screens (where the pop-up is taller than the screen) other parts of the pop-up and the app's top bar ended up covering it.
- **Fix:** the pop-up now has a **fixed header** (title + ✕, never scrolls) above a **scrolling body** (the steps, "Don't show again", "Got it"). The ✕ is a 44 px tap target, and the pop-up moves to the top level of the page when it opens so nothing sits on top of it.
- **Check it yourself:** on your phone, sign in to the Portal (or refresh) → tap ✕ on the pop-up → it closes.
- **Guarded by:** `MOB-LAY-01` (both phones sign in and close the pop-up before testing the menu).

### #17 — On a phone, the whole Portal was zoomed out and the pop-up was bigger than the screen (Portal) — *spotted by Jamie watching the phone demo, Sept 29*
- **Where:** Employee Portal on any phone — every page, and the 🚀 Getting Started pop-up.
- **What you saw:** the pop-up was bigger than the phone screen; everything looked shrunk.
- **Cause:** the top bar tried to fit ☰, the logo **and** "AI-Prowler HR", a divider, ← Back, the page title, the **full email address**, the avatar, refresh, and Sign out in one row — far wider than a phone. The phone zoomed the whole page out to fit it, so everything (including the pop-up) was laid out wider than the screen, and the pop-up's ✕ ended up off the right edge. This was the real reason the ✕ couldn't be tapped in bug #16.
- **Fix (phones only; desktop unchanged):** a phone-sized top bar — logo icon only, email hidden (it's already in the sidebar), smaller ← Back / Sign out, long titles cut off with "…" — plus a safety net so the page is never wider than the screen. The pop-up is also sized for phones (less padding, smaller title, at most 80% of the screen height).
- **Check it yourself:** open the Portal on your phone — nothing is zoomed out, and the pop-up fits with the app visible around it.
- **Guarded by:** `MOB-LAY-01` (checks the top bar fits the phone's width right after sign-in).

### #18 — Nobody could sign in to the Portal the way the screen said to (Portal + HR Admin) — *reported by Jamie, Sept 30*
- **Where:** Employee Portal sign-in screen; HR Admin → employee → Direct Reports tab → 🔑 Portal Access.
- **What you saw:** the sign-in screen asked for a **"Bearer Token"**, and HR Admin said employees sign in with *"the AI-Prowler Bearer Token … share it with employees."* Jamie entered her email + the AI-Prowler bearer token → refused.
- **Cause:** the two halves disagreed. Someone removed HR Admin's **Set PIN** box planning for everyone to share the AI-Prowler token — but the server was later changed (for good reason) to accept **only each employee's own PIN or token**, never the shared one. So the screens told people to use a credential the server refuses, and HR had no way left to give anyone a PIN. (Also: no employee has a work email on file, so sign-in must use the personal email.)
- **Fix:** kept the safer design (everyone has their own PIN, so nobody can sign in as someone else):
  - HR Admin → employee → **Direct Reports** tab → **🔑 Portal Sign-in** now shows **which email** to sign in with and has a working **Set PIN** box (checks the server's answer; shows "✓ PIN set" or a clear error).
  - The Portal sign-in screen now says **Email** + **Portal PIN**, with "Forgot your PIN? Ask HR — they can set a new one."
- **Check it yourself:** HR Admin → your record → Direct Reports → set a PIN → sign into the Portal with your email + that PIN.
- **Guarded by:** `ADM-PIN-01` (HR sets a PIN → the employee signs in with it; the shared bearer token is refused).

### #19 — 🔒 The server would store a FULL bank account number if a page sent one (server) — *found by PRT-DEP-02, Sept 30*
- **Where:** the server behind Portal → Deposits → Update Bank Account (and HR Admin employee edits).
- **What was wrong:** the Portal itself was fine — it only ever sends the last 4 digits, and the test proved the full numbers never leave the page, aren't stored in the browser, and aren't shown. But the **server trusted whatever it was sent**: a tampered request put a full account number (`000123456789`) into the "last 4" field and the server stored it as-is. For a product holding other businesses' payroll details, the server must enforce the rule itself.
- **Real data:** checked all 7 employees — every bank "last 4" field was 4 digits or fewer. Nothing had been exposed.
- **Fix:** both save routes (employee self-service and HR Admin) now keep **only the last 4 digits** of anything saved as "last 4". Also: HR Admin record edits can no longer overwrite an employee's portal sign-in token directly — credentials only change through Set PIN.
- **Guarded by:** `PRT-DEP-01/02` (network, server, browser, screen, and a tampered-request probe).

### #20 — Every evening after 5 PM, both apps thought it was already tomorrow (Portal + HR Admin) — *found building the calendar tests, Sept 30*
- **Where:** 44 places — 3 in the Portal, 41 in HR Admin. Examples: the Company Calendar's upcoming list; default dates for termination, final pay, and unemployment reports; the date on generated employment and contractor agreements; training "completed" dates; "overdue", "due today", and "upcoming" checks.
- **What you'd see (after 5 PM Arizona time):** today's meetings vanish from the upcoming list; a termination defaults to tomorrow's date; an agreement printed in the evening is dated tomorrow; a training completed tonight is recorded as tomorrow.
- **Cause:** "today" was worked out with `new Date().toISOString()`, which is **London time (UTC)**. Arizona is 7 hours behind, so from 5 PM on, UTC is already the next day. (Same family as bug #14, which was about reading dates; this one is about what "today" is.)
- **Fix:** one small "local today" helper in each app, and all 44 spots switched to it.
- **Guarded by:** `REG-21` (sets the browser clock to 8 PM Arizona and checks both apps still say today is today; also fails if any UTC "today" spot creeps back into the code).

### #21 — Uploading a document from an employee's record made HR pick the employee again, and the file didn't appear (HR Admin) — *found building ADM-DOC-01, Sept 30*
- **Where:** HR Admin → open an employee → **Documents** tab → **Upload Document**.
- **What you saw:** the upload box opened with **"Select employee…"** even though you were already in that person's record — so HR had to find them again in the dropdown (an easy place to pick the wrong name). After uploading, the file **didn't show** in the record's Documents tab until you left and came back, which looked like the upload failed.
- **Not as bad as it could have been:** Upload refuses to go through until an employee is picked, so files couldn't silently land in the wrong person's folder.
- **Fix:** from inside an employee's record, the upload box comes up with **that employee already selected**, and the record's Documents tab **refreshes right after** a successful upload.
- **Guarded by:** `ADM-DOC-01` (uploads a test PDF from Test Tester's record, checks the pre-selection, that it shows immediately, and that it downloads back byte-for-byte).

### #22 — An employee's record listed their documents, but there was no way to open them (HR Admin) — *found by ADM-DOC-01, Sept 30*
- **Where:** HR Admin → open an employee → **Documents** tab.
- **What you saw:** each document showed its icon, name, folder, and date — but there was **no Download button** and the card wasn't clickable. To actually open a file, HR had to leave the record and dig through the separate Documents page.
- **How the test caught it:** after uploading, the test went to click the document's download control in the record — there was nothing to click, so no file ever arrived.
- **Correction:** my first diagnosis was wrong. I first blamed the download code for discarding the file too soon. That change was still worth keeping as a safety improvement (the download link is now added to the page and the file kept for 10 seconds, which Firefox and Safari need) — but it wasn't what the test hit. The real problem was the missing button.
- **Fix:** every document in an employee's record now has a **⬇ Download** button.
- **Guarded by:** `ADM-DOC-01` (finds the document's ⬇ Download button in the record, downloads it, and checks it's byte-for-byte identical to what was uploaded).

### #23 — Uploaded documents came back slightly changed (server) — *found by ADM-DOC-01, Sept 30*
- **Where:** the server's document upload — every file HR uploads (HR Admin's Documents, and the other upload spots that share the same code).
- **What was wrong:** the downloaded test PDF was **415 bytes; the original was 416**. Everything matched except the last character: the line break after `%%EOF` was gone.
- **Cause:** an upload wraps the file in a small "envelope" that adds exactly one line break after the file. The server stripped **every** trailing line-break byte (`rstrip(b"\r\n")`) — so it also removed line breaks that were part of the file itself. HR documents (especially signed forms) need to come back exactly as they went in.
- **Impact so far:** most PDF readers forgive a missing final line break, so already-uploaded documents should still open. But any file whose real content ends in those bytes was being changed.
- **Fix:** the server now removes only the one line break the envelope added — nothing from the file.
- **Guarded by:** `ADM-DOC-01` — its test PDF now has a binary marker line (bytes above 127, like real PDFs) and ends with `\r\n`, and it must download back byte-for-byte identical.

### #25 — Managers never saw who on their team was out today (Portal) — *found building E2E-07, Oct 1*
- **Where:** Employee Portal → **👥 My Team** (managers only) — the "Out / PTO" and "Active Today" counts and the "🏖 Out today" badge.
- **What you saw:** a report approved off **today** still counted as **active**, with no "Out today" badge. Proven on the live Portal: Out / PTO showed **0** for a report who was off that day.
- **Cause:** the same London-time (UTC) date mistake as bugs #14 and #20 — a day off on "2026-10-01" was read as ending at **5 PM on Sept 30** in Arizona, so on the day itself it had already "ended".
- **Fix:** My Team compares plain dates against **today's Arizona date** — no time zones involved. (Also: report names/emails on My Team are now safely escaped, and the HR Assistant's answer about swaps describes the new coworker-swap flow.)
- **Guarded by:** `E2E-07` (a test manager's report is off today → Out / PTO 1, Active 0, "🏖 Out today"; a non-manager doesn't see My Team).

---

## Improvements (approved by Jamie)

### Quiet retry on network hiccups (Portal) — *Sept 28*
- If a request to the HR server gets **no answer at all**, the Portal waits 0.8 seconds and tries once more, silently — for loading data and signing in only. Sends and saves (messages, time off, clock in) are never retried automatically, so a blip can't create duplicates.
- **Guarded by:** `REG-18` (simulates a network blip both ways).

### Recruiting edits can't overwrite each other (HR Admin + server) — *Sept 28*
- **Before:** every Recruiting save sent *everything*, and the server replaced it — so if two people edited recruiting at the same time, whoever saved last silently erased the other's changes.
- **Now:** recruiting has a version number. A save made from an out-of-date copy is refused; HR Admin loads the latest and says *"Someone else just changed recruiting. Their changes are loaded — please redo your last change."* Your own quick saves line up one after another.
- **Guarded by:** `ADM-REC-13` (two HR people save at the same time — the older copy is refused and nothing is lost).

---

## Things found that need a decision (not bugs to "fix" without you)

| Found | What | Needs |
|---|---|---|
| Sept 28 | **PTO balances are hard-coded** — every employee sees "8.5 days PTO · 3 sick · 4 holidays" | Your PTO policy (days per year, monthly build-up?) |
| Sept 28 | A **network hiccup** once made the Portal say "Could not reach HR server" on a correct sign-in | Should the Portal quietly retry once before showing that? |
| Sept 28 | **Record IDs get reused** after deletions (a new request got `PTOREQ-00001` again) | Low priority — fix when convenient |
| Sept 25 | Two employees with the **same full name** could see each other's HR replies | Low priority |

---

## Not bugs (checked and cleared)
- **Recruiting page "blank"** — it draws into its own special area; the test was updated.
- **Second "Send Message to HR" form** — unused leftover code; no employee can reach it.
- **AUTH-05 sign-in failure** — a one-time network hiccup; the test now retries like a person would and logs `⚠ NETWORK BLIP`.
