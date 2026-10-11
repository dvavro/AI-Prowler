# AI-Prowler HR — End-to-End Tests

Automated browser tests that click through the **real installed** HR Admin and Employee Portal, like a person with a mouse and keyboard. Full plan: [`TEST_SPEC_HR_E2E.md`](TEST_SPEC_HR_E2E.md).

Tests run **only when you start them**.

---

## Before you run

1. **Deploy the latest code** (Administrator Command Prompt):
   ```
   C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\deploy_hr.py
   ```
   Restart AI-Prowler if `ai_prowler_mcp.py` changed. Tests check what's **installed**, not the dev folder.
2. **AI-Prowler is running.**
3. Nobody is in the middle of real HR work (tests use the live apps).

You do **not** need to type any password. The script reads your AI-Prowler bearer token from `C:\Users\jamie\.ai-prowler\config.json`, and gives the **Test Tester** account a fresh random PIN each run.

---

## How to run — Option A: Command Prompt (best for watching)

1. Open **Command Prompt** (a normal one is fine — no admin needed).
2. Type these two lines, pressing **Enter** after each:
   ```
   cd C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\tests\hr_e2e
   run_tests_hr_e2e.py
   ```
3. **First run only:** it installs Playwright and a test copy of Chrome (a few minutes). After that it starts right away.
4. A **Chrome window opens** and the test runs in slow motion. A **red dot** shows every click.
5. When it finishes, the window shows **PASS / FAIL**, a list of any problems, and where the log is. Press **Enter** to close.

> Don't type `python` in front — just the file name, the same way you run `deploy_hr.py`.

### Options

| Type this | What it does |
|---|---|
| `run_tests_hr_e2e.py` | All tests, visible browser, slow motion |
| `run_tests_hr_e2e.py --fast` | Hidden browser, full speed |
| `run_tests_hr_e2e.py --slow 800` | Even slower — easier to follow |
| `run_tests_hr_e2e.py --test "LAY"` | Only tests whose name contains `LAY` |
| `run_tests_hr_e2e.py --no-pause` | Don't wait for Enter at the end |

## How to run — Option B: ask Claude (through AI-Prowler)

In the Claude chat, say **"run the HR e2e tests"**. Claude starts `run_tests_hr_e2e.py` with AI-Prowler's `run_script` tool and reads the results back to you.

---

## Reading the results

Every run gets its own folder: `logs\run_<date>_<time>\`

| File | What's in it |
|---|---|
| `run_tests_hr_e2e.log` | **Start here.** Every step, PASS/FAIL, each problem in plain English, and paths to screenshots/videos |
| `report\index.html` | Double-click to open. Each test with its steps, screenshots, video, and trace |
| `test-results\...\video.webm` | Recording of the whole test — open in Chrome |
| `test-results\...\trace.zip` | Step-by-step replay (see below) |
| `test-results\...\page_<name>.png` | Screenshot of each page visited |
| `results.json` | Machine-readable results |
| `hr_db.snapshot.json` | Emergency backup of the HR database from before the run |

**Replay a test step by step** (shows every click, the screen before/after, and console errors):
```
cd C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\tests\hr_e2e
npx playwright show-trace "<path to trace.zip from the log>"
```

---

## Tests so far

| ID | What it checks |
|---|---|
| **PRT-LAY-01** | Signs into the Portal as Test Tester, opens **every** sidebar page, and checks each one: inside the main area (not pushed below), sidebar full height, page not blank, no sideways scrolling, no "undefined" / "NaN" / "DEBUG:" text, sidebar shows the real name, Portfolio details filled in. Lists every console error and failed server call. *Views only — creates no test data.* |
| **X-MSG-01** | **Messaging between both apps**, in two windows side by side. Portal (Test Tester) sends a message to HR → HR Admin sees it as **NEW**, opens it, text matches, replies → Portal **↻ Refresh** shows "Re: …" and the reply → HR Admin deletes it with 🗑 → verified gone from the server and the Portal. Checks the server after every step. *Creates one tagged `ZZTEST` message and deletes it; cleanup verified.* Run just this one: `run_tests_hr_e2e.py --test "X-MSG"` |

---

## Safety

- Tests only sign into the Portal as **Test Tester** (`jamievavroaiprowler+hrtest@gmail.com` — emails land in Jamie's inbox).
- Every test that creates data deletes it and verifies it's gone (see spec, Section 3.4).
- `hr_db.snapshot.json` is **not** restored automatically. Only restore it by hand if a run leaves a mess (spec, Section 2.4) — it undoes *all* HR changes since that run started.
- `test_config.json`, `logs\`, and `node_modules\` are in `.gitignore` and never pushed.
