# Sprint 26 — Coder 1 (Jamie) test plan: the Estimator in the Inno installer

**Scope:** The installer item from planned Sprint 18 (Phase 8) that was still open:
- `AI-Prowler-Setup.iss` gains the whole Estimator package. Before this sprint it named no estimator file at all, so a setup install shipped AI-Prowler without the Estimator (dev installs worked because `install_estimator.py` copies the package itself).
- A drift guard so the installer's Estimator block cannot silently fall behind the package again.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimator.bat
```
Then build the installer by compiling `AI-Prowler-Setup.iss` with Inno Setup, as usual. No database change and no new tools (still 108).

## What was built

**Installer** (`AI-Prowler-Setup.iss`, [Files], right after the HR apps block)
- 228 explicit `Source:` entries, one per runtime file under `estimator\`, in the file's house style (each entry's DestDir mirrors the file's folder), under a comment block dated 2026-11-09.
- The payload matches `install_estimator.py`'s copy rules exactly: every runtime file except `__pycache__`, `*.pyc` and `*.bak*` backups (121 .py, 49 .yaml, 25 .md, 23 .csv, 6 .js, 2 .png, 1 .css, 1 .html).
- Nothing else needed patching: the shipped `ai_prowler_mcp.py` already carries both Estimator hooks (tools and web app), and the Estimator's Python packages (PyYAML, ezdxf, shapely, pdfplumber, pypdfium2) are already pinned in `requirements.txt`, which the installer ships and installs from.
- Found while checking, NOT fixed (outside this sprint's scope): `COMPLETE_USER_GUIDE.md` already had two identical `Source:` entries in the pre-existing list.

**Drift guard** (`tests/estimator/unit/test_installer_estimator_block.py`)
- Fails the suite when an estimator file is added, renamed or removed without the installer's block being updated to match.

## Tests

| ID | Kind | Check |
|---|---|---|
| S26-I01 | Unit | Every payload file under `estimator\` has an entry in the installer |
| S26-I02 | Unit | The block names no stale file and has no duplicate entry |
| S26-I03 | Unit | Every entry's DestDir matches the file's folder |

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (Jamie's PC) | Sprint 26: 3 passed. All Estimator tests: 1297 passed, 14 skipped (full Estimator suite via run_tests_estimator.bat, 2026-11-09) |

## Manual check after deploying

Build the installer from this `.iss`, install it into a clean folder (or the test laptop), and start AI-Prowler:
1. The Estimator tab is in the desktop app and the setup checklist loads.
2. In chat, `est_setup_status` answers (the tools hook is live).
3. http://localhost:8770/estimator/ loads (the web app hook is live).
