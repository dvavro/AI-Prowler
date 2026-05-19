# AI-Prowler Release Helper

Two files, one job: turn the messy 6-files-across-4-repos release process into
one command.

```
release.bat                     # repo root — double-clickable wrapper
scripts/
  └── release.py                # all the real logic
```

## Why these files live HERE (and how the script knows which repo to release)

`release.py` resolves the repo root as `Path(__file__).parent.parent`. So
**whichever copy of `release.py` you invoke, _that_ work-folder is the repo
that gets released.** You cannot accidentally bump version numbers in
`AI-Prowler_V5_to_V6_work` while thinking you're releasing
`AI-Prowler_V601_to_V602_work` — the file's location is the truth.

On startup the script verifies the location *looks right* (has `.git`,
`rag_gui.py`, `AI-Prowler-Setup.iss`) and asks you to confirm the path before
doing anything destructive.

This means: **commit `release.bat` and `scripts/release.py` to the AI-Prowler
source repo itself, not the admin repo.** They travel with the code they
release.

## First time: introduce VERSION as the single source of truth

Pre-refactor, the version lives in three places:

  - `rag_gui.py` line 95: `APP_VERSION = "6.0.1"`
  - `AI-Prowler-Setup.iss` line 113: `AppVersion=6.0.1`
  - `COMPLETE_USER_GUIDE.md` line 3: `**Version 6.0.0**` (yes, currently
    out of sync — a 6.0.1 bug we're fixing during the refactor)

Run the one-shot refactor:

```cmd
release --refactor-only
```

This will:

  1. Create a `VERSION` file at the repo root containing the current version.
  2. Patch `rag_gui.py` so `APP_VERSION` reads from `VERSION` at import time.
  3. Patch `AI-Prowler-Setup.iss` so `AppVersion={#MyAppVersion}` and add a
     preprocessor `#define MyAppVersion Trim(ReadFileLine(SourcePath +
     "VERSION", 0))` near the top.

Diff-preview is shown before anything is written. Review and confirm.

## Normal release: bump from 6.0.1 to 6.0.2

```cmd
release 6.0.2
```

The script will:

  1. Verify repo location and current version.
  2. Pre-flight git: clean working tree? on `main`? tag `v6.0.2` not yet
     taken?
  3. Show a unified diff of every change it will make.
  4. Ask you to confirm.
  5. Write changes: `VERSION` becomes `6.0.2`, user guide banner updated,
     plus any leftover hardcoded values it can find (defensive — in case
     someone re-introduced one).
  6. Run `py -m pytest tests`. Abort on any failure.
  7. Compile `AI-Prowler-Setup.iss` with Inno Setup → produces
     `Output/AI-Prowler_INSTALL.exe`.
  8. Write `release-drafts/welcome_ad.json` and
     `release-drafts/notifications.json` for you to review and copy into the
     admin repo.
  9. Print a numbered checklist of the remaining manual steps (git commit,
     tag, push, GitHub release, subscription manager push, beta emails).

## Why the script does NOT auto-commit, auto-tag, or auto-push

Three reasons:

  - **Reversibility.** Bumping a file you can `git checkout --` away. Pushing
    a tag you cannot — `git push --delete origin v6.0.2` is a public "I made
    a mistake" signal, and the v6.0.1 retag from your prior notes shows
    that's a real risk to design against.
  - **Human-in-the-loop on text.** The release notes, welcome-ad bullets,
    and email copy are not mechanical. The script produces drafts; you write
    the prose. That's the right division of labor.
  - **Admin repo separation.** `welcome_ad.json` and `notifications.json`
    live in a *different repo* (`ai-prowler-public/`). Having the release
    script reach across repos to commit on your behalf is the kind of
    convenience that becomes a footgun. Drafts in `release-drafts/` keep the
    cross-repo step explicit.

## Inno Setup compiler location

The script looks for `ISCC.exe` in this order:

  1. `ISCC_EXE` environment variable (override)
  2. `C:\Program Files (x86)\Inno Setup 6\ISCC.exe`
  3. `C:\Program Files\Inno Setup 6\ISCC.exe`
  4. Anything named `ISCC` on `PATH`

If none are found, you get a clear "install Inno Setup" message and the
compile step is skipped — the rest of the release still completes.

## Flags

| Flag               | Effect                                                |
|--------------------|-------------------------------------------------------|
| `--check`          | Verify repo state, print current version, exit.        |
| `--refactor-only`  | First-time VERSION introduction. Does not bump.        |
| `--skip-tests`     | Skip pytest (hotfix iteration only — not recommended). |
| `--skip-compile`   | Bump only; don't build installer.                      |
| `-y` / `--yes`     | Auto-confirm all prompts (CI/scripted use).            |

## Files this tool touches

| File                          | What changes                          |
|-------------------------------|---------------------------------------|
| `VERSION`                     | New version string.                   |
| `rag_gui.py`                  | (refactor only) APP_VERSION reader.   |
| `AI-Prowler-Setup.iss`        | (refactor only) `#define MyAppVersion`. |
| `COMPLETE_USER_GUIDE.md`      | `**Version X.Y.Z**` banner.           |
| `release-drafts/*.json`       | Generated; review then copy to admin. |
| `Output/AI-Prowler_INSTALL.exe` | Built by Inno Setup.                |

## What the tool deliberately does NOT touch

  - Anything in the admin repo (`ai-prowler-public/`, `ai-prowler-subs/`).
    Drafts only.
  - Git history (no auto-commit, no auto-tag).
  - GitHub (no auto-release, no auto-upload).
  - Beta-tester emails.

## Gitignore additions you may want

```
release-drafts/
Output/
.release-config.json
```
