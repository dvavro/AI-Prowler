@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  AI-Prowler — sync dev changes into the real install
REM ============================================================
REM  Copies every product source file this work directory has (Python
REM  modules + the Jobs/Remote PWA files) into the real install at
REM  C:\Program Files\AI-Prowler, so testing runs against the ACTUAL
REM  installed app instead of the dev copy sitting untouched. Also copies
REM  COMPLETE_USER_GUIDE.md to both the install dir (Help -> User Guide)
REM  and Documents\AI-Prowler (the indexed, searchable copy).
REM
REM  Every file that would be overwritten is backed up first into a
REM  fresh timestamped folder under the install dir (matching the
REM  _pre_*_backup_<timestamp> pattern already used by earlier deploys).
REM
REM  USAGE
REM    update_install.bat        (asks to confirm before copying)
REM    update_install.bat /y     (skips the confirmation — for quick
REM                                iteration while stepping through tests)
REM
REM  IMPORTANT
REM    - Run this AS ADMINISTRATOR — "Program Files" is a protected
REM      directory; a non-elevated copy silently fails or prompts.
REM    - RESTART AI-Prowler after this finishes if any .py file changed
REM      -- Python does not hot-reload; the running process keeps using
REM      old code in memory until restarted. Restarting drops the
REM      current Claude MCP connection to AI-Prowler Local, so do this
REM      at a natural pause, not mid-tool-call.
REM    - Database SCHEMA fixes to an already-existing .db file (like
REM      generated-column formula fixes) are applied directly to the
REM      .db file, separately from this script, and take effect
REM      immediately without a restart — this script only syncs SOURCE
REM      CODE so the fix is baked in for the next fresh apply_schema()
REM      run (new installs, or a full schema rebuild).
REM ============================================================

set "WORK=C:\Users\david\AI-Prowler-V910_to_V920_work\AI-Prowler"
set "INSTALL=C:\Program Files\AI-Prowler"
set "STAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "STAMP=%STAMP: =0%"
set "BACKUP=%INSTALL%\_pre_sync_backup_%STAMP%"

echo.
echo ============================================================
echo  AI-Prowler install sync
echo  Work dir:    %WORK%
echo  Install dir: %INSTALL%
echo  Backup dir:  %BACKUP%
echo ============================================================
echo.

REM ── Elevation check ──────────────────────────────────────────
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo [!] This does not appear to be an elevated ^(Administrator^) shell.
    echo     Copies into "%INSTALL%" will likely fail. Right-click this
    echo     file and choose "Run as administrator", then try again.
    echo.
    pause
    goto :end
)

REM ── Confirm before touching a real install (skip with /y) ────
if /i "%~1"=="/y" goto :confirmed
set /p CONFIRM="Copy files into the real install now? [y/N] "
if /i not "%CONFIRM%"=="y" (
    echo Cancelled — nothing was copied.
    goto :end
)
:confirmed

REM (2026-10-03: the "Patch MCP Tool Config handlers" step that ran
REM  deploy_tool_config_fix.py was removed. rag_gui.py now uses
REM  tool_config_store.py for Save/Reset itself, so the patch had nothing left
REM  to do — and a deploy script that rewrites source files can silently undo
REM  later changes. tool_config_store.py is still copied below.)


REM ── Top-level product Python modules ─────────────────────────
set FILES=ai_prowler_mcp.py cli_signin_relay.py cloudflared_service_helper.py console_inject.py create_shortcut.py custom_tasks_manager.py db_access.py db_backup_ops.py db_export_ops.py db_read_ops.py db_route_ops.py db_schema.py db_write_ops.py file_watchdog.py mcp_diagnostics.py mcp_tool_catalog.py mobile_activator.py rag_gui.py rag_preprocessor.py scheduler_engine.py scheduler_jobs.py scope_lookup.py scope_resolver.py self_learning.py setup_wizard.py sms_backends.py sms_consent.py sms_inbox.py startup_log.py subscription_client.py task_queue_automation.py tool_config_store.py

REM ── Jobs PWA + Remote PWA files (relative to jobs\ / remote\) ─
set JOBS_FILES=index.html manifest.json sw.js icon.png icon-192.png icon-512.png
set REMOTE_FILES=index.html manifest.json sw.js icon-192.png icon-512.png

echo.
echo Backing up + copying top-level modules...
mkdir "%BACKUP%" >nul 2>&1
set CHANGED=0
set COPIED=0

for %%F in (%FILES%) do (
    if exist "%WORK%\%%F" (
        if exist "%INSTALL%\%%F" (
            copy /Y "%INSTALL%\%%F" "%BACKUP%\%%F" >nul
        )
        copy /Y "%WORK%\%%F" "%INSTALL%\%%F" >nul
        if !errorlevel!==0 (
            echo   [ok] %%F
            set /a COPIED+=1
        ) else (
            echo   [FAILED] %%F
        )
    )
)

echo.
echo Backing up + copying Jobs PWA files...
mkdir "%BACKUP%\jobs" >nul 2>&1
if not exist "%INSTALL%\jobs" mkdir "%INSTALL%\jobs" >nul 2>&1
for %%F in (%JOBS_FILES%) do (
    if exist "%WORK%\jobs\%%F" (
        if exist "%INSTALL%\jobs\%%F" (
            copy /Y "%INSTALL%\jobs\%%F" "%BACKUP%\jobs\%%F" >nul
        )
        copy /Y "%WORK%\jobs\%%F" "%INSTALL%\jobs\%%F" >nul
        if !errorlevel!==0 (
            echo   [ok] jobs\%%F
            set /a COPIED+=1
        ) else (
            echo   [FAILED] jobs\%%F
        )
    )
)

echo.
echo Backing up + copying Remote PWA files...
mkdir "%BACKUP%\remote" >nul 2>&1
if not exist "%INSTALL%\remote" mkdir "%INSTALL%\remote" >nul 2>&1
for %%F in (%REMOTE_FILES%) do (
    if exist "%WORK%\remote\%%F" (
        if exist "%INSTALL%\remote\%%F" (
            copy /Y "%INSTALL%\remote\%%F" "%BACKUP%\remote\%%F" >nul
        )
        copy /Y "%WORK%\remote\%%F" "%INSTALL%\remote\%%F" >nul
        if !errorlevel!==0 (
            echo   [ok] remote\%%F
            set /a COPIED+=1
        ) else (
            echo   [FAILED] remote\%%F
        )
    )
)

echo.
echo Backing up + copying user guide...
REM COMPLETE_USER_GUIDE.md lives in TWO deployed places:
REM   - %INSTALL%  : what Help -> User Guide opens (the app reads it
REM                  from its install/working folder)
REM   - Documents\AI-Prowler : the tracked, indexed copy Claude finds via
REM                  AI-Prowler search (the file watcher re-indexes it
REM                  automatically when it changes)
set "GUIDE=COMPLETE_USER_GUIDE.md"
set "DOCS=%USERPROFILE%\Documents\AI-Prowler"
if exist "%WORK%\%GUIDE%" (
    if exist "%INSTALL%\%GUIDE%" copy /Y "%INSTALL%\%GUIDE%" "%BACKUP%\%GUIDE%" >nul
    copy /Y "%WORK%\%GUIDE%" "%INSTALL%\%GUIDE%" >nul
    if !errorlevel!==0 (
        echo   [ok] %GUIDE%  -^> install
        set /a COPIED+=1
    ) else (
        echo   [FAILED] %GUIDE%  -^> install
    )

    mkdir "%BACKUP%\Documents_AI-Prowler" >nul 2>&1
    if not exist "%DOCS%" mkdir "%DOCS%" >nul 2>&1
    if exist "%DOCS%\%GUIDE%" copy /Y "%DOCS%\%GUIDE%" "%BACKUP%\Documents_AI-Prowler\%GUIDE%" >nul
    copy /Y "%WORK%\%GUIDE%" "%DOCS%\%GUIDE%" >nul
    if !errorlevel!==0 (
        echo   [ok] %GUIDE%  -^> Documents\AI-Prowler
        set /a COPIED+=1
    ) else (
        echo   [FAILED] %GUIDE%  -^> Documents\AI-Prowler
    )
) else (
    echo   [skip] %GUIDE% not found in work dir
)

echo.
echo ============================================================
echo  Done. %COPIED% file(s) copied.
echo  Backup of every overwritten file: %BACKUP%
echo.
echo  NEXT STEP: restart AI-Prowler now if any .py file above
echo  actually changed since the last sync — close and reopen the
echo  app (or restart its service/process). This will drop the
echo  current Claude <-^> AI-Prowler Local MCP connection; reconnect
echo  after it's back up.
echo.
echo  Rollback: copy everything from
echo    %BACKUP%
echo  back over %INSTALL% (except the Documents_AI-Prowler subfolder,
echo  whose guide goes back to %DOCS%), then restart.
echo ============================================================
echo.

:end
pause
endlocal
