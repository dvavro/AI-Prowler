@echo off
setlocal EnableExtensions EnableDelayedExpansion
REM =====================================================================
REM  AI-Prowler - Pre-Upgrade Cleanup (chromadb 0.6.x -> 1.0.x migration)
REM ---------------------------------------------------------------------
REM  WHY THIS EXISTS:
REM    v7 upgrades chromadb from 0.6.3 to 1.0.12 (the Rust rewrite). That
REM    on-disk format change is IRREVERSIBLE, so the old database folder
REM    must be removed before the new version runs. The DB lives OUTSIDE
REM    Program Files (under the user profile), so a normal uninstall /
REM    reinstall does NOT clear it -- hence this script.
REM
REM  WHAT IT DOES (surgical, not scorched-earth):
REM    1. Backs up durable data to a timestamped folder.
REM    2. Deletes ONLY the stale Chroma store + the file-tracking index.
REM    3. Leaves learnings, license/subscription, config, and the
REM       tracked-paths list untouched.
REM
REM  NO admin rights required -- everything here is under %USERPROFILE%.
REM  CLOSE AI-Prowler before running, or the files will be locked.
REM =====================================================================

title AI-Prowler Pre-Upgrade Cleanup

set "CHROMA_DIR=%USERPROFILE%\AI-Prowler\rag_database"
set "TRACKING_DB=%USERPROFILE%\.rag_file_tracking.json"

for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "TS=%%i"
set "BACKUP=%USERPROFILE%\AI-Prowler-migration-backup-%TS%"

echo.
echo =====================================================================
echo   AI-Prowler Pre-Upgrade Cleanup
echo =====================================================================
echo.
echo   This will:
echo     - BACK UP your durable data to:
echo         %BACKUP%
echo     - DELETE the old ChromaDB store:
echo         %CHROMA_DIR%
echo     - DELETE the stale file-tracking index:
echo         %TRACKING_DB%
echo.
echo   It will NOT touch your learnings, license/subscription, config,
echo   or your tracked-folders list -- those are preserved and backed up.
echo.
echo   *** Make sure AI-Prowler is fully closed before continuing. ***
echo.
set "CONFIRM="
set /p "CONFIRM=Type  YES  to proceed (anything else cancels): "
if /i not "%CONFIRM%"=="YES" (
    echo.
    echo   Cancelled. Nothing was changed.
    echo.
    pause
    goto :eof
)

echo.
echo [1/3] Backing up durable data to %BACKUP% ...
mkdir "%BACKUP%" >nul 2>&1

if exist "%USERPROFILE%\.ai-prowler\" (
    robocopy "%USERPROFILE%\.ai-prowler" "%BACKUP%\.ai-prowler" /E /NFL /NDL /NJH /NJS /NP >nul
)

robocopy "%USERPROFILE%" "%BACKUP%\home-root" ^
    .rag_auto_update_dirs.json ^
    .rag_writable_dirs.json ^
    .rag_writable_pending.json ^
    .rag_config.json ^
    .rag_file_tracking.json ^
    /NFL /NDL /NJH /NJS /NP >nul

echo       Backup complete.

echo.
echo [2/3] Removing old ChromaDB store ...
if exist "%CHROMA_DIR%" (
    rd /s /q "%CHROMA_DIR%"
    if exist "%CHROMA_DIR%" (
        echo       WARNING: Could not fully delete %CHROMA_DIR%
        echo                Is AI-Prowler still running? Close it and re-run.
    ) else (
        echo       Removed.
    )
) else (
    echo       Not present - nothing to remove.
)

echo.
echo [3/3] Removing stale file-tracking index ...
if exist "%TRACKING_DB%" (
    del /q "%TRACKING_DB%"
    if exist "%TRACKING_DB%" (
        echo       WARNING: Could not delete %TRACKING_DB%
    ) else (
        echo       Removed.
    )
) else (
    echo       Not present - nothing to remove.
)

echo.
echo =====================================================================
echo   Cleanup done. You're ready to install / re-run the v7 installer.
echo.
echo   AFTER the new version is installed:
echo     Run AI-Prowler_PostUpgrade_Reindex.bat to rebuild the document
echo     and learning indexes from your preserved data.
echo.
echo   Your backup is at:
echo     %BACKUP%
echo =====================================================================
echo.
pause
endlocal
