@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM AI Prowler Uninstaller
REM Removes AI Prowler system and all components
REM ============================================================

echo.
echo ============================================================
echo AI PROWLER UNINSTALLER
echo ============================================================
echo.
echo This will remove:
echo   - AI Prowler program files
echo   - AI Prowler database (indexed documents)
echo   - AI Prowler configuration files
echo   - Desktop shortcut
echo   - Scheduled tasks
echo   - PATH entries
echo   - Ollama (~600 MB)
echo.
echo This will NOT remove (to protect other programs):
echo   - Python (other programs may need it)
echo   - Python packages (other programs may need them)
echo.

set /P "CONFIRM=Are you sure you want to uninstall AI Prowler? (yes/no): "

if /I not "%CONFIRM%"=="yes" (
    echo.
    echo Uninstall cancelled.
    echo.
    pause
    exit /b 0
)

echo.
echo ============================================================
echo UNINSTALLING AI PROWLER
echo ============================================================
echo.

REM ============================================================
REM STEP 1: Remove scheduled tasks
REM ============================================================

echo [Step 1/9] Removing scheduled tasks...

schtasks /query /tn "RAG Auto-Update" >nul 2>&1
if %errorlevel%==0 (
    schtasks /delete /tn "RAG Auto-Update" /f >nul 2>&1
    if %errorlevel%==0 (
        echo   [OK] Removed scheduled task: RAG Auto-Update
    ) else (
        echo   [SKIP] Could not remove scheduled task
    )
) else (
    echo   [SKIP] No scheduled task found
)

echo.

REM ============================================================
REM STEP 2: Remove desktop shortcut
REM ============================================================

echo [Step 2/9] Removing desktop shortcut...

set "SHORTCUT_FOUND=0"

REM Check for both possible shortcut names
if exist "%USERPROFILE%\Desktop\AI Prowler.lnk" (
    del /f /q "%USERPROFILE%\Desktop\AI Prowler.lnk" >nul 2>&1
    echo   [OK] Removed: AI Prowler.lnk
    set "SHORTCUT_FOUND=1"
)

if exist "%USERPROFILE%\Desktop\RAG.lnk" (
    del /f /q "%USERPROFILE%\Desktop\RAG.lnk" >nul 2>&1
    echo   [OK] Removed: RAG.lnk
    set "SHORTCUT_FOUND=1"
)

if "%SHORTCUT_FOUND%"=="0" (
    echo   [SKIP] No desktop shortcut found
)

echo.

REM ============================================================
REM STEP 3: Remove from PATH
REM ============================================================

echo [Step 3/9] Removing from Windows PATH...

REM Get installation directory
set "INSTALL_DIR=%~dp0"
set "INSTALL_DIR=%INSTALL_DIR:~0,-1%"

REM Use PowerShell entirely - avoids hang caused by piping long PATH strings through echo/find
powershell -NoProfile -Command ^
  "$installDir = '%INSTALL_DIR%';" ^
  "$path = [Environment]::GetEnvironmentVariable('Path', 'User');" ^
  "if ($path -and $path -like ('*' + $installDir + '*')) {" ^
  "  $newPath = ($path.Split(';') | Where-Object { $_ -ne $installDir }) -join ';';" ^
  "  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User');" ^
  "  Write-Host '  [OK] Removed from PATH';" ^
  "} else {" ^
  "  Write-Host '  [SKIP] Not in PATH';" ^
  "}" >nul 2>&1

if %errorlevel%==0 (
    echo   [OK] PATH step completed
) else (
    echo   [SKIP] Could not update PATH (not critical)
)

echo.

REM ============================================================
REM STEP 4: Remove configuration files
REM ============================================================

echo [Step 4/9] Removing configuration files...

set "CONFIG_REMOVED=0"

if exist "%USERPROFILE%\.rag_config.json" (
    del /f /q "%USERPROFILE%\.rag_config.json" >nul 2>&1
    echo   [OK] Removed: .rag_config.json
    set "CONFIG_REMOVED=1"
)

if exist "%USERPROFILE%\.rag_auto_update_dirs.json" (
    del /f /q "%USERPROFILE%\.rag_auto_update_dirs.json" >nul 2>&1
    echo   [OK] Removed: .rag_auto_update_dirs.json
    set "CONFIG_REMOVED=1"
)

if exist "%USERPROFILE%\.rag_file_tracking.json" (
    del /f /q "%USERPROFILE%\.rag_file_tracking.json" >nul 2>&1
    echo   [OK] Removed: .rag_file_tracking.json
    set "CONFIG_REMOVED=1"
)

if exist "%USERPROFILE%\.rag_license.key" (
    del /f /q "%USERPROFILE%\.rag_license.key" >nul 2>&1
    echo   [OK] Removed: .rag_license.key
    set "CONFIG_REMOVED=1"
)

if exist "%USERPROFILE%\rag_auto_update.bat" (
    del /f /q "%USERPROFILE%\rag_auto_update.bat" >nul 2>&1
    echo   [OK] Removed: rag_auto_update.bat
    set "CONFIG_REMOVED=1"
)

if exist "%USERPROFILE%\rag_auto_update.sh" (
    del /f /q "%USERPROFILE%\rag_auto_update.sh" >nul 2>&1
    echo   [OK] Removed: rag_auto_update.sh
    set "CONFIG_REMOVED=1"
)

if "%CONFIG_REMOVED%"=="0" (
    echo   [SKIP] No configuration files found
)

echo.

REM ============================================================
REM STEP 5: Remove database
REM ============================================================

echo [Step 5/9] Removing database...

if exist "%INSTALL_DIR%\rag_database" (
    echo.
    echo   WARNING: This will delete all your indexed documents!
    echo   Database location: %INSTALL_DIR%\rag_database
    echo.
    set /P "DELETE_DB=Delete database? (yes/no): "
    
    if /I "!DELETE_DB!"=="yes" (
        rmdir /s /q "%INSTALL_DIR%\rag_database" >nul 2>&1
        if %errorlevel%==0 (
            echo   [OK] Database removed
        ) else (
            echo   [ERROR] Could not remove database
        )
    ) else (
        echo   [SKIP] Database kept
    )
) else (
    echo   [SKIP] No database found
)

echo.

REM ============================================================
REM STEP 6: Remove program files
REM ============================================================

echo [Step 6/9] Removing program files...

set "FILES_REMOVED=0"

REM Python files
if exist "%INSTALL_DIR%\rag_preprocessor.py" (
    del /f /q "%INSTALL_DIR%\rag_preprocessor.py" >nul 2>&1
    echo   [OK] Removed: rag_preprocessor.py
    set "FILES_REMOVED=1"
)

if exist "%INSTALL_DIR%\rag_gui.py" (
    del /f /q "%INSTALL_DIR%\rag_gui.py" >nul 2>&1
    echo   [OK] Removed: rag_gui.py
    set "FILES_REMOVED=1"
)

if exist "%INSTALL_DIR%\rag_launcher.py" (
    del /f /q "%INSTALL_DIR%\rag_launcher.py" >nul 2>&1
    echo   [OK] Removed: rag_launcher.py
    set "FILES_REMOVED=1"
)

if exist "%INSTALL_DIR%\create_shortcut.py" (
    del /f /q "%INSTALL_DIR%\create_shortcut.py" >nul 2>&1
    echo   [OK] Removed: create_shortcut.py
    set "FILES_REMOVED=1"
)

if exist "%INSTALL_DIR%\generate_license.py" (
    del /f /q "%INSTALL_DIR%\generate_license.py" >nul 2>&1
    echo   [OK] Removed: generate_license.py
    set "FILES_REMOVED=1"
)

REM Batch files
if exist "%INSTALL_DIR%\RAG_RUN.bat" (
    del /f /q "%INSTALL_DIR%\RAG_RUN.bat" >nul 2>&1
    echo   [OK] Removed: RAG_RUN.bat
    set "FILES_REMOVED=1"
)

REM Icon files
if exist "%INSTALL_DIR%\rag_icon.svg" (
    del /f /q "%INSTALL_DIR%\rag_icon.svg" >nul 2>&1
    echo   [OK] Removed: rag_icon.svg
    set "FILES_REMOVED=1"
)

if exist "%INSTALL_DIR%\rag_icon.ico" (
    del /f /q "%INSTALL_DIR%\rag_icon.ico" >nul 2>&1
    echo   [OK] Removed: rag_icon.ico
    set "FILES_REMOVED=1"
)

REM Documentation files
if exist "%INSTALL_DIR%\COMPLETE_USER_GUIDE.md" (
    del /f /q "%INSTALL_DIR%\COMPLETE_USER_GUIDE.md" >nul 2>&1
    echo   [OK] Removed: COMPLETE_USER_GUIDE.md
    set "FILES_REMOVED=1"
)

if exist "%INSTALL_DIR%\README.md" (
    del /f /q "%INSTALL_DIR%\README.md" >nul 2>&1
    echo   [OK] Removed: README.md
    set "FILES_REMOVED=1"
)

REM Requirements file
if exist "%INSTALL_DIR%\requirements.txt" (
    del /f /q "%INSTALL_DIR%\requirements.txt" >nul 2>&1
    echo   [OK] Removed: requirements.txt
    set "FILES_REMOVED=1"
)

REM Keep INSTALL.bat and UNINSTALL.bat for reference

if "%FILES_REMOVED%"=="0" (
    echo   [SKIP] No program files found
)

echo.

REM ============================================================
REM STEP 7: Remove Ollama
REM ============================================================

echo [Step 7/9] Removing Ollama...

REM Check if Ollama is installed
where ollama >nul 2>&1
if %errorlevel%==0 (
    echo.
    echo Removing Ollama (~600 MB)...
    
    REM Stop Ollama service
    taskkill /F /IM ollama.exe >nul 2>&1
    timeout /t 2 >nul
    
    REM Try using winget (Windows 11/10)
    winget uninstall Ollama.Ollama --silent >nul 2>&1
    
    if errorlevel 1 (
        REM Fallback: Try using standard uninstaller
        if exist "C:\Program Files\Ollama\uninstall.exe" (
            "C:\Program Files\Ollama\uninstall.exe" /S >nul 2>&1
            timeout /t 3 >nul
        )
        
        REM Remove Ollama directory if still exists
        if exist "C:\Program Files\Ollama" (
            rmdir /s /q "C:\Program Files\Ollama" >nul 2>&1
        )
        
        REM Remove Ollama user data
        if exist "%USERPROFILE%\.ollama" (
            rmdir /s /q "%USERPROFILE%\.ollama" >nul 2>&1
        )
        
        REM Remove from PATH
        powershell -Command "$path = [Environment]::GetEnvironmentVariable('Path', 'Machine'); if ($path) { $newPath = ($path.Split(';') | Where-Object { $_ -notlike '*Ollama*' }) -join ';'; [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine') }" >nul 2>&1
        powershell -Command "$path = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($path) { $newPath = ($path.Split(';') | Where-Object { $_ -notlike '*Ollama*' }) -join ';'; [Environment]::SetEnvironmentVariable('Path', $newPath, 'User') }" >nul 2>&1
    )
    
    REM Verify removal
    where ollama >nul 2>&1
    if errorlevel 1 (
        echo   [OK] Ollama removed (~600 MB freed)
    ) else (
        echo   [WARN] Ollama may not be completely removed
        echo          You can manually uninstall via Settings → Apps → Ollama
    )
) else (
    echo   [SKIP] Ollama not installed
)

echo.

REM ============================================================
REM STEP 8: Remove Whisper speech model cache
REM ============================================================

echo [Step 8/9] Removing Whisper speech model cache...
echo.

REM Target ONLY the faster-whisper large-v3-turbo model directory.
REM Deleting the entire huggingface\hub folder would silently wipe caches
REM used by other tools (LM Studio, Transformers, etc.).
set "WHISPER_MODEL_DIR=%USERPROFILE%\.cache\huggingface\hub\models--Systran--faster-whisper-large-v3-turbo"
set "WHISPER_CACHE_FALLBACK=%USERPROFILE%\.cache\huggingface\hub"

if exist "%WHISPER_MODEL_DIR%" (
    rmdir /s /q "%WHISPER_MODEL_DIR%" >nul 2>&1
    if not exist "%WHISPER_MODEL_DIR%" (
        echo   [OK] Whisper large-v3-turbo model removed (~1.6 GB freed)
    ) else (
        echo   [WARN] Could not fully remove model - delete manually:
        echo          %WHISPER_MODEL_DIR%
    )
) else (
    echo   [SKIP] No Whisper model cache found
    echo          (checked: %WHISPER_MODEL_DIR%)
)

echo.

REM ============================================================
REM STEP 9: Summary
REM ============================================================

echo [Step 9/9] Uninstall summary...
echo.

echo ============================================================
echo UNINSTALL COMPLETE
echo ============================================================
echo.
echo What was removed:
echo   ✓ AI Prowler program files (.py, .bat, .md, .svg, .ico)
echo   ✓ Configuration files (.json, .key)
echo   ✓ Desktop shortcut
echo   ✓ Scheduled tasks
echo   ✓ PATH entries
echo   ✓ Auto-update scripts
echo   ✓ Ollama (~600 MB freed)
echo   ✓ Whisper model cache (~1.6 GB freed)
echo.
echo What was kept (safe for other programs):
echo   ✓ Python (other programs may need it)
echo   ✓ Python packages including faster-whisper (other programs may need them)
echo   ✓ INSTALL.bat (in case you want to reinstall)
echo   ✓ UNINSTALL.bat (this file)
echo.
echo Remaining files in this folder:
echo   %INSTALL_DIR%
echo.
echo You can now:
echo   1. Delete this entire folder (if you're done)
echo   2. Keep INSTALL.bat to reinstall later
echo.
echo To remove Python (only if no other programs need it):
echo   Settings → Apps → Uninstall "Python 3.11.8"
echo   WARNING: This may break other programs!
echo.
echo ============================================================
echo.

pause
