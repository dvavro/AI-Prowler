@echo off
:: ============================================================
:: AI-Prowler — Keep It Running Setup
:: Configures Windows power settings so AI-Prowler stays online
:: when plugged in. Run once as Administrator.
:: ============================================================

echo.
echo ============================================================
echo  AI-Prowler Power Settings Setup
echo  Configuring Windows to never sleep when plugged in...
echo ============================================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo Right-click the file and choose "Run as administrator"
    pause
    exit /b 1
)

:: ── Step 1: Never sleep when plugged in ─────────────────────
echo [1/5] Setting plugged-in sleep to Never...
powercfg /change standby-timeout-ac 0
if %errorlevel% equ 0 (echo       OK) else (echo       FAILED)

echo [2/5] Setting plugged-in screen off to Never...
powercfg /change monitor-timeout-ac 0
if %errorlevel% equ 0 (echo       OK) else (echo       FAILED)

echo [3/5] Setting plugged-in hibernate timeout to Never...
powercfg /change hibernate-timeout-ac 0
if %errorlevel% equ 0 (echo       OK) else (echo       FAILED)

:: ── Step 2: Disable hibernate entirely ──────────────────────
echo [4/5] Disabling hibernate (powercfg /h off)...
powercfg /h off
if %errorlevel% equ 0 (echo       OK) else (echo       FAILED)

:: ── Lid close action: do nothing when plugged in ────────────
:: GUID 5ca83367-6e45-459f-a27b-476b1d01c936 = Lid close action
:: Value 0 = Do Nothing, 1 = Sleep, 2 = Hibernate, 3 = Shut down
echo [5/5] Setting lid close action to Do Nothing (plugged in)...
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
powercfg /SetActive SCHEME_CURRENT
if %errorlevel% equ 0 (echo       OK) else (echo       FAILED)

:: ── Step 3: Windows Update Active Hours via registry ─────────
:: Active hours: 6 AM (6) to 11 PM (23)
echo.
echo [+] Setting Windows Update Active Hours (6AM - 11PM)...
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v ActiveHoursStart /t REG_DWORD /d 6 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v ActiveHoursEnd   /t REG_DWORD /d 23 /f >nul 2>&1
if %errorlevel% equ 0 (echo       OK) else (echo       FAILED)

echo [+] Turning off auto-restart for updates...
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsExpedited /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f >nul 2>&1
if %errorlevel% equ 0 (echo       OK) else (echo       FAILED)

echo.
echo ============================================================
echo  Done! AI-Prowler will now stay online when plugged in.
echo.
echo  Summary of changes:
echo    Sleep (plugged in)      -- Never
echo    Screen off (plugged in) -- Never
echo    Hibernate               -- Disabled
echo    Lid close (plugged in)  -- Do Nothing
echo    Windows Update hours    -- 6:00 AM to 11:00 PM
echo    Auto-restart for updates-- Off
echo ============================================================
echo.
pause
