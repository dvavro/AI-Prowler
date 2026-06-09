# =============================================================================
# Test-SeedUserGuideTracking.ps1
#
# Standalone test harness for the SeedUserGuideTracking installer procedure.
# Runs both scenarios without touching any real AI-Prowler files.
#
# Called by tests/installer/test_installer_scripts.py via subprocess so it
# runs as part of the main pytest suite and release_gate.bat Suite 1.
#
# Can also be run directly for manual debugging:
#   powershell -NoProfile -ExecutionPolicy Bypass -File Test-SeedUserGuideTracking.ps1
#
# What it tests:
#   Scenario A  - Fresh install: no .rag_auto_update_dirs.json exists yet.
#                 Seed script should CREATE the file with the guide as first entry.
#
#   Scenario B  - Reinstall / keep database: file already exists with user's
#                 tracked directories. Seed script should MERGE the guide in
#                 and preserve all existing entries intact.
#
#   Scenario C  - Re-run idempotency: guide path is already in the list.
#                 Seed script should make NO change and report "already tracked".
#
#   Scenario D  - Corrupted / empty JSON: file exists but contains garbage.
#                 Seed script should not crash and should report a warning.
#
#   Scenario E  - Guide already tracked but stored with backslashes (legacy format).
#                 Contains() check uses forward slashes - should not add a duplicate.
# =============================================================================

$ErrorActionPreference = "Stop"
$PassCount = 0
$FailCount = 0
$Results   = @()

# -- Helpers ------------------------------------------------------------------

function Write-Header($text) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Pass($scenario, $message) {
    Write-Host "  [PASS] $message" -ForegroundColor Green
    $script:PassCount++
    $script:Results += [pscustomobject]@{ Scenario=$scenario; Result="PASS"; Detail=$message }
}

function Fail($scenario, $message) {
    Write-Host "  [FAIL] $message" -ForegroundColor Red
    $script:FailCount++
    $script:Results += [pscustomobject]@{ Scenario=$scenario; Result="FAIL"; Detail=$message }
}

# Exact PowerShell logic extracted from SeedUserGuideTracking in AI-Prowler-Setup.iss.
# $TrackFile and $GuideDest are injected by the caller (simulating Inno's ExpandConstant).
function Invoke-SeedScript($TrackFile, $GuideDest) {
    $output = ""
    try {
        $guidePath = $GuideDest.Replace("\", "/")

        if (Test-Path $TrackFile) {
            $obj  = Get-Content $TrackFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $dirs       = [System.Collections.Generic.List[string]]::new()
            $dirsNormed = [System.Collections.Generic.List[string]]::new()
            if ($obj.directories) { foreach ($d in $obj.directories) { $dirs.Add($d); $dirsNormed.Add($d.Replace("\", "/")) } }
            if ($dirsNormed.Contains($guidePath)) {
                $output = "User guide already tracked - no change needed."
            } else {
                $dirs.Add($guidePath)
                [pscustomobject]@{ directories = $dirs.ToArray() } |
                    ConvertTo-Json -Compress | Set-Content $TrackFile -Encoding UTF8
                $output = "User guide added to tracking list."
            }
        } else {
            @{ directories = @($guidePath) } |
                ConvertTo-Json -Compress | Set-Content $TrackFile -Encoding UTF8
            $output = "Tracking file created with user guide as first entry."
        }
    } catch {
        $output = "WARNING: Could not seed user guide tracking: $_"
    }
    return $output
}

# -- Test working directory ---------------------------------------------------

$TempDir  = Join-Path $env:TEMP "SeedGuideTest_$(Get-Random)"
New-Item -ItemType Directory -Path $TempDir | Out-Null

$FakeGuide    = "C:/Users/testuser/OneDrive/Documents/AI-Prowler/COMPLETE_USER_GUIDE.md"
$FakeGuideBS  = $FakeGuide.Replace("/", "\")   # backslash version for comparison
$TrackFile    = Join-Path $TempDir ".rag_auto_update_dirs.json"

# Simulated pre-existing user directories (as AI-Prowler writes them - backslashes)
$ExistingDirs = @(
    "C:\Users\testuser\Projects\MyWebApp",
    "C:\Users\testuser\Documents\WorkDocs",
    "C:\Users\testuser\OneDrive\Business"
)

# =============================================================================
Write-Header "Scenario A - Fresh install (no tracking file exists)"
# =============================================================================

if (Test-Path $TrackFile) { Remove-Item $TrackFile }

$out = Invoke-SeedScript -TrackFile $TrackFile -GuideDest $FakeGuideBS

Write-Host "  Script output: $out"

if (Test-Path $TrackFile) {
    Pass "A" "Tracking file was created"
} else {
    Fail "A" "Tracking file was NOT created"
}

$json = Get-Content $TrackFile -Raw | ConvertFrom-Json
if ($json.directories -contains $FakeGuide) {
    Pass "A" "Guide path present in new file (forward slashes)"
} else {
    Fail "A" "Guide path MISSING from new file. Contents: $($json.directories)"
}

if ($json.directories.Count -eq 1) {
    Pass "A" "Exactly 1 entry in fresh file"
} else {
    Fail "A" "Expected 1 entry, got $($json.directories.Count)"
}

if ($out -eq "Tracking file created with user guide as first entry.") {
    Pass "A" "Correct stdout message for fresh install"
} else {
    Fail "A" "Wrong stdout message: '$out'"
}

# =============================================================================
Write-Header "Scenario B - Reinstall with existing tracked directories (keep database)"
# =============================================================================

$preExisting = [pscustomobject]@{
    directories  = $ExistingDirs
    last_updated = "2026-06-08T09:00:00.000000"
}
$preExisting | ConvertTo-Json | Set-Content $TrackFile -Encoding UTF8

$out = Invoke-SeedScript -TrackFile $TrackFile -GuideDest $FakeGuideBS

Write-Host "  Script output: $out"

$json = Get-Content $TrackFile -Raw | ConvertFrom-Json

$allPreserved = $true
foreach ($dir in $ExistingDirs) {
    if ($json.directories -notcontains $dir) {
        Fail "B" "Existing dir was LOST: $dir"
        $allPreserved = $false
    }
}
if ($allPreserved) {
    Pass "B" "All $($ExistingDirs.Count) pre-existing directories preserved"
}

if ($json.directories -contains $FakeGuide) {
    Pass "B" "Guide path added alongside existing entries"
} else {
    Fail "B" "Guide path MISSING after merge. Entries: $($json.directories -join ', ')"
}

$expectedCount = $ExistingDirs.Count + 1
if ($json.directories.Count -eq $expectedCount) {
    Pass "B" "Total entry count correct ($expectedCount)"
} else {
    Fail "B" "Expected $expectedCount entries, got $($json.directories.Count)"
}

if ($out -eq "User guide added to tracking list.") {
    Pass "B" "Correct stdout message for reinstall-merge"
} else {
    Fail "B" "Wrong stdout message: '$out'"
}

# =============================================================================
Write-Header "Scenario C - Re-run idempotency (guide already in list)"
# =============================================================================

$out = Invoke-SeedScript -TrackFile $TrackFile -GuideDest $FakeGuideBS

Write-Host "  Script output: $out"

$jsonBefore = $json
$jsonAfter  = Get-Content $TrackFile -Raw | ConvertFrom-Json

if ($jsonAfter.directories.Count -eq $jsonBefore.directories.Count) {
    Pass "C" "Entry count unchanged on re-run ($($jsonAfter.directories.Count))"
} else {
    Fail "C" "Entry count changed: was $($jsonBefore.directories.Count), now $($jsonAfter.directories.Count)"
}

if ($out -eq "User guide already tracked - no change needed.") {
    Pass "C" "Correct stdout message for idempotent re-run"
} else {
    Fail "C" "Wrong stdout message: '$out'"
}

# =============================================================================
Write-Header "Scenario D - Corrupted tracking file (should not crash)"
# =============================================================================

"{ this is not valid json !!!" | Set-Content $TrackFile -Encoding UTF8

$out = Invoke-SeedScript -TrackFile $TrackFile -GuideDest $FakeGuideBS

Write-Host "  Script output: $out"

Pass "D" "Script did not crash on corrupt JSON"

if ($out -like "WARNING:*") {
    Pass "D" "Correct WARNING message returned for corrupt file"
} else {
    Fail "D" "Expected WARNING message, got: '$out'"
}

# =============================================================================
Write-Header "Scenario E - Guide already tracked but stored with backslashes (legacy format)"
# =============================================================================

$legacyDirs = @($ExistingDirs[0], $FakeGuideBS)
$legacy = [pscustomobject]@{ directories = $legacyDirs }
$legacy | ConvertTo-Json -Compress | Set-Content $TrackFile -Encoding UTF8

$out = Invoke-SeedScript -TrackFile $TrackFile -GuideDest $FakeGuideBS

Write-Host "  Script output: $out"

$json = Get-Content $TrackFile -Raw | ConvertFrom-Json

$guideCount = ($json.directories | Where-Object { $_ -replace "\\","/" -eq $FakeGuide }).Count

if ($guideCount -gt 1) {
    Fail "E" "BUG: Guide path duplicated ($guideCount entries) - backslash normalisation not working. Entries: $($json.directories -join ' | ')"
} else {
    Pass "E" "Backslash-stored guide path correctly detected as duplicate - no extra entry added"
}

# =============================================================================
Write-Header "TEST SUMMARY"
# =============================================================================

Write-Host ""
$Results | Format-Table -AutoSize
Write-Host ""
Write-Host "  Passed: $PassCount" -ForegroundColor Green
Write-Host "  Failed: $FailCount" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "Green" })
Write-Host ""

Remove-Item $TempDir -Recurse -Force

if ($FailCount -gt 0) {
    Write-Host "  *** FAILURES DETECTED - review output above ***" -ForegroundColor Red
    exit 1
} else {
    Write-Host "  All tests passed." -ForegroundColor Green
    exit 0
}
