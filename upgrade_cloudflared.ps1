<#
upgrade_cloudflared.ps1  (v9.5.0)
=================================
Brings cloudflared.exe up to at least -MinVersion.

Why: Cloudflare advisory, Oct 2026 - cloudflared before 2026.10.2 still
trusts eight compromised eMudhra intermediate certificates, so anyone in
the network path could impersonate Cloudflare to the tunnel.

Used by BOTH:
  * AI-Prowler-Setup.iss (ssDone step, already elevated), and
  * cloudflared_upgrade.py (in-app "Update now" prompt, elevated via one
    UAC approval) - so existing users fixed by the in-app updater get the
    same code path as fresh installs.

Steps:
  1. Read the installed version. Already >= MinVersion -> nothing to do.
  2. Download the latest Windows release to a temp file.
  3. Verify: Authenticode status Valid, signer CN "Cloudflare, Inc.",
     and version >= MinVersion. Any failure -> abort, nothing touched.
  4. Stop the cloudflared service ONLY if its ImagePath is this exe.
  5. Rename the old exe to cloudflared.exe.old (renaming works even when a
     manual "Start Tunnel" process still has it open) and copy the new one in.
  6. Restart the service if it was running; if it will not come back,
     roll back to the old exe and restart that.

The service keeps its existing token/config - nothing is reinstalled.
Writes a one-line JSON result to -ResultFile (status ok|upgraded|failed).
ASCII only on purpose: Windows PowerShell 5.1 reads BOM-less files as ANSI.
#>
param(
    [Parameter(Mandatory = $true)][string]$Dest,
    [string]$MinVersion  = "2026.10.2",
    [string]$ResultFile  = "",
    [string]$LogFile     = "",
    [string]$ServiceName = "cloudflared",
    [string]$DownloadUrl = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe",
    [string]$ExpectedSigner = 'CN="Cloudflare, Inc."'
)

$ErrorActionPreference = "Stop"

function Write-Log([string]$msg) {
    $line = "{0}  [cloudflared-upgrade] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Write-Host $line
    if ($LogFile) {
        try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Write-Result([string]$status, [string]$oldV, [string]$newV, [string]$message) {
    Write-Log ("RESULT {0}: {1}" -f $status, $message)
    if ($ResultFile) {
        $obj = [ordered]@{
            status      = $status
            old_version = $oldV
            new_version = $newV
            min_version = $MinVersion
            message     = $message
            finished    = (Get-Date -Format "s")
        }
        try {
            ($obj | ConvertTo-Json -Compress) | Set-Content -Path $ResultFile -Encoding ASCII
        } catch {
            Write-Log "could not write result file: $_"
        }
    }
}

function Get-CfVersion([string]$exe) {
    if (-not (Test-Path -LiteralPath $exe)) { return $null }
    try {
        $out = & $exe --version 2>&1 | Out-String
        $m = [regex]::Match($out, 'version\s+(\d+\.\d+\.\d+)')
        if ($m.Success) { return $m.Groups[1].Value }
    } catch { }
    return $null
}

function Test-AtLeast([string]$have, [string]$want) {
    if (-not $have) { return $false }
    try { return ([version]$have) -ge ([version]$want) } catch { return $false }
}

function Get-OurService {
    # Return the service object only if it runs THIS exe - never touch a
    # cloudflared service some other tool installed elsewhere.
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return $null }
    try {
        $img = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -ErrorAction Stop).ImagePath
    } catch { return $null }
    if ($img -and $img.ToLower().Contains($Dest.ToLower())) { return $svc }
    # ImagePath carries the tunnel token ("tunnel run --token ...") - never log it.
    $imgSafe = [regex]::Replace("$img", '(--token\s+)\S+', '$1<redacted>')
    Write-Log "service '$ServiceName' runs a different exe ($imgSafe) - leaving it alone"
    return $null
}

function Wait-SvcStatus($name, [string]$status, [int]$secs) {
    for ($i = 0; $i -lt $secs; $i++) {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($s -and $s.Status.ToString() -eq $status) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

$oldVersion = ""
$tmp = $null
try {
    Write-Log "=== start  dest=$Dest  min=$MinVersion ==="

    # 1. Current version
    $oldVersion = Get-CfVersion $Dest
    if ($oldVersion) { Write-Log "installed version: $oldVersion" } else { Write-Log "no usable cloudflared.exe at destination" }
    if (Test-AtLeast $oldVersion $MinVersion) {
        Write-Result "ok" $oldVersion $oldVersion "cloudflared $oldVersion already meets minimum $MinVersion"
        exit 0
    }

    # 2. Download
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $tmp = Join-Path $env:TEMP ("cloudflared-new-{0}.exe" -f ([guid]::NewGuid().ToString("N").Substring(0, 8)))
    Write-Log "downloading $DownloadUrl"
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $tmp -UseBasicParsing
    Write-Log ("downloaded {0:N1} MB" -f ((Get-Item -LiteralPath $tmp).Length / 1MB))

    # 3. Verify signature + version BEFORE touching anything
    $sig = Get-AuthenticodeSignature -LiteralPath $tmp
    $signer = ""
    if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
    Write-Log "signature: $($sig.Status)  signer: $signer"
    if ($sig.Status -ne "Valid") {
        throw "downloaded file signature is not valid (status=$($sig.Status))"
    }
    if (-not $signer.StartsWith($ExpectedSigner)) {
        throw "downloaded file is signed by an unexpected publisher (expected $ExpectedSigner)"
    }
    $newVersion = Get-CfVersion $tmp
    Write-Log "downloaded version: $newVersion"
    if (-not (Test-AtLeast $newVersion $MinVersion)) {
        throw "downloaded version '$newVersion' is below minimum $MinVersion"
    }

    # 4. Stop our service if it is running
    $svc = Get-OurService
    $wasRunning = $false
    if ($svc -and $svc.Status -eq "Running") {
        $wasRunning = $true
        Write-Log "stopping service '$ServiceName'"
        Stop-Service -Name $ServiceName -Force
        if (-not (Wait-SvcStatus $ServiceName "Stopped" 30)) { throw "service did not stop within 30 s" }
    }

    # 5. Swap: rename old (works even if a manual tunnel process holds it), copy new
    $backup = $null
    if (Test-Path -LiteralPath $Dest) {
        $backup = "$Dest.old"
        if (Test-Path -LiteralPath $backup) {
            try { Remove-Item -LiteralPath $backup -Force }
            catch { $backup = "$Dest.old-" + (Get-Date -Format "yyyyMMddHHmmss") }
        }
        Move-Item -LiteralPath $Dest -Destination $backup
        Write-Log "previous exe kept as $backup"
    } else {
        $parent = Split-Path -Parent $Dest
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    }
    Copy-Item -LiteralPath $tmp -Destination $Dest -Force

    # 6. Restart + verify, roll back if the service will not come up
    if ($wasRunning) {
        Write-Log "starting service '$ServiceName'"
        $started = $false
        try {
            Start-Service -Name $ServiceName
            $started = Wait-SvcStatus $ServiceName "Running" 30
        } catch { Write-Log "start failed: $_" }
        if (-not $started) {
            Write-Log "service did not start on the new version - rolling back"
            try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch { }
            if ($backup) {
                Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $backup -Destination $Dest
            }
            try { Start-Service -Name $ServiceName } catch { }
            throw "new version would not start; restored $oldVersion"
        }
    }

    $installed = Get-CfVersion $Dest
    if (-not (Test-AtLeast $installed $MinVersion)) { throw "post-install version check failed ('$installed')" }

    $from = $oldVersion
    if (-not $from) { $from = "none" }
    $note = ""
    if (-not $wasRunning) { $note = " (tunnel service was not running; a manually started tunnel picks it up on its next start)" }
    Write-Result "upgraded" $oldVersion $installed ("cloudflared upgraded {0} -> {1}{2}" -f $from, $installed, $note)
    exit 0
}
catch {
    Write-Result "failed" $oldVersion "" ("$_")
    exit 1
}
finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}
