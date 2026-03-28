# RetroBIOS installer for Windows (PowerShell 5+, no Python required)
$ErrorActionPreference = "Stop"
$baseUrl = "https://raw.githubusercontent.com/Abdess/retrobios/main"
$releaseUrl = "https://github.com/Abdess/retrobios/releases/download/large-files"

$platform = $null
$biosPath = $null

# Detect EmuDeck
$emudeckSettings = Join-Path $env:APPDATA "EmuDeck\settings.ps1"
if (Test-Path $emudeckSettings) {
    $content = Get-Content $emudeckSettings -Raw
    if ($content -match '\$emulationPath\s*=\s*"([^"]+)"') {
        $platform = "emudeck"
        $biosPath = Join-Path $Matches[1] "bios"
        Write-Host "Found EmuDeck at $biosPath"
    }
}

# Detect RetroArch
if (-not $platform) {
    $raCfg = Join-Path $env:APPDATA "RetroArch\retroarch.cfg"
    if (Test-Path $raCfg) {
        $platform = "retroarch"
        $biosPath = Join-Path $env:APPDATA "RetroArch\system"
        foreach ($line in Get-Content $raCfg) {
            if ($line -match '^\s*system_directory\s*=\s*"?([^"]+)"?') {
                $val = $Matches[1].Trim()
                if ($val -and $val -ne "default") {
                    $biosPath = $val
                }
                break
            }
        }
        Write-Host "Found RetroArch at $biosPath"
    }
}

# Fallback
if (-not $platform) {
    $platform = Read-Host "Platform (retroarch, batocera, emudeck, ...)"
    $biosPath = Read-Host "BIOS directory path"
    if (-not $platform -or -not $biosPath) {
        Write-Host "Aborted." -ForegroundColor Red; exit 1
    }
}

Write-Host "`nFetching file index for $platform..."
$manifest = Invoke-RestMethod "$baseUrl/install/$platform.json"
$files = $manifest.files
Write-Host "  $($files.Count) files"

Write-Host "`nChecking existing files..."
$toDownload = @()
$upToDate = 0

foreach ($f in $files) {
    $dest = Join-Path $biosPath $f.dest
    if (Test-Path $dest) {
        if ($f.sha1) {
            $actual = (Get-FileHash $dest -Algorithm SHA1).Hash.ToLower()
            if ($actual -eq $f.sha1) { $upToDate++; continue }
        } else {
            $upToDate++; continue
        }
    }
    $toDownload += $f
}

Write-Host "  $upToDate/$($files.Count) up to date, $($toDownload.Count) to download"

if ($toDownload.Count -eq 0) {
    Write-Host "`nDone. 0 downloaded, $upToDate already up to date."
    exit 0
}

$downloaded = 0
$errors = 0
$total = $toDownload.Count

foreach ($f in $toDownload) {
    $dest = Join-Path $biosPath $f.dest
    $dir = Split-Path $dest -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    if ($f.release_asset) {
        $url = "$releaseUrl/$($f.release_asset)"
    } else {
        $url = "$baseUrl/$($f.repo_path)"
    }

    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
        $downloaded++
        $i = $downloaded + $errors
        Write-Host "  [$i/$total] $($f.dest) ok"
    } catch {
        $errors++
        $i = $downloaded + $errors
        Write-Host "  [$i/$total] $($f.dest) FAILED" -ForegroundColor Red
    }
}

Write-Host "`nDone. $downloaded downloaded, $upToDate already up to date."
