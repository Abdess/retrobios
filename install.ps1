# RetroBIOS installer for Windows (PowerShell 5+, no Python required)
$ErrorActionPreference = "Stop"
$baseUrl = if ($env:RETROBIOS_BASE_URL) { $env:RETROBIOS_BASE_URL } else { "https://raw.githubusercontent.com/Abdess/retrobios/main" }
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

# Expand the notations RetroArch writes into its config values:
# '~' is the home directory and ':' the application directory, both dropping
# two leading characters (libretro-common/file/file_path.c).
function Expand-RetroArchPath {
    param([string]$Value, [string]$AppDir)
    if ($Value.StartsWith('~')) { return Join-Path $env:USERPROFILE $Value.Substring(2) }
    if ($Value.StartsWith(':')) { return Join-Path $AppDir $Value.Substring(2) }
    return [Environment]::ExpandEnvironmentVariables($Value)
}

function Get-RetroArchSystemDir {
    param([string]$CfgPath, [string]$AppDir)
    if (-not (Test-Path $CfgPath)) { return $null }
    foreach ($line in Get-Content $CfgPath) {
        if ($line -match '^\s*system_directory\s*=\s*"?([^"]*)"?') {
            $val = $Matches[1].Trim()
            if (-not $val -or $val -eq "default") { return Join-Path $AppDir "system" }
            return Expand-RetroArchPath -Value $val -AppDir $AppDir
        }
    }
    return $null
}

# Detect RetroArch
if (-not $platform) {
    $raCfg = Join-Path $env:APPDATA "RetroArch\retroarch.cfg"
    if (Test-Path $raCfg) {
        $platform = "retroarch"
        $raRoot = Join-Path $env:APPDATA "RetroArch"
        $found = Get-RetroArchSystemDir -CfgPath $raCfg -AppDir $raRoot
        $biosPath = if ($found) { $found } else { Join-Path $raRoot "system" }
        Write-Host "Found RetroArch at $biosPath"
    }
}

# Locate LaunchBox. It installs wherever the user points its installer and
# writes no uninstall registry key, so the Start menu shortcut is the only
# record of that choice.
function Get-LaunchBoxRoot {
    $candidates = @()
    $lnk = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\LaunchBox\LaunchBox.lnk"
    if (Test-Path $lnk) {
        $bytes = [System.IO.File]::ReadAllBytes($lnk)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        if ($text -match '([A-Za-z]:\\[ -~]{0,260}?LaunchBox\.exe)') {
            # The shortcut points at Core\LaunchBox.exe
            $exeDir = Split-Path $Matches[1] -Parent
            $candidates += (Split-Path $exeDir -Parent)
            $candidates += $exeDir
        }
    }
    $candidates += (Join-Path $env:USERPROFILE "LaunchBox")
    foreach ($root in $candidates) {
        if (Test-Path (Join-Path $root "Data\Emulators.xml")) { return $root }
    }
    return $null
}

# Map each emulator LaunchBox knows about to its installation directory.
# ApplicationPath is either absolute or relative to the LaunchBox root.
function Get-LaunchBoxEmulators {
    param([string]$Root)
    $map = @{}
    if (-not $Root) { return $map }
    $xmlPath = Join-Path $Root "Data\Emulators.xml"
    if (-not (Test-Path $xmlPath)) { return $map }
    $doc = $null
    try { $doc = [xml](Get-Content $xmlPath -Raw) } catch { return $map }
    foreach ($emu in $doc.LaunchBox.Emulator) {
        $app = "$($emu.ApplicationPath)"
        if (-not $app) { continue }
        $exe = if ($app -match '^[A-Za-z]:' -or $app.StartsWith('\')) { $app } else { Join-Path $Root $app }
        $dir = Split-Path $exe -Parent
        $name = (Split-Path $exe -Leaf).ToLower()
        if ((Test-Path $dir) -and -not $map.ContainsKey($name)) { $map[$name] = $dir }
    }
    return $map
}

# BIOS directories LaunchBox itself computes for the emulators it manages.
function Get-LaunchBoxBiosDirs {
    $dirs = @{}
    $root = Get-LaunchBoxRoot
    if (-not $root) { return $dirs }
    $emulators = Get-LaunchBoxEmulators -Root $root
    $documents = Join-Path $env:USERPROFILE "Documents"

    if ($emulators.ContainsKey("pcsx2.exe")) {
        # portable.ini or portable.txt next to the executable moves the data
        # root there, portable.txt naming a subfolder when it holds one
        # (EmuFolders in pcsx2/Pcsx2Config.cpp). Otherwise it is Documents.
        $emuDir = $emulators["pcsx2.exe"]
        $portableTxt = Join-Path $emuDir "portable.txt"
        $portable = (Test-Path (Join-Path $emuDir "portable.ini")) -or (Test-Path $portableTxt)
        if ($portable) {
            $subpath = if (Test-Path $portableTxt) { (Get-Content $portableTxt -Raw).Trim() } else { "" }
            $dataRoot = if ($subpath) { Join-Path $emuDir $subpath } else { $emuDir }
        } else {
            $dataRoot = Join-Path $documents "PCSX2"
        }
        $ini = Join-Path $dataRoot "inis\PCSX2.ini"
        $bios = Join-Path $dataRoot "bios"
        if (Test-Path $ini) {
            foreach ($line in Get-Content $ini) {
                if ($line.StartsWith("Bios = ")) {
                    $val = $line.Substring(7).Trim()
                    $bios = if ($val -match '^[A-Za-z]:' -or $val.StartsWith('\')) { $val } else { Join-Path $dataRoot $val }
                    break
                }
            }
        }
        $dirs["pcsx2"] = $bios
    }

    if ($emulators.ContainsKey("xemu.exe")) {
        # bootrom_path and flashrom_path name a file whose directory holds
        # the images; both default to bios/ under the executable.
        $emuDir = $emulators["xemu.exe"]
        $toml = Join-Path $emuDir "xemu.toml"
        if (-not (Test-Path $toml)) { $toml = Join-Path $env:APPDATA "xemu\xemu\xemu.toml" }
        $bios = Join-Path $emuDir "bios"
        if (Test-Path $toml) {
            foreach ($line in Get-Content $toml) {
                if ($line.StartsWith("bootrom_path") -or $line.StartsWith("flashrom_path")) {
                    $parts = $line.Split("'")
                    if ($parts.Count -gt 1 -and (Test-Path $parts[1])) {
                        $bios = Split-Path $parts[1] -Parent
                        break
                    }
                }
            }
        }
        $dirs["xemu"] = $bios
    }

    if ($emulators.ContainsKey("dolphin.exe")) {
        # portable.txt beside the executable moves the user directory to User
        # (SetUserDirectory in Source/Core/UICommon/UICommon.cpp)
        $emuDir = $emulators["dolphin.exe"]
        if (Test-Path (Join-Path $emuDir "portable.txt")) {
            $dirs["dolphin"] = Join-Path $emuDir "User"
        }
    }
    return $dirs
}

# Detect LaunchBox (portable RetroArch referenced in Data\Emulators.xml)
if (-not $platform) {
    $lbRoot = Get-LaunchBoxRoot
    $lbXml = if ($lbRoot) { Join-Path $lbRoot "Data\Emulators.xml" } else { $null }
    if ($lbXml -and (Test-Path $lbXml)) {
        $lb = $null
        try { $lb = [xml](Get-Content $lbXml -Raw) } catch { Write-Host "Warning: could not parse $lbXml" }
        if ($lb) {
            foreach ($emu in $lb.LaunchBox.Emulator) {
                $app = "$($emu.ApplicationPath)".Replace('\', '/')
                if ($app -notmatch 'retroarch\.exe$') { continue }
                $lbRoot = Split-Path (Split-Path $lbXml -Parent) -Parent
                if ($app -match '^[A-Za-z]:' -or $app.StartsWith('/')) {
                    $exe = $app
                } else {
                    $exe = Join-Path $lbRoot $app
                }
                $raDir = Split-Path $exe -Parent
                if (Test-Path $raDir) {
                    $platform = "retroarch"
                    $found = Get-RetroArchSystemDir -CfgPath (Join-Path $raDir "retroarch.cfg") -AppDir $raDir
                    $biosPath = if ($found) { $found } else { Join-Path $raDir "system" }
                    Write-Host "Found LaunchBox with RetroArch at $biosPath"
                    break
                }
            }
        }
    }
}

# Fallback
if (-not $platform) {
    $available = @("retroarch", "batocera", "recalbox", "retrobat", "emudeck", "lakka", "retrodeck", "rocknix", "romm", "bizhawk", "misterfpga")
    $platform = (Read-Host "Platform ($($available -join ', '))").Trim().ToLower()
    $biosPath = (Read-Host "BIOS directory path").Trim()
    if (-not $platform -or -not $biosPath) {
        Write-Host "Aborted." -ForegroundColor Red; exit 1
    }
    if ($available -notcontains $platform) {
        Write-Host "Unknown platform '$platform'. Available: $($available -join ', ')" -ForegroundColor Red
        exit 1
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

    $tmp = "$dest.tmp"
    $ok = $false
    foreach ($attempt in 1..3) {
        try {
            Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
        } catch {
            continue
        }
        if ($f.sha1) {
            $actual = (Get-FileHash $tmp -Algorithm SHA1).Hash.ToLower()
            if ($actual -ne $f.sha1) {
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                continue
            }
        }
        Move-Item $tmp $dest -Force
        $ok = $true
        break
    }

    if ($ok) {
        $downloaded++
        $i = $downloaded + $errors
        Write-Host "  [$i/$total] $($f.dest) ok"
    } else {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        $errors++
        $i = $downloaded + $errors
        Write-Host "  [$i/$total] $($f.dest) FAILED" -ForegroundColor Red
    }
}

# Standalone emulator copies
if ($manifest.standalone_copies) {
    Write-Host "`nStandalone emulators:"
    $extraDirs = Get-LaunchBoxBiosDirs
    foreach ($entry in $manifest.standalone_copies) {
        if ($entry.note) {
            $detectPaths = @()
            if ($entry.detect -and $entry.detect.windows) {
                $detectPaths = $entry.detect.windows
            }
            foreach ($dp in $detectPaths) {
                $expanded = [Environment]::ExpandEnvironmentVariables($dp)
                if (Test-Path $expanded) {
                    Write-Host "  $($entry.note)"
                    break
                }
            }
            continue
        }
        $sources = @()
        if ($entry.pattern) {
            $sources = Get-ChildItem -Path $biosPath -Filter $entry.pattern -File -ErrorAction SilentlyContinue
        } elseif ($entry.file) {
            $src = Join-Path $biosPath $entry.file
            if (Test-Path $src) { $sources = @(Get-Item $src) }
        }
        if ($sources.Count -eq 0) { continue }
        $targetDirs = @()
        if ($entry.targets -and $entry.targets.windows) {
            $targetDirs = $entry.targets.windows
        }
        if ($entry.emulator -and $extraDirs.ContainsKey($entry.emulator)) {
            $extra = $extraDirs[$entry.emulator]
            $subdir = if ($entry.file) { Split-Path $entry.file -Parent } else { "" }
            if ($subdir) { $extra = Join-Path $extra $subdir }
            $targetDirs += $extra
        }
        foreach ($td in $targetDirs) {
            $expanded = [Environment]::ExpandEnvironmentVariables($td)
            if (-not (Test-Path $expanded)) { continue }
            foreach ($s in $sources) {
                $dest = Join-Path $expanded $s.Name
                try {
                    Copy-Item $s.FullName $dest -Force
                    Write-Host "  $($s.Name) -> $expanded"
                } catch {
                    Write-Host "  $($s.Name) -> $expanded FAILED" -ForegroundColor Red
                }

            }
        }
    }
}

Write-Host "`nDone. $downloaded downloaded, $upToDate already up to date."
