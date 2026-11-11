# One-line bootstrap and local wrapper. The downloaded installer is accepted
# only when it matches the SHA-256 embedded in this wrapper.
# Everything runs in a script block of its own: piped into iex, the script
# would otherwise leave its variables and $ErrorActionPreference = "Stop"
# in the user's session, where every later error would stop their commands.
# Neither the script nor the block declares a parameter: one [Parameter()]
# attribute makes it an advanced one, whose common parameters took -v
# (-Verbose), -vb, -d (-Debug) and -ea before install.py could see them.
& {
    $InstallerArguments = @($args)

    $ErrorActionPreference = "Stop"
    $defaultInstallUrl = "https://raw.githubusercontent.com/Abdess/retrobios/main/install.py"
    # What a refused installer most likely means for this copy. The copy the
    # site serves reads a commit's installer, which no cache serves stale,
    # and Invoke-WebRequest throws on a cut transfer before the hash is read:
    # the site's build rewrites this line there (scripts/sitebootstrap.py).
    $mismatchAdvice = "The download was most likely cut short: try again. Within minutes of an update of this project the two files can come from caches of different ages. Waiting five minutes settles that."
    $defaultInstallSha256 = "0eb4260d873e9fa9186fec264a0f4d484707d58daf432d5addbe65feb4912ae2"
    # The pin above refuses any changed byte: this cap only stops a body that
    # cannot be the installer (a sign-in portal's page) before it is hashed.
    $maximumInstallerBytes = 8MB
    $installerExit = 0
    $installer = if ($PSScriptRoot) { Join-Path $PSScriptRoot "install.py" } else { $null }
    $temporary = $null

    try {
        if (-not $installer -or -not (Test-Path -LiteralPath $installer -PathType Leaf)) {
            $url = if ($env:RETROBIOS_INSTALL_URL) { $env:RETROBIOS_INSTALL_URL } else { $defaultInstallUrl }
            $expected = if ($env:RETROBIOS_INSTALL_SHA256) { $env:RETROBIOS_INSTALL_SHA256 } else { $defaultInstallSha256 }
            $uri = [Uri]$url
            if ($uri.Scheme -ne "https") {
                throw "RETROBIOS_INSTALL_URL must use HTTPS."
            }
            if ($expected -notmatch '^[0-9a-fA-F]{64}$') {
                throw "Installer SHA-256 must contain exactly 64 hexadecimal characters."
            }
            # Windows PowerShell 5.1 still negotiates SSL 3.0 / TLS 1.0 by default
            # and GitHub refuses both, so the download fails before any hash is
            # checked. install.sh pins the same floor with curl --tlsv1.2.
            if ($PSVersionTable.PSEdition -ne "Core") {
                [Net.ServicePointManager]::SecurityProtocol = `
                    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            }
            $temporary = Join-Path ([IO.Path]::GetTempPath()) ("retrobios-install-{0}.py" -f [Guid]::NewGuid())
            try {
                # A server that takes the connection and never answers (a
                # captive portal, a proxy) held the window forever with no
                # line: the wait for an answer stops after 30 s, as curl's
                # --connect-timeout in install.sh.
                Invoke-WebRequest -Uri $uri -OutFile $temporary -UseBasicParsing -TimeoutSec 30
            } catch {
                # The raw WebException read as a crash and named no next step.
                throw ("The installer could not be downloaded from {0}: {1} " +
                    "Check the network connection and any proxy, then run the same command again. " +
                    "Nothing was run and nothing was written.") -f $url, $_.Exception.Message
            }
            $downloaded = (Get-Item -LiteralPath $temporary).Length
            if ($downloaded -gt $maximumInstallerBytes) {
                # A page served in place of the file says the network
                # answered, not this project: the one cause a user can act on.
                $tooLarge = ("The downloaded installer is {0} bytes, more than the {1} this script accepts. " +
                    "Nothing was run and nothing was written. A network that answers with a page of its own " +
                    "(a sign-in portal, a proxy) gives this: open any web page to sign in, then run the same " +
                    "command again.") -f $downloaded, $maximumInstallerBytes
                if ([Environment]::GetEnvironmentVariable("RETROBIOS_INSTALL_URL")) {
                    $tooLarge += " RETROBIOS_INSTALL_URL is set in this session and names another installer: " +
                        "remove it to use the installer this script names."
                }
                throw $tooLarge
            }
            $actual = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected.ToLowerInvariant()) {
                $mismatch = "The downloaded installer does not match its expected fingerprint. Nothing was run and nothing was written. "
                $overrides = @("RETROBIOS_INSTALL_URL", "RETROBIOS_INSTALL_SHA256") |
                    Where-Object { [Environment]::GetEnvironmentVariable($_) }
                if ($overrides) {
                    # A pin or a URL of the user's own refuses the installer:
                    # retrying, as the advice below says, would never help.
                    throw ($mismatch + "{0} is set in this session and decides which installer is accepted: " +
                        "remove it to use the installer this script names, or set it to match.") -f ($overrides -join " and ")
                }
                throw ($mismatch + $mismatchAdvice)
            }
            $installer = $temporary
        }

        $usable = {
            param($candidate)
            if (-not $candidate) { return $false }
            $arguments = $candidate[1]
            & $candidate[0].Source @arguments -c "import sys, ssl, unicodedata, zlib; raise SystemExit(sys.version_info < (3, 8))" 2>$null | Out-Null
            return ($LASTEXITCODE -eq 0)
        }
        # The py launcher first, then python3 and python, the first that
        # passes the check: a py launcher left with no usable runtime hid a
        # Python 3.12 on PATH. The Microsoft Store places a python.exe that
        # only points at the Store: it fails the check like a missing one.
        $findPython = {
            $candidates = @()
            $found = Get-Command py -ErrorAction SilentlyContinue
            if ($found) { $candidates += ,@($found, @("-3")) }
            foreach ($name in @("python3", "python")) {
                $found = Get-Command $name -ErrorAction SilentlyContinue
                if ($found) { $candidates += ,@($found, @()) }
            }
            foreach ($candidate in $candidates) {
                if (& $usable $candidate) { return ,$candidate }
            }
            return $null
        }
        $needPython = "Python 3.8 or newer is required. Install it with " +
            "'winget install Python.Python.3.12' or from https://www.python.org/downloads/ " +
            "(tick 'Add python.exe to PATH'), then open a new PowerShell window and run this command again."
        $candidate = & $findPython
        if (-not $candidate) {
            # winget ships with Windows 10 and 11: at a console the bootstrap
            # offers to run the install the message names, then carries on.
            $winget = Get-Command winget -ErrorAction SilentlyContinue
            if ($winget -and -not [Console]::IsInputRedirected) {
                $answer = Read-Host "Python 3.8 or newer is required. Install Python 3.12 now with winget? [Y/n]"
                if ($answer -notmatch '^\s*[nNqQ]') {
                    & $winget.Source install --id Python.Python.3.12 --exact --source winget `
                        --accept-package-agreements --accept-source-agreements
                    # The installer adds Python to the PATH of new sessions:
                    # this one reads it again from the registry.
                    if ($env:OS -eq "Windows_NT") {
                        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                            [Environment]::GetEnvironmentVariable("Path", "User")
                    }
                    $candidate = & $findPython
                }
            }
            if (-not $candidate) { throw $needPython }
        }
        $python = $candidate[0]
        $launcher = $candidate[1]
        # The installer rebuilds this command in its hints, and the user has
        # no install.py of their own to run.
        $previousBootstrap = $env:RETROBIOS_BOOTSTRAP
        $env:RETROBIOS_BOOTSTRAP = if ($temporary) { "ps1" } else { $null }
        try {
            & $python.Source @launcher $installer @InstallerArguments
        } finally {
            $env:RETROBIOS_BOOTSTRAP = $previousBootstrap
        }
        # The installer has already said what happened: its status is passed on
        # as it is (1 for files left to fetch under --check, 2 when nothing was
        # installed, 130 on Ctrl+C), not turned into a red exception that reads
        # as a crash and flattens every code to one.
        $installerExit = $LASTEXITCODE
    }
    catch {
        # One line saying what failed and what to do, rather than the red
        # exception block PowerShell prints for an uncaught throw.
        [Console]::Error.WriteLine("Error: " + $_.Exception.Message)
        $installerExit = 1
    }
    finally {
        if ($temporary -and (Test-Path -LiteralPath $temporary)) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }

    if ($installerExit) {
        # Run from a file, the script ends with that status. Piped into iex it
        # runs in the user's own session, which exit would close.
        if ($PSScriptRoot) { exit $installerExit }
        $global:LASTEXITCODE = $installerExit
    }
} @args
