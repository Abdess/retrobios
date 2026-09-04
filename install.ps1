# One-line bootstrap and local wrapper. The downloaded installer is accepted
# only when it matches the SHA-256 embedded in this wrapper.
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$InstallerArguments
)

$ErrorActionPreference = "Stop"
$defaultInstallUrl = "https://raw.githubusercontent.com/Abdess/retrobios/main/install.py"
$defaultInstallSha256 = "7dbb5c48a834d31a470b1952a9b8659b4c1f49f8d37c709a4032a56abe495f27"
$maximumInstallerBytes = 2MB
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
        Invoke-WebRequest -Uri $uri -OutFile $temporary -UseBasicParsing
        if ((Get-Item -LiteralPath $temporary).Length -gt $maximumInstallerBytes) {
            throw "Downloaded installer exceeds the size limit."
        }
        $actual = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected.ToLowerInvariant()) {
            throw "install.py SHA-256 mismatch."
        }
        $installer = $temporary
    }

    $python = Get-Command py -ErrorAction SilentlyContinue
    if ($python) {
        & $python.Source -3 -c "import sys; raise SystemExit(sys.version_info < (3, 8))"
        if ($LASTEXITCODE -ne 0) { throw "Python 3.8 or newer is required." }
        & $python.Source -3 $installer @InstallerArguments
        if ($LASTEXITCODE -ne 0) { throw "RetroBIOS installer failed with exit code $LASTEXITCODE." }
        return
    }
    $python = Get-Command python3 -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python -ErrorAction SilentlyContinue
    }
    if (-not $python) {
        throw "Python 3.8 or newer is required."
    }
    & $python.Source -c "import sys; raise SystemExit(sys.version_info < (3, 8))"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.8 or newer is required." }
    & $python.Source $installer @InstallerArguments
    if ($LASTEXITCODE -ne 0) { throw "RetroBIOS installer failed with exit code $LASTEXITCODE." }
}
finally {
    if ($temporary -and (Test-Path -LiteralPath $temporary)) {
        Remove-Item -LiteralPath $temporary -Force
    }
}
