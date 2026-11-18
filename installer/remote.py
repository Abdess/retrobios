"""Where file lists and files come from, the pages the installer names, and bounds on what it reads."""
from __future__ import annotations

import os
import sys
import urllib.parse

# File lists are read from main, the newest ones, whichever commit the
# installer came from. RETROBIOS_REF pins them to a tag or a commit when
# reproducibility matters.
DEFAULT_RELEASE_REF = "main"
RELEASE_REF = os.environ.get("RETROBIOS_REF", DEFAULT_RELEASE_REF)
DEFAULT_BASE_URL = (
    "https://raw.githubusercontent.com/Abdess/retrobios/"
    + urllib.parse.quote(RELEASE_REF, safe="")
)


_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def _checked_base_url(value: str) -> str:
    """Refuse a base URL that is neither HTTPS nor loopback.

    This base serves the manifest and the files it declares, so whoever
    controls it controls the expected hashes too and verification stops
    proving anything. install.sh and install.ps1 make the same check on the
    URL they fetch the installer from.

    Plain HTTP to loopback stays allowed: nothing sits between the two ends
    to intercept it, and it is how the installer is exercised end to end.
    """
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme == "https":
        return value
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and host in _LOOPBACK_HOSTS:
        return value
    print(
        f"Error: RETROBIOS_BASE_URL must use HTTPS, got {value!r}",
        file=sys.stderr,
    )
    sys.exit(1)


BASE_URL = _checked_base_url(os.environ.get("RETROBIOS_BASE_URL", DEFAULT_BASE_URL))
MANIFEST_URL = f"{BASE_URL}/install/{{platform}}.json"
TARGETS_URL = f"{BASE_URL}/install/targets/{{platform}}.json"
# What --standalone reads, apart from the list every run downloads.
STANDALONE_DIR = "standalone"
STANDALONE_URL = f"{BASE_URL}/install/standalone/{{platform}}.json"


RAW_FILE_URL = f"{BASE_URL}/{{path}}"
RELEASE_URL = (
    "https://github.com/Abdess/retrobios/releases/download/large-files/{asset}"
)
MAX_RETRIES = 3
# Seconds a connection has to open. A dropped network cost three tries of a
# 30-second timeout, 93 s, before the error: a connection that does not open
# now fails in this time, and once open a read waits as long as before, so
# a slow line is not cut.
CONNECT_TIMEOUT = 4.0
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_TARGETS_BYTES = 4 * 1024 * 1024
MAX_STANDALONE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_FILES = 100_000
MAX_DOWNLOAD_SIZE = 1024 * 1024 * 1024
# A data directory's source archive: PCSX2's source tarball is the largest.
MAX_DATA_ARCHIVE_SIZE = 4 * 1024 * 1024 * 1024
MAX_TOTAL_DOWNLOAD_SIZE = 64 * 1024 * 1024 * 1024


SITE_URL = "https://abdess.github.io/retrobios/"
INSTALLER_PAGE = f"{SITE_URL}wiki/installer/"
TROUBLESHOOTING_PAGE = f"{SITE_URL}wiki/troubleshooting/"
# The one-line bootstraps the site serves: BOOTSTRAP_URL for sh, .ps1 after it
# for PowerShell (scripts/sitebootstrap.py).
BOOTSTRAP_URL = f"{SITE_URL}i"


# A file this size or larger keeps its partial download when a transfer
# stops, and the next run asks the server for the rest: the release assets
# run to hundreds of megabytes. Smaller files simply start over.
RESUME_FROM_SIZE = 16 * 1024 * 1024
