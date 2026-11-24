"""Where file lists and files come from, the pages the installer names, and bounds on what it reads."""
from __future__ import annotations

import contextlib
import os
import urllib.parse
from collections.abc import Iterator
from typing import NamedTuple

# File lists are read from main, the newest ones, whichever commit the
# installer came from. RETROBIOS_REF pins them to a tag or a commit when
# reproducibility matters.
DEFAULT_RELEASE_REF = "main"


def default_base_url(ref: str) -> str:
    """The project's own address for the file lists of ref."""
    return ("https://raw.githubusercontent.com/Abdess/retrobios/"
            + urllib.parse.quote(ref, safe=""))


_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def _checked_base_url(value: str) -> str:
    """Refuse a base URL that is neither HTTPS nor loopback, as ValueError.

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
    raise ValueError(f"RETROBIOS_BASE_URL must use HTTPS, got {value!r}")


# What --standalone reads, apart from the list every run downloads.
STANDALONE_DIR = "standalone"


class Remote(NamedTuple):
    """Where a run reads its lists and files: the revision, the base
    address, and whether RETROBIOS_BASE_URL chose that base."""

    ref: str
    base: str
    overridden: bool

    @property
    def manifest_url(self) -> str:
        return f"{self.base}/install/{{platform}}.json"

    @property
    def targets_url(self) -> str:
        return f"{self.base}/install/targets/{{platform}}.json"

    @property
    def standalone_url(self) -> str:
        return f"{self.base}/install/{STANDALONE_DIR}/{{platform}}.json"

    @property
    def raw_file_url(self) -> str:
        return f"{self.base}/{{path}}"


def remote_from_env() -> Remote:
    """The remote RETROBIOS_REF and RETROBIOS_BASE_URL name, ValueError for
    a base that is neither HTTPS nor loopback. A variable set but empty is
    unset, as every other reading of them takes it."""
    ref = os.environ.get("RETROBIOS_REF") or DEFAULT_RELEASE_REF
    override = os.environ.get("RETROBIOS_BASE_URL") or ""
    if override:
        return Remote(ref, _checked_base_url(override), True)
    return Remote(ref, default_base_url(ref), False)


# The remote main resolved, for the length of its run.
_IN_USE: list[Remote] = []


@contextlib.contextmanager
def remote_in_use(remote: Remote) -> Iterator[None]:
    """remote answers active_remote() until the block ends."""
    _IN_USE.append(remote)
    try:
        yield
    finally:
        _IN_USE.pop()


def active_remote() -> Remote:
    """The remote of this run: the one main resolved, else the one the
    environment names now, for a caller that did not come through main."""
    return _IN_USE[-1] if _IN_USE else remote_from_env()


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
# for PowerShell (scripts/sitegen/bootstrap.py).
BOOTSTRAP_URL = f"{SITE_URL}i"


# A file this size or larger keeps its partial download when a transfer
# stops, and the next run asks the server for the rest: the release assets
# run to hundreds of megabytes. Smaller files simply start over.
RESUME_FROM_SIZE = 16 * 1024 * 1024
