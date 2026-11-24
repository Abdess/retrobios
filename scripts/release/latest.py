"""The release endpoint the downloader trusts, and the latest release it names."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from core.forgehttp import forge_headers, open_retrying
from release.downloaderror import DownloadError

DEFAULT_API = "https://api.github.com"
REPO = "Abdess/retrobios"

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def checked_url(value: str, label: str) -> str:
    """Return *value* cleaned, or raise DownloadError when it is neither HTTPS nor loopback.

    This endpoint names the assets and, through them, the bytes that land in
    the BIOS directory, so it is the trust anchor of the whole download.
    Plain HTTP to loopback stays allowed: it is how this is tested end to end.
    """
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme == "https":
        return value.rstrip("/")
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and host in _LOOPBACK_HOSTS:
        return value.rstrip("/")
    raise DownloadError(f"Error: {label} must use HTTPS, got {value!r}")


def get_latest_release(api: str) -> dict:
    """Fetch the latest release info from the releases endpoint *api*."""
    url = f"{api}/repos/{REPO}/releases/latest"
    # The anonymous quota is 60 calls an hour per address. The token goes to
    # GitHub's API only: RETROBIOS_API can name any host.
    headers = forge_headers(url, "application/vnd.github.v3+json", "retrobios-downloader/1.0")
    req = urllib.request.Request(url, headers=headers)

    try:
        return json.loads(open_retrying(req, lambda resp: resp.read(), 30))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise DownloadError(
                "No releases found. The repository may not have any releases yet."
            ) from e
        raise
