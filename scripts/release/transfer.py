"""One release asset downloaded to disk, its progress handed to a callback."""

from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

from core.upstream import UpstreamError, open_retrying
from release.downloaderror import DownloadError
from release.latest import checked_url

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

TRANSFER_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError, UpstreamError)


def download_file(
    url: str,
    dest: Path,
    expected_size: int = 0,
    progress: Callable[[int, int], None] | None = None,
) -> int:
    """Write the asset at *url* to *dest* and return its byte count.

    *progress* receives the bytes written so far and the announced total
    after each block. core.upstream.open_retrying asks again after a dropped
    connection, a stream cut midway or a 5xx, and waits out a rate limit:
    each attempt writes `dest` from its first byte. A transfer that fails or
    ends short of *expected_size* raises DownloadError.
    """
    url = checked_url(url, "asset URL")
    req = urllib.request.Request(
        url, headers={"User-Agent": "retrobios-downloader/1.0"}
    )

    def save(resp: http.client.HTTPResponse) -> int:
        total = int(resp.headers.get("Content-Length", expected_size))
        downloaded = 0
        with open(dest, "wb") as f:
            while chunk := resp.read(65536):
                f.write(chunk)
                downloaded += len(chunk)
                if progress is not None:
                    progress(downloaded, total)
        return downloaded

    try:
        downloaded = open_retrying(req, save, 300)
    except TRANSFER_ERRORS as exc:
        raise DownloadError(f"Error: downloading {dest.name} failed: {exc}") from exc
    if expected_size and downloaded != expected_size:
        raise DownloadError(
            f"Error: downloaded {downloaded:,} bytes of {dest.name}, "
            f"expected {expected_size:,}."
        )
    return downloaded
