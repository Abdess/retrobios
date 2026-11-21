"""One release asset downloaded to disk, with its progress line."""

from __future__ import annotations

import os
import shutil
import sys
import urllib.request
from typing import TYPE_CHECKING

from core.sizes import size_text
from core.upstream import open_retrying
from release.latest import checked_url

if TYPE_CHECKING:
    import http.client
    from pathlib import Path


def download_file(
    url: str, dest: Path, expected_size: int = 0, label: str = ""
) -> None:
    """Download a file with progress indication.

    core.upstream.open_retrying asks again after a dropped connection, a
    stream cut midway or a 5xx, and waits out a rate limit: each attempt
    writes `dest` from its first byte.
    """
    url = checked_url(url, "asset URL")
    req = urllib.request.Request(
        url, headers={"User-Agent": "retrobios-downloader/1.0"}
    )

    # A redrawn bar only on a terminal: written to a log, 32,768 redraws of a
    # 2 GiB part made one line of nearly 3 MB.
    live = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"

    def save(resp: http.client.HTTPResponse) -> int:
        total = int(resp.headers.get("Content-Length", expected_size))
        downloaded = 0
        shown = -1
        with open(dest, "wb") as f:
            while chunk := resp.read(65536):
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0 and live:
                    pct = downloaded * 100 // total
                    if pct != shown:
                        shown = pct
                        columns = shutil.get_terminal_size((80, 24)).columns
                        line = progress_line(label, downloaded, total, columns)
                        print(f"\r\033[K{line}", end="", flush=True)
        return downloaded

    downloaded = open_retrying(req, save, 300)
    if live:
        print()
    else:
        print(f"  {label}{downloaded:,} bytes")
    if expected_size and downloaded != expected_size:
        raise ValueError(f"downloaded {downloaded} bytes, expected {expected_size}")


def progress_line(label: str, done: int, total: int, columns: int) -> str:
    """One physical line shorter than the terminal: a wrapped line leaves a
    copy of itself on every redraw, since \\r goes back one row only. The
    bar shrinks first, then goes."""
    pct = done * 100 // total
    figures = f" {pct}% ({size_text(done)}/{size_text(total)})"
    room = min(50, columns - 1 - len(f"  {label}[]") - len(figures))
    if room < 10:
        return f"  {label}{figures.strip()}"[: columns - 1]
    filled = room * pct // 100
    return f"  {label}[{'=' * filled}{' ' * (room - filled)}]{figures}"
