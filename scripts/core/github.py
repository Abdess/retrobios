"""The token a run uses for the GitHub API."""

from __future__ import annotations

import functools
import os


@functools.lru_cache(maxsize=1)
def _gh_cli_token() -> str:
    """What `gh auth token` prints, or "" when gh is absent or logged out."""
    import logging
    import subprocess

    log = logging.getLogger(__name__)
    try:
        proc = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except FileNotFoundError:
        log.debug("gh is not installed, GitHub API calls go anonymous")
        return ""
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.warning("gh auth token did not answer: %s", exc)
        return ""
    if proc.returncode != 0:
        log.debug("gh auth token: %s", (proc.stderr or "").strip())
        return ""
    return (proc.stdout or "").strip()


def github_token() -> str:
    """The token for api.github.com: GITHUB_TOKEN, GH_TOKEN, then gh's own.

    A maintainer logged in to gh had to export GITHUB_TOKEN by hand before
    profile_sync, the scrapers or an online pipeline, which refused the run
    or burnt the anonymous quota of 60 calls an hour. The token gh returns
    is put in the environment, so the subprocesses a run starts and the
    readers of os.environ get it too. RETROBIOS_OFFLINE runs make no API
    call and never ask gh.
    """
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if token or os.environ.get("RETROBIOS_OFFLINE"):
        return token
    token = _gh_cli_token()
    if token:
        os.environ["GITHUB_TOKEN"] = token
    return token
