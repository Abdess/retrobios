"""The anonymous GitHub quota a profile pass has to fit in."""

from __future__ import annotations

import sys

from core.github import github_token
from core.offline import run_is_offline

ANON_QUOTA = 60


def check_quota(count: int, offline: bool) -> None:
    """Refuse a run the anonymous quota cannot carry to completion."""
    if run_is_offline(offline) or github_token():
        return
    if count * 5 > ANON_QUOTA:
        print(
            f"{count} profiles need roughly {count * 5} API calls, the anonymous "
            f"quota is {ANON_QUOTA} per hour. Log in with `gh auth login`, set "
            "GITHUB_TOKEN, or use --offline.",
            file=sys.stderr,
        )
        raise SystemExit(1)
