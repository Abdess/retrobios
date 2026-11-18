"""The environment a child process inherits: an allowlist, never a token or a password."""

from __future__ import annotations

import os
from collections.abc import Sequence


# What a job step inherits. A step can run third-party code (a buildbot
# core, a scraped page, a downloaded tool), so it gets the variables a
# program needs to run and nothing it could leak: no token, no password.
SAFE_ENV = frozenset({"PATH", "HOME", "LANG", "TZ", "TMPDIR"})
SECRET_NAMES = frozenset({"GITHUB_TOKEN", "GH_TOKEN", "ROMSTATION_USER", "ROMSTATION_PASS"})
SECRET_MARKERS = ("TOKEN", "SECRET", "PASS")


def is_secret(name: str) -> bool:
    upper = name.upper()
    return name in SECRET_NAMES or any(marker in upper for marker in SECRET_MARKERS)


def safe_env(names: Sequence[str] = (), add: dict[str, str] | None = None,
             source: dict[str, str] | None = None) -> dict[str, str]:
    """The allowlisted environment, plus the variables a step names
    explicitly. A secret is dropped even when named."""
    source = dict(os.environ) if source is None else source
    wanted = set(names)
    env = {key: value for key, value in source.items()
           if (key in SAFE_ENV or key.startswith("LC_") or key in wanted) and not is_secret(key)}
    env.update({key: value for key, value in (add or {}).items() if not is_secret(key)})
    return env
