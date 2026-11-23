"""The tracked paths a pipeline run rewrites, as globs whose `*` stays inside one path segment."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable

# What `pipeline.py --offline` writes and the nightly job commits under its
# "regenerate collection records" rule (automation/jobs.yml).
COLLECTION_RECORDS = (
    "database.json",
    "derivable.json",
    "retired.json",
    "install/*.json",
    "install/standalone/*.json",
    "install/targets/*.json",
    "install/games/*.json",
    "install/games/*/*.json",
    "README.md",
    "CONTRIBUTING.md",
    "wiki/installer.md",
    "wiki/reading-reports.md",
    "website/src/data/*.json",
)
# The archive recipes of step 1c, committed by the recipes rule, and the
# reports of `--with-export`.
OTHER_PIPELINE_OUTPUTS = (
    "recipes/archives.json",
    "exports/*.json",
    "exports/*/*.json",
)
GENERATED = COLLECTION_RECORDS + OTHER_PIPELINE_OUTPUTS


def path_matches(pattern: str, path: str) -> bool:
    """A glob whose `*` stays inside one path segment."""
    parts, segments = pattern.split("/"), path.split("/")
    return len(parts) == len(segments) and all(
        fnmatch.fnmatchcase(s, p) for p, s in zip(parts, segments)
    )


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(path_matches(p, path) for p in patterns)


def is_generated(path: str) -> bool:
    return matches_any(path, GENERATED)
