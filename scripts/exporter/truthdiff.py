"""One platform's truth model read beside its own scraped file and diffed."""

from __future__ import annotations

import os

from model.platforms import load_platform_config, native_layer
from model.safeparse import require_yaml, yaml_load
from resolve.truth import diff_platform_truth

require_yaml()


class NoDiffInput(LookupError):
    """One side of the diff is absent: the message says which."""


def load_truth(truth_dir: str, platform: str) -> dict | None:
    """The truth model generate_truth wrote for a platform, None when absent."""
    path = os.path.join(truth_dir, f"{platform}.yml")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return yaml_load(f) or {}


def platform_diff(platform: str, truth_dir: str, platforms_dir: str) -> dict:
    """The diff report of one platform, raising NoDiffInput when a side is absent."""
    truth = load_truth(truth_dir, platform)
    if truth is None:
        raise NoDiffInput(f"no truth YAML in {truth_dir}/")
    try:
        # What the platform's own file declares: our shared groups,
        # mirrors and curated additions are not theirs to be credited.
        scraped = native_layer(load_platform_config(platform, platforms_dir))
    except FileNotFoundError as exc:
        raise NoDiffInput("no scraped config") from exc
    report = diff_platform_truth(truth, scraped)
    report["platform"] = platform
    return report
