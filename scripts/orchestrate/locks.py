"""The locks a run holds from its first step to its exit."""

from __future__ import annotations

import argparse
import contextlib
import sys

from core.artifacts import (
    ArtifactLockBusy,
    hold_artifact_lock,
    hold_repository_outputs,
    publish_hold,
)
from core.paths import REPO_ROOT


def hold_outputs(args: argparse.Namespace) -> contextlib.ExitStack:
    """Take every lock the run holds until it exits, or exit when one is busy."""
    # A second run on the same output directory is refused before any work:
    # the database rebuild alone takes minutes, and the reader holding the
    # directory would otherwise see the answer only after all of it. The
    # hold lasts until this process exits: taken step by step, it let another
    # run purge the packs between the build and the integrity check, which
    # then reported every platform SKIP and passed.
    # database.json, install/, README.md, CONTRIBUTING.md and website/ sit at
    # fixed paths (artifacts.REPOSITORY_OUTPUTS), so
    # every run holds them too: a run on a scratch --output-dir otherwise
    # rewrote them beside the run on dist/.
    held = contextlib.ExitStack()
    try:
        root = str(REPO_ROOT)
        held.enter_context(hold_repository_outputs(root))
        # Its steps write database.json, install/ and README.md themselves,
        # and take the same lock to do so.
        held.enter_context(publish_hold(root))
        if not args.skip_packs:
            held.enter_context(hold_artifact_lock(args.output_dir))
    except ArtifactLockBusy as exc:
        held.close()
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    return held
