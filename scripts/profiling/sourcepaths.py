"""The site's record of cited source paths, rebuilt after a pass wrote profiles."""

from __future__ import annotations

import argparse
import os
import sys

from model.profiles import load_emulator_profiles
from profiling.run import WRITTEN_PROFILES


def refresh_source_paths(args: argparse.Namespace) -> None:
    """Rebuild the site's record of cited source paths after a write.

    Each bump left website/src/data/source-paths.json behind its pins, and
    the site's freshness test stayed red until someone ran sitesources.py
    --fetch by hand. A run that writes nothing, or makes no request, leaves
    it alone.
    """
    if not WRITTEN_PROFILES or args.dry_run or args.offline or os.environ.get("RETROBIOS_OFFLINE"):
        return
    from core.artifacts import ArtifactLockBusy
    from model.profiles import emulator_profiles_cache
    from sitegen import sources

    # The run loaded the profiles before writing them, and the loader caches
    # by directory: read again, the record described the pins just replaced
    # (linapple, then ten profiles in one advance).
    emulator_profiles_cache.clear()
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    try:
        held, unread = sources.refresh_record(profiles, [sources.TREE_CACHE], fetch=True)
    except ArtifactLockBusy as exc:
        # The profiles are written: only the record waits for the other run.
        print(
            f"source paths not refreshed ({exc}): run python scripts/sitesources.py "
            "--fetch once it finishes",
            file=sys.stderr,
        )
        return
    print(
        f"source paths: {sum(map(len, held.values()))} in {len(held)} trees, "
        f"{len(unread)} trees not cached: {sources.SOURCE_PATHS}",
        file=sys.stderr,
    )
