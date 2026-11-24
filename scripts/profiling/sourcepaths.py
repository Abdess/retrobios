"""The site's record of cited source paths, rebuilt after a pass wrote profiles."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from core.offline import run_is_offline
from core.paths import EMULATORS_DIR, REPO_ROOT
from model.profiles import load_emulator_profiles


@contextmanager
def record_write(path: Path, name: str, written: set[str]) -> Iterator[None]:
    """Add *name* to *written* when the profile's bytes changed in the block.

    Every writer of a pass runs inside it, so a new writer cannot forget to
    say it wrote: --backfill-commits and --attribute-refs never did, and the
    pins they wrote stayed out of the record. A write put back is no write.
    """
    before = path.read_bytes() if path.is_file() else None
    try:
        yield
    finally:
        if path.is_file() and path.read_bytes() != before:
            written.add(name)


def refresh_source_paths(args: argparse.Namespace, written: set[str]) -> None:
    """Rebuild the site's record of cited source paths after a write.

    Each bump left website/src/data/source-paths.json behind its pins, and
    the site's freshness test stayed red until someone ran site_sources.py
    --fetch by hand. A run that writes nothing, or makes no request, leaves
    it alone. The record describes the repository's profiles: a pass over
    another tree prints the command for it instead of reducing the record
    to the trees that tree cites.
    """
    if not written or args.dry_run or run_is_offline(args.offline):
        return
    if Path(args.emulators_dir).resolve() != (REPO_ROOT / EMULATORS_DIR).resolve():
        print(
            f"source paths not refreshed: {args.emulators_dir} is not the repository's "
            f"{EMULATORS_DIR}/: run python scripts/site_sources.py --fetch "
            f"--emulators-dir {args.emulators_dir} --cache-dir {args.cache_dir} "
            "--output <record> to record them",
            file=sys.stderr,
        )
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
        held, unread = sources.refresh_record(
            profiles, [Path(args.cache_dir)], fetch=True, output=sources.SOURCE_PATHS,
        )
    except ArtifactLockBusy as exc:
        # The profiles are written: only the record waits for the other run.
        print(
            f"source paths not refreshed ({exc}): run python scripts/site_sources.py "
            "--fetch once it finishes",
            file=sys.stderr,
        )
        return
    print(
        f"source paths: {sum(map(len, held.values()))} in {len(held)} trees, "
        f"{len(unread)} trees not cached: {sources.SOURCE_PATHS}",
        file=sys.stderr,
    )
