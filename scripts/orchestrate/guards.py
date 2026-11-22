"""The refusals the run makes before its first step: flags it would drop, offline inputs it lacks."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from core.paths import PLATFORMS_DIR, REPO_ROOT
from exporter.originals import DEFAULT_CACHE
from model.registry import load_data_dir_registry


def refuse_unapplied_flags(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    """A flag the run would drop is refused before any step.

    --all-variants builds every source itself, so a --source beside it is
    dropped; --skip-packs builds none, so both are, and step 5 does not run
    for --full-narrowings to widen, nor does it without a full pack.
    """
    # --source defaults to None so a typed `--source full` is seen: compared
    # with its default value, it went through beside the modes that refuse it.
    source_given = args.source is not None
    if args.all_variants and source_given:
        parser.error("--source is incompatible with --all-variants")
    if args.skip_packs:
        for flag, on in (("--source", source_given),
                         ("--all-variants", args.all_variants),
                         ("--full-narrowings", args.full_narrowings)):
            if on:
                parser.error(f"{flag} is incompatible with --skip-packs")
    # Step 5 compares the full pack, and --source platform or truth builds
    # none: the comparison is skipped and the flag had no effect.
    if args.full_narrowings and source_given and args.source != "full":
        parser.error(f"--full-narrowings is incompatible with --source {args.source}")
    if args.source is None:
        args.source = "full"


def refuse_offline_without_caches(
    parser: argparse.ArgumentParser, args: argparse.Namespace, platforms_dir: str = PLATFORMS_DIR,
) -> None:
    """An offline run that builds packs needs the data directories cached.

    On a fresh clone none is: --offline skips the refresh, and the run went
    through the database, verify and every pack before failing at the end
    of the build. Only an empty cache is refused here: with some cached, the
    packs decide which ones they need and the build names the rest. A
    relative cache is read from the repository root, where the steps run.
    """
    if not args.offline or args.skip_packs:
        return
    registry = load_data_dir_registry(platforms_dir)
    if registry and not any(
        e.get("local_cache") and os.path.isdir(os.path.join(REPO_ROOT, e["local_cache"]))
        for e in registry.values()
    ):
        parser.error(
            "no data directory is cached and --offline skips their refresh: run "
            "python scripts/refresh_data_dirs.py once, or drop --offline"
        )


def refuse_offline_export_without_originals(
    parser: argparse.ArgumentParser, args: argparse.Namespace,
    cache: str = DEFAULT_CACHE,
) -> None:
    """An offline run with --with-export needs each patched file cached.

    Seven formats carry code, so step 2e patches the platform's own file,
    which --offline does not fetch. On a fresh clone the database, verify
    and the truth model were built before step 2e failed on every one. A
    relative cache is read from the repository root, where step 2e runs.
    """
    if not (args.offline and args.with_export):
        return
    from exporter import discover_exporters

    lacking = sorted(
        name for name, exporter in discover_exporters().items()
        if exporter.needs_original() and not any(Path(REPO_ROOT, cache, name).glob("*"))
    )
    if lacking:
        parser.error(
            f"--with-export patches each platform's own file, and {cache}/ holds none "
            f"for {', '.join(lacking)}: run python scripts/export_native.py --all "
            "--refresh-cache once, or drop --offline"
        )
