"""Terminal text of the recipe survey, the archive capture and the archive builds."""

from __future__ import annotations

import sys
from collections import defaultdict

from romrecipes.build import BuildResult, BuildTally
from romrecipes.capture import CaptureRun


def print_survey(result: dict) -> None:
    """The survey counts, then each report it ran."""
    print(
        f"{result['archives_with_recipes']} archives described by "
        f"{result['recipes']} recipes "
        f"({result['profile_recipes']} from profiles, {result['dat_recipes']} from DATs), "
        f"{result['atoms']} ROM atoms available"
    )
    if not result["dat_recipes"]:
        print(
            "  No DAT recipe: import one with "
            "`python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0289`"
        )
    for problem in result.get("unreadable_archives", []):
        print(f"  UNREADABLE: {problem}")

    if "identify" in result:
        print_identification(result["identify"])

    if "missing" in result:
        print_missing(result["missing"])
        for path in result.get("written", []):
            print(f"  WROTE: {path}")


def print_identification(ident: dict) -> None:
    """Which recipe reproduces each local archive, counted by recipe."""
    print(
        f"\nIdentification: {len(ident['identified'])} archives reproduced "
        f"by a recipe, {len(ident['unidentified'])} unidentified"
    )
    print(
        "  The label is the oldest version producing these bytes: a recipe "
        "unchanged since 0.177 is counted there, not at its own version."
    )
    by_recipe: dict[str, int] = defaultdict(int)
    for record in ident["identified"]:
        by_recipe[record["recipe"]] += 1
    for label, count in sorted(by_recipe.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {label}: {count}")
    for record in ident["unidentified"][:10]:
        print(f"  UNIDENTIFIED: {record['path']}")


def print_missing(gap: dict) -> None:
    """The pinned archives the collection lacks, each one named."""
    print(
        f"\nPinned archives not held: "
        f"{len(gap['constructible'])} buildable, "
        f"{len(gap['unreproducible'])} not reproducible, "
        f"{len(gap['no_recipe'])} without a recipe"
    )
    for record in gap["constructible"]:
        print(
            f"  BUILDABLE: {record['archive']} md5={record['md5'][:8]} "
            f"via {record['recipe']} ({record['size']} bytes)"
        )
    # The acquisition targets: an archive pinned under several md5s is
    # one line, the platforms' own bundles rather than romsets.
    by_archive: dict[str, list[str]] = defaultdict(list)
    for record in gap["unreproducible"]:
        by_archive[record["archive"]].append(record["md5"][:8])
    for archive, md5s in sorted(by_archive.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"  NOT REPRODUCIBLE: {archive} ({len(md5s)} pinned: {', '.join(sorted(md5s))})")
    for record in gap["no_recipe"]:
        print(f"  NO RECIPE: {record['archive']} md5={record['md5'][:8]}")


def print_capture(run: CaptureRun, archives: str) -> None:
    """The archives a capture could not read, its counts and whether it wrote."""
    for path, reason in sorted(run.failed.items()):
        print(f"  UNREADABLE: {path}: {reason}", file=sys.stderr)
    counts = run.counts()
    print(
        f"{len(run.records)} archive recipes: {counts['exact']} exact, "
        f"{counts['canonical']} canonical; {counts['agreed']} agree with a profile or DAT "
        f"recipe, {counts['pinned']} pinned as bytes"
    )
    print(f"{'Wrote' if run.changed else 'Unchanged'} {archives}")


def print_build_result(result: BuildResult) -> None:
    """One line per built archive, one per member an impossible build lacks."""
    if result.status == "impossible":
        for member in result.missing:
            print(
                f"  IMPOSSIBLE: {result.path}: missing {member['name']} "
                f"({member['sha1']})"
            )
    elif result.status == "failed":
        print(f"  FAILED: {result.path}: {result.detail}")
    else:
        note = f" ({result.detail})" if result.detail else ""
        print(f"  {result.status.upper()}: {result.path}{note}")


def print_build_totals(tally: BuildTally, total: int) -> None:
    """The build run counted by status, and the members held only in their own archive."""
    counts = tally.counts
    print(
        f"\n{total} archives: {counts['exact']} rebuilt exact, "
        f"{counts['canonical']} canonical, {counts['impossible']} impossible, "
        f"{counts['failed']} failed"
    )
    print(
        f"  {len(tally.own)} of them read {tally.own_members} members from their "
        "own archive, held nowhere else in the collection"
    )
