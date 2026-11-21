"""Hardware targets: the cores each target of a platform can run."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from core.paths import PLATFORMS_DIR, REPO_ROOT
from core.cli import SourceUnreadable, suggest_names
from model.sources import source_yaml_file


def read_target_overrides(targets_dir: str | os.PathLike[str]) -> dict:
    """The whole _overrides.yml of a targets directory, {} without one."""
    overrides_file = os.path.join(targets_dir, "_overrides.yml")
    if not os.path.exists(overrides_file):
        return {}
    return source_yaml_file(overrides_file) or {}


def platform_overrides(all_overrides: dict, platform: str) -> dict:
    """The per-target entries of _overrides.yml for one platform, an empty
    value read as no entry."""
    return ((all_overrides.get(platform) or {}).get("targets")) or {}


def target_overrides(platform: str, targets_dir: str | os.PathLike[str]) -> dict:
    """One platform's per-target entries, read from its targets directory."""
    return platform_overrides(read_target_overrides(targets_dir), platform)


def not_cores(
    platform: str, targets_dir: str | os.PathLike[str] = REPO_ROOT / PLATFORMS_DIR / "targets",
) -> set[str]:
    """Names a platform's system list files under an emulator that are not
    emulators (machine selectors, video plugins, launchers): its
    `_default.remove_cores` overrides."""
    default = target_overrides(platform, targets_dir).get("_default") or {}
    return {str(name) for name in default.get("remove_cores") or []}


def target_aliases(overrides: dict, target: str) -> list[str]:
    """The other names a target answers to: the pack builder and the
    installer read this one list, or the installer refuses a word the pack
    accepts."""
    return [
        alias for alias in (overrides.get(target) or {}).get("aliases") or []
        if isinstance(alias, str)
    ]


def _target_alias_index(targets: dict, overrides: dict) -> dict[str, str]:
    """Every name a target answers to, mapped to the name its file uses."""
    alias_index: dict[str, str] = {}
    for tname in targets:
        alias_index[tname] = tname
        for alias in target_aliases(overrides, tname):
            alias_index[alias] = tname
    return alias_index


def _platform_targets(platform: str, targets_dir: str) -> dict | None:
    """The `targets:` mapping of a platform's targets file, None without one."""
    target_file = os.path.join(targets_dir, f"{platform}.yml")
    if not os.path.exists(target_file):
        return None
    return (source_yaml_file(target_file) or {}).get("targets", {})


def platform_files_target(platform: str, target: str, platforms_dir: str = PLATFORMS_DIR) -> bool:
    """Whether the platform's targets file knows this target, by any alias."""
    targets_dir = os.path.join(platforms_dir, "targets")
    targets = _platform_targets(platform, targets_dir)
    if targets is None:
        return False
    return target in _target_alias_index(targets, target_overrides(platform, targets_dir))


def canonical_target_name(
    platforms: list[str], target: str, platforms_dir: str = PLATFORMS_DIR
) -> str:
    """The name a target is filed under, whichever alias was typed.

    `switch`, `nx` and `nintendo-switch` named three packs of one target, and
    --verify-packs looked for a name no build had written. The typed name is
    kept when no platform knows it or when platforms file it differently.
    """
    targets_dir = os.path.join(platforms_dir, "targets")
    all_overrides = read_target_overrides(targets_dir)
    found: set[str] = set()
    for platform_name in platforms:
        targets = _platform_targets(platform_name, targets_dir)
        if targets is None:
            continue
        canonical = _target_alias_index(
            targets, platform_overrides(all_overrides, platform_name)
        ).get(target)
        if canonical:
            found.add(canonical)
    return found.pop() if len(found) == 1 else target


def truth_target_dir(
    output_dir: str, platforms: list[str], target: str, platforms_dir: str = PLATFORMS_DIR
) -> str:
    """Where a target-narrowed truth model is written and read.

    Slugged from the name the target is filed under: `nx`, `switch` and
    `nintendo-switch` wrote three copies of one model, and a run under one
    alias left the others stale beside it. Called per platform, since two
    platforms can file one name differently (Lakka builds an image named
    switch). generate_truth writes here and diff_truth reads here.
    """
    named = canonical_target_name(platforms, target, platforms_dir)
    slug = re.sub(r"[^a-z0-9]+", "-", named.strip().lower()).strip("-")
    return os.path.join(output_dir, slug or "target")


def load_target_config(
    platform_name: str,
    target: str,
    platforms_dir: str = PLATFORMS_DIR,
) -> set[str] | None:
    """Load target config and return the set of core names for the given target.

    Resolves aliases from _overrides.yml, applies add_cores/remove_cores.
    A target whose cores are null runs every core the platform declares and
    returns None, which filters nothing: the platforms with a single target
    (RetroBat on Windows, RetroDECK, RomM in the browser) kept a hand list
    that dropped 98 RetroBat cores and 300 RetroDECK ones.
    Raises ValueError if target is unknown (with list of available targets).
    Raises FileNotFoundError if no target file exists for the platform.
    """
    targets_dir = os.path.join(platforms_dir, "targets")
    targets = _platform_targets(platform_name, targets_dir)
    if targets is None:
        # The expected state for a platform that ships one build, said as
        # such: the file path read like a file missing from the repository.
        with_targets = sorted(
            Path(f).stem for f in os.listdir(targets_dir)
            if f.endswith(".yml") and not f.startswith("_")
        )
        raise FileNotFoundError(
            f"{platform_name} has no hardware targets: drop --target "
            f"(platforms with targets: {', '.join(with_targets)})"
        )
    overrides = target_overrides(platform_name, targets_dir)
    alias_index = _target_alias_index(targets, overrides)

    canonical = alias_index.get(target)
    if canonical is None:
        # A typo got the 30 targets and 18 aliases in two lines to read
        # through, where a platform or emulator name gets the closest ones.
        raise ValueError(
            f"Unknown target '{target}' for platform '{platform_name}'.\n"
            # Named as a full command: cross_reference.py and slots.py take
            # --target but have no --list-targets of their own.
            + suggest_names(
                [target], sorted(alias_index),
                f"python scripts/verify.py --platform {platform_name} --list-targets", len(targets),
            )
        )

    return _target_core_set(targets[canonical] or {}, overrides, canonical, platforms_dir)


def _target_core_set(
    entry: dict, overrides: dict, target: str, platforms_dir: str
) -> set[str] | None:
    """A target's cores: what the board builds, overrides applied, and the
    buildbot cores its RetroArch core downloader installs (`downloads`, a
    RetroArch targets entry), which a Batocera x86_64 or armv7 board can
    fetch from its menu."""
    declared = entry.get("cores")
    if declared is None:
        return None
    cores = apply_target_overrides({str(c) for c in declared}, overrides, target)
    downloads = entry.get("downloads")
    if downloads:
        cores |= load_target_config("retroarch", str(downloads), platforms_dir) or set()
    return cores


def apply_target_overrides(
    cores: set[str], overrides: dict, target: str
) -> set[str]:
    """Cores of one target once the platform's overrides are applied.

    ``_default`` applies to every target of the platform, then the target's
    own entry: a name the scraper reads as a core on every board (a machine
    variant, a launcher) is written once instead of once per board.
    """
    result = set(cores)
    for scope in ("_default", target):
        entry = overrides.get(scope) or {}
        result |= {str(c) for c in entry.get("add_cores") or []}
        result -= {str(c) for c in entry.get("remove_cores") or []}
    return result


def list_available_targets(
    platform_name: str,
    platforms_dir: str = PLATFORMS_DIR,
) -> list[dict]:
    """List available targets for a platform with their aliases.

    Returns list of dicts with keys: name, architecture, core_count, aliases.
    Returns empty list if no target file exists.
    """
    targets_dir = os.path.join(platforms_dir, "targets")
    targets = _platform_targets(platform_name, targets_dir)
    if targets is None:
        return []

    # The count --target filters on: overrides applied, as load_target_config
    # applies them. The scraped list counted Batocera's machine variants and
    # launchers, 198 cores shown for 187 used.
    overrides = target_overrides(platform_name, targets_dir)

    result = []
    for tname, tdata in sorted(targets.items()):
        aliases = target_aliases(overrides, tname)
        # None: the target runs every core the platform declares.
        found = _target_core_set(tdata or {}, overrides, tname, platforms_dir)
        count = None if found is None else len(found)
        result.append(
            {
                "name": tname,
                "architecture": (tdata or {}).get("architecture", ""),
                "core_count": count,
                "aliases": aliases,
            }
        )
    return result


def target_listing_line(row: dict) -> str:
    """One --list-targets row, as verify and generate_pack print it."""
    aliases = f" (aliases: {', '.join(row['aliases'])})" if row["aliases"] else ""
    count = "all" if row["core_count"] is None else str(row["core_count"])
    return f"  {row['name']:30s} {row['architecture']:10s} {count:>4s} cores{aliases}"


def build_target_cores_cache(
    platforms: list[str],
    target: str,
    platforms_dir: str,
    is_all: bool = False,
) -> tuple[dict[str, set[str] | None], list[str], list[str]]:
    """Build target cores cache for a list of platforms.

    Returns (cache dict, platforms kept after skipping failures, one note per
    skipped platform for a command line to print).
    A platform without a targets file cannot honour the target and is left
    out with the others, never run unfiltered, and a target no platform knows
    is refused: `--all --target swtich` checked BizHawk and MiSTer whole and
    exited 0, a green run that said nothing about the Switch.
    """
    cache: dict[str, set[str] | None] = {}
    skip: list[str] = []
    notes: list[str] = []
    for p in platforms:
        try:
            cache[p] = load_target_config(p, target, platforms_dir)
        except FileNotFoundError:
            if not is_all:
                raise
            notes.append(f"INFO: Skipping {p}: no hardware targets")
            skip.append(p)
        except SourceUnreadable:
            # A damaged targets file is not a platform without the target.
            raise
        except ValueError as e:
            if is_all:
                notes.append(f"INFO: Skipping {p}: {e}")
                skip.append(p)
            else:
                raise
    kept = [p for p in platforms if p not in skip]
    if is_all and platforms and not kept:
        # The seventeen per-platform lines buried the one suggestion that
        # mattered: the refusal names the closest target across them all.
        raise ValueError(_unknown_target_message(target, platforms, platforms_dir))
    return cache, kept, notes


def target_scope(
    platforms: list[str],
    target: str | None,
    platforms_dir: str,
    is_all: bool = False,
) -> tuple[dict[str, set[str] | None], list[str]]:
    """build_target_cores_cache for a command line: no target keeps every
    platform unfiltered, a refused target ends the run with its reason."""
    if not target:
        return {}, platforms
    try:
        cache, kept, notes = build_target_cores_cache(
            platforms, target, platforms_dir, is_all=is_all
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    # On stderr: slots --json printed them ahead of its document.
    for note in notes:
        print(note, file=sys.stderr)
    return cache, kept


def _unknown_target_message(target: str, platforms: list[str], platforms_dir: str) -> str:
    """A target no platform has, with the closest names any of them knows."""
    import difflib

    targets_dir = os.path.join(platforms_dir, "targets")
    all_overrides = read_target_overrides(targets_dir)
    owners: dict[str, list[str]] = {}
    for platform in platforms:
        targets = _platform_targets(platform, targets_dir)
        if targets is None:
            continue
        overrides = platform_overrides(all_overrides, platform)
        for name in _target_alias_index(targets, overrides):
            owners.setdefault(name, []).append(platform)
    message = f"unknown target '{target}': no platform has it."
    close = difflib.get_close_matches(target, sorted(owners), n=3, cutoff=0.6)
    if close:
        named = ", ".join(f"{n} ({', '.join(sorted(owners[n]))})" for n in close)
        return f"{message} Close matches: {named}."
    return (f"{message} python scripts/verify.py --platform <name> --list-targets "
            "lists the targets of one platform.")
