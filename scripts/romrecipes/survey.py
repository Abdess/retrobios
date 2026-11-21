"""The recipe survey: recipes and ROM atoms counted, archives identified, missing pins attempted."""

from __future__ import annotations

from pathlib import Path

from model.profiles import load_emulator_profiles
from romrecipes.identify import identify_report, missing_report, write_reconstructions
from romrecipes.pool import DIGEST_CACHE, AtomPool
from romrecipes.romsets import collect_recipes, load_dat_recipes, merge_recipes


def survey_modes(identify: bool, missing: bool, write: bool) -> tuple[bool, bool]:
    """Which reports run: both by default, and the missing pins whenever *write*.

    The reconstructions --write saves are those of the missing pins: with
    --identify alone beside it, nothing ran them, nothing was written, and
    the run exited 0.
    """
    if write:
        missing = True
    if not identify and not missing:
        identify = missing = True
    return identify, missing


def survey(
    bios_dir: Path,
    emulators_dir: str,
    dat_recipes_path: str,
    platforms_dir: str,
    db: dict,
    *,
    identify: bool,
    missing: bool,
    write: bool,
) -> dict:
    """Recipe and atom counts, then the identification and missing-pin reports asked for."""
    profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    profile_recipes = collect_recipes(profiles)
    dat_recipes = load_dat_recipes(dat_recipes_path)
    recipes = merge_recipes(profile_recipes, dat_recipes)
    pool = AtomPool(bios_dir, DIGEST_CACHE, db)

    result: dict = {
        "recipes": sum(len(v) for v in recipes.values()),
        "profile_recipes": sum(len(v) for v in profile_recipes.values()),
        "dat_recipes": sum(len(v) for v in dat_recipes.values()),
        "archives_with_recipes": len(recipes),
        "atoms": len(pool),
    }
    if pool.unreadable:
        result["unreadable_archives"] = pool.unreadable
    if identify:
        result["identify"] = identify_report(recipes, pool, db)
    if missing:
        result["missing"] = missing_report(recipes, pool, db, platforms_dir)
        if write:
            result["written"] = write_reconstructions(
                result["missing"]["constructible"], recipes, pool, bios_dir, db,
            )

    pool.save_digests()
    return result
