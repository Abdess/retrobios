"""The launcher rows of a gap report: names read and not held, records left unproven."""

from __future__ import annotations

from model.platforms import load_platform_config
from model.registry import list_registered_platforms
from packs.crossref import launcher_reads_not_held
from resolve.launchers import LauncherLayer, launcher_unproven

# The --json key of the launcher reads category, beside the emulator keys.
LAUNCHER_READS_KEY = "_launcher_reads_not_held"
# The --json key of the launcher records a config file does not prove.
LAUNCHER_UNPROVEN_KEY = "_launcher_unproven"


def launcher_rows(
    selected: list[str] | None,
    platforms_dir: str,
    db: dict,
    all_profiles: dict[str, dict],
    registry: dict,
    emulator: str | None,
) -> tuple[list[dict], list[dict]]:
    """The names a launcher reads that the collection lacks, and the
    launcher records nothing proves."""
    configs = {
        name: load_platform_config(name, platforms_dir)
        for name in (selected or list_registered_platforms(platforms_dir))
    }
    # Counted apart from the profile gaps: a name only a launcher reads is
    # reported, not yet judged.
    launcher_reads = launcher_reads_not_held(
        configs, db, all_profiles, registry, emulator or "",
    )

    unproven = [
        row for row in launcher_unproven(configs, all_profiles)
        if not emulator or any(
            emulator in LauncherLayer._profiles_named(part, all_profiles, set(all_profiles))
            for part in row["emulator"].split(", ")
        )
    ]
    return launcher_reads, unproven
