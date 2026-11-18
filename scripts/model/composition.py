"""What the collection holds by tree area: systems, arcade sets, game data."""

from __future__ import annotations




# Trees that hold game and engine data rather than the system files of a
# machine: the engine trees, and the publishers whose games an engine runs.
GAME_DATA_TOPS = (
    "RPG Maker",
    "ScummVM",
    "Game Engines",
    "sdlpal",
    "Dinothawr",
    "3D Realms",
    "Apogee",
    "Blizzard",
    "Bungie",
    "Crack dot Com",
    "Electronic Arts",
    "Epic MegaGames",
    "Id Software",
    "Interplay",
    "Monolith",
    "Softdisk",
    "Toys for Bob",
    "Valve",
)


def composition_tier(path: str) -> str:
    """Which composition bucket a repository path belongs to."""
    parts = path.split("/")
    top = parts[1] if len(parts) > 1 else ""
    if top == "Arcade":
        return "arcade"
    if top in GAME_DATA_TOPS:
        return "game_data"
    return "systems"


def compute_composition(db: dict) -> dict:
    """File and byte counts by tree area.

    Three buckets, each re-derivable from paths alone: arcade ROM sets
    (Arcade/), game and engine data (the trees of GAME_DATA_TOPS), and
    console or computer system files (everything else).
    """
    buckets = {
        "systems": {"files": 0, "size_bytes": 0},
        "arcade": {"files": 0, "size_bytes": 0},
        "game_data": {"files": 0, "size_bytes": 0},
    }
    for entry in db.get("files", {}).values():
        bucket = buckets[composition_tier(entry.get("path", ""))]
        bucket["files"] += 1
        bucket["size_bytes"] += entry.get("size", 0)
    return buckets


def count_catalog_matched(db: dict) -> int:
    """System files byte-identical to a dump-preservation catalog entry.

    Scoped to the systems bucket, the denominator every surface pairs it
    with: No-Intro, Redump and TOSEC index console and computer dumps, so
    arcade ROM sets and engine data sit on neither side of the ratio.
    """
    return sum(
        1
        for entry in db.get("files", {}).values()
        if entry.get("provenance")
        and composition_tier(entry.get("path", "")) == "systems"
    )
