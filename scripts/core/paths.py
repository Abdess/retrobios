"""The repository root, and pack-relative destinations normalized the same way by every reader."""

from __future__ import annotations

from pathlib import Path


# The repository: scripts/core/ is two levels below it.
REPO_ROOT = Path(__file__).resolve().parents[2]


# The inputs a command reads unless told otherwise, relative to the
# repository root it runs from.
DB_FILE = "database.json"
PLATFORMS_DIR = "platforms"
EMULATORS_DIR = "emulators"
BIOS_DIR = "bios"
RECIPES_DIR = "recipes"
# The data directory registry refresh_data_dirs, the packs and the checks read.
DATA_DIRS_FILE = f"{PLATFORMS_DIR}/_data_dirs.yml"
# Where generate_truth writes its models and diff_truth and export_native read them.
TRUTH_DIR = "dist/truth"
# The unattended runner's home, and the worktree it commits from, which disk
# cleanup must never take for an idle session worktree.
AUTORUN_DIR = ".cache/autorun"
AUTORUN_WORKTREE = f"{AUTORUN_DIR}/worktree"


def sanitize_pack_path(raw: str) -> str:
    """Strip traversal components from a relative destination.

    The builder and the coverage report key their region grouping on this
    value, so they have to derive it the same way: a destination normalized on
    one side only would be looked up under a key the other side never emits.
    """
    raw = raw.replace("\\", "/")
    return "/".join(p for p in raw.split("/") if p and p not in ("..", "."))


def comparable_destination(destination: str, fold: bool = True) -> str:
    """Comparable form of a destination, since layers write it differently.

    Case is folded only where the platform's filesystem folds it: on Linux
    RetroDECK ships bios/DISK.ROM and bios/disk.rom side by side.
    """
    cleaned = destination.strip().strip("/").replace("\\", "/")
    return cleaned.casefold() if fold else cleaned


def declared_destination(entry: dict) -> str:
    """The destination a declaration names, its name when it names none,
    normalized as sanitize_pack_path does: the key the builder, the manifest
    and verify all file a declaration under."""
    return sanitize_pack_path(entry.get("destination", entry.get("name", "")))
