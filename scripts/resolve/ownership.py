"""Which emulator, engine or manufacturer a path of the collection belongs to."""

from __future__ import annotations

import re

from core.memo import DerivedView
from model.manufacturers import manufacturer_slug


# bios/Other/<emulator> and bios/Arcade/<emulator or board> file a copy by
# who loads it, not by machine.
BUCKET_FOLDERS = frozenset({"Other", "Arcade"})


def names_manufacturer(sys_id: str, manufacturer: str) -> bool:
    """Whether a system id names a maker folder: nec-pc-88 names NEC."""
    slug = manufacturer_slug(manufacturer)
    return sys_id == slug or sys_id.startswith(f"{slug}-")


def maker_folder(path: str, bios_dir: str) -> str | None:
    """The bios/<maker>/ folder a collection path is filed under."""
    prefix = f"{bios_dir.rstrip('/')}/"
    if not path.startswith(prefix):
        return None
    return maker_of_relative(path[len(prefix):])


def maker_of_relative(relative: str) -> str | None:
    """The maker folder of a path relative to the BIOS directory, None for a
    file sitting at its root."""
    parts = relative.split("/")
    return parts[0] if len(parts) >= 2 else None


def _filed_maker_folders(files_db: dict, bios_dir: str) -> frozenset[str]:
    return frozenset(
        folder
        for entry in files_db.values()
        if (folder := maker_folder(str(entry.get("path", "")), bios_dir))
        and folder not in BUCKET_FOLDERS
    )


_maker_folders_view = DerivedView(_filed_maker_folders)


def _maker_folders(db: dict) -> frozenset[str]:
    """Every maker folder the collection files a copy under."""
    return _maker_folders_view(db.get("files", {}), str(db.get("bios_dir") or "bios"))


def system_makers(file_entry: dict, db: dict) -> frozenset[str]:
    """The maker folders a platform entry's system names.

    Only a platform's own entry is asked: one that names an owning emulator
    is placed by that emulator's tree. Empty when the system names no maker
    (pc88, arcade), so nothing is narrowed there.
    """
    sys_id = str(file_entry.get("platform_system") or "")
    if not sys_id or owner_tokens(file_entry):
        return frozenset()
    return makers_named_by(sys_id, db)


def makers_named_by(sys_id: str, db: dict) -> frozenset[str]:
    """The maker folders a system id names: nintendo-gba names Nintendo."""
    return frozenset(
        folder for folder in _maker_folders(db) if names_manufacturer(sys_id, folder)
    )


def other_maker(path: str, makers: frozenset[str], db: dict) -> bool:
    """Whether a path is filed under a maker the entry's system does not name."""
    if not makers:
        return False
    folder = maker_folder(path, str(db.get("bios_dir") or "bios"))
    return folder is not None and folder not in BUCKET_FOLDERS and folder not in makers


def affinity_tokens(text: str) -> set[str]:
    return {
        token
        for token in (re.sub(r"[^0-9a-z]", "", part.casefold()) for part in text.split("/"))
        if token
    }


def owner_tokens(file_entry: dict) -> set[str]:
    """Tokens naming the profile that asks for the file.

    A profile named after another with a suffix (cxbx-reloaded-2023,
    mame4droid-2024) is a release of that emulator, and the tree named by
    the shorter name is its own: cxbx-reloaded-2023 was served xemu's
    encrypted EEPROM because bios/Other/cxbx-reloaded/ read as foreign.
    Only whole leading words count, so dolphin-mmjr2 is not dolphin-mmjr.
    """
    tokens: set[str] = set()
    for owner in (file_entry.get("source_profile"), file_entry.get("source_emulator")):
        if owner:
            tokens |= affinity_tokens(str(owner).replace(" ", ""))
    profile = str(file_entry.get("source_profile") or "").casefold()
    words = [word for word in re.split(r"[^0-9a-z]+", profile) if word]
    tokens |= {"".join(words[:end]) for end in range(1, len(words))}
    return tokens


def foreign_tree(path: str, owners: set[str]) -> bool:
    """Whether a path lives in the tree of an emulator that is not the asker.

    bios/Other/<emulator>/ holds what one emulator ships. A same-named file
    found there answers that emulator's entry, not another's: EmuCoreX's
    unlock.wav was served from NetherSX2's tree, and upstream PCSX2's
    GameIndex.yaml from EmuCoreX's, while the system directory held a copy.
    """
    parts = path.split("/")
    if not owners or len(parts) < 4 or parts[0] != "bios" or parts[1] != "Other":
        return False
    return not (owners & affinity_tokens(parts[2]))


def engine_tree(path: str, owners: set[str]) -> bool:
    """Whether a path lives in another game's folder under bios/Game Engines/."""
    parts = path.split("/")
    if len(parts) < 4 or parts[0] != "bios" or parts[1] != "Game Engines":
        return False
    return not (owners & affinity_tokens(parts[2]))


def own_tree(path: str, owners: set[str]) -> bool:
    """Whether a path lives in the bios/Other/<emulator>/ tree of the asker."""
    parts = path.split("/")
    if not owners or len(parts) < 4 or parts[0] != "bios" or parts[1] != "Other":
        return False
    return bool(owners & affinity_tokens(parts[2]))
