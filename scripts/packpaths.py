"""Where a file lands inside a pack.

Two files may not claim the same destination, and a destination may
not sit inside another file's path: a pack that cannot be extracted
on Windows is not a pack."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from common import sanitize_pack_path
from validation import read_from_save_dir


@dataclass(frozen=True)
class SaveLayout:
    """Where a platform's frontend keeps the save directory it hands a core.

    ``folder`` names it twice: the folder of the pack that holds the files
    read below it, and its default place relative to the folder holding the
    system directory (RetroArch's own folder holds system/ and saves/,
    EmuDeck's Emulation/ holds bios/ and saves/retroarch/saves/). A pack is
    extracted into the system directory, so that folder is moved by hand,
    and the installer writes to the save directory the frontend's config
    names.
    ``by_core`` is set when the frontend hands each core <save
    directory>/<library_name>, RetroArch's sort_savefiles_enable.
    ``by_system`` is set when the launcher hands a core <save
    directory>/<system>, the system it was launched for (Batocera's
    /userdata/saves/<system>): a file read there is placed once for each
    system that runs the core, the systems the platform file names in
    ``libretro_systems``. ``by_core_for`` names the cores a launcher
    sorts by core where it sorts no other. ``pack_folder`` renames the
    pack's folder when the BIOS tree holds one of the same name.
    """

    folder: str
    by_core: bool
    by_system: bool = False
    by_core_for: frozenset[str] = frozenset()
    pack_folder: str = ""

    @property
    def in_pack(self) -> str:
        """The pack folder holding these files: ``pack_folder`` where the
        platform's own BIOS tree already has a folder named ``folder``
        (Batocera lists bios/saves/dolphin-emu/Triforce/segaboot.gcm),
        ``folder`` otherwise."""
        return self.pack_folder or self.folder

    def sorts(self, names: Iterable[str]) -> bool:
        """Whether the frontend inserts the core's folder for a core known
        by any of these names: always where it sorts saves by core, else
        only for the cores its launcher sorts (``by_core_for``, RetroBat's
        CoreSaveSort)."""
        return self.by_core or bool(self.by_core_for & {str(n) for n in names})


def save_layout(config: dict) -> SaveLayout | None:
    """The platform's save directory, or None when it is no fixed place.

    Read from the registry's ``save_directory``. A platform that keeps
    saves beside the content has none: a file read below it has no single
    destination. ``folder`` is a relative path, never one that climbs.
    """
    block = config.get("save_directory")
    if not isinstance(block, dict):
        return None
    raw = str(block.get("folder") or "")
    folder = sanitize_pack_path(raw)
    if not folder or folder != raw:
        return None
    return SaveLayout(
        folder, bool(block.get("by_core")), bool(block.get("by_system")),
        frozenset(str(core) for core in block.get("by_core_for") or []),
        sanitize_pack_path(str(block.get("pack_folder") or "")),
    )


def save_destination(
    path: str, core_folder: str | None, layout: SaveLayout, system: str = "",
    sorted_by_core: bool | None = None,
) -> str | None:
    """The pack path of a file a core reads below the save directory.

    ``path`` is relative to the directory the core is handed. ``core_folder``
    is the folder a frontend sorting saves by core inserts: the core's
    library_name, empty when it inserts none (an empty library_name, or a
    core that reads the same place sorted or not), None when the profile
    does not say. None then, where the frontend sorts by core. ``system``
    is the folder a launcher saving by system inserts first, required
    where the layout is ``by_system``. ``sorted_by_core`` says whether the
    frontend sorts this core's saves, the layout's ``by_core`` by default.
    """
    rel = sanitize_pack_path(path)
    if not rel:
        return None
    root = layout.in_pack
    if layout.by_system:
        folder = sanitize_pack_path(system)
        if not folder or "/" in folder:
            return None
        root = f"{root}/{folder}"
    by_core = layout.by_core if sorted_by_core is None else sorted_by_core
    if by_core and core_folder:
        return f"{root}/{sanitize_pack_path(core_folder)}/{rel}"
    if by_core and core_folder is None:
        return None
    return f"{root}/{rel}"


def libretro_systems(config: dict, names: Iterable[str]) -> list[str]:
    """The systems a platform runs any of these libretro core names for.

    Read from the platform file's ``libretro_systems`` (core -> the systems
    whose launch offers it), which the platform's scraper writes from its
    system list. Sorted, each once.
    """
    table = config.get("libretro_systems") or {}
    found: set[str] = set()
    for name in names:
        found.update(str(system) for system in table.get(str(name)) or [])
    return sorted(found)


def core_save_folder(profile: dict) -> str | None:
    """The folder a frontend sorting saves by core inserts for this core.

    RetroArch appends a non-empty library_name only (runloop.c
    runloop_path_set_redirect). A core declaring ``save_folder_once`` adds
    its own folder to the save directory unless it is already named so
    (Cemu's in_named_dir): its paths start with that folder and land in the
    same place sorted or not. None when the profile names no library_name.
    """
    if "library_name" not in profile:
        return None
    if profile.get("save_folder_once"):
        return ""
    return str(profile.get("library_name") or "")


# Top folder of an emulator pack holding the files a libretro core reads
# below the frontend's save directory, apart from those of its system
# directory at the root.
EMULATOR_PACK_SAVE_FOLDER = "saves"


def _path_parents(dest: str) -> list[str]:
    """Return all parent directory segments of a path."""
    parts = dest.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]

def _has_path_conflict(dest: str, seen_files: set[str], seen_parents: set[str]) -> bool:
    """Check if dest conflicts with existing paths (file vs directory).

    Returns True if adding dest would create an impossible extraction:
    - A parent of dest is already a file (e.g., adding X/Y when X is a file)
    - dest itself is already used as a directory (e.g., adding X when X/Y exists)
    """
    for parent in _path_parents(dest):
        if parent in seen_files:
            return True
    if dest in seen_parents:
        return True
    return False

def placement_block(
    dest: str,
    seen_files: set[str],
    seen_lower: set[str],
    seen_parents: set[str],
    case_insensitive: bool,
) -> str | None:
    """Why a destination cannot take a file in this pack, or None.

    The one rule the builder applies to a core extra and the report replays:
    counted apart, the report called a skipped file packed.
    """
    if dest in seen_files:
        return "taken"
    if case_insensitive and dest.lower() in seen_lower:
        return "case_twin"
    if _has_path_conflict(dest, seen_files, seen_parents):
        return "path_conflict"
    return None


def _register_path(dest: str, seen_files: set[str], seen_parents: set[str]) -> None:
    """Track a file path and its parent directories."""
    seen_files.add(dest)
    for parent in _path_parents(dest):
        seen_parents.add(parent)

# Android's media scanner hides a folder holding a .nomedia file, and every
# folder below it (MediaProvider a183e2b9, FileUtils.java:1587-1629
# isDirectoryHidden, ModernMediaScanner.java:845-846). RetroArch writes none
# (libretro-common/file/file_path_io.c:194 only skips one), so a pack
# unzipped into RetroArch Android's system folder put its samples, overlays
# and videos in the gallery and music apps.
MEDIA_MARKER = ".nomedia"


def lands_on_android(target_names: Iterable[str], target: str | None) -> bool:
    """Whether a pack can be unzipped on Android: its target is an Android
    one, or, unfiltered, the platform files one."""
    if target:
        return target.startswith("android")
    return any(name.startswith("android") for name in target_names)


def _flat(arcname: str, prefix: str, flatten: bool) -> str:
    """Strip base_destination prefix from ZIP arcname when flattening."""
    if flatten and prefix and arcname.startswith(prefix + "/"):
        return arcname[len(prefix) + 1:]
    return arcname

def _resolve_destination(file_entry: dict, standalone: bool) -> str:
    """Resolve the ZIP destination path for a file entry.

    ``path:`` is where the libretro build reads the file from the system
    directory and ``standalone_path:`` where the standalone app reads it, so
    a file's destination is written whole. ``pack_structure`` places a
    profile's data directories and archives: prefixing files with it gave
    PPSSPP/PPSSPP/ppge_atlas.zim, and the platform packs, which never read
    it, put libretro Dolphin's IPL at the root of system/.
    """
    # 1. standalone_path override
    if standalone and file_entry.get("standalone_path"):
        rel = file_entry["standalone_path"]
    # 2. path field
    elif file_entry.get("path"):
        rel = file_entry["path"]
    # 3. name fallback
    else:
        rel = file_entry.get("name", "")

    dest = sanitize_pack_path(rel)
    # Read below the frontend's save directory: kept apart from the system
    # directory's files at the root, in the folder the pack names for it.
    if dest and read_from_save_dir(file_entry, standalone):
        return f"{EMULATOR_PACK_SAVE_FOLDER}/{dest}"
    return dest


def _archive_destination(
    archive_name: str, archive_prefix: str, pack_structure: dict | None, standalone: bool
) -> str:
    """Where an emulator pack places one of the profile's archives."""
    archive_dest = sanitize_pack_path(archive_name)
    if archive_prefix:
        archive_dest = f"{archive_prefix}/{archive_dest}"
    prefix = (pack_structure or {}).get("standalone" if standalone else "libretro", "")
    return f"{prefix}/{archive_dest}" if prefix else archive_dest
