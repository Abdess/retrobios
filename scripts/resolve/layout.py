"""Where a platform's launch code puts a file: system directories and standalone layout paths."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

from model.profiles import profile_names

if TYPE_CHECKING:
    from resolve.launches import PlatformLaunches


# The key, in a platform's system file index, of a machine a launcher record offers.
MACHINE_KEY = "machine:"


def core_system_dirs(
    emu_name: str, profile: dict, launches: PlatformLaunches
) -> list[str] | None:
    """The system directories a platform hands this libretro core, or None.

    None when the platform declares no per-core directory: the core reads
    the one system directory every core shares. A platform that declares
    them (MinUI hands each launch tag its own Bios/<TAG>/) gives a core it
    lists no directory at all, so the list is then empty.
    """
    if not launches.core_dirs:
        return None
    names = set(profile_names(emu_name, profile))
    return sorted({directory for core, directory in launches.core_dirs if core in names})


def system_dir_view(profile: dict, directory: str) -> dict:
    """The profile as a core reads it from one handed system directory.

    Each file keeps its own path, relative to the system directory, and
    carries the directory: destinations put it in front, resolution takes
    it off again (resolve_local_file), so the collection is still searched
    by the core's own path. A core's archive subfolder moves with it.
    """
    view = {
        **profile,
        "files": [
            {**f, "system_dir": directory} if isinstance(f, dict) else f
            for f in profile.get("files") or []
        ],
    }
    if profile.get("archive_prefix"):
        view["archive_prefix"] = f"{directory}/{profile['archive_prefix']}"
    return view


def system_dir_path(entry: dict, path: str) -> str:
    """``path`` below the system directory the entry carries, if any."""
    directory = entry.get("system_dir")
    return f"{directory}/{path}" if directory else path


def entry_launch_systems(entry: dict, index: Mapping[str, set[str]]) -> frozenset[str]:
    """The platform systems, by our ids, that launch the emulator for an entry.

    The systems the entry names, and those under which the platform declares
    a file of one of its names (``index``, PlatformLaunches.system_file_index):
    Recalbox lists XRoar's coco3.rom under trs80coco, which our coco is.
    """
    systems = {str(s) for s in entry.get("systems") or []}
    if entry.get("system"):
        systems.add(str(entry["system"]))
    for name in [entry.get("name"), *(entry.get("aliases") or [])]:
        if name:
            systems |= index.get(str(name).lower(), set())
    return frozenset(systems)


# Why a standalone entry has no destination on a platform that relocates its
# layout: the manifest's omission reason, named as the installer words it.
OUTSIDE_BIOS_FOLDER = "outside_bios_folder"


def standalone_layout_path(entry: dict, profile: dict) -> str | None:
    """The path of an entry relative to the directories its standalone build declares.

    ``standalone_path`` when the entry has one. A profile with no libretro
    build has one layout, so its ``path`` is that layout: UAE4All2 reads
    kickstarts/kick13.rom below its working directory. So does an entry only
    the standalone build reads (``mode: standalone``), whose destination is
    its ``path``: Dolphin's Load/Firmware/rtl_bt/ under its User directory.
    """
    own = entry.get("standalone_path")
    if own:
        return own
    if "libretro" in str(profile.get("type", "")) and entry.get("mode") != "standalone":
        return None
    return entry.get("path") or None


def _names_entry(pattern: str, entry: dict) -> bool:
    """Whether an ``outside_data_root`` pattern names this entry: ``*``, a
    path or standalone_path prefix ending in ``/``, or a name."""
    if pattern == "*":
        return True
    if pattern.endswith("/"):
        return any(str(entry.get(key) or "").startswith(pattern)
                   for key in ("path", "standalone_path"))
    return entry.get("name") == pattern


def outside_data_root(profile: dict, entry: dict) -> set[str]:
    """The data_root keys on which the app reads this entry from another
    folder than data_root: every key ({"*"}), some, or none."""
    keys: set[str] = set()
    for rule in profile.get("outside_data_root") or ():
        if any(_names_entry(pattern, entry) for pattern in rule.get("files") or ()):
            keys |= set(rule.get("systems") or ()) or {"*"}
    return keys


def data_root_place(profile: dict, entry: dict, key: str = "") -> str:
    """The path under data_root where the standalone app reads this entry, or "".

    Nothing for a profile without data_root, an entry the libretro core alone
    reads, or one the profile's ``outside_data_root`` lists (on ``key``, or on
    any key when ``key`` is empty). The site prints this place and the
    installer copies the file there, so both read it here.
    """
    if not isinstance(entry, dict) or not profile.get("data_root"):
        return ""
    if entry.get("mode") == "libretro":
        return ""
    excluded = outside_data_root(profile, entry)
    if "*" in excluded or (key in excluded if key else excluded):
        return ""
    return str(standalone_layout_path(entry, profile) or "")


def standalone_destination(
    entry: dict, profile: dict, bindings: dict[str, tuple[str, str]]
) -> tuple[str, str] | None:
    """Where a platform puts a standalone entry: (tree, path).

    ``bindings`` are the places the platform's launchers give the layout
    (launchers.standalone_bindings): RetroPie and ROCKNIX give Flycast bios/dc,
    EmuDeck bios/flycast/bios, RetroPie gives UAE4All2's kickstarts/ bios/amiga,
    ROCKNIX runs PICO-8 from roms/pico-8. The tree is launchers.BIOS_TREE or
    launchers.ROMS_TREE. None when no binding covers the entry.
    """
    layout = standalone_layout_path(entry, profile)
    if layout is None or not bindings:
        return None
    from resolve.launchers import bound_path

    return bound_path(layout, bindings)


def standalone_bindings_for(
    emu_name: str, profile: dict, launches: PlatformLaunches,
    systems: Iterable[str] = (),
) -> dict[str, tuple[str, str]]:
    """The places a platform gives this emulator's standalone layout, by subfolder.

    ``systems`` are those the entry is launched for (entry_launch_systems).
    """
    from resolve.launchers import directory_handles, pool_folders, standalone_bindings

    declared = directory_handles(profile)
    pools = pool_folders(profile)
    if not declared and not pools:
        return {}

    names = set(profile_names(emu_name, profile))
    layout = [
        path for f in profile.get("files") or []
        if isinstance(f, dict) and (path := standalone_layout_path(f, profile))
    ]
    return standalone_bindings(
        names, declared, launches.handed, launches.executed, layout,
        pools, systems,
    )


def placed_entry(entry: dict, profile: dict, placed: tuple[str, str]) -> dict:
    """A standalone entry moved to the (tree, path) a platform reads it from."""
    tree, path = placed
    moved = {**entry, "standalone_path": path,
             "layout_path": standalone_layout_path(entry, profile)}
    if entry.get("load_from"):
        # The build's own root no longer applies: RetroDECK hands
        # Cemu's MLC, read from its data directory, to bios/cemu.
        load_from = entry["load_from"]
        moved["load_from"] = {
            **(load_from if isinstance(load_from, dict) else {"libretro": load_from}),
            "standalone": "system_dir",
        }
    if tree == "install":
        # Below the roms root inside the install tree (AmberELEC's
        # /storage/roms): a plain dest the platform prefix skips.
        return {**moved, "unprefixed": True}
    # A file the launcher runs from the roms directory (ROCKNIX's
    # roms/pico-8) or an emulator folder (RetroBat's emulators/pico8)
    # is relative to it, and says so.
    return {**moved, "root": tree} if tree else moved
