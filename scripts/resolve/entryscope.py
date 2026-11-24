"""Where an entry is read and whether a build delivers it: system or save dir, build mode, gap scope."""

from __future__ import annotations

from collections.abc import Mapping

from core.paths import sanitize_pack_path
from resolve.archives import archive_members
from resolve.content import name_match_size_ok


def read_from_system_dir(file_entry: dict, standalone: bool = False) -> bool:
    """Whether the emulator reads this entry from the system directory.

    A file loaded from the save, content or working directory is not in the
    BIOS tree: no platform lists it, and the truth model must not ask a
    platform to declare it. Packs place one read below the save directory
    there (read_from_save_dir), never in the BIOS tree. Two builds can read one file from two
    places: libretro Dolphin keeps its User tree in the save directory, the
    standalone app in its own folder, so ``load_from`` can be keyed by build.
    """
    load_from = _load_from(file_entry, standalone)
    return not load_from or load_from == "system_dir"


def _load_from(file_entry: dict, standalone: bool) -> str:
    """The ``load_from`` value that applies to one build."""
    load_from = file_entry.get("load_from", "")
    if isinstance(load_from, dict):
        load_from = load_from.get("standalone" if standalone else "libretro", "")
    return load_from or ""


def read_from_save_dir(file_entry: dict, standalone: bool = False) -> bool:
    """Whether the libretro build reads this entry below the frontend's save
    directory, the one RETRO_ENVIRONMENT_GET_SAVE_DIRECTORY returns.

    ``path`` is then relative to that directory. A standalone app has no
    frontend to hand it one: its files are placed by ``standalone_path``.
    """
    return not standalone and _load_from(file_entry, False) == "save_dir"


def entry_root(file_entry: dict, standalone: bool = False) -> str:
    """The frontend directory an entry's ``path`` is relative to: ``save``
    for a file the libretro build reads below the save directory, else
    ``system``."""
    return "save" if read_from_save_dir(file_entry, standalone) else "system"


def outside_gap_scope(file_entry: dict, is_standalone: bool) -> bool:
    """Whether an entry is a file the platform's pack would carry for this build.

    Read by the gap report and by verify's undeclared-file pass, so both set
    aside the same entries: a placeholder standing for a family of files, a
    file the user imports through the UI (``path: null``), an entry of the
    build the platform does not run, a file read outside the system and
    save directories, and a filename-agnostic entry the builder scans for
    itself. A file the libretro build reads below the save directory is in
    scope: the pack places it there (``entry_root``).
    """
    name = file_entry.get("name", "")
    if "<" in name or ">" in name or "*" in name:
        return True
    if "path" in file_entry and file_entry["path"] is None:
        return True
    if not read_by_build(file_entry, is_standalone):
        return True
    return not (
        read_from_system_dir(file_entry, is_standalone)
        or read_from_save_dir(file_entry, is_standalone)
    ) or bool(file_entry.get("agnostic"))


def case_folded_slots(
    config: dict, declarations: Mapping[str, list[tuple[int | None, str]]],
) -> frozenset[str]:
    """The slots a platform whose filesystem folds case fills, any spelling.

    On RetroBat the 32X_G_BIOS.BIN it declares is the file BlastEm opens as
    32X_G_BIOS.bin. On Lakka bios.col and BIOS.col are two files: nothing.
    """
    if not config.get("case_insensitive_fs", False):
        return frozenset()
    return frozenset(
        where for places in declarations.values() for _size, where in places if where
    )


def declaration_settles(
    file_entry: dict,
    fname: str,
    declared_names: Mapping[str, list[tuple[int | None, str]]] | set[str],
    dest: str = "",
    folded_slots: frozenset[str] = frozenset(),
    declared_contents: Mapping[str, set[str]] | None = None,
) -> bool:
    """Whether a platform declaration meets a core's requirement.

    An entry the core finds by content (``found_by: content`` on the entry)
    is met by any declaration of a file it accepts by hash, in the folder it
    scans: atari800 takes RetroDECK's ROM_BASIC_A by its CRC32, so its own
    label for that ROM is not one more file to ship.

    A platform declaring the name the core reads has met the requirement
    where the declaration fills the entry's own slot, whose content the slot
    arbitration decides, or elsewhere at a size the core accepts: the builder
    copies that file to the core's path. Galaksija's 4 KiB ROM1.BIN does not
    stand for DOSBox's 32 KiB SC-55 one. The builder copies nothing for an
    alias, so an alias answers only where the core reads it: quasi88 reads
    n88sub.rom or disk.rom in quasi88/, and System.dat names quasi88/disk.rom.
    RetroDECK's root MSX.ROM is not CLK's MSX/MSX.ROM, and RetroBat's 16 KiB
    MSX DISK.ROM at the root is not the 256-byte Disk II ROM gsplus also
    accepts as c600.rom. The archive answers by its name. A bare set of names
    carries no slot or size and answers by name.

    Read by verify and by the gap report, which settled on the name alone
    and left DOSBox's SC-55 ROMs off the gaps page. ``folded_slots``
    (case_folded_slots) are slots a declaration fills in another spelling on
    a filesystem that folds case: the core opens that file there.
    """
    if file_entry.get("archive") in declared_names:
        return True
    slot = sanitize_pack_path(dest or fname).lower()
    directory = slot if dest.endswith("/") else slot.rpartition("/")[0]
    if declared_contents and file_entry.get("found_by") == "content":
        for field in ("md5", "sha1", "crc32"):
            values = file_entry.get(field) or []
            for value in values if isinstance(values, list) else str(values).split(","):
                folders = declared_contents.get(f"{field}:{str(value).strip().lower()}")
                if folders and directory in folders:
                    return True
    if not dest.endswith("/") and slot in folded_slots:
        return True
    for name in (fname, *file_entry.get("aliases", [])):
        if name not in declared_names:
            continue
        if not isinstance(declared_names, Mapping):
            return True
        if name == fname:
            if any(
                where == slot or name_match_size_ok(file_entry, size)
                for size, where in declared_names[name]
            ):
                return True
            continue
        read_at = f"{directory}/{name}".lower() if directory else name.lower()
        if any(
            where == read_at and name_match_size_ok(file_entry, size)
            for size, where in declared_names[name]
        ):
            return True
    return False


def with_archive_members(entry: dict, files: list[dict]) -> dict:
    """A loose entry resolved as the archive its profile reads members from.

    gngeopi declares neogeo.zip and, apart, the ROMs it opens inside it. The
    members decide which same-named copy is the archive: resolved by name
    alone, the loose entry took another copy than the archive pass and the
    profile blocked its own archive.
    """
    if entry.get("archive"):
        return entry
    members = archive_members(entry.get("name", ""), files)
    return {**entry, "members": members} if members else entry


def opens_by_name(file_entry: dict, profile: dict, standalone: bool = False) -> bool:
    """Whether the code opens this entry by its name.

    A core that scans a folder and identifies firmware by content
    (DuckStation by MD5, bios.cpp:208) gives its entries names that are
    labels. `found_by` says which, on the file or the profile, keyed by
    build when the two builds differ.
    """
    for source in (file_entry, profile):
        value = source.get("found_by")
        if isinstance(value, dict):
            value = value.get("standalone" if standalone else "libretro")
        if value:
            return value != "content"
    return True


def read_by_build(entry: dict, standalone: bool) -> bool:
    """Whether the build that runs (standalone or libretro) reads the entry."""
    return entry.get("mode") != ("libretro" if standalone else "standalone")


def filter_files_by_mode(files: list[dict], standalone: bool) -> list[dict]:
    """Filter file entries by libretro/standalone mode."""
    return [f for f in files if read_by_build(f, standalone)]


def installed_with_emulator(entry: dict, platform: str = "") -> bool:
    """Whether the emulator as this platform installs it already brings the entry.

    `bundled` describes the emulator's own release. A platform package can
    differ both ways: Batocera's hcl package installs the binary alone and
    sends users to fetch the data (`not_bundled_on`), while its blueMSX core
    package copies the machines and databases beside the core
    (`installed_on`).
    """
    if platform and platform in (entry.get("installed_on") or []):
        return True
    return bool(entry.get("bundled")) and platform not in (entry.get("not_bundled_on") or [])


def installed_everywhere(entry: dict) -> bool:
    """Whether the emulator brings the entry on every setup, for a view that names none.

    An entry a platform package leaves out (`not_bundled_on`) is a file that
    setup's users still need: touchHLE panics without its fonts on ROCKNIX.
    """
    return bool(entry.get("bundled")) and not entry.get("not_bundled_on")


def unread_on(entry: dict, platform: str) -> bool:
    """Whether this platform's launcher points the emulator at other files.

    RetroBat starts standalone BlastEm with absolute paths to its own BIOS
    names in the config it writes, so the defaults the emulator would read
    (cdbios.bin, colecovision_bios.col) are never opened there.
    """
    return bool(platform) and platform in (entry.get("unread_on") or [])


def deliverable(entries: list[dict], standalone: bool, platform: str = "") -> list[dict]:
    """The entries of one build a pack has to bring.

    A file or tree installed with the emulator is already on the user's
    machine: shipping it again only weighs the pack. `bundled` is scoped by
    `mode` like any entry, so PPSSPP's assets, shipped by the standalone
    release and not by the libretro core, still reach a RetroArch pack.
    """
    return [
        e for e in filter_files_by_mode(entries, standalone)
        if not installed_with_emulator(e, platform) and not unread_on(e, platform)
    ]
