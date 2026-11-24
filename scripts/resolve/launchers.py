"""Where a platform's launch code puts an emulator's files: handed directories, executed files, standalone bindings."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from model.declarations import CONFIGS_ROOT, ROMS_ROOT, declared_root, declared_slot, outer_layout
from model.launcherrecords import record_emulators
from core.paths import sanitize_pack_path
from resolve.launcherconfig import bound_launchers
from resolve.launcherplaces import bios_relative, record_directories


# The names a platform's launch code gives its BIOS root, besides the
# base_destination bios_relative reads: RetroPie's scriptmodules set
# biosdir="$home/RetroPie/BIOS", EmuDeck's scripts ${biosPath}, RetroDECK's
# component scripts $bios_path.
BIOS_ROOT_VARIABLES = ("$biosdir", "$home/RetroPie/BIOS", "${biosPath}", "$bios_path")

# The name a platform's launch code gives its roms root: RetroDECK's
# component scripts write $roms_path (retrodeck_launchers), the setting whose
# default is the roms root (config/retrodeck/retrodeck.json:5), RetroPie's
# scriptmodules $romdir (retropie_packages.sh:47-49).
ROMS_ROOT_VARIABLES = ("$roms_path", "${roms_path}", "$romdir", "${romdir}")

# The kinds that hand an emulator a whole directory. A scans_dir record sets
# the directory the emulator picks its file from: ROCKNIX writes ARMSX2's
# [Folders] Bios, EmuDeck PCSX2's.
HANDED_KINDS = ("links", "passes_path", "scans_dir")

# How a launcher record says the platform starts the emulator in a directory
# (retropie_reader._working_directory), and the handle a profile gives
# that directory in standalone_directories: the call its code reads it with.
WORKING_DIRECTORY_PASSED = "working directory of "
WORKING_DIRECTORY = "getcwd"
# The handle a profile declares when its program reads its files beside its
# own executable: a launcher record executing one of the profile's files
# places the folder holding that file where the launcher runs it from.
EXECUTABLE_DIRECTORY = "executable directory"

# The trees a placed folder belongs to: the BIOS tree every destination is
# relative to, and the roms directory of a platform whose registry names it.
BIOS_TREE = ""
ROMS_TREE = "roms"
# The emulator folders of a platform whose registry describes them.
EMULATORS_TREE = "emulators"
# The frontend's configs folder of a platform whose file records it.
CONFIGS_TREE = "configs"
# The tree a platform's list installs into when it starts above the BIOS
# folder: a plain dest, with no prefix.
INSTALL_TREE = "install"
# A folder of neither tree, which no pack and no installer can fill.
OUTSIDE_TREE = "outside"
Place = tuple[str, str]
# The binding key of a search list standing for the whole layout: the
# directories hold the layout's files themselves (XRoar's ROMs, MAME's sets),
# never its subfolders.
SEARCHED_FILES = "*"

_HOME = re.compile(r"^(?:\$\{HOME\}|\$HOME|\$home|~)(?=/|$)")
# Flatpak sets XDG_DATA_HOME to ~/.var/app/<id>/data inside the sandbox.
_FLATPAK_DATA = re.compile(r"^~/\.var/app/[^/]+/data(?=/|$)")


def normalize_handle(token: str, home: str = "") -> str:
    """One spelling for a path, setting or function a launcher record names.

    ``$home``, ``$HOME``, ``${HOME}`` and ``~`` are one directory, and a
    Flatpak's data directory is its ``$XDG_DATA_HOME``. ``home`` is the
    platform's home directory spelled out (``home_directory``): EmuELEC
    links /storage/.local/share/flycast, Flycast's ~/.local/share/flycast.
    """
    token = token.strip().strip("\"'").rstrip(",;").rstrip("/")
    token = token.removesuffix("()")
    home = home.rstrip("/")
    if home and _below(token, home) is not None:
        token = "~" + token[len(home):]
    token = _HOME.sub("~", token)
    return _FLATPAK_DATA.sub("$XDG_DATA_HOME", token)


_INI_KEY = re.compile(r"(\[[^\]\s]+\])\s+([^\s,;=()]+)")


def ini_keys(passes_to: str) -> frozenset[str]:
    """The INI keys a record's ``passes_to`` writes, as "[Section] Key".

    A key alone is ambiguous: PCSX2 reads its BIOS folder from [Folders]
    Bios and the image name from [Filenames] BIOS. A profile declares the
    key it resolves a folder from in that spelling ("[Folders] Bios = bios").
    """
    return frozenset(f"{section} {key}" for section, key in _INI_KEY.findall(passes_to))


def _folder_in_bios(directory: str, base: str) -> str | None:
    """A directory relative to the BIOS root, None when it lies outside."""
    relative = bios_relative(directory, base)
    if relative is not None:
        return relative
    directory = directory.strip().rstrip("/")
    for variable in BIOS_ROOT_VARIABLES:
        if directory == variable:
            return ""
        if directory.startswith(variable + "/"):
            rest = directory[len(variable) + 1:]
            return None if re.search(r"[\s<>$:;]", rest) else rest
    return None


@dataclass(frozen=True)
class HandedDirectory:
    """A whole directory a platform hands a standalone emulator.

    ``folder`` is the directory relative to the BIOS root, None when it lies
    outside it. ``handles`` are the paths, settings and functions the record
    names on the emulator's side: the link's other end, the config key, the
    function a patch rewrites.
    """

    emulator: str
    folder: str | None
    directory: str
    handles: frozenset[str]
    source_ref: str
    roms_place: Place | None = None
    # The platform systems, by our ids, the record applies to. Empty when
    # the launcher hands the directory whatever the system.
    systems: frozenset[str] = frozenset()
    # Whether the platform's own list declares files in the folder.
    holds_declared: bool = False

    def place(self) -> Place | None:
        """The folder as a place, None when it lies outside both roots."""
        if self.folder is not None:
            return (BIOS_TREE, self.folder)
        return self.roms_place


# The placeholder a launcher record writes for the system it is launched
# for, as Recalbox's extractor spells it: Recalbox passes XRoar `-rompath`
# `os.path.join(BIOS, args.system)`.
SYSTEM_PLACEHOLDER = "<system>"


def native_systems(config: dict) -> dict[str, str]:
    """The platform's own system names, each to our id for it.

    A system states its name (native_id) or its files do (native_system).
    Without either, our id is the platform's name.
    """
    found: dict[str, str] = {}
    for slug, system in (config.get("systems") or {}).items():
        names = {str(system["native_id"])} if system.get("native_id") else {
            str(f["native_system"]) for f in system.get("files") or [] if f.get("native_system")
        }
        for name in names or {slug}:
            found.setdefault(name, slug)
    return found


# How the launcher extractors spell the folder holding the launched game:
# RetroBat's Path.GetDirectoryName(rom) (retrobat_render._KNOWN), KNULLI's
# os.path.dirname(rom) and its software list folder (mameGenerator.py:113-116).
GAME_FOLDERS = ("<rom directory>", "<romDirname>", "<softDir>")


def _listed_directories(raw: str) -> list[str] | None:
    """The directories of a search path, None for one directory.

    XRoar's rompath is a colon-separated list (RetroDECK writes four
    directories), each entry a path or a variable spelling one. A Windows
    drive letter or a backslash means a single path. MAME splits its search
    paths on semicolons whatever the system (src/emu/fileio.cpp:53-58):
    RetroBat passes `-rp bios;<rom directory>`, KNULLI `-rompath
    <romDirname>;/userdata/bios/mame;/userdata/bios`. The game's own folder
    is no folder a pack fills, so it gives no directory.
    """
    if ";" in raw:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        kept = [p for p in parts if p not in GAME_FOLDERS]
        if kept and all(not re.search(r"[\s,<>]", p) for p in kept):
            return kept
        return None
    if ":" not in raw or "\\" in raw or re.match(r"^[A-Za-z]:", raw):
        return None
    parts = [p.strip() for p in raw.split(":")]
    if all(p and p[0] in "/$~" and not re.search(r"[\s,;]", p) for p in parts):
        return parts
    return None


def handed_directories(
    config: dict, profiles: Mapping[str, dict]
) -> list[HandedDirectory]:
    """Every whole directory a platform links or passes to a standalone build.

    A record naming files (gpsp's gba_bios.bin) or one slot of a directory
    (RetroDECK's GC/EUR) hands over no whole directory, and a search_dir
    describing several directories in prose names no single one. A search
    path (XRoar's rompath) gives each of its directories, in order. A record
    naming systems applies to those systems only, and one whose search_dir
    holds <system> gives one directory per system the platform declares.
    """
    base = str(config.get("base_destination") or "bios")
    home = str(config.get("home_directory") or "")
    natives = native_systems(config)
    declared = {d.lower() for d in declared_destinations(config)}
    found: list[HandedDirectory] = []
    for record in bound_launchers(config, profiles):
        if record.get("build") != "standalone" or record.get("kind") not in HANDED_KINDS:
            continue
        if record.get("names") or record.get("slot"):
            continue
        raw = str(record.get("search_dir") or "").strip()
        if not raw:
            continue
        named = frozenset(natives.get(str(s), str(s)) for s in record.get("systems") or [])
        if SYSTEM_PLACEHOLDER in raw:
            variants = [
                (raw.replace(SYSTEM_PLACEHOLDER, native), frozenset({slug}))
                for native, slug in sorted(natives.items())
                if not named or slug in named
            ]
        else:
            variants = [(raw, named)]
        passes_to = str(record.get("passes_to") or "")
        for spelled, systems in variants:
            parts = _listed_directories(spelled) or [spelled]
            if any(re.search(r"[\s,:;]", part) for part in parts):
                continue
            for part in parts:
                directory = normalize_handle(part, home)
                if passes_to.startswith(WORKING_DIRECTORY_PASSED):
                    # The program runs from the directory: what its code
                    # reads through getcwd(), or relative to it, is below it.
                    handles = frozenset({WORKING_DIRECTORY})
                else:
                    handles = frozenset(
                        handle
                        for token in passes_to.split()
                        if (handle := normalize_handle(token, home)) and handle != directory
                    ) | ini_keys(passes_to)
                folder = _folder_in_bios(part, base)
                found.extend(
                    HandedDirectory(
                        emulator=emulator,
                        folder=folder,
                        directory=directory,
                        handles=handles,
                        source_ref=str(record.get("source_ref", "")),
                        roms_place=None if folder is not None else (
                            roms_place_of(config, folder_in_roms(part, config))
                            or _configs_place(folder_in_configs(part, config))
                            or _emulators_place(folder_in_emulators(part, config))
                        ),
                        systems=systems,
                        holds_declared=bool(folder) and any(
                            d.startswith(f"{(folder or '').lower()}/") for d in declared
                        ),
                    )
                    for emulator in record_emulators(record)
                )
    return found


def _configs_place(path: str | None) -> Place | None:
    """A folder below the configs root, as a place of the configs tree."""
    return None if path is None else (CONFIGS_TREE, path)


def _emulators_place(path: str | None) -> Place | None:
    """A folder an emulator key names, as a place of the emulators tree."""
    return None if path is None else (EMULATORS_TREE, path)


def roms_place_of(config: dict, path: str | None) -> Place | None:
    """A path below the roms root as a place: in the install tree when the
    platform installs above its BIOS folder (AmberELEC), else the roms tree."""
    if path is None:
        return None
    layout = outer_layout(config, ROMS_ROOT) or {}
    if "install_prefix" in layout:
        prefix = layout["install_prefix"]
        return (INSTALL_TREE, sanitize_pack_path(f"{prefix}/{path}" if prefix else path))
    return (ROMS_TREE, path)


def folder_in_configs(directory: str, config: dict) -> str | None:
    """A directory relative to the frontend's configs folder, None outside it.

    Only a platform whose file records its configs root has one
    (``configs_root.path``): Batocera's /userdata/system/configs, where its
    generators start shadPS4 from configs/shadps4.
    """
    return folder_in_root(directory, config, CONFIGS_ROOT)


def folder_in_roms(directory: str, config: dict) -> str | None:
    """A directory relative to the platform's roms directory, None outside it.

    Only a platform whose rom folders file records its roms root has one
    (``roms_root.path``): ROCKNIX's /storage/roms, which holds its BIOS
    folder and the folders its launchers run programs from.
    """
    spelled = directory.strip().rstrip("/")
    for variable in ROMS_ROOT_VARIABLES:
        if outer_layout(config, ROMS_ROOT) and (
            spelled == variable or spelled.startswith(variable + "/")
        ):
            rest = spelled[len(variable) + 1:]
            return None if re.search(r"[\s<>$:;]", rest) else rest
    return folder_in_root(directory, config, ROMS_ROOT)


def folder_in_root(directory: str, config: dict, root: str) -> str | None:
    """A directory relative to an outer root's path, None outside it."""
    roms = str((outer_layout(config, root) or {}).get("path") or "").rstrip("/")
    directory = directory.strip().rstrip("/")
    if not roms or not directory.startswith(roms + "/"):
        return None
    rest = directory[len(roms) + 1:]
    return None if re.search(r"[\s<>$:;]", rest) else rest


def folder_in_emulators(directory: str, config: dict) -> str | None:
    """The emulator folder a launcher names by its key, None for any other.

    Only a platform whose registry describes its emulator folders has one
    (``emulators_directory.launcher_spelling``): RetroBat's generators take
    each from AppConfig.GetFullPath("<key>"), a folder of the RetroBat
    install named after the key.
    """
    spelling = str((config.get("emulators_directory") or {}).get("launcher_spelling") or "")
    if "{key}" not in spelling:
        return None
    # The key, then any folder below it: Citron's generator creates
    # <folder>/user, its portable data folder.
    pattern = re.escape(spelling).replace(re.escape("{key}"), r"([\w.-]+)") + r"((?:/[\w.-]+)*)"
    found = re.fullmatch(pattern, directory.strip())
    return found.group(1) + found.group(2) if found else None


@dataclass(frozen=True)
class ExecutedFile:
    """A file a platform's launcher executes, and where it lies.

    ``place`` is (root, path): the BIOS tree or the roms directory, None
    when the file lies outside both (RetroBat's emulator folders).
    """

    emulator: str
    name: str
    place: Place | None
    source_ref: str


def executed_files(config: dict, profiles: Mapping[str, dict]) -> list[ExecutedFile]:
    """Every file a platform's launchers execute, from bound records passing it to exec."""
    base = str(config.get("base_destination") or "bios")
    found: list[ExecutedFile] = []
    for record in bound_launchers(config, profiles):
        if record.get("kind") not in ("fixed_name", "names_searched"):
            continue
        if str(record.get("passes_to") or "").strip() != "exec":
            continue
        raw = str(record.get("search_dir") or "").strip()
        directories = record_directories(record, base)
        roms = folder_in_roms(raw, config) if raw and not directories else None
        emulator_folder = folder_in_emulators(raw, config) if raw and not directories else None
        # A program file needs no extension (pico8, vox): the names are
        # taken as written, placeholders left out.
        for name in (str(n).strip() for n in record.get("names") or []):
            if not name or re.search(r"[<>{}]", name):
                continue
            if directories:
                place: Place | None = (BIOS_TREE, sanitize_pack_path(
                    f"{directories[0]}/{name}" if directories[0] else name
                ))
            elif roms is not None:
                place = roms_place_of(config, sanitize_pack_path(f"{roms}/{name}" if roms else name))
            elif emulator_folder is not None:
                place = (EMULATORS_TREE, sanitize_pack_path(f"{emulator_folder}/{name}"))
            else:
                place = None
            found.extend(
                ExecutedFile(
                    emulator, name.rsplit("/", 1)[-1], place, str(record.get("source_ref", ""))
                )
                for emulator in record_emulators(record)
            )
    return found


def _below(handle: str, directory: str) -> str | None:
    """``handle`` relative to ``directory``, None when it is not inside it."""
    if handle == directory:
        return ""
    if handle.startswith(directory + "/"):
        return handle[len(directory) + 1:]
    return None


def _join(*parts: str) -> str:
    return "/".join(p for p in parts if p)


def _record_places(
    record: HandedDirectory, inner: str, records: list[HandedDirectory]
) -> list[tuple[str, Place]]:
    """(subfolder, place) for the directory ``inner`` below what a record hands.

    A record handing a folder of a tree gives it directly. One handing a
    directory outside the trees is followed through the links that put a
    folder at that directory, below it or above it.
    """
    if record.folder is not None:
        return [("", (BIOS_TREE, _join(record.folder, inner)))]
    base = _join(record.directory, inner)
    found: list[tuple[str, Place]] = []
    for link in records:
        target = link.place()
        if target is None:
            continue
        for handle in link.handles:
            rest = _below(handle, base)
            if rest is not None:
                found.append((rest, target))
                continue
            up = _below(base, handle) if inner else None
            if up:
                found.append(("", (target[0], _join(target[1], up))))
    if not found and record.roms_place is not None:
        root, folder = record.roms_place
        found.append(("", (root, _join(folder, inner))))
    return found


def _bind(
    records: list[HandedDirectory],
    links: list[HandedDirectory],
    wanted: set[str],
    named: Mapping[str, str],
    pools: Mapping[str, str],
) -> dict[str, set[Place]]:
    """The places each subfolder of the layout is given by ``records``.

    A record whose handle is a declared directory, or lies below one, gives
    that subfolder, and a handle ``named`` gives the one folder it stands
    for. One whose handle lies above a declared directory, or is the
    environment variable the declared directory is spelled from
    ($XDG_DATA_HOME/suyu), gives the declared directory where it lands:
    RetroPie configures XRoar with --prefix=$md_inst, so
    ${prefix}/share/xroar/roms is $md_inst/share/xroar/roms. When it lands
    in no folder a pack fills, the layout is read outside the trees.
    ``links`` are the records followed from a directory outside the trees.

    A handle in ``pools`` names a list of directories the program searches
    one after the other: openMSX's filepool, XRoar's rompath. A file in any
    of them is read, so the pool gives one: the directory the platform's own
    list already fills (Batocera's bios/openmsx beside bios/Machines), else
    the first of the BIOS tree, else the first a pack can fill. A list that
    already holds the folder the layout's files take without the launcher
    keeps them there: KNULLI starts MAME with `-rompath`
    <romDirname>;/userdata/bios/mame;/userdata/bios, and the sets at the BIOS
    root stay. A pool standing for the whole layout holds its files
    directly, not its folders (SEARCHED_FILES): MAME reads hash/ and
    samples/ through other settings.
    """
    found: dict[str, set[Place]] = {}
    pooled: dict[str, list[tuple[bool, Place]]] = {}
    for record in records:
        for handle in record.handles:
            if handle in pools:
                for rest, place in _record_places(record, "", links):
                    pooled.setdefault(_join(pools[handle], rest), []).append(
                        (record.holds_declared, place)
                    )
                continue
            if handle in named:
                for rest, place in _record_places(record, "", links):
                    found.setdefault(_join(named[handle], rest), set()).add(place)
            for directory in wanted:
                sub = _below(handle, directory)
                if sub is not None:
                    for rest, place in _record_places(record, "", links):
                        found.setdefault(_join(sub, rest), set()).add(place)
                    continue
                if handle == directory:
                    continue
                inner = next(
                    (up for spelled in (f"${handle}", handle)
                     if (up := _below(directory, spelled)) is not None),
                    None,
                )
                if inner is None:
                    continue
                places = _record_places(record, inner, links)
                for rest, place in places or [("", (OUTSIDE_TREE, ""))]:
                    found.setdefault(rest, set()).add(place)
    for sub, entries in pooled.items():
        # The folder the files already take, else the directory the
        # platform's own list fills, else the first of the BIOS tree, else
        # the first a pack fills.
        unmoved = [p for _held, p in entries if p == (BIOS_TREE, sub)]
        filled = [p for held, p in entries if held]
        in_bios = [p for _held, p in entries if p[0] == BIOS_TREE]
        chosen = (unmoved or filled or in_bios or [p for _h, p in entries])[0]
        found.setdefault(sub or SEARCHED_FILES, set()).add(chosen)
    return found


def standalone_bindings(
    names: Iterable[str],
    declared: Iterable[str],
    handed: Iterable[HandedDirectory],
    executed: Iterable[ExecutedFile] = (),
    layout: Iterable[str] = (),
    pools: Mapping[str, str] | None = None,
    systems: Iterable[str] = (),
) -> dict[str, Place]:
    """The folders a platform gives a standalone build's layout.

    ``declared`` are the directories the build resolves its paths against,
    as its profile names them (``standalone_directories``), and ``pools``
    the settings it reads as search lists, each to the subfolder of the
    layout its directories stand for (``standalone_pools``). The result maps
    a subfolder of that layout ("" for the whole of it) to the place, a
    folder of the BIOS tree or of the roms directory, the emulator reads it
    from.

    A record handing a folder under a declared directory gives it directly:
    RetroPie points Flycast's ~/.local/share/flycast at bios/dc. A record
    handing a directory outside the trees is followed through the links that
    put a folder at it or below it: ROCKNIX's patched Flycast uses
    /storage/roms/dreamcast/data, which its start script links to bios/dc,
    and RetroPie starts UAE4All2 in $md_inst, whose kickstarts folder it
    links to bios/amiga.

    ``systems`` are the platform systems, by our ids, an entry is launched
    for. A record naming systems replaces, for those systems, what the
    records naming none give: RetroBat passes XRoar `-rompath bios/coco` for
    coco and bios/dragon for every other system.

    A profile whose program reads its files beside its executable declares
    EXECUTABLE_DIRECTORY, and ``layout`` holds its paths: a launcher that
    executes one of them gives the folder holding it. Batocera runs
    pico-8/pico8 from its BIOS folder, ROCKNIX pico8_64 from
    /storage/roms/pico-8.

    A subfolder two records give two places is left out.
    """
    names = set(names)
    pools = {normalize_handle(k): str(v).strip("/") for k, v in (pools or {}).items()}
    # "<handle> = <subfolder>" names the code's handle for one folder of the
    # layout: Citron's CitronPath::KeysDir is its keys/ folder, and a patch
    # that rewrites the handle moves that folder alone.
    named: dict[str, str] = {}
    wanted: set[str] = set()
    for raw in declared:
        handle, sep, sub = str(raw).partition(" = ")
        if sep:
            named[normalize_handle(handle)] = sanitize_pack_path(sub.strip())
        else:
            wanted.add(normalize_handle(handle))
    wanted -= set(pools)
    if not wanted and not named and not pools:
        return {}
    systems = set(systems)
    records = [h for h in handed if h.emulator in names]
    generic = [h for h in records if not h.systems]
    specific = [h for h in records if h.systems & systems]

    found = _bind(generic, generic, wanted, named, pools)
    # A link is followed whatever system it was written for.
    found.update(_bind(specific, specific + generic, wanted, named, pools))
    if EXECUTABLE_DIRECTORY in wanted:
        paths = list(layout)
        for run in executed:
            if run.emulator not in names:
                continue
            # A program run from a folder outside both trees (RetroBat's
            # emulators/pico8) binds its folder to no place a pack fills.
            root, path = run.place or (OUTSIDE_TREE, run.name)
            folder = path.rsplit("/", 1)[0] if "/" in path else ""
            for entry_path in paths:
                if entry_path.rsplit("/", 1)[-1] != run.name:
                    continue
                sub = entry_path.rsplit("/", 1)[0] if "/" in entry_path else ""
                found.setdefault(sub, set()).add((root, folder))
    return {sub: next(iter(places)) for sub, places in found.items() if len(places) == 1}


def bound_path(path: str, bindings: dict[str, Place]) -> Place | None:
    """Where a platform holds a layout path, None when no binding covers it.

    The longest subfolder that contains the path wins: a link of
    kickstarts/ places kickstarts/kick13.rom even when the whole layout is
    bound elsewhere. SEARCHED_FILES covers the files at the root of the
    layout alone.
    """
    for sub in sorted(bindings, key=len, reverse=True):
        if sub == SEARCHED_FILES:
            if "/" in path:
                continue
            root, folder = bindings[sub]
            return (root, f"{folder}/{path}" if folder else path)
        if sub and not path.startswith(sub + "/"):
            continue
        rest = path[len(sub) + 1:] if sub else path
        root, folder = bindings[sub]
        return (root, f"{folder}/{rest}" if folder else rest)
    return None


def declared_destinations(config: dict) -> set[str]:
    """Each destination the platform declares, relative to the core file directory.

    Case is kept: a launcher that matches names exactly is not served by a
    declaration of another case.
    """
    prefix = declared_root(config)
    found: set[str] = set()
    for system in config.get("systems", {}).values():
        for entry in system.get("files", []):
            slot = declared_slot(entry, prefix)
            if slot:
                found.add(slot)
    return found
