"""Files a core reads beside the content: rom folders, boards and MAME search sets."""

from __future__ import annotations

import functools
import json
from collections.abc import Callable, Iterable

from model.targets import list_available_targets
from resolve.launches import ContentFolder, ContentLaunches, PlatformLaunches, RomSearch
from resolve.layout import (
    OUTSIDE_BIOS_FOLDER,
    placed_entry,
    standalone_layout_path,
)
from model.declarations import ROMS_ROOT, outer_layout
from model.platforms import config_platforms_dir
from model.profiles import core_key, profile_names
from core.paths import REPO_ROOT


LIBRETRO_RUNNERS = frozenset({"libretro", "retroarch", "retroarch32", "retrorun"})


# Set on a platform config built for one board (generate_pack, verify
# --target): a core a roms folder offers on other boards only is not placed
# there.
TARGET_KEY = "_target"


def _branch_holds(branch: str, board: str) -> bool:
    """Whether one `VARIABLE PATTERN` branch of a device case admits a board.

    ROCKNIX files a board under the DEVICE value its target scraper reads,
    lowercased. A branch on any other variable (PREFER_GLES) is no board
    condition, and admits every board.
    """
    variable, _, pattern = branch.strip().partition(" ")
    if variable != "DEVICE" or not pattern.strip():
        return True
    import fnmatch

    return any(
        fnmatch.fnmatchcase(board.upper(), p.strip().upper()) for p in pattern.split("|")
    )


def when_admits(when: str, board: str) -> bool:
    """Whether an offer's `when` holds on a board: alternatives joined by
    "; ", each the branches it is nested under joined by ", "."""
    return any(
        all(_branch_holds(branch, board) for branch in alternative.split(", "))
        for alternative in when.split("; ")
    )


def offer_boards(config: dict) -> dict[tuple[str, str], frozenset[str] | None]:
    """The boards on which each roms folder offers each core, by
    (core key, folder), None where every board does.

    ROCKNIX writes a core under a `case "${DEVICE}"` branch for the devices
    it builds (`when`), and a default for a named device in board_defaults
    (DEVICE=RK3326). Boards are the platform's targets, aliases included,
    read from the directory the config was loaded from.
    """
    platform = str(config.get("_key") or "")
    targets = (
        list_available_targets(platform, config_platforms_dir(config)) if platform else []
    )
    names = {t["name"]: [t["name"], *t.get("aliases", [])] for t in targets}

    def admitted(test: Callable[[str], bool]) -> set[str]:
        return {n for board, spelled in names.items() if test(board) for n in spelled}

    every = admitted(lambda _board: True)
    found: dict[tuple[str, str], set[str]] = {}
    for row in config.get("_rom_folders") or []:
        folder = str(row.get("folder") or "")
        offers = row.get("offers") or []
        offered = {(o.get("emulator"), core_key(o.get("core") or "")) for o in offers}
        choices: list[tuple[dict, set[str]]] = []
        if row.get("core") and (row.get("emulator"), core_key(row["core"])) not in offered:
            choices.append((row, every))
        for key, spec in (row.get("board_defaults") or {}).items():
            branch = str(key).replace("=", " ", 1)
            choices.append((spec, admitted(functools.partial(_branch_holds, branch))))
        for offer in offers:
            when = str(offer.get("when") or "")
            choices.append((offer, admitted(functools.partial(when_admits, when))
                            if when else every))
        for choice, boards in choices:
            if choice.get("core") and choice.get("emulator") in LIBRETRO_RUNNERS:
                found.setdefault((core_key(choice["core"]), folder), set()).update(boards)
    return {
        pair: None if not names or boards >= every else frozenset(boards)
        for pair, boards in found.items()
    }


def content_folder_boards(config: dict) -> dict[tuple[str, str], frozenset[str] | None]:
    """Each (core key, roms folder) a platform launches a libretro core for,
    with the boards it does so on, None for every board."""
    pairs: set[tuple[str, str]] = set()
    for core, systems in (config.get("libretro_systems") or {}).items():
        pairs |= {(core_key(core), str(s)) for s in systems or []}
    for system in (config.get("systems") or {}).values():
        if isinstance(system, dict) and system.get("native_id"):
            pairs |= {(core_key(c), str(system["native_id"])) for c in system.get("cores") or []}
    for record in config.get("launchers") or []:
        if record.get("kind") == "package" and record.get("build") == "libretro":
            package = str(record.get("emulator", ""))
            if package.startswith("lr-mess"):
                # Built with SUBTARGET=mess (lr-mess2016.sh:31): the MESS
                # drivers alone, none of the arcade sets of the core it
                # shares a repository with.
                continue
            core = core_key(package.removeprefix("lr-"))
            pairs |= {(core, str(s)) for s in record.get("systems") or []}
    # Pairs from the platform's own lists hold on every board, an offer on
    # the boards its frontend writes it for.
    return {
        **{pair: on for pair, on in offer_boards(config).items() if pair not in pairs},
        **{pair: None for pair in pairs},
    }


def content_launches(config: dict) -> ContentLaunches:
    """The roms folders a platform launches each libretro core for, and the
    ROM search paths its commands hand emulators and cores.

    A core reading its BIOS sets beside the game (MAME 2003's osd_get_path
    gives FILETYPE_ROM the content directory) reads them in the folder of
    the system it is launched for. The folders come from the platform's own
    lists: ``libretro_systems``, every core a folder of its rom folders file
    offers (its default, its board defaults, ``offers``), the cores a system
    offers under its own name, and the systems a RetroPie package registers.
    A platform with no roms root, or one keeping no folder per system
    (RetroArch, Lakka), gives none.
    """
    if config.get("inherits_from") == "emulatorjs":
        # EmulatorJS writes the BIOS a frontend hands it and the game to
        # the root of one filesystem (data/src/emulator.js:845, 990, 1054):
        # RomM's firmware folder is beside the content.
        return ContentLaunches(beside=True)
    if outer_layout(config, ROMS_ROOT) is None:
        return ContentLaunches(scoped=True)
    rows = config.get("_rom_folders") or []
    folders = {str(r.get("folder")) for r in rows if r.get("folder")}
    boards = content_folder_boards(config)
    target = config.get(TARGET_KEY)
    pairs = {pair for pair, on in boards.items() if not target or on is None or target in on}
    from resolve.launchers import roms_place_of

    def place(folder: str) -> tuple[str, ...]:
        return tuple(roms_place_of(config, folder) or ())

    # Without a board, a core a folder offers on some boards only carries
    # them, for a manifest the installer narrows to one.
    content_folders = frozenset(
        ContentFolder(
            c, f, place(f),
            None if target or (offered_on := boards.get((c, f))) is None
            else tuple(sorted(offered_on)),
        )
        for c, f in pairs if f in folders
    )
    searches = frozenset(
        RomSearch(
            str(search.get("core") or search["emulator"]), place(read),
            str(row["folder"]), tuple(sorted(search.get("machines") or [])),
            bool(search.get("any_machine")), str(search.get("source_ref", "")),
            "libretro" if search.get("core") else "standalone",
        )
        for row in rows
        for search in row.get("searched_by") or []
        for read in search.get("reads") or []
        if read in folders
    )
    return ContentLaunches(scoped=True, folders=content_folders, searches=searches)


# The machines ES-DE runs from a folder whose command starts the game itself
# (%BASENAME%), by the folder's system: its BIOS root, the driver source
# files of its board, or a device its machines carry. A system not listed
# holds any machine.
ANY_MACHINE_POPULATIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "neogeo": ("bios", ("neogeo",)),
    "stv": ("bios", ("stvbios",)),
    "cps": ("source", ("capcom/cps1.cpp", "capcom/cps2.cpp", "capcom/cps3.cpp")),
    "cps1": ("source", ("capcom/cps1.cpp",)),
    "cps2": ("source", ("capcom/cps2.cpp",)),
    "cps3": ("source", ("capcom/cps3.cpp",)),
    "model2": ("source", ("sega/model2.cpp",)),
    "model3": ("source", ("sega/model3.cpp",)),
    "daphne": ("device_source", ("devices/machine/ld",)),
    "laserdisc": ("device_source", ("devices/machine/ld",)),
    "gameandwatch": ("source", ("handheld/",)),
    "lcdgames": ("source", ("handheld/",)),
}


@functools.lru_cache(maxsize=8)
def _arcade_relation(profile_key: str) -> dict | None:
    """games/arcade/<profile>.json: the BIOS and device sets each game set
    loads, from the -listxml of the version the profile pins."""
    path = REPO_ROOT / "games" / "arcade" / f"{profile_key}.json"
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def rom_search_sets(
    profile_key: str, system: str, machines: Iterable[str], any_machine: bool,
) -> frozenset[str]:
    """The sets a command reads from the ROM search path it passes.

    The machines it starts, the BIOS sets on their romof chain and the
    device sets with ROMs they instantiate, as the -listxml records them.
    A command starting the game itself reads them for each machine its
    folder holds (ANY_MACHINE_POPULATIONS).
    """
    return _rom_search_sets(profile_key, system, tuple(sorted(machines)), any_machine)


@functools.lru_cache(maxsize=256)
def _rom_search_sets(
    profile_key: str, system: str, machines: tuple[str, ...], any_machine: bool,
) -> frozenset[str]:
    relation = _arcade_relation(profile_key)
    if relation is None:
        return frozenset()
    bios, devices = relation.get("bios") or {}, relation.get("devices") or {}
    # A clone reads the ROMs it shares with its parent from the parent's
    # archive: the search path is the set and every ancestor
    # (src/emu/driver.cpp:31-38, src/emu/romload.cpp:67-84 at mame0289).
    parents = relation.get("parents") or {}
    sources = relation.get("sources") or {}
    members: set[str] = set(machines)
    kind, keys = ANY_MACHINE_POPULATIONS.get(system, ("all", ())) if any_machine else ("", ())
    if kind == "bios":
        members |= {g for k in keys for g in bios.get(k) or []} | set(keys)
    elif kind == "source":
        members |= {g for src, sets in sources.items() if src.startswith(keys) for g in sets}
    elif kind == "device_source":
        carried = {d for src, sets in sources.items() if src.startswith(keys) for d in sets}
        members |= {g for d in carried for g in devices.get(d) or []}

    def used(users: list[str]) -> bool:
        return kind == "all" or not members.isdisjoint(users)

    found = {b for b, users in bios.items() if used(users)}
    found |= {p for p, users in parents.items() if used(users)}
    found |= {d for d, users in devices.items() if used(users)}
    return frozenset(found | members)


def _search_reads(emu_name: str, searches: list[RomSearch], name: str) -> list[tuple[str, str]]:
    """The (tree, folder) places a passed ROM search reads this set from."""
    stem = name.rsplit(".", 1)[0]
    return sorted({
        (s.place[0], s.place[1]) for s in searches
        if s.place and stem in rom_search_sets(emu_name, s.folder, s.machines, s.any_machine)
    })


def _roms_entry(entry: dict, tree: str, folder: str, rel: str) -> dict:
    """The entry placed in a roms folder."""
    # Below the roms root inside the install tree (EmuELEC's
    # /storage/roms): a plain dest the platform prefix skips, as a
    # standalone entry placed there (placed_entry).
    where: dict[str, object] = (
        {"unprefixed": True} if tree == "install" else {"root": ROMS_ROOT}
    )
    return {**entry, **where, "path": f"{folder}/{rel}", "layout_path": rel}


def _content_folder_boards(
    folders: Iterable[ContentFolder], names: set[str],
) -> dict[tuple, set[str] | None]:
    """Each roms folder the platform launches the core from, with its boards."""
    # A place keeps the boards its core is offered on there, every board
    # when one folder offers it everywhere.
    on_boards: dict[tuple, set[str] | None] = {}
    for folder in folders:
        if folder.core not in names or not folder.place:
            continue
        known = on_boards.get(folder.place, set())
        on_boards[folder.place] = (
            None if folder.boards is None or known is None else known | set(folder.boards)
        )
    return on_boards


def _libretro_content_layout(
    emu_name: str, view: dict, content: ContentLaunches, names: set[str],
    searches: list[RomSearch],
) -> dict:
    """The libretro layout with each file read beside the content placed there."""
    on_boards = _content_folder_boards(content.folders, names)
    folders = sorted(on_boards)
    # The folders a passed `-rompath` replaces the build's own search
    # path with stand for these: libretro MAME hands MAME
    # <system>/mame/bios unless the content's command line names
    # another (retro_init.cpp Set_Path_Option, execute_game_cmd).
    from resolve.launcherconfig import pool_folders

    pools = set(pool_folders({"standalone_pools": view.get("libretro_pools")}).values())
    out: list = []
    changed = False
    for f in view.get("files") or []:
        if not isinstance(f, dict):
            out.append(f)
            continue
        if _content_load(f) != "content_dir" or f.get("category") == "game_data":
            # Game data read beside the content is the game's own.
            out.append(f)
            parent, _, rel = str(f.get("path") or "").rpartition("/")
            if searches and parent in pools and rel:
                reads = _search_reads(emu_name, searches, rel)
                changed |= bool(reads)
                out.extend(_roms_entry(f, tree, folder, rel) for tree, folder in reads)
            continue
        changed = True
        plain = _without_libretro_load(f)
        if not folders:
            out.append({**plain, "unplaced": OUTSIDE_BIOS_FOLDER})
            continue
        rel = str(f.get("path") or f.get("name") or "")
        out.extend(
            {**_roms_entry(plain, tree, folder, rel),
             **({"boards": sorted(on)} if (on := on_boards[(tree, folder)]) is not None else {})}
            for tree, folder in folders
        )
    return {**view, "files": out} if changed else view


def _standalone_content_layout(emu_name: str, view: dict, searches: list[RomSearch]) -> dict:
    """The standalone layout with each set a passed search reads placed there."""
    pools = {str(v).strip("/") for v in (view.get("standalone_pools") or {}).values()}
    if not searches or "" not in pools:
        return view
    out: list = []
    changed = False
    for f in view.get("files") or []:
        layout = (
            (f.get("layout_path") or standalone_layout_path(f, view)) if isinstance(f, dict) else None
        )
        if not layout or "/" in layout:
            out.append(f)
            continue
        reads = _search_reads(emu_name, searches, layout)
        if f.get("unplaced") != OUTSIDE_BIOS_FOLDER:
            # A set a launcher record placed stays there: EmuDeck's
            # mame.ini rompath is read when Steam ROM Manager starts MAME
            # with no `-rompath` (tools/launchers/mame.sh), and ES-DE's
            # commands read the folders they pass.
            out.append(f)
            held = {(f.get("root") or "", f.get("standalone_path") or "")}
            extra = [
                placed_entry(f, view, (tree, f"{folder}/{layout}")) for tree, folder in reads
            ]
            extra = [e for e in extra if (e.get("root") or "", e["standalone_path"]) not in held]
            changed |= bool(extra)
            out.extend(extra)
            continue
        if not reads:
            out.append(f)
            continue
        changed = True
        placed = {k: v for k, v in f.items() if k != "unplaced"}
        out.extend(
            placed_entry(placed, view, (tree, f"{folder}/{layout}")) for tree, folder in reads
        )
    return {**view, "files": out} if changed else view


def content_layout(
    emu_name: str, view: dict, standalone: bool, launches: PlatformLaunches,
) -> dict:
    """The layout with each file read in a roms folder placed in that folder.

    A libretro entry read beside the content (``load_from: content_dir``)
    goes to the folder of each system the platform launches the core for,
    and is named as read outside the BIOS folder where it knows none. An
    entry in the folder a passed ROM search path stands for (the root of a
    standalone layout, a ``libretro_pools`` folder) also goes to each folder
    a command passes for a machine that reads it, and a standalone entry no
    launcher record places goes there only. Outside a platform (not
    ContentLaunches.scoped) the view is left as it is.
    """
    content = launches.content
    if content.beside and not standalone:
        files = [
            _without_libretro_load(f)
            if isinstance(f, dict) and _content_load(f) == "content_dir"
            and f.get("category") != "game_data" else f
            for f in view.get("files") or []
        ]
        return {**view, "files": files}
    if not content.scoped:
        return view
    names = {core_key(n) for n in profile_names(emu_name, view)}
    build = "standalone" if standalone else "libretro"
    searches = [
        s for s in content.searches if core_key(s.emulator) in names and s.build == build
    ]
    if not standalone:
        return _libretro_content_layout(emu_name, view, content, names, searches)
    return _standalone_content_layout(emu_name, view, searches)


def _content_load(entry: dict) -> str:
    load_from = entry.get("load_from") or ""
    if isinstance(load_from, dict):
        load_from = load_from.get("libretro") or ""
    return str(load_from)


def _without_libretro_load(entry: dict) -> dict:
    """The entry without the libretro build's load_from: its folder is now its path."""
    load_from = entry.get("load_from")
    rest = {k: v for k, v in entry.items() if k != "load_from"}
    if isinstance(load_from, dict) and load_from.get("standalone"):
        rest["load_from"] = {"standalone": load_from["standalone"]}
    return rest
