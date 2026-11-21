"""A rom folder resolved to the systems it holds and the profile of the program that runs it."""

from __future__ import annotations

from pathlib import Path

from games.profileindex import Profiles
from model.romfolders import ProfileResolver, Resolution, SystemResolver, folder_names


def arcade_profiles(directory: Path) -> set[str]:
    return {p.stem for p in directory.glob("*.json")} if directory.is_dir() else set()


def resolve_folder(
    row: dict, platform: str, profile: str | None, resolver: SystemResolver, profiles: Profiles,
    arcade: frozenset[str] | set[str] = frozenset(),
) -> Resolution:
    """The systems a folder holds: its names first, else its core's machines.

    A name nothing spells, run by a core of one machine, is that machine
    (ECWolf's wolf3d folder, a port's own folder). Run by a core of several,
    its games are one of them (theodore's thomson folder), and every one
    is kept: left empty, the folder had no fallback and its games got no file.
    An arcade core is the exception: the arcade index names each set's
    files, and its hundred machines would make any unknown file a fallback
    for all of them.

    A name that spells a machine its core does not run adds the core's
    machines to it: the games run on that core. Mednafen's PC Engine core
    lists nec-pc-engine, the CD folder resolved to nec-pc-engine-cd alone,
    and an unrecognised CD game got no System Card.
    """
    resolution = resolver.resolve(folder_names(row), platform)
    own = [str(s) for s in profiles.profiles.get(profile or "", {}).get("systems") or []]
    if resolution.systems and own and profile not in arcade:
        runs = {sid for s in own for sid in resolver.equivalents(s)}
        if not runs & set(resolution.systems):
            systems = set(resolution.systems) | {resolver.canonical(s) for s in own}
            return Resolution(sorted(systems), f"{resolution.basis}, and systems of {profile}")
    if resolution.systems or not own:
        return resolution
    if len(own) == 1:
        return Resolution([resolver.canonical(own[0])], f"only system of {profile}")
    if profile in arcade:
        return resolution
    return Resolution(sorted({resolver.canonical(s) for s in own}), f"systems of {profile}")


# The emulator column of a row names the frontend or a launch mode, never
# a program whose files are read: these never answer for a core.
_NOT_PROGRAMS = frozenset({"retroarch", "retroarch32", "libretro", "external", "standalone",
                           "port", "ports", "native", "sh", "os-shell", "none"})


def emulator_profile(row: dict, platform: str, cores: ProfileResolver,
                     resolver: SystemResolver, profiles: Profiles) -> str | None:
    """The profile of the program a row's emulator column names, when its
    core column names a mode, a machine or a plugin of that program: RetroBat
    runs demul for core hikaru, AmberELEC MAME for core gamate, Batocera
    mupen64plus for core glide64mk2.

    Kept only when that profile declares a system of the folder: MAME's
    profile has no GameKing, and answering MAME for its folder would leave
    out the ROM the core needs. Unresolved, the folder keeps the files of
    every core of its systems, as it did.
    """
    emulator = str(row.get("emulator") or "").strip()
    if not emulator or emulator.lower() in _NOT_PROGRAMS or emulator.lower().startswith("standalone"):
        return None
    candidate = cores.resolve(emulator)
    if not candidate:
        return None
    systems = resolver.resolve(folder_names(row), platform).systems
    own = {str(s) for s in profiles.profiles.get(candidate, {}).get("systems") or []}
    declared = {spelling for sid in own for spelling in resolver.equivalents(sid)}
    return candidate if any(resolver.equivalents(sid) & declared for sid in systems) else None


def folder_systems(setups: dict[str, dict]) -> dict[str, list[str]]:
    """Every folder name a setup gives a system, casefolded, with the systems
    any setup reads there, and each system id under its own name.

    What a games folder on a computer is read with when its setup names no
    folder of its own (RetroArch): a name two setups give two systems keeps
    both.
    """
    names: dict[str, set[str]] = {}
    for doc in setups.values():
        for row in doc["folders"]:
            systems = row["systems"]
            if not systems:
                continue
            for name in [row["folder"], *(row.get("aliases") or [])]:
                names.setdefault(str(name).casefold(), set()).update(systems)
            for system in systems:
                names.setdefault(system.casefold(), set()).add(system)
    return {name: sorted(systems) for name, systems in sorted(names.items())}
