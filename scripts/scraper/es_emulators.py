"""The emulators an EmulationStation system list offers, by system.

AmberELEC writes its list as es_systems.cfg XML, EmuELEC as an es_systems.json
it turns into that XML at build time. Both name, per system and in the order
the menu shows them, the emulators a user may pick and the cores under each.
Some emulators are libretro front ends (RetroArch, retrorun) whose cores are
libretro core names. Every other emulator is a standalone program, named as
the OS's launch code dispatches on it (`HATARISA`, `PPSSPPSDL`): profiles
answer to that spelling in their `cores:`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping

from model.safeparse import parse_untrusted_xml

# system -> [(emulator, [core, ...]), ...], both in the list's order.
SystemEmulators = dict[str, list[tuple[str, list[str]]]]


def xml_systems(text: str) -> SystemEmulators:
    """Each system's emulators and cores, from an es_systems.cfg."""
    root = parse_untrusted_xml(text, "es_systems.cfg")
    systems: SystemEmulators = {}
    for system in root.iter("system"):
        name = (system.findtext("name") or "").strip()
        if not name:
            continue
        systems[name] = [
            (emulator.get("name"),
             [core.text.strip() for core in emulator.iter("core") if core.text])
            for emulator in system.iter("emulator")
            if emulator.get("name")
        ]
    if not any(systems.values()):
        raise ValueError("es_systems.cfg names no emulator")
    return systems


def json_systems(text: str) -> SystemEmulators:
    """Each system's emulators and cores, from an es_systems.json."""
    systems: SystemEmulators = {}
    for system in json.loads(text).get("systems", []):
        systems[system["name"]] = [
            (emulator["name"], [core["name"] for core in emulator.get("cores") or []])
            for emulator in system.get("emulators") or []
        ]
    if not any(systems.values()):
        raise ValueError("es_systems.json names no emulator")
    return systems


def _pairs(systems: SystemEmulators) -> dict[str, set[str]]:
    pairs: dict[str, set[str]] = {}
    for emulators in systems.values():
        for emulator, cores in emulators:
            pairs.setdefault(emulator, set()).update(cores)
    return pairs


def xml_emulators(text: str) -> dict[str, set[str]]:
    """Emulator -> cores, from an es_systems.cfg."""
    return _pairs(xml_systems(text))


def json_emulators(text: str) -> dict[str, set[str]]:
    """Emulator -> cores, from an es_systems.json."""
    return _pairs(json_systems(text))


def _names(
    emulator: str,
    cores: Iterable[str],
    runners: Mapping[str, str | None],
) -> list[str]:
    """The core names one emulator entry stands for.

    A runner's entry stands for the libretro cores it lists, or for the one
    core it always loads. A standalone emulator stands for itself.
    """
    if emulator in runners:
        fixed = runners[emulator]
        return [fixed] if fixed else list(cores)
    return [emulator]


def system_cores(
    systems: SystemEmulators,
    runners: Mapping[str, str | None],
    not_cores: Iterable[str] = (),
) -> dict[str, list[str]]:
    """system -> the cores it runs, in the list's order, as the OS writes them."""
    dropped = set(not_cores)
    result: dict[str, list[str]] = {}
    for system, emulators in systems.items():
        names = [
            name
            for emulator, cores in emulators
            for name in _names(emulator, cores, runners)
            if name not in dropped
        ]
        if names:
            result[system] = list(dict.fromkeys(names))
    return result


def es_cores(
    systems: SystemEmulators,
    runners: Mapping[str, str | None],
    builds_of: Mapping[str, str] | None = None,
    not_cores: Iterable[str] = (),
) -> tuple[list[str], list[str], list[str]]:
    """(cores, standalone_cores, dual_mode_cores) of an ES system list.

    `runners` maps each emulator that runs libretro cores to None when the
    cores it lists are libretro core names, or to the one core it always
    loads (AmberELEC's `mame` lists MAME machines and loads the MAME core).
    `builds_of` maps a standalone emulator to the libretro core of the same
    emulator, each pair read in the OS's packages: the standalone one is
    dual-mode when the list also offers that core, as is a standalone name
    the list also offers as a core. `not_cores` names what
    the list files as an emulator without emulating anything (a media
    player, a runtime).
    """
    builds_of = builds_of or {}
    dropped = set(not_cores)
    libretro: set[str] = set()
    standalone: set[str] = set()
    for emulators in systems.values():
        for emulator, cores in emulators:
            names = {n for n in _names(emulator, cores, runners) if n not in dropped}
            (libretro if emulator in runners else standalone).update(names)
    dual = {
        name for name in standalone
        if name in libretro or builds_of.get(name) in libretro
    }
    return sorted(libretro | standalone), sorted(standalone), sorted(dual)


def attach_system_cores(
    platform_systems: dict[str, dict], by_native: Mapping[str, list[str]]
) -> None:
    """Give each platform system the cores its native systems run.

    A slug can gather several native systems (Diablo and Hellfire under
    diablo): its list is their union, in the order first met. A system the
    ES list does not name gets no list, as nothing says what runs it.
    """
    for entry in platform_systems.values():
        natives = [entry.get("native_id")] + [
            f.get("native_system") for f in entry.get("files") or []
        ]
        cores = [
            core
            for native in dict.fromkeys(n for n in natives if n)
            for core in by_native.get(native, [])
        ]
        if cores:
            entry["cores"] = list(dict.fromkeys(cores))
