"""What EmuELEC runs per system, read by its BIOS scraper and its device targets.

es_systems.json names the emulators of each system, ports.yaml the engine of
each port, and emuelecRunEmu.sh decides which of them are libretro cores."""

from __future__ import annotations

import shlex

from .es_emulators import SystemEmulators
from model.safeparse import yaml_load_upstream


_RAW = "https://raw.githubusercontent.com/EmuELEC/EmuELEC/{ref}/"
ES_SYSTEMS_TEMPLATE = _RAW + "packages/sx05re/emuelec-emulationstation/config/es_systems.json"
PORTS_TEMPLATE = _RAW + "packages/sx05re/emuelec-ports/sources/ports.yaml"

# es_systems.json names libretro cores under `libretro`, and `retrorun`
# loads the libretro core it lists. emuelecRunEmu.sh:101-116 turns either
# into ${CORE}_libretro. Any other emulator runs the core it names
# (EMU="${CORE}", line 107) through the case at lines 164-353.
RUNNERS: dict[str, str | None] = {"libretro": None, "retrorun": None}

# A standalone emulator and the libretro core of the same emulator, from the
# packages each one builds (packages/sx05re/emulators/<pkg>/package.mk
# PKG_SITE): hatarisa hatari/hatari, stellasa stella-emu/stella, fbneoSA
# finalburnneo/FBNeo, flycastsa flyinghead/flycast, scummvmsa
# scummvm/scummvm, PPSSPPSDL hrydgard/ppsspp.
BUILDS_OF = {
    "HATARISA": "hatari",
    "STELLASA": "stella",
    "FBNEOSA": "fbneo",
    "flycastsa": "flycast",
    "SCUMMVMSA": "scummvm",
    "PPSSPPSDL": "ppsspp",
}

# The ES system `ports` (es_systems.json:2570-2590) runs one generated
# script per entry of ports.yaml through emuelecRunApp.sh:22, and its single
# emulator `ports` is that dispatch, not a program. The scripts are rendered
# from port.sh.j2 by port_builder.py (emuelec-ports/package.mk:62-64): each
# runs its `commands`, so the engine is the libretro core a command hands
# emuelecRunEmu.sh with -C (lines 367-369 load <core>_libretro.so), or the
# program `port_exe` names.
PORTS_SYSTEM = "ports"


def port_engines(text: str) -> list[tuple[str, str, str | None, bool]]:
    """(port, engine, check_bios key, libretro?) for each entry of ports.yaml.

    The engine is written as the OS writes it: the libretro core a command
    hands emuelecRunEmu.sh with -C, else `port_exe`. `check_bios` is the
    batocera-systems key the script hands ee_check_bios on a failed start
    (port.sh.j2:23-25), the key the port's files are listed under.
    """
    data = yaml_load_upstream(text)
    if not isinstance(data, dict) or not data:
        raise ValueError("ports.yaml names no port")
    engines = []
    for port, spec in data.items():
        core = None
        for command in map(str, spec.get("commands") or []):
            if "emuelecRunEmu.sh" in command:
                core = next(
                    (w[2:] for w in shlex.split(command) if w.startswith("-C")), core
                )
        engine = core or spec.get("port_exe")
        if not engine:
            raise ValueError(f"ports.yaml: {port} names neither a core nor port_exe")
        engines.append((str(port), str(engine), spec.get("check_bios"), core is not None))
    return engines


def with_ports(
    systems: SystemEmulators, engines: list[tuple[str, str, str | None, bool]]
) -> SystemEmulators:
    """The ES systems, each port engine filed under `ports` and its own key."""
    def entry(engine: str, libretro: bool) -> tuple[str, list[str]]:
        return ("libretro", [engine]) if libretro else (engine, [engine])

    result = {**systems, PORTS_SYSTEM: [entry(e, lr) for _, e, _, lr in engines]}
    for _, engine, key, libretro in engines:
        if key:
            result[key] = [*result.get(key, []), entry(engine, libretro)]
    return result
