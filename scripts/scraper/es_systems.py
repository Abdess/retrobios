"""The systems and cores Batocera's es_systems.yml offers."""

from __future__ import annotations

from collections.abc import Callable, Iterator

from model.safeparse import yaml_load_upstream


def es_systems_data(text: str) -> dict:
    """es_systems.yml as a mapping, ValueError when it is not one."""
    data = yaml_load_upstream(text)
    if not isinstance(data, dict):
        raise ValueError("es_systems.yml is not a mapping")
    return data


def system_entries(spec: object) -> Iterator[tuple[str, str | None, dict | None]]:
    """(emulator, core, core spec) for each core one es_systems.yml system offers.

    A system lists each emulator a user may pick and the cores under it.
    Keys whose value is not a mapping (archs_include) describe the entry,
    not a core. An emulator that lists no core is yielded once with None.
    """
    emulators = spec.get("emulators") if isinstance(spec, dict) else None
    if not isinstance(emulators, dict):
        return
    for emulator, entries in emulators.items():
        if not isinstance(entries, dict):
            continue
        offered = [(str(core), item) for core, item in entries.items() if isinstance(item, dict)]
        if not offered:
            yield str(emulator), None, None
        for core, item in offered:
            yield str(emulator), core, item


def es_systems_entries(text: str) -> Iterator[tuple[str, str, str | None, dict | None]]:
    """(system, emulator, core, core spec) for every core es_systems.yml offers.

    `emulator` is `libretro` for a libretro core. Any other emulator is its
    own core, and what it lists under it are machines or builds. Raises
    ValueError when the file is not a mapping.
    """
    for system, spec in es_systems_data(text).items():
        for emulator, core, item in system_entries(spec):
            yield str(system), emulator, core, item


def es_systems_emulators(text: str) -> tuple[set[str], set[str]]:
    """Every core es_systems.yml offers, and those that run standalone.

    configgen-defaults.yml only names the one picked by default, so
    reading it alone left DOSBox Staging, melonDS DS and nine other built
    cores outside the pack. The non-cores a standalone emulator lists are
    named in the overrides.
    """
    cores: set[str] = set()
    standalone: set[str] = set()
    for _system, emulator, core, _spec in es_systems_entries(text):
        names = {core} if core else set()
        if emulator != "libretro":
            names.add(emulator)
            standalone |= names
        cores |= names
    return cores, standalone


def es_systems_libretro(text: str) -> set[str]:
    """The cores es_systems.yml offers under `libretro:` for some system."""
    return {
        core for _system, emulator, core, _spec in es_systems_entries(text)
        if emulator == "libretro" and core
    }


def es_systems_libretro_systems(text: str, dropped: set[str]) -> dict[str, list[str]]:
    """libretro core -> the systems es_systems.yml offers it under `libretro:`.

    configgen hands a libretro core /userdata/saves/<system> at each launch
    (libretroConfig.py: savefile_directory = SAVES / system.name), so a file
    a core reads below its save directory sits once in each of these
    system folders.
    """
    found: dict[str, set[str]] = {}
    for system, emulator, core, _spec in es_systems_entries(text):
        if emulator == "libretro" and core and core not in dropped:
            found.setdefault(core, set()).add(system)
    return {core: sorted(systems) for core, systems in sorted(found.items())}


def es_systems_by_system(
    es_systems_text: str, defaults_text: str, dropped: set[str],
    built: Callable[[str], bool] | None = None,
) -> dict[str, list[str]]:
    """system -> the cores es_systems.yml offers it, in the file's order.

    Read as configgen_cores reads the whole list: a core under `libretro:`
    is a libretro core, any other emulator is its own core and so is each
    build it lists. The core configgen-defaults.yml starts by default comes
    last when es_systems.yml does not offer it.
    """
    data = es_systems_data(es_systems_text)
    defaults = yaml_load_upstream(defaults_text)
    if not isinstance(defaults, dict):
        raise ValueError("configgen-defaults.yml is not a mapping")
    result: dict[str, list[str]] = {}
    for system, spec in data.items():
        names: list[str] = []
        for offered, core, _item in system_entries(spec):
            if offered != "libretro":
                names.append(offered)
            if core:
                names.append(core)
        default = defaults.get(system)
        if isinstance(default, dict):
            emulator, core = default.get("emulator"), default.get("core")
            if (built is not None and emulator and emulator != "libretro"
                    and str(emulator) not in names and not built(str(emulator))):
                # A default the build lacks (configgen_cores).
                emulator = core = None
            if emulator and emulator != "libretro":
                names.append(str(emulator))
            if core:
                names.append(str(core))
        names = [n for n in dict.fromkeys(names) if n not in dropped]
        if names:
            result[str(system)] = names
    return result
