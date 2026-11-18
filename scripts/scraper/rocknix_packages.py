"""The emulators ROCKNIX packages, by the names the profiles use, read by its
BIOS scraper and its device targets."""

from __future__ import annotations

import re


def standalone_emulators(package_names: list[str]) -> list[str]:
    """The standalone emulators ROCKNIX packages, by the names profiles use.

    A package is named after its emulator with an ``-sa`` suffix
    (``duckstation-sa``), once without its hyphen (``hatarisa``), and both
    spellings are kept so a profile listing either is found.
    """
    names: set[str] = set()
    for package in package_names:
        names.add(package)
        stripped = _emulator_of(package)
        if stripped != package:
            names.add(stripped)
    return sorted(names)


def _emulator_of(package: str) -> str:
    return re.sub(r"-?sa$", "", package) or package


def dual_mode_emulators(standalone: list[str], package_mk: str) -> list[str]:
    """The standalone emulators RetroArch also runs as a core.

    package.mk adds each launch option with `add_emu_core <system> <emulator>
    <core> <default>`. Only an emulator also added as `retroarch <core>` is
    launched both ways: ARMSX2 is added as armsx2-sa alone.
    """
    retroarch = set(re.findall(r"^\s*add_emu_core\s+\S+\s+retroarch\s+(\S+)", package_mk, re.M))
    return sorted(name for name in standalone if _emulator_of(name) in retroarch)
