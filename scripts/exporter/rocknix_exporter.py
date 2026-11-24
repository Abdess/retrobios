"""Exporter for ROCKNIX's rocknix-systems.

Same shape as Batocera's script: a systems mapping inside a checker ROCKNIX
runs, so only the mapping is rewritten.
"""

from __future__ import annotations

import re

from resolve.nativemodel import NativeSystem, Report
from .batocera_exporter import Exporter as BatoceraExporter

SOURCE_URL = (
    "https://raw.githubusercontent.com/ROCKNIX/distribution/next/projects/ROCKNIX"
    "/packages/rocknix/sources/scripts/rocknix-systems"
)


EMULATORS_URL = (
    "https://raw.githubusercontent.com/ROCKNIX/distribution/next/projects/ROCKNIX"
    "/packages/virtual/emulators/package.mk"
)
EMULATORS_MK = "emulators/package.mk"
# `add_emu_core <system> <emulator> <core> <default>`: the pairs es_systems.cfg
# lists, and so the names checkBios's emuDict holds.
_ADD_EMU_CORE = re.compile(r"^\s*add_emu_core\s+(\S+)\s+(\S+)\s+(\S+)", re.MULTILINE)


class Exporter(BatoceraExporter):
    """Write ROCKNIX's rocknix-systems, corrected."""

    def __init__(self, profiles: dict[str, dict] | None = None) -> None:
        super().__init__(profiles)
        self._pairs: set[tuple[str, str]] = set()

    def _runner_pair(self, runner: tuple[bool, str]) -> tuple[str, str | None] | None:
        """ROCKNIX registers libretro cores under `retroarch` and each
        standalone under its own emulator (`azahar azahar-sa`), in the
        emulators package. The `libretro` Batocera writes names nothing
        there.

        The build decides which registration answers. A libretro core is the
        `retroarch` pair of that core. A standalone is its own emulator's
        pair: DuckStation is registered both ways, and looking the standalone
        up as a core name sent its 98 files to the libretro core's users.
        """
        standalone, name = runner
        if not standalone:
            return ("retroarch", name) if ("retroarch", name) in self._pairs else None
        own = sorted(
            pair for pair in self._pairs
            if pair[0] == name or (pair[1] == name and pair[0] != "retroarch")
        )
        return own[0] if own else None

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        self._pairs = {
            (emulator, core)
            for _system, emulator, core in _ADD_EMU_CORE.findall(
                originals.get(EMULATORS_MK, "")
            )
        }
        return super().render(systems, report, originals, scraped)

    @staticmethod
    def platform_name() -> str:
        return "rocknix"

    @staticmethod
    def native_filename() -> str:
        return "rocknix-systems"

    @staticmethod
    def file_modes() -> dict[str, int]:
        # 100755 in ROCKNIX's tree at the pinned tag (git/trees 20261001).
        return {"rocknix-systems": 0o755}

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"rocknix-systems": SOURCE_URL, EMULATORS_MK: EMULATORS_URL}
