"""Exporter for AmberELEC's batocera-systems.

Batocera's script shape, so only the systems dict is rewritten. Two things
differ. Paths are relative to /storage/roms, where the list also names
neogeo/ beside bios/, and our destinations start there too. No entry carries
an emulator or core gate: coreExists() lets an ungated item through for
every build, and an addition is written the same way.
"""

from __future__ import annotations

from resolve.reconcile import NativeFile
from .batocera_exporter import Exporter as BatoceraExporter

SOURCE_URL = (
    "https://raw.githubusercontent.com/AmberELEC/AmberELEC/dev"
    "/packages/amberelec/sources/scripts/batocera-systems"
)


class Exporter(BatoceraExporter):
    """Write AmberELEC's batocera-systems, corrected."""

    PATH_PREFIX = ""

    # The list gates nothing on a runner, so an addition needs none.
    RUNNER_GATED = False

    def _addition_keys(self, fe: NativeFile) -> list[tuple[str, str | None]] | None:
        return []

    @staticmethod
    def platform_name() -> str:
        return "amberelec"

    @staticmethod
    def file_modes() -> dict[str, int]:
        # 100755 at a21975bf (git/trees).
        return {"batocera-systems": 0o755}

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"batocera-systems": SOURCE_URL}
