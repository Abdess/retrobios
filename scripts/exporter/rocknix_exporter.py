"""Exporter for ROCKNIX's rocknix-systems.

Same shape as Batocera's script: a systems mapping inside a checker ROCKNIX
runs, so only the mapping is rewritten.
"""

from __future__ import annotations

from .batocera_exporter import Exporter as BatoceraExporter

SOURCE_URL = (
    "https://raw.githubusercontent.com/ROCKNIX/distribution/next/projects/ROCKNIX"
    "/packages/rocknix/sources/scripts/rocknix-systems"
)


class Exporter(BatoceraExporter):
    """Write ROCKNIX's rocknix-systems, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "rocknix"

    @staticmethod
    def native_filename() -> str:
        return "rocknix-systems"

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"rocknix-systems": SOURCE_URL}
