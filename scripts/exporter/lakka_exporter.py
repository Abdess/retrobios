"""Exporter for Lakka, which reads RetroArch's System.dat unchanged."""

from __future__ import annotations

from .systemdat_exporter import Exporter as SystemDatExporter


class Exporter(SystemDatExporter):
    """Write Lakka's System.dat, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "lakka"
