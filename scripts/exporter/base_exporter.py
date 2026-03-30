"""Abstract base class for platform exporters."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseExporter(ABC):
    """Base class for exporting truth data to native platform formats."""

    @staticmethod
    @abstractmethod
    def platform_name() -> str:
        """Return the platform identifier this exporter targets."""

    @abstractmethod
    def export(
        self,
        truth_data: dict,
        output_path: str,
        scraped_data: dict | None = None,
    ) -> None:
        """Export truth data to the native platform format."""

    @abstractmethod
    def validate(self, truth_data: dict, output_path: str) -> list[str]:
        """Validate exported file against truth data, return list of issues."""

    @staticmethod
    def _is_pattern(name: str) -> bool:
        """Check if a filename is a placeholder pattern (not a real file)."""
        return "<" in name or ">" in name or "*" in name

    @staticmethod
    def _dest(fe: dict) -> str:
        """Get destination path for a file entry, falling back to name."""
        return fe.get("path") or fe.get("destination") or fe.get("name", "")

    @staticmethod
    def _display_name(
        sys_id: str, scraped_sys: dict | None = None,
    ) -> str:
        """Get display name for a system from scraped data or slug."""
        if scraped_sys:
            name = scraped_sys.get("name")
            if name:
                return name
        # Fallback: convert slug to display name with acronym handling
        _UPPER = {
            "3do", "cdi", "cpc", "cps1", "cps2", "cps3", "dos", "gba",
            "gbc", "hle", "msx", "nes", "nds", "ngp", "psp", "psx",
            "sms", "snes", "stv", "tvc", "vb", "zx",
        }
        parts = sys_id.replace("-", " ").split()
        result = []
        for p in parts:
            if p.lower() in _UPPER:
                result.append(p.upper())
            else:
                result.append(p.capitalize())
        return " ".join(result)
