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
