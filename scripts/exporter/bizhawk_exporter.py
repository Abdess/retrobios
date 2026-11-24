"""Exporter for BizHawk's FirmwareDatabase.cs.

The database is C#: every firmware is a call whose arguments are the SHA1,
the size, the file name and a description, wired into option lists and
status flags that only the source expresses. Every hash it states is
BizHawk's own and every hash it leaves out is left out on purpose, so the
file is served as BizHawk wrote it, checked for its structure.
"""

from __future__ import annotations

from .base_exporter import BaseExporter
from resolve.nativemodel import NativeFile, NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/TASEmulators/BizHawk/master"
    "/src/BizHawk.Emulation.Common/Database/FirmwareDatabase.cs"
)


class Exporter(BaseExporter[str]):
    """Serve BizHawk's FirmwareDatabase.cs as BizHawk wrote it."""

    @staticmethod
    def platform_name() -> str:
        return "bizhawk"

    @staticmethod
    def native_filename() -> str:
        return "FirmwareDatabase.cs"

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"FirmwareDatabase.cs": SOURCE_URL}

    @staticmethod
    def can_add() -> bool:
        # A firmware is a call wired into an option list and a status: the
        # exporter does not write C#.
        return False

    @staticmethod
    def needs_original() -> bool:
        # The database is code: option lists, statuses and the systems they
        # hang off exist nowhere else.
        return True

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"sha1", "size"})

    def states(self, fe: NativeFile, field_name: str) -> bool:
        """No hash or size is written, so no correction is delivered.

        Every call holding a hash holds one BizHawk declares, the authority
        for its cores. The calls without one are SHA1Checksum.Dummy, a
        per-console dump (DSi firmware, NAND) BizHawk leaves unhashed on
        purpose. The rewrite this exporter had could only ever fire on a
        same-named call of another system, giving it the wrong system's hash.
        """
        if field_name in ("sha1", "size"):
            return False
        return super().states(fe, field_name)

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        source = originals.get(self.native_filename(), "")
        if not source:
            raise ValueError(
                "FirmwareDatabase.cs cannot be written without BizHawk's own "
                "file: the database is C#, not data"
            )
        return {self.native_filename(): source}

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        content = produced[self.native_filename()]
        issues: list[str] = []

        if "FirmwareDatabase" not in content:
            issues.append("the class the database lives in is missing")
        if content.count("{") != content.count("}"):
            issues.append("braces are unbalanced, the file would not compile")
        return issues
