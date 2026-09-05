"""Exporter for BizHawk's FirmwareDatabase.cs.

The database is C#: every firmware is a call whose arguments are the SHA1,
the size, the file name and a description, wired into option lists and
status flags that only the source expresses. The calls are rewritten in
place, and nothing else in the file is touched.
"""

from __future__ import annotations

import re

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/TASEmulators/BizHawk/master"
    "/src/BizHawk.Emulation.Common/Database/FirmwareDatabase.cs"
)

# File("<sha1>", <size>, "<name>", ...) and the same three arguments inside
# FirmwareAndOption(<sha1>, <size>, <system>, <id>, <name>, ...).
_FILE_CALL = re.compile(
    r'(File\(\s*")([0-9A-Fa-f]{40})("\s*,\s*)(\d+)(\s*,\s*")([^"]+)(")'
)
_FIRMWARE_AND_OPTION = re.compile(
    r'(FirmwareAndOption\(\s*")([0-9A-Fa-f]{40})("\s*,\s*)(\d+)'
    r'(\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*")([^"]+)(")'
)


class Exporter(BaseExporter):
    """Write BizHawk's FirmwareDatabase.cs, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "bizhawk"

    @staticmethod
    def native_filename() -> str:
        return "FirmwareDatabase.cs"

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"sha1", "size"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"FirmwareDatabase.cs": SOURCE_URL}

    @staticmethod
    def can_add() -> bool:
        # A firmware is a call wired into an option list and a status; the
        # exporter corrects the calls that exist, it does not write C#.
        return False

    @staticmethod
    def needs_original() -> bool:
        # The database is code: option lists, statuses and the systems they
        # hang off exist nowhere else.
        return True

    @staticmethod
    def _unambiguous(systems: dict[str, NativeSystem]) -> dict[str, NativeFile]:
        """Files whose name identifies exactly one entry with a SHA1.

        BizHawk names a firmware by file name inside a system, and the same
        name recurs across systems. Correcting on a name that resolves to
        two different sets of bytes would corrupt the database, so only the
        names that resolve to one are touched.
        """
        seen: dict[str, list[NativeFile]] = {}
        for system in systems.values():
            for fe in system.files:
                if fe.hash("sha1"):
                    seen.setdefault(fe.name.casefold(), []).append(fe)
        resolved: dict[str, NativeFile] = {}
        for name, entries in seen.items():
            hashes = {fe.hash("sha1").lower() for fe in entries}
            if len(hashes) == 1:
                resolved[name] = entries[0]
        return resolved

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

        index = self._unambiguous(systems)

        def commented_out(text: str, position: int) -> bool:
            """Whether the call sits on a line the compiler never sees.

            BizHawk keeps disabled entries in place behind //, and a hash
            written into one of those is a change to a comment.
            """
            line_start = text.rfind("\n", 0, position) + 1
            return text[line_start:position].lstrip().startswith("//")

        def rewrite(match: re.Match[str], name_group: int) -> str:
            if commented_out(match.string, match.start()):
                return match.group(0)
            name = match.group(name_group)
            fe = index.get(name.casefold())
            if fe is None:
                return match.group(0)
            sha1 = fe.hash("sha1").upper()
            size = fe.size() or int(match.group(4))
            groups = list(match.groups())
            groups[1] = sha1
            groups[3] = str(size)
            return "".join(groups)

        patched = _FILE_CALL.sub(lambda m: rewrite(m, 6), source)
        patched = _FIRMWARE_AND_OPTION.sub(lambda m: rewrite(m, 6), patched)
        return {self.native_filename(): patched}

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

        index = self._unambiguous(systems)
        declared: dict[str, str] = {}
        for pattern in (_FILE_CALL, _FIRMWARE_AND_OPTION):
            for match in pattern.finditer(content):
                line_start = content.rfind("\n", 0, match.start()) + 1
                if content[line_start : match.start()].lstrip().startswith("//"):
                    continue
                declared[match.group(6).casefold()] = match.group(2).lower()

        for name, fe in index.items():
            written = declared.get(name)
            if written is not None and written != fe.hash("sha1").lower():
                issues.append(f"hash not applied: {fe.name}")
        return issues
