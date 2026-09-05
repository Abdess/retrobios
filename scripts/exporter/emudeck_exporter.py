"""Exporter for EmuDeck's checkBIOS.sh.

checkBIOS.sh is a shell library: each system is a function EmuDeck calls by
name, and the only data in it is the MD5 list each function matches against.
Writing the functions from a table would publish a file missing whichever
checks the table forgot, so the original is patched instead and every
function it defines keeps its shape, its scan directory and its output.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scraper.emudeck_scraper import FUNCTION_HASH_MAP, _RE_FUNC, _RE_LOCAL_HASHES

from .base_exporter import BaseExporter
from .baseline import NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/dragoonDorise/EmuDeck/main"
    "/functions/checkBIOS.sh"
)
_MD5 = re.compile(r"^[0-9a-f]{32}$")


class Exporter(BaseExporter):
    """Write EmuDeck's checkBIOS.sh, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "emudeck"

    @staticmethod
    def native_filename() -> str:
        return "checkBIOS.sh"

    @staticmethod
    def requires() -> str:
        return "md5"

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"md5"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"checkBIOS.sh": SOURCE_URL}

    @staticmethod
    def needs_original() -> bool:
        # The checks are code, and EmuDeck calls them by name.
        return True

    @staticmethod
    def can_add() -> bool:
        """A hash is corrected in place, never added to an array.

        EmuDeck's frontend calls one check for several emulators
        (EmulatorsDetailPage.jsx: 'ra' asks checkPS1BIOS, checkSegaCDBios,
        checkSaturnBios, checkDSBios and checkDreamcastBios, and
        'duckstation' asks checkPS1BIOS as well), and nothing in
        checkBIOS.sh names them. Growing an array therefore changes answers
        for consumers the array does not list: DuckStation boots from a PS2
        image, the RetroArch PSX cores do not, so adding the ones
        DuckStation accepts would report a BIOS to a card that has none.
        Correcting a value in place changes no consumer's set.
        """
        return False

    @classmethod
    def _md5s(cls, systems: dict[str, NativeSystem], system_id: str) -> list[str]:
        """Every MD5 the system accepts, in a stable order, deduplicated."""
        seen: list[str] = []
        for system in systems.values():
            if system.native_id != system_id:
                continue
            for fe in system.files:
                if not cls.writable(fe):
                    continue
                for value in fe.hashes("md5"):
                    if _MD5.match(value) and value not in seen:
                        seen.append(value)
        return seen

    def _function_spans(self, script: str) -> list[tuple[str, int, int]]:
        """Name and byte span of every check the script defines."""
        matches = list(_RE_FUNC.finditer(script))
        spans: list[tuple[str, int, int]] = []
        for index, match in enumerate(matches):
            end = (
                matches[index + 1].start()
                if index + 1 < len(matches)
                else len(script)
            )
            spans.append((match.group(1), match.start(), end))
        return spans

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        script = originals.get(self.native_filename(), "")
        if not script:
            raise ValueError(
                "checkBIOS.sh cannot be written without EmuDeck's own file: "
                "the checks are code, not data"
            )

        pieces: list[str] = []
        cursor = 0
        for name, start, end in self._function_spans(script):
            pieces.append(script[cursor:start])
            body = script[start:end]
            system_id = FUNCTION_HASH_MAP.get(name)
            md5s = self._md5s(systems, system_id) if system_id else []
            match = _RE_LOCAL_HASHES.search(body)
            if md5s and match:
                # An array compared by membership says nothing about order,
                # so the same set is left as the maintainer wrote it.
                if set(md5s) != set(match.group(1).split()):
                    body = (
                        body[: match.start(1)]
                        + " ".join(md5s)
                        + body[match.end(1) :]
                    )
            pieces.append(body)
            cursor = end
        pieces.append(script[cursor:])

        return {self.native_filename(): "".join(pieces)}

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        content = produced[self.native_filename()]
        issues: list[str] = []

        defined = {name for name, _, _ in self._function_spans(content)}
        for name, system_id in FUNCTION_HASH_MAP.items():
            if name not in defined:
                issues.append(f"check absent from the output: {name}")
                continue
            md5s = self._md5s(systems, system_id)
            if not md5s:
                continue
            body = next(
                content[start:end]
                for fname, start, end in self._function_spans(content)
                if fname == name
            )
            if not _RE_LOCAL_HASHES.search(body):
                # A check with no hash list is a path check, not a hash check.
                continue
            for md5 in md5s:
                if md5 not in body:
                    issues.append(f"absent from {name}: {md5}")
        return issues
