"""Exporter for RetroBat's batocera-systems.json.

Pure data: a system key carrying a name and a biosFiles array whose entries
state md5 then file, in that order.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/master"
    "/batocera-systems/Resources/batocera-systems.json"
)


_TOP_KEY = re.compile(r'^  "((?:[^"\\]|\\.)*)":', re.MULTILINE)


def keep_blank_lines(original: str, produced: str) -> str:
    """The blank line RetroBat writes before each system, written again.

    json.dumps has no blank lines, and the original separates every system
    after the first with one: dropped, they were 100 hunks of a diff meant
    to show corrections. A system the original separates is separated, and
    where it separates them all, an added one is too.
    """
    keys = _TOP_KEY.findall(original)
    separated = set(re.findall(r'\n\n  "((?:[^"\\]|\\.)*)":', original))
    every = bool(keys) and separated == set(keys[1:])
    first = True

    def separate(match: re.Match[str]) -> str:
        nonlocal first
        key, was_first = match.group(1), first
        first = False
        if not was_first and (key in separated or (every and key not in keys)):
            return "\n" + match.group(0)
        return match.group(0)

    return _TOP_KEY.sub(separate, produced)


class Exporter(BaseExporter):
    """Write RetroBat's batocera-systems.json, corrected."""

    # One md5 per entry, compared as Batocera's checkBios does.
    SINGLE_HASH_FIELD = "md5"

    @staticmethod
    def platform_name() -> str:
        return "retrobat"

    @staticmethod
    def native_filename() -> str:
        return "batocera-systems.json"

    @staticmethod
    def requires() -> str:
        return "md5"

    @staticmethod
    def keys_by_system() -> bool:
        return True

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"md5"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"batocera-systems.json": SOURCE_URL}

    def states(self, fe: NativeFile, field_name: str) -> bool:
        if field_name == "md5" and "md5" in fe.filled:
            return bool(self.single_value(fe, "md5"))
        return super().states(fe, field_name)

    def __init__(self) -> None:
        super().__init__()
        # Additions render did not write: another entry holds their path.
        self._merged: set[int] = set()

    @staticmethod
    def _path(fe: NativeFile) -> str:
        declared = fe.native("native_path", "")
        return str(declared) if declared else f"bios/{fe.destination}"

    def lands(self, fe: NativeFile) -> bool:
        """An addition lands only where render wrote it."""
        return self.writable(fe) and id(fe) not in self._merged

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        # The platform's own file is the base: its key and entry order stay,
        # so the diff a maintainer reads is the corrections and nothing else,
        # and a system or file our transcription does not carry (RetroBat
        # renamed ic10_g24lc64 after a scrape) is kept as RetroBat wrote it.
        base: dict = {}
        original = originals.get(self.native_filename(), "")
        if original:
            try:
                base = json.loads(original, object_pairs_hook=OrderedDict)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"RetroBat's {self.native_filename()} does not parse ({exc}); "
                    "fetch it again with --refresh-cache"
                ) from exc

        self._merged = set()
        exportable = {
            system.native_id: (system, files)
            for system, files in self.exportable(systems, require="md5")
        }
        keys = list(base)
        keys.extend(sorted(k for k in exportable if k not in base))

        output: OrderedDict[str, object] = OrderedDict()
        for key in keys:
            if key not in exportable:
                output[key] = base[key]
                continue
            system, files = exportable[key]
            ours: OrderedDict[str, OrderedDict[str, object]] = OrderedDict()
            # The checker reads one md5 per biosFiles item and reports the
            # item by its path, so a path holds one item. An addition whose
            # path the platform or an earlier addition holds is not written.
            claimed = {self._path(fe) for fe in files if fe.platform is not None}
            for fe in files:
                path = self._path(fe)
                if fe.platform is None and (path in claimed or path in ours):
                    self._merged.add(id(fe))
                    continue
                entry: OrderedDict[str, object] = OrderedDict()
                entry["md5"] = self.single_value(fe, "md5")
                entry["file"] = path
                # The two fields Program.cs reads besides md5 and file, as the
                # scraper took them: group (one held file is enough) and
                # optional (required: false).
                if fe.platform is not None and fe.platform.get("group"):
                    entry["group"] = str(fe.platform["group"])
                if fe.platform is not None and fe.platform.get("required") is False:
                    entry["optional"] = True
                ours.setdefault(path, entry)
            bios_files = []
            for theirs in (base.get(key) or {}).get("biosFiles", []):
                bios_files.append(ours.pop(theirs.get("file"), theirs))
            bios_files.extend(ours.values())
            system_entry: OrderedDict[str, object] = OrderedDict()
            system_entry["name"] = self.display_name(system)
            system_entry["biosFiles"] = bios_files
            output[key] = system_entry

        text = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
        original = (originals or {}).get(self.native_filename(), "")
        return {self.native_filename(): keep_blank_lines(original, text) if original else text}

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        try:
            data = json.loads(produced[self.native_filename()])
        except json.JSONDecodeError as exc:
            return [f"the JSON does not parse: {exc}"]

        issues: list[str] = []
        for key, entry in data.items():
            if not entry.get("name"):
                issues.append(f"system without a name: {key}")
            if not entry.get("biosFiles"):
                issues.append(f"empty entry: {key}")
            for bios in entry.get("biosFiles", []):
                # RetroBat states an unhashed file with an empty md5, so only
                # a missing path makes an entry unusable.
                if "md5" not in bios or not bios.get("file"):
                    issues.append(f"incomplete entry: {key}/{bios.get('file', '?')}")

        for system, files in self.exportable(systems, require="md5"):
            entry = data.get(system.native_id)
            if entry is None:
                issues.append(f"system absent: {system.native_id}")
                continue
            declared = {bios.get("file") for bios in entry.get("biosFiles", [])}
            for fe in files:
                if self._path(fe) not in declared:
                    issues.append(f"absent: {system.native_id}/{fe.name}")
        return issues
