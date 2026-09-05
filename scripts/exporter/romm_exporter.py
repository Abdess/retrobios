"""Exporter for RomM's known_bios_files.json.

Keys are "<igdb slug>:<filename>". RomM verifies a firmware file with
`file_size_bytes == int(entry.get("size", 0))` and then one hash among md5,
sha1 and crc, so an entry without a size can never match and an entry
without a hash can never match either. Neither is written.
"""

from __future__ import annotations

import json
import sys
from collections import OrderedDict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scraper.romm_scraper import SLUG_MAP

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/rommapp/romm/master/backend/models"
    "/fixtures/known_bios_files.json"
)


class Exporter(BaseExporter):
    """Write RomM's known_bios_files.json, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "romm"

    @staticmethod
    def native_filename() -> str:
        return "known_bios_files.json"

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"size", "crc32", "md5", "sha1"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"known_bios_files.json": SOURCE_URL}

    @staticmethod
    def _verifiable(fe: NativeFile) -> bool:
        return bool(fe.size()) and any(
            fe.hash(h) for h in ("md5", "sha1", "crc32")
        )

    @staticmethod
    def _known_platform(native_id: str) -> bool:
        """RomM keys by IGDB platform slug, and only looks up its own.

        A key spelled with one of our slugs (capcom-cps3, snk-neogeo-mvs)
        matches nothing on their side, so it is reported rather than
        written.
        """
        return native_id in SLUG_MAP

    @classmethod
    def writable(cls, fe: NativeFile, require: str = "") -> bool:
        """What RomM already ships stays; the conditions gate additions.

        An entry of theirs that could never verify is still theirs, and the
        round trip is not the place to decide otherwise.
        """
        if fe.platform is not None:
            return True
        return cls._verifiable(fe) and cls._known_platform(fe.native_system)

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        output: OrderedDict[str, dict] = OrderedDict()

        for system in sorted(systems.values(), key=lambda s: s.native_id):
            for fe in sorted(system.files, key=lambda f: f.name):
                if not self.writable(fe):
                    continue
                entry: OrderedDict[str, str] = OrderedDict()
                # The fixture states every value as a string, size included.
                entry["size"] = str(fe.size())
                crc = fe.hash("crc32")
                if crc:
                    entry["crc"] = crc
                md5 = fe.hash("md5")
                if md5:
                    entry["md5"] = md5
                sha1 = fe.hash("sha1")
                if sha1:
                    entry["sha1"] = sha1
                output[f"{system.native_id}:{fe.name}"] = entry

        text = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
        return {self.native_filename(): text}

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
            slug = key.split(":", 1)[0] if ":" in key else ""
            if not slug:
                issues.append(f"key without a platform slug: {key}")
            elif not self._known_platform(slug):
                issues.append(f"platform slug RomM does not know: {slug}")
            if not entry.get("size"):
                issues.append(f"entry without a size, never verifiable: {key}")
            if not any(entry.get(h) for h in ("md5", "sha1", "crc")):
                issues.append(f"entry without a hash, never verifiable: {key}")

        for system in systems.values():
            for fe in system.files:
                if not self.writable(fe):
                    continue
                if f"{system.native_id}:{fe.name}" not in data:
                    issues.append(f"absent: {system.native_id}/{fe.name}")
        return issues
