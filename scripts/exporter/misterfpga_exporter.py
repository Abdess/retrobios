"""Exporter for MiSTer's BiosDB (bios_db.json, shipped zipped).

A Downloader database entry carries the download URL, the install path and
the tag ids alongside the hash, and none of those are ours to invent. Only
the hash and the size are rewritten, in MiSTer's own database.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections import OrderedDict

from .base_exporter import BaseExporter
from .baseline import NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/ajgowans/BiosDB_MiSTer/db/bios_db.json.zip"
)
_DB_NAME = "bios_db.json"


class Exporter(BaseExporter):
    """Write MiSTer's bios_db.json, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "misterfpga"

    @staticmethod
    def native_filename() -> str:
        return _DB_NAME

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"md5", "size"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"bios_db.json.zip": SOURCE_URL}

    @staticmethod
    def can_add() -> bool:
        # Every entry carries the URL MiSTer installs it from, and that is
        # not ours to invent.
        return False

    @staticmethod
    def needs_original() -> bool:
        # Entries carry a URL and a tag vocabulary the database owns.
        return True

    @staticmethod
    def unpack(raw: bytes) -> dict[str, str]:
        """Read the database out of the archive MiSTer publishes."""
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return {_DB_NAME: archive.read(_DB_NAME).decode("utf-8")}

    def _by_path(self, systems: dict[str, NativeSystem]) -> dict[str, object]:
        indexed: dict[str, object] = {}
        for system in systems.values():
            for fe in system.files:
                if fe.destination:
                    indexed[f"games/{fe.destination}"] = fe
        return indexed

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        original = originals.get(_DB_NAME) or originals.get("bios_db.json.zip")
        if not original:
            raise ValueError(
                "bios_db.json cannot be written without MiSTer's own database: "
                "every entry carries a URL and tag ids that are not ours"
            )
        database = json.loads(original, object_pairs_hook=OrderedDict)
        indexed = self._by_path(systems)

        for path, entry in database.get("files", {}).items():
            fe = indexed.get(path)
            if fe is None:
                continue
            md5 = fe.hash("md5")
            if md5:
                entry["hash"] = md5
            size = fe.size()
            if size:
                entry["size"] = size

        return {_DB_NAME: json.dumps(database, indent=2, ensure_ascii=False) + "\n"}

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        try:
            database = json.loads(produced[_DB_NAME])
        except json.JSONDecodeError as exc:
            return [f"the database does not parse: {exc}"]

        issues: list[str] = []
        if not database.get("db_id"):
            issues.append("the database lost its db_id")
        files = database.get("files", {})
        if not files:
            issues.append("the database has no files left")
        for path, entry in files.items():
            if not entry.get("hash"):
                issues.append(f"entry without a hash: {path}")
            if not entry.get("url"):
                issues.append(f"entry without a URL, uninstallable: {path}")

        indexed = self._by_path(systems)
        for path, fe in indexed.items():
            declared = files.get(path)
            md5 = fe.hash("md5")
            if declared is not None and md5 and declared.get("hash") != md5:
                issues.append(f"hash not applied: {path}")
        return issues
