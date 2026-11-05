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
from .baseline import NativeFile, NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/ajgowans/BiosDB_MiSTer/db/bios_db.json.zip"
)
_DB_NAME = "bios_db.json"


_ARCHIVE = "bios_db.json.zip"


def rebuild_archive(original: bytes, member: str, text: str) -> bytes:
    """The archive with one member's content replaced, as MiSTer writes it.

    The member keeps its name, date, compression and attributes, so the
    archive differs from MiSTer's only by the content that changed.
    """
    with zipfile.ZipFile(io.BytesIO(original)) as source:
        info = source.getinfo(member)
    rebuilt = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    rebuilt.compress_type = info.compress_type
    rebuilt.external_attr = info.external_attr
    rebuilt.create_system = info.create_system
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as target:
        target.writestr(rebuilt, text.encode("utf-8"))
    return buffer.getvalue()


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

    def states(self, fe: NativeFile, field_name: str) -> bool:
        """A correction whose path the database does not hold is not written."""
        written = getattr(self, "_written", None)
        if written is not None and id(fe) not in written:
            return False
        return super().states(fe, field_name)

    def written(self, fe: NativeFile, field_name: str) -> str:
        """An entry is one record: its md5, size and url describe one dump.

        The first value the truth accepts replaced MiSTer's own accepted
        md5 while the url still served MiSTer's dump, which the Downloader
        then refused (fetch_file_worker.py:127), and the report said
        nothing. record_hash keeps the platform's value when it is accepted.
        """
        return fe.record_hash(field_name)

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
    ) -> dict[str, str | bytes]:
        original = originals.get(_DB_NAME) or originals.get("bios_db.json.zip")
        if not original:
            raise ValueError(
                "bios_db.json cannot be written without MiSTer's own database: "
                "every entry carries a URL and tag ids that are not ours"
            )
        database = json.loads(original, object_pairs_hook=OrderedDict)
        indexed = self._by_path(systems)
        self._written = set()
        self._unsized: list[str] = []

        for path, entry in database.get("files", {}).items():
            fe = indexed.get(path)
            if fe is None:
                continue
            md5 = self.written(fe, "md5")
            if not md5:
                # The record is checked by its md5: where the truth takes the
                # entry without one, a new size beside the old hash describes
                # no file, and the entry is left as MiSTer wrote it.
                continue
            size = fe.size()
            if md5 != entry.get("hash") and entry.get("size") and not size:
                # Downloader refuses an entry without an integer size
                # (db_entity.py:187) and compares it after each fetch
                # (fetch_file_worker.py:127). The old size beside the new
                # hash describes the dump the truth rejects, so the entry
                # stays as MiSTer wrote it.
                self._unsized.append(path)
                continue
            self._written.add(id(fe))
            entry["hash"] = md5
            if size:
                entry["size"] = size

        # MiSTer publishes the database as one line, without a final
        # newline: written with an indent it came out as 1499 changed lines.
        text = json.dumps(database, ensure_ascii=False)
        produced: dict[str, str | bytes] = {_DB_NAME: text}
        # MiSTer's Downloader fetches the archive, not the JSON in it: handed
        # back as it came when nothing changed, rebuilt around the new
        # member otherwise.
        archive = self.archive(_ARCHIVE)
        if archive is not None:
            unchanged = text == originals.get(_DB_NAME)
            produced[_ARCHIVE] = archive if unchanged else rebuild_archive(archive, _DB_NAME, text)
        return produced

    def withheld(self) -> list[str]:
        """Each hash correction left out for want of the new dump's size."""
        return [
            f"{path} keeps its hash: the truth states no size for the new "
            "dump, and the Downloader checks every entry by size"
            for path in getattr(self, "_unsized", [])
        ]

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
            md5 = self.written(fe, "md5")
            if (
                declared is not None and md5 and declared.get("hash") != md5
                and path not in getattr(self, "_unsized", [])
            ):
                issues.append(f"hash not applied: {path}")
        return issues
