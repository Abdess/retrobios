"""Exporter for Recalbox's es_bios.xml.

The file is validated by es_bios.xsd, which makes path, md5 and core
required on every bios element. An entry we cannot give all three to is not
written: Recalbox would reject the file whole.

mandatory and hashMatchMandatory are separate axes. Recalbox reads a missing
attribute as true for both, so each is written only when it is false, or
when the platform stated it explicitly.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.etree.ElementTree import ParseError
from xml.sax.saxutils import quoteattr

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import parse_untrusted_xml

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report

SOURCE_URL = (
    "https://gitlab.com/recalbox/recalbox/-/raw/master/board/recalbox/fsoverlay"
    "/recalbox/share_init/system/.emulationstation/es_bios.xml"
)
SCHEMA_URL = (
    "https://gitlab.com/recalbox/recalbox/-/raw/master/board/recalbox/fsoverlay"
    "/recalbox/share_init/system/.emulationstation/es_bios.xsd"
)


class Exporter(BaseExporter):
    """Write Recalbox's es_bios.xml, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "recalbox"

    @staticmethod
    def native_filename() -> str:
        return "es_bios.xml"

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"md5", "required"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"es_bios.xml": SOURCE_URL, "es_bios.xsd": SCHEMA_URL}

    def _path(self, fe: NativeFile, native_id: str) -> str:
        """The path Recalbox reads, pipe-joined when it accepts several.

        A path Recalbox already states is reproduced exactly: several of its
        entries sit at the BIOS root with no directory at all, and prefixing
        them with the system would point the frontend somewhere else.
        """
        if fe.platform is not None:
            path = str(fe.platform.get("destination") or fe.name)
            alternatives = fe.platform.get("alt_paths") or []
            if alternatives:
                return "|".join([path, *[str(a) for a in alternatives]])
            return path
        dest = fe.destination or fe.name
        return dest if "/" in dest else f"{native_id}/{dest}"

    def _bios_element(self, fe: NativeFile, native_id: str) -> str:
        attrs = [f"path={quoteattr(self._path(fe, native_id))}"]
        attrs.append(f'md5={quoteattr(",".join(fe.hashes("md5")))}')
        attrs.append(f'core={quoteattr(",".join(fe.cores()))}')

        if not fe.required:
            attrs.append('mandatory="false"')
        elif fe.native("mandatory_declared", None) is True:
            attrs.append('mandatory="true"')

        hash_match = fe.native("hash_match_mandatory", None)
        if hash_match is False:
            attrs.append('hashMatchMandatory="false"')
        elif hash_match is True:
            attrs.append('hashMatchMandatory="true"')

        note = " ".join(str(fe.native("note", "")).split())
        if note:
            attrs.append(f"note={quoteattr(note)}")

        return f"    <bios {' '.join(attrs)} />"

    @classmethod
    def writable(cls, fe: NativeFile, require: str = "") -> bool:
        """es_bios.xsd makes md5 and core required; without them, no element.

        An entry Recalbox already ships has both, so this only ever gates
        what we would be adding.
        """
        return bool(fe.hashes("md5")) and bool(fe.cores())

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<biosList xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            ' xsi:noNamespaceSchemaLocation="es_bios.xsd">',
        ]

        for system in sorted(systems.values(), key=lambda s: s.native_id):
            writable = [fe for fe in system.files if self.writable(fe)]
            if not writable:
                continue
            fullname = quoteattr(self.display_name(system))
            platform = quoteattr(system.native_id)
            lines.append(f"  <system fullname={fullname} platform={platform}>")
            for fe in writable:
                lines.append(self._bios_element(fe, system.native_id))
            lines.append("  </system>")

        lines.append("</biosList>")
        lines.append("")
        return {self.native_filename(): "\n".join(lines)}

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        content = produced[self.native_filename()]
        issues: list[str] = []
        try:
            root = parse_untrusted_xml(content, self.native_filename())
        except (ParseError, ValueError) as exc:
            return [f"the XML does not parse: {exc}"]

        for element in root.iter("bios"):
            for attribute in ("path", "md5", "core"):
                if not element.get(attribute):
                    issues.append(
                        f"es_bios.xsd requires {attribute}: "
                        f"{element.get('path', '?')}"
                    )
        for element in root.iter("system"):
            if not list(element):
                issues.append(f"empty system: {element.get('platform', '?')}")
            for attribute in ("fullname", "platform"):
                if not element.get(attribute):
                    issues.append(f"es_bios.xsd requires {attribute} on system")

        exported = {
            element.get("path", "").casefold() for element in root.iter("bios")
        }
        for system in systems.values():
            for fe in system.files:
                if not self.writable(fe):
                    continue
                if self._path(fe, system.native_id).casefold() not in exported:
                    issues.append(f"absent: {system.native_id}/{fe.name}")
        return issues
