"""Exporter for Recalbox's es_bios.xml.

The file is validated by es_bios.xsd, which makes path, md5 and core
required on every bios element. An entry we cannot give all three to is not
written: Recalbox would reject the file whole.

mandatory and hashMatchMandatory are separate axes. Recalbox reads a missing
attribute as true for both, so each is written only when it is false, or
when the platform stated it explicitly.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path
from xml.etree.ElementTree import Comment, ParseError
from xml.sax.saxutils import quoteattr

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import load_emulator_profiles, parse_untrusted_xml

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report, by_destination, by_name

SOURCE_URL = (
    "https://gitlab.com/recalbox/recalbox/-/raw/master/board/recalbox/fsoverlay"
    "/recalbox/share_init/system/.emulationstation/es_bios.xml"
)
# Resolved from the file: the profiles say which names each core answers to.
EMULATORS_DIR = Path(__file__).resolve().parents[2] / "emulators"
SCHEMA_URL = (
    "https://gitlab.com/recalbox/recalbox/-/raw/master/board/recalbox/fsoverlay"
    "/recalbox/share_init/system/.emulationstation/es_bios.xsd"
)


_ATTRIBUTE = re.compile(r'([A-Za-z][A-Za-z0-9]*)\s*=\s*"([^"]*)"')
_SYSTEM_BLOCK = re.compile(r"<system\b.*?</system>", re.S)
_BIOS_ELEMENT = re.compile(r"[ \t]*<bios\b.*?/>", re.S)


def _stated(text: str) -> dict[str, str]:
    """What an element says, without its layout: attribute order, spacing,
    line breaks inside a value and the case of a digest are not content."""
    attrs = {k: " ".join(html.unescape(v).split()) for k, v in _ATTRIBUTE.findall(text)}
    if "md5" in attrs:
        # Recalbox accepts any digest of the list (Bios.cpp:109-130): the
        # order is not content, and neogeo.zip's 24, reordered, were
        # written again.
        attrs["md5"] = ",".join(sorted({h.strip().lower() for h in attrs["md5"].split(",")}))
    return attrs


_SPACED_ATTRIBUTE = re.compile(r'(\s+)([A-Za-z][A-Za-z0-9]*)(\s*=\s*")([^"]*)(")')


def patch_element(kept: str, mine: str) -> str:
    """Recalbox's element with only the attributes that changed rewritten.

    Rendered again, a corrected element lost its alignment and the place
    of its attributes. A changed value is replaced where it stands, an
    attribute ours drops goes with the space before it, and one ours adds
    goes before the closing />.
    """
    target = dict(_ATTRIBUTE.findall(mine))
    target_stated = _stated(mine)
    present: set[str] = set()

    def rewrite(match: re.Match[str]) -> str:
        name = match.group(2)
        present.add(name)
        if name not in target:
            return ""
        if _stated(f'<x {name}="{match.group(4)}"/>') == {name: target_stated[name]}:
            return match.group(0)
        return match.group(1) + name + match.group(3) + target[name] + match.group(5)

    patched = _SPACED_ATTRIBUTE.sub(rewrite, kept)
    added = "".join(f' {name}="{value}"' for name, value in target.items() if name not in present)
    if added:
        close = re.search(r"\s*/>\s*$", patched)
        if close is None:
            return mine
        patched = patched[:close.start()] + added + patched[close.start():]
    return patched


def _original_openings(original: str) -> list[str]:
    """Each system block's opening tag as written, its indentation included:
    cdi's is indented four spaces where the others take two (l.604)."""
    openings = []
    for block in _SYSTEM_BLOCK.finditer(original):
        line_start = original.rfind("\n", 0, block.start()) + 1
        openings.append(original[line_start:block.start()] + block.group(0).split(">", 1)[0] + ">")
    return openings


def _original_elements(original: str) -> list[dict[str, str]]:
    """Each system block's <bios> elements as written, by path, in order."""
    blocks = []
    for block in _SYSTEM_BLOCK.finditer(original):
        elements: dict[str, str] = {}
        for match in _BIOS_ELEMENT.finditer(block.group(0)):
            raw = match.group(0)
            elements.setdefault(_stated(raw).get("path", ""), raw)
        blocks.append(elements)
    return blocks


class Exporter(BaseExporter):
    """Write Recalbox's es_bios.xml, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "recalbox"

    @staticmethod
    def native_filename() -> str:
        return "es_bios.xml"

    @staticmethod
    def keys_by_system() -> bool:
        return True

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"md5", "required"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"es_bios.xml": SOURCE_URL, "es_bios.xsd": SCHEMA_URL}

    def _path(self, fe: NativeFile) -> str:
        """The path Recalbox reads, pipe-joined when it accepts several.

        A path Recalbox already states is reproduced exactly: several of its
        entries sit at the BIOS root with no directory at all, and prefixing
        them with the system would point the frontend somewhere else. An
        addition goes where the core reads it, relative to the BIOS directory
        Recalbox gives its cores: DuckStation reads scph5000.bin at the root,
        not under psx/.
        """
        if fe.platform is not None:
            path = str(fe.platform.get("destination") or fe.name)
            alternatives = fe.platform.get("alt_paths") or []
            if alternatives:
                return "|".join([path, *[str(a) for a in alternatives]])
            return path
        return fe.destination or fe.name

    def _profile_keys(self) -> dict[str, str]:
        """Each name a core answers to, as Recalbox writes it, to its profile."""
        index = getattr(self, "_keys", None)
        if index is None:
            index = {}
            for key, profile in load_emulator_profiles(str(EMULATORS_DIR)).items():
                for name in (key, *(str(c) for c in profile.get("cores") or [])):
                    index.setdefault(name.replace("-", "_").lower(), key)
            self._keys = index
        return index

    def required_value(self, fe: NativeFile) -> bool:
        """Whether the cores the element names need the file.

        The element lists its cores, and each core's own entry for the file,
        found by name, says whether that core needs it. The md5 pairing
        takes one entry only: saturn/saturn_bios.bin names yabause,
        yabasanshiro and kronos, which require it, and its md5 paired it
        with the beetle_saturn entry. The merged flag is true when any core
        needs the file: cdi/cdibios.zip names same_cdi, which declares no
        such set, and became mandatory because MAME requires it. Where none
        of the element's cores declares the file, the platform's value
        stands.
        """
        entries = [fe.truth] if fe.truth else []
        entries += [
            e for e in fe.namesakes
            if e is not fe.truth and self._same_file(e, fe.platform or {})
        ]
        if not entries:
            return fe.required
        index = self._profile_keys()
        named = {
            index.get(core.rsplit("/", 1)[-1].replace("-", "_").lower(), "")
            for core in fe.cores()
        } - {""}
        readers: set[str] = set()
        requirers: set[str] = set()
        set_readers: set[str] = set()
        for entry in entries:
            cores = set(entry.get("_cores") or ()) & named
            readers |= cores
            if entry.get("one_of_required"):
                set_readers |= cores & set(entry.get("one_of") or ())
            required_by = entry.get("_required_by")
            if required_by is None:
                if entry.get("required") is not False:
                    requirers |= cores
            else:
                requirers |= cores & set(required_by)
        # A core that needs one file of a set needs none of them on its own,
        # which a mandatory flag cannot say: the line keeps its value.
        if not readers or (not requirers and set_readers):
            if fe.platform is not None and fe.platform.get("required") is not None:
                return bool(fe.platform["required"])
            return fe.required
        return bool(requirers)

    @staticmethod
    def _same_file(entry: dict, declared: dict) -> bool:
        """Whether a truth entry of that name describes this element's file.

        Its path or its name in the same directory does. A name under an
        unrelated directory does too: kronos reads kronos/saturn_bios.bin,
        and Recalbox files the same BIOS under saturn/. A name in another
        directory of the same tree does not: bluemsx reads
        Machines/Shared Roms/KANJI.rom, which is not Recalbox's
        Machines/MSX2+ - European/KANJI.rom.
        """
        if by_destination(entry, declared) or by_name(entry, declared):
            return True
        theirs = str(declared.get("destination") or declared.get("name", "")).split("/")[:-1]
        ours = str(entry.get("path") or entry.get("name", "")).split("/")[:-1]
        return not {d.casefold() for d in theirs} & {d.casefold() for d in ours}

    def _bios_element(
        self, fe: NativeFile, native_id: str, also: tuple[NativeFile, ...] = ()
    ) -> str:
        """``also`` are further additions at fe's path: Bios.cpp reads one
        element per path, and its md5 and core lists take every one of them."""
        group = (fe, *also)
        md5 = dict.fromkeys(h for f in group for h in f.hashes("md5"))
        cores = dict.fromkeys(c for f in group for c in f.cores())
        attrs = [f"path={quoteattr(self._path(fe))}"]
        attrs.append(f'md5={quoteattr(",".join(md5))}')
        attrs.append(f'core={quoteattr(",".join(cores))}')

        if not any(self.required_value(f) for f in group):
            attrs.append('mandatory="false"')
        elif fe.native("mandatory_declared", None) is True:
            attrs.append('mandatory="true"')

        hash_match = fe.native("hash_match_mandatory", None)
        if hash_match is False:
            attrs.append('hashMatchMandatory="false"')
        elif hash_match is True:
            attrs.append('hashMatchMandatory="true"')

        # The platform's own note only: ours is prose about our profiles, with
        # file:line citations, and the format does not carry note corrections.
        note = " ".join(str((fe.platform or {}).get("note") or "").split())
        if note:
            attrs.append(f"note={quoteattr(note)}")

        return f"    <bios {' '.join(attrs)} />"

    def written_list(self, fe: NativeFile, field_name: str) -> list[str] | None:
        """md5 is the comma list Bios.cpp splits and compares one by one, so
        a list the truth extended is a change the report names."""
        if field_name == "md5" and len(fe.hashes("md5")) > 1:
            return fe.hashes("md5")
        return None

    def states(self, fe: NativeFile, field_name: str) -> bool:
        """An element it cannot rewrite is written back as Recalbox wrote it.

        es_bios.xsd makes md5 required: an entry whose md5 the truth
        contradicts without naming another keeps its element whole, and
        counting the md5 cleared announced a change absent from the file.
        """
        if fe.platform is not None and not self.writable(fe):
            return False
        return super().states(fe, field_name)

    def lands(self, fe: NativeFile) -> bool:
        """An element of theirs the render cannot rewrite is still in the
        file, written back as Recalbox wrote it."""
        return self.writable(fe) or id(fe) in getattr(self, "_held_whole", {})

    def withheld(self) -> list[str]:
        """Each element kept as written because the truth names no md5."""
        return [
            f"{label} keeps its md5: the truth accepts another dump and "
            "names no md5 for it, which es_bios.xsd requires"
            for label in sorted(getattr(self, "_held_whole", {}).values())
        ]

    @classmethod
    def writable(cls, fe: NativeFile, require: str = "") -> bool:
        """es_bios.xsd makes md5 and core required: without them, no element.

        An entry Recalbox already ships has both, so this only ever gates
        what we would be adding.
        """
        if fe.platform is None and fe.foreign_system:
            return False
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
        # Recalbox's own file is the base, so an element our transcription
        # does not carry (added or renamed after a scrape) stays as written,
        # and its system order with it. A platform can hold several blocks
        # (Pentagon and Scorpion are both zxspectrum), and an entry the
        # maintainer commented out stays commented out.
        theirs: list[tuple[str, str, list[dict[str, str] | str]]] = []
        original = originals.get(self.native_filename(), "")
        if original:
            try:
                root = parse_untrusted_xml(original, self.native_filename(), comments=True)
            except (ParseError, ValueError) as exc:
                # Rebuilt from our model alone, the export would drop every
                # system we do not transcribe and the maintainer's comments.
                raise ValueError(
                    f"Recalbox's {self.native_filename()} does not parse ({exc}); "
                    "fetch it again with --refresh-cache"
                ) from exc
            if root is not None:
                theirs = [
                    (s.get("platform", ""), s.get("fullname", ""), [
                        f"<!--{child.text}-->" if child.tag is Comment else dict(child.attrib)
                        for child in s
                        if child.tag is Comment or child.tag == "bios"
                    ])
                    for s in root.iter("system")
                ]

        # Elements of theirs written back as they stand, by (platform, path).
        held = {
            (platform, " ".join(child.get("path", "").split()))
            for platform, _, children in theirs
            for child in children
            if isinstance(child, dict)
        }
        self._held_whole = {
            id(fe): f"{system.native_id}/{self._path(fe)}"
            for system in systems.values()
            for fe in system.files
            if fe.platform is not None
            and not self.writable(fe)
            and (system.native_id, " ".join(self._path(fe).split())) in held
        }
        ours: dict[str, tuple[NativeSystem, dict[str, tuple[NativeFile, str]]]] = {}
        for system in systems.values():
            # Two additions at one path (two cores, two dumps) are one
            # element: keyed by path, the second replaced the first and its
            # md5 left the file while both were counted added.
            at_path: dict[str, list[NativeFile]] = {}
            for fe in system.files:
                if self.writable(fe):
                    at_path.setdefault(self._path(fe), []).append(fe)
            if at_path:
                ours[system.native_id] = (system, {
                    path: (group[0], self._bios_element(group[0], system.native_id, tuple(group[1:])))
                    for path, group in at_path.items()
                })

        def element(attrs: dict[str, str]) -> str:
            rendered = " ".join(f"{k}={quoteattr(v)}" for k, v in attrs.items())
            return f"    <bios {rendered} />"

        def emit(platform: str, fullname: str, body: list[str], opening: str = "") -> None:
            stated = _stated(opening) if opening else {}
            if stated.get("platform") == platform and stated.get("fullname") == fullname:
                lines.append(opening)
            else:
                lines.append(
                    f"  <system fullname={quoteattr(fullname)} platform={quoteattr(platform)}>"
                )
            lines.extend(body)
            lines.append("  </system>")

        # Each block of theirs corrects the entries it holds. An element that
        # states what Recalbox wrote keeps Recalbox's text: re-rendered, 222
        # unchanged elements made 180 lines of diff the report never named.
        written = _original_elements(original) if original else []
        openings = _original_openings(original) if original else []
        blocks: list[tuple[str, str, list[str]]] = []
        for index, (platform, fullname, children) in enumerate(theirs):
            elements = ours.get(platform, (None, {}))[1]
            raw = written[index] if index < len(written) else {}
            body: list[str] = []
            for child in children:
                if isinstance(child, str):
                    body.append(f"    {child}")
                    continue
                path = child.get("path", "")
                mine = elements.pop(path, None)
                kept = raw.get(" ".join(path.split()))
                if kept is not None and (mine is None or _stated(mine[1]) == _stated(kept)):
                    body.append(kept)
                elif kept is not None and mine is not None and _stated(
                    patched := patch_element(kept, mine[1])
                ) == _stated(mine[1]):
                    body.append(patched)
                else:
                    body.append(mine[1] if mine else element(child))
            blocks.append((platform, fullname, body))

        # An addition joins the block named like its file, else the first
        # block of its platform.
        first: dict[str, int] = {}
        named: dict[tuple[str, str], int] = {}
        for index, (platform, fullname, _) in enumerate(blocks):
            first.setdefault(platform, index)
            named.setdefault((platform, fullname), index)
        for platform in [p for p in ours if p in first]:
            _, elements = ours.pop(platform)
            for fe, rendered in elements.values():
                key = (platform, str(fe.native("native_name", "")))
                blocks[named.get(key, first[platform])][2].append(rendered)

        for index, (platform, fullname, body) in enumerate(blocks):
            emit(platform, fullname, body, openings[index] if index < len(openings) else "")
        for platform in sorted(ours):
            system, elements = ours[platform]
            emit(platform, self.display_name(system), [r for _, r in elements.values()])

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
                if self._path(fe).casefold() not in exported:
                    issues.append(f"absent: {system.native_id}/{fe.name}")
        return issues
