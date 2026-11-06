"""Exporter for RetroPie's scriptmodules.

RetroPie ships no BIOS list. What it maintains is one shell script per
package, and the BIOS files a package needs are named in its
`rp_module_help` string, in prose a person reads before copying files.
platforms.cfg carries extensions and full names only.

So the correctable unit is that sentence, and the correction is a file name
missing from it. A name RetroPie already writes is never removed, and no
sentence is invented where a maintainer wrote none: a package we would have
to document from scratch is reported, not drafted.
"""

from __future__ import annotations

import io
import re
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import load_emulator_profiles

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report, search_order

SOURCE_URL = (
    "https://codeload.github.com/RetroPie/RetroPie-Setup/tar.gz/refs/heads/master"
)
ARCHIVE = "RetroPie-Setup.tar.gz"
# Resolved from the file rather than the working directory: the profiles
# are what say which files a package needs.
EMULATORS_DIR = Path(__file__).resolve().parents[2] / "emulators"

# The longest list RetroPie writes is six names (lr-atari800). Past that the
# sentence stops being something a reader uses, so the names are reported
# instead of appended.

_MODULE_ID = re.compile(r'rp_module_id="([^"]+)"')
_MODULE_HELP = re.compile(r'rp_module_help="((?:[^"\\]|\\.)*)"')
_FILENAME = re.compile(r"[A-Za-z0-9][\w.+-]*\.[A-Za-z0-9]{1,5}\b")
# fs-uae's help reads "(e.g, kick13.rom)": e.g and i.e have a file name's shape.
_ABBREVIATION = re.compile(r"[a-z]\.[a-z]", re.I)
# RetroPie words the instruction several ways ("Copy the required BIOS files
# a.bin and b.bin to $biosdir", "The Sega CD requires the BIOS files a.bin,
# b.bin copied to $biosdir"), so the clause is found by the word BIOS rather
# than by a sentence template, and the names in it are the list to extend.
_BIOS_CLAUSE = re.compile(r"BIOS\b.*?(?=\\n|$)", re.DOTALL | re.I)
_BIOS_NOUN = re.compile(r"(BIOS) (files?)\b", re.I)
_SEPARATOR = re.compile(r"\s*(?:,\s*(?:and\s+)?|and\s+)")
_EXAMPLES = re.compile(r"\b(?:e\.?g\b|for example|for instance|such as|like)\W*$", re.I)


class Exporter(BaseExporter):
    """Write RetroPie's scriptmodules, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "retropie"

    @staticmethod
    def native_filename() -> str:
        return "scriptmodules"

    @staticmethod
    def carries() -> frozenset[str]:
        # The help names files. It states no hash and no requirement flag.
        return frozenset({"name"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {ARCHIVE: SOURCE_URL}

    @staticmethod
    def needs_original() -> bool:
        # The declaration is a sentence inside a shell script.
        return True

    @staticmethod
    def may_write_nothing() -> bool:
        # Nothing to correct is a result, not a failure.
        return True

    @staticmethod
    def unpack(raw: bytes) -> dict[str, str]:
        """Keep the scriptmodules that say anything about BIOS files."""
        found: dict[str, str] = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for member in archive:
                if not member.isfile() or not member.name.endswith(".sh"):
                    continue
                relative = member.name.split("/", 1)[-1]
                if not relative.startswith("scriptmodules/"):
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                text = handle.read().decode("utf-8", errors="replace")
                # xm7, np2pi, quasi88 and five more write "bios".
                if "bios" in text.lower():
                    found[relative] = text
        return found

    def _core_index(self) -> dict[str, dict[str, str]]:
        """Module id (without its lr- prefix) to the profile it stands for,
        per build.

        An lr- package is a libretro core and a bare one a standalone
        emulator: the standalone minivmac package matched the libretro
        profile, which reads MacII.ROM where Mini vMac 37 reads vMac.ROM.
        """
        index: dict[str, dict[str, str]] = {"libretro": {}, "standalone": {}}
        for key, profile in load_emulator_profiles(str(EMULATORS_DIR)).items():
            kind = str(profile.get("type", ""))
            for build in ("libretro", "standalone"):
                if build not in kind:
                    continue
                index[build][key.replace("-", "_").lower()] = key
                for name in profile.get("cores", []) or []:
                    index[build][str(name).replace("-", "_").lower()] = key
        return index

    @staticmethod
    def _files_by_core(systems: dict[str, NativeSystem]) -> dict[str, list[NativeFile]]:
        """Which files each core asks for, as the truth read its source."""
        grouped: dict[str, list[NativeFile]] = {}
        for system in systems.values():
            for fe in system.files:
                for core in (fe.truth or {}).get("_cores", []):
                    grouped.setdefault(str(core), []).append(fe)
        return grouped

    @staticmethod
    def _names_in(text: str) -> list[re.Match[str]]:
        """File names in a fragment, skipping what only looks like one.

        A token preceded by a dot is the tail of a ROM extension list
        (.atr.gz), and one preceded by a separator is part of a path
        ($biosdir/Machines/COL/coleco.rom): neither is a name in a list.
        """
        found: list[re.Match[str]] = []
        for match in _FILENAME.finditer(text):
            before = text[match.start() - 1 : match.start()]
            if before in (".", "/", "\\") or _ABBREVIATION.fullmatch(match.group(0)):
                continue
            found.append(match)
        return found

    @classmethod
    def _listed(cls, help_text: str) -> set[str]:
        """File names the help already writes, wherever in the string."""
        plain = help_text.replace("\\n", " ")
        return {match.group(0).lower() for match in cls._names_in(plain)}

    @classmethod
    def _enumeration(cls, help_text: str) -> tuple[int, int, list[str]] | None:
        """The first BIOS clause's list of names to extend, or None."""
        clauses = cls._clauses(help_text)
        return clauses[0][2] if clauses else None

    @classmethod
    def _clauses(
        cls, help_text: str
    ) -> list[tuple[int, list[str], tuple[int, int, list[str]] | None]]:
        """Each BIOS clause that names files: its start, its names, and the
        list to extend or None when it cannot be extended.

        flycast's help has a Dreamcast clause and a Naomi/Atomiswave one.
        Only the first was read, and naomi2.zip and segasp.zip were added to
        the Dreamcast list.
        """
        found = []
        for clause in _BIOS_CLAUSE.finditer(help_text):
            names = [m.group(0) for m in cls._names_in(clause.group(0))]
            if names:
                found.append((clause.start(), names, cls._extendable(clause)))
        return found

    @classmethod
    def _extendable(cls, clause: re.Match[str]) -> tuple[int, int, list[str]] | None:
        """The list of names to extend: its span and its names, or None.

        A list of alternatives ("a or b", "a/b") is not an enumeration: an
        appended ", c" reads as one more required file and the plural turns
        "one of these" into "all of these". Such a list is left alone, and so
        are a list of examples ("eg. a, b") and one with words between its
        names, which a rewrite would lose.
        """
        text = clause.group(0)
        names = cls._names_in(text)
        if not names:
            return None
        between = text[names[0].start():names[-1].end()]
        if re.search(r"\bor\b|/", between):
            return None
        # "a minimum of two BIOS files (eg. a, b)" names examples, not the
        # set: an appended name reads as one more required file.
        if _EXAMPLES.search(text[:names[0].start()]):
            return None
        gaps = [text[a.end():b.start()] for a, b in zip(names, names[1:])]
        if not all(_SEPARATOR.fullmatch(gap) for gap in gaps):
            return None
        return (
            clause.start() + names[0].start(),
            clause.start() + names[-1].end(),
            [match.group(0) for match in names],
        )

    @staticmethod
    def _in_search_order(candidates: list[NativeFile]) -> list[str]:
        """The names in the order the code looks for them, best first.

        Someone reading the sentence copies the files in the order it
        gives, so the one the emulator prefers is named first. The model
        already holds them in that order, so this only removes the duplicates
        a name can pick up from several cores.
        """
        names: list[str] = []
        for fe in search_order(candidates):
            if fe.name not in names:
                names.append(fe.name)
        return names

    @staticmethod
    def _slot_of(fe: NativeFile) -> tuple[str, tuple[str, ...]] | None:
        """The search chain a file belongs to, or None when it is in none.

        PicoDrive walks one ranked list per region and loads the first file
        it finds: the files of one chain are alternatives, and naming two of
        them in an enumeration that reads "requires a, b and c" says both
        are needed. A file joins a chain only when its source ranks it and
        names its territory.
        """
        regions = (fe.truth or {}).get("region") or []
        if fe.priority is None or not regions:
            return None
        return fe.native_system, tuple(sorted(str(r) for r in regions))

    @classmethod
    def _one_per_slot(cls, candidates: list[NativeFile], filled: set) -> list[NativeFile]:
        """The candidates whose chain the help leaves empty, best first."""
        kept: list[NativeFile] = []
        for fe in search_order(candidates):
            slot = cls._slot_of(fe)
            if slot is not None:
                if slot in filled:
                    continue
                filled.add(slot)
            kept.append(fe)
        return kept

    @staticmethod
    def _required_for(fe: NativeFile, core: str | None) -> bool:
        """Whether the package's own core needs the file.

        The merged `required` is true when any core needs it: pcsx_rearmed
        runs in HLE without a BIOS, yet four were proposed as required for
        its package because other PSX cores require them.
        """
        truth = fe.truth or {}
        # A file the package installs is not one to copy: gngeopi's
        # gngeo_data.zip lands in its data directory with make install.
        brought = truth.get("_brought_by")
        if brought is not None and not any(b.startswith(f"{core}:") for b in brought):
            return False
        required_by = truth.get("_required_by")
        if required_by is None:
            return fe.required
        return core in required_by

    @staticmethod
    def _join(names: list[str], serial: bool = False) -> str:
        """RetroPie's own idiom: a, b and c, or a, b, and c where the
        sentence already writes the comma before its final and."""
        if len(names) == 1:
            return names[0]
        last = ", and " if serial and len(names) > 2 else " and "
        return ", ".join(names[:-1]) + last + names[-1]

    @classmethod
    def _extended(
        cls,
        help_text: str,
        enumeration: tuple[int, int, list[str]],
        missing: list[str],
    ) -> str:
        """The help with the names added to its list.

        The whole list is written again so the "and" moves before the last
        name: appending ", c and d" after "a and b" read "a and b, c and d".
        """
        start, end, written = enumeration
        serial = ", and " in help_text[start:end]
        return help_text[:start] + cls._join([*written, *missing], serial) + help_text[end:]

    def modules(self, originals: dict[str, str]) -> dict[str, tuple[str, str]]:
        """Module id and help string of every script that mentions BIOS."""
        found: dict[str, tuple[str, str]] = {}
        for relative, text in originals.items():
            if not relative.startswith("scriptmodules/"):
                continue
            module = _MODULE_ID.search(text)
            help_text = _MODULE_HELP.search(text)
            if not module or not help_text or "bios" not in help_text.group(1).lower():
                continue
            found[relative] = (module.group(1), help_text.group(1))
        return found

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        modules = self.modules(originals)
        if not modules:
            raise ValueError(
                "the scriptmodules cannot be written without RetroPie's own "
                "repository: the BIOS list is a sentence inside a shell script"
            )

        index = self._core_index()
        # A sentence grows no longer than the longest RetroPie writes itself:
        # past that it stops reading as one, and the names are reported.
        self._longest = max(len(self._listed(help_text)) for _, help_text in modules.values())
        by_core = self._files_by_core(systems)
        # Aliases count as names we know: RetroPie writes dc_flash.bin where
        # flycast's profile files it as an alias of another primary.
        systems_of: dict[str, set[str]] = {}
        for system in systems.values():
            for fe in system.files:
                for name in [fe.name, *(fe.native("aliases", []) or [])]:
                    systems_of.setdefault(str(name).lower(), set()).add(fe.native_system)
        known = set(systems_of)
        self._skipped: dict[str, list[str]] = {}
        # Rewritten, with a file of a system no clause lists left out.
        self._partial: list[str] = []
        self._named: set[int] = set()
        produced: dict[str, str] = {}

        def skip(reason: str, module: str) -> None:
            self._skipped.setdefault(reason, []).append(module)

        for relative, (module_id, help_text) in sorted(modules.items()):
            build = "libretro" if module_id.startswith("lr-") else "standalone"
            core = index[build].get(module_id.removeprefix("lr-").replace("-", "_").lower())
            files = by_core.get(core or "", [])
            if not files:
                skip("which no profiled core matches", module_id)
                continue

            listed = self._listed(help_text)
            unknown = sorted(listed - known)
            if unknown:
                skip(
                    f"whose help text names a file no profile documents yet ({', '.join(unknown)})",
                    module_id,
                )
                continue

            # A file already listed under one of its other names is not
            # missing: proposing the primary would name the same bytes twice.
            # A system RetroPie does not have is no package's: lr-geargrafx
            # adds pcengine only, not the LaserActive its core also reads.
            candidates = [
                fe
                for fe in files
                if not fe.foreign_system
                and self._required_for(fe, core)
                and not (
                    {fe.name.lower()}
                    | {str(a).lower() for a in (fe.native("aliases", []) or [])}
                )
                & listed
            ]
            filled = {
                slot
                for fe in files
                if ({fe.name.lower()}
                    | {str(a).lower() for a in (fe.native("aliases", []) or [])}) & listed
                and (slot := self._slot_of(fe)) is not None
            }
            proposed = self._one_per_slot(candidates, filled)
            if not proposed:
                continue

            # A file joins the list of its own system: the clause whose
            # names the platform files under that system, and only one.
            clauses = self._clauses(help_text)
            homes: dict[int, list[NativeFile]] = {}
            homeless = False
            for fe in proposed:
                owners = [
                    i for i, (_, names, _) in enumerate(clauses)
                    if fe.native_system in set().union(
                        *(systems_of.get(n.lower(), set()) for n in names))
                ]
                if len(owners) == 1 and clauses[owners[0]][2] is not None:
                    homes.setdefault(owners[0], []).append(fe)
                else:
                    homeless = True
            # No enumeration of that system to extend, and a sentence we
            # would have to write ourselves is a documentation change, not a
            # correction. With nothing placed the package is left as is.
            if not homes:
                skip("whose help text lists no files of that system to add to", module_id)
                continue

            added = sum(len(self._in_search_order(fes)) for fes in homes.values())
            if len(listed) + added > self._longest:
                skip("whose help text would grow longer than any it has today", module_id)
                continue

            new_help = help_text
            for i in sorted(homes, reverse=True):
                start, _, enumeration = clauses[i]
                missing = self._in_search_order(homes[i])
                new_help = self._extended(new_help, enumeration, missing)
                if len(enumeration[2]) + len(missing) > 1:
                    new_help = new_help[:start] + _BIOS_NOUN.sub(
                        r"\1 files", new_help[start:enumeration[0]], count=1
                    ) + new_help[enumeration[0]:]
                self._named.update(id(fe) for fe in homes[i])
            produced[relative] = originals[relative].replace(
                f'rp_module_help="{help_text}"',
                f'rp_module_help="{new_help}"',
                1,
            )
            if homeless:
                self._partial.append(module_id)

        return produced

    def lands(self, fe: NativeFile) -> bool:
        """An addition lands only where a help sentence now names it.

        Every file a profiled core reads is writable in principle, yet the
        render appends names to a handful of sentences: counting the rest
        listed 1360 additions for one changed scriptmodule.
        """
        if fe.platform is not None:
            return self.writable(fe)
        return id(fe) in getattr(self, "_named", set())

    def names_anew(self, fe: NativeFile) -> bool:
        """flycast's naomi2.zip is in the RetroArch list RetroPie inherits,
        yet no flycast help sentence named it: the render adds it there."""
        return fe.platform is not None and id(fe) in getattr(self, "_named", set())

    def outcome(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> str:
        """Packages are the unit here, not file entries."""
        skipped: dict[str, list[str]] = getattr(self, "_skipped", {})

        def shown(modules: list[str]) -> str:
            names = ", ".join(sorted(modules)[:4])
            return names + (f" and {len(modules) - 4} more" if len(modules) > 4 else "")

        parts = [f"{len(produced)} packages updated"]
        partial = getattr(self, "_partial", [])
        if partial:
            parts.append(
                f"Updated in part: {shown(partial)}, whose help text lists no files "
                "of one of their systems to add to"
            )
        for reason, modules in sorted(skipped.items()):
            parts.append(f"Left as is: {shown(modules)}, {reason}")
        return ". ".join(parts)

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        issues: list[str] = []
        for relative, text in produced.items():
            module = _MODULE_ID.search(text)
            help_text = _MODULE_HELP.search(text)
            if not module:
                issues.append(f"{relative}: the module lost its id")
            if not help_text:
                issues.append(f"{relative}: the help string is not closed")
                continue
            if "bios" not in help_text.group(1).lower():
                issues.append(f"{relative}: the BIOS sentence is gone")
            names = self._listed(help_text.group(1))
            if len(names) > getattr(self, "_longest", len(names)):
                issues.append(
                    f"{relative}: {len(names)} names, past what the help enumerates"
                )
        return issues
