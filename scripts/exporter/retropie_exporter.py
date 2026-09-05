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
MAX_NAMES = 6

_MODULE_ID = re.compile(r'rp_module_id="([^"]+)"')
_MODULE_HELP = re.compile(r'rp_module_help="((?:[^"\\]|\\.)*)"')
_FILENAME = re.compile(r"[A-Za-z0-9][\w.+-]*\.[A-Za-z0-9]{1,5}\b")
# RetroPie words the instruction several ways ("Copy the required BIOS files
# a.bin and b.bin to $biosdir", "The Sega CD requires the BIOS files a.bin,
# b.bin copied to $biosdir"), so the clause is found by the word BIOS rather
# than by a sentence template, and the names in it are the list to extend.
_BIOS_CLAUSE = re.compile(r"BIOS\b.*?(?=\\n|$)", re.DOTALL)
_BIOS_NOUN = re.compile(r"BIOS (files?)\b")


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
        # The help names files; it states no hash and no requirement flag.
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
                if "BIOS" in text:
                    found[relative] = text
        return found

    def _core_index(self) -> dict[str, str]:
        """Module id (without its lr- prefix) to the profile it stands for."""
        index: dict[str, str] = {}
        for key, profile in load_emulator_profiles(str(EMULATORS_DIR)).items():
            index[key.replace("-", "_").lower()] = key
            for name in profile.get("cores", []) or []:
                index[str(name).replace("-", "_").lower()] = key
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
            if before in (".", "/", "\\"):
                continue
            found.append(match)
        return found

    @classmethod
    def _listed(cls, help_text: str) -> set[str]:
        """File names the help already writes, wherever in the string."""
        plain = help_text.replace("\\n", " ")
        return {match.group(0).lower() for match in cls._names_in(plain)}

    @classmethod
    def _insertion_point(cls, help_text: str) -> int | None:
        """Where a name joins the list, or None when there is no list."""
        clause = _BIOS_CLAUSE.search(help_text)
        if clause is None:
            return None
        names = cls._names_in(clause.group(0))
        return clause.start() + names[-1].end() if names else None

    @staticmethod
    def _in_search_order(candidates: list[NativeFile]) -> list[str]:
        """The names in the order the code looks for them, best first.

        Someone reading the sentence copies the files in the order it
        gives, so the one the emulator prefers is named first. The model
        already holds them in that order; this only removes the duplicates
        a name can pick up from several cores.
        """
        names: list[str] = []
        for fe in search_order(candidates):
            if fe.name not in names:
                names.append(fe.name)
        return names

    @staticmethod
    def _join(names: list[str]) -> str:
        """RetroPie's own idiom: a, b and c."""
        if len(names) == 1:
            return names[0]
        return ", ".join(names[:-1]) + " and " + names[-1]

    def modules(self, originals: dict[str, str]) -> dict[str, tuple[str, str]]:
        """Module id and help string of every script that mentions BIOS."""
        found: dict[str, tuple[str, str]] = {}
        for relative, text in originals.items():
            if not relative.startswith("scriptmodules/"):
                continue
            module = _MODULE_ID.search(text)
            help_text = _MODULE_HELP.search(text)
            if not module or not help_text or "BIOS" not in help_text.group(1):
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
        by_core = self._files_by_core(systems)
        # Aliases count as names we know: RetroPie writes dc_flash.bin where
        # flycast's profile files it as an alias of another primary.
        known: set[str] = set()
        for system in systems.values():
            for fe in system.files:
                known.add(fe.name.lower())
                known.update(
                    str(a).lower() for a in (fe.native("aliases", []) or [])
                )
        self._skipped: dict[str, list[str]] = {}
        produced: dict[str, str] = {}

        def skip(reason: str, module: str) -> None:
            self._skipped.setdefault(reason, []).append(module)

        for relative, (module_id, help_text) in sorted(modules.items()):
            core = index.get(module_id.removeprefix("lr-").replace("-", "_").lower())
            files = by_core.get(core or "", [])
            if not files:
                skip("no core of ours packages it", module_id)
                continue

            listed = self._listed(help_text)
            unknown = sorted(listed - known)
            if unknown:
                skip(
                    f"names a file we have never seen ({', '.join(unknown)})",
                    module_id,
                )

            # A file already listed under one of its other names is not
            # missing: proposing the primary would name the same bytes twice.
            candidates = [
                fe
                for fe in files
                if fe.required
                and not (
                    {fe.name.lower()}
                    | {str(a).lower() for a in (fe.native("aliases", []) or [])}
                )
                & listed
            ]
            missing = self._in_search_order(candidates)
            if not missing:
                continue

            insert_at = self._insertion_point(help_text)
            if insert_at is None:
                # No enumeration to extend, and a sentence we would have to
                # write ourselves is a documentation change, not a correction.
                skip("names no file to extend", module_id)
                continue

            if len(listed) + len(missing) > MAX_NAMES:
                skip("more names than the help enumerates", module_id)
                continue

            new_help = (
                help_text[:insert_at]
                + ", "
                + self._join(missing)
                + help_text[insert_at:]
            )
            if len(listed) + len(missing) > 1:
                new_help = _BIOS_NOUN.sub("BIOS files", new_help, count=1)
            produced[relative] = originals[relative].replace(
                f'rp_module_help="{help_text}"',
                f'rp_module_help="{new_help}"',
                1,
            )

        return produced

    def outcome(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> str:
        """Packages are the unit here, not file entries."""
        skipped: dict[str, list[str]] = getattr(self, "_skipped", {})
        parts = [f"{len(produced)} packages corrected"]
        for reason, modules in sorted(skipped.items()):
            shown = ", ".join(sorted(modules)[:4])
            if len(modules) > 4:
                shown += f" and {len(modules) - 4} more"
            parts.append(f"{len(modules)} {reason} ({shown})")
        return "; ".join(parts)

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
            if "BIOS" not in help_text.group(1):
                issues.append(f"{relative}: the BIOS sentence is gone")
            names = self._listed(help_text.group(1))
            if len(names) > MAX_NAMES:
                issues.append(
                    f"{relative}: {len(names)} names, past what the help enumerates"
                )
        return issues
