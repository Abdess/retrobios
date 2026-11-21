"""Contract shared by the platform exporters.

An exporter answers one question: what would this platform's own file look
like if it were corrected. It is handed the platform's file when we have it,
because several of these formats carry code, and a generator that emits only
the data block hands the maintainer something that no longer runs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Union

from core.paths import EMULATORS_DIR, REPO_ROOT
from model.profiles import core_key_index, load_emulator_profiles, platform_core_profiles
from resolve.reconcile import NativeFile, NativeSystem, Report

# What a produced file holds: text for every format, bytes besides for one
# that also hands back an archive (MiSTer's bios_db.json.zip).
Content = TypeVar("Content", bound=Union[str, bytes])


class BaseExporter(ABC, Generic[Content]):
    """Base class for writing a platform's own BIOS file, corrected."""

    # A hash field the checker compares to one value: an addition the
    # truth accepts under several cannot be written whole.
    SINGLE_HASH_FIELD: str | None = None

    @staticmethod
    @abstractmethod
    def platform_name() -> str:
        """Return the platform identifier this exporter targets."""

    @staticmethod
    @abstractmethod
    def native_filename() -> str:
        """Return the name the platform gives this file."""

    @staticmethod
    def carries() -> frozenset[str]:
        """Fields this format has somewhere to put.

        A correction the file cannot state is not a correction it delivers,
        and counting it would announce a change the maintainer will not find
        in the diff.
        """
        return frozenset({"md5"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        """Return {relative path: URL} of the originals this exporter patches.

        An exporter that can build its file from nothing returns an empty
        mapping. One whose format carries code cannot, and names the file it
        needs so the caller can fetch it.
        """
        return {}

    @classmethod
    def needs_original(cls) -> bool:
        """Whether a faithful export requires the platform's own file.

        Any format we patch does: System.dat rebuilt from our data lost
        libretro's quoted names, es_bios.xml its comments and one of its two
        zxspectrum blocks, and both runs said OK.
        """
        return bool(cls.native_sources())

    @staticmethod
    def may_write_nothing() -> bool:
        """Whether producing no file is an outcome rather than a failure.

        True only where the unit is a correction rather than a document:
        RetroPie has no BIOS list to rewrite, so a run with nothing to
        correct writes nothing and is right to.
        """
        return False

    @abstractmethod
    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, Content]:
        """Return {relative output path: file content}."""

    @abstractmethod
    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, Content],
    ) -> list[str]:
        """Check the produced files against what was asked of them."""

    # Shared helpers

    def exportable(
        self,
        systems: dict[str, NativeSystem],
        require: str = "",
    ) -> list[tuple[NativeSystem, list[NativeFile]]]:
        """Systems paired with the files this format can actually carry.

        `require` names a hash the format cannot omit. An entry the format
        has no way to express is dropped here and counted by the caller,
        never written as a half entry the platform would read as a file that
        can never verify. Read through the instance: RomM decides on the
        keys its render has seen.
        """
        result: list[tuple[NativeSystem, list[NativeFile]]] = []
        for system in systems.values():
            files = [fe for fe in system.files if fe.name and self.writable(fe, require)]
            if files:
                result.append((system, files))
        return result

    @staticmethod
    def requires() -> str:
        """The hash this format cannot write a new entry without."""
        return ""

    @staticmethod
    def can_add() -> bool:
        """Whether a file the platform does not declare can be stated at all.

        False where an entry is a declaration in code rather than a row:
        BizHawk wires each firmware into an option list and a status that
        only its source expresses, and writing C# for one is not something
        an exporter can do safely.
        """
        return True

    def keep_archive(self, relative: str, payload: bytes) -> None:
        """Hold the bytes of an original archive the render may hand back."""
        if not hasattr(self, "_archives"):
            self._archives: dict[str, bytes] = {}
        self._archives[relative] = payload

    def archive(self, relative: str) -> bytes | None:
        return getattr(self, "_archives", {}).get(relative)

    @staticmethod
    def file_modes() -> dict[str, int]:
        """The mode of each file the platform publishes other than 0644."""
        return {}

    @staticmethod
    def keys_by_system() -> bool:
        """Whether the platform finds a file through its system's own name.

        Batocera's checkBios walks only the systems es_systems declares, and
        Recalbox lists a <system> by its platform name: a file filed under
        one of our slugs (nintendo-snes beside their snes) is never read.
        """
        return False

    def lands(self, fe: NativeFile) -> bool:
        """Whether this render writes the entry: writable(), plus whatever
        the render learned from the platform's own file."""
        return self.writable(fe)

    def names_anew(self, fe: NativeFile) -> bool:
        """Whether the render wrote, for the first time, a file the platform
        layer already declares. Only a format whose unit is not the entry
        does: a RetroPie help sentence can lack a name the inherited RetroArch
        list carries."""
        return False

    def writable(self, fe: NativeFile, require: str = "") -> bool:
        """Whether this format can carry the entry.

        An entry the platform already declares is always carried, hash or
        no hash: it is in their file today, and an export that drops it
        hands back a file poorer than the one it corrects. The requirement
        only gates what we would be adding.
        """
        return self._carried(fe, require, self.SINGLE_HASH_FIELD)

    @classmethod
    def _carried(cls, fe: NativeFile, require: str, single: str | None) -> bool:
        """writable(), with the field held to one value named by the caller:
        a checker that reads a list for an entry holds it to none."""
        if fe.platform is not None:
            return True
        if not cls.can_add() or (cls.keys_by_system() and fe.foreign_system):
            return False
        if single and len(set(fe.hashes(single))) > 1:
            # One value checked: written with the first, the addition
            # refuses every other dump the core accepts.
            return False
        require = require or cls.requires()
        return not require or bool(fe.hash(require))

    @staticmethod
    def single_value(fe: NativeFile, field_name: str) -> str:
        """The one hash a single-value field is checked against.

        A platform that leaves the field empty checks the file by existence.
        Filling it turns that into a content check on one value: right when
        the truth accepts exactly one image, wrong when the core takes several
        and the field can hold only the first. Such a fill stays empty.
        """
        if field_name in fe.filled and len(set(fe.hashes(field_name))) != 1:
            return ""
        return fe.hash(field_name)

    def written(self, fe: NativeFile, field_name: str) -> str:
        """The value the render writes for one hash field, comma-joined.

        The report gives each change its value before and after, so it reads
        the value the way the render chooses it: one md5 where the format
        checks one, every accepted value where it lists them.
        """
        if field_name == self.SINGLE_HASH_FIELD:
            return self.single_value(fe, field_name)
        return ",".join(fe.hashes(field_name))

    def written_list(self, fe: NativeFile, field_name: str) -> list[str] | None:
        """The values of a hash field the render writes as a list, None when
        it writes one string. The report shows a list as a list: joined, it
        reads as one value the checker never compares."""
        return None

    def core_profiles(self, name: str, mode: str | None) -> set[str]:
        """The profiles a core name in the platform's own file stands for,
        in the build ``mode`` it names (libretro or standalone, None for
        either).

        The platform's own build of a name is what the name means there:
        Recalbox's libretro/pcsx2 is its PCSX2 1.7 fork, not the LRPS2
        revision Batocera builds under that name, and load order picked
        either one.
        """
        cached = getattr(self, "_core_profiles", None)
        if cached is None:
            profiles = load_emulator_profiles(str(REPO_ROOT / EMULATORS_DIR))
            cached = (profiles, core_key_index(profiles, include_aliases=True))
            self._core_profiles = cached
        profiles, index = cached
        return platform_core_profiles(index, profiles, name, self.platform_name(), mode)

    def required_value(self, fe: NativeFile) -> bool:
        """The requirement the render writes for an entry.

        The model's flag is true when any core needs the file. A format
        that names the cores of each entry narrows it to those cores.
        """
        return fe.required

    def states(self, fe: NativeFile, field_name: str) -> bool:
        """Whether the written file carries this entry's corrected field.

        The summary counts what lands, read entry by entry: a correction the
        model makes and the format keeps out of the file is not a change the
        maintainer will find in the diff.
        """
        return field_name in self.carries()

    def fills(self, fe: NativeFile, field_name: str) -> bool:
        """Whether a hash only the truth names lands in the written entry."""
        return self.states(fe, field_name)

    def clears(self, fe: NativeFile, field_name: str) -> bool:
        """Whether a platform hash the truth contradicts leaves the entry."""
        return self.states(fe, field_name)

    @staticmethod
    def record_fills(fe: NativeFile, field_name: str) -> bool:
        """A record format writes a filled hash only when record_hash names
        one: two values the truth accepts make no single record."""
        return bool(fe.record_hash(field_name))

    def withheld(self) -> list[str]:
        """Corrections the render proved and still did not write, named.

        Empty for most formats. One that refuses a rewrite to keep a value
        the platform holds says so here, or the run reads as nothing to do.
        """
        return []

    def outcome(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> str | None:
        """What this export did, when counting file entries would not say it.

        Most formats state one entry per file, so the caller's own count is
        the answer. RetroPie states a sentence per package, and a count of
        file entries would describe work it did not do.
        """
        return None

    @staticmethod
    def display_name(system: NativeSystem) -> str:
        """The name the platform shows for a system."""
        if system.name:
            return system.name
        for fe in system.files:
            native = fe.native("native_name", "")
            if native:
                return str(native)
        _UPPER = {
            "3do", "cdi", "cpc", "cps1", "cps2", "cps3", "dos", "gba", "gbc",
            "hle", "msx", "nes", "nds", "ngp", "psp", "psx", "sms", "snes",
            "stv", "tvc", "vb", "zx",
        }
        parts = system.native_id.replace("-", " ").replace("_", " ").split()
        return " ".join(
            p.upper() if p.lower() in _UPPER else p.capitalize() for p in parts
        )
