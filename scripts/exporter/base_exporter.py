"""Contract shared by the platform exporters.

An exporter answers one question: what would this platform's own file look
like if it were corrected. It is handed the platform's file when we have it,
because several of these formats carry code, and a generator that emits only
the data block hands the maintainer something that no longer runs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .baseline import NativeFile, NativeSystem, Report


class BaseExporter(ABC):
    """Base class for writing a platform's own BIOS file, corrected."""

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

    @staticmethod
    def needs_original() -> bool:
        """Whether a faithful export requires the platform's own file."""
        return False

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
    ) -> dict[str, str]:
        """Return {relative output path: file content}."""

    @abstractmethod
    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        """Check the produced files against what was asked of them."""

    # Shared helpers

    @classmethod
    def exportable(
        cls,
        systems: dict[str, NativeSystem],
        require: str = "",
    ) -> list[tuple[NativeSystem, list[NativeFile]]]:
        """Systems paired with the files this format can actually carry.

        `require` names a hash the format cannot omit. An entry the format
        has no way to express is dropped here and counted by the caller,
        never written as a half entry the platform would read as a file that
        can never verify.
        """
        result: list[tuple[NativeSystem, list[NativeFile]]] = []
        for system in systems.values():
            files = [fe for fe in system.files if fe.name and cls.writable(fe, require)]
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

    @classmethod
    def writable(cls, fe: NativeFile, require: str = "") -> bool:
        """Whether this format can carry the entry.

        An entry the platform already declares is always carried, hash or
        no hash: it is in their file today, and an export that drops it
        hands back a file poorer than the one it corrects. The requirement
        only gates what we would be adding.
        """
        if fe.platform is not None:
            return True
        if not cls.can_add():
            return False
        require = require or cls.requires()
        return not require or bool(fe.hash(require))

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
