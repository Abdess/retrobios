"""What a platform's launch code says about the emulators it runs."""

from __future__ import annotations

import json
from collections.abc import Hashable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from resolve.launchers import ExecutedFile, HandedDirectory


@dataclass(frozen=True)
class ContentFolder:
    """A roms folder a platform launches a libretro core for, which reads beside the content."""

    core: str
    folder: str
    # The folder as a (tree, path) place, empty when the platform gives none.
    place: tuple[str, ...]
    # The boards the folder offers the core on, None for every board.
    boards: tuple[str, ...] | None


@dataclass(frozen=True)
class RomSearch:
    """A roms folder a system's launch command hands as ROM search path.

    ``emulator`` is a standalone emulator, or a libretro core in the command
    line it is handed as content (``build``).
    """

    emulator: str
    place: tuple[str, ...]
    folder: str
    machines: tuple[str, ...]
    any_machine: bool
    source_ref: str
    build: str


@dataclass(frozen=True)
class ContentLaunches:
    """Where a platform puts the files a core reads beside the content."""

    # The platform is known: an entry read beside the content is placed in
    # the roms folders a core is launched for, or named as read outside the
    # BIOS folder.
    scoped: bool = False
    # The frontend writes the BIOS it hands a core beside the content: the
    # folder it gives the BIOS is the content's.
    beside: bool = False
    folders: frozenset[ContentFolder] = frozenset()
    searches: frozenset[RomSearch] = frozenset()


def frozen_source(source: object) -> Hashable:
    """A profile's ``source`` in a form a set can hold: a dict by build mode, or a URL."""
    if isinstance(source, dict):
        return tuple(sorted((str(k), frozen_source(v)) for k, v in source.items()))
    if isinstance(source, list):
        return tuple(frozen_source(v) for v in source)
    return source  # type: ignore[return-value]


def _handed_order(position: int, handed: HandedDirectory) -> tuple[int, str]:
    """Where a record of one platform's search lists sorts among several platforms'."""
    return position, json.dumps([
        position, handed.emulator, handed.folder, handed.directory, sorted(handed.handles),
        handed.source_ref, handed.roms_place, sorted(handed.systems), handed.holds_declared,
    ])


@dataclass(frozen=True)
class PlatformLaunches:
    """The emulators a platform launches standalone and how its launchers lay them out."""

    # The names the platform runs standalone (standalone_cores).
    standalone: frozenset[str] = frozenset()
    # The names it also launches as libretro cores.
    dual: frozenset[str] = frozenset()
    # (standalone name, profile, source): a build the platform compiles
    # itself (built_by) answers to that name there.
    own_builds: frozenset[tuple[str, str, Hashable]] = frozenset()
    # The directories its launchers hand standalone emulators, a search list
    # read in order.
    handed: tuple[HandedDirectory, ...] = ()
    # The files its launchers execute.
    executed: tuple[ExecutedFile, ...] = ()
    # (libretro core, system directory the platform hands it).
    core_dirs: frozenset[tuple[str, str]] = frozenset()
    # (system, lower-case file name or MACHINE_KEY + machine): a name the
    # platform declares under a system a launcher record is written for.
    system_files: frozenset[tuple[str, str]] = frozenset()
    content: ContentLaunches = field(default_factory=ContentLaunches)

    def runs_standalone(self, emu_name: str, profile: dict) -> bool:
        """Whether the platform lays this emulator's files out for its standalone build.

        A platform names the emulators it launches standalone in
        ``standalone_cores``, by profile key or by any name in ``cores:``. The
        name alone is not enough: Recalbox and Batocera call their standalone
        ScummVM ``scummvm``, which is also the key of the libretro core's
        profile, and that profile documents no standalone build. Laid out
        "standalone" it would lose every ``path:`` and drop its files at the
        root, so a profile whose ``type`` has no standalone build keeps its
        libretro layout whatever the platform calls it.
        """
        if not self.standalone:
            return False
        if "standalone" not in str(profile.get("type", "")):
            return False
        names = {emu_name, *(str(c) for c in profile.get("cores", []))}
        # A name a build the platform compiles itself answers to means that
        # build there: RetroBat's standalone amiberry is 8.3.0, and the 8.5.0
        # profile, run there as the buildbot core, keeps its libretro layout.
        source = frozen_source(profile.get("source"))
        owners: dict[str, set[str]] = {}
        for name, owner, built in self.own_builds:
            if built == source:
                owners.setdefault(name, set()).add(owner)
        if any(emu_name not in owners[n] for n in names & owners.keys()):
            return False
        return emu_name in self.standalone or bool(self.standalone & names)

    def is_dual(self, names: Iterable[str]) -> bool:
        """Whether the platform also launches, as a libretro core, an emulator of these names."""
        return not self.dual.isdisjoint(names)

    def system_file_index(self) -> dict[str, set[str]]:
        """File name, lower case -> the platform systems declaring it."""
        index: dict[str, set[str]] = {}
        for slug, name in self.system_files:
            index.setdefault(name, set()).add(slug)
        return index

    @classmethod
    def merged(cls, launches: Iterable[PlatformLaunches]) -> PlatformLaunches:
        """Several platforms' launches read as one tree.

        A per-core directory marker says which cores one platform hands a
        folder and that it hands the others none. Carried into the union,
        MinUI's 86 markers left every core they do not list without a layout:
        the global gap report lost 238 profiles and 1201 files without a word.
        Core directories and content folders stay with their platform.
        """
        each = list(launches)
        handed = {
            (position, h) for one in each for position, h in enumerate(one.handed)
        }
        return cls(
            standalone=frozenset().union(*(one.standalone for one in each)),
            dual=frozenset().union(*(one.dual for one in each)),
            own_builds=frozenset().union(*(one.own_builds for one in each)),
            handed=tuple(h for _p, h in sorted(handed, key=lambda pair: _handed_order(*pair))),
            executed=tuple(dict.fromkeys(run for one in each for run in one.executed)),
            system_files=frozenset().union(*(one.system_files for one in each)),
        )
