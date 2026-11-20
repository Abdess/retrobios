"""The standalone builds a platform launches and the layouts their files take."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from model.profiles import load_emulator_profiles, profile_names
from model.systems import norm_system_id
from resolve.contentlayout import content_folder_tags, content_layout
from resolve.layout import (
    CONTENT_TAG_PREFIXES,
    CORE_DIR_PREFIX,
    DUAL_MODE_PREFIX,
    EXECUTED_PREFIX,
    HANDED_PREFIX,
    MACHINE_KEY,
    OUTSIDE_BIOS_FOLDER,
    OWN_BUILD_PREFIX,
    SYSTEM_FILE_PREFIX,
    handed_from_tags,
    placed_entry,
    core_system_dirs,
    entry_launch_systems,
    runs_standalone,
    standalone_bindings_for,
    standalone_destination,
    standalone_layout_path,
    system_dir_view,
    system_file_index,
)
from core.paths import REPO_ROOT


def own_build_tags(config: dict, standalone: set[str]) -> set[str]:
    """The standalone names the platform's own builds answer to, tagged.

    Read from the profiles of this repository, the ones every pack, manifest
    and report is built from.
    """
    platform = str(config.get("_key") or "")
    if not platform or not standalone:
        return set()
    profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
    return {
        OWN_BUILD_PREFIX + json.dumps([n, key, p.get("source")])
        for key, p in profiles.items()
        if platform in (p.get("built_by") or []) and "standalone" in str(p.get("type", ""))
        for n in set(profile_names(key, p)) & standalone
    }


def twin_build_names(config: dict) -> set[str]:
    """The libretro core names of emulators a platform also runs standalone
    under another name.

    RetroBat's es_systems.cfg offers MAME as the libretro core mame and as
    the standalone mame64, two names of one profile: the platform runs it
    both ways, and each build reads its own layout.
    """
    standalone = {str(c) for c in config.get("standalone_cores") or []}
    libretro = {str(c) for c in config.get("cores") or []} - standalone if isinstance(
        config.get("cores"), list
    ) else set()
    if not standalone or not libretro:
        return set()
    profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
    found: set[str] = set()
    for key, profile in profiles.items():
        kind = str(profile.get("type", ""))
        if "libretro" not in kind or "standalone" not in kind:
            continue
        names = set(profile_names(key, profile))
        if names & standalone:
            found |= names & libretro
    return found


def standalone_set(config: dict) -> set[str]:
    """The emulators a platform launches standalone, with its dual-mode ones.

    ``dual_mode_cores`` names those it offers both ways (Batocera lists
    libretro:dolphin and standalone dolphin for GameCube). They travel in the
    same set, tagged, so every reader of standalone_cores sees them.
    """
    names = {str(c) for c in config.get("standalone_cores") or []}
    names |= {DUAL_MODE_PREFIX + str(c) for c in config.get("dual_mode_cores") or []}
    # A buildbot core the platform's RetroArch installs under the name of an
    # emulator it runs standalone is that emulator's libretro build: run
    # both ways, as Batocera runs amiberry standalone and can fetch
    # amiberry_libretro.
    names |= {
        DUAL_MODE_PREFIX + str(c)
        for c in set(map(str, config.get("installable_cores") or []))
        & set(map(str, config.get("standalone_cores") or []))
    }
    names |= own_build_tags(config, names)
    names |= {DUAL_MODE_PREFIX + n for n in twin_build_names(config)}
    # The system directory each core is handed travels the same way, so
    # platform_layouts places a core's files below it for every reader.
    names |= {
        CORE_DIR_PREFIX + json.dumps([str(core), directory])
        for directory, entry in (config.get("core_system_dirs") or {}).items()
        for core in entry.get("cores") or []
    }
    if names - {n for n in names if n.startswith(CORE_DIR_PREFIX)}:
        from resolve.launchers import executed_files, handed_directories

        handed = handed_directories(config)
        # The record's position travels too: a search list is read in order.
        names |= {
            HANDED_PREFIX + json.dumps(
                [position, h.emulator, h.folder, h.directory, sorted(h.handles), h.source_ref,
                 h.roms_place, sorted(h.systems), h.holds_declared]
            )
            for position, h in enumerate(handed)
        }
        named = {system for h in handed for system in h.systems}
        names |= {
            SYSTEM_FILE_PREFIX + json.dumps([slug, str(f["name"]).lower()])
            for slug, system in (config.get("systems") or {}).items()
            if slug in named
            for f in system.get("files") or []
            if f.get("name")
        }
        # The machines a record offers under its systems, by normalized id.
        from resolve.launchers import native_systems

        natives = native_systems(config)
        names |= {
            SYSTEM_FILE_PREFIX + json.dumps(
                [natives.get(str(native), str(native)), MACHINE_KEY + norm_system_id(str(m))]
            )
            for record in config.get("launchers") or []
            for native in record.get("systems") or []
            for m in record.get("machines") or []
        }
        names |= {
            EXECUTED_PREFIX + json.dumps([run.emulator, run.name, run.place, run.source_ref])
            for run in executed_files(config)
        }
    return names | content_folder_tags(config)


def merged_standalone_set(configs: Iterable[dict]) -> set[str]:
    """The standalone set of several platforms read as one tree.

    A per-core directory marker says which cores one platform hands a folder
    and that it hands the others none. Carried into the union, MinUI's 86
    markers left every core they do not list without a layout: the global
    gap report lost 238 profiles and 1201 files without a word.
    """
    return {
        tag
        for config in configs
        for tag in standalone_set(config)
        if not tag.startswith((CORE_DIR_PREFIX, *CONTENT_TAG_PREFIXES))
    }


def platform_layouts(
    emu_name: str, profile: dict, standalone_cores: set[str]
) -> list[tuple[dict, bool]]:
    """The layouts a platform gives an emulator: (profile, standalone?) each,
    with the files read in a roms folder placed there (content_layout)."""
    return [
        (content_layout(emu_name, view, standalone, standalone_cores), standalone)
        for view, standalone in _build_layouts(emu_name, profile, standalone_cores)
    ]


@dataclass
class _StandaloneLaunches:
    """Where a platform's launches of a standalone emulator read its files."""

    emu_name: str
    profile: dict
    standalone_cores: set[str]
    per_system: bool
    index: Mapping[str, set[str]]
    # A profile system the platform launches under a system of its own, as
    # its list says for one entry, is launched there for every entry.
    family: dict[str, set[str]]
    # The systems the launcher records name.
    named_systems: frozenset[str]
    # The layout folders a search setting stands for (standalone_pools).
    pool_folders: set[str]
    # Bindings can depend on the system an entry is launched for, so each
    # set of launch systems gets its own.
    by_systems: dict[frozenset[str], dict[str, tuple[str, str]]] = dataclasses.field(default_factory=dict)

    @classmethod
    def of(cls, emu_name: str, profile: dict, standalone_cores: set[str]) -> _StandaloneLaunches:
        names = set(profile_names(emu_name, profile))
        per_system = bool(
            profile.get("standalone_directories") or profile.get("standalone_pools")
        ) and any(h.systems and h.emulator in names for h in handed_from_tags(standalone_cores))
        index = system_file_index(standalone_cores) if per_system else {}
        # A profile system the platform launches under a system of its own, as
        # its list says for one entry, is launched there for every entry:
        # Recalbox lists mc10.rom under trs80coco, so alice.rom is read there.
        family: dict[str, set[str]] = {}
        for f in (profile.get("files") or []) if per_system else []:
            if isinstance(f, dict):
                own = entry_launch_systems(f, {})
                for system in own:
                    family.setdefault(system, set()).update(entry_launch_systems(f, index) - own)

        # The systems the launcher records name: a launch for one of them reads
        # the folder its record gives, every other launch the folder the records
        # naming none give.
        named_systems = frozenset().union(*(
            h.systems for h in handed_from_tags(standalone_cores) if h.emulator in names
        )) if per_system else frozenset()

        # The layout folders a search setting stands for (standalone_pools):
        # bound, the launcher passes the setting and the default is not read.
        from resolve.launchers import pool_folders as _pool_folders

        pool_folders = {v.strip("/") for v in _pool_folders(profile).values()} - {""}
        return cls(
            emu_name, profile, standalone_cores, per_system, index, family,
            named_systems, pool_folders,
        )

    def launch_systems(self, entry: dict) -> frozenset[str]:
        systems: frozenset[str] = frozenset()
        if self.per_system:
            own = entry_launch_systems(entry, {})
            systems = entry_launch_systems(entry, self.index)
            if systems == own:
                systems = systems.union(*(self.family.get(s, set()) for s in own))
            if systems == own:
                # The platform's list names none of the entry's names: its
                # own system selects the launch that offers it as a machine
                # (RetroBat runs XRoar's coco3 under coco).
                systems = systems.union(*(
                    self.index.get(MACHINE_KEY + norm_system_id(s), set()) for s in own
                ))
        return systems

    def bindings_for(self, systems: frozenset[str]) -> dict[str, tuple[str, str]]:
        if systems not in self.by_systems:
            self.by_systems[systems] = standalone_bindings_for(
                self.emu_name, self.profile, self.standalone_cores, systems
            )
        return self.by_systems[systems]

    def bindings_of(self, entry: dict) -> dict[str, tuple[str, str]]:
        return self.bindings_for(self.launch_systems(entry))

    def passed_setting(self, entry: dict) -> bool:
        layout = str(standalone_layout_path(entry, self.profile) or "")
        bindings = self.bindings_of(entry)
        return any(
            folder in bindings and (layout == folder or layout.startswith(folder + "/"))
            for folder in self.pool_folders
        )

    def destinations(self, entry: dict) -> list[tuple[str, str] | None]:
        """Each place the entry's launches read it from, in launch order.

        An entry of a system a record names is read where that record puts
        it. One also launched for systems no record names is read, for those
        launches, where the records naming none put it: EmuELEC starts
        AdvanceMAME with dir_rom roms/arcade for arcade and roms/mame for
        mame and cps1-3 (advmame.sh:26-30), and an arcade set is read in both.
        """
        systems = self.launch_systems(entry)
        found = [standalone_destination(entry, self.profile, self.bindings_for(systems))]
        # A system the platform's list or machines put the entry under
        # stands for the entry's own ids: XRoar's coco3 is launched as coco.
        own = entry_launch_systems(entry, {})
        launched = (systems - own) | (own & self.named_systems) if systems != own else systems
        if launched & self.named_systems and launched - self.named_systems:
            generic = standalone_destination(entry, self.profile, self.bindings_for(frozenset()))
            if generic not in found:
                found.append(generic)
        return found

    def placed_files(self) -> list:
        """The profile's files, each layout entry at the folders its launches read."""
        files = []
        for f in self.profile.get("files") or []:
            if not isinstance(f, dict) or standalone_layout_path(f, self.profile) is None:
                files.append(f)
                continue
            places = [p for p in self.destinations(f) if p is not None and p[0] != "outside"]
            if not places:
                files.append({**f, "unplaced": OUTSIDE_BIOS_FOLDER})
                continue
            moved = f
            if f.get("bundled") and self.passed_setting(f):
                # The copy installed with the emulator sits where the setting
                # pointed before the launcher moved it: RetroBat passes MAME
                # -hash bios/mame/hash (Mame64.Generator.cs:172, 177-178), and
                # the hash/ beside mame.exe is no longer read.
                moved = {k: v for k, v in f.items() if k != "bundled"}
            files.extend(placed_entry(moved, self.profile, placed) for placed in places)
        return files


def _build_layouts(
    emu_name: str, profile: dict, standalone_cores: set[str]
) -> list[tuple[dict, bool]]:
    """The layouts a platform gives an emulator: (profile, standalone?) each.

    One, libretro or standalone, for most. Both for an emulator the platform
    launches either way: laid out standalone only, Batocera's libretro
    Dolphin found dolphin-emu/Sys/GC/ empty. Each layout keeps its own rules
    (what the build reads from the system directory, where it reads it).
    """
    if not runs_standalone(emu_name, profile, standalone_cores):
        directories = core_system_dirs(emu_name, profile, standalone_cores)
        if directories is None:
            return [(profile, False)]
        return [(system_dir_view(profile, d), False) for d in directories]
    standalone = profile
    launches = _StandaloneLaunches.of(emu_name, profile, standalone_cores)

    layout_entries = [
        f for f in profile.get("files") or []
        if isinstance(f, dict) and standalone_layout_path(f, profile) is not None
    ]
    if any(launches.bindings_of(f) for f in layout_entries):
        # The standalone view carries the platform's destination, so every
        # reader of standalone_path (builder, manifest, verify, slots) places
        # the file in the folder the platform hands the emulator.
        # An entry of the layout no binding covers is read in a folder the
        # platform keeps outside the BIOS tree: UAE4All2's kick.rom in
        # RetroPie's $md_inst. It is marked, never left at the BIOS root
        # where the emulator does not read it.
        standalone = {**profile, "files": launches.placed_files()}
    dual = {c.removeprefix(DUAL_MODE_PREFIX) for c in standalone_cores
            if c.startswith(DUAL_MODE_PREFIX)}
    if "libretro" in str(profile.get("type", "")) and dual & {
        emu_name, *(str(c) for c in profile.get("cores", []))
    }:
        return [(profile, False), (standalone, True)]
    return [(standalone, True)]
