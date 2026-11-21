"""The emulator profiles a platform runs, per target and per system."""

from __future__ import annotations

import functools
from collections.abc import Collection
from dataclasses import dataclass

from core.cli import suggest_names
from core.paths import sanitize_pack_path
from model.declarations import declared_slot
from model.platforms import load_platform_config
from model.profiles import preferred_profile, profile_names, upstream_profile_index
from model.systems import norm_system_id, select_systems
from model.targets import list_available_targets, load_target_config
from core.paths import REPO_ROOT


@dataclass(frozen=True)
class RunScope:
    """The platforms a run keeps, a notice for each one it leaves out, and
    why it refuses a platform the command line names."""

    kept: list[str]
    notices: list[str]
    refusal: str | None = None


def without_profile_blind(
    platforms: list[str],
    flags: list[str],
    platforms_dir: str,
    profiles: dict[str, dict],
    target_cores: dict[str, set[str] | None] | None,
    is_all: bool,
) -> RunScope:
    """The platforms a narrowing read from profiles can apply to.

    Regions, search order and game data are read from the profiles of the
    cores a platform runs. MiSTer and BizHawk declare `cores: []`: a
    --region, --one-per-slot or --no-game-data pack of theirs withdrew
    nothing while its name and README said it had. A named platform is
    refused. Under --all it is left out with a notice. generate_pack and
    verify both read this, and print the notices and the refusal.
    """
    if not flags:
        return RunScope(platforms, [])
    blind = [
        name for name in platforms
        if not resolve_platform_cores(
            load_platform_config(name, platforms_dir),
            profiles,
            target_cores=(target_cores or {}).get(name),
        )
    ]
    kept = [name for name in platforms if name not in blind]
    notices: list[str] = []
    for name in blind:
        message = (
            f"{name} runs no core a profile describes, and {', '.join(flags)} "
            "reads the profiles"
        )
        if not is_all:
            return RunScope(kept, notices, f"{message}: drop {', '.join(flags)}")
        notices.append(f"  {message}: left out")
    return RunScope(kept, notices)


def resolve_platform_cores(
    config: dict,
    profiles: dict[str, dict],
    target_cores: set[str] | None = None,
) -> set[str]:
    """Resolve which emulator profiles are relevant for a platform.

    Resolution strategies (by priority):
    1. cores: "all_libretro" -- all profiles with libretro in type
    2. cores: [list] -- profiles whose dict key matches a core name
    3. cores: absent, fallback to systems intersection

    Alias profiles are always excluded (they point to another profile).
    If target_cores is provided, result is intersected with it.
    """
    result, downloaded_only = _platform_profiles(config, profiles)
    if target_cores is not None:
        result = result & designated_profiles(profiles, target_cores)
        result -= {
            profile for profile, names in downloaded_only.items()
            if not downloadable_on(target_cores, names)
        }
    return result


def downloaded_only_profiles(
    config: dict, profiles: dict[str, dict]
) -> dict[str, frozenset[str]]:
    """The profiles a platform reaches only through its RetroArch core
    downloader, each with the installable names that reach it."""
    return _platform_profiles(config, profiles)[1]


def _platform_profiles(
    config: dict, profiles: dict[str, dict]
) -> tuple[set[str], dict[str, frozenset[str]]]:
    cores_config = config.get("cores")
    platform_key = str(config.get("_key") or "")
    downloaded_only: dict[str, set[str]] = {}
    # The builds the platform compiles itself, by the names they answer to.
    # Such a name means that build there, and another revision of the same
    # project is not what the platform runs: ROCKNIX and RetroPie build only
    # standalone Amiberry, Recalbox its standalone and libretro Amiberry 8.2.2.
    # Only a platform listing the name both ways (dual_mode_cores) beside a
    # standalone-only build of its own runs the buildbot core too (RetroBat).
    # A core of another project under the name stays: RetroPie builds
    # minivmac37 standalone beside the minivmac core.
    own_builds = {
        name: p for name, p in profiles.items()
        if platform_key and platform_key in (p.get("built_by") or [])
    }

    def replaced_by_own(name: str, p: dict, libretro_only: bool = False) -> bool:
        if platform_key in (p.get("built_by") or []):
            return False
        names = set(profile_names(name, p))
        return any(
            (not libretro_only or "libretro" in str(q.get("type", "")))
            and q.get("source") == p.get("source")
            and names.intersection(profile_names(key, q))
            for key, q in own_builds.items()
        )

    def every_libretro() -> set[str]:
        # A build only some platforms compile (built_by) is absent from the
        # buildbot RetroArch installs from, so it is reached by name, or as one
        # of the libretro cores of a platform that compiles it: ROCKNIX ships
        # yabadabadoo with its RetroArch and names it nowhere else.
        return {
            name
            for name, p in profiles.items()
            if "libretro" in p.get("type", "") and p.get("type") != "alias"
            and (
                not p.get("built_by")
                or (platform_key and platform_key in p["built_by"])
            )
            and not replaced_by_own(name, p)
        }

    if cores_config == "all_libretro":
        result = every_libretro()
    elif isinstance(cores_config, list):
        # An emulator the platform launches standalone runs there even when
        # its own list names only the cores: Batocera's es_systems.yml files
        # lexaloffle and gsplus as standalone emulators and nowhere else. A
        # core its RetroArch installs from the buildbot is a libretro build
        # and designates libretro profiles only (below): Batocera downloads
        # the linuxloader core and runs no standalone Linux Loader.
        core_set = {str(c) for c in cores_config} | {
            str(c) for c in config.get("standalone_cores") or []
        }
        index = upstream_profile_index(profiles)
        platform = str(config.get("_key") or "")
        dual_names = {str(c) for c in config.get("dual_mode_cores") or []}

        def build_modes(p: dict) -> set[str]:
            kind = str(p.get("type", ""))
            return {mode for mode in ("standalone", "libretro") if mode in kind}

        def designated(name: str) -> set[str]:
            # A build the platform compiles itself (built_by) is what its
            # name means there: Recalbox's uae4all is Chips-fr/uae4all-rpi,
            # RetroPie's the standalone uae4all2 under the same name. A
            # platform building one name in several revisions, one per board,
            # runs all of them: RetroPie's amiberry is 5.7.2 and 6.3.3 on x86.
            own = {
                p for p in index.get(name, ())
                if platform and platform in (profiles[p].get("built_by") or [])
            }
            preferred = preferred_profile(index, name)
            if not own:
                return {preferred} if preferred is not None else set()
            # The own builds stand for the modes they are built in only.
            # Batocera builds LRPS2 as pcsx2_libretro.so and launches
            # standalone PCSX2 under the same name.
            own_modes = set().union(*(build_modes(profiles[p]) for p in own))
            if (
                name in dual_names
                and preferred is not None
                and preferred not in own
                and not build_modes(profiles[preferred]) & own_modes
            ):
                own.add(preferred)
            return own

        result = {profile for c in core_set for profile in designated(c)}
        # A name the platform launches both ways designates its libretro
        # build too. Batocera, Recalbox and RetroBat run pcsx2 standalone and
        # as LRPS2, two profiles: the key match kept the standalone one and
        # LRPS2's files never reached their packs. A core its RetroArch
        # installs is a libretro build as well (amiberry's buildbot core
        # beside Batocera's standalone amiberry).
        def libretro_builds(name: object) -> set[str]:
            return {
                profile
                for profile in index.get(str(name), set())
                if "libretro" in str(profiles[profile].get("type", ""))
                and not profiles[profile].get("built_by")
                and not replaced_by_own(profile, profiles[profile], libretro_only=True)
            }

        dual = {p for c in config.get("dual_mode_cores") or [] for p in libretro_builds(c)}
        # A core reached only through the RetroArch downloader runs on the
        # boards whose downloader offers it: Batocera's x86_64 RetroArch
        # installs the amiberry core, its armv7 and aarch64 boards cannot.
        # Every installable name counts: Batocera's x86_64 downloader offers
        # nside_sfc_balanced, not the higan_sfc_balanced it also lists.
        for c in config.get("installable_cores") or []:
            for profile in libretro_builds(c) - dual - result:
                downloaded_only.setdefault(profile, set()).add(str(c))
        result |= dual | set(downloaded_only)
        # Support "all_libretro" as a list element: combines all libretro
        # profiles with explicitly listed standalone cores (e.g. RetroDECK
        # ships RetroArch + standalone emulators)
        if "all_libretro" in core_set or "retroarch" in core_set:
            result |= every_libretro()
    else:
        # Fallback: system ID intersection with normalization
        norm_plat_systems = {norm_system_id(s) for s in config.get("systems", {})}
        result = {
            name
            for name, p in profiles.items()
            if {norm_system_id(s) for s in p.get("systems", [])} & norm_plat_systems
            and p.get("type") != "alias"
            and not p.get("built_by")
        }

    return result, {p: frozenset(names) for p, names in downloaded_only.items()}


@functools.lru_cache(maxsize=1)
def _retroarch_target_sets() -> tuple[frozenset[str], ...]:
    platforms = str(REPO_ROOT / "platforms")
    return tuple(
        frozenset(found)
        for t in list_available_targets("retroarch", platforms)
        if (found := load_target_config("retroarch", t["name"], platforms))
    )


def downloadable_on(target_cores: set[str], names: Collection[str]) -> bool:
    """Whether a board's core set holds a RetroArch download list offering
    one of `names`.

    A board with a downloader carries a whole RetroArch targets entry in its
    set (load_target_config, `downloads`), a board without one only what it
    builds.
    """
    return any(
        found <= target_cores and not found.isdisjoint(names)
        for found in _retroarch_target_sets()
    )


def unresolved_platform_cores(config: dict, profiles: dict[str, dict]) -> set[str]:
    """The core names a platform lists that no profile answers to.

    resolve_platform_cores drops them without a word: ROCKNIX's `dolphin-sa`
    or Batocera's `wine` designate no profile, so nothing is known of the
    files they open. `retroarch` and `all_libretro` stand for every libretro
    profile and are never unresolved. A platform without a `cores:` list
    names no core.
    """
    cores_config = config.get("cores")
    if not isinstance(cores_config, list):
        return set()
    index = upstream_profile_index(profiles)
    return {
        name
        for name in (str(c) for c in cores_config)
        if name not in ("retroarch", "all_libretro") and not index.get(name)
    }


def designated_profiles(profiles: dict[str, dict], names: set[str]) -> set[str]:
    """The profiles a list of upstream core names designates.

    The buildbot and es_systems name cores their own way (`mednafen_psx` for
    beetle_psx), and a profile's `cores:` lists those names. A name no profile
    claims stands for itself.
    """
    index = upstream_profile_index(profiles, include_aliases=True)
    return {profile for c in names for profile in index.get(c, {c})}


def _destination_cores(profiles: dict[str, dict]) -> dict[str, set[str]]:
    """Each lowercased destination with a directory -> the cores reading it."""
    dest_cores: dict[str, set[str]] = {}
    for name, p in profiles.items():
        if p.get("type") == "alias":
            continue
        for f in p.get("files", []):
            for key in ("path", "standalone_path"):
                dest = f.get(key)
                if not isinstance(dest, str):
                    continue
                if dest.endswith("/"):
                    dest += f.get("name", "")
                dest = sanitize_pack_path(dest).lower()
                if "/" in dest:
                    dest_cores.setdefault(dest, set()).add(name)
    return dest_cores


def system_core_reach(
    systems: dict[str, dict],
    profiles: dict[str, dict],
    platform_cores: set[str] | None,
) -> dict[str, set[str] | None]:
    """For each platform system, the cores whose presence keeps it.

    A system is reachable if at least one core that emulates it is available.
    Only cores relevant to the platform (platform_cores) can rule a system
    out: a system whose cores are all outside the platform's scope maps to
    None, kept whatever is available, there being no information to exclude
    it.
    """
    _norm_sid = norm_system_id

    # Normalized system -> cores, from ALL profiles
    norm_system_cores: dict[str, set[str]] = {}
    for name, p in profiles.items():
        if p.get("type") == "alias":
            continue
        for sid in p.get("systems", []):
            norm_system_cores.setdefault(_norm_sid(sid), set()).add(name)

    # Platform-scoped mapping (for distinguishing "no info" from "known but off-target")
    norm_plat_system_cores: dict[str, set[str]] = {}
    if platform_cores is not None:
        for name in platform_cores:
            p = profiles.get(name, {})
            for sid in p.get("systems", []):
                norm_plat_system_cores.setdefault(_norm_sid(sid), set()).add(name)

    # A platform can file a system under an id no profile uses: Batocera's
    # enterprise-64-128 is ep128emu's enterprise-64 and enterprise-128, and
    # only CLK, off most targets, carries the joined id. The destinations a
    # system declares name the cores that read its files. A bare name proves
    # nothing (bios.bin belongs to many systems), so only a path counts.
    # The evidence only keeps: a path shared with an off-target core says
    # nothing of the other files, and Batocera's bbc runs on MAME, which no
    # profile ties to bbcb.zip, while CLK reads two of its ROMs.
    dest_cores = _destination_cores(profiles)

    reach: dict[str, set[str] | None] = {}
    for sys_id, sys_data in systems.items():
        norm_key = _norm_sid(sys_id)
        if not norm_plat_system_cores.get(norm_key):
            reach[sys_id] = None
            continue
        file_cores = {
            core
            for fe in sys_data.get("files", [])
            if (slot := declared_slot(fe))
            for core in dest_cores.get(slot.lower(), ())
        }
        reach[sys_id] = file_cores | norm_system_cores.get(norm_key, set())
    return reach


def filter_systems_by_target(
    systems: dict[str, dict],
    profiles: dict[str, dict],
    target_cores: set[str] | None,
    platform_cores: set[str] | None = None,
) -> dict[str, dict]:
    """Filter platform systems to only those reachable by target cores.

    Returns the filtered systems dict (or all if no target).
    """
    if target_cores is None:
        return systems
    available = designated_profiles(profiles, target_cores)
    reach = system_core_reach(systems, profiles, platform_cores)
    return {
        sys_id: sys_data
        for sys_id, sys_data in systems.items()
        if (cores := reach[sys_id]) is None or cores & available
    }


def platform_scope_systems(
    config: dict,
    profiles: dict[str, dict],
    target_cores: set[str] | None,
    system_filter: list[str] | None = None,
) -> dict[str, dict]:
    """The systems a pack or a report of a platform covers.

    Those a core of the target runs, then the ones a --system list keeps.
    verify.py and generate_pack.py read this one function.
    """
    plat_cores = resolve_platform_cores(config, profiles) if target_cores else None
    systems = filter_systems_by_target(
        config.get("systems", {}), profiles, target_cores, platform_cores=plat_cores
    )
    return select_systems(systems, system_filter) if system_filter else systems


def platforms_with_systems(
    platforms: list[str],
    system_filter: list[str],
    profiles: dict[str, dict],
    target_cores_cache: dict[str, set[str] | None],
    platforms_dir: str,
    target: str | None,
    is_all: bool,
) -> RunScope:
    """The platforms a --system list leaves a system to cover, before any lock.

    Under --all a platform without one is out of scope, as a platform
    without the target is: `--all --system sony-playstation-2` built every
    PS2 pack and exited 1 on MiSTer, which has no PS2. Under --platform the
    request is refused, with its reason. verify.py and generate_pack.py
    scope a --system list through this one function, and print the notices
    on stderr: verify --json prints its document on stdout.
    """
    kept: list[str] = []
    notices: list[str] = []
    for name in platforms:
        config = load_platform_config(name, platforms_dir)
        tc = target_cores_cache.get(name) if target else None
        if platform_scope_systems(config, profiles, tc, system_filter):
            kept.append(name)
            continue
        if not is_all:
            return RunScope(
                kept, notices, system_scope_error(config, name, system_filter, target)
            )
        declared = select_systems(config.get("systems", {}), system_filter)
        reason = (
            system_scope_error(config, name, system_filter, target)
            if declared and target
            else f"no system {', '.join(system_filter)}"
        )
        notices.append(f"INFO: Skipping {name}: {reason}")
    if not kept:
        where = f" on target {target}" if target else ""
        return RunScope(
            kept, notices, f"no platform here runs {', '.join(system_filter)}{where}"
        )
    return RunScope(kept, notices)


def system_scope_error(
    config: dict, platform_name: str, system_filter: list[str], target: str | None
) -> str:
    """Why a --system list leaves a platform no system.

    A system the platform declares but no core of the target runs was
    reported as a system the platform lacks, with a lookalike to try and a
    listing that refuses --target.
    """
    systems = config.get("systems", {})
    declared = select_systems(systems, system_filter)
    if declared and target:
        return (
            f"no core {platform_name} runs on target {target} emulates "
            f"{', '.join(sorted(declared))}"
        )
    hint = suggest_names(
        system_filter, sorted(systems), f"--platform {platform_name} --list-systems"
    )
    return f"{platform_name} has no system matching {', '.join(system_filter)}. {hint}"
