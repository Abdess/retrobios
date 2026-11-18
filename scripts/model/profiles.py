"""Loading and selecting emulator profiles, and the fields that identify an entry."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from core.cli import InputMissing, suggest_names
from model.alternatives import derive_member_requirements
from model.sources import source_yaml
from model.systems import norm_system_id
from core.paths import REPO_ROOT


# The content tests a profile can declare in ``validation:``, each run by
# reading the candidate the way the emulator does.
CONTENT_CHECKS = frozenset({"romdir", "masked_sha1"})


emulator_profiles_cache: dict[tuple[str, bool], dict[str, dict]] = {}


class ProfileSelectionError(ValueError):
    """A named profile cannot answer for itself."""


def profiles_for_systems(
    profiles: dict, system_ids: list[str], standalone: bool = False
) -> list[str]:
    """Profile keys that serve any of the systems, spelled either way.

    Compared on the normalized id: stella2014 writes atari_2600 where every
    other profile writes atari-2600, and an exact match built two different
    packs under one file name, the second replacing the first.
    """
    wanted = {norm_system_id(sid) for sid in system_ids}
    matching = []
    for name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias") or profile.get("role") == "test":
            continue
        if standalone and "standalone" not in profile.get("type", "libretro"):
            continue
        if wanted & {norm_system_id(sid) for sid in profile.get("systems", [])}:
            matching.append(name)
    return matching


def entry_system_ids(entry: dict, profile: dict) -> list[str]:
    """Systems a profile entry serves.

    The entry's own `system:`, else its own `systems:` (a MAME device set
    the machines of several systems load), else every system of its
    profile.
    """
    own = entry.get("system")
    if own:
        return [str(own)]
    listed = entry.get("systems") or profile.get("systems") or []
    return [str(sid) for sid in listed]


def entry_serves_systems(entry: dict, profile: dict, system_ids: list[str]) -> bool:
    """Whether a profile entry belongs to one of the systems, spelled either way.

    The entry's own `system:` or `systems:` decides. One without either
    serves every system of its profile, the rule a platform pack applies to
    core extras.
    """
    wanted = {norm_system_id(sid) for sid in system_ids}
    return bool(wanted & {norm_system_id(sid) for sid in entry_system_ids(entry, profile)})


def select_emulator_profiles(
    profile_names: list[str],
    all_profiles: dict,
    standalone: bool = False,
) -> list[tuple[str, dict]]:
    """Resolve named profiles, refusing the ones that answer for no core.

    An alias is the same binary under another name, so naming one selects
    the profile it is an alias of, said on stderr. A launcher only starts an
    emulator and has no requirements of its own: naming one is a question
    about the wrong profile, and the error says so. Raising rather than exiting lets the verifier stop and the
    builder return empty-handed from one rule.
    """
    selected: list[tuple[str, dict]] = []
    for name in profile_names:
        if name not in all_profiles:
            # A buildbot name (pcfx, advmame) lives in a profile's cores:,
            # and the spelling hints sent pcfx to two PlayStation cores.
            claimants = sorted(
                key for key in upstream_profile_index(all_profiles).get(name, ())
                if all_profiles[key].get("type") != "launcher" and all_profiles[key].get("role") != "test"
            )
            if len(claimants) == 1:
                name = claimants[0]
            elif claimants:
                raise ProfileSelectionError(
                    f"{name} is a core name of {', '.join(claimants)}: "
                    f"use --emulator with one of them"
                )
        if name not in all_profiles:
            available = sorted(
                key
                for key, value in all_profiles.items()
                if value.get("type") != "alias" and value.get("role") != "test"
            )
            raise ProfileSelectionError(
                f"emulator '{name}' not found\n"
                + suggest_names([name], available, "--list-emulators")
            )
        profile = all_profiles[name]
        kind = profile.get("type", "libretro")
        if kind == "alias":
            # An alias without alias_of is found through the profile whose
            # cores: names it, as the buildbot reverse index does.
            target = profile.get("alias_of") or next(
                (
                    key for key, value in all_profiles.items()
                    if value.get("type") != "alias" and name in (value.get("cores") or [])
                ),
                None,
            )
            if not target or target not in all_profiles:
                raise ProfileSelectionError(
                    f"{name} is an alias with no profile of its own to name"
                )
            # The name a user reads in RetroArch or on the buildbot: the tool
            # knows the profile, so it says which and carries on.
            print(f"{name} is {target}: using its profile", file=sys.stderr)
            name, profile = target, all_profiles[target]
            kind = profile.get("type", "libretro")
            if any(key == name for key, _ in selected):
                continue
        if kind == "launcher":
            raise ProfileSelectionError(
                f"{name} is a launcher: use the emulator it launches"
            )
        if standalone and "standalone" not in kind:
            raise ProfileSelectionError(
                f"{name} ({kind}) does not support --standalone"
            )
        selected.append((name, profile))
    return selected


PROFILE_BACKUP_SUFFIX = ".old.yml"


def source_yaml_paths(directory: str | Path) -> list[Path]:
    """YAML sources in a directory, without the copies the hash merge keeps."""
    return [
        path
        for path in sorted(Path(directory).glob("*.yml"))
        if not path.name.endswith(PROFILE_BACKUP_SUFFIX)
    ]


def installed_data_refs(platform: str, emulators_dir: str = "") -> frozenset[str]:
    """Data directories a platform's own packages install beside the cores.

    The platform layer names trees for its systems (retroarch.yml carries
    dolphin-sys and ppsspp-assets, and Lakka inherits them), while Lakka's
    core packages put both into the system directory themselves. A profile
    records that with installed_on on its data directory reference.
    """
    emulators_dir = emulators_dir or os.path.join(
        REPO_ROOT, "emulators")
    return frozenset(
        str(tree.get("ref", ""))
        for profile in load_emulator_profiles(emulators_dir, skip_aliases=False).values()
        for tree in profile.get("data_directories") or []
        if isinstance(tree, dict) and platform in (tree.get("installed_on") or [])
    )


def load_emulator_profiles(
    emulators_dir: str,
    skip_aliases: bool = True,
) -> dict[str, dict]:
    """Load all emulator YAML profiles from a directory (cached)."""
    cache_key = (os.path.realpath(emulators_dir), skip_aliases)
    if cache_key in emulator_profiles_cache:
        return emulator_profiles_cache[cache_key]
    if skip_aliases:
        # A filter over the full set: parsed once, 534 YAML files cost 1.6 s
        # every time a process asked for both variants.
        profiles = {
            name: profile
            for name, profile in load_emulator_profiles(emulators_dir, False).items()
            if profile.get("type") != "alias"
        }
        emulator_profiles_cache[cache_key] = profiles
        return profiles
    if importlib.util.find_spec("yaml") is None:
        # Every consumer reads {} as "this repo documents no emulator", which
        # is what a broken install looks like from the outside: zero coverage,
        # no gap, nothing to fix.
        print(
            "warning: pyyaml is not installed, no emulator profile was loaded",
            file=sys.stderr,
        )
        return {}
    profiles = {}
    emu_path = Path(emulators_dir)
    if not emu_path.is_dir():
        # Read as "no emulator", a mistyped --emulators-dir built a pack
        # without any core file marked OK, and sitesources wrote {} over
        # source-paths.json, both exiting 0.
        raise InputMissing(f"no emulator profile directory at {emulators_dir}")
    for f in source_yaml_paths(emu_path):
        with open(f) as fh:
            profile = source_yaml(fh) or {}
        if "emulator" not in profile:
            continue
        _normalize_hash_fields(profile)
        derive_member_requirements(profile)
        profiles[f.stem] = profile
    emulator_profiles_cache[cache_key] = profiles
    return profiles


_HASH_FIELDS = ("crc32", "md5", "sha1", "sha256")


def _normalize_hash_fields(node: object) -> None:
    """Coerce hash values to str in place.

    YAML types unquoted digit-only hashes (e.g. crc32: 70295038) as int,
    which breaks string comparisons and formatting downstream.
    """
    if isinstance(node, dict):
        for key, val in node.items():
            if key in _HASH_FIELDS:
                if isinstance(val, int):
                    node[key] = str(val)
                elif isinstance(val, list):
                    node[key] = [str(v) if isinstance(v, int) else v for v in val]
            else:
                _normalize_hash_fields(val)
    elif isinstance(node, list):
        for item in node:
            _normalize_hash_fields(item)


def unique_emulator_profiles(profiles: dict[str, dict]) -> dict[str, dict]:
    """Profiles counting as distinct emulators (aliases and tests excluded)."""
    return {
        k: v for k, v in profiles.items() if v.get("type") != "alias" and v.get("role") != "test"
    }


# What identifies a profile entry's content, carried unchanged wherever the
# entry travels (cross-reference report, core extras, second-pass copies).
# Each copy once kept its own subset: np2kai's bios.rom lost min_size and
# validation on the way and resolved to an IBM PCjr ROM of the same name.
PROFILE_IDENTITY_FIELDS = (
    "sha1", "md5", "sha256", "crc32", "size", "min_size", "max_size",
    "size_multiple", "validation", *sorted(CONTENT_CHECKS), "aliases", "unsourceable",
)


def upstream_profile_index(
    profiles: dict[str, dict], include_aliases: bool = False
) -> dict[str, set[str]]:
    """Every name a core is known by upstream -> the profiles that claim it.

    A name can be claimed twice: the buildbot's `pcsx2` is the LRPS2 core,
    which lrps2.yml lists in `cores:`, and also the key of the standalone
    pcsx2 profile. A last-wins dict kept one of the two depending on file
    order, and a RetroArch target filter dropped LRPS2's files. Callers
    choose: a platform list prefers the exact key, a target filter keeps
    every claimant.
    """
    index: dict[str, set[str]] = {}
    for name, profile in profiles.items():
        if not include_aliases and profile.get("type") == "alias":
            continue
        index.setdefault(name, set()).add(name)
        for core in profile.get("cores") or []:
            index.setdefault(str(core), set()).add(name)
    return index


def preferred_profile(index: dict[str, set[str]], name: str) -> str | None:
    """The profile a name designates: its own key first, else the first claimant."""
    claimants = index.get(name)
    if not claimants:
        return None
    return name if name in claimants else sorted(claimants)[0]
