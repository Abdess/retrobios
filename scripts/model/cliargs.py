"""Command-line arguments and listings read from the registry and the profiles."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.registry import list_registered_platforms, list_release_pack_platforms
from model.systems import platform_system_names, system_index
from core.paths import REPO_ROOT


def work_from_repo_root(
    args: argparse.Namespace, parser: argparse.ArgumentParser, path_flags: list[str]
) -> None:
    """Run from the repository root, whichever directory the command started in.

    database.json records every file from the root and the data registry
    names its caches the same way, so a run from scripts/ ended on a
    FileNotFoundError traceback. A path the caller typed is read from where
    they typed it, a default from the root.
    """
    root = REPO_ROOT
    if Path.cwd().resolve() == root:
        return
    for flag in path_flags:
        value = getattr(args, flag, None)
        if value and value != parser.get_default(flag):
            # A Path stays a Path for the code that joins onto it.
            setattr(args, flag, type(value)(os.path.abspath(value)))
    os.chdir(root)
    if getattr(args, "platform", None):
        # Read before the move, the registry was not there to map
        # "RetroArch" to its slug.
        args.platform = platform_arg(args.platform)


def platform_arg(value: str) -> str:
    """--platform as typed, mapped to the registry's slug when it names one.

    The site and the pack names say RetroArch and MiSTer FPGA, but verify and
    generate_pack refused both while install.py took them. Letters and
    digits decide, as for pack names. Anything else reaches require_platform
    unchanged and gets its suggestion.
    """
    key = re.sub(r"[^a-z0-9]", "", value.lower())
    if yaml is None or not os.path.isdir("platforms"):
        return value
    known = list_registered_platforms("platforms")
    for name in known:
        if re.sub(r"[^a-z0-9]", "", name.lower()) == key:
            return name
    return value


def require_platform(name: str, platforms_dir: str = "platforms") -> None:
    """Exit with a usable message when no platform answers to a name.

    A typo used to end in a traceback (verify, cross_reference) or in "no
    pack for batocra" after the whole build ran (generate_pack).
    """
    if "," in name:
        # generate_pack split the list to validate it, then used the whole
        # string as one name and ended in a traceback.
        raise SystemExit(
            f"ERROR: --platform takes one platform, not '{name}'. "
            "Run once per platform, or use --all."
        )
    if os.path.exists(os.path.join(platforms_dir, f"{name}.yml")):
        return
    import difflib

    known = list_registered_platforms(platforms_dir)
    close = difflib.get_close_matches(name, known, n=1)
    hint = f" Close match: '{close[0]}'." if close else ""
    raise SystemExit(
        f"ERROR: unknown platform '{name}'.{hint}\nKnown platforms: {', '.join(known)}"
    )


def list_emulator_profiles(emulators_dir: str, skip_aliases: bool = True) -> None:
    """Print available emulator profiles."""
    profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    for name in sorted(profiles):
        p = profiles[name]
        if p.get("type") == "alias" or p.get("role") == "test":
            continue
        display = p.get("emulator", name)
        ptype = p.get("type", "libretro")
        systems = ", ".join(p.get("systems", [])[:3])
        more = "..." if len(p.get("systems", [])) > 3 else ""
        # The type is padded to its longest value, so the systems start in
        # one column whatever the type reads.
        kind = f"[{ptype}]"
        print(f"  {name:30s} {display:40s} {kind:24s}{systems}{more}".rstrip())


def list_system_ids(emulators_dir: str) -> None:
    """Print available system IDs with emulator count."""
    index = system_index(load_emulator_profiles(emulators_dir))
    for _key, (spelling, emulators) in sorted(index.items(), key=lambda kv: kv[1][0]):
        count = len(emulators)
        print(f"  {spelling:35s} ({count} emulator{'s' if count > 1 else ''})")


def print_platform_listing(platforms_dir: str) -> None:
    """Every registered platform, one per line, marked when the installer
    alone serves it.

    Every platform takes --platform. --all covers every one, and the pack
    builder's --all the release packs. Printed by --list-platforms in
    verify.py and generate_pack.py, the name install.py gives it.
    """
    released = set(list_release_pack_platforms(platforms_dir))
    for name in list_registered_platforms(platforms_dir):
        print(name if name in released else f"{name} (installer only)")


def list_platform_system_ids(platform_name: str, platforms_dir: str) -> None:
    """Print system IDs from a platform's YAML config, with the platform's
    own names for them, which --system also accepts."""
    config = load_platform_config(platform_name, platforms_dir)
    systems = config.get("systems", {})
    names = platform_system_names(config, list(systems))
    for sys_id in sorted(systems):
        file_count = len(systems[sys_id].get("files", []))
        mfr = systems[sys_id].get("manufacturer", "")
        mfr_display = f"  [{mfr.split('|')[0]}]" if mfr else ""
        count = f"({file_count} file{'s' if file_count != 1 else ''})"
        also = f"  also: {', '.join(names[sys_id])}" if sys_id in names else ""
        print(f"  {sys_id:35s} {count:12s}{mfr_display}{also}".rstrip())
