"""Command-line arguments and listings read from the registry and the profiles."""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from model.platforms import load_platform_config
from model.profiles import is_emulator, load_emulator_profiles
from model.registry import list_registered_platforms, list_release_pack_platforms
from model.systems import platform_system_names, system_index
from core.paths import PLATFORMS_DIR, REPO_ROOT


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


def require_platform(name: str, platforms_dir: str = PLATFORMS_DIR) -> None:
    """Exit with a usable message when no registered platform answers to a
    name. A file under platforms/ is not enough: _shared, _registry and the
    emulatorjs base config passed and reported 0/0 present.

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
    if not os.path.exists(os.path.join(platforms_dir, "_registry.yml")):
        # A fixture directory without a registry names its platforms by file.
        if os.path.exists(os.path.join(platforms_dir, f"{name}.yml")):
            return
        raise SystemExit(f"ERROR: unknown platform '{name}' in {platforms_dir}")
    known = list_registered_platforms(platforms_dir)
    if name in known:
        return
    import difflib

    close = difflib.get_close_matches(name, known, n=1)
    hint = f" Close match: '{close[0]}'." if close else ""
    raise SystemExit(
        f"ERROR: unknown platform '{name}'.{hint}\nKnown platforms: {', '.join(known)}"
    )


def selected_platforms(
    args: argparse.Namespace, parser: argparse.ArgumentParser | None = None
) -> list[str]:
    """The platforms --all or --platform names, every one registered."""
    if args.all:
        return list_registered_platforms(args.platforms_dir)
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
        return [args.platform]
    if parser is not None:
        parser.error("Specify --platform or --all")
    raise SystemExit("ERROR: specify --platform or --all")


def comma_list(value: str) -> list[str]:
    """The names of a comma-separated option, blanks dropped."""
    return [name.strip() for name in value.split(",") if name.strip()]


def requested_regions(value: str | None, parser: argparse.ArgumentParser) -> list[str]:
    """--region as a priority list, best first; a bad value ends the run."""
    if not value:
        return []
    from model import region

    try:
        return region.parse_requested(value)
    except ValueError as exc:
        parser.error(str(exc))


# What each listing reads. Anything else given beside it, another listing
# included, is refused: printing past a narrowing flag lets the user believe
# it applied.
LISTING_FLAGS: dict[str, set[str]] = {
    "--list-platforms": set(),
    "--list-emulators": set(),
    "--list-systems": {"--platform"},
    "--list-targets": {"--platform"},
}


def refuse_beside_mode(
    modes: Sequence[tuple[str, object]],
    given: set[str],
    allowed: Mapping[str, set[str]],
    parser: argparse.ArgumentParser,
) -> str | None:
    """The first mode requested, after refusing every other given flag it
    does not read. A flag is applied or refused, never ignored."""
    mode = next((name for name, on in modes if on), None)
    if mode is not None:
        for flag in sorted(given - allowed[mode] - {mode}):
            parser.error(f"{flag} is incompatible with {mode}")
    return mode


def run_listing(
    args: argparse.Namespace, parser: argparse.ArgumentParser, list_platforms: bool
) -> bool:
    """Print the listing the command line asks for. True when one ran."""
    if list_platforms:
        print_platform_listing(args.platforms_dir)
    elif args.list_emulators:
        list_emulator_profiles(args.emulators_dir)
    elif args.list_systems and args.platform:
        list_platform_system_ids(args.platform, args.platforms_dir)
    elif args.list_systems:
        list_system_ids(args.emulators_dir)
    elif args.list_targets:
        if not args.platform:
            parser.error("--list-targets requires --platform")
        from model.targets import list_available_targets, target_listing_line

        targets = list_available_targets(args.platform, args.platforms_dir)
        if not targets:
            print(f"No targets configured for platform '{args.platform}'")
        for t in targets:
            print(target_listing_line(t))
    else:
        return False
    return True


def list_emulator_profiles(emulators_dir: str, skip_aliases: bool = True) -> None:
    """Print available emulator profiles."""
    profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    for name in sorted(profiles):
        p = profiles[name]
        if not is_emulator(p):
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
