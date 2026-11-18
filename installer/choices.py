"""RomM firmware layout and the narrowing a command or a record asks for."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from installer.constants import DEFAULT_RELEASE_REF, RELEASE_REF
from installer.cores import entry_systems, key_file_holders, refuse_name
from installer.embedded import display_name
from installer.line_ui import emulator_names, system_aliases
from installer.narrowing import (
    available_choices,
    designated_cores,
    narrow_to_cores,
    recorded_axes,
    resolve_choices,
    resolve_regions,
    standalone_layout,
)
from installer.network import _pack_alone, fetch_standalone
from installer.offline import LOCAL
from installer.probe import _is_dir
from installer.record import drop_recorded
from installer.terminal import detail


# RomM 5.4 places each platform's firmware by `filesystem.structure.firmware`
# in config.yml, "bios/{platform}" by default, relative to the library
# (rommapp/romm 5.4.0 68f71259, backend/config/config_manager.py:58,101-109,
# 205-225,564-568). The library and config.yml both sit under the RomM base
# folder (config/__init__.py:46-48, config_manager.py:264-265). A library
# laid out as {platform}/roms makes RomM stop until config.yml declares its
# templates, and RomM suggests firmware: "{platform}/bios" there
# (config_manager.py:1105-1124).


def parse_romm_firmware(template: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The literal folders before and after {platform}, as RomM parses them."""
    sections = [section for section in template.strip().split("/") if section]
    if not sections:
        raise ValueError("the RomM firmware template is empty")

    def macro(section: str) -> str | None:
        if section.startswith("{") and section.endswith("}"):
            return section[1:-1].strip()
        return None

    if any(section in (".", "..") for section in sections):
        raise ValueError(f"the RomM firmware template {template!r} climbs out of the library")
    platform_at = [i for i, section in enumerate(sections) if macro(section) == "platform"]
    if len(platform_at) != 1:
        raise ValueError(f"the RomM firmware template {template!r} needs one '{{platform}}'")
    before, after = sections[:platform_at[0]], sections[platform_at[0] + 1:]
    if any(macro(section) is not None for section in before + after):
        raise ValueError(f"the RomM firmware template {template!r} takes literal folder "
                         "names around '{platform}'")
    return tuple(before), tuple(after)


def _romm_configured_firmware(config: Path) -> str | None:
    """filesystem.structure.firmware from RomM's config.yml, read without a
    YAML library: only that nested scalar is needed."""
    try:
        lines = config.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    path: list[tuple[int, str]] = []
    for line in lines:
        stripped = line.split(" #", 1)[0].rstrip()
        if not stripped.strip() or stripped.lstrip().startswith(("#", "-")):
            continue
        indent = len(stripped) - len(stripped.lstrip())
        key, sep, value = stripped.strip().partition(":")
        if not sep:
            continue
        while path and path[-1][0] >= indent:
            path.pop()
        keys = [name for _indent, name in path] + [key.strip().strip("'\"")]
        if keys == ["filesystem", "structure", "firmware"] and value.strip():
            return value.strip().strip("'\"")
        path.append((indent, key.strip().strip("'\"")))
    return None


def romm_firmware_layout(
    bios_path: Path, template: str | None
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Where RomM reads each platform's firmware, relative to its library.

    bios_path is the folder the default template names, so its parent is the
    library. The template comes from --romm-firmware, else from config.yml
    beside the library. None keeps the pack's own bios/<platform> layout.
    """
    library = bios_path.parent
    if template is None:
        template = _romm_configured_firmware(library.parent / "config" / "config.yml")
    if template is not None:
        return parse_romm_firmware(template)
    platform_first = not _is_dir(library / "roms") and any(
        _is_dir(path) for path in library.glob("*/roms")
    )
    if platform_first:
        raise ValueError(
            f"{library} keeps its roms inside each platform folder, and RomM then "
            "reads firmware where filesystem.structure.firmware in its config.yml "
            "says, which was not found here. RomM suggests \"{platform}/bios\" for "
            "this layout: run again with --romm-firmware \"{platform}/bios\", or "
            "with the value config.yml holds."
        )
    return None


def romm_relayout(
    files: list[dict], bios_path: Path,
    before: tuple[str, ...], after: tuple[str, ...],
) -> tuple[list[dict], Path]:
    """The manifest's bios/<platform>/<file> entries under RomM's template,
    with the library as the root they are relative to."""
    if (before, after) == (("bios",), ()):
        return files, bios_path
    moved = []
    for entry in files:
        slug, _, rest = str(entry["dest"]).partition("/")
        if not rest:
            # Firmware of no platform: RomM lists none, the default place stays.
            moved.append({**entry, "dest": f"bios/{slug}"})
            continue
        moved.append({**entry, "dest": "/".join((*before, slug, *after, rest))})
    return moved, bios_path.parent


def _older_list_advice(plat: str = "") -> str:
    """How to reach a file list that records what an option needs.

    A list without the fields comes from an older release. Pinned with
    RETROBIOS_REF, as the docs suggest for reproducibility, "a newer one"
    meant unsetting the variable, and nothing said so. A pack's own list is
    the pack's: the one-line installer does not change it, and a current
    pack was said to come from an older release.
    """
    if _pack_alone(plat) and LOCAL.pack is not None:
        return (f"  The list in {LOCAL.pack.name} does not record it: add --manifest FILE, "
                f"a copy of install/{plat or '<platform>'}.json, or run without the option.")
    if RELEASE_REF != DEFAULT_RELEASE_REF:
        return (f"  RETROBIOS_REF={RELEASE_REF} selects file lists published before "
                "this option existed: unset RETROBIOS_REF to use the current ones, "
                "or run without the option.")
    return ("  The file list comes from an older release: run the one-line "
            "installer again to fetch the current one.")


def _narrowing_advice(plat: str, axis: str, flag: str, recorded: frozenset,
                      pack_alone: bool) -> str:
    """What to do when a list or a pack records no axis: only a remedy
    that changes the outcome. The pack's remedy named install/minui.json,
    refused the same way, and the list's fetched the same list again."""
    works = [name for name, field in (("--system", "systems"), ("--core", "cores"),
                                      ("--region", "regions")) if field in recorded]
    rest = f"Run it without {flag}" + (f", or narrow with {' and '.join(works)}"
                                       if works else "") + "."
    if pack_alone:
        listed = LOCAL.pack.list_records if LOCAL.pack is not None else None
        if listed is not None and axis not in listed:
            # The pack says its platform's own list lacks the axis too.
            return f"  {display_name(plat)}'s own file list records no {axis} either. {rest}"
        when = "which records them" if listed is not None else f"when that list records {axis}"
        return f"  Add --manifest FILE, a copy of install/{plat}.json, {when}. {rest}"
    if recorded:
        # A current list: the platform has no such axis.
        return f"  {rest}"
    return _older_list_advice(plat)


def _narrow_to_emulators(
    names: list[str], manifest: dict, plat: str,
    files: list[dict], omitted: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Keep what the named emulators read, as the pack built for them.

    An emulator page offers this as one command, so a name the platform
    does not run is refused rather than read as nothing to install.
    """
    if "system_cores" not in manifest:
        print(f"Error: the {plat} file list does not say which emulators read "
              "which systems, which --emulator needs.", file=sys.stderr)
        print(_older_list_advice(plat), file=sys.stderr)
        sys.exit(1)
    known = sorted(emulator_names(manifest, files, omitted))
    try:
        chosen = resolve_choices(names, known, "emulator")
    except ValueError as exc:
        refuse_name(plat, f"Error: {plat}: {exc}")
    before = len(files)
    files, omitted = narrow_to_cores(manifest, chosen, files, omitted)
    # A whole-platform install keeps the platform's files of a system no
    # core is mapped to. Here only the named emulators' systems are wanted.
    cores = designated_cores(manifest, chosen)
    reached = {
        system for system, readers in (manifest.get("system_cores") or {}).items()
        if cores.intersection(readers)
    }

    def theirs(entry: dict) -> bool:
        return entry.get("cores") is not None or bool(reached.intersection(entry_systems(entry)))

    files = [entry for entry in files if theirs(entry)]
    omitted = [entry for entry in omitted if theirs(entry)]
    print(f"  Narrowed {before} to {len(files)} files to {', '.join(chosen)}")
    return files, omitted


def _standalone_builds(
    values: list[str], names: dict[str, str], manifest: dict, plat: str,
    files: list[dict], omitted: list[dict],
) -> tuple[list[dict], list[dict]]:
    """--emulator with --standalone: each emulator's standalone build in
    place of the files its core reads. An emulator with no standalone
    build is refused, as `generate_pack.py --standalone` refuses it."""
    if "standalone_builds" not in manifest:
        print(f"Error: the {plat} file list does not say which emulators have a "
              "standalone build, which --standalone needs.", file=sys.stderr)
        print(_older_list_advice(plat), file=sys.stderr)
        sys.exit(1)
    profiles = sorted({names[name] for name in resolve_choices(values, sorted(names),
                                                                "emulator")})
    lacking = [p for p in profiles if p not in manifest["standalone_builds"]]
    if lacking:
        refuse_name(plat, f"Error: {', '.join(lacking)} has no standalone build: run "
                    "again without --standalone.")
    before = len(files)
    files, omitted = standalone_layout(manifest, fetch_standalone(plat, manifest), profiles,
                                       files, omitted)
    detail(f"  The standalone {'builds' if len(profiles) > 1 else 'build'}: "
           f"{before} to {len(files)} files")
    return files, omitted


def _known_names(values: list[str] | None, known: list[str], label: str,
                 aliases: dict[str, str] | None = None) -> list[str]:
    """The names of values that resolve against known, the others left out."""
    kept = []
    for value in values or []:
        try:
            resolve_choices([value], known, label, aliases)
        except ValueError:
            continue
        kept.append(value)
    return kept


def _recorded_names(args: argparse.Namespace, plat: str, flag: str, known: list[str],
                    aliases: dict[str, str] | None = None) -> None:
    """A recorded --system, --core or --emulator kept to the names the list
    still holds, the others left out in one line."""
    name = flag[2:].replace("-", "_")
    values = list(getattr(args, name) or [])
    kept = _known_names(values, known, flag[2:], aliases)
    if kept != values:
        gone = ", ".join(value for value in values if value not in kept)
        drop_recorded(args, plat, flag, f"{gone} no longer on the list", kept)


def _recorded_emulators(args: argparse.Namespace, plat: str, manifest: dict,
                        files: list[dict], omitted: list[dict]) -> None:
    """A recorded --emulator that cannot narrow this list, left out."""
    if "system_cores" not in manifest:
        drop_recorded(args, plat, "--emulator", "the list does not say which emulators "
                      "read which systems")
        return
    _recorded_names(args, plat, "--emulator", sorted(emulator_names(manifest, files, omitted)))


def _recorded_regions(args: argparse.Namespace, plat: str) -> None:
    """A recorded --region kept to the regions this installer knows."""
    values = list(args.region or [])
    kept = []
    for value in values:
        try:
            resolve_regions([value])
        except ValueError:
            continue
        kept.append(value)
    if kept != values:
        drop_recorded(args, plat, "--region", "a region this installer does not know", kept)


def _requested_narrowing(
    args: argparse.Namespace, plat: str, files: list[dict], omitted: list[dict],
    manifest: dict | None = None,
) -> tuple[list[str], list[str], list[str]] | None:
    """The systems, cores and regions named on the command line, checked."""
    if not (args.system or args.core or args.region):
        return None
    pack_alone = _pack_alone(plat)
    recorded = recorded_axes(files, omitted)
    if pack_alone:
        # A pack records the systems of its files, not their cores or
        # regions: either filter would keep everything, and is refused.
        recorded = recorded & {"systems"}
    asked = [(flag, axis) for flag, given, axis in (
        ("--system", args.system, "systems"), ("--core", args.core, "cores"),
        ("--region", args.region, "regions")) if given]
    if getattr(args, "from_record", False):
        # A recorded option that cannot narrow this list is left out: nobody
        # typed it, and every run without options would stop on it.
        for flag, axis in asked:
            if axis not in recorded:
                drop_recorded(args, plat, flag, f"the list records no {axis}")
        asked = [(flag, axis) for flag, axis in asked if axis in recorded]
        _recorded_regions(args, plat)
        choices = available_choices(files, omitted)
        if args.system:
            _recorded_names(args, plat, "--system", choices["systems"],
                            system_aliases(manifest))
        if args.core:
            _recorded_names(args, plat, "--core", choices["cores"])
        if not (args.system or args.core or args.region):
            return None
    for flag, axis in asked:
        if axis in recorded:
            continue
        # Without the field, a filter would match nothing and install
        # everything: refused rather than ignored, by the axis the list
        # lacks, with what works on it.
        source = (LOCAL.pack.name if pack_alone and LOCAL.pack is not None
                  else f"the {plat} file list")
        print(f"Error: {source} records no {axis}, so {flag} cannot narrow it.",
              file=sys.stderr)
        print(_narrowing_advice(plat, axis, flag, recorded, pack_alone), file=sys.stderr)
        sys.exit(1)
    choices = available_choices(files, omitted)
    try:
        systems = resolve_choices(
            args.system or [], choices["systems"], "system", system_aliases(manifest),
            key_file_holders(files, omitted),
        )
        cores = resolve_choices(args.core or [], choices["cores"], "core")
        regions = resolve_regions(args.region or [])
    except ValueError as exc:
        refuse_name(plat, f"Error: {plat}: {exc}")
    return systems, cores, regions
