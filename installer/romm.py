"""RomM: where it reads each platform's firmware, and the list laid out under its library."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from installer.console import detail
from installer.host_fs import _is_dir
from installer.refusal import Refusal

if TYPE_CHECKING:
    from installer.setup_passes import _PlatformPass
    from installer.run_setups import _InstallRun

# RomM serves the firmware rows its library scan records (rommapp/romm 5.4.0,
# backend/endpoints/firmware.py:148,175 read db_firmware_handler.list_firmware),
# and its folder watcher is off unless ENABLE_RESCAN_ON_FILESYSTEM_CHANGE is
# set (backend/config/__init__.py:284, backend/watcher.py:106): files put in
# place stay unseen by the player until a scan.
ROMM_SCAN_WORDS = ("RomM lists the firmware its library scan has recorded: start a scan "
                   "in RomM so that its player finds these files.")


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


def _check_run_romm(run: _InstallRun) -> None:
    """--romm-firmware applied or refused, never ignored."""
    args = run.args
    if args.romm_firmware is None:
        return
    # Applied or refused, never ignored.
    if not any(name == "romm" for name, _path in run.platforms):
        raise Refusal("option", "not_applicable", "romm",
                      "Error: --romm-firmware applies to RomM, which this run does not "
                      "install for.")
    try:
        parse_romm_firmware(args.romm_firmware)
    except ValueError as exc:
        raise Refusal("option", "invalid", "romm", f"Error: {exc}") from None


def _pass_romm_layout(run: _InstallRun, p: _PlatformPass) -> None:
    """RomM's firmware laid out under its library, as --romm-firmware says."""
    bios_path = p.bios_path
    try:
        layout = romm_firmware_layout(bios_path, run.args.romm_firmware)
    except ValueError as exc:
        raise Refusal("option", "invalid", "romm", f"Error: {exc}") from None
    if layout is not None:
        p.files, library = romm_relayout(p.files, bios_path, *layout)
        if library != bios_path:
            run.installed_paths[run.installed_paths.index(bios_path)] = library
            detail(f"  Firmware laid out as {'/'.join(layout[0] + ('{platform}',) + layout[1])} "
                   f"under {library}")
            p.bios_path = library
