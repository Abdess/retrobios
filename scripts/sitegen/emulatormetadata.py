"""An emulator's romset and version, in its metadata rows and in the FAQ's romset table."""

from __future__ import annotations

import re
from pathlib import Path

from core.sizes import size_text
from model.profiles import reads_own_files
from sitegen.cards import ROMSET_FAQ
from sitegen.install import OS_LABELS, under_root
from sitegen.render import WIKI_SRC_DIR, code_span, count_text
from sitegen.sources import source_ref_markdown, version_basis_url


_MAME_RELEASE = re.compile(r"^0\.\d")


def emulator_romset(profile: dict) -> str:
    """The romset an arcade emulator's sets must match, "MAME 0.78", or "".

    ``mame_version`` where the profile has one (MAME4droid 2024 is app
    1.38.1 on MAME 0.289), else the version of a MAME build or of a
    FinalBurn core, whose sets follow its own release.
    """
    if not reads_own_files(profile):
        return ""
    emulator = str(profile.get("emulator", ""))
    version = str(profile.get("core_version") or "")
    if profile.get("mame_version"):
        return f"MAME {profile['mame_version']}"
    # HBMAME's sets are its own homebrew sets, whatever MAME it is based on.
    if "MAME" in emulator and "HBMAME" not in emulator and _MAME_RELEASE.match(version):
        return f"MAME {version}"
    if emulator.startswith("FinalBurn Neo") and version:
        return f"FinalBurn Neo {version}"
    if (emulator.startswith("FB Alpha") or "FBA" in emulator) and version:
        return f"FB Alpha {version}"
    return ""


def _version_said(value: object, basis: dict, profile: dict, mode: str = "") -> str:
    """One build's version and where the profile reads it, linked to the
    file or the tag where the source allows."""
    kind = basis.get("kind")
    if kind == "none":
        return "none stated in the source"
    if value is None:
        if kind == "unverified":
            return f"unknown: {_UNVERIFIED.get(str(basis.get('why')), 'unread')}"
        return "none published"
    value = str(value)
    url = version_basis_url(profile, basis, mode) if kind in ("file", "tag") else ""

    def shown(text: object) -> str:
        return f"[{code_span(str(text))}]({url})" if url else code_span(str(text))

    if kind == "file":
        return f"{value}, stated in {shown(basis.get('path'))}"
    if kind == "tag":
        distance = int(basis.get("distance") or 0)
        if not distance:
            return f"{value}, the tag at this revision"
        return f"{value}, {count_text(distance, 'commit')} after tag {shown(basis.get('tag'))}"
    if kind == "package":
        return f"{value}, read from {basis.get('artifact')}"
    if kind == "unverified":
        return f"{value}, not confirmed: {_UNVERIFIED.get(str(basis.get('why')), 'unread')}"
    return value


# Why a profile's version could not be read, said to a reader.
_UNVERIFIED = {
    "no_pin": "no revision recorded",
    "host_unsupported": "its host cannot be read",
    "host_gone": "its source is gone",
    "host_unreachable": "its host did not answer",
    "pin_off_branch": "its recorded revision is not the build described",
    "no_artifact": "no build recorded as read",
    "no_source": "no source declared",
}


def version_markdown(profile: dict) -> str:
    """The Version cell: core_version and where version_basis reads it.

    A null version said "none published" whether the code states none or
    nobody looked. Keyed by build mode like source, each build is named,
    where the page printed the dict's Python repr.
    """
    if "core_version" not in profile and not profile.get("version_basis"):
        return "unknown"
    value = profile.get("core_version")
    raw_basis = profile.get("version_basis")
    basis: dict = raw_basis if isinstance(raw_basis, dict) else {}
    if isinstance(value, dict) or (basis and "kind" not in basis):
        values = value if isinstance(value, dict) else {}
        modes = list(dict.fromkeys([*values, *basis]))
        return ", ".join(
            f"{_version_said(values.get(mode), basis.get(mode) or {}, profile, mode)} ({mode})"
            for mode in modes
        )
    return _version_said(value, basis, profile)


ROMSET_FAQ_PAGE = Path(WIKI_SRC_DIR) / "technical-faq.md"
_ROMSET_BLOCK = re.compile(
    r"(<!-- generated: romsets -->\n)(.*?)(<!-- /generated: romsets -->)", re.S)


def _retroarch_label(profile: dict) -> str:
    """"Arcade (MAME 2003)" gives "MAME 2003", "Arcade (FinalBurn Neo)
    (Neo-Geo)" gives "FinalBurn Neo (Neo-Geo)"."""
    inner = str(profile.get("display_name") or profile.get("emulator") or "").split("(", 1)[-1]
    return inner.replace(")", "", 1).strip()


def romset_table(profiles: dict) -> list[str]:
    """The FAQ's arcade table: each MAME and FinalBurn libretro core and the
    romset its profile reads at its pin.

    Written by hand, it told readers to collect MAME 0.160 sets for a core
    whose src/version.c states 0.159, and FinalBurn Neo 1.0.0.2 for a source
    at 1.0.0.03. A core whose name gives its version (Recalbox's MAME 0.258)
    needs no row.
    """
    rows: dict[str, list[str]] = {}
    for key, profile in sorted(profiles.items()):
        if not re.match(r"(mame|fbneo|fbalpha)", key) or \
                "libretro" not in str(profile.get("type", "")):
            continue
        romset = emulator_romset(profile)
        label = _retroarch_label(profile)
        if not romset or romset.split(" ", 1)[1].lstrip("v") in label:
            continue
        rows.setdefault(romset, []).append(label)

    def order(romset: str) -> tuple:
        family = 0 if romset.startswith("MAME") else 1 if romset.startswith("FB Alpha") else 2
        numbers = tuple(int(n) for n in re.findall(r"\d+", romset.split(" (", 1)[0]))
        return family, numbers

    lines = ["| Emulator, as RetroArch names it | Sets from |", "|---|---|"]
    lines.extend(f"| {', '.join(sorted(rows[romset]))} | {romset} |"
                 for romset in sorted(rows, key=order))
    return lines


def with_romset_table(page: str, profiles: dict) -> str:
    """The FAQ page with its romset table read from the profiles."""
    table = "\n".join(romset_table(profiles)) + "\n"
    if not _ROMSET_BLOCK.search(page):
        raise ValueError(f"{ROMSET_FAQ_PAGE}: no romsets block to write the table in")
    return _ROMSET_BLOCK.sub(lambda m: f"{m.group(1)}{table}{m.group(3)}", page, count=1)


def render_metadata_rows(profile: dict) -> list[str]:
    """Scalar profile fields, one table row each.

    Anything structured belongs in a collapsible block below, not in a
    row: a dict rendered into a table cell is unreadable.
    """
    lines: list[str] = []
    romset = emulator_romset(profile)
    if romset:
        lines.append(f"| Romset | [{romset}]({ROMSET_FAQ}) |")
    for field, label in [
        ("core", "Core ID"),
        ("core_name", "Core name"),
        ("bios_size", "BIOS size"),
        ("bios_directory", "BIOS directory"),
        ("bios_detection", "BIOS detection"),
        ("bios_selection", "BIOS selection"),
        ("firmware_file", "Firmware file"),
        ("firmware_source", "Firmware source"),
        ("firmware_install", "Firmware install"),
        ("firmware_detection", "Firmware detection"),
        ("resources_directory", "Resources directory"),
        ("rom_path", "ROM path"),
        ("game_count", "Game count"),
        ("verification", "Checks the file by"),
        ("analysis_date", "Analysis date"),
        ("analysis_commit", "Analysis commit"),
    ]:
        val = profile.get(field)
        if val is None or val == "" or isinstance(val, (dict, list)):
            continue
        if field == "bios_directory" and profile.get("type") == "standalone" \
                and not str(val).startswith(("/", "~", "$")) and ":" not in str(val):
            # A bare `bios/` read as a place on the device: it is a folder
            # inside the app's own data folder, which the notes describe.
            lines.append(f"| {label} | {code_span(val)}, inside the app's own data folder |")
        elif field == "bios_size" and isinstance(val, int):
            lines.append(f"| {label} | {size_text(val)} ({val:,} bytes) |")
        elif isinstance(val, str) and val.startswith("http"):
            lines.append(f"| {label} | [{val}]({val}) |")
        else:
            lines.append(f"| {label} | {val} |")
    roots = profile.get("data_root")
    if isinstance(roots, dict):
        # The folder per system, for the reader who checks the profile.
        for key in ("windows", "macos", "linux", "android", "ios"):
            root = roots.get(key)
            if isinstance(root, dict) and root.get("path"):
                lines.append(f"| Data folder ({OS_LABELS[key]}) | "
                             f"{under_root(str(root['path']), '')} |")
    if profile.get("source_ref"):
        lines.append(
            f"| Source ref | {source_ref_markdown(profile, profile['source_ref'])} |"
        )
    return lines
