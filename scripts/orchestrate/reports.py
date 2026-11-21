"""What verify and the pack build print, read back as counts, paths and platform identities."""

from __future__ import annotations

import re
from collections.abc import Iterator

from core.paths import PLATFORMS_DIR

# "Label: X/Y OK ..." or "Label: X/Y present ...", the summary line verify
# prints for each group of identical platforms.
_VERIFY_SUMMARY = re.compile(r"^(.+?):\s+(\d+)/(\d+)\s+(OK|present)")
_PACK_HEADER = re.compile(r"Generating (?:shared )?pack for (.+)\.\.\.")


def _verify_groups(output: str) -> Iterator[tuple[list[str] | None, str, re.Match[str] | None]]:
    """Each verify line with the platforms of the summary it falls under,
    and its own summary match when it is one."""
    names: list[str] | None = None
    for line in output.splitlines():
        m = _VERIFY_SUMMARY.match(line)
        if m:
            names = [name.strip() for name in m.group(1).split(" / ")]
        yield names, line, m


def _pack_lines(output: str) -> Iterator[tuple[str, str]]:
    """Each generate_pack line under a full pack's header, with its label.

    Labels carry execution metadata such as ``[source=full]``. Only the
    full, unreduced pack is what verify describes: with --all-variants the
    six variants shared one label and the last (platform, required) was
    compared to the full report.
    """
    label = ""
    for line in output.splitlines():
        m = _PACK_HEADER.match(line)
        if m:
            label = _full_pack_label(m.group(1).strip())
        elif label:
            yield label, line


def parse_verify_counts(output: str) -> dict[str, tuple[int, int]]:
    """Per-platform OK/total from verify output."""
    return {
        name: (int(m.group(2)), int(m.group(3)))
        for names, _line, m in _verify_groups(output) if m and names
        for name in names
    }


def parse_verify_extras(output: str) -> dict[str, int]:
    """Core files and game data verify says each pack carries, per platform.

    Read from the "Core files: N in pack" and "Game data: N in pack" lines
    that follow a platform's summary line.
    """
    extras: dict[str, int] = {}
    for names, line, m in _verify_groups(output):
        if m and names:
            extras.update(dict.fromkeys(names, 0))
            continue
        packed = re.match(r"^\s+(?:Core files|Game data): (\d+) in pack", line)
        if packed and names:
            for name in names:
                extras[name] += int(packed.group(1))
    return extras


def parse_pack_extras(output: str) -> dict[str, int]:
    """Files each full pack takes from the cores, per pack label."""
    extras: dict[str, int] = {}
    for label, line in _pack_lines(output):
        cores = re.search(r"\+ (\d+) from cores\)", line)
        if "files packed" in line and cores:
            extras[label] = int(cores.group(1))
    return extras


def _full_pack_label(label: str) -> str:
    """The pack name, or "" for a reduced variant such as [source=platform]."""
    meta = re.search(r"\s+\[([^\]]+)\]$", label)
    if meta is None:
        return label
    return label[: meta.start()] if meta.group(1) == "source=full" else ""


def parse_pack_counts(output: str) -> dict[str, tuple[int, int]]:
    """Per-pack OK/total from generate_pack output: {pack_label: (ok, total)}."""
    counts = {}
    for label, line in _pack_lines(output):
        # "622 files packed (359 baseline + 263 from cores), 358/359 files OK"
        ok_m = re.search(r"(\d+)/(\d+) files OK", line) if "files packed" in line else None
        if ok_m:
            counts[label] = (int(ok_m.group(1)), int(ok_m.group(2)))
    return counts


def parse_pack_exclusions(output: str) -> dict[str, int]:
    """Intentional unsafe-omission counts from pack output, per pack label."""
    exclusions: dict[str, int] = {}
    for label, line in _pack_lines(output):
        if "files packed" in line:
            excluded = re.search(r"(\d+) unsafe excluded", line)
            exclusions[label] = int(excluded.group(1)) if excluded else 0
    return exclusions


def parse_pack_paths(output: str) -> dict[str, str]:
    """The archive each full pack was written to, per pack label."""
    paths: dict[str, str] = {}
    for label, line in _pack_lines(output):
        written = re.match(r"^\s+(\S.*?\.zip): \d+ files packed", line)
        if written:
            paths[label] = written.group(1)
    return paths


def match_key(label: str) -> set[str]:
    """Comparable identity for a platform label.

    Display labels and registry ids differ in punctuation and spacing
    (``MiSTer FPGA`` against ``misterfpga``), and grouped packs join their
    members with either separator.
    """
    return {
        re.sub(r"[^a-z0-9]+", "", part.strip().lower())
        for part in label.replace("+", "/").split("/")
    } - {""}


def release_pack_keys(platforms_dir: str = PLATFORMS_DIR) -> set[str]:
    """Comparable identities of the platforms --all builds a pack for: their
    registry ids and display names, normalized as match_key does."""
    from model.registry import list_release_pack_platforms
    from model.platforms import load_platform_config

    keys: set[str] = set()
    for name in list_release_pack_platforms(platforms_dir):
        keys |= match_key(name)
        keys |= match_key(str(load_platform_config(name, platforms_dir).get("platform", name)))
    return keys
