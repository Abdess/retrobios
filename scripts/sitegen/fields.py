"""Profile and platform fields rendered as page text."""

from __future__ import annotations

import re
from collections.abc import Callable

from sitegen import markup
from sitegen.render import escape_tags, scalar_text, render_yaml_value
from sitegen.sources import source_ref_markdown, link_prose_citations


def search_excluded(lines: list[str]) -> list[str]:
    """Lines the site search leaves out, as a block of their own.

    The browser downloads and indexes the whole search index before the
    first result: hashes, link lists and install commands repeated on 600
    pages made it 21 MB. Hashes are found by files/?hash=, names and prose
    stay searchable.

    A section, not a div: the search plugin compares elements by tag, so
    the first div closed inside an excluded div (a code block's) ended the
    exclusion and the rest of the block was indexed.
    """
    return ["", markup.block_open("section", markup.search_exclude()), "",
            *lines, "", "</section>", ""]


def render_platform_details(profile: dict) -> list[str]:
    """The per-platform block, one level of nesting deep."""
    lines: list[str] = []
    platform_details = profile.get("platform_details")
    if platform_details and isinstance(platform_details, dict):
        body: list[str] = []
        for pk, pv in platform_details.items():
            if isinstance(pv, dict):
                body.extend([f"- **{pk}:**", ""])
                for sk, sv in pv.items():
                    body.append(f"    - {sk}: {_detail_value(profile, sk, sv)}")
                body.append("")
            else:
                body.append(f"- **{pk}:** {_detail_value(profile, pk, pv)}")
        lines.extend(markup.details("info", "Platform details", body, opened=True))

    return lines


def _detail_value(profile: dict, key: object, value: object) -> str:
    """A platform detail, its citations linked at the profile's pin."""
    if key == "source_ref" and isinstance(value, (str, dict)):
        return source_ref_markdown(profile, value)
    if isinstance(value, str):
        return escape_tags(link_prose_citations(profile, value))
    return _plain_value(value)


def _plain_value(value: object) -> str:
    """A scalar or a list of scalars as a reader writes it, not as Python does."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        # A YAML null states that there is none, but Python's `None` read as a gap.
        return "none"
    if isinstance(value, (list, tuple)):
        return ", ".join(_plain_value(item) for item in value)
    return escape_tags(str(value))


def _structured_field_text(profile: dict) -> Callable[[object, object], str]:
    """Scalars of a structured block, citations linked at the profile's pin.

    The file entries and platform details linked their source_ref, and the
    analysis and firmware blocks printed 186 of them as plain code.
    """
    def text(key: object, value: object) -> str:
        if key == "source_ref" and isinstance(value, str):
            return source_ref_markdown(profile, value)
        if isinstance(value, str):
            return link_prose_citations(profile, scalar_text(key, value))
        return scalar_text(key, value)

    return text


def render_structured_blocks(profile: dict) -> list[str]:
    """Every remaining structured field, as a collapsible section."""
    lines: list[str] = []
    _structured_blocks = [
        ("analysis", "Source analysis"),
        ("memory_layout", "Memory layout"),
        ("regions", "Regions"),
        ("nvm_layout", "NVM layout"),
        ("model_kickstart_map", "Model kickstart map"),
        ("builtin_boot_roms", "Built-in boot ROMs"),
        ("common_bios_filenames", "Common BIOS filenames"),
        ("valid_bios_crc32", "Valid BIOS CRC32"),
        ("dev_flash", "dev_flash"),
        ("dev_flash2", "dev_flash2"),
        ("dev_flash3", "dev_flash3"),
        ("firmware_modules", "Firmware modules"),
        ("firmware_titles", "Firmware titles"),
        ("fallback_fonts", "Fallback fonts"),
        ("io_devices", "I/O devices"),
        ("partitions", "Partitions"),
        ("mlc_structure", "MLC structure"),
        ("machine_directories", "Machine directories"),
        ("machine_properties", "Machine properties"),
        ("whdload_kickstarts", "WHDLoad kickstarts"),
        ("bios_identical_to", "BIOS identical to"),
        ("pack_structure", "Pack structure"),
        ("firmware_version", "Firmware version"),
    ]
    for field, label in _structured_blocks:
        val = profile.get(field)
        if val is None:
            continue
        body: list[str] = []
        render_yaml_value(body, val, indent=0,
                           field_text=_structured_field_text(profile))
        # Closed: raw profile data, below the files (Cemu's firmware
        # titles opened the page above them).
        block = markup.details(
            "abstract", label, [escape_tags(line) for line in body])
        # A block listing hashes is the lookup's, as a card's hash lines are:
        # izapple2's ROM table put "md5" 59 times in the search, above the
        # page that explains MD5 checks.
        if any(re.search(r"\b[0-9a-f]{32,64}\b", line) for line in body):
            block = search_excluded(block)
        lines.extend(block)

    return lines


def hash_spans(value: str | list, copy: bool = False) -> str:
    """Each hash a profile accepts, in full, each with a copy button when
    *copy*.

    Cut to 12 characters with the rest in a title attribute, 208 hashes
    that only a profile declares were out of reach of the site search: it
    indexes text, and a pasted sha1 matched nothing.
    """
    from core.hashing import parse_hash_list

    return ", ".join(
        markup.hash_value(v, copy) for v in parse_hash_list(value)
    )
