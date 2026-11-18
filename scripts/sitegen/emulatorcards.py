"""An emulator file's card: badges, place, size, hashes and copies."""

from __future__ import annotations

import html
import os
import re
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from model.collection import _slug
from model.systemnames import system_name
from packs.crossref import FileConsumers, entry_target, held_copy
from resolve.cores import resolve_platform_cores
from sitegen import markup
from sitegen.cards import (
    ROMSET_FAQ,
    SEARCH_SKIPPED,
    SHORT_HASH,
    _card_title,
    _listed_words,
    _places_markdown,
    _platform_links,
    _platform_places,
    _search_skipped_apart,
    card_fold,
)
from sitegen.config import REPO_URL
from sitegen.descriptions import _said_as_list
from sitegen.fields import _hash_spans
from sitegen.install import (
    _OS_LABELS,
    _platform_display,
    _under_root,
    comes_with_app,
    data_root_words,
    standalone_place,
)
from sitegen.render import (
    WIKI_SRC_DIR,
    _code,
    _count,
    _escape_tags,
    _fmt_size,
    card_page,
    console_href,
)
from sitegen.sources import (
    _source_permalink,
    _source_ref_markdown,
    link_prose_citations,
    requested_by,
    version_basis_url,
)


# Emulator pages


def _named_system_link(sys_id: str, prefix: str = "") -> str:
    """A system by its display name, linked where _system_link links it.

    The emulator pages printed the id ("sony-playstation") where every
    other page says "Sony PlayStation". The id stays in the address only.
    """
    from sitegen.render import system_section

    name = system_name(sys_id).replace("[", r"\[").replace("]", r"\]")
    section = system_section(sys_id)
    if not section:
        return name
    slug, console = section
    return f"[{name}]({console_href(slug, console, prefix)})"


# Region slugs whose words are not the slug title-cased, beyond region.LABELS.
_REGION_WORDS = {"world": "every region"}


def _region_words(value: object, most: int = 0) -> str:
    """A region: value in words. ``most`` caps the regions named, the rest
    counted: one Saturn BIOS serves seven."""
    raw = value if isinstance(value, list) else [value] if value else []
    from model.region import label

    words = [_REGION_WORDS.get(str(r)) or label(str(r)) for r in raw]
    if most and len(words) > most:
        words = words[:most] + [f"{len(words) - most} more"]
    return _said_as_list(words)


_CATEGORY_WORDS = {"bios": "BIOS", "game_data": "game data", "bios_zip": "BIOS ZIP"}


def _snippet_noun(names: Iterable[str], firmware: int, fetched: int) -> str:
    """What an emulator's files are called in its snippet. A Switch
    emulator reads keys, and "eden keys" is what readers search for. Ship
    of Harkinian reads game ROMs, which are no BIOS."""
    names = list(names)
    keys = sum("key" in name.casefold() for name in names)
    if keys >= 2 and any("firmware" in name.casefold() for name in names):
        return "keys and firmware"
    if names and keys * 2 > len(names):
        return "keys"
    return "BIOS" if firmware * 2 >= fetched else "files"


def _status_badges(f: dict, in_repo: bool, for_system: str, shipped: bool) -> list[str]:
    """The chips saying whether a file is needed and whether it is held."""
    required = f.get("required", False)
    badges = []
    if shipped:
        # NetherSX2's three interface fonts sat beside the BIOS as
        # "required" and "missing": the app ships them, nobody fetches them.
        # Narrowed to one build, the build is named.
        build = f.get("mode") if f.get("mode") in ("standalone", "libretro") else ""
        label = f"installed with the {build} emulator" if build else "comes with the app"
        badges.append(f'<span class="rb-badge rb-badge-info">{label}</span>')
    elif required:
        needed = f"required for {html.escape(for_system)}" if for_system else "required"
        badges.append(
            f'<span class="rb-badge rb-badge-danger">{needed}</span>'
        )
    else:
        badges.append(
            '<span class="rb-badge rb-badge-muted">optional</span>'
        )
    # Whether the collection holds a file the app ships says nothing to
    # the reader: no status chip.
    if shipped:
        status = ""
    elif in_repo:
        status = '<span class="rb-badge rb-badge-success">in repo</span>'
    elif f.get("unsourceable"):
        status = '<span class="rb-badge rb-badge-muted">unsourceable</span>'
    else:
        status = '<span class="rb-badge rb-badge-warning">missing</span>'
    if status:
        badges.append(status)
    return badges


def _file_badges(f: dict, in_repo: bool, for_system: str = "") -> list[str]:
    """The status chips shown beside a file name.

    Fourteen independent optional fields, each contributing at most one
    chip. Kept apart from the rest of the row so the field-by-field
    rendering stays readable. ``for_system`` names the system a required
    file serves, on a profile that runs more than one.
    """
    hle = f.get("hle_fallback", False)
    mode = f.get("mode", "")
    category = f.get("category", "")
    region = f.get("region", "")
    storage = f.get("storage", "")
    embedded = f.get("embedded", False)
    has_builtin = f.get("has_builtin", False)
    archive = f.get("archive", "")
    ftype = f.get("type", "")
    shipped = comes_with_app(f)
    badges = _status_badges(f, in_repo, for_system, shipped)
    if hle:
        badges.append(
            '<span class="rb-badge rb-badge-info">HLE fallback</span>'
        )
    if mode and not (shipped and mode in ("standalone", "libretro")):
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{mode}</span>'
        )
    if category and category != "bios":
        badges.append(
            f'<span class="rb-badge rb-badge-info">{_CATEGORY_WORDS.get(category, category)}</span>'
        )
    if region:
        # Labelled: "optional in repo japan" read as one run-on phrase.
        badges.append(
            f'<span class="rb-badge rb-badge-muted">Region: {_region_words(region)}</span>'
        )
    if storage and storage != "embedded":
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{storage}</span>'
        )
    if embedded:
        badges.append(
            '<span class="rb-badge rb-badge-muted">embedded</span>'
        )
    if has_builtin:
        badges.append(
            '<span class="rb-badge rb-badge-info">built-in fallback</span>'
        )
    if archive:
        badges.append(
            f'<span class="rb-badge rb-badge-muted rb-badge-archive">in {archive}</span>'
        )
    if ftype and ftype != "bios":
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{ftype}</span>'
        )

    return badges


_LOAD_FROM = {
    "system_dir": "the system (BIOS) directory",
    "save_dir": "the save directory, not the BIOS directory",
    "content_dir": "the folder of the loaded content, not the BIOS directory",
    "working_directory": "the working directory, not the BIOS directory",
    "data_dir": "the emulator's data directory, not the BIOS directory",
    "hdd_image": "inside the emulated hard disk image, not the BIOS directory",
    "internal_storage": "the app's internal storage, not the BIOS directory",
}


def _by_build(value: object, words: Callable[[str], str]) -> str:
    """A field keyed by build, said per build, or a plain value said once."""
    if isinstance(value, dict):
        return ", ".join(f"{words(str(v))} ({mode} build)" for mode, v in value.items() if v)
    return words(str(value)) if value else ""


def _load_from_text(value: object) -> str:
    """Where the code reads a file, in words.

    The card showed the Path alone: Dolphin's libretro core reads
    gba_bios.bin from its save directory, and a reader put it under system/.
    """
    if value in (None, "", "system_dir"):
        return ""
    return _by_build(value, lambda v: _LOAD_FROM.get(v, _code(v)))


def _found_by_text(value: object) -> str:
    """How the code finds a file: by the name it opens, or by content."""
    words = {
        "name": "file name (the code opens this name)",
        "content": "content (the code scans the folder and identifies the file "
                   "by its hash, any file name works)",
    }
    return _by_build(value, lambda v: words.get(v, _code(v)))


def _on_mismatch_lines(value: object) -> list[str]:
    """What the code does when a declared check fails, where it is not reject."""
    said = {"warn": "warns and runs with the file", "reject": "rejects the file"}
    if value == "warn":
        return [f"On a failed check: {said['warn']}"]
    if isinstance(value, dict):
        return [f"On a failed {check} check: {said.get(str(how), _code(str(how)))}"
                for check, how in value.items()]
    return []


def emulator_setups(coverages: dict, profiles: dict) -> dict[str, list[str]]:
    """Each emulator with the platforms that run it, by display name."""
    setups: dict[str, list[str]] = {}
    for platform, cov in coverages.items():
        for emulator in resolve_platform_cores(cov["config"], profiles):
            setups.setdefault(emulator, []).append(platform)
    return {
        emulator: sorted(names, key=lambda p: _platform_display(p).casefold())
        for emulator, names in setups.items()
    }


def _validation_names(validation: dict | list | None) -> set[str]:
    """The checks a `validation:` names, a list or one list per build."""
    if isinstance(validation, dict):
        return {str(v) for checks in validation.values() for v in checks or []}
    return {str(v) for v in validation or []}


def _exact_size(size: int) -> str:
    """A rounded size with its bytes, where the bytes are not the same figure."""
    return _fmt_size(size) if size < 1024 else f"{_fmt_size(size)} ({size:,} bytes)"


def _build_file_links(pin_build: list[dict]) -> list[str]:
    """Each platform build file that holds the revision, linked at the
    commit it was read at when the source record holds it. The prose of
    pin_frozen named the file as plain text."""
    from sitegen.sources import _browse_repo, tree_holds

    links = []
    for build in pin_build:
        repo = _browse_repo(str(build["repo"]))
        path = str(build["path"])
        revision = str(build["revision"])
        text = f"{_escape_tags(_platform_display(str(build['platform'])))} {_code(path)}"
        # Linked where the record saw the file at that commit, as every
        # source link is: a tag can move, and is never recorded.
        if repo is not None and tree_holds(repo, revision, path):
            text = f"[{text}]({_source_permalink(repo, revision, path, None, None)})"
        links.append(f"{text} at {_code(str(build['revision']))} sets {_code(str(build['variable']))}")
    return links


def _build_rows(profile: dict) -> list[str]:
    """Meta card rows for who ships the build, how its files are found, why
    its revision is held and where its releases are announced."""
    rows = []
    built_by = profile.get("built_by") or []
    if built_by:
        names = ", ".join(f"[{p}](../platforms/{p}.md)" for p in map(str, built_by))
        rows.append(f"| Built by | {names}, under its core name. The libretro "
                    "buildbot does not publish this build. |")
    found = _found_by_text(profile.get("found_by"))
    if found:
        rows.append(f"| Files found by | {found} |")
    # Each pin says why it is held: a bare upstream revision read as a
    # profile left behind HEAD (mupen64plus, aps3e).
    for field, label in (("pin_frozen", "Revision held"),
                         ("upstream_frozen", "Upstream revision held")):
        frozen = profile.get(field)
        if frozen:
            held = _escape_tags(' '.join(str(frozen).split())).replace('|', r'\|')
            rows.append(f"| {label} | {held} |")
    builds = _build_file_links(profile.get("pin_build") or [])
    if builds:
        rows.append(f"| Build file | {'<br>'.join(builds)} |")
    announced = profile.get("version_source")
    if isinstance(announced, dict) and announced.get("url"):
        url = str(announced["url"])
        row = f"| Releases announced at | [{url}]({url})"
        if announced.get("no_genuine_copy"):
            row += (f" (version {_escape_tags(str(announced['no_genuine_copy']))} "
                    "announced there, found only as rebuilt copies)")
        rows.append(row + " |")
    return rows


def _entry_label(f: dict, profile: dict) -> str:
    """The name a file card goes by, its title without the badges."""
    fname = f.get("name", "")
    if f is any_name_bios(profile):
        # Found by content: the name is an example, any image of the system works.
        system = system_name((profile.get("systems") or [""])[0])
        return (f"a {system} BIOS (example: {_code(fname)})" if _named_example(str(fname))
                else f"a {system} BIOS, any file name")
    return _code(fname)


@dataclass(frozen=True)
class CardLayout:
    """Where a file card lands. `alias` is a second id the card answers to,
    `data_href` links the data folder an app reads the entry under, from the
    page the card lands on. `badges_apart`: the title holds the name alone,
    for a table whose Status column shows the badges (sitegen/entries.py)."""

    alias: str = ""
    data_href: str = "#data-folder"
    badges_apart: bool = False


_CARD_LAYOUT = CardLayout()


def _card_place_details(f: dict, profile: dict, owner: str, data_href: str) -> list[str]:
    """Where the file goes and how the code finds it."""
    details = []
    fname = f.get("name", "")
    fpath = f.get("path", "")
    fsystem = f.get("system", "")
    # Where the app reads it under its data folder, said beside the path:
    # Ryujinx's card read "Path: system/prod.keys" with no root.
    place = standalone_place(owner, profile, f) if owner else ""
    under = f", in [the data folder]({data_href})"
    standalone_path = f.get("standalone_path", "")
    if (fpath and fpath != fname) or (place and place == fpath):
        details.append(f"Path: `{fpath}`" + (under if place and place == fpath else ""))
    if standalone_path and standalone_path != fpath:
        # The standalone build reads it elsewhere: MesenCE's dsp1.rom goes
        # under Firmware/, and a page naming only the core's path sent its
        # users to the wrong folder.
        details.append(f"Standalone path: `{standalone_path}`"
                       + (under if place == standalone_path else ""))
    read_from = _load_from_text(f.get("load_from"))
    if read_from:
        details.append(f"Read from: {read_from}")
    found = _found_by_text(f.get("found_by"))
    if found:
        details.append(f"Found by: {found}")
    if fsystem:
        details.append(f"System: {_named_system_link(fsystem, '../')}")
    return details


def _card_size_details(f: dict) -> list[str]:
    """The size, with its bounds."""
    size = f.get("size")
    fmin = f.get("min_size")
    fmax = f.get("max_size")
    # Where the code compares the size, the exact bytes: raze tells three
    # DUKE3D.GRP apart by size, all three shown as 42.3 MB.
    sized = _exact_size if "size" in _validation_names(f.get("validation", [])) else _fmt_size
    bounds = []
    if fmin:
        bounds.append(f"min {sized(fmin)}")
    if fmax:
        bounds.append(f"max {sized(fmax)}")
    if size:
        if isinstance(size, list):
            size_str = " / ".join(sized(s) for s in size)
        else:
            size_str = sized(size)
        if bounds:
            size_str += f" ({', '.join(bounds)})"
        return [f"Size: {size_str}"]
    if bounds:
        return [f"Size: {', '.join(bounds)}"]
    return []


def _card_hash_details(f: dict) -> list[str]:
    """Every declared hash."""
    details = []
    fsha1 = f.get("sha1", "")
    fmd5 = f.get("md5", "")
    fcrc32 = f.get("crc32", "")
    fsha256 = f.get("sha256", "")
    fadler32 = f.get("known_hash_adler32", "")
    # Starlight folds the hashes and gives each a copy button.
    copyable = markup.starlight()
    if fsha1:
        details.append(f"SHA1: {_hash_spans(fsha1, copyable)}")
    if fmd5:
        details.append(f"MD5: {_hash_spans(fmd5, copyable)}")
    if fcrc32:
        crcs = fcrc32 if isinstance(fcrc32, list) else [fcrc32]
        details.append("CRC32: " + ", ".join(
            markup.hash_value(crc, True) if copyable else f"`{crc}`" for crc in crcs))
    if fsha256:
        details.append(f"SHA256: {_hash_spans(fsha256, copyable)}")
    if fadler32:
        # Printed as the downloads spell a hash, one per code span: the list
        # repr read `['0x66f334fe', ...]`. Dolphin hashes its DSP ROMs over
        # byte-swapped 16-bit words, so the raw Adler-32 the downloads carry
        # for the same file differs, and the card says which one it lists.
        values = fadler32 if isinstance(fadler32, list) else [fadler32]
        shown = ", ".join(_code(str(v).lower().removeprefix("0x")) for v in values)
        if f.get("adler32_byteswap"):
            details.append(
                f"Adler32 over the file's 16-bit words byte-swapped: {shown} "
                "(the Adler-32 in the downloads is the file's own and differs)"
            )
        else:
            details.append(f"Adler32: {shown}")
    return details


def _validation_lines(validation: object) -> list[str]:
    """The checks the code runs, one line, or one line per build."""
    if isinstance(validation, list):
        return [f"Validation: {', '.join(validation)}"]
    if isinstance(validation, dict):
        return [f"Validation ({scope}): {', '.join(checks)}" for scope, checks in validation.items()]
    return []


def _card_reading_details(f: dict, profile: dict) -> list[str]:
    """How the code reads the file, on which setups, and where it asks for it."""
    details = []
    aliases = f.get("aliases", [])
    priority = f.get("priority")
    fast_boot = f.get("fast_boot")
    validation = f.get("validation", [])
    source_ref = f.get("source_ref", "")
    if aliases:
        details.append(f"Aliases: {', '.join(f'`{a}`' for a in aliases)}")
    if priority is not None:
        details.append(f"Priority: {priority}")
    if fast_boot is not None:
        details.append(f"Fast boot: {'yes' if fast_boot else 'no'}")
    if validation:
        details.extend(_validation_lines(validation))
    details.extend(_on_mismatch_lines(f.get("on_mismatch")))
    if f.get("installed_on"):
        details.append("Installed by the platform's own package on: "
                       + ", ".join(sorted(f["installed_on"])))
    if f.get("not_bundled_on"):
        details.append("Not in the platform's package, so the pack brings it, on: "
                       + ", ".join(sorted(f["not_bundled_on"])))
    if f.get("unread_on"):
        details.append("Never opened on these platforms, whose launcher names other files: "
                       + ", ".join(sorted(f["unread_on"])))
    if source_ref:
        asker = requested_by(profile, source_ref)
        if asker:
            # A profile reading a libretro core and the original emulator
            # cited both trees alike: readers could not tell which code asks
            # for the file.
            details.append(f"Asked for by: {asker}")
        details.append(
            f"Source: {_source_ref_markdown(profile, source_ref)}"
        )
    return details


def _card_copy_line(
    f: dict, consumers: FileConsumers, held: str, sha1: str, in_repo: bool, details: list[str],
) -> list[str]:
    """Which collection copy answers the entry. `details` are the lines said
    before, read for copies already named."""
    parts = held.split("/")
    if len(parts) >= 3 and parts[0] == "bios" and f.get("archive"):
        return [_held_copy_line((held, f["name"]), consumers)]
    if len(parts) >= 3 and parts[0] == "bios":
        # Which copy answers this entry, linked to its collection card
        # (provenance, every hash, download): an entry declaring no hash
        # said "in repo" without naming the file.
        page = card_page(held, sha1)
        return [
            f"Collection copy: [{_code(held)}]"
            f"(../systems/{urllib.parse.quote(page)}.md#sha1-{sha1[:12]})"
        ]
    if in_repo and not any(d.startswith("Collection copies:") for d in details):
        copy = held_copy(f)
        if copy:
            return [_held_copy_line(copy, consumers)]
    return []


def _card_copy_details(
    f: dict, profile: dict, consumers: FileConsumers | None, owner: str, in_repo: bool,
    details: list[str],
) -> list[str]:
    """The collection copy that answers the entry and the setups that list
    it. `details` are the lines said before."""
    if not consumers:
        return []
    added = []
    if f.get("type") == "directory":
        added.extend(_directory_copies(f, consumers))
    sha1 = consumers.sha1_of(
        *entry_target(f, profile.get("files") or []), owner=owner)
    held = consumers.path_of(sha1) if sha1 and in_repo else ""
    added.extend(_card_copy_line(f, consumers, held, sha1, in_repo, details + added))
    plat_links = _platform_links(sha1, consumers) if sha1 else []
    if plat_links and markup.starlight():
        # Grouped by where the setups put the file, as the system card
        # says it: twelve setups repeating scph5502.bin took twelve
        # names and twelve paths where a few say it. One sentence a
        # place: a list or a line break was one more element a place.
        places = _places_markdown(_platform_places(sha1, consumers))
        added.append("Platforms: " + ". ".join(places))
    elif plat_links:
        added.append(f"Platforms: {', '.join(plat_links)}")
    return added


def _card_extra_details(f: dict) -> list[str]:
    """The remaining optional fields, one line each."""
    details = []
    fname = f.get("name", "")
    fpath = f.get("path", "")
    dest = f.get("dest", f.get("destination", ""))
    config_key = f.get("config_key", "")
    fpattern = f.get("pattern", "")
    region_check = f.get("region_check")
    size_note = f.get("size_note", "")
    size_range = f.get("size_range", "")
    if dest and dest != fname and dest != fpath:
        details.append(f"Destination: `{dest}`")
    if config_key:
        details.append(f"Config key: `{config_key}`")
    if fpattern:
        details.append(f"Pattern: `{fpattern}`")
    if region_check is not None:
        details.append(f"Region check: {'yes' if region_check else 'no'}")
    if size_note:
        details.append(f"Size note: {size_note}")
    if size_range:
        details.append(f"Size range: {size_range}")
    return details


def _card_heading(f: dict, profile: dict, in_repo: bool, anchor: str, layout: CardLayout) -> list[str]:
    """The card's opening: its title with the badges, then the description."""
    lines: list[str] = []
    fsystem = f.get("system", "")
    desc = f.get("description", "")
    # melonDS reads DS and DSi files: "required" alone sat on the DSi NAND
    # above the DS files, for an emulator most people run for DS games.
    for_system = (system_name(str(fsystem))
                  if fsystem and len(profile.get("systems") or []) > 1 else "")
    badges = _file_badges(f, in_repo, for_system)
    badge_str = " ".join(badges)
    lines.append(markup.block_open("div", 'class="rb-file-entry"'))
    lines.append("")
    marker = f'<span id="{layout.alias}"></span>' if layout.alias else ""
    label = _entry_label(f, profile)
    title = f"{marker}{label}" if layout.badges_apart else f"{marker}{label} {badge_str}"
    lines.append(_card_title(title, anchor, weight=5))
    lines.append("")
    if desc:
        lines.extend([data_root_words(_escape_tags(str(desc)), layout.data_href), ""])
    return lines


def _render_emulator_file(
    f: dict,
    profile: dict,
    consumers: FileConsumers | None,
    files: list,
    _file_available: Callable[[dict], bool],
    anchor: str = "",
    owner: str = "",
    layout: CardLayout = _CARD_LAYOUT,
) -> list[str]:
    """Render one row of an emulator profile's file table.

    `anchor` is the card's id on the page, so one file can be cited by URL,
    and `layout` says where the card lands (CardLayout).

    Split out of generate_emulator_page, where it was a 228-line loop body
    carrying most of that function's branching: thirty-odd optional fields,
    each with its own badge, hash line or note.
    """
    in_repo = _file_available(f)
    fnote = f.get("note", f.get("notes", ""))
    contents = f.get("contents", [])
    data_href = layout.data_href

    lines = _card_heading(f, profile, in_repo, anchor, layout)
    body_start = len(lines)

    details = _card_place_details(f, profile, owner, data_href)
    details.extend(_card_size_details(f))
    details.extend(_card_hash_details(f))
    details.extend(_card_reading_details(f, profile))
    details.extend(_card_copy_details(f, profile, consumers, owner, in_repo, details))
    details.extend(_card_extra_details(f))

    if markup.starlight():
        lines.extend(_emulator_card_folds(f, details, fnote, profile, in_repo, contents,
                                          data_href))
        lines.extend(["", "</div>", ""])
        return lines
    lines.extend(f"- {d}" for d in details)
    if fnote:
        lines.append(f"- {data_root_words(_escape_tags(link_prose_citations(profile, str(fnote))), data_href)}")
    if not in_repo and f.get("unsourceable"):
        lines.append(f"- {_unsourceable_line(f)}")
    lines.extend(_contents_lines(contents))
    lines[body_start:] = _search_skipped_apart(lines[body_start:])
    lines.append("")
    lines.append("</div>")
    lines.append("")
    return lines


def _contents_lines(contents: list) -> list[str]:
    """Every member with the hashes the emulator checks: MAME and FBNeo
    verify the members, never the archive, so a member's crc32 is the
    value a reader compares a set against."""
    if not contents:
        return []
    lines = [f"- Contents ({len(contents)} members):"]
    for c in contents:
        if isinstance(c, dict):
            parts = []
            if c.get("description"):
                parts.append(_escape_tags(str(c["description"])))
            if c.get("size"):
                parts.append(_fmt_size(c["size"]))
            if c.get("crc32"):
                parts.append(f"CRC32 `{c['crc32']}`")
            if c.get("sha1"):
                parts.append(f"SHA1 `{c['sha1']}`")
            extra = f": {', '.join(parts)}" if parts else ""
            lines.append(f"    - `{c.get('name', '')}`{extra}")
        else:
            lines.append(f"    - {c}")
    return lines


# What an emulator card shows at a glance: where the file goes, how big it
# is, which setups list it and which copy answers it. Fingerprints and the
# reading details open on demand.
_ENTRY_KEY_FACTS = ("Path:", "Standalone path:", "Read from:", "Found by:", "System:",
                    "Size:", "Aliases:", "Collection copy:", "Collection copies:",
                    "Platforms", "Destination:")
_ENTRY_HASHES = ("SHA1:", "MD5:", "CRC32:", "SHA256:", "Adler32")
# The words the fold of an emulator card names its facts by.
_ENTRY_MORE_WORDS = (
    ("Priority", "priority"), ("Fast boot", "fast boot"), ("Validation", "validation"),
    ("On a failed", "failed check"), ("Installed by the platform's own package", "packages"),
    ("Not in the platform's package", "packages"), ("Never opened", "unread setups"),
    ("Asked for by", "source"), ("Source", "source"), ("Config key", "config key"),
    ("Pattern", "pattern"), ("Region check", "region check"), ("Size note", "size note"),
    ("Size range", "size range"),
)


def _more_words(lines: list[str]) -> list[str]:
    """The words a fold names its facts by, once each, in their order."""
    words: list[str] = []
    for line in lines:
        text = re.sub(r"<[^>]+>", "", line.removeprefix("- "))
        word = next((w for prefix, w in _ENTRY_MORE_WORDS if text.startswith(prefix)),
                    text.split(":", 1)[0].lower())
        if word not in words:
            words.append(word)
    return words


def _short_hash_line(f: dict) -> str:
    """The entry's strongest declared hash, cut to SHORT_HASH characters,
    with a copy button for the whole value. "" when it declares none."""
    from core.hashing import parse_hash_list

    for field, label in (("sha1", "SHA1"), ("md5", "MD5"), ("sha256", "SHA256"), ("crc32", "CRC32")):
        values = parse_hash_list(f.get(field) or "")
        if values:
            value = str(values[0])
            more = f" and {len(values) - 1} more" if len(values) > 1 else ""
            return (f'{label}: <span class="rb-hash" data-copy="{html.escape(value)}">'
                    f"{html.escape(value[:SHORT_HASH])}</span>{more}")
    return ""


def _emulator_card_folds(
    f: dict, details: list[str], fnote: object, profile: dict, in_repo: bool,
    contents: list, data_href: str,
) -> list[str]:
    """An emulator card's body under Starlight: the key facts and the notes
    open, the hashes and the rest in one closed fold.

    Lines the search reads and lines it skips are kept in two runs: mixed,
    each change of side was one more list and one more block, five lists
    on a card of a dozen lines.
    """
    def skipped(line: str) -> bool:
        return f"- {line}".startswith(SEARCH_SKIPPED)

    key = [d for d in details if d.startswith(_ENTRY_KEY_FACTS)]
    hashes = [d for d in details if d.startswith(_ENTRY_HASHES)]
    more = [d for d in details if d not in key and d not in hashes]
    short = _short_hash_line(f)
    shut_open = [d for d in key if skipped(d)]
    sized = next((i for i, d in enumerate(shut_open) if d.startswith("Size:")), None)
    if short and sized is not None:
        # On the size's line: what tells this dump from another, one list
        # item fewer on each card.
        shut_open[sized] += ", " + short.replace(": ", " ", 1)
    elif short:
        shut_open.insert(0, short)
    # What the search reads first, the notes included, then what it skips:
    # one list each.
    open_lines = [d for d in key if not skipped(d)]
    if fnote:
        open_lines.append(data_root_words(
            _escape_tags(link_prose_citations(profile, str(fnote))), data_href))
    if not in_repo and f.get("unsourceable"):
        open_lines.append(_unsourceable_line(f))
    lines = [f"- {d}" for d in open_lines]
    shut_fold = [f"- {d}" for d in hashes + [m for m in more if skipped(m)]]
    read_fold = [f"- {m}" for m in more if not skipped(m)]
    # The members of an archive, a list of their own under the fold's
    # summary, which counts them: a "Contents" item holding them was two
    # more elements and 44 bytes on each of 200 MAME cards.
    members = [f"* {line.removeprefix('    - ')}" for line in _contents_lines(contents)[1:]]
    fold: list[str] = []
    if shut_fold or read_fold or members:
        words = (["hashes"] if hashes else []) + _more_words(
            [line for line in shut_fold + read_fold if not line.startswith(
                tuple(f"- {h}" for h in _ENTRY_HASHES))])
        words = words if len(words) <= 3 else [*words[:3], "more"]
        if members:
            words.append(_count(len(members), "member"))
        hidden_part = [*shut_fold, "", *members] if members else shut_fold
        body = (hidden_part if not read_fold else [
            "", markup.block_open("div", f'class="rb-search-skip" {markup.search_exclude()}'),
            "", *hidden_part, "", "</div>", "", *read_fold])
        fold = card_fold(_listed_words(words), body, skip=False)
    # A fold the search skips whole sits in the skipped block before it, with
    # no attribute of its own: on a page of 200 MAME cards the attribute, the
    # class and a block each were 12 KB.
    hidden = bool(fold) and not read_fold
    shut = [f"- {d}" for d in shut_open] + (["", *fold] if hidden else [])
    if shut:
        lines += ["", markup.block_open("div", f'class="rb-search-skip" {markup.search_exclude()}'),
                  "", *shut, "", "</div>", ""]
    if fold and not hidden:
        lines += ["", *fold, ""]
    return lines


def _held_copy_line(copy: tuple[str, str], consumers: FileConsumers) -> str:
    """Where a copy the database does not index sits: a ZIP member under
    bios/, or a file or tree of a data directory the packs fetch."""
    path, member = copy
    parts = path.rstrip("/").split("/")
    if member:
        archive = _code(path)
        zsha1 = consumers.sha1_at(path)
        if zsha1 and len(parts) >= 3 and parts[0] == "bios":
            page = urllib.parse.quote(card_page(path, zsha1))
            archive = f"[{archive}](../systems/{page}.md#sha1-{zsha1[:12]})"
        return f"Collection copy: member {_code(member)} of {archive}"
    if parts[0] == "data" and len(parts) >= 2:
        ref, inside = parts[1], "/".join(parts[2:])
        if path.endswith("/"):
            where = _code(inside + "/") if inside else "the tree"
            return f"Collection copy: {where} in the {_code(ref)} data directory"
        info = (_DATA_MEMBERS.get(ref) or {}).get(inside) or {}
        shown = _code(inside)
        if info.get("sha1"):
            shown = (f'<a href="../../files/?sha1={info["sha1"]}">'
                     f"<code>{html.escape(inside)}</code></a>")
        return f"Collection copy: {shown} in the {_code(ref)} data directory"
    tree = f"{REPO_URL}/tree/main/{urllib.parse.quote(path.rstrip('/'))}"
    return f"Collection copy: [{_code(path)}]({tree})"


def _directory_copies(entry: dict, consumers: FileConsumers) -> list[str]:
    """What the collection holds under a directory entry, and where.

    The card said "in repo" and linked none of the files: alephone's
    Plugins/ holds 393 of them, each with its own card on a system page.
    """
    members = consumers.directory_members(entry)
    held = sorted({consumers.path_of(sha1) for sha1 in members.values()} - {""})
    if not held:
        return []
    folder = os.path.commonpath(held) if len(held) > 1 else os.path.dirname(held[0])
    parts = folder.split("/")
    where = _code(folder + "/")
    if len(parts) >= 3 and parts[0] == "bios":
        where = f"[{where}]({console_href(_slug(parts[1]), parts[2], '../')})"
    tree = f"{REPO_URL}/tree/main/{urllib.parse.quote(folder)}"
    return [f"Collection copies: {_count(len(members), 'file')} under {where} "
            f"([browse]({tree}))"]


_MAME_RELEASE = re.compile(r"^0\.\d")


def emulator_romset(profile: dict) -> str:
    """The romset an arcade emulator's sets must match, "MAME 0.78", or "".

    ``mame_version`` where the profile has one (MAME4droid 2024 is app
    1.38.1 on MAME 0.289), else the version of a MAME build or of a
    FinalBurn core, whose sets follow its own release.
    """
    if profile.get("type") in ("alias", "launcher") or profile.get("role") == "test":
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
        return f"[{_code(str(text))}]({url})" if url else _code(str(text))

    if kind == "file":
        return f"{value}, stated in {shown(basis.get('path'))}"
    if kind == "tag":
        distance = int(basis.get("distance") or 0)
        if not distance:
            return f"{value}, the tag at this revision"
        return f"{value}, {distance} commit{'s' if distance != 1 else ''} after tag {shown(basis.get('tag'))}"
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


ARCHIVE_RECIPES_PAGE = Path(WIKI_SRC_DIR) / "archive-recipes.md"
_ARCHIVE_BLOCK = re.compile(
    r"(<!-- generated: archive-recipes -->\n)(.*?)(<!-- /generated: archive-recipes -->)", re.S)


def archive_recipe_lines(counts: dict[str, int]) -> list[str]:
    """What an exact and a canonical rebuild are, each with its count."""
    total = f"{counts['total']:,}"
    return [
        f"- **Exact**: the same bytes as the archive in the collection."
        f" {counts['exact']:,} of {total} archives.",
        f"- **Canonical**: the same files inside, packed another way."
        f" {counts['canonical']:,} of {total} archives.",
    ]


def with_archive_counts(page: str, counts: dict[str, int]) -> str:
    """The archive recipes page with its counts read from recipes/archives.json."""
    block = "\n".join(archive_recipe_lines(counts)) + "\n"
    if not _ARCHIVE_BLOCK.search(page):
        raise ValueError(f"{ARCHIVE_RECIPES_PAGE}: no archive-recipes block to write the counts in")
    return _ARCHIVE_BLOCK.sub(lambda m: f"{m.group(1)}{block}{m.group(3)}", page, count=1)


def _render_metadata_rows(profile: dict) -> list[str]:
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
            lines.append(f"| {label} | {_code(val)}, inside the app's own data folder |")
        elif field == "bios_size" and isinstance(val, int):
            lines.append(f"| {label} | {_fmt_size(val)} ({val:,} bytes) |")
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
                lines.append(f"| Data folder ({_OS_LABELS[key]}) | "
                             f"{_under_root(str(root['path']), '')} |")
    if profile.get("source_ref"):
        lines.append(
            f"| Source ref | {_source_ref_markdown(profile, profile['source_ref'])} |"
        )
    return lines


# Data directory members and revisions, read once per build.
_DATA_MEMBERS: dict[str, dict[str, dict]] = {}


def any_name_bios(profile: dict) -> dict | None:
    """The one BIOS an emulator needs under any name, or None.

    A profile found by content (`found_by: content`, `bios_mode: agnostic`)
    for one system, with one required file of no declared region: the
    code identifies the image by what it holds, so the entry's name is an
    example. AetherSX2's page showed `bios/ps2-0230a-20080220.bin` as the
    file to get, while its notes say no name and no hash is matched.
    """
    if profile.get("found_by") != "content" and profile.get("bios_mode") != "agnostic":
        return None
    if len(profile.get("systems") or []) != 1:
        return None
    required = [f for f in profile.get("files") or []
                if isinstance(f, dict) and f.get("required") is True and not comes_with_app(f)]
    if len(required) != 1 or required[0].get("region") or required[0].get("category") not in (None, "bios"):
        return None
    return required[0]


def _named_example(name: str) -> bool:
    """A real file name, not a placeholder such as `<bios>.bin`."""
    return bool(name) and "<" not in name


def _unsourceable_line(f: dict) -> str:
    """Why the collection holds no copy of a file a profile marks
    `unsourceable:`, linked to the list of them. The flag only keeps a
    same-named file from being served in its place: the file is still
    wanted, and "Not collectable" sent readers away from KANJI2.ROM, which
    MAME's fm7740sx.zip carries."""
    return (f"Not collected yet: {_escape_tags(str(f['unsourceable']))} "
            "([files not collected yet](../gaps.md#not-collected-yet))")
