"""A system file's card: its places, facts, hashes and romset lines."""

from __future__ import annotations

import functools
import html
import re
import sys
import urllib.parse
import zipfile
from collections.abc import Callable

from core.hashing import parse_hash_list
from model.collection import profiles_on_disk
from packs.crossref import FileConsumers
from romrecipes.romsets import dat_snapshots, usable_recipe
from sitegen import markup, wanted as sitewanted
from core.paths import REPO_ROOT
from sitegen.fields import search_excluded
from sitegen.install import manifest_systems, platform_display
from sitegen.render import code_span, count_text, system_page_map, emulator_card_page


def emulator_file_anchors(files: list[dict]) -> list[str]:
    """The id of each file card on an emulator page, in profile order.

    An entry that declares a hash is addressed by it: its anchor depends on
    its own content, never on the entries beside it, and a second version
    added under the same path moves nothing. An entry without one keeps
    its plain anchor when its path is declared once, and otherwise takes
    its size, else, when even the size is shared, its description. The
    page and its JSON-LD both read this, so a structured part links to its
    card. The plain anchor of a hashed card stays reachable through
    emulator_file_aliases.
    """
    bases = [
        "file-" + (
            re.sub(
                r"[^a-z0-9]+", "-",
                str(f.get("path") or f.get("standalone_path") or f.get("name", "")).lower(),
            ).strip("-") or "entry"
        )
        for f in files
    ]
    repeated = {b for b in bases if bases.count(b) > 1}

    def _version_key(f: dict) -> str:
        digest = _first_hash_value(f)
        if digest:
            return digest[:8]
        return f"{f['size']}b" if f.get("size") else ""

    keys = [
        (b, _version_key(f)) if b in repeated or _first_hash_value(f) else (b, "")
        for f, b in zip(files, bases)
    ]
    used: dict[str, int] = {}
    anchors = []
    for f, (base, key) in zip(files, keys):
        anchor = f"{base}-{key}" if key else base
        if keys.count((base, key)) > 1 and f.get("description"):
            described = re.sub(r"[^a-z0-9]+", "-", str(f["description"]).lower()).strip("-")
            anchor = f"{anchor}-{described[:40].strip('-')}"
        used[anchor] = used.get(anchor, 0) + 1
        if used[anchor] > 1:
            anchor = f"{anchor}-{used[anchor]}"
        anchors.append(anchor)
    return anchors


PROVENANCE_LABELS = {"redump": "Redump", "no-intro": "No-Intro", "tosec": "TOSEC"}


# TOSEC dump flags that say the dump is not a clean copy of the chip
# (TOSEC Naming Convention, "Dump info flags"); [a] alternate and [!]
# verified good are not among them.
_TOSEC_BAD_FLAGS = {
    "b": "bad dump", "o": "overdump", "h": "hacked", "cr": "cracked",
    "f": "fixed", "t": "trained", "p": "pirate",
}
_TOSEC_FLAG_RE = re.compile(r"\[(b|o|h|cr|f|t|p)\d*(?:\s[^\]]*)?\]")


def _dump_flags(source: str, data: dict) -> list[str]:
    """What a catalog's name says is wrong with the dump, as words."""
    if source != "tosec":
        return []
    name = str(data.get("name") or data.get("description") or "")
    seen: list[str] = []
    for flag in _TOSEC_FLAG_RE.findall(name):
        word = _TOSEC_BAD_FLAGS[flag]
        if word not in seen:
            seen.append(word)
    return seen


def _provenance_lines(provenance: dict, prefix: str) -> list[str]:
    """One visible line per catalog: its badge and the entry's own name.

    The name was only a title attribute, unreadable on a touch screen and
    absent from the search for 793 of 803 provenances, and a TOSEC entry
    flagged [b] or [o] wore the same green badge as a clean dump.
    """
    lines: list[str] = []
    for source, data in sorted(provenance.items()):
        label = PROVENANCE_LABELS.get(source, source)
        flags = _dump_flags(source, data)
        kind = "rb-badge-warning" if flags else "rb-badge-success"
        badge = f'<span class="rb-badge {kind}">[{label}]({prefix}provenance.md#{source})</span>'
        name = str(data.get("name") or data.get("description") or "")
        line = f"- Catalogued: {badge} {code_span(name)}" if name else f"- Catalogued: {badge}"
        if flags:
            line += f" ({', '.join(flags)}, as {label} records it)"
        lines.append(line)
    return lines


ROMSET_SOURCES = {"mame": "MAME", "fbneo": "FBNeo"}


_RELEASE_ASSET_NAMES: dict[str, str] | None = None


def _download_name(path: str) -> str:
    """The name a browser saves a collection file under: the last segment
    of its download URL. Neither host sends a Content-Disposition, and the
    download attribute is ignored on another origin."""
    return urllib.parse.unquote(fetch_url(path).rsplit("/", 1)[-1])


def fetch_url(path: str) -> str:
    """Where a collection file downloads from: its raw URL, or the
    large-files release asset when .gitignore keeps it out of git."""
    global _RELEASE_ASSET_NAMES
    if _RELEASE_ASSET_NAMES is None:
        from model.largefiles import asset_names, asset_url, load_registered_paths, published_asset_name

        _RELEASE_ASSET_NAMES = {
            registered: asset_url(published_asset_name(name))
            for registered, name in asset_names(load_registered_paths()).items()
        }
    return _RELEASE_ASSET_NAMES.get(path) or (
        "https://raw.githubusercontent.com/Abdess/retrobios/main/"
        + urllib.parse.quote(path)
    )


# A setup, the link to its page, and where it puts the file.
Place = tuple[str, str, list[str]]


def platform_places(sha1: str, consumers: FileConsumers) -> list[Place]:
    """Each platform declaring the file, linked to its system section, with
    the destination it gives the file."""
    systems_of = getattr(consumers, "platform_systems", {}).get(sha1, {})
    destinations_of = getattr(consumers, "platform_destinations", {}).get(sha1, {})
    places: list[Place] = []
    for platform in consumers.platforms.get(sha1, ()):
        section = sorted(systems_of.get(platform, ()))
        fragment = f"#{section[0].replace(' ', '-')}" if section else ""
        places.append((platform_display(platform), f"../platforms/{platform}.md{fragment}",
                       sorted(destinations_of.get(platform, ()))))
    return sorted(places, key=lambda place: place[0].casefold())


def platform_links(sha1: str, consumers: FileConsumers) -> list[str]:
    """Each platform declaring the file, as Markdown: its name, linked to
    its system section, then the destination it gives the file."""
    return [
        f"[{name}]({href})" + (": " + ", ".join(code_span(d) for d in dests) if dests else "")
        for name, href, dests in platform_places(sha1, consumers)
    ]


_card_anchors: dict[str, tuple[list, list[str]]] = {}


def emulator_card_anchor(emulator: str, files: list, index: int) -> str:
    """The id of a profile entry's card on its emulator page."""
    cached = _card_anchors.get(emulator)
    if cached is None or cached[0] is not files:
        cached = _card_anchors[emulator] = (files, emulator_file_anchors(files))
    return cached[1][index] if 0 <= index < len(cached[1]) else ""


def wanted_link(profiles: dict) -> Callable[[str, str, dict], str]:
    """The page a row of the wanted list links: an emulator entry's card,
    where its notes, hashes and source line are, else the setup's page."""
    def link(kind: str, key: str, entry: dict) -> str:
        files = (profiles.get(key) or {}).get("files") or [] if kind == "emulator" else []
        index = next((i for i, f in enumerate(files) if f is entry), -1)
        anchor = emulator_card_anchor(key, files, index) if index >= 0 else ""
        if anchor:
            return f"emulators/{emulator_card_page(key, anchor)}/#{anchor}"
        return sitewanted.reader_page(kind, key, entry)
    return link


def _emulator_links(sha1: str, consumers: FileConsumers) -> list[str]:
    """Each emulator reading the file, linked to the entry that reads it.

    The platform links landed on their system section, and the emulator
    links on the page top: duckstation's scph5501.bin entry, with the line
    that accepts it, sat 260 lines down a page of 105 entries.
    """
    entries = getattr(consumers, "emulator_entries", {}).get(sha1, {})
    files_of = getattr(consumers, "emulator_files", {})
    links = []
    # By the name the emulator's page carries: 19,499 card links read
    # melonds_ds where its page says melonDS DS.
    named = sorted(((emulator_display(e), e) for e in consumers.emulators.get(sha1, ())),
                   key=lambda pair: (pair[0].casefold(), pair[1]))
    for display, emulator in named:
        index = entries.get(emulator)
        anchor = (emulator_card_anchor(emulator, files_of[emulator], index)
                  if index is not None and emulator in files_of else "")
        page = emulator_card_page(emulator, anchor) if anchor else emulator
        fragment = f"#{anchor}" if anchor else ""
        # The card's facts are raw HTML: "Game & Watch" is escaped, and a
        # bracket would end the link the facts are parsed from.
        text = html.escape(display, quote=False).replace("[", "&#91;").replace("]", "&#93;")
        links.append(f"[{text}](../emulators/{page}.md{fragment})")
    return links


def _installed_places(sha1: str, consumers: FileConsumers, declared: set[str]) -> list[Place]:
    """Each pack installing the file that its platform's list does not name,
    with the place the pack gives it."""
    places = [
        (platform_display(platform), f"../platforms/{platform}.md", sorted(d for d in dests if d))
        for platform, dests in getattr(consumers, "installed", {}).get(sha1, {}).items()
        if platform not in declared
    ]
    return sorted(places, key=lambda place: place[0].casefold())


def _places_lines(places: list[Place]) -> list[str]:
    """Setups grouped by where they put the file, one line per place:
    "`scph5501.bin`: Batocera, EmuDeck". Each setup repeating the name
    took five lines where one says it. A setup that names no place (EmuDeck
    matches by MD5) is listed on a line of its own, last."""
    def plain(text: str) -> str:
        return html.escape(text, quote=False).replace("`", "&#96;")

    by_place: dict[tuple[str, ...], list[str]] = {}
    for name, href, dests in places:
        by_place.setdefault(tuple(dests), []).append(f"[{name}]({href})")
    ordered = sorted(by_place.items(), key=lambda item: (not item[0], -len(item[1]), item[0]))
    return [
        (" and ".join(f"<code>{plain(d)}</code>" for d in dests) + ": " if dests else "")
        + ", ".join(links)
        for dests, links in ordered
    ]


def places_markdown(places: list[Place]) -> list[str]:
    """_places_lines in Markdown, for a card written as a list: the places
    as code spans, which the glossary and the line breaks treat as code."""
    by_place: dict[tuple[str, ...], list[str]] = {}
    for name, href, dests in places:
        by_place.setdefault(tuple(dests), []).append(f"[{name}]({href})")
    ordered = sorted(by_place.items(), key=lambda item: (not item[0], -len(item[1]), item[0]))
    return [(" and ".join(code_span(d) for d in dests) + ": " if dests else "") + ", ".join(links)
            for dests, links in ordered]


def _inline_card_html(text: str) -> str:
    """A card value written in Markdown (code spans, links), as the HTML a
    fact list holds. HTML already in the value is kept."""
    out: list[str] = []
    for part in re.split(r"(`[^`]*`)", text):
        if len(part) > 1 and part.startswith("`") and part.endswith("`"):
            out.append(f"<code>{html.escape(part[1:-1], quote=False)}</code>")
        else:
            out.append(re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', part))
    return "".join(out)


# A link icon, the way a heading anchor is drawn: the word "permalink" was
# read as part of every card title, by the search and by screen readers.
# Drawn once per page and used by each card: inline, its 400 bytes were
# 100 KB on the Sony page.
PERMALINK_SYMBOL = (
    '<svg aria-hidden="true" style="display:none"><symbol id="rb-link-icon" '
    'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/>'
    '<path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></symbol></svg>'
)
_PERMALINK_ICON = ('<svg aria-hidden="true" width="16" height="16">'
                   '<use href="#rb-link-icon"/></svg>')


def icon_symbol() -> list[str]:
    """The icon's drawing, for a page of cards. None in the yardstick."""
    return [PERMALINK_SYMBOL, ""] if markup.starlight() else []


RomsetMembers = tuple[tuple[str, str], ...]
# A release a recipe agrees with: its place among the imported releases of
# its source, and its name ("0.220", "1.0.0.03").
Release = tuple[int, str]


def _release_name(source: str, label: str, versions: dict) -> str:
    """"MAME mame0220" as "0.220", an FBNeo DAT title as its version."""
    match = re.fullmatch(r"MAME mame(\d)(\d+)", label) if source == "mame" else None
    return f"{match[1]}.{match[2]}" if match else str(versions.get(label) or label)


@functools.lru_cache(maxsize=1)
def _romset_snapshots() -> list[tuple[str, dict]]:
    return list(dat_snapshots(REPO_ROOT / "recipes"))


@functools.lru_cache(maxsize=1)
def romset_releases() -> dict[str, list[tuple[RomsetMembers, str, list[Release]]]]:
    """Archive name -> (members, source, the releases agreeing on them), from
    the MAME and FBNeo recipe snapshots under recipes/.

    A snapshot stores a recipe once for every version that agrees on it,
    so a match reads "this set's contents in those versions".
    """
    releases: dict[str, list[tuple[RomsetMembers, str, list[Release]]]] = {}
    for source, snapshot in _romset_snapshots():
        versions = snapshot.get("dats") or {}
        order = {label: index for index, label in enumerate(versions)}
        for entry in snapshot.get("entries") or []:
            recipe = usable_recipe(entry.get("members") or [])
            if not entry.get("name") or recipe is None:
                continue
            members = tuple(sorted(recipe))
            agreed = [(order.get(label, -1), _release_name(source, str(label), versions))
                      for label in entry.get("dats") or [entry.get("dat")]]
            releases.setdefault(str(entry["name"]), []).append((members, source, agreed))
    return releases


def _release_runs(releases: list[Release]) -> str:
    """Releases as runs of consecutive imports: "0.190 to 0.195, 0.220 to
    0.289". One FBNeo version shared by 15 DATs reads once."""
    runs: list[list[Release]] = []
    for release in sorted(set(releases)):
        if runs and release[1] == runs[-1][-1][1]:
            continue
        if runs and release[0] == runs[-1][-1][0] + 1:
            runs[-1].append(release)
        else:
            runs.append([release])
    return ", ".join(run[0][1] if len(run) == 1 else f"{run[0][1]} to {run[-1][1]}"
                     for run in runs)


def _source_order(source: str) -> tuple[bool, str]:
    return source != "mame", source


def _romset_line(f: dict) -> str:
    """Which MAME and FBNeo releases a collected archive's contents match.

    MAME and FBNeo check the members of an archive by CRC32, never its own
    bytes or its member names: a set works with a release when it holds
    every CRC32 the release's recipe lists, extra members or not. The
    main neogeo.zip, which every MAME from 0.177 to 0.289 loads, read "No
    match" when names had to agree and no member could be extra. Empty
    when no recipe names the archive or the file is not on disk.
    """
    recipes = romset_releases().get(str(f.get("name", "")))
    path = REPO_ROOT / str(f.get("path", ""))
    if not recipes or not path.is_file():
        return ""
    try:
        with zipfile.ZipFile(path) as archive:
            held = tuple(sorted((info.filename, f"{info.CRC:08x}")
                                for info in archive.infolist() if not info.is_dir()))
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"  WARNING: {path}: {exc}", file=sys.stderr)
        return ""
    crcs = {crc for _name, crc in held}
    same: dict[str, list[Release]] = {}
    holds: dict[str, list[Release]] = {}
    # source -> (fewest CRC32s missing, the latest release missing that many)
    closest: dict[str, tuple[int, Release]] = {}
    for members, source, agreed in recipes:
        missing = len({crc for _name, crc in members} - crcs)
        if members == held:
            same.setdefault(source, []).extend(agreed)
        elif not missing:
            holds.setdefault(source, []).extend(agreed)
        elif agreed:
            latest = max(agreed)
            best = closest.get(source)
            if best is None or (missing, -latest[0]) < (best[0], -best[1][0]):
                closest[source] = (missing, latest)

    def runs(found: dict[str, list[Release]], skip: dict[str, list[Release]]) -> str:
        return " and ".join(
            f"{ROMSET_SOURCES.get(source, source)} {_release_runs(kept)}"
            for source in sorted(found, key=_source_order)
            for kept in [[r for r in found[source] if r not in skip.get(source, [])]] if kept)

    said = []
    if same:
        said.append(f"Same contents as {runs(same, {})}")
    if holds and runs(holds, same):
        said.append(f"Holds every ROM of {runs(holds, same)}")
    if said:
        return ". ".join(said)
    if not closest:
        return f"No match in {_romset_coverage()}"
    return "No match: missing " + ", ".join(
        f"{count_text(missing, 'ROM')} of {ROMSET_SOURCES.get(source, source)} {release[1]}"
        for source, (missing, release) in sorted(closest.items(),
                                                 key=lambda item: _source_order(item[0])))


@functools.lru_cache(maxsize=1)
def _romset_coverage() -> str:
    """The releases the recipes cover: "MAME 0.190 to 0.289 or FBNeo 1.0.0.03"."""
    covered = {}
    for source, snapshot in _romset_snapshots():
        versions = snapshot.get("dats") or {}
        if versions:
            ends = [(index, _release_name(source, label, versions))
                    for index, label in enumerate(versions)]
            # The ends of the span, read as one run.
            span = [ends[0], (1, ends[-1][1])] if len(ends) > 1 else ends
            covered[source] = f"{ROMSET_SOURCES.get(source, source)} {_release_runs(span)}"
    return " or ".join(covered[source] for source in sorted(covered, key=_source_order))


ROMSET_FAQ = "../wiki/technical-faq.md#which-mame-version-do-the-arcade-bios-sets-match"


def system_file_card(
    f: dict, consumers: FileConsumers, anchored: set[str] | None = None,
    searchable: bool = True,
) -> list[str]:
    """One file of a system page: hashes, who reads it, its provenance.

    ``searchable`` false keeps even the name out of the site search: the
    asset trees of game engines hold thousands of 0.ogg and tile.png.
    """
    name = f["name"]
    sha1_full = f.get("sha1", "unknown")
    md5_full = f.get("md5", "unknown")
    # The size a card names is the file's own, exact: rounded, 44,348,015
    # and 44,356,548 bytes were one 42.3 MB.
    size = _card_size(int(f.get("size", 0)))
    # Who reads this file, not who reads a file of this name
    plats = sorted(consumers.platforms.get(sha1_full, ()))
    emus = sorted(consumers.emulators.get(sha1_full, ()))
    installed = _installed_places(sha1_full, consumers, set(plats))

    anchor = f"sha1-{sha1_full[:12]}" if sha1_full != "unknown" else ""
    # A copy filed under two consoles of one maker is listed twice on its
    # page: the first card holds the anchor, as an id names one element.
    if anchored is not None:
        if anchor in anchored:
            anchor = ""
        else:
            anchored.add(anchor)
    skip = markup.search_exclude()
    lines = [markup.block_open("div", 'class="rb-sys-file"'), ""]
    # The heading's own link is this page's, the icon is the file's own
    # address, resolved by content wherever its card moves.
    # The yardstick keeps the word, the size the page budget was set on.
    icon = _PERMALINK_ICON if markup.starlight() else "permalink"
    permalink = (
        f' <a class="rb-permalink" href="{markup.site_href(f"files/?sha1={sha1_full}")}" '
        f'aria-label="Permanent link to {html.escape(name)}" '
        f'title="Permanent link, by content" {skip}>{icon}</a>'
    ) if anchor else ""
    # A file nothing reads said so nowhere: 53 of 248 Sony cards had no
    # emulator, platform or pack line and looked unfinished.
    unread = (f' <span class="rb-badge rb-badge-muted" {skip}>No reader</span>'
              if not (emus or plats or installed) else "")
    # The download leads the card: as a "(download)" after the collection
    # path, fourth of the facts, a reader of the Apple II page found none.
    download = (
        f' <a class="rb-download" href="{html.escape(fetch_url(f["path"]))}" '
        f'aria-label="Download {html.escape(name)}" {skip}>Download</a>'
    ) if f.get("path") and markup.starlight() else ""
    lines.append(card_title(
        f'{code_span(name)} <span class="rb-badge rb-badge-muted">{size}</span>{unread}{download}{permalink}',
        anchor, searchable,
    ))
    lines.append("")

    # Each fact: its label, its values, whether the search reads it. What a
    # setup does with the file comes first, the fingerprints last.
    facts: list[tuple[str, list[str], bool]] = []
    saved = _download_name(f["path"]) if f.get("path") else name
    if saved != name:
        # A .variants/ copy is stored as advision.zip.1c086064, and the
        # browser names the download after the URL: copied as it came, the
        # file a platform pins was not found under its name.
        facts.append(("Save as", [f"{code_span(name)}, the download is named {code_span(saved)}"], False))
    if plats:
        # Each link lands on the platform's system section, and says where
        # that platform puts the file. Out of the search: the card's title
        # weighs the most a word can, and the list made the excerpt of
        # every card a run of setup names and paths.
        facts.append(("On the setup's list",
                      _places_lines(platform_places(sha1_full, consumers)), False))
    if installed:
        # The packs that carry the file for their cores: a RetroBat user
        # looking up scph5501.bin found every platform but RetroBat, whose
        # pack installs it for six cores.
        facts.append(("Packed for its emulators by", _places_lines(installed), False))
    if emus:
        facts.append(("Emulators", [", ".join(_emulator_links(sha1_full, consumers))], False))
    romset = _romset_line(f)
    if romset:
        # The version question every arcade player asks, answered from the
        # recipes: the cards named emulators and no release.
        facts.append(("Romset", [romset], False))
    if f.get("path"):
        # The card named a file, its hashes and provenance, but not where to
        # get it: a user missing scph5501.bin found the reference and no way
        # to the bytes.
        path = code_span(f["path"])
        if not markup.starlight():
            path += f" ([download]({fetch_url(f['path'])}))"
        facts.append(("Collection path", [path], False))
    catalogued = [line.split(": ", 1)[1]
                  for line in _provenance_lines(f.get("provenance") or {}, "../")]
    if catalogued:
        facts.append(("Catalogued", catalogued, False))
    # Every hash in full: the site search indexes text, not a title
    # attribute, so a pasted md5 or crc32 (what clrmamepro, RomVault or an
    # emulator log prints) found nothing behind a 12-character prefix.
    # files/?hash= finds them, and the index skips them.
    for label, value in (("SHA1", sha1_full), ("MD5", md5_full),
                         ("CRC32", f.get("crc32")), ("SHA256", f.get("sha256"))):
        if value and value != "unknown":
            # Starlight writes the value bare: its cell carries the hash
            # style and the copy button (_fact_list).
            shown = (html.escape(str(value)) if markup.starlight()
                     else f'<span class="rb-hash">{html.escape(str(value))}</span>')
            facts.append((label, [shown], False))

    if not markup.starlight():
        # The size yardstick pages are cut by: the list a card was when the
        # budget was set, so a fact grid moves no card to another page.
        lines.extend(search_excluded([f"- {label}: {', '.join(values)}"
                                      for label, values, _searched in facts]))
    else:
        lines.extend(_card_fact_groups(facts, sha1_full, searchable))
    lines.extend(["", "</div>", ""])
    return lines


# What a system card shows at a glance: who lists the file and who reads it.
# Its fingerprints and the rest open on demand, so a page of 250 cards reads
# as a list of files, not a wall of hashes.
_CARD_KEY_FACTS = ("Save as", "On the setup's list", "Packed for its emulators by", "Emulators")
_CARD_HASHES = ("SHA1", "MD5", "CRC32", "SHA256")
# The words a card's fold names its other facts by.
_CARD_MORE_WORDS = {"Romset": "romset", "Collection path": "collection path",
                    "Catalogued": "catalogues"}
# A hash shown short, in a card, a platform row or an emulator table: as long
# as the card's own address (sha1-<12 hex>), one length across the site.
SHORT_HASH = 12


def listed_words(words: list[str]) -> str:
    """"a", "a and b", "a, b and c", first letter capital."""
    text = words[0] if len(words) == 1 else f"{', '.join(words[:-1])} and {words[-1]}"
    return text[:1].upper() + text[1:]


def _fact_list(facts: list[tuple[str, list[str], bool]], skip: str,
               copy: dict[str, str] | None = None) -> list[str]:
    """Facts as a grid, label then value, one value cell per label.

    A label in *copy* holds one hash: its cell takes the hash style, and
    the site script a copy button (site.ts). *copy* gives the cell's
    classes. One element, where a span in the cell was one more per hash.
    """
    if not facts:
        return []
    copy = copy or {}

    def cell(label: str, values: list[str]) -> str:
        if label in copy:
            return f'<dd class="{copy[label]}">{values[0]}</dd>'
        return "<dd>" + "<br>".join(_inline_card_html(v) for v in values) + "</dd>"

    return [f'<dl class="rb-facts"{skip}>',
            *(f"<dt>{label}</dt>{cell(label, values)}" for label, values, _searched in facts),
            "</dl>"]


def card_fold(summary: str, body: list[str], skip: bool = True) -> list[str]:
    """A fold of a file card: closed, its summary naming what it holds.

    Native details: no script needed, and the text inside stays in the page
    (and in the search, unless *skip*). No class: the card styles its folds,
    and a class was 21 bytes on each of 250 cards."""
    attribute = f" {markup.search_exclude()}" if skip else ""
    summary_line = f"<summary>{html.escape(summary, quote=False)}</summary>"
    # Each tag on a line of its own, or MDX reads the fold as a paragraph
    # left open. Markdown inside also takes a blank line around it.
    gap = [] if body and body[0].startswith("<") else [""]
    return [f"<details{attribute}>", summary_line, *gap, *body, *gap, "</details>"]


def _card_fact_groups(facts: list[tuple[str, list[str], bool]], sha1: str,
                      searchable: bool) -> list[str]:
    """A system card's facts under Starlight: the key ones open, a short
    SHA1 first, then the hashes and the rest in one closed fold.

    The search skips all of them, as it did when they were one list: on
    each row the attribute was 77 KB of the Sony page. Hashes are found by
    files/?hash=, which the search box offers for a pasted hash.
    """
    skip = f" {markup.search_exclude()}"
    key = [fact for fact in facts if fact[0] in _CARD_KEY_FACTS]
    hashes = [fact for fact in facts if fact[0] in _CARD_HASHES]
    more = [fact for fact in facts if fact not in key and fact not in hashes]
    searched = [fact for fact in facts if fact[2] and searchable]
    lines: list[str] = []
    if searched:
        # No fact is searched today. One that is keeps its label out: the
        # excerpt ran the two together, "On the setup's listAmberELEC".
        lines += ['<dl class="rb-facts">',
                  *(f"<dt{skip}>{label}</dt><dd>"
                    + "<br>".join(_inline_card_html(v) for v in values) + "</dd>"
                    for label, values, _searched in searched),
                  "</dl>"]
        key = [fact for fact in key if fact not in searched]
        more = [fact for fact in more if fact not in searched]
    glance = []
    if sha1 and sha1 != "unknown":
        # The first characters, enough to tell two dumps apart at a glance.
        # Its button copies the whole value, read from the fold below: the
        # value twice was 54 bytes more on each card.
        glance.append(("SHA1", [html.escape(sha1[:SHORT_HASH])], False))
    lines += _fact_list(glance + key, skip, {"SHA1": "rb-hash"})
    # One fold: two were four more elements on each of 250 cards.
    folded = hashes + more
    if folded:
        words = (["hashes"] if hashes else []) + [
            _CARD_MORE_WORDS.get(label, label.lower()) for label, _values, _searched in more]
        # On one line: nothing reads it as Markdown, and a page cut by size
        # holds its cards in the same bytes.
        lines += card_fold(listed_words(words),
                           ["".join(_fact_list(folded, "", dict.fromkeys(_CARD_HASHES, "rb-hash")))])
    return lines


SEARCH_TABLE_BYTES = 3000


def tables_out_of_search(markdown: str, threshold: int = SEARCH_TABLE_BYTES) -> str:
    """Each table longer than ``threshold`` bytes, wrapped out of the search.

    A search result shows the start of a section: a 600-row table as one
    snippet helps nobody, and the gaps, provenance and cross-reference
    tables were 900 KB of the index. The headings above them stay.
    """
    lines = markdown.split("\n")
    out: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"( *)\|", lines[index])
        if not match:
            out.append(lines[index])
            index += 1
            continue
        indent = match.group(1)
        end = index
        while end < len(lines) and re.match(rf"{indent}\|", lines[end]):
            end += 1
        table = lines[index:end]
        if sum(len(line) for line in table) > threshold:
            out += ["", indent + markup.block_open("section", markup.search_exclude()), "",
                    *table, "", f"{indent}</section>", ""]
        else:
            out += table
        index = end
    return "\n".join(out)


# Card lines the site search leaves out. They list where a file goes and
# who cites it, links to other pages that index the same names, and they
# were 6.6 of the 24.7 MB the browser downloads and indexes before the first
# result. The name, the hashes, the entry's path and the notes stay
# searchable.
SEARCH_SKIPPED = (
    "- SHA1:", "- MD5:", "- CRC32:", "- SHA256:", "- Adler32", "- Size:",
    "- Validation", "- Priority:", "- Contents (",
    "- Platforms:", "- Source:", "- Asked for by:",
    "- Collection path:", "- Collection copy:", "- Collection copies:",
    "- Installed by the platform's own package on:",
    "- Not in the platform's package", "- Never opened on these platforms",
)


def search_skipped_apart(lines: list[str]) -> list[str]:
    """Card list lines, each run the search skips in a block of its own."""
    out: list[str] = []
    skipping = False
    for line in lines:
        skip = line.startswith(SEARCH_SKIPPED) or (skipping and line.startswith("    "))
        if skip and not skipping:
            out.extend(["", markup.block_open(
                "div", f'class="rb-search-skip" {markup.search_exclude()}'), ""])
        elif skipping and not skip:
            out.extend(["", "</div>", ""])
        skipping = skip
        out.append(line)
    if skipping:
        out.extend(["", "</div>", ""])
    return out


def card_title(text: str, anchor: str, searchable: bool = True, weight: int = 10) -> str:
    """A file card's heading, so the site search lands on the card.

    The search splits a page at its headings: a card titled in bold sent a
    pasted md5 to the top of a page of a hundred cards. Level 3, under
    the console or the Files heading: a level 4 after a level 2 skipped
    one for screen readers on 551 pages. The table of contents of a page
    of cards stops above it (sitegen/starlight.py), and a card without an
    anchor keeps the id the toc gives it.
    """
    if markup.starlight():
        # Raw HTML: the card links to itself already, and a Markdown heading
        # would add the engine's anchor link and icon to every card.
        title = re.sub(r"`([^`]+)`", lambda m: f"<code>{html.escape(m[1], quote=False)}</code>", text)
        ident = f' id="{anchor}"' if anchor else ""
        # A system page's card is the file's own page in all but name: its
        # title weighs the most a word can, so a file name typed in the
        # search finds the card before a guide that cites it as an example.
        # An emulator's card says who reads the file, and weighs half.
        search = f' data-pagefind-weight="{weight}"' if searchable else f" {markup.search_exclude()}"
        return f'<h3{ident} class="rb-file-title"{search}>{title}</h3>'
    attributes = f"#{anchor} .rb-file-title" if anchor else ".rb-file-title"
    if not searchable:
        attributes += " data-search-exclude"
    return f"### {text} {{ {attributes} }}"


def system_install_choices(coverages: dict) -> dict[str, dict[str, list[tuple[str, str]]]]:
    """slug -> console -> the (platform, system id) pairs linked to it.

    Read through the same table as every system link, so a command sits in
    the section the platform's system links to. Only a system the
    platform's install manifest records is offered: --system refuses any
    other name.
    """
    from sitegen.render import page_by_norm

    choices: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for name, cov in sorted(coverages.items()):
        recorded = manifest_systems(name)
        for sys_id in sorted(set(cov["config"].get("systems") or {}) & recorded):
            page = system_page_map.get(sys_id) or page_by_norm(sys_id)
            if page:
                slug, console = page
                choices.setdefault(slug, {}).setdefault(console, []).append((name, sys_id))
    return choices


def emulator_display(emulator: str) -> str:
    return str((profiles_on_disk().get(emulator) or {}).get("emulator") or emulator)


def _first_hash_value(entry: dict) -> str:
    """The first declared hash of an entry, lowercase, for a stable anchor."""
    for field in ("sha1", "md5", "crc32", "sha256"):
        values = parse_hash_list(entry.get(field))
        if values:
            return values[0]
    return ""


def _card_size(size: int) -> str:
    """A file's size, exact: in whole MB or KB when it is one, else in B."""
    for unit, scale in (("MB", 1024 * 1024), ("KB", 1024)):
        if size >= scale and size % scale == 0:
            return f"{size // scale:,} {unit}"
    return f"{size:,} B"
