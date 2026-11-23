"""A platform's file reference: each system's rows, roles and checks."""

from __future__ import annotations

import functools
import html
import json
import re
import urllib.parse

from model import siteinputs
from model.collection import profiles_in, profiles_on_disk
from model.database import load_database, sha1_at
from model.profiles import is_emulator, upstream_profile_index
from model.systemnames import system_name
from sitegen import entries as siteentries, markup
from sitegen.config import REPO_URL, date_line
from core.sizes import size_text
from sitegen.fields import hash_spans, search_excluded
from sitegen.parts import (
    PAGE_BYTES,
    PAGE_ELEMENTS,
    PLATFORM_PART_BUDGET,
    PLATFORM_REFERENCE_BUDGET,
    PLATFORM_SECTION_BUDGET,
    blocks_in_runs,
    character_count,
    parent_front_matter,
    part_links,
    part_stems,
)
from sitegen.render import (
    SHORT_HASH,
    card_anchor,
    code_span,
    count_text,
    emulator_link,
    escape_tags,
)
from sitegen.runlinks import card_page, console_href


def _collection_sha1(path: str) -> str:
    """The sha1 of the file the collection holds at a path."""
    return sha1_at(_collection_db(str(siteinputs.current().db)), path) or ""


@functools.cache
def _collection_db(db_path: str) -> dict:
    return load_database(db_path)


def _system_heading_link(sys_id: str, prefix: str = "") -> str:
    """A system's name, linked to its own console section when it has one.

    The id stays beside it in small text: it is what the platform's list
    writes. A system with no section of its own is named, never sent to the
    page a storage folder chose.
    """
    return f"{_system_named_link(sys_id, prefix)} <small>{escape_tags(sys_id)}</small>"


def _system_named_link(sys_id: str, prefix: str = "") -> str:
    """A system's name, linked to the section system_section gives."""
    from sitegen.runlinks import system_section

    name = escape_tags(system_name(sys_id))
    section = system_section(sys_id)
    if section is not None:
        slug, console = section
        name = f"[{name}]({console_href(slug, console, prefix)})"
    return name


def emulator_named_link(key: str, prefix: str = "") -> str:
    """An emulator by the name its page carries, linked to that page. A
    profile with no page (an alias, a test) is named only."""
    profile = profiles_on_disk().get(key, {})
    label = escape_tags(str(profile.get("emulator") or key))
    if not is_emulator(profile):
        return label
    return f"[{label}]({prefix}emulators/{key}.md)"


def _served_line(f: dict, declared_sha1: str = "") -> str:
    """Which collection file answers the entry, from the resolver's result.

    "OK" with no path gave an expert nothing to check: Batocera's
    scph1001.bin is served by bios/Sony/PlayStation/scph1001_v20.bin.
    The copy's sha1 is named only when it is not one the row already
    declares (Recalbox joins several with commas).
    """
    path = str(f.get("path") or "")
    if f.get("status") == "missing":
        return "Not held"
    if not path:
        # A slot the pack fills from a release asset or leaves to the user.
        return ""
    sha1 = _collection_sha1(path)
    label = "Served by" if f.get("status") == "ok" else "Held, not the declared hash"
    parts = path.split("/")
    if not sha1 or len(parts) < 3 or parts[0] != "bios":
        return f"{label}: {code_span(path)}"
    # The card of that copy: every hash, provenance and the download.
    page = urllib.parse.quote(card_page(path, sha1))
    link = f"{label}: [{code_span(path)}](../systems/{page}.md#{card_anchor(sha1)})"
    declared = {value.strip().lower() for value in declared_sha1.split(",")}
    return link if sha1 in declared else f"{link} (sha1 `{sha1[:8]}`)"


def _launcher_refs(config: dict) -> dict[str, list[str]]:
    """Entry name, casefolded -> each launcher record that opens it, rendered."""
    from resolve.launchers import record_names as launcher_names
    from resolve.launchers import bound_launchers
    from sitegen.sources import launcher_ref_markdown, list_source

    # Every scraper reads its launchers in the repository and at the revision
    # of the list it scrapes, so `source` pins each source_ref. A record a
    # config file does not prove opens nothing: it is listed apart.
    source = list_source(str(config.get("source") or ""))
    found: dict[str, list[str]] = {}
    for record in bound_launchers(config, _site_profiles()):
        if not isinstance(record, dict) or not record.get("source_ref"):
            continue
        text = (f"{escape_tags(str(record.get('emulator', '')))} at "
                f"{launcher_ref_markdown(source, str(record['source_ref']))}")
        for name in launcher_names(record):
            names = found.setdefault(name.rsplit("/", 1)[-1].casefold(), [])
            if text not in names:
                names.append(text)
    return found


UNPROVEN_TITLE = "Launcher records a config does not prove"


def launcher_unproven_section(config: dict) -> list[str]:
    """The platform's launcher records resting on a config the code does not prove.

    A config file is proof only when the code installing it and the code
    reading it are shown: these records place no file.
    """
    from resolve.launchers import launcher_unproven
    from sitegen.sources import launcher_ref_markdown, list_source

    rows = launcher_unproven({str(config.get("_key") or ""): config}, _site_profiles())
    if not rows:
        return []
    source = list_source(str(config.get("source") or ""))
    body = [
        f"- {escape_tags(row['emulator'])}, `{escape_tags(row['passes_to'] or row['kind'])}` "
        f"at {launcher_ref_markdown(source, row['source_ref'])}: "
        f"{escape_tags('; '.join(row['missing']))}"
        for row in rows
    ]
    return ["", *markup.details("note", f"{UNPROVEN_TITLE} ({len(rows)})", body)]


# The hash a row shows first, when the list does not say which it checks.
_ROW_HASHES = ("sha1", "md5", "sha256", "crc32")
# An untested entry whose reason is a hash the bytes do not match.
_OTHER_HASH = re.compile(r"hash|mismatch|expected|must match", re.IGNORECASE)
# A list this long gets a filter box above it, as a table of RECORD_ROWS
# rows does (website/src/plugins/rehype-stack-tables.mjs).
FILTER_ROWS = 20


def _status_chip(f: dict) -> str:
    """The row's status as a chip, its word and its colour saying the same. A
    declared hash the held copy does not have is "Other hash": the two differ,
    which says nothing of whose is right (a platform may pin its own bundle)."""
    status = f.get("status")
    if status == "ok":
        word, tone = "OK", "success"
    elif status == "missing":
        word, tone = "Missing", "danger"
    elif status == "untested":
        word = "Other hash" if _OTHER_HASH.search(str(f.get("reason") or "")) else "Untested"
        tone = "warning"
    else:
        word, tone = str(status), "muted"
    return f'<span class="rb-badge rb-badge-{tone}">{html.escape(word)}</span>'


def _copy_hash(algorithm: str, value: str | list) -> str:
    """A declared hash cut to SHORT_HASH characters on a button that copies
    it whole. A list of accepted values (Recalbox) copies its first. Outside
    a form a button submits nothing, so it carries no type."""
    from core.hashing import parse_hash_list

    values = parse_hash_list(value)
    if not values:
        return ""
    first = html.escape(values[0])
    more = f" +{len(values) - 1}" if len(values) > 1 else ""
    return (f'<button class="rb-copy" data-copy="{first}" '
            f'aria-label="Copy {algorithm.upper()} {first[:SHORT_HASH]}{more}">'
            f'{first[:SHORT_HASH]}{more}</button>')


# Characters Markdown or MDX would read inside the raw HTML of a row: an
# MDX page parses the text of its HTML as Markdown, a .md page does not.
_INERT = str.maketrans({"*": "&#42;", "_": "&#95;", "`": "&#96;", "[": "&#91;", "]": "&#93;"})
_INLINE_MD = re.compile(
    r"\[(?P<label>(?:`[^`]*`|[^\]`])+)\]\((?P<url>[^)\s]+)\)"
    r"|`(?P<code>[^`]+)`"
    r"|\*\*(?P<bold>[^*]+)\*\*"
)


def _text_html(text: str) -> str:
    """Plain text as HTML that neither Markdown nor MDX rewrites."""
    return html.escape(html.unescape(text), quote=False).translate(_INERT)


def _inline_html(markdown: str) -> str:
    """The inline Markdown of a row's evidence (links, code, bold) as HTML.

    Code spans become plain text and a linked path loses its code element:
    one per reference and per reader was the bulk of the elements of a
    platform page, and the words say the same without them.
    """
    out: list[str] = []
    position = 0
    for match in _INLINE_MD.finditer(markdown):
        out.append(_text_html(markdown[position:match.start()]))
        if match["url"]:
            out.append(f'<a href="{html.escape(match["url"])}">'
                       f'{_text_html(match["label"].replace("`", ""))}</a>')
        elif match["code"]:
            out.append(_text_html(match["code"]))
        else:
            out.append(f"<strong>{_text_html(match['bold'])}</strong>")
        position = match.end()
    out.append(_text_html(markdown[position:]))
    return "".join(out)


def _row_path(fname: str, cfg_entry: dict) -> str:
    """Where the file goes, when its name alone does not say: three GameCube
    IPL.bin differ only by GC/USA, GC/EUR and GC/JAP. A destination that is
    the name says nothing, and one that ends with it shows its folder."""
    destination = str(cfg_entry.get("destination") or "")
    if destination.endswith("/" + fname):
        return destination[:len(destination) - len(fname)]
    return "" if destination == fname else destination


def _platform_file_row(f: dict, cfg_entry: dict, hash_type: str = "",
                       launched: list[str] | None = None) -> str:
    """One file of a platform's list as one row, written as HTML.

    The row is a details element whose summary holds the name, the folder
    when there is one and the status, followed by the short hash on its copy
    button: a button cannot sit in a summary, which is itself a control.
    The details hold every hash the platform declares, the size, the copy
    that serves it and its readers, across the width of the list.
    """
    fname = f["name"]
    hashes = {
        "sha1": cfg_entry.get("sha1", f.get("sha1", "")),
        "md5": cfg_entry.get("md5", f.get("expected_md5", "")),
        # The crc32 is what System.dat and clrmamepro print. RetroDECK
        # declares sha256 too (dsifirmware.bin).
        "crc32": str(cfg_entry.get("crc32") or ""),
        "sha256": str(cfg_entry.get("sha256") or ""),
    }
    size = cfg_entry.get("size", f.get("size", 0))
    shown = next((alg for alg in (hash_type, *_ROW_HASHES) if alg in hashes and hashes[alg]), "")

    facts: list[str] = []
    # One code element per value: Recalbox lists accepted md5s joined by
    # commas, and each is a value a reader compares a dump with.
    facts.extend(f"{alg.upper()}: {hash_spans(hashes[alg])}"
                 for alg in ("sha1", "md5", "crc32", "sha256") if hashes[alg])
    # The size closes the hash lines: a line of its own was one more
    # element per row.
    if size and facts:
        facts[-1] += f" ({size_text(size)})"
    elif size:
        facts.append(f"Size: {size_text(size)}")
    if f.get("status") == "untested" and f.get("reason"):
        facts.append(_text_html(f"Not confirmed: {f['reason']}"))
    # Not every entry is firmware: the platform may list a game's data or a
    # file no core it runs opens.
    kind = {"game_data": "Game data, not firmware",
            "unread": "No core the platform runs opens it"}.get(f.get("category", ""))
    if kind:
        facts.append(kind)
    served = _served_line(f, str(hashes["sha1"] or ""))
    if served:
        facts.append(_inline_html(served))
    if f.get("category_evidence"):
        facts.append(_inline_html(_category_evidence_md(f["category_evidence"], launched)))

    path = _row_path(fname, cfg_entry)
    # Spaces between name, path and status: the summary lays them out as
    # columns, and the page text read "SVI603.ROMbios/Machines/...OK".
    summary = " ".join([_text_html(fname), *([f"<code>{_text_html(path)}</code>"] if path else []),
                        _status_chip(f)])
    copy = _copy_hash(shown, hashes[shown]) if shown else ""
    return (f'<details class="rb-file"><summary>{summary}</summary>'
            f'{"<br>".join(facts)}</details>{copy}')


def _platform_file_list(rows: list[str], has_path: bool, anchor: str) -> list[str]:
    """A system's rows as one HTML block, with a filter box when long.

    The list drops its path column when no row has one, so a blank cell
    never reads as missing data.
    """
    lines: list[str] = []
    if len(rows) >= FILTER_ROWS:
        lines += [siteentries.filter_box(f"rb-files-filter-{anchor}", "files",
                                         ["File", "path", "status", "hash"], len(rows)), ""]
    kind = "rb-files rb-files-path" if has_path else "rb-files"
    return [*lines, f'<div class="{kind}">', *rows, "</div>"]


# The elements a line puts on the page: its HTML tags, and the links and
# code spans of the Markdown before a list.
_ELEMENT = re.compile(r"<[a-zA-Z]|\]\(|`[^`]+`")


def _element_weight(lines: list[str]) -> int:
    """How many elements the lines render to."""
    return sum(len(_ELEMENT.findall(line)) for line in lines)


def _page_share(lines: list[str]) -> float:
    """The share of a page the lines render to, in thousandths: the rows
    are HTML already, so their length is their weight in bytes."""
    return max(_element_weight(lines) * 1000 / PAGE_ELEMENTS,
               character_count(lines) * 1000 / PAGE_BYTES)


def render_platform_systems(
    by_system: dict, config_files: dict, emulator_files: dict | None,
    platform: tuple[str, str] | None = None, moved: dict[str, str] | None = None,
    config: dict | None = None,
) -> list[str]:
    """One collapsible block per system, listing every file it needs.

    Split out of generate_platform_page: the block is most of that
    function's branching, since each file renders a different set of
    hashes, sizes and provenance depending on what the platform declares.
    With ``platform`` (its key and name) and ``moved``, a list longer than
    PLATFORM_SECTION_BUDGET goes to a page of its own, written into
    ``moved`` by stem, and the system's heading stays with a link to it.
    """
    lines: list[str] = []
    # Per-system detail sections (collapsible for large platforms)
    use_collapsible = len(by_system) > 10
    by_system_declared = declared_by_system(config_files)
    launched = _launcher_refs(config or {})

    sections: list[dict] = []
    for sys_id, files in sorted(by_system.items()):
        ok_count = sum(1 for f in files if f["status"] == "ok")
        total = len(files)

        sys_emus = system_emulators(sys_id, emulator_files, by_system_declared.get(sys_id))
        anchor = sys_id.replace(" ", "-")
        head = [f"{ok_count}/{total} files verified"]
        if sys_emus:
            emu_links = ", ".join(emulator_named_link(e, "../") for e in sorted(sys_emus))
            head[-1] += "\\"
            head.append(f"Emulators: {emu_links}")
        head.append("")

        # One row per file, the evidence in its details. The sort is stable,
        # so same-named entries keep the order verify reported them in,
        # which is the declaration order.
        rows: list[str] = []
        has_path = False
        seen_names: dict[str, int] = {}
        for f in sorted(files, key=lambda x: x["name"]):
            fname = f["name"]
            declared = config_files.get((sys_id, fname), [])
            nth = seen_names.get(fname, 0)
            seen_names[fname] = nth + 1
            cfg_entry = declared[nth] if nth < len(declared) else {}
            has_path = has_path or bool(_row_path(fname, cfg_entry))
            rows.append(_platform_file_row(
                f, cfg_entry, str((config or {}).get("hash_type") or ""),
                launched.get(fname.rsplit("/", 1)[-1].casefold())))
        body = head + _platform_file_list(rows, has_path, anchor)

        # Measured in the share of a page the list renders to.
        size = _page_share(body)
        if use_collapsible:
            status_tag = "OK" if ok_count == total else count_text(total - ok_count, "issue")
            block = markup.details("note", f"{count_text(total, 'file')} ({status_tag})", body)
            while block and not block[-1]:
                block.pop()
        else:
            block = body
        sections.append({"sys_id": sys_id, "anchor": anchor, "head": head, "rows": rows,
                         "has_path": has_path, "block": block,
                         "size": size, "total": total, "ok": ok_count})

    # A list longer than its budget goes to a page of its own, then the
    # largest lists until the page's reference fits PLATFORM_REFERENCE_BUDGET:
    # with each file's served copy and pinned readers, Batocera's 97 systems
    # rendered 785 KB of HTML on one page.
    own_page: set[str] = set()
    if moved is not None and platform:
        own_page = {sec["sys_id"] for sec in sections if sec["size"] > PLATFORM_SECTION_BUDGET}
        kept = sum(sec["size"] for sec in sections if sec["sys_id"] not in own_page)
        for sec in sorted(sections, key=lambda sec: -sec["size"]):
            if kept <= PLATFORM_REFERENCE_BUDGET:
                break
            if sec["sys_id"] not in own_page:
                own_page.add(sec["sys_id"])
                kept -= sec["size"]

    for sec in sections:
        sys_id, anchor = sec["sys_id"], sec["anchor"]
        total, ok_count = sec["total"], sec["ok"]
        # Every system is a heading with the same anchor in both layouts:
        # emulator cards link here, and the site search splits a page at its
        # headings. Folded into blocks under one heading, every hash pasted
        # in the search led to the systems overview of a 100-block page.
        lines.append(f"### {_system_heading_link(sys_id, '../')} {{ #{anchor} }}")
        lines.append("")
        if moved is not None and platform and sys_id in own_page:
            key, display = platform
            runs = [sec["head"] + _platform_file_list(run, sec["has_path"], anchor)
                    for run in blocks_in_runs([[row] for row in sec["rows"]],
                                               PLATFORM_PART_BUDGET, _page_share)]
            stems = part_stems(f"{key}-{anchor}", len(runs))
            for n, (stem, run) in enumerate(zip(stems, runs), 1):
                part = f" (part {n} of {len(runs)})" if len(runs) > 1 else ""
                # A console query landed here with no way to the console's
                # own page: the list says whose it is first, linked.
                moved[stem] = "\n".join([
                    "---", *parent_front_matter((display, f"/platforms/{key}/")), "---", "",
                    f"# {display}: {system_name(sys_id)}{part}", "",
                    f"{display}'s list for {_system_named_link(sys_id, '../')}. "
                    f"Part of the [{display} page]({key}.md#{anchor}), whose other systems "
                    f"are listed there. Each file below is as {display} declares it, with "
                    "its status in the pack.",
                    *(["", part_links(stems, stem)] if len(runs) > 1 else []),
                    "", "## Files", "", *markup.details("note", ROLE_LEGEND_TITLE, [ROLE_LEGEND]),
                    *search_excluded(run),
                    "", date_line(),
                ]) + "\n"
            # The count and status a folded system shows in its summary,
            # linked to the page that lists the files.
            tag = "OK" if ok_count == total else count_text(total - ok_count, "issue")
            count = f"{count_text(total, 'file')} ({tag})"
            lines.extend([
                f"[{count}]({stems[0]}.md)" if len(stems) == 1 else f"{count}: " + part_links(stems),
                "",
            ])
            continue
        # The section's heading stays searchable, its file list with every
        # hash is the lookup's: retrodeck's arcade list was 495 KB of index.
        lines.extend(search_excluded(sec["block"]))

    return lines


# Platforms with an updated file published by export_native.py.
EXPORTED: set[str] = set()


def platform_data_links(name: str) -> str:
    """The platform's own data, machine-readable: the YAML transcribed from
    its upstream list, this page's JSON and the manifest the installer reads.

    An emulator page linked its YAML and JSON, a platform page nothing: a
    tool had to download all twelve platforms in platforms.json and filter.
    """
    links = [
        f"[YAML]({REPO_URL}/blob/main/platforms/{name}.yml)",
        f"[JSON](../api/v1/platforms/{name}.json)",
    ]
    if (siteinputs.manifests_dir() / f"{name}.json").is_file():
        # The site's own copy, byte for byte (publish_manifests).
        links.append(f"[install manifest](../api/v1/manifests/{name}.json)")
        # The installed BIOS folder for clrmamepro and RomVault.
        links.append(f"[DAT](../downloads/dat/{name}.dat)")
    return ", ".join(links)


def _site_profiles() -> dict[str, dict]:
    """Every emulator profile, read once for the citations of a page."""
    return profiles_in(str(siteinputs.current().emulators), skip_aliases=True)


# Whose code a source reference cites, in one word: a platform page names
# each role once in ROLE_LEGEND. Written after every reference, "(emulator
# code, libretro port)" ran through Batocera's 14,000 words.
ROLE_WORDS = {
    "libretro glue": "glue",
    "emulator code, libretro port": "port",
    "upstream emulator": "upstream",
    "this build": "build",
}
ROLE_LEGEND_TITLE = "Source reference words"
ROLE_LEGEND = (
    "In a file's details, a word before its source references says whose code they are. "
    "**glue** means libretro glue, **port** means emulator code in the libretro port, "
    "**upstream** means the upstream emulator and **build** means this build's own code."
)


def _refs_by_role(profile: dict, value: str | dict | None) -> str:
    """A source_ref's parts grouped by whose code they cite, each role named
    once by its ROLE_WORDS word: `glue a.c:1, b.c:2 and port c.c:3`."""
    from sitegen.sources import source_ref_items

    texts = []
    for label, items in source_ref_items(profile, value):
        by_role: dict[str, list[str]] = {}
        for part, role in items:
            by_role.setdefault(role, []).append(part)
        text = " and ".join(
            (f"{ROLE_WORDS.get(role, role)} " if role else "") + ", ".join(parts)
            for role, parts in by_role.items())
        texts.append(f"**{label}:** {text}" if label else text)
    return ", ".join(texts)


def _category_evidence_md(evidence: dict, launched: list[str] | None = None) -> str:
    """What establishes an entry's category, as the page shows it.

    ``launched`` holds the platform's launcher records that open the entry,
    already rendered: "(by launcher)" alone named no record and no line.
    """
    if evidence.get("read_by"):
        groups: dict[bool, list[str]] = {True: [], False: []}
        bare: list[str] = []
        profiles = _site_profiles()
        for reader in evidence["read_by"]:
            # Pinned links, the repository named in words: the refs were
            # plain code with the role word ("source") left in front.
            profile = profiles.get(reader["emulator"], {})
            refs = [
                (f"`{e['name']}` at {_refs_by_role(profile, e['source_ref'])}"
                 if e.get("source_ref") else f"`{e['name']}`")
                + (" (by name)" if e.get("by") == "name" else "")
                for e in reader.get("entries", [])
            ]
            if reader["emulator"] == "launcher":
                name = "the platform's launcher"
                refs = list(launched or [])
            else:
                name = emulator_link(reader["emulator"], "../")
            groups[bool(reader.get("runs_system"))].append(
                f"{name} ({', '.join(refs)})" if refs else f"{name} (by {reader['proof']})")
            if not reader.get("runs_system"):
                # A launcher record is this platform's own code: kept whole.
                bare.append(f"{name} ({', '.join(refs)})"
                            if reader["emulator"] == "launcher" and refs else name)
        if not groups[True]:
            return "Read by " + ", ".join(groups[False])
        text = "Read by " + ", ".join(groups[True])
        # Cores of other systems that share the name: named, not cited, as
        # their lines describe another machine's file.
        if bare:
            text += ", also named by " + ", ".join(bare)
        return text
    examined = evidence.get("cores_examined") or []
    # A core the site gives no page (a test core) is named, not linked.
    with_page = _profiles_with_page(str(siteinputs.current().emulators))
    cores = ("cores examined: " + ", ".join(
        emulator_link(c, "../") if c in with_page else c for c in examined)
             if examined else "no core examined")
    if evidence.get("unsettled"):
        return f"No reader found, not settled: {evidence['unsettled']} ({cores})"
    return f"No reader found ({cores})"


def _profiles_by_core_name() -> dict[str, list[str]]:
    """Core name as a platform writes it -> the profiles with a page for it.

    MinUI writes `mednafen_vb`, the profile and its page are `beetle_vb`.
    """
    return _core_names_in(str(siteinputs.current().emulators))


@functools.cache
def _profiles_with_page(emulators_dir: str) -> frozenset[str]:
    """The profiles the site writes a page for: no alias, no test core."""
    profiles = profiles_in(emulators_dir, skip_aliases=True)
    return frozenset(
        k for k, v in profiles.items() if is_emulator(v)
    )


@functools.cache
def _core_names_in(emulators_dir: str) -> dict[str, list[str]]:
    profiles = profiles_in(emulators_dir, skip_aliases=True)
    with_page = _profiles_with_page(emulators_dir)
    return {
        core: sorted(k for k in keys if k in with_page)
        for core, keys in upstream_profile_index(profiles).items()
    }


def _core_name_links(cores: list[str]) -> list[str]:
    """A link per core to its profile page, the bare name where none exists."""
    index = _profiles_by_core_name()
    links: list[str] = []
    for core in cores:
        keys = [core] if core in index.get(core, []) else index.get(core, [])
        if keys:
            links.extend(emulator_link(k, "../") for k in keys)
        else:
            links.append(f"`{core}`")
    return links


def core_folders_section(name: str, config: dict) -> list[str]:
    """Each folder the frontend hands a core, and the files the pack puts in it.

    For a platform that names no file of its own (MinUI and its forks): the
    folders come from its launch scripts, the files from its install manifest.
    """
    folders = config.get("core_system_dirs") or {}
    manifest = siteinputs.manifests_dir() / f"{name}.json"
    files = json.loads(manifest.read_text())["files"] if manifest.is_file() else []
    lines = [
        "### Core folders",
        "",
        "Each folder below is the one the frontend gives that core. The pack "
        "puts the files the core reads there.",
        "",
        "| Folder | Cores | Files |",
        "|--------|-------|-------|",
    ]
    for folder, info in sorted(folders.items()):
        held = sorted(
            f["dest"][len(folder) + 1:] for f in files
            if f.get("dest", "").startswith(folder + "/")
        )
        cores = ", ".join(_core_name_links(info.get("cores", [])))
        shown = ", ".join(f"`{n}`" for n in held) if held else "none needed"
        lines.append(f"| `{folder}/` | {cores} | {shown} |")
    lines.append("")
    return lines


def declared_by_system(config_files: dict) -> dict[str, list[dict]]:
    """The platform's own entries of each system, hashes included."""
    by_system: dict[str, list[dict]] = {}
    for (sys_id, _name), entries in config_files.items():
        by_system.setdefault(sys_id, []).extend(entries)
    return by_system


def system_emulators(
    sys_id: str, emulator_files: dict | None, files: list[dict] | None = None
) -> list[str]:
    """The emulators a platform runs for one of its systems.

    A platform can group machines no profile names as one system: RetroArch
    files NAOMI and Atomiswave as sega-dreamcast-arcade, the Enterprise 64
    and 128 as enterprise-64-128. When no system id matches, the emulators
    are the ones that read a file the system lists, by its name. A member of
    an archive does not count: fbneo's boot.bin is read inside bubsys.zip,
    and RomM's Dreamcast boot.bin is not that file.
    """
    from model.systems import norm_system_id

    norm = norm_system_id(sys_id)
    by_id = [name for name, data in (emulator_files or {}).items()
             if sys_id in data["systems"] or norm in data["norm"]]
    if by_id or not files:
        return by_id
    names = {str(f.get("name", "")).lower() for f in files} - {""}
    return [name for name, data in (emulator_files or {}).items()
            if names & data.get("names", set())]
