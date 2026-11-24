"""An emulator page's data directories and the pages their file lists go to."""

from __future__ import annotations

from core.sizes import size_text
from core.text import series
from sitegen import markup
from sitegen.config import date_line, yaml
from sitegen.fields import search_excluded
from sitegen.lookup import data_directory_origin, data_tree_pages
from sitegen.pageregistry import PageRegistry
from sitegen.parts import part_front_matter
from sitegen.render import card_anchor, code_span, count_text, escape_tags
from sitegen.sources import source_ref_markdown


def _data_member_table(members: dict[str, dict], names: list[str], anchors: set[str]) -> list[str]:
    """A data directory's files with their size and sha1, each sha1 an
    anchor the first time the page lists it (``anchors``, the page's ids)."""
    table = ["| File | Size | SHA1 |", "|------|-----:|------|"]
    for member in names:
        info = members[member]
        sha1 = str(info.get("sha1", ""))
        # One id per page: two members can hold the same bytes (every empty
        # file), and Dolphin's trees share Sys.
        anchor = card_anchor(sha1)
        span = "" if anchor in anchors else f'<span id="{anchor}"></span>'
        anchors.add(anchor)
        table.append(f"| {span}{code_span(member)} | {size_text(int(info.get('size', 0)))} | {code_span(sha1)} |")
    return table


def _data_tree_page(ref: str, entry: dict, pages: list[tuple[str, list[str]]],
                    index: int, registry: PageRegistry) -> str:
    """One page of a large data directory's file list."""
    stem, names = pages[index]
    members = registry.data_members.get(ref) or {}
    part = f" (part {index + 1} of {len(pages)})" if len(pages) > 1 else ""
    read_by = series([f"[{escape_tags(display)}]({key}.md#data-directories)"
                             for key, display in registry.data_readers.get(ref, [])])
    # A file list out of the search: "dolphin" found three parts of the
    # dolphin-sys tree, on their title, before the Dolphin page.
    front: dict = {"level": "reference", "search": "exclude"}
    # The reader the tree is named after (dolphin for dolphin-sys), else
    # the first by name.
    readers = registry.data_readers.get(ref) or []
    owner = max(readers, default=None,
                key=lambda reader: len(reader[0]) if ref.startswith(f"{reader[0]}-") else 0)
    if owner:
        head = part_front_matter(
            (owner[1], f"{owner[0]}.md"),
            [(f"The {ref} data directory, part {n}", f"{other}.md")
             for n, (other, _names) in enumerate(pages, 1)], index, front)
    else:
        head = ["---", yaml.safe_dump(front, sort_keys=False, allow_unicode=True).rstrip("\n"),
                "---", ""]
    lines = [
        *head,
        f"# The {ref} data directory{part}", "",
        f"{entry.get('description') or 'A data directory'}: "
        f"{count_text(len(members), 'file')}, as the packs ship them."
        + (f" Read by {read_by}." if read_by else ""), "",
    ]
    if len(pages) > 1:
        lines.extend([", ".join(f"[part {i}]({other}.md)" if other != stem else f"part {i}"
                                for i, (other, _names) in enumerate(pages, 1)), ""])
    lines.extend(search_excluded(_data_member_table(members, names, set())))
    lines.extend(["", date_line()])
    return "\n".join(lines) + "\n"


def _data_directory_lines(
    dd: dict, profile: dict, data_registry: dict | None, member_anchors: set[str],
    registry: PageRegistry,
) -> tuple[list[str], dict[str, str]]:
    """One data directory: what it holds, where it comes from, which build
    reads it, and the pages its member list went to."""
    lines: list[str] = []
    part_pages: dict[str, str] = {}
    ref = dd.get("ref", "")
    dest = dd.get("destination", "")
    entry = (data_registry or {}).get(ref, {})
    # An empty destination wrote "``", which opened a code span
    # running to the next one and hid a link from the MDX pass.
    line = f"- `{ref}` > `{dest}`" if dest else f"- `{ref}`"
    if entry.get("description"):
        line += f": {entry['description']}"
    lines.append(line)
    lines.extend(f"    - {line}" for line in data_directory_origin(
        entry, registry.data_revisions.get(ref) or {}))
    if dd.get("mode"):
        lines.append(f"    - Read by the {dd['mode']} build only")
    if dd.get("bundled"):
        lines.append("    - Installed with the emulator, so packs leave it out")
    if dd.get("source_ref"):
        lines.append(f"    - Source: {source_ref_markdown(profile, dd['source_ref'])}")
    members = registry.data_members.get(ref) or {}
    tree_pages = data_tree_pages(ref, members)
    if tree_pages:
        where = (f"[a page of their own]({tree_pages[0][0]}.md)" if len(tree_pages) == 1
                 else "pages of their own: " + ", ".join(
                     f"[part {i}]({stem}.md)" for i, (stem, _names) in enumerate(tree_pages, 1)))
        lines.append(f"    - {count_text(len(members), 'file')}, listed on {where}")
        for index, (stem, _names) in enumerate(tree_pages):
            part_pages[stem] = _data_tree_page(ref, entry, tree_pages, index, registry)
    elif members:
        table = _data_member_table(members, sorted(members), member_anchors)
        lines.append("")
        lines.extend(markup.details(
            "info", f"{count_text(len(members), 'file')}, as the packs ship them",
            table, indent="    "))
    return lines, part_pages


def data_directories_section(
    profile: dict, data_dirs: list[dict], data_registry: dict | None, registry: PageRegistry,
) -> tuple[list[str], dict[str, str]]:
    """The Data directories section, and the pages its member lists went to."""
    # The member tables are a file list with hashes: out of the search,
    # dolphin, primehack and ishiiruka each put 210 KB of it there.
    trees: list[str] = []
    part_pages: dict[str, str] = {}
    member_anchors: set[str] = set()
    # Each tree with what it holds, where it comes from, which build reads
    # it and the code that does: these trees put thousands of files in
    # the packs, and the page said only `dolphin-sys` > `Sys`.
    for dd in data_dirs:
        lines, pages = _data_directory_lines(dd, profile, data_registry, member_anchors, registry)
        trees.extend(lines)
        part_pages.update(pages)
    trees.append("")
    # The member tables are the lookup's.
    return ["## Data directories", "", *search_excluded(trees)], part_pages
