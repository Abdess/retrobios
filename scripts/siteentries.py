"""Long lists as one filterable table, each row opening to its details.

MAME's card pages read 13,000 to 16,000 words, one card after another,
before a reader found the archive they came for. Here each entry is one
row: its name, the facts that tell rows apart, and the full card in a
closed block under the name. The table is written as HTML so the block can
hold the card's Markdown. It carries what rehype-stack-tables.mjs gives a
Markdown table: `data-rb-stack` (one block per row on a phone) and the
filter box above, which site.ts wires. Without JavaScript the rows show and
every block opens. A closed block stays in the page, so the browser's find
and the site search still reach every name it holds.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field

import sitemarkup as markup

# rehype-stack-tables.mjs RECORD_ROWS: from this many rows a table has a
# filter box, and its stacked labels are written by site.ts, not the build.
RECORD_ROWS = 20
# filterPlaceholder in rehype-stack-tables.mjs: the column names offered.
PLACEHOLDER_COLUMNS = 4


@dataclass
class Row:
    """One entry: ``title`` is the inline HTML of its name (a heading, so
    the site search lands on it), ``body`` the Markdown lines shown when the
    row opens, ``cells`` the HTML of the other columns."""

    title: str
    body: list[str]
    cells: list[str] = field(default_factory=list)


def filter_placeholder(labels: list[str]) -> str:
    """"File, contents, status..." as rehype-stack-tables.mjs words it."""
    words = [label for label in labels if label][:PLACEHOLDER_COLUMNS]
    if not words:
        return "Type to filter..."
    lowered = [word if index == 0 or not (word[:1].isupper() and word[1:2].islower())
               else word[0].lower() + word[1:] for index, word in enumerate(words)]
    return f"{', '.join(lowered)}..."


def filter_box(ident: str, heading: str, labels: list[str], rows: int, noun: str = "rows") -> str:
    """The filter box rehype-stack-tables.mjs writes above a long table.

    It is `hidden` until site.ts wires it: without the script it filters
    nothing, so a reader with no JavaScript, a text dump and the search
    skip it while the rows stay. retrobios.css keeps its room meanwhile,
    so the table does not move when it shows. The count is the input's
    description, and spaces keep label, field and count apart in any text
    read from the HTML."""
    return (
        f'<div class="rb-table-filter" hidden {markup.search_exclude()}>'
        f'<label for="{ident}">Filter {html.escape(heading)}</label> '
        f'<input id="{ident}" type="search" autocomplete="off" '
        f'placeholder="{html.escape(filter_placeholder(labels))}" aria-describedby="{ident}-count"> '
        f'<span id="{ident}-count" class="rb-table-filter-count" aria-live="polite">'
        f"{rows:,} {noun}</span></div>"
    )


def card_title_and_body(card: list[str]) -> tuple[str, list[str]]:
    """A card's heading line and the lines under it, its wrapping block
    (the first line and the last closing tag) taken off."""
    title_at = next(index for index, line in enumerate(card) if line.startswith("<h3"))
    closing = max(index for index, line in enumerate(card) if line.strip() == "</div>")
    body = card[title_at + 1:closing]
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    return card[title_at], body


def entry_table(rows: list[Row], heads: list[str], ident: str, heading: str,
                stacked: list[str] | None = None,
                searched: frozenset[str] = frozenset()) -> list[str]:
    """``rows`` under ``heads`` (the first names the column of titles).

    ``stacked`` gives a column's short label on a phone, as a header's
    `title` does in a Markdown table. A column every row leaves empty
    (``""``) is not written. The site search skips every column but the
    titles and those ``searched`` names: a count or a short hash is no word
    anyone types.
    """
    keep = [0] + [column for column in range(1, len(heads))
                  if any(row.cells[column - 1] for row in rows)]
    labels = [heads[c] for c in keep]
    short = [(stacked or heads)[c] for c in keep]
    skip = markup.search_exclude()
    # The block holds the box and the table: an open card spans its width.
    lines = ["", '<div class="rb-entries-wrap">']
    if len(rows) >= RECORD_ROWS:
        lines.append(filter_box(ident, heading, labels, len(rows)))
    lines.append('<table class="rb-entries" data-rb-stack="true">')
    head_cells = ""
    for label, name in zip(labels, short):
        title = f' title="{html.escape(name)}"' if name != label else ""
        head_cells += f'<th scope="col"{title}>{html.escape(label)}</th>'
    lines.extend(["<thead>", f"<tr>{head_cells}</tr>", "</thead>", "<tbody>"])
    for row in rows:
        lines.append("<tr>")
        if row.body:
            lines.extend(["<td>", '<details class="rb-entry">', f"<summary>{row.title}</summary>",
                          "", *row.body, "", "</details>", "</td>"])
        else:
            lines.append(f"<td>{row.title}</td>")
        for column in keep[1:]:
            label = (f' data-label="{html.escape(short[keep.index(column)])}"'
                     if len(rows) < RECORD_ROWS else "")
            ignored = "" if heads[column] in searched else f" {skip}"
            lines.append(f"<td{label}{ignored}>{row.cells[column - 1] or '-'}</td>")
        lines.append("</tr>")
    lines.extend(["</tbody>", "</table>", "</div>", ""])
    return lines
