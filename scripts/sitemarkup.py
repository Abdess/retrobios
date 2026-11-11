"""The page constructs the generator writes, in the syntax of the site engine.

Every block that is not plain Markdown (a callout, a collapsible block, OS
tabs, a button, a card grid) is written through one of these functions, so
the generator holds no engine syntax of its own. Bodies are passed without
indentation: the function indents them as the engine reads them.

The site is built with Astro Starlight. The MkDocs Material syntax the site
was first written in stays as one thing only: the yardstick of the size
budgets that split long pages (system pages, platform sections). Those
budgets were set on that Markdown, and measuring it keeps every page cut
at the same file, so no card changes address.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterator
from contextlib import contextmanager

ENGINES = ("mkdocs", "starlight")
_engine = "starlight"

# Material's callout kinds, by the role Starlight gives them.
ASIDE_ROLES = {
    "note": "note", "info": "note", "abstract": "note", "example": "note",
    "question": "note", "quote": "note", "tip": "tip", "success": "tip",
    "warning": "caution", "failure": "danger", "danger": "danger", "bug": "danger",
}

# The attribute that keeps an element out of the site search.
SEARCH_EXCLUDE = {"mkdocs": "data-search-exclude", "starlight": "data-pagefind-ignore"}


def set_engine(name: str) -> None:
    global _engine
    if name not in ENGINES:
        raise ValueError(f"unknown site engine {name!r}, expected one of {ENGINES}")
    _engine = name


def engine() -> str:
    return _engine


@contextmanager
def using(name: str) -> Iterator[None]:
    """Write in another syntax for a while: a page split by size is
    measured in the MkDocs Markdown its budgets were set on."""
    previous = _engine
    set_engine(name)
    try:
        yield
    finally:
        set_engine(previous)


def starlight() -> bool:
    return _engine == "starlight"


def search_exclude() -> str:
    return SEARCH_EXCLUDE[_engine]


def inline_html(text: str) -> str:
    """Inline Markdown (code, bold, links) for text placed inside raw HTML,
    where Markdown is not read."""
    parts = re.split(r"(`[^`]+`)", text)
    out = []
    for part in parts:
        if part.startswith("`") and part.endswith("`") and len(part) > 1:
            out.append(f"<code>{html.escape(part[1:-1], quote=False)}</code>")
            continue
        part = html.escape(part, quote=False)
        part = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", part)
        part = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", _link, part)
        out.append(part)
    return "".join(out)


# A scheme before any slash: javascript:, data:, vbscript: and the like.
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _link(match: re.Match) -> str:
    """A Markdown link as an anchor when its target is http(s) or relative,
    else left as the text it was. The target is already escaped for text,
    quotes are escaped for the attribute."""
    label, href = match.group(1), match.group(2)
    if _SCHEME.match(href) and not re.match(r"^https?://", href, re.IGNORECASE):
        return match.group(0)
    return f'<a href="{href.replace(chr(34), "&quot;").replace(chr(39), "&#x27;")}">{label}</a>'


def _indented(lines: list[str], pad: str) -> list[str]:
    return [f"{pad}{line}" if line.strip() else "" for line in lines]


def _trim(lines: list[str]) -> list[str]:
    start, end = 0, len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return list(lines[start:end])


def aside(kind: str, title: str, body: list[str], indent: str = "") -> list[str]:
    """A callout that is always open."""
    body = _trim(body)
    if _engine == "mkdocs":
        return [f'{indent}!!! {kind} "{title}"', "", *_indented(body, indent + "    "), ""]
    label = title.replace("[", "\\[").replace("]", "\\]")
    fence = "::::" if any(line.lstrip().startswith(":::") for line in body) else ":::"
    return [f"{indent}{fence}{ASIDE_ROLES.get(kind, 'note')}[{label}]",
            *_indented(body, indent), f"{indent}{fence}", ""]


def details(kind: str, title: str, body: list[str], indent: str = "", opened: bool = False) -> list[str]:
    """A collapsible block, closed unless *opened*."""
    body = _trim(body)
    if _engine == "mkdocs":
        marker = "???+" if opened else "???"
        return [f'{indent}{marker} {kind} "{title}"', "", *_indented(body, indent + "    "), ""]
    role = ASIDE_ROLES.get(kind, "note")
    state = " open" if opened else ""
    return [
        f'{indent}<details class="rb-details rb-details-{role}"{state}>',
        f"{indent}<summary>{inline_html(title)}</summary>",
        "",
        *_indented(body, indent),
        "",
        f"{indent}</details>",
        "",
    ]


def tabs(items: list[tuple[str, list[str]]], indent: str = "", sync: str = "os") -> list[str]:
    """Content tabs. Tabs that share a label share the reader's choice
    across pages.

    One item is no choice: 142 bars offered a single tab, most of them
    "On the device" under a heading that says so. Its body stands alone,
    led by its label when it has one: the RetroPie card is read from Linux
    only, and the label is where the page said so."""
    lines: list[str] = []
    if len(items) == 1:
        label, body = items[0]
        lead = [f"{indent}**{label}**", ""] if label else []
        return [*lead, *_indented(_trim(body), indent), ""]
    if _engine == "mkdocs":
        for label, body in items:
            lines += [f'{indent}=== "{label}"', "", *_indented(_trim(body), indent + "    "), ""]
        return lines
    lines.append(f'{indent}<Tabs syncKey="{sync}">')
    for label, body in items:
        lines += [f'{indent}<TabItem label="{html.escape(label)}">', "",
                  *_indented(_trim(body), indent), "", f"{indent}</TabItem>"]
    return [*lines, f"{indent}</Tabs>", ""]


def button(text: str, target: str, primary: bool = False) -> str:
    """A link drawn as a button."""
    if _engine == "mkdocs":
        classes = ".md-button .md-button--primary" if primary else ".md-button"
        return f"[{text}]({target}){{ {classes} }}"
    classes = "rb-button rb-button-primary" if primary else "rb-button"
    return f'<a class="{classes}" href="{html.escape(target)}">{inline_html(text)}</a>'


def image(alt: str, src: str, **attributes: str) -> str:
    """An image with HTML attributes (width, align)."""
    if _engine == "mkdocs":
        attrs = " ".join(f"{key}={value}" for key, value in attributes.items())
        return f"![{alt}]({src}){{ {attrs} }}"
    attrs = "".join(f' {key}="{html.escape(str(value))}"' for key, value in attributes.items())
    return f'<img src="{html.escape(src)}" alt="{html.escape(alt)}"{attrs}>'


def hash_value(value: object, copy: bool = False) -> str:
    """A hash printed whole, in the hash style. One element under Starlight:
    a span around a code span was 1,400 extra elements on a page of cards.
    *copy* marks it for the copy button the site script adds after it."""
    text = str(value).replace("`", "'")
    if _engine == "mkdocs":
        return f'<span class="rb-hash">`{text}`</span>'
    marker = ' data-copy=""' if copy else ""
    return f'<code class="rb-hash"{marker}>{html.escape(text, quote=False)}</code>'


def block_open(tag: str, attributes: str = "") -> str:
    """The opening tag of an HTML block whose content is Markdown."""
    attributes = f" {attributes.strip()}" if attributes.strip() else ""
    if _engine == "mkdocs":
        return f"<{tag}{attributes} markdown>"
    return f"<{tag}{attributes}>"


def card_grid(cards: list[tuple[str, list[str]]]) -> list[str]:
    """Cards in a grid: a bold title line and a body each."""
    lines = [block_open("div", 'class="grid cards"' if _engine == "mkdocs" else 'class="rb-cards"'), ""]
    for title, body in cards:
        if _engine == "mkdocs":
            lines += [f"-   **{title}**", "", *_indented(_trim(body), "    "), ""]
        else:
            lines += ['<div class="rb-card">', "", f"**{title}**", "", *_trim(body), "", "</div>", ""]
    return [*lines, "</div>", ""]


def initials(name: str) -> str:
    """Up to two capitals of a name, for a setup that has no logo: MyMinUI is MM.
    A name written from a lowercase prefix keeps it: iPhone is iP, not PP."""
    if len(name) > 1 and name[0].islower() and name[1].isupper():
        return name[:2]
    capitals = [c for c in name if c.isupper()]
    return "".join(capitals[:2]) or name[:2].upper()


def _tile_mark(name: str, logo: str, lazy: bool = False) -> str:
    """A tile's logo, or its initials. *lazy* for a tile below the first
    screen: the browser fetches its logo when the reader scrolls near it."""
    if logo:
        loading = ' loading="lazy"' if lazy else ""
        return (f'<img class="rb-card-logo" src="{html.escape(logo)}" alt="" '
                f'width="40" height="40"{loading}>')
    # The same square as a logo, drawn on white like the logos are. The
    # letters are the stylesheet's (::before), not text of the page: the
    # tile's name follows, and a copy or a text dump read "MMMyMinUI".
    return (f'<span class="rb-card-logo rb-card-initials" data-initials="{html.escape(initials(name))}" '
            'aria-hidden="true"></span>')


# Tiles in the first row of a grid at its widest, two columns of 15rem in
# the content column: the logos the reader may see without scrolling.
FIRST_ROW_TILES = 2


def platform_tiles(tiles: list[tuple[str, str, str, str]], eager: int = 0) -> list[str]:
    """One link per setup: its logo (or its initials), its name and where it
    runs. *tiles* are (name, target, logo, runs_on). The first *eager*
    logos load with the page, the others when the reader scrolls to them.

    One HTML line: a grid of links is a menu, not prose, and the Markdown
    around it reads none of it."""
    links = "".join(
        f'<a class="rb-card rb-tile" href="{html.escape(target)}">'
        f"{_tile_mark(name, logo, lazy=index >= eager)}"
        f'<strong class="rb-tile-name">{html.escape(name)}</strong> '
        f'<span class="rb-tile-runs">{inline_html(runs_on)}</span></a> '
        for index, (name, target, logo, runs_on) in enumerate(tiles)
    )
    return [f'<div class="rb-cards rb-tiles">{links}</div>', ""]


def steps(items: list[str]) -> list[str]:
    """An ordered list drawn as numbered steps."""
    return [block_open("div", 'class="rb-steps"'), "",
            *(f"{number}. {item}" for number, item in enumerate(items, 1)), "", "</div>", ""]


def heading_attributes(anchor: str = "", classes: str = "", search: bool = True) -> str:
    """The attribute block of a heading: its id, classes, and whether the
    search reads it."""
    parts = [f"#{anchor}" if anchor else "", *(f".{c}" for c in classes.split())]
    if not search:
        parts.append(search_exclude())
    parts = [part for part in parts if part]
    return f" {{ {' '.join(parts)} }}" if parts else ""


def site_href(path: str) -> str:
    """A link to a site address written in raw HTML (``files/?sha1=...``),
    which no Markdown resolution reaches: rooted at the site under Starlight,
    relative to a page two levels deep under MkDocs."""
    if _engine == "mkdocs":
        return f"../../{path}"
    return f"/retrobios/{path}"
