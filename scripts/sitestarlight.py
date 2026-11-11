"""The site as an Astro Starlight project: pages, sidebar and data files.

generate_site.py writes each page body, and this module gives it the form
Starlight reads. A page's links are written as the docs tree holds them
(``../systems/sony.md``, MkDocs' convention, the one a Markdown editor
follows), and the site serves them as addresses under /retrobios/, so
each target is resolved against the page's own place here. Every heading
keeps the id the MkDocs site gave it, so the anchors cited since stay
valid.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from html import unescape
from pathlib import Path, PurePosixPath

BASE = "/retrobios/"
SITE_URL = "https://abdess.github.io/retrobios/"

# Components a page body may use, and where each comes from.
COMPONENTS = {
    "Tabs": "@astrojs/starlight/components",
    "TabItem": "@astrojs/starlight/components",
    "FilePicker": "components/FilePicker.astro",
    "MeasurementsExplorer": "components/MeasurementsExplorer.astro",
    "InstallDemo": "components/InstallDemo.astro",
}

# Pages of file cards: level 3 headings by the hundred, so the table of
# contents stops at level 2.
CARD_PAGES = ("systems/", "emulators/", "platforms/")

FENCE = re.compile(r"(^[ \t]*(`{3,}|~{3,}).*?^[ \t]*\2[ \t]*$)", re.M | re.S)
CODE_SPAN = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.S)
MD_LINK = re.compile(r"(?P<bang>!?)\[(?P<text>(?:[^\[\]\n]|\[[^\]\n]*\])*)\]\((?P<url>[^)\s]+)(?P<title> \"[^\"]*\")?\)")
HTML_URL = re.compile(r"(?P<attr>\b(?:href|src))=\"(?P<url>[^\"]*)\"")
ATTR_BLOCK = re.compile(r"[ \t]*\{(?P<attrs>[^{}]*)\}[ \t]*$")
ID_ATTR = re.compile(r"\bid=\"(?P<id>[^\"]+)\"")
IDCOUNT = re.compile(r"^(.*)_([0-9]+)$")


# Addresses


def page_url(rel: str) -> str:
    """The address of a page, by its path under the docs tree."""
    stem = rel.rsplit(".", 1)[0] if rel.endswith((".md", ".mdx")) else rel
    if stem == "index":
        return BASE
    if stem.endswith("/index"):
        stem = stem[: -len("/index")]
    return f"{BASE}{stem}/"


def resolve(rel_page: str, target: str) -> str:
    """A link target written relative to the page's file, as a site address."""
    if not target or re.match(r"^(?:[a-z][a-z0-9+.-]*:|#|/)", target):
        return target
    path, hash_mark, fragment = target.partition("#")
    path, question, query = path.partition("?")
    parts: list[str] = []
    for piece in (PurePosixPath(rel_page).parent / path).as_posix().split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            if parts:
                parts.pop()
        else:
            parts.append(piece)
    joined = "/".join(parts)
    if joined.endswith((".md", ".mdx")):
        url = page_url(joined)
    elif path.endswith("/") or not path:
        url = f"{BASE}{joined}/" if joined else BASE
    else:
        url = f"{BASE}{joined}"
    if question:
        url += f"?{query}"
    return url + (f"#{fragment}" if hash_mark else "")


# Text outside code


def outside_fences(text: str, fn: Callable[[str], str]) -> str:
    parts = FENCE.split(text)
    # FENCE has two groups: text, fence, marker, text, ...
    out = []
    for index in range(0, len(parts), 3):
        out.append(fn(parts[index]))
        if index + 1 < len(parts):
            out.append(parts[index + 1])
    return "".join(out)


def outside_code(text: str, fn: Callable[[str], str]) -> str:
    def chunk(part: str) -> str:
        out, position = [], 0
        for match in CODE_SPAN.finditer(part):
            out.append(fn(part[position:match.start()]))
            out.append(match.group(0))
            position = match.end()
        out.append(fn(part[position:]))
        return "".join(out)
    return outside_fences(text, chunk)


def rewrite_links(text: str, rel: str) -> str:
    def markdown(match: re.Match) -> str:
        return (f"{match['bang']}[{match['text']}]({resolve(rel, match['url'])}"
                f"{match['title'] or ''})")

    def attribute(match: re.Match) -> str:
        return f'{match["attr"]}="{resolve(rel, match["url"])}"'

    text = outside_fences(text, lambda chunk: MD_LINK.sub(markdown, chunk))
    return outside_fences(text, lambda chunk: HTML_URL.sub(attribute, chunk))


# Heading ids, as Python-Markdown's toc extension gives them


def toc_slug(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)(\{[^}]*\})?", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = unescape(text.replace("`", "").replace("**", "").replace("\\", ""))
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", text)


def _unique(ident: str, used: set[str]) -> str:
    while ident in used or not ident:
        match = IDCOUNT.match(ident)
        ident = f"{match[1]}_{int(match[2]) + 1}" if match else f"{ident}_1"
    used.add(ident)
    return ident


def pin_heading_ids(text: str, title_id: str = "") -> str:
    """Every heading with the id the MkDocs build gave it. *title_id* is
    the page title's, taken first."""
    used: set[str] = {title_id} if title_id else set()
    explicit = set()
    for match in re.finditer(r"\{[^{}\n]*#([^\s}]+)[^{}\n]*\}[ \t]*$", text, re.M):
        explicit.add(match[1])
    for match in ID_ATTR.finditer(text):
        explicit.add(match["id"])
    used |= explicit

    def markdown(match: re.Match) -> str:
        heading = match["mdtext"]
        attrs = ATTR_BLOCK.search(heading)
        body = heading[: attrs.start()] if attrs else heading
        tokens = attrs["attrs"].split() if attrs else []
        if any(token.startswith("#") for token in tokens):
            return match.group(0)
        ident = _unique(toc_slug(body), used)
        return f"{match['hashes']} {body.rstrip()} {{ {' '.join(['#' + ident, *tokens])} }}"

    def raw(match: re.Match) -> str:
        if ID_ATTR.search(match["attrs"]):
            return match.group(0)
        level, text = match["level"], match["htmltext"]
        ident = _unique(toc_slug(text), used)
        return f'<h{level} id="{ident}"{match["attrs"]}>{text}</h{level}>'

    def pick(match: re.Match) -> str:
        return markdown(match) if match["hashes"] else raw(match)

    # In document order: one pass over either kind of heading.
    return outside_fences(text, lambda chunk: _ANY_HEADING.sub(pick, chunk))


_ANY_HEADING = re.compile(
    r"^(?P<hashes>#{2,6})[ \t]+(?P<mdtext>.+?)[ \t]*$"
    r"|<h(?P<level>[2-6])(?P<attrs>(?:\s[^>]*)?)>(?P<htmltext>.*?)</h(?P=level)>",
    re.M | re.S,
)


# Glossary tooltips


def glossary_terms(path: Path) -> dict[str, str]:
    """Each term the glossary defines, with its definition as plain text."""
    terms: dict[str, str] = {}
    if not path.is_file():
        return terms
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"^(?P<term>\*\*.+)\n:   (?P<body>.+(?:\n    .+)*)", text, re.M):
        definition = re.sub(r"\s+", " ", match["body"]).strip()
        definition = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", definition).replace("`", "")
        for term in re.findall(r"\*\*([^*]+)\*\*", match["term"]):
            terms.setdefault(term, definition)
    return terms


_SKIP_TAGS = re.compile(r"<(a|code|pre|abbr|h[1-6]|script|style|summary|svg|figure)\b.*?</\1>", re.S | re.I)


def add_tooltips(text: str, terms: dict[str, str]) -> str:
    """The first use of each glossary term on a page, with its definition
    a hover or a tap away. Headings, links, code and HTML are left as they are."""
    if not terms:
        return text
    pending = dict(terms)
    pattern = re.compile(
        r"(?<![\w/.-])(" + "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True))
        + r")(?![\w/-])"
    )

    def prose(chunk: str) -> str:
        if not pending:
            return chunk
        out = []
        for line in chunk.split("\n"):
            stripped = line.lstrip()
            if (not pending or stripped.startswith(("#", "|", "<", ":::", "[", "!"))
                    or not stripped):
                out.append(line)
                continue
            out.append(_tooltip_line(line, pattern, pending))
        return "\n".join(out)

    return outside_code(text, prose)


def _tooltip_line(line: str, pattern: re.Pattern, pending: dict[str, str]) -> str:
    # Inline HTML, links and emphasis markers stay whole.
    protected = re.compile(r"<[^>]+>|\[[^\]]*\]\([^)]*\)|\*\*[^*]+\*\*|\{[^}]*\}")
    out, position = [], 0
    for match in protected.finditer(line):
        out.append(_tooltip_text(line[position:match.start()], pattern, pending))
        out.append(match.group(0))
        position = match.end()
    out.append(_tooltip_text(line[position:], pattern, pending))
    return "".join(out)


_NAME_BEFORE = re.compile(r"(?:/|\b[A-Z][\w'-]*[ \t]+)$")


def _in_proper_name(term: str, before: str) -> bool:
    """A capitalised term after a capitalised word or a slash is part of a
    name: Free Unix Spectrum Emulator, Windows Terminal, Documents/Dolphin
    Emulator. An acronym (BIOS, ZIP) is the term wherever it stands."""
    first = term.split()[0]
    return first[:1].isupper() and not first.isupper() and bool(_NAME_BEFORE.search(before))


def _tooltip_text(text: str, pattern: re.Pattern, pending: dict[str, str]) -> str:
    def swap(match: re.Match) -> str:
        term = match.group(1)
        if term not in pending or _in_proper_name(term, text[:match.start()]):
            return term
        definition = pending.pop(term)
        return f'<abbr class="rb-term" title="{html.escape(definition)}">{term}</abbr>'
    return pattern.sub(swap, text)


# MDX


_VOID = re.compile(r"<(br|img|input|hr|source|meta|link|wbr)\b([^>]*?)(?<!/)>")
_HEADING_ATTRS = re.compile(r"(?m)(?<=\S)[ \t]+\{[ \t]*#[^{}\n]*\}[ \t]*$")
_COMMENT = re.compile(r"<!--.*?-->", re.S)


_TAG_GAP = re.compile(r"(</[A-Za-z][\w-]*>)[ \t]+(?=<[A-Za-z])")


def mdx_safe(text: str) -> str:
    """What MDX would read as code in prose: braces, a stray ``<``,
    comments, unclosed void tags and ``<https://...>`` links. A space
    between two tags is written as an expression MDX keeps."""
    def fix(chunk: str) -> str:
        chunk = _COMMENT.sub("", chunk)
        chunk = re.sub(r"<(https?://[^>\s]+)>", r"[\1](\1)", chunk)
        held: list[str] = []

        def hold(match: re.Match) -> str:
            held.append(match.group(0))
            return f"\x00{len(held) - 1}\x00"
        chunk = _HEADING_ATTRS.sub(hold, chunk)
        chunk = chunk.replace("{", "&#123;").replace("}", "&#125;")
        chunk = re.sub(r"\x00(\d+)\x00", lambda m: held[int(m[1])], chunk)
        chunk = re.sub(r"<(?![A-Za-z/])", "&lt;", chunk)
        chunk = _VOID.sub(lambda m: f"<{m[1]}{m[2].rstrip()} />", chunk)
        # A line of tags alone is JSX to MDX, which drops the space between
        # them: a setup page with tabs read "2007/2008Coverage".
        return _TAG_GAP.sub(r'\1{" "}', chunk)
    return outside_code(text, fix)


def used_components(body: str) -> list[str]:
    return [name for name in COMPONENTS if re.search(rf"<{name}[\s/>]", body)]


# Pages


def _front_matter(data: dict) -> str:
    import yaml

    return "---\n" + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=1000) + "---\n\n"


def og_section(rel: str, level: str) -> str:
    """The sharing card a page takes: its level, or what its address says."""
    url = page_url(rel)[len(BASE):]
    if not url:
        return "home"
    if level in ("start", "setup", "explore", "reference", "contribute"):
        return level
    if url.startswith(("which-pack", "wiki/first-install", "wiki/faq", "wiki/getting-started")):
        return "start"
    if url.startswith("platforms"):
        return "setup"
    if url.startswith(("systems", "emulators", "files")):
        return "explore"
    if url.startswith(("contributing", "wiki/adding", "wiki/profiling", "wiki/testing", "wiki/release")):
        return "contribute"
    return "reference"


# Sharing cards of their own, made by scripts/make_og_cards.py: one per
# platform page, titled with the platform's name.
OG_DIR = Path(__file__).resolve().parent.parent / "docs_assets" / "og"


# An emulator page's card is that of the maker of the first system it runs,
# by page path: "emulators/mgba.mdx" -> "nintendo". One card per emulator
# would be some 900 images in the repository, and the maker's names the
# consoles. Filled by generate_site.record_emulator_page.
EMULATOR_CARDS: dict[str, str] = {}


def og_image(rel: str, level: str) -> str:
    """The sharing card's address: the page's own when it has one, its
    maker's for an emulator, else its section's."""
    own = re.fullmatch(r"(platforms|systems)/([a-z0-9_-]+)\.mdx?", rel)
    if own and own[2] != "index" and (OG_DIR / own[1] / f"{own[2]}.png").is_file():
        return f"{SITE_URL}assets/og/{own[1]}/{own[2]}.png"
    maker = EMULATOR_CARDS.get(re.sub(r"\.mdx?$", "", rel))
    if maker and (OG_DIR / "systems" / f"{maker}.png").is_file():
        return f"{SITE_URL}assets/og/systems/{maker}.png"
    return f"{SITE_URL}assets/og/{og_section(rel, level)}.png"


NOT_FOUND = "404.md"


def page_head(rel: str, level: str, title: str, browser_title: str, structured: dict) -> list[dict]:
    """What a page adds to its head: its own window title, its sharing
    card (og_image), and its structured data. The page a stale link
    lands on asks not to be indexed and describes nothing."""
    head: list[dict] = []
    if browser_title != title:
        head.append({"tag": "title", "content": f"{browser_title} - RetroBIOS"})
    if rel == NOT_FOUND:
        return head + [{"tag": "meta", "attrs": {"name": "robots", "content": "noindex"}}]
    image = og_image(rel, level)
    if browser_title != title:
        # Starlight writes og:title from the H1 ("mGBA"): a shared link
        # reads as the search result does ("mGBA BIOS files").
        head += [{"tag": "meta", "attrs": {"property": "og:title", "content": browser_title}},
                 {"tag": "meta", "attrs": {"name": "twitter:title", "content": browser_title}}]
    head += [
        {"tag": "meta", "attrs": {"property": "og:image", "content": image}},
        {"tag": "meta", "attrs": {"property": "og:image:width", "content": "1200"}},
        {"tag": "meta", "attrs": {"property": "og:image:height", "content": "630"}},
        {"tag": "meta", "attrs": {"property": "og:image:alt", "content": f"RetroBIOS: {browser_title}"}},
        {"tag": "meta", "attrs": {"name": "twitter:image", "content": image}},
        {"tag": "script", "attrs": {"type": "application/ld+json"},
         "content": json.dumps(structured, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")},
    ]
    return head


def split_title(markdown: str) -> tuple[str, str, str]:
    """The page's H1 as plain text, the id MkDocs gave it, and the body
    without it."""
    match = re.search(r"^# (.+?)[ \t]*$\n?", markdown, re.M)
    if not match:
        return "", "", markdown
    explicit = re.search(r"\{[^}]*#([^\s}]+)[^}]*\}\s*$", match[1])
    title = re.sub(r"\s*\{[^}]*\}\s*$", "", match[1])
    ident = explicit[1] if explicit else toc_slug(title)
    title = re.sub(r"<[^>]+>", "", title)
    title = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", title)
    title = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", title).replace("`", "")
    return unescape(title).strip(), ident, markdown[: match.start()] + markdown[match.end():]


_CARD_NAME = re.compile(r'<h3[^>]*class="rb-file-title"(?![^>]*data-pagefind-ignore)[^>]*><code>([^<]+)</code>')
# What separates the parts of a file name: anything but a letter or a digit.
_NAME_PART = re.compile(r"[\W_]+")


def search_field(key: str, words: list[str]) -> str:
    """A search field of the page, held in an attribute of an empty
    element: the text of an element is indexed and shown as the result's
    excerpt (a run of 250 file names). Pagefind splits several fields at a
    comma, so a value carries none."""
    value = " ".join(word.replace(",", " ") for word in words).strip()
    if not value:
        return ""
    return f'\n<span data-pagefind-meta="{html.escape(f"{key}:{value}", quote=True)}" hidden></span>\n'


def file_names_meta(body: str) -> str:
    """The names of the files a system page holds cards for, as a search
    field of the page. A page of 250 cards is long, and the search weighs a
    long page down: the Sony page, where scph5501.bin is downloaded, came
    after every short page citing the name. The field is weighted in the
    site's ranking (astro.config.mjs, metaWeights.files).

    A name is written as its parts (scph5501 bin), each once. The search
    matches a word as the start of a longer one and scores every distinct
    word it reaches: whole names gave "ds" twelve rare words on the DSi page
    (dsi_bios7.bin, DSi_Nand_USA.bin...), which then ranked first for
    "nintendo ds bios"."""
    names = sorted({unescape(name) for name in _CARD_NAME.findall(body)})
    parts: dict[str, str] = {}
    for name in names:
        for part in _NAME_PART.split(name):
            if part:
                parts.setdefault(part.casefold(), part)
    return search_field("files", list(parts.values()))


# systems/ page -> the platforms' own ids for the consoles it holds, built
# on the first system page, once the generator has installed the sections.
_page_aliases: dict[str, list[str]] = {}
_page_aliases_built = [False]


def page_aliases(rel: str) -> list[str]:
    """The names the platforms file the consoles of a system page under
    (psx, dreamcast, gba), from siterender.system_search_aliases(): "psx
    bios" finds the PlayStation page though the page never says psx."""
    if not _page_aliases_built[0]:
        import siterender

        by_page: dict[str, set[str]] = {}
        for sys_id in list(siterender._system_page_map):
            section = siterender.system_section(sys_id)
            names = siterender.system_search_aliases(sys_id)
            if not section or not names:
                continue
            target = siterender.console_href(*section).partition("#")[0]
            by_page.setdefault(urllib.parse.unquote(target), set()).update(names)
        _page_aliases.clear()
        _page_aliases.update({page: sorted(names, key=str.casefold)
                              for page, names in by_page.items()})
        _page_aliases_built[0] = bool(siterender._system_page_map)
    return list(_page_aliases.get(rel, []))


def field_words(value: object) -> list[str]:
    """The words of a front matter search field: a list, or one string
    with its words or phrases split at commas."""
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


def console_words(names: list[str]) -> list[str]:
    """What a visitor types for a console: its name with "BIOS". A page that
    answers "No file needed" says BIOS only where the search does not read,
    so "nes bios" found NES.emu and never the NES page. As a task word it
    weighs like one: in the consoles field, NES.emu's title still won."""
    return [f"{name} BIOS" for name in names]


_CONSOLES_META = re.compile(r'data-pagefind-meta="consoles:([^"]*)"')


def page_console_words(authored: dict, text: str) -> set[str]:
    """The words of the consoles a page answers for: its `consoles` front
    matter (*authored*) before decoration, its `consoles` field after."""
    names = field_words(authored.get("consoles"))
    if names:
        return {word.casefold() for name in names for word in name.split()}
    match = _CONSOLES_META.search(text)
    return set(unescape(match[1]).casefold().split()) if match else set()


def covered_names(names: list[str], page: str, words_by_page: Mapping[str, set[str]]) -> list[str]:
    """The names of *names* whose every word another page's consoles also
    hold, as a word or the start of one (PlayStation on the PlayStation 2
    page, Nintendo DS on the DSi page, Nintendo Super System on the
    Nintendo page). The search matches a word as the start of a longer one
    and ignores the words a page has that the query lacks: it cannot tell
    these pages apart by words, only by a weight the other page lacks."""
    held = [words for other, words in words_by_page.items() if other != page]
    return [name for name in names
            if any(all(any(word.startswith(part) for word in words)
                       for part in name.casefold().split())
                   for words in held)]


def _neighbour(rel: str, value: object) -> object:
    """A `prev:` or `next:` the page states, its link resolved like any
    other link of the page."""
    if isinstance(value, dict) and value.get("link"):
        # Starlight writes the link as given: a site path gets the base.
        link = resolve(rel, str(value["link"]))
        if link.startswith("/") and not link.startswith(BASE):
            link = BASE + link.lstrip("/")
        return {**value, "link": link}
    return value


_NEXT_STEPS = re.compile(r"^## Next steps\b[^\n]*\n+(?P<list>(?:[ \t]*[-*] .*\n?)+)", re.M)


def next_step(body: str) -> dict | None:
    """The first link of the page's "Next steps" list, as the theme's
    `next:` front matter."""
    match = _NEXT_STEPS.search(body)
    if not match:
        return None
    link = MD_LINK.search(match["list"])
    if not link or link["bang"]:
        return None
    return {"link": link["url"], "label": re.sub(r"[*_`]", "", link["text"]).strip()}


def finalize_page(
    rel: str,
    markdown: str,
    *,
    level: str,
    weight: float | None,
    browser_title: str,
    description: str,
    structured: dict,
    terms: dict[str, str],
    search: bool = True,
    logo: str = "",
    parent: dict | None = None,
    authored: dict | None = None,
    words_by_page: Mapping[str, set[str]] | None = None,
) -> tuple[str, str]:
    """The Starlight file for a page body: its path under the content
    collection and its text. *parent* ({label, link}, the link written
    relative to the page) is the page a part page belongs to: the route
    middleware makes it the last crumb and marks it in the sidebar.

    *authored* is the front matter the page was written with. Its
    `searchWeight`, `prev` and `next` win over the computed ones (a part
    page states its neighbours and its weight), and its `consoles` and
    `terms` become search fields (astro.config.mjs, metaWeights): the
    consoles a manufacturer page holds sections for, and the words a page
    answers that its text does not say, as an error message words them.
    *words_by_page* holds the console words of every system page, by path
    without extension: a console another page's words cover is written
    once more, in `exact`."""
    authored = authored or {}
    title, title_id, body = split_title(markdown)
    body = body.lstrip("\n")
    body = rewrite_links(body, rel)
    body = pin_heading_ids(body, title_id)
    if title_id:
        # The title is the theme's, with an id of its own: the one MkDocs
        # gave it stays an anchor at the top of the text.
        body = f'<div id="{html.escape(title_id)}" class="rb-anchor"></div>\n\n' + body
    if rel not in ("wiki/glossary.md", "wiki/reference-terms.md"):
        body = add_tooltips(body, terms)
    # A badge is a status (required, missing, MD5), not a word a reader
    # searches for: 141 "missing" badges put an emulator page above the
    # troubleshooting page for "missing bios". The archive a file sits in
    # is a name, and stays: it is how "neogeo.zip" finds the cores reading it.
    body = re.sub(r'<span class="(rb-badge(?![^"]*rb-badge-archive)[^"]*)"',
                  r'<span data-pagefind-ignore class="\1"', body)
    # "Next steps" closes most pages with the same links ("for the setup in
    # use"): the "u" of "wii u bios" matched the start of "use" there, and
    # the Nintendo page came before the Wii U page.
    body = _NEXT_STEPS.sub(
        lambda match: f"<div data-pagefind-ignore>\n\n{match[0].rstrip()}\n\n</div>\n\n", body, count=1)
    if rel.startswith("systems/"):
        body += file_names_meta(body) + search_field("aliases", page_aliases(rel))
    consoles = field_words(authored.get("consoles"))
    body += search_field("consoles", consoles)
    body += search_field("exact", covered_names(consoles, rel.rsplit(".", 1)[0], words_by_page or {}))
    body += search_field("terms", field_words(authored.get("terms")) + console_words(consoles))
    components = used_components(body)
    stem = rel.rsplit(".", 1)[0]
    if components:
        body = mdx_safe(body)
        imports: dict[str, list[str]] = {}
        for name in components:
            imports.setdefault(COMPONENTS[name], []).append(name)
        # Our own components are imported from src/, two levels above the
        # content collection plus the page's own folders.
        up = "../" * (rel.count("/") + 2)
        body = "".join(f"import {{ {', '.join(names)} }} from '{source}';\n"
                       if source.startswith("@") else f"import {names[0]} from '{up}{source}';\n"
                       for source, names in imports.items()) + "\n" + body
    front: dict = {"title": title or browser_title, "description": description}
    # Starlight's slugger drops dots and plus signs: the address stays MkDocs'.
    if re.search(r"[^a-z0-9_/-]", stem):
        front["slug"] = stem
    if level:
        front["level"] = level
    if logo:
        front["logo"] = logo
    if parent:
        front["parent"] = {"label": str(parent["label"]),
                           "link": resolve(rel, str(parent["link"]))}
    weight = authored.get("searchWeight", weight)
    if weight:
        front["searchWeight"] = weight
    if rel == NOT_FOUND:
        front["tableOfContents"] = False
    elif rel.startswith(CARD_PAGES):
        sections = len(re.findall(r"^## ", body, re.M))
        # A page of cards under one or two headings has nothing to list, and
        # the table of contents watches every block of the page to follow
        # the reader: 2 x 430 ms of a phone's main thread on 400 cards.
        front["tableOfContents"] = (
            {"minHeadingLevel": 2, "maxHeadingLevel": 2} if sections > 2 else False)
    if not search:
        front["pagefind"] = False
    step = next_step(body)
    if rel == NOT_FOUND or not reads_in_order(rel):
        front["prev"] = False
        front["next"] = False
    elif step:
        # The page's own "Next steps" list and the next link agree.
        front["next"] = step
    for side in ("prev", "next"):
        if rel != NOT_FOUND and side in authored:
            front[side] = _neighbour(rel, authored[side])
    front["head"] = page_head(rel, level, front["title"], browser_title, structured)
    if structured.get("dateModified"):
        front["lastmod"] = str(structured["dateModified"])
    return stem + (".mdx" if components else ".md"), _front_matter(front) + body


# Navigation


def _sidebar_link(rel: str) -> str:
    return page_url(rel)[len(BASE) - 1:]


# Tabs whose groups hold pages by the hundred (every system, every
# emulator): a group that does not hold the current page is drawn as one
# link to its overview, so an emulator page does not carry the links of
# every other emulator.
PRUNED_TABS = ("explore",)

# Reading runs from one tab into the next only here: the last Start here
# page leads to Setups. Every other tab is read on its own.
CHAINED_TABS = (("start-here", "setups"),)


def topic_id(label: str) -> str:
    return re.sub(r"[^a-z]+", "-", label.lower()).strip("-")


def heading_ids(text: str) -> set[str]:
    """The anchors a page's headings carry, as written by pin_heading_ids."""
    ids = {match[1] for match in re.finditer(r"\{[^{}\n]*#([^\s}]+)[^{}\n]*\}[ \t]*$", text, re.M)}
    return ids | {match["id"] for match in ID_ATTR.finditer(text)}


def reads_in_order(rel: str) -> bool:
    """A page the previous and next links pass through. A system, emulator
    or platform page is reached by its name, not read after its neighbour
    in the alphabet: "SNK, Sony, Sord" is no reading order."""
    return not rel.startswith(CARD_PAGES) or rel.endswith("/index.md")


_DIGIT_RANGE = re.compile(r"[0-9] to [0-9]")


def by_initial(label: str, children: list[dict]) -> bool:
    """A group that files its pages by the first character of their names
    (A, B, "0 to 9"): a way through a long list, not a place, so it is no
    crumb."""
    if not children or any("items" in child for child in children):
        return False
    firsts = {str(child["label"])[:1].upper() for child in children}
    if len(label) == 1:
        return firsts == {label}
    return bool(_DIGIT_RANGE.fullmatch(label)) and not any("A" <= first <= "Z" for first in firsts)


def sidebar(nav: list, present: set[str], anchors: dict[str, set[str]] | None = None) -> dict:
    """The navigation as Starlight topics, one per tab, with what the route
    middleware (website/src/routeData.ts) reads beside it.

    A page the navigation does not list (the parts of a split page) joins
    the topic that holds most pages of its directory. In a directory the
    navigation lists nothing of (get/), it joins the topic of the pages of
    the same name, and a page with neither joins the first topic: no page
    is left out of every tab.

    A group that files names by their first letter is marked `crumb: false`:
    the breadcrumbs skip it.

    `groups` gives each group, keyed by the labels from its tab down, the
    page that introduces it: its own overview page, or the heading named
    after it on the overview above it (`anchors` lists each page's heading
    ids). A group with neither has no address, never the address of its
    first page, which is a sibling of the page being read. `prune` marks the
    groups drawn as one link when they do not hold the current page.

    `reading` is the order of the previous and next links, one list per run
    of tabs read in sequence.
    """
    anchors = anchors or {}
    owner: dict[str, str] = {}
    groups: dict[str, dict] = {}

    def label_of(entry: object) -> str:
        return next(iter(entry)) if isinstance(entry, dict) else ""

    def overview_of(value: list) -> str | None:
        return next((v for v in value if isinstance(v, str)), None)

    def item(entry: object, topic: str, trail: tuple[str, ...], parent: str | None) -> dict | None:
        if isinstance(entry, str):
            owner[entry] = topic
            return {"label": "Overview", "link": _sidebar_link(entry)} if entry in present else None
        (label, value), = entry.items()
        if isinstance(value, str):
            if value.startswith("http"):
                return {"label": label, "link": value}
            owner[value] = topic
            return {"label": label, "link": _sidebar_link(value)} if value in present else None
        if "/" in label:
            raise ValueError(f"a navigation group label holds a slash: {label!r}")
        own = overview_of(value)
        here = (*trail, label)
        href = None
        if own and own in present:
            href = page_url(own)
        elif parent and parent in present:
            anchor = toc_slug(label)
            if anchor in anchors.get(parent, set()):
                href = f"{page_url(parent)}#{anchor}"
            elif topic in PRUNED_TABS:
                # Drawn as a link, it needs an address: the overview it
                # sits under, never one of its own pages.
                href = page_url(parent)
        children = [child for child in (item(v, topic, here, own or parent) for v in value) if child]
        if not children:
            return None
        groups["/".join(here)] = {"href": href, "prune": topic in PRUNED_TABS and href is not None,
                                  "crumb": not by_initial(label, children)}
        return {"label": label, "items": children, "collapsed": True}

    topics = []
    for tab in nav:
        (label, value), = tab.items()
        topic = topic_id(label)
        children = [child for child in (item(v, topic, (label,), overview_of(value)) for v in value)
                    if child]
        if children:
            topics.append({"id": topic, "label": label, "link": next(_links(children))["link"],
                           "items": children})

    votes: dict[str, dict[str, int]] = {}
    for rel, topic in owner.items():
        tally = votes.setdefault(rel.rpartition("/")[0], {})
        tally[topic] = tally.get(topic, 0) + 1
    # The page a stale link lands on opens on the first tab: its sidebar
    # is the way back in. Excluded from every tab, the theme named the tabs
    # by their position, 0 to 4.
    extra: dict[str, list[str]] = {topics[0]["id"]: ["/404"]} if topics else {}
    # A folder the navigation lists nothing of (get/, one download page per
    # setup) has no vote, and excluded from every tab its pages had the
    # tabs numbered 0 to 4 too. Its pages take the tab of the pages of the
    # same name (get/batocera.md, platforms/batocera.md), and its overview
    # the tab its pages took.
    by_name: dict[str, dict[str, int]] = {}
    for rel, topic in owner.items():
        tally = by_name.setdefault(PurePosixPath(rel).name, {})
        tally[topic] = tally.get(topic, 0) + 1
    unlisted = sorted(present - owner.keys())
    adopted: dict[str, dict[str, int]] = {}
    for rel in unlisted:
        folder, name = rel.rpartition("/")[0], PurePosixPath(rel).name
        if folder in votes or name == "index.md":
            continue
        tally = adopted.setdefault(folder, {})
        for topic, count in by_name.get(name, {}).items():
            tally[topic] = tally.get(topic, 0) + count
    for rel in unlisted:
        folder = rel.rpartition("/")[0]
        tally = votes.get(folder) or adopted.get(folder)
        if tally:
            topic = max(tally, key=tally.get)
        elif topics:
            topic = topics[0]["id"]
        else:
            continue
        extra.setdefault(topic, []).append("/" + (_sidebar_link(rel).strip("/") or "index"))
    return {"topics": topics, "options": {"topics": extra, "exclude": []},
            "groups": groups, "reading": _reading(nav, present)}


def _reading(nav: list, present: set[str]) -> list[list[dict]]:
    """The previous and next links, in runs. An overview is named after the
    group or tab it opens ("Setups", not "Overview")."""
    def walk(value: list, name: str) -> Iterator[dict]:
        for entry in value:
            if isinstance(entry, str):
                if entry in present and reads_in_order(entry):
                    yield {"label": name, "link": page_url(entry)}
                continue
            (label, target), = entry.items()
            if isinstance(target, list):
                yield from walk(target, label)
            elif not target.startswith("http") and target in present and reads_in_order(target):
                yield {"label": label, "link": page_url(target)}

    tabs = {topic_id(label): list(walk(value, label))
            for tab in nav for label, value in tab.items()}
    runs: list[list[dict]] = []
    previous = ""
    for tab, pages in tabs.items():
        if runs and (previous, tab) in CHAINED_TABS:
            runs[-1].extend(pages)
        else:
            runs.append(list(pages))
        previous = tab
    return [run for run in runs if run]


# Addresses that once held a page, and where its content went.
MOVED_PAGES = {"wiki/getting-started.md": "which-pack.md"}

_CORE_NAME = re.compile(r"[a-z0-9_-]+")


def redirects(profiles: dict, present: set[str],
              moved: dict[str, str] | None = None) -> dict[str, str]:
    """Old and alternative addresses, for src/generated/redirects.json.

    A page that moved, once its source is gone, and each name a profile's
    `cores:` gives the emulator (the buildbot's `mednafen_psx` for
    beetle_psx), to the profile's page, and an alias profile's own name to
    the page of the profile it is an alias of. A name two profiles claim, or one
    that is already a page's address, is left out. Addresses are written
    under the site root, without its base. ``moved`` adds pages that moved
    by generation, old page to new page, the new one with an optional
    #fragment. A page MOVED_PAGES names keeps that target over the part
    record: cross-reference-minui is answered on MinUI's own page."""
    def address(rel: str) -> str:
        page, _, fragment = rel.partition("#")
        return "/" + page_url(page)[len(BASE):] + (f"#{fragment}" if fragment else "")

    out = {address(old): address(new) for old, new in {**(moved or {}), **MOVED_PAGES}.items()
           if old not in present and new.partition("#")[0] in present}
    pages = {rel.casefold() for rel in present}
    claims: dict[str, set[str]] = {}
    for key, profile in profiles.items():
        if f"emulators/{key}.md" not in present:
            continue
        for name in profile.get("cores") or []:
            name = str(name)
            if _CORE_NAME.fullmatch(name) and name != key:
                claims.setdefault(name, set()).add(key)
    # An alias profile has no page of its own: its name is the address of
    # the profile it designates (emulators/vba_m/ is VBA-M's, under vbam).
    for key, profile in profiles.items():
        target = str(profile.get("alias_of") or "")
        if (profile.get("type") == "alias" and _CORE_NAME.fullmatch(key)
                and f"emulators/{target}.md" in present):
            claims.setdefault(key, set()).add(target)
    for name, keys in sorted(claims.items()):
        if len(keys) == 1 and f"emulators/{name}.md".casefold() not in pages:
            out[address(f"emulators/{name}.md")] = address(f"emulators/{next(iter(keys))}.md")
    return out


def _links(items: list[dict]) -> Iterator[dict]:
    for entry in items:
        if "link" in entry:
            yield entry
        else:
            yield from _links(entry["items"])


# The picker's data


def picker_data(install: Path, out: Path, titles: dict[str, str]) -> int:
    """Each manifest, compacted to what the file picker reads: per file its
    destination, size and systems, the systems install.py --system accepts.
    `titles` names a system id the way its system page does.
    """
    out.mkdir(parents=True, exist_ok=True)
    index = []
    for manifest in sorted(install.glob("*.json")):
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "files" not in data or "platform" not in data:
            continue
        systems = sorted({s for f in data["files"] for s in f.get("systems") or []})
        position = {s: k for k, s in enumerate(systems)}
        names = data.get("system_names") or {}
        payload = {
            "platform": data["platform"],
            "name": data.get("display_name", data["platform"]),
            "folder": (data.get("detect") or [{}])[0].get("bios_path", ""),
            "generated": data.get("generated", ""),
            "systems": [{"id": s, "title": titles.get(s, ""), "native": names.get(s, [])}
                        for s in systems],
            "other": any(not f.get("systems") for f in data["files"]),
            "files": [[f["dest"], f.get("size", 0), [position[s] for s in f.get("systems") or []]]
                      for f in sorted(data["files"], key=lambda f: f["dest"])],
        }
        (out / f"{data['platform']}.json").write_text(
            json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        index.append({"platform": data["platform"], "name": payload["name"],
                      "files": len(payload["files"])})
    index.sort(key=lambda entry: entry["name"].casefold())
    (out / "index.json").write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
    return len(index)


def quote_url(url: str) -> str:
    return urllib.parse.quote(url, safe="/:#?=&%")
