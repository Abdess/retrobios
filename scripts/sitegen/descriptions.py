"""Page titles and descriptions, as search engines and link previews read them."""

from __future__ import annotations

import html
import re
from pathlib import Path

from model import releaserecord
from sitegen import measurements as sitemeasurements
from sitegen.config import SITE_NAME


def page_title(markdown: str, path: Path) -> str:
    match = re.search(r"^#\s+(.+?)\s*$", markdown, flags=re.MULTILINE)
    if match:
        title = re.sub(r"<[^>]+>", "", match.group(1))
        return title.replace(f" - {SITE_NAME}", "").strip()
    return path.stem.replace("-", " ").title()


def page_browser_title(relative: Path, title: str) -> str:
    """Return a concise, unique browser/search title for a generated page."""
    key = relative.as_posix()
    index_titles = {
        # Material appends " - RetroBIOS": the home title says what the site
        # is, instead of "RetroBIOS - RetroBIOS".
        "index.md": "BIOS and firmware packs for RetroArch, Batocera and more",
        "platforms/index.md": "Setups",
        "systems/index.md": "Systems",
        "emulators/index.md": "Emulators",
        "wiki/index.md": "Reference",
        "explore.md": "Explore",
    }
    if key in index_titles:
        return index_titles[key]
    # A console page is filed with the parts of its manufacturer's page, and
    # titled "Sega: Dreamcast". A part names its range of files.
    part = key in PART_PAGES and (
        not key.startswith("systems/") or ": " not in title
        or re.search(r", part \d+ of \d+$", title))
    if part:
        return title
    # The words a web search for a console or an emulator types: "dreamcast
    # bios", "duckstation bios". The h1 and the sidebar keep the name.
    if key.startswith("emulators/"):
        has_files = PAGE_DATA.get(key, {}).get("hasPart") and key not in NOTHING_TO_FETCH
        # Lexaloffle, QEMU and ScummVM name a system page too.
        own = " emulator" if f"systems/{relative.name}" in PAGE_DATA else ""
        return f"{title}{own} BIOS files" if has_files else f"{title} emulator"
    if key.startswith("systems/"):
        maker, _, console = title.partition(": ")
        return f"{console} BIOS files ({maker})" if console else f"{title} BIOS files"
    return title


_LINK_TEXT = r"(?:`[^`]*`|\[[^\]\[]*\]|[^\]\[])"


def _plain_markdown(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    # Link text may hold brackets: a code span or a No-Intro name such as
    # `[BIOS] LaserActive PAC-N1 (Japan) (v1.02).bin` left the whole link,
    # anchor included, in the Pioneer page's meta description.
    text = re.sub(rf"!\[({_LINK_TEXT}*)\]\([^)]*\)", r"\1", text)
    text = re.sub(rf"\[({_LINK_TEXT}+)\]\([^)]*\)", r"\1", text)
    # Code spans keep their text whole: validate_schemas.py read
    # validateschemas.py once every underscore was taken for emphasis.
    pieces = re.split(r"(`[^`]*`)", text)
    text = "".join(
        piece.strip("`") if piece.startswith("`")
        else re.sub(r"(?<!\w)_+|_+(?!\w)", "", re.sub(r"[*~]", "", piece))
        for piece in pieces
    )
    return re.sub(r"\s+", " ", text).strip()


def _shorten(plain: str, limit: int = 157) -> str:
    """A description cut at a word, never inside one: six snippets ended
    in "op..." or "Fo..."."""
    if len(plain) <= limit:
        return plain
    cut = plain[: limit + 1].rsplit(" ", 1)[0] if " " in plain[:limit] else plain[:limit]
    return cut.rstrip(" ,;:-(.") + "..."


def page_description(markdown: str, relative: Path, title: str) -> str:
    key = relative.as_posix()
    specific = {
        "index.md": "The BIOS files emulators need, for RetroArch, Batocera, EmuDeck and more: the folder they go in, one command that installs and checks them, and packs to download.",
        "data.md": "Versioned RetroBIOS JSON API, CSV exports, SQLite snapshot, schemas, checksums and data interpretation guidance.",
        "cross-reference.md": "Every emulator core each retrogaming platform runs, the systems it emulates and the upstream project it comes from.",
        "gaps.md": "Current RetroBIOS verification gaps, platform-to-emulator divergences, missing files and documented source limitations.",
        "exports.md": "Each platform's own BIOS list (System.dat, batocera-systems, es_bios.xml and the rest) with the hashes and files the emulator source code shows, offered to its maintainers.",
        sitemeasurements.EXPLORER_PAGE: "The records of emulator cores run headless on demand, each with its claim, verdict, the BIOS it ran, method, computer and full record, filterable, and as SQLite.",
        "provenance.md": "Hash-based comparison of RetroBIOS metadata with No-Intro, Redump and TOSEC catalog snapshots.",
        "explore.md": "Systems, emulators and installer options to explore, with the figures of the BIOS collection.",
        "which-pack.md": "Pick a device or setup and get its BIOS files: the folder they go in, one command that installs and checks them, or a ZIP pack to extract.",
        "contributing.md": "Add a BIOS file the collection lacks from the browser, checked on arrival, or add a platform or an emulator profile.",
        "wanted.md": "Every file the collection lacks, by system, each with its upload button to GitHub. Drop files on the page to learn if they are wanted.",
    }
    if key in specific:
        return specific[key]
    # What a search engine shows is the page's own first sentence: 707 pages
    # shared five templates of level 3 words ("source-pinned", "provenance").
    browser = page_browser_title(relative, title)
    held = re.search(r"\bThis part holds (.+?)\.(?: |$)", markdown, re.M)
    if key in PART_PAGES and held:
        return _shorten(f"{browser}. This part holds {_plain_markdown(held[1])}.", 155)
    lead = _lead(markdown)
    if key in PART_PAGES and re.search(r"\bpart \d+ of \d+", title):
        # The parts of one list open on the same sentence.
        first = _first_paragraph(lead) or _first_paragraph(markdown)
        return _shorten(f"{title}. {first}", 155)
    described = _section_description(markdown, relative, title, browser, lead)
    if described is not None:
        return described
    first = _first_paragraph(lead, minimum=35)
    questions = [_plain_markdown(re.sub(r"\s*\{[^}]*\}\s*$", "", heading))
                 for heading in re.findall(r"^## (.+\?)(?:[ \t]*\{[^}]*\})?[ \t]*$", markdown, re.M)]
    if not first and len(questions) >= 3:
        # A page of questions with no intro: its first paragraph is the
        # answer to one of them ("Run the command with --dry-run").
        return _shorten(f"{title}: {' '.join(questions)}", 155)
    first = first or _first_paragraph(markdown, minimum=35)
    if first:
        return _shorten(first, 155)
    return f"{title}: RetroBIOS source-traced retrogaming firmware reference."


def _section_description(markdown: str, relative: Path, title: str, browser: str,
                         lead: str) -> str | None:
    """The description of a download, system, emulator or platform page,
    or None for a page of another section."""
    key = relative.as_posix()
    if key.startswith(f"{releaserecord.GET_DIR}/"):
        size = re.search(r"^- (.+ to download\b.*?)\.?$", markdown, re.M)
        if size:
            return _shorten(f"{title}: the BIOS pack of this setup, {_plain_markdown(size[1])}. "
                            "The address stays the same and always gives the latest ZIP.", 155)
        return _shorten(_first_paragraph(lead) or title, 155)
    if key.startswith("systems/") and relative.stem != "index":
        return _system_description(markdown, browser)
    if key.startswith("emulators/") and relative.stem != "index":
        return _emulator_description(markdown, key, title, _first_paragraph(lead))
    if key.startswith("platforms/") and relative.stem != "index":
        # The summary ends on a link to the platform's site, whose label
        # alone was left: "A system for handhelds. ROCKNIX website."
        summary = _first_paragraph(lead).removesuffix(f" {title} website.")
        return _shorten(f"The BIOS files for {title}, the folder they go in and the "
                        f"command that installs them. {summary}", 155)
    return None


def _lead(markdown: str) -> str:
    """The text a page opens with, before its first section, details
    block or ignored section (the install box, the profile table)."""
    return re.split(r"^(?:## |<details|<section)", markdown, maxsplit=1, flags=re.M)[0]


def _emulator_description(markdown: str, key: str, title: str, intro: str) -> str:
    """An emulator page by its intro sentence ("DuckStation emulates Sony
    PlayStation. It picks the BIOS for the game's region: ..."), or by
    its profile table when the profile names no system."""
    notes = re.search(r"<summary>Technical notes</summary>\s*\n\n(.+?)(?:\n\n|$)", markdown, re.S)
    if not intro and notes:
        # An initial is no sentence end: hcl's read "open-source port of E."
        sentence = re.split(r"(?<![\s(][A-Z]\.)(?<=\.)\s", _plain_markdown(notes[1]),
                            maxsplit=1)[0]
        intro = f"{title}: {sentence[:1].lower()}{sentence[1:]}"
    if not intro:
        row = {name: _plain_markdown(value) for name, value in re.findall(
            r"^\| (Type|Classification|Version) \| (.+?) \|$", markdown, re.M)}
        kind = row.get("Classification") or row.get("Type") or "emulator"
        # The cell goes on to say where the version is read: the intro
        # keeps the version alone.
        version = row.get("Version", "").split(", ")[0]
        known = f", version {version}" if version and version[0].isdigit() else ""
        intro = f"{title}: {kind.lower()}{known}."
    elif title not in intro:
        # "It reads 1 file": the profile names no system to open on.
        intro = f"{title}: {intro[:1].lower()}{intro[1:]}"
    if key in NOTHING_TO_FETCH:
        return _shorten(f"{intro} Every file it reads comes with the app.", 155)
    if PAGE_DATA.get(key, {}).get("hasPart"):
        return _shorten(_files_snippet(markdown, key, title, intro), 155)
    # An alias page sends the reader to the core whose files it shares.
    if "uses the same firmware as" in intro:
        return _shorten(intro, 155)
    needs = "It needs no BIOS or firmware file."
    if "\n## Data directories" in markdown:
        needs = "It needs no BIOS or firmware file, only the data folders listed."
    return _shorten(f"{intro} {needs}", 155)


def _files_snippet(markdown: str, key: str, title: str, intro: str) -> str:
    """The snippet of an emulator page with files to get.

    A search for "gba_bios.bin" or "scph5500.bin" landed on a page described
    as "It reads 4 files, none of them required": the names the reader typed
    were not in the result, and fewer than 1 in 70 clicked. The longest
    form that fits is kept: a snippet cut by "..." reads as unfinished.
    """
    if " any region." in intro:
        step = ("Download one from this page and put it in the folder it shows."
                if re.search(r"^1\. Download ", _lead(markdown), re.M)
                else "Where to get one and the folder it goes in.")
        head = f"{intro.split(' any region.')[0]} any region."
        forms = [f"{head} {step} Any file name works.", f"{head} {step}"]
        return next((form for form in forms if len(form) <= 155), intro)
    snippet = EMULATOR_SNIPPETS.get(key)
    if not snippet or not snippet[1] or "It reads " not in intro:
        return intro
    system, names, required, noun = snippet
    if required == 0:
        need = "none required"
    elif required == len(names):
        need = "all required" if len(names) > 1 else "required"
    else:
        need = f"{required:,} required"
    subject = f"{system} {noun} for {title}" if system else f"{title} {noun}"
    tails = ["Where each goes, its hashes and one command that installs them."
             if "Install this emulator's files" in markdown else "",
             "Where each goes and its hashes.", "Where each goes."]
    forms = []
    for count in range(min(len(names), 4), 0, -1):
        shown = (names if count == len(names)
                 else [*names[:count - 1], f"{len(names) - count + 1:,} more"])
        head = f"{subject}: {said_as_list(shown)}, {need}."
        forms += [f"{head} {tail}" for tail in tails if tail] + [head]
    return next((form for form in forms if len(form) <= 155), intro)


# Lines a page opens with that say where it sits, not what it holds.
_PLACE_LINES = ("Part of ", "This part holds ", "On a card, ")


def _first_paragraph(markdown: str, minimum: int = 1) -> str:
    """The first paragraph of prose of a page body, as plain text: no
    heading, table, list, fence, admonition or HTML block, and none that
    only says where the page sits."""
    for paragraph in re.split(r"\n\s*\n", markdown):
        stripped = paragraph.strip()
        if (
            not stripped
            or stripped.startswith(("#", "|", "```", "???", ":::", "<", "- ", "* ", "import "))
        ):
            continue
        plain = _plain_markdown(stripped)
        if plain.startswith(_PLACE_LINES):
            continue
        # A paragraph that ends on a colon introduces what follows: alone,
        # it describes nothing ("One file needs no clone and no local setup:").
        if len(plain) >= minimum and not plain.endswith(":"):
            return plain
    return ""


# Section headings of a system page that are not a console.
_NOT_A_CONSOLE = {"Next steps", "Files", "Other files"}
_CARD_TITLE = re.compile(r'class="rb-file-title"[^>]*><code>([^<]+)</code>')


def _system_description(markdown: str, browser: str) -> str:
    """A system page by what it holds: a manufacturer page by its consoles,
    a console page by its "Start with" line, else by its first files."""
    consoles = [
        _plain_markdown(re.sub(r"\s*\{[^}]*\}\s*$", "", heading))
        for heading in re.findall(r"^## (.+?)[ \t]*$", markdown, re.M)
    ]
    consoles = [name for name in consoles if name and name not in _NOT_A_CONSOLE]
    if len(consoles) > 1:
        shown = consoles if len(consoles) <= 4 else consoles[:3] + [f"{len(consoles) - 3} more"]
        return _shorten(f"{browser} for {said_as_list(shown)}, one card per file with its "
                        "hashes and the emulators that read it.", 155)
    start = re.search(r"^\*\*Start with\*\*(?P<line>.*)$(?P<list>(?:\n+- .*)*)", markdown, re.M)
    if start:
        # "Start with the files of your machine:" introduces one line per machine.
        machines = [_plain_markdown(item) for item in re.findall(r"^- (.+)$", start["list"], re.M)]
        text = _plain_markdown(start["line"]).lstrip(": ")
        said = "; ".join(machines) if machines and text.endswith(":") else text
        return _shorten(f"{browser}. Start with {said}", 155)
    names = list(dict.fromkeys(html.unescape(name) for name in _CARD_TITLE.findall(markdown)))
    if names:
        shown = names if len(names) <= 3 else names[:3] + [f"{len(names) - 3} more"]
        return _shorten(f"{browser}: {said_as_list(shown)}, with their hashes and the "
                        "emulators that read them.", 155)
    return _shorten(f"{browser}, one card per file with its hashes and the emulators "
                    "that read it.", 155)


# Structured data a page generator knows beyond its text, by page path
# relative to docs/: read by decorate_markdown_pages.
PAGE_DATA: dict[str, dict] = {}
# Emulator pages whose every file comes with the app: no "BIOS files" in
# their title, and their description says so (DaedalusX64, ZEsarUX).
NOTHING_TO_FETCH: set[str] = set()
# The first system, the file names, the count of required names and the
# word for them ("BIOS" or "files") of each emulator page, for its snippet.
EMULATOR_SNIPPETS: dict[str, tuple[str, list[str], int, str]] = {}
# Pages that hold part of a page too long for one (a console of a split
# manufacturer, a run of an emulator's cards), by path relative to docs/:
# their H1 already says what they are.
PART_PAGES: set[str] = set()


def said_as_list(items: list[str]) -> str:
    """"a, b and c"."""
    return ", ".join(items[:-1]) + f" and {items[-1]}" if len(items) > 1 else "".join(items)
