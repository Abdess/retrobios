"""Wiki pages made ready for the site: figures, local images, install tabs, options glance, hidden hashes."""

from __future__ import annotations

import json
import re
import urllib.parse
from collections import Counter
from functools import cache
from pathlib import Path

from core.paths import REPO_ROOT
from sitegen import markup
from sitegen.diagrams import IMAGE_IDS, figure_html


PLACEHOLDER = re.compile(r"(?m)^([ \t]*)<!--\s*image:\s*([A-Za-z0-9_-]+)\s*-->[ \t]*$")
PLACEHOLDER_ANYWHERE = re.compile(r"<!--\s*image:\s*([A-Za-z0-9_-]+)\s*-->")


def resolve_images(markdown: str) -> str:
    """Replace each image placeholder line with its figure.

    An unknown id is left in place: validate_site reports the comment in the
    built page, and the test of placeholders names it.
    """
    if "<!--" not in markdown:
        return markdown
    seen: Counter[str] = Counter()

    def replace(match: re.Match[str]) -> str:
        indent, image_id = match.group(1), match.group(2)
        if image_id not in IMAGE_IDS:
            return match.group(0)
        seen[image_id] += 1
        html = figure_html(image_id, seen[image_id], inline=bool(indent))
        return "\n".join(indent + line for line in html.split("\n"))

    resolved = PLACEHOLDER.sub(replace, markdown)
    return markdown if resolved == markdown else resolved


def unresolved_images(markdown: str) -> list[str]:
    return [m for m in PLACEHOLDER_ANYWHERE.findall(markdown) if m not in IMAGE_IDS]


# Local copies of images the site used to load from other hosts.

LOGO_DIR = REPO_ROOT / "docs_assets" / "logos"
ICON_DIR = REPO_ROOT / "docs_assets" / "system-icons"
SITE_LOGO_DIR = "assets/logos"
SITE_ICON_DIR = "assets/system-icons"
IMAGE_LINK = re.compile(r"(!\[[^\]\n]*\]\()(https?://[^)\s]+)(\))")
IMG_SRC = re.compile(r'(<img\b[^>]*?\bsrc=")(https?://[^"]+)(")')


@cache
def local_images() -> dict[str, str]:
    """Remote URL -> path under the site root, from the two source manifests."""
    mapping: dict[str, str] = {}
    for directory, site_dir in ((LOGO_DIR, SITE_LOGO_DIR), (ICON_DIR, SITE_ICON_DIR)):
        manifest = directory / "sources.json"
        if not manifest.is_file():
            continue
        for entry in json.loads(manifest.read_text(encoding="utf-8"))["images"]:
            mapping[entry["source"]] = f"{site_dir}/{entry['file']}"
    return mapping


def localize_images(markdown: str, page: Path) -> str:
    """Point image links with a local copy at that copy, relative to *page*.

    *page* is the page's path under the docs root. A remote image with no
    local copy is left as written, and validate_site refuses it.
    """
    if "http" not in markdown:
        return markdown
    mapping = local_images()
    depth = len(page.parts) - 1
    prefix = "../" * depth

    def swap(match: re.Match[str]) -> str:
        local = mapping.get(match.group(2))
        if local is None:
            return match.group(0)
        return match.group(1) + prefix + urllib.parse.quote(local) + match.group(3)

    return IMG_SRC.sub(swap, IMAGE_LINK.sub(swap, markdown))


# Installer commands on wiki pages. The page keeps the Linux line, readable
# where the Markdown is read as is, and the site shows it in one tab per
# system, the Windows form written by the same function as the setup pages'.

OS_TABS = re.compile(
    r"(?m)^(?P<indent>[ \t]*)<!--\s*os-tabs(?P<own>(?:\s+[^\n]*?)?)\s*-->[ \t]*\n"
    r"(?P=indent)```(?:sh|bash)[^\n]*\n(?P<body>.*?)\n(?P=indent)```[ \t]*$",
    re.S,
)
OS_TAB_KEYS = ("windows", "macos", "linux", "steamdeck")
_OWN_ARGS = re.compile(r"(?:^|\s)(" + "|".join(OS_TAB_KEYS) + r"):\s*")
FENCE_TITLES = {"sh": "Terminal", "powershell": "PowerShell"}


def _installer_args(body: str) -> str:
    """The options of a one-line install command, continuation lines joined."""
    from model.guides import install_sh

    line = " ".join(part.strip().rstrip("\\").strip() for part in body.splitlines())
    match = re.fullmatch(rf"curl -fsSL {re.escape(install_sh())} \| sh(?: -s -- (.+))?", line)
    if not match:
        raise ValueError(f"an os-tabs block holds no install command: {line!r}")
    return match.group(1) or ""


def _own_args(text: str) -> dict[str, str]:
    """`windows: ARGS macos: ARGS` -> the options each named tab uses."""
    parts = _OWN_ARGS.split(text.strip())
    if parts[0].strip():
        raise ValueError(f"an os-tabs marker names no system: {text.strip()!r}")
    return {key: value.strip() for key, value in zip(parts[1::2], parts[2::2])}


def expand_commands(markdown: str) -> str:
    """Each install command marked `<!-- os-tabs -->` as Windows, macOS,
    Linux and Steam Deck tabs. `<!-- os-tabs windows: ARGS macos: ARGS -->`
    gives a tab its own options, for a folder that differs there."""
    if "os-tabs" not in markdown:
        return markdown
    from model.guides import terminals, install_command

    def replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        args = _installer_args(match.group("body"))
        own_args = _own_args(match.group("own"))
        items = []
        for key in OS_TAB_KEYS:
            label, _how, shell = terminals()[key]
            own = own_args.get(key) or args
            items.append((label, [f'```{shell} title="{FENCE_TITLES[shell]}"',
                                  install_command(shell, own), "```"]))
        return "\n".join(markup.tabs(items, indent)).rstrip("\n")

    return OS_TABS.sub(replace, markdown)


# The installer page's glance groups its options by task. The list is
# written from the parser when the page is built: an option the parser
# gains and no group names lands under "Other", never off the page.
GLANCE_HEADING = "## Options at a glance"
GLANCE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Where and for what", ("--platform", "--dest", "--target", "--every-board", "--save-dir",
                            "--romm-firmware", "--standalone-copies", "--add-app")),
    ("Fewer files", ("--for-games", "--required-only", "--all-files", "--system", "--core", "--emulator",
                     "--standalone", "--region", "--one-per-slot", "--no-game-data",
                     "--declared-only", "--source", "--find", "--installed-cores",
                     "--cores-dir")),
    ("Look first", ("--check", "--dry-run", "--list-platforms", "--list-targets",
                    "--list-systems", "--list-cores", "--list-emulators")),
    ("From files on hand", ("--from", "--from-pack", "--manifest", "--offline")),
    ("Make a pack", ("--pack", "--split")),
    ("Remove and put back", ("--remove", "--file", "--misplaced", "--backup", "--backups",
                             "--restore", "--delete-backup")),
    ("How the run talks", ("--tui", "--plain", "--no-input", "--yes", "--quiet", "--verbose",
                           "--events", "--json", "--jobs", "--version", "--help")),
)
GLANCE_OTHER = "Other"


def installer_flags() -> list[str]:
    """Each option's first flag, in the order --help lists them."""
    from installer_build.installerdoc import parser_options

    return [flags[0] for flags, _metavar in parser_options()]


def options_glance() -> list[str]:
    """One line per group of the glance, each option a link to its row."""
    flags = installer_flags()
    groups = [(label, [flag for flag in members if flag in flags]) for label, members in GLANCE_GROUPS]
    named = {flag for _label, members in GLANCE_GROUPS for flag in members}
    groups.append((GLANCE_OTHER, [flag for flag in flags if flag not in named]))
    return [
        f"- **{label}**: " + ", ".join(f"[`{flag}`](#option-{flag.lstrip('-')})" for flag in members)
        for label, members in groups if members
    ]


def expand_glance(markdown: str) -> str:
    """The glance's list, after the sentence that opens the section."""
    start = markdown.find(f"\n{GLANCE_HEADING}\n")
    if start == -1:
        return markdown
    body_start = start + len(GLANCE_HEADING) + 2
    end = markdown.find("\n## ", body_start)
    end = len(markdown) if end == -1 else end
    body = markdown[body_start:end].strip("\n")
    if any(line.startswith("- ") for line in body.splitlines()):
        raise ValueError(f"{GLANCE_HEADING}: the list is written from install.py's parser, "
                         "not by hand")
    return (markdown[:body_start] + "\n" + body + "\n\n" + "\n".join(options_glance())
            + "\n" + markdown[end:])


# Example hashes in the documentation stay out of search, so a hash typed in
# the search box finds the file card that holds it, not a page quoting it.

HASH_SPAN = re.compile(r"`[^`\n]*\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b[^`\n]*`")
HASH_TEXT = re.compile(r"\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b")
FENCE = re.compile(r"(?m)^(?P<indent>[ \t]*)(?P<mark>```|~~~)[^\n]*\n.*?\n(?P=indent)(?P=mark)[ \t]*$", re.S)


def hide_hashes(markdown: str) -> str:
    """Wrap each code block and code span quoting a hash in a search exclusion."""
    if not HASH_TEXT.search(markdown):
        return markdown
    attribute = markup.search_exclude()
    pieces: list[str] = []
    position = 0
    for match in FENCE.finditer(markdown):
        pieces.append(HASH_SPAN.sub(lambda m: f"<span {attribute}>{m.group(0)}</span>",
                                    markdown[position:match.start()]))
        block = match.group(0)
        if HASH_TEXT.search(block):
            indent = match.group("indent")
            block = f"{indent}<div {attribute}>\n\n{block}\n\n{indent}</div>"
        pieces.append(block)
        position = match.end()
    pieces.append(HASH_SPAN.sub(lambda m: f"<span {attribute}>{m.group(0)}</span>",
                                markdown[position:]))
    return "".join(pieces)


# The markers scripts/generate_installer_doc.py writes its tables between:
# for the source only, the page shows the table alone.
GENERATED_MARKER = re.compile(r"(?m)^<!-- /?generated: [a-z-]+ -->\n\n?")


def prepare_page(markdown: str, page: Path) -> str:
    """Everything this module does to a page before it is decorated."""
    markdown = expand_glance(expand_commands(resolve_images(localize_images(markdown, page))))
    markdown = GENERATED_MARKER.sub("", markdown)
    if page.parts[:1] == ("wiki",):
        markdown = hide_hashes(markdown)
    return markdown


