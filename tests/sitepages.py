"""The generated site pages, for the tests that read them.

generate_site.py writes each page into the Starlight project's content
collection, as .md or as .mdx when it uses a component. A test names a
page by its docs path (``which-pack.md``) and gets whichever file holds it.
The built site, the public data, the navigation the generator writes and the
pronoun scanner are read here too.
"""

from __future__ import annotations

import tests

import html
import os
import re
import unittest
from pathlib import Path

from core import anchors as core_anchors
from model.platforms import load_platform_config
from model.registry import list_registered_platforms, load_platform_registry
from sitegen import emulatorsindex, nav as sitegen_nav, starlight as sitestarlight
from sitegen.guidedata import device_groups

REPO_ROOT = tests.REPO_ROOT
CONTENT = REPO_ROOT / "website" / "src" / "content" / "docs"
DIST = REPO_ROOT / "website" / "dist"
PUBLIC = REPO_ROOT / "website" / "public"
API = PUBLIC / "api" / "v1"
SITE = "https://abdess.github.io/retrobios/"


def built(path: Path) -> Path:
    """path, or a skip when the build that writes it has not run."""
    if not path.exists():
        raise unittest.SkipTest(f"{path.relative_to(REPO_ROOT)} not generated")
    return path


def require() -> Path:
    """The content folder, or a skip when the site was not generated (a
    failure in CI, which generates it before the suite)."""
    # The home page is MDX once it holds a component (the install demo):
    # looking for index.md alone skipped every page test here and failed
    # them all in CI.
    if not page("index.md").is_file():
        if os.environ.get("CI"):
            raise AssertionError("CI generates the site before the suite")
        raise unittest.SkipTest("site not generated (python scripts/generate_site.py)")
    return CONTENT


def page(name: str) -> Path:
    """The file of a page named by its docs path."""
    stem = name[:-3] if name.endswith(".md") else name
    for suffix in (".md", ".mdx"):
        candidate = CONTENT / f"{stem}{suffix}"
        if candidate.is_file():
            return candidate
    return CONTENT / f"{stem}.md"


def pages() -> list[Path]:
    """Every page file, sorted."""
    root = require()
    return sorted(p for p in root.rglob("*") if p.suffix in (".md", ".mdx"))


def name(path: Path) -> str:
    """A page file's docs path, the name tests use for it."""
    return path.relative_to(CONTENT).with_suffix(".md").as_posix()


def generator_sources() -> list[Path]:
    """Every module whose strings reach a page: the commands that write the
    site, each module of scripts/sitegen/, the guides and system names it
    prints, and the pack README writer. Listed by glob, so text moved
    between the site modules stays under the guards that read it."""
    scripts = REPO_ROOT / "scripts"
    return sorted({*scripts.glob("site*.py"), scripts / "generate_site.py",
                   *(scripts / "sitegen").glob("*.py"), scripts / "model" / "guides.py",
                   scripts / "model" / "systemnames.py", scripts / "packs" / "readme.py"})


def _nav() -> list:
    platforms = REPO_ROOT / "platforms"
    registry = load_platform_registry(str(platforms))
    coverages = {
        key: {"platform": load_platform_config(key, str(platforms))["platform"]}
        for key in list_registered_platforms(str(platforms))
    }
    manufacturers = {"Sony": {}, "Sega": {}, "ScummVM": {}}
    profiles = {
        "duckstation": {"emulator": "DuckStation", "systems": ["sony-playstation"]},
        "dolphin": {"emulator": "Dolphin", "systems": ["nintendo-gamecube"]},
        "mame": {"emulator": "MAME", "systems": ["arcade"]},
    }
    return sitegen_nav.generate_nav(coverages, manufacturers, profiles, registry)


def _targets(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return set().union(*(_targets(v) for v in value)) if value else set()
    return set().union(*(_targets(v) for v in value.values()))


def _present(nav: list) -> set[str]:
    return {t for t in _targets(nav) if not t.startswith("http")}


def _index_anchors(markdown: str) -> set[str]:
    """The heading ids a generated page carries once written."""
    _title, title_id, body = sitestarlight.split_title(markdown)
    return sitestarlight.heading_ids(sitestarlight.pin_heading_ids(body, title_id))


ANCHORS = {
    "platforms/index.md": {core_anchors.toc_slug(label) for label, _ in device_groups().values()},
    "systems/index.md": {"consoles-and-computers"},
    "emulators/index.md": _index_anchors(emulatorsindex.generate_emulators_index({
        "duckstation": {"emulator": "DuckStation", "systems": ["sony-playstation"]},
        "dolphin": {"emulator": "Dolphin", "systems": ["nintendo-gamecube"]},
        "mame": {"emulator": "MAME", "systems": ["arcade"]},
    })),
}


PRONOUN = re.compile(
    r"(?<![\w-])((?-i:I)|me|my|mine|myself|we|us|our|ours|ourselves"
    r"|you|your|yours|yourself|yourselves)(?![\w-])",
    re.I,
)

FENCED = re.compile(r"^[ \t]*(```|~~~).*?^[ \t]*\1[^\n]*$", re.S | re.M)
INLINE_CODE = re.compile(r"(`+)(?:(?!\n\n)[^`])*?\1")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
SCRIPT_STYLE = re.compile(r"<(script|style|pre|code)\b.*?</\1>", re.S | re.I)
TAG = re.compile(r"</?[A-Za-z][^<>]*>")
ENTITY = re.compile(r"&#(?:\d+|x[0-9a-fA-F]+);")
URL = re.compile(r"(?:https?|ftp|smb)://\S+|\bwww\.\S+")
LINK_TARGET = re.compile(r"\]\([^)\s]*(?:\s+\"[^\"]*\")?\)|^\[[^\]]+\]:\s*\S+.*$", re.M)
ANCHOR = re.compile(r"\{[^{}\n]*#[^{}\n]*\}")
PATHLIKE = re.compile(r"\S*[/\\]\S*")
# File names, domains and dotted initials: baserom.us.z64, delete.me, A.I.R.
DOTTED = re.compile(r"[\w-]+(?:\.[\w-]+)+\.?")
# A list of single letters or digits (D, F, I, P), or of lowercase option
# values in parentheses (euro, us, asia), names keys, not people.
LETTERS = re.compile(r"(?<!\w)[A-Z0-9](?:,\s?[A-Z0-9#@^](?!\w))+")
VALUES = re.compile(r"\((?:[a-z][\w-]*, )+[a-z][\w-]*\)")
LETTER_HEADING = re.compile(r"^#+ [A-Z]\s*$", re.M)
# Search keywords, written the way readers type a query. Pagefind matches
# them, the page never shows them.
TERMS = re.compile(r"^terms: .*$", re.M)
# A capitalised "US" names the country and its region code.
COUNTRY = re.compile(r"(?<![\w-])US(?![\w-])")

# Proper names that hold one of the words.
NAMES: dict[str, str] = {
    r"I(?:'|''|&#x27;|&#39;)Max": "I'Max MACS, an arcade board maker",
    r"My (?:Old)?Boy!": "My Boy! and My OldBoy!, Android emulators",
    r"My Vision": "Nichibutsu My Vision, a console",
    r"On My iPhone": "the Files app location on iOS",
    r"Us vs Them": "a game title",
    r"Aliens Ate My Railway|Fell Apart On Me": "OpenTTD music track titles",
    r"\b(?:Model|Level|Series|Mk|MK|Ultima|Interface|Type) I\b(?!')":
        "a roman numeral in a machine or game name (Model I, Ultima I)",
    r"\bI(?= \([A-Z])": "a model letter, I (Palladium)",
    r"Java ME": "Java ME, the mobile Java platform",
    r"\bME(?=,? (?:and )?MA\b)": "FM Towns ME, a model name beside the MA (geartowns)",
    r"laseractive us(?=:)": "the LaserActive region key of geargrafx's BIOS list",
}

# Program output quoted word for word. INSTALLER holds install.py's own
# messages, empty since the installer speaks without pronouns. SOURCE holds what an emulator prints, quoted in its
# profile from the emulator's code, which this project does not write.
INSTALLER: dict[str, str] = {}
SOURCE: dict[str, str] = {
    "You do not have a ROM image installed for Model": "sdltrs message, emulators/sdl2trs.yml",
    "You might not get sound because": "lindbergh-loader message, emulators/lindbergh-loader.yml",
    '"Your Card"': "KEGS disk name, emulators/kegs.yml",
    "How do I use SC3000": "MG.html question title, emulators/mastergear.yml",
    "How do I use SF7000 disk images?": "MG.html question title, emulators/mastergear.yml",
    "There is no version of MG for my Unix!": "MG.html question title, emulators/mastergear.yml",
    "rename your own SFX dat file to this name": "Zelda Classic README, emulators/zc210.yml",
    "Could not load ROM images! You must supply these.":
        "hypseus message, emulators/hypseus-singe.yml",
    "Please copy pak0.pk3 from the 'etmain' path of your":
        "ET: Legacy message, emulators/etlegacy.yml",
    '"keyconf.dat(us)"': "file name px68k ships, emulators/px68k-sdl.yml",
}

_SPACED = [
    re.compile(r"\s+".join(map(re.escape, phrase.split())))
    for phrase in (*INSTALLER, *SOURCE)
]
_NAMES = [re.compile(pattern) for pattern in NAMES]


def _blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match[0])


def prose(text: str) -> str:
    """The text of a page with everything that is not prose blanked."""
    for pattern in (HTML_COMMENT, SCRIPT_STYLE, TAG):
        text = pattern.sub(_blank, text)
    # &#95; and &#x27; spell a file name or a name: read them as characters.
    text = ENTITY.sub(lambda m: html.unescape(m[0]), text)
    for pattern in (
        *_SPACED, FENCED, INLINE_CODE, LINK_TARGET, URL, ANCHOR, PATHLIKE,
        TERMS, *_NAMES, DOTTED, LETTERS, VALUES, LETTER_HEADING, COUNTRY,
    ):
        text = pattern.sub(_blank, text)
    return text


def pronouns(text: str) -> list[tuple[int, str]]:
    """(line number, line) for each prose line holding a personal pronoun."""
    lines = text.splitlines()
    return [
        (number, lines[number - 1].strip())
        for number, line in enumerate(prose(text).splitlines(), 1)
        if PRONOUN.search(line)
    ]
