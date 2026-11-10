"""The site speaks without personal pronouns.

Every page is written as an instruction or a plain statement: "Open the
Start menu.", "The installer finds the BIOS folder." No I, we, you or their
forms in the wiki sources, the pages the generators write, the README and
CONTRIBUTING, llms.txt or the agent skill. Code, URLs, markup and anchor ids
are not prose.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import html
import re
import subprocess
import sys
import unittest
from functools import cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "website" / "src" / "content" / "docs"

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


def _hits(paths: list[Path]) -> list[str]:
    return [
        f"{path.relative_to(ROOT)}:{number}: {line}"
        for path in paths
        for number, line in pronouns(path.read_text(encoding="utf-8"))
    ]


@cache
def _generated() -> bool:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_site.py")],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    return result.returncode == 0


class Scanner(unittest.TestCase):
    def test_code_urls_and_anchors_are_not_prose(self):
        text = (
            "Run `install.py --help` first.\n"
            "```\nyou are here\n```\n"
            "See https://example.org/your/page and [a link](our-page.md).\n"
            "## Get the files { #get-your-files }\n"
            '<a title="your title">Open the menu</a>\n'
            "A US BIOS, Quake II I mean.\n"
        )
        self.assertEqual(pronouns(text), [(8, "A US BIOS, Quake II I mean.")])

    def test_each_form_is_found_in_any_case(self):
        for word in ("I", "me", "My", "mine", "we", "Us", "OUR", "you", "Yours",
                     "yourselves", "you're", "I'm"):
            with self.subTest(word=word):
                self.assertTrue(pronouns(f"Then {word} copy it."))

    def test_a_word_holding_the_letters_passes(self):
        self.assertEqual(pronouns("Usage of the menu, mine-craft, youth."), [])


class SitePronouns(unittest.TestCase):
    def test_wiki_sources(self):
        hits = _hits(sorted((ROOT / "wiki").glob("*.md")))
        self.assertEqual(hits, [], "\n".join(hits))

    def test_readme_and_contributing(self):
        hits = _hits([ROOT / "README.md", ROOT / "CONTRIBUTING.md"])
        self.assertEqual(hits, [], "\n".join(hits))

    def test_generated_pages(self):
        if not _generated():
            self.fail("scripts/generate_site.py failed")
        pages = sorted(p for p in DOCS.rglob("*") if p.suffix in (".md", ".mdx"))
        self.assertTrue(pages)
        hits = _hits(pages)
        self.assertEqual(hits, [], "\n".join(hits[:200]))

    def test_agent_files(self):
        if not _generated():
            self.fail("scripts/generate_site.py failed")
        public = ROOT / "website" / "public"
        files = [public / "llms.txt", *sorted((public / "skills").rglob("*.md"))]
        self.assertTrue(all(path.is_file() for path in files))
        hits = _hits(files)
        self.assertEqual(hits, [], "\n".join(hits))

    def test_release_notes(self):
        """The release page is public text too. Rendered from the committed
        record, and once more with a pack in parts, its own paragraph."""
        sys.path.insert(0, str(ROOT / "scripts"))
        import release_notes
        import release_record

        record = release_record.load_record(ROOT / "release.json")
        first = next(iter(record["packs"]))
        parted = {**record, "packs": {**record["packs"], first: {
            **record["packs"][first], "assets": ["a.part1of2.zip", "a.part2of2.zip"]}}}
        platforms = str(ROOT / "platforms")
        hits = [f"release notes:{number}: {line}"
                for sample in (record, parted)
                for number, line in pronouns(release_notes.render(sample, platforms, "x"))]
        self.assertEqual(hits, [], "\n".join(hits))

    def test_every_allowed_quote_says_why(self):
        for quoted, reason in {**NAMES, **INSTALLER, **SOURCE}.items():
            with self.subTest(quoted=quoted):
                self.assertTrue(reason.strip())


if __name__ == "__main__":
    unittest.main()
