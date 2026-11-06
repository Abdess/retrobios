"""Prose in the repository is written the way its maintainer writes.

Em-dashes, clause-joining semicolons, unicode arrows, the ellipsis character,
box-drawing banners and check-mark emoji had spread through profiles, docs,
comments and command output. None of them is wrong, but the maintainer does
not write them. This module names every place one comes back.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import io
import os
import re
import subprocess
import tokenize
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

GLYPHS = re.compile(
    "[\u2013\u2014\u2026\u2190-\u21ff\u2500-\u257f\u2713-\u2718\u26a0\u2705\u274c]"
)
# A semicolon between two words of prose. Code quoted in prose sits in
# backticks, which are blanked before the search.
CLAUSE_SEMICOLON = re.compile(r"[A-Za-z0-9)\]\"']; [A-Za-z(]")
BACKTICKS = re.compile(r"`[^`\n]*`")
# "1 files", a count the generator printed without its singular.
ONE_PLURAL = re.compile(r"(?<![\w,./])1 (files|issues|entries|emulators|platforms|systems|cores)\b")
FENCED = re.compile(r"^```.*?^```", re.S | re.M)

SKIPPED_TREES = ("bios/", "data/", "recipes/", "provenance/", "install/")
TEXT_SUFFIXES = {
    ".py", ".sh", ".ps1", ".js", ".css", ".md", ".yml", ".yaml", ".html",
    ".txt", ".cfg", ".toml", "",
}
PROSE_KEYS = {
    "notes", "note", "description", "exclusion_note", "size_note",
    "region_note", "hle_note", "comment", "reason",
}


def _tracked() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    return [
        ROOT / name
        for name in listed
        if not name.startswith(SKIPPED_TREES)
        and Path(name).suffix in TEXT_SUFFIXES
        and (ROOT / name).is_file()
    ]


def _semicolons(text: str) -> list[str]:
    # An HTML character reference (&amp; &#123;) ends in a semicolon that
    # joins no clauses.
    text = re.sub(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", "&", text)
    return [
        line.strip()
        for line in BACKTICKS.sub("``", text).splitlines()
        if CLAUSE_SEMICOLON.search(line)
    ]


def _python_prose(source: str) -> str:
    """Comments and docstrings of a module, one per line."""
    parts: list[str] = []
    previous = tokenize.INDENT
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            parts.append(token.string)
        elif token.type == tokenize.STRING and previous in (
            tokenize.INDENT, tokenize.NEWLINE, tokenize.NL, tokenize.DEDENT,
        ):
            parts.append(token.string)
        if token.type not in (tokenize.COMMENT, tokenize.NL):
            previous = token.type
    return "\n".join(parts)


class _TagTolerantLoader(yaml.SafeLoader):
    """mkdocs.yml names Python callables with !!python/name tags."""


_TagTolerantLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/", lambda loader, suffix, node: None
)


def _yaml_prose(text: str) -> str:
    """Prose scalars and comments of a YAML document."""
    parts = [
        line.split("#", 1)[1]
        for line in text.splitlines()
        if line.lstrip().startswith("#")
    ]

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in PROSE_KEYS and isinstance(value, str):
                    parts.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(yaml.load(text, Loader=_TagTolerantLoader))
    return "\n".join(parts)


# Words a heading keeps capitalized: names of platforms, systems and programs.
_HEADING_KEEP = set("""Batocera Recalbox Lakka Dolphin Redump Linux Windows Android Python Steam Deck
macOS Termux Flatpak Switch Raspberry Pi Mega Drive Genesis Saturn Dreamcast Amiga Atari Sega
Nintendo Sony Neo Geo Lynx Jaguar Commodore Apple Mac Spectrum Sinclair Amstrad MSX GameCube Wii
Game Boy Advance Famicom Disk System Super Master PlayStation Vita Xbox Arcade English French
Spanish I Lua Unity Qt Kodi Discord Pages Actions Docker Windows Mac Ubuntu Debian Arch
SteamOS Chihiro NAOMI Triforce Lindbergh Model PinMAME ScummVM Dinothawr Cemu Citra Yuzu Ryujinx
Mednafen Beetle Stella Hatari Caprice Vice Fuse Daphne Hypseus Singe Supermodel Flycast Redream
DuckStation SwanStation Opera Gearsystem Picodrive Snes9x Nestopia Mesen Gambatte SameBoy
mGBA melonDS DeSmuME Azahar Eden Sudachi Torzu Xemu Cxbx PCSX2 AetherSX2 NetherSX2 ARMSX2
RPCS3 Vita3K Zinc Raine FBNeo FinalBurn Neo MAME Clrmamepro RomVault""".split())


def _sentence_case(title: str) -> str:
    words = title.split(" ")
    out = []
    starts = True
    for w in words:
        core = w.strip("()[],:.")
        if starts:
            # The first word of a heading or of a clause after ":", "." or " - ".
            head, sep, tail = core.partition("-")
            if sep and re.fullmatch(r"[A-Z][a-z]+", tail) and tail not in _HEADING_KEEP:
                w = w.replace(core, f"{head}-{tail.lower()}", 1)
        elif re.fullmatch(r"[A-Z][a-z]+(-[A-Z]?[a-z]+)*", core) and core not in _HEADING_KEEP:
            w = w.replace(core, core.lower(), 1)
        out.append(w)
        starts = w.endswith((":", ".")) or w == "-" or re.fullmatch(r"\d+[a-z]?\.?", w) is not None
    return " ".join(out)


class NoGeneratedTypography(unittest.TestCase):
    def test_no_dash_arrow_ellipsis_or_banner_glyphs(self):
        offenders = []
        for path in _tracked():
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), 1):
                if GLYPHS.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:100]}")
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))


class NoMarketingVocabulary(unittest.TestCase):
    """The project bans these words in published text, and nothing checked
    it: "streamlined interface" reached the site's platform table."""

    WORDS = re.compile(
        r"\b(comprehensive|robust|seamless(ly)?|leverag\w*|streamlin\w*|delv(e|ing))\b",
        re.IGNORECASE,
    )

    def test_no_tracked_text_uses_them(self):
        offenders = []
        for path in _tracked():
            # This file and the commit rules have to name the words they refuse.
            if path.name in {"test_prose_style.py", "commit_rules.py"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), 1):
                if self.WORDS.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:100]}")
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))


class ProfilesStateNoVerdict(unittest.TestCase):
    """A profile note says what the code does, never what is wrong with
    another project's work (wiki/testing-guide.md): emuscv called its
    core's option handling a "code bug"."""

    VERDICTS = [
        re.compile(r"\bcode bug\b", re.IGNORECASE),
        # nosgba said RetroBat "leaves out" a file and "still carries" an
        # older executable: a reproach, where the package's content is a fact.
        re.compile(
            r"\b(RetroArch|Batocera|Recalbox|RetroBat|RetroDECK|EmuDeck|RetroPie|"
            r"Lakka|ROCKNIX|KNULLI|AmberELEC|EmuELEC|RomM|MiSTer)\b[^.]{0,60}?"
            r"\b(leaves out|left out|still carries|forgot|forgets)\b"
        ),
    ]

    def test_no_profile_note_passes_a_verdict(self):
        offenders = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            text = " ".join(path.read_text(encoding="utf-8").split())
            offenders += [
                f"{path.name}: {found.group(0)}"
                for pattern in self.VERDICTS
                for found in pattern.finditer(text)
            ]
        self.assertEqual(offenders, [], "\n".join(offenders))


def _name(*parts: str) -> str:
    """A private name, assembled so that this file does not carry it."""
    return "".join(parts)


_NOTES = _name("cla", "ude")
_VENDOR = _name("anth", "ropic")
_MD_STEMS = (_name("pro", "mpt"), _name("age", "nts"), _name("au", "dit"))
_DOT_DIRS = (
    _NOTES, _name("co", "dex"), _name("cur", "sor"), _name("conti", "nue"),
    _name("copi", "lot"), _name("gem", "ini"), _name("wind", "surf"),
    _name("ser", "ena"), _name("playwright", "-mcp"),
)
_AIDER = _name("ai", "der")


class NoToolingNames(unittest.TestCase):
    """Nothing committed names a path the private exclude list keeps out of
    version control. Two test docstrings did, and history keeps them. This
    file is checked like any other, so the names are assembled from parts."""

    NAMES = re.compile(
        rf"(?i)\b({_NOTES}\w*|{_VENDOR})\b|\b({'|'.join(_MD_STEMS)})\.md\b"
        rf"|\.({'|'.join(map(re.escape, _DOT_DIRS))})/|\.{_AIDER}"
    )

    def test_the_pattern_covers_every_private_name(self):
        """The pattern caught the notes file and missed the other two .md
        files and the notes directory the same exclude list holds."""
        for text in (
            f"see {_NOTES.upper()}.md",
            f"rules live in {_MD_STEMS[1].upper()}.md",
            f"{_MD_STEMS[2].upper()}.md angle G",
            f"notes in {_NOTES}docs/launchers",
            f"{_MD_STEMS[0]}.md",
            f"under .{_NOTES}/hooks",
            f"a .{_DOT_DIRS[2]}/ rule",
            f"the .{_DOT_DIRS[7]}/ cache",
            f".{_AIDER}.conf.yml",
        ):
            with self.subTest(text=text):
                self.assertRegex(text, self.NAMES)
        for text in (
            f"{_MD_STEMS[2]}_regressions", f"{_MD_STEMS[1]} of change",
            f"a {_MD_STEMS[0]} reply",
        ):
            with self.subTest(text=text):
                self.assertNotRegex(text, self.NAMES)

    def test_no_tracked_file_names_them(self):
        offenders = []
        for path in _tracked():
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), 1):
                if self.NAMES.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}")
        self.assertEqual(offenders, [], "\n".join(offenders[:20]))


class NoReviewTags(unittest.TestCase):
    """A comment cites what the code does, never the private review that
    asked for it. About 650 comments and test texts ended on a tag such as
    "(tui review 13, P3-8)" written in its short form, which points at notes
    no clone holds. The pattern is assembled so this file does not match."""

    TAG = re.compile(r"[a-z]+_" + "aud" + r"it_\d+|\(rounds? \d")

    def test_the_pattern_matches_the_short_forms(self):
        for text in ("tui_" + "aud" + "it_13 P3-8", "(" + "round 5, 6.3)",
                     "code_" + "aud" + "it_24"):
            with self.subTest(text=text):
                self.assertRegex(text, self.TAG)
        self.assertNotRegex("test_" + "aud" + "it_regressions", self.TAG)

    def test_no_tracked_file_carries_one(self):
        offenders = []
        for path in _tracked():
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), 1):
                if self.TAG.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}")
        self.assertEqual(offenders, [], "\n".join(offenders[:20]))

    def test_tests_are_named_by_subject(self):
        """Test modules and classes were named after the review that wrote
        them (test_site_r4_p0, a class per review number). A name says what
        the test holds."""
        rounds = sorted(p.name for p in (ROOT / "tests").glob("test_*_r[0-9]_*.py"))
        self.assertEqual(rounds, [])
        classes = []
        for path in sorted((ROOT / "tests").glob("test_*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.match(r"class Audit[A-Z]", line):
                    classes.append(f"{path.name}:{number}")
        self.assertEqual(classes, [])


class ProfilesStateFactsAboutOtherProjects(unittest.TestCase):
    """A profile says what another project's file declares and what the code
    does, never a verdict on that file. Ten notes and comments in ten profiles
    called .info entries "phantom", "misleading" or "incorrectly" written, and
    the site rendered them on the emulator pages."""

    VERDICTS = re.compile(
        r"\b(phantoms?|misleading|bogus|typos?|has errors|incorrectly "
        r"(?:says|lists|declares|states|claims|names|describes))\b",
        re.IGNORECASE,
    )

    # A line that names another project's file grades it when it calls the
    # file correct or accurate, says it still declares something, or that an
    # entry is missing from it or omitted. prosystem, retrodream,
    # fbalpha2012_neogeo and seven more profiles wrote it that way.
    OTHER_FILE = re.compile(r"(\.info\b|core-info|System\.dat)", re.IGNORECASE)
    GRADES = re.compile(
        r"\b(?:is (?:correct|accurate|inaccurate|outdated|stale)|accurate here|"
        r"correct:|still (?:declares|lists)|omits|missing (?:the|from))|"
        r"\.info missing",
        re.IGNORECASE,
    )

    def test_profile_prose_and_comments(self):
        offenders = [
            f"{path.relative_to(ROOT)}: {line.strip()[:100]}"
            for path in sorted((ROOT / "emulators").glob("*.yml"))
            for line in _yaml_prose(path.read_text(encoding="utf-8")).splitlines()
            if self.VERDICTS.search(line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))

    # A project's state is a dated fact or its own words, never a verdict:
    # "Upstream project is dead" (yabause), "abandoned fork" (gearboy).
    PROJECT_VERDICTS = re.compile(
        r"\b(?:(?:project|upstream)(?:\s+project)?\s+(?:is\s+)?dead|"
        r"abandoned\s+(?:fork|since)|project\s+abandoned|never-completed)\b",
        re.IGNORECASE,
    )

    def test_no_verdict_on_a_project(self):
        offenders = [
            f"{path.relative_to(ROOT)}: {found.group(0)}"
            for path in sorted((ROOT / "emulators").glob("*.yml"))
            for found in self.PROJECT_VERDICTS.finditer(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))

    def test_no_grade_on_another_projects_file(self):
        offenders = [
            f"{path.relative_to(ROOT)}: {line.strip()[:100]}"
            for path in sorted((ROOT / "emulators").glob("*.yml"))
            for line in path.read_text(encoding="utf-8").splitlines()
            if self.OTHER_FILE.search(line) and self.GRADES.search(line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))


class NoClauseSemicolons(unittest.TestCase):
    def _check(self, files: list[Path], extract) -> None:
        offenders = []
        for path in files:
            text = path.read_text(encoding="utf-8")
            for line in _semicolons(extract(text)):
                offenders.append(f"{path.relative_to(ROOT)}: {line[:100]}")
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))

    def test_markdown(self):
        files = [p for p in _tracked() if p.suffix == ".md"]
        self._check(files, lambda text: FENCED.sub("", text))

    def test_markdown_headings_are_headings(self):
        """Troubleshooting carried 21 bold lines in place of headings: no
        anchor to link from an issue, no entry in the page's contents."""
        pseudo = re.compile(r"^\*\*[^*]+:\*\*$", re.M)
        offenders = [
            f"{p.relative_to(ROOT)}: {m.group(0)}"
            for p in _tracked() if p.suffix == ".md"
            for m in pseudo.finditer(FENCED.sub("", p.read_text(encoding="utf-8")))
        ]
        self.assertEqual(offenders, [], "\n".join(offenders[:20]))

    def test_bold_labels_do_not_run_together(self):
        """community-tools.md wrote Author, Repository and License on three
        lines of one paragraph: rendered, the three ran on one line."""
        label = r"\*\*[^*\n]+:\*\*"
        run = re.compile(rf"^{label}.*\n{label}", re.M)
        offenders = [
            f"{p.relative_to(ROOT)}: {m.group(0).splitlines()[0]}"
            for p in _tracked() if p.suffix == ".md"
            for m in run.finditer(FENCED.sub("", p.read_text(encoding="utf-8")))
        ]
        self.assertEqual(offenders, [], "\n".join(offenders[:20]))

    def test_wiki_headings_use_sentence_case(self):
        """The gaps page and two wiki pages titled in Title Case ("What Each
        Pack Contains") beside sentence-case pages ("Quick install")."""
        offenders = []
        for page in sorted((ROOT / "wiki").glob("*.md")):
            text = FENCED.sub("", page.read_text(encoding="utf-8"))
            for title in re.findall(r"(?m)^#{1,4} (.+)$", text):
                if _sentence_case(title) != title:
                    offenders.append(f"{page.name}: {title}")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_yaml_prose_and_comments(self):
        files = [p for p in _tracked() if p.suffix in (".yml", ".yaml")]
        self._check(files, _yaml_prose)

    def test_python_comments_and_docstrings(self):
        files = [p for p in _tracked() if p.suffix == ".py"]
        self._check(files, _python_prose)


    def test_python_prose_has_no_lone_dash_asides(self):
        """Removing " -- " asides left 72 comments reading "shape -a size or
        a size range -is all": half a dash glued to the next word. A command
        line flag quoted in prose (MAME's -listxml) is not an aside, and a
        quotation is left alone."""
        lone = re.compile(r"[A-Za-z0-9,)] -(?!listxml\b|lr\b|sa\b)[a-z]{2,}")
        offenders = [
            f"{path.relative_to(ROOT)}: {line.strip()[:100]}"
            for path in _tracked() if path.suffix == ".py"
            for line in re.sub(
                r'`[^`]*`|"[^"\n]*\n?[^"\n]*"',
                "",
                _python_prose(path.read_text(encoding="utf-8")).replace('"""', ""),
            ).splitlines()
            if lone.search(line) and not re.search(r"\b(python|curl|unittest|sh)\b .* -", line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))

    def test_schema_descriptions(self):
        offenders = []
        for path in sorted((ROOT / "schemas").glob("*.json")):
            text = path.read_text(encoding="utf-8")
            for line in _semicolons(text) + GLYPHS.findall(text):
                offenders.append(f"{path.relative_to(ROOT)}: {line[:100]}")
        self.assertEqual(offenders, [], "\n".join(offenders))


class GeneratedSiteProse(unittest.TestCase):
    """The site pages carry strings no tracked file shows verbatim."""

    def test_generated_pages(self):
        import sys  # noqa: PLC0415

        sys.path.insert(0, str(ROOT / "scripts"))
        from generate_site import LOCAL_NOTE_DIRS  # noqa: PLC0415

        from tests import sitepages  # noqa: PLC0415

        pages = [p for p in sitepages.pages()
                 if not set(p.relative_to(sitepages.CONTENT).parts[:-1]) & set(LOCAL_NOTE_DIRS)]
        offenders = []
        for page in pages:
            text = page.read_text(encoding="utf-8")
            # The front matter carries the page's structured data, not prose.
            if text.startswith("---\n"):
                text = text[text.index("\n---\n", 4) + 5:]
            text = re.sub(r"<script.*?</script>", "", text, flags=re.S)
            text = FENCED.sub("", text)
            for number, line in enumerate(text.splitlines(), 1):
                if GLYPHS.search(line) or _semicolons(line) or ONE_PLURAL.search(line):
                    offenders.append(f"{page.relative_to(ROOT)}:{number}: {line.strip()[:100]}")
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))


if __name__ == "__main__":
    unittest.main()
