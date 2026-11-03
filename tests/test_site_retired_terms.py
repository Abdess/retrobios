"""What the generators write must not bring back what the project retired.

The generated pages, README.md, CONTRIBUTING.md and the site's components
are read for two things. A retired command, address or feature term, each
listed with the reason it was retired. And every `--option` a generated
command passes: the script it names must declare it in its parser, or a
reader copies a command that stops on "unrecognized arguments".

The pages copied from wiki/ are left to their own tests: the installer page
keeps the raw one-liner as the documented fallback.
"""
from __future__ import annotations

import ast
import re
import unittest
from functools import cache
from pathlib import Path

from tests import sitepages

ROOT = Path(__file__).resolve().parents[1]

# (string, why it is retired). Compared case-sensitively against the text.
RETIRED = (
    ("raw.githubusercontent.com/Abdess/retrobios/main/install.sh",
     "the site serves the one-liner at https://abdess.github.io/retrobios/i "
     "since 2026-10-28, pinned to the commit the site was built from"),
    ("raw.githubusercontent.com/Abdess/retrobios/main/install.ps1",
     "served at https://abdess.github.io/retrobios/i.ps1 since 2026-10-28"),
    ("Abdess/retroarch_system",
     "the repository was renamed retrobios in March 2026"),
    ("mkdocs serve", "the MkDocs site was replaced by Astro Starlight on 2026-10-22"),
    ("mkdocs build", "the MkDocs site was replaced by Astro Starlight on 2026-10-22"),
    ("pip install mkdocs", "the site is built by Node from website/package-lock.json"),
    ('class="rb-tested', "the Tested blocks were removed on 2026-10-28: "
     "only Proof lines and the Measurements page remain"),
    ("rb-region-runs", "region outcomes left the system pages on 2026-10-28"),
    ("## Campaign", "the campaign table left the Measurements page on 2026-10-28"),
    ("| Tested by |", "the coverage table left the Measurements page on 2026-10-28"),
    ("ms per frame", "benchmark figures stay in the records and SQLite files, "
     "never on a page, since 2026-10-28"),
    ("with this BIOS folder as", "the Tested block of platform pages, removed on 2026-10-28"),
    ("regenerated in its native format", "the export patches each platform's own "
     "file and never regenerates it (scripts/exporter/base_exporter.py needs_original)"),
)

COMMAND = re.compile(
    r"(?:python3? (?P<script>scripts/[\w/]+\.py|install\.py)"
    r"|python3? -m (?P<module>scripts(?:\.\w+)+)"
    r"|(?P<oneliner>retrobios/i \| sh -s --|retrobios/i\.ps1\)\)\)))"
    r"(?P<args>[^\n`<|]*)"
)
OPTION = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")


def retired_hits(text: str) -> list[str]:
    return [term for term, _why in RETIRED if term in text]


@cache
def parser_options(script: str) -> frozenset[str]:
    """The long options *script* declares through add_argument, with the
    shared ones of scraper_cli for a scraper that hands its parser over."""
    source = (ROOT / script).read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            found.update(arg.value for arg in node.args
                         if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                         and arg.value.startswith("--"))
    if "scraper_cli(" in source and script != "scripts/scraper/base_scraper.py":
        found |= parser_options("scripts/scraper/base_scraper.py")
    return frozenset(found)


def unknown_options(text: str) -> list[str]:
    """Each `script --option` of a command whose script does not declare it."""
    wrong = []
    for match in COMMAND.finditer(text):
        if match["oneliner"]:
            script = "install.py"
        elif match["module"]:
            script = match["module"].replace(".", "/") + ".py"
        else:
            script = match["script"]
        if not (ROOT / script).is_file():
            wrong.append(f"{script}: no such script")
            continue
        known = parser_options(script)
        wrong += [f"{script} {option}" for option in OPTION.findall(match["args"])
                  if option not in known]
    return wrong


def _surfaces() -> dict[str, str]:
    content = sitepages.require()
    texts = {
        str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
        for path in sorted(content.rglob("*.md*"))
        if "wiki" not in path.relative_to(content).parts
    }
    for name in ("README.md", "CONTRIBUTING.md"):
        texts[name] = (ROOT / name).read_text(encoding="utf-8")
    for path in sorted((ROOT / "website" / "src").glob("*/*")):
        if path.suffix in (".astro", ".ts", ".css", ".mjs"):
            texts[str(path.relative_to(ROOT))] = path.read_text(encoding="utf-8")
    return texts


class RetiredTermsStayRetired(unittest.TestCase):
    def test_each_retired_term_says_why(self):
        for term, why in RETIRED:
            with self.subTest(term=term):
                self.assertTrue(term.strip())
                self.assertGreater(len(why.split()), 4)

    def test_the_check_finds_what_the_old_output_wrote(self):
        old = (
            "curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n"
            '## Tested\n\n<div class="rb-tested">\n'
            "The same comparison drives `scripts/exporter/`: each platform's own "
            "file can be regenerated in its native format with these differences.\n"
        )
        self.assertEqual(retired_hits(old), [
            "raw.githubusercontent.com/Abdess/retrobios/main/install.sh",
            'class="rb-tested', "regenerated in its native format",
        ])

    def test_no_surface_brings_one_back(self):
        found = {name: hits for name, text in _surfaces().items()
                 if (hits := retired_hits(text))}
        self.assertEqual(found, {})


class EveryOptionExists(unittest.TestCase):
    def test_the_check_reads_each_form_of_command(self):
        text = (
            "python scripts/generate_pack.py --platform retroarch --zip-all\n"
            "curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --check --frobnicate\n"
            "&([scriptblock]::Create((irm https://abdess.github.io/retrobios/i.ps1))) --dry-run\n"
            "python -m scripts.scraper.libretro_scraper --dry-run\n"
        )
        self.assertEqual(unknown_options(text), [
            "scripts/generate_pack.py --zip-all", "install.py --frobnicate",
        ])

    def test_every_generated_command_names_options_its_script_has(self):
        wrong = {name: bad for name, text in _surfaces().items()
                 if (bad := unknown_options(text))}
        self.assertEqual(wrong, {})


if __name__ == "__main__":
    unittest.main()
