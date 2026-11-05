"""One folder per console.

A system section is named after the folder its files live in. Nintendo held
DS and Nintendo DS, 64DD and Nintendo 64DD, Sega held Mega CD and Mega-CD,
Sinclair ZX Spectrum and ZXSpectrum, VTech V.Smile and VSmile, Acorn BBC and
BBC Micro: each console had two sections that hid each other on the site.
Reads the git index, which is what a clone checks out, and the database,
which also lists the release assets the index never holds: FBAlpha 2012 had
three samples committed under "FBAlpha 2012" and four release assets under
"fba2012", the folder the core reads.
"""

from __future__ import annotations

import json
import re
import subprocess
import unittest
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def console_key(name: str) -> str:
    """Spaces, dashes, dots and case folded, and "Alpha" read as its "A"
    abbreviation, so "FBAlpha 2012" and "fba2012" are one core."""
    return re.sub(r"[\s.\-]", "", name).casefold().replace("alpha", "a")


def twin_consoles(paths: list[str]) -> list[list[str]]:
    """Console folders of one maker that read as the same name."""
    spellings: dict[tuple[str, str], set[str]] = defaultdict(set)
    for path in paths:
        parts = path.split("/")
        if len(parts) < 4 or parts[0] != "bios":
            continue
        maker, console = parts[1], parts[2]
        spellings[(maker, console_key(console))].add(f"{maker}/{console}")
    return sorted(sorted(names) for names in spellings.values() if len(names) > 1)


class OneFolderPerConsole(unittest.TestCase):
    def test_no_maker_files_one_console_twice(self) -> None:
        listed = subprocess.run(
            ["git", "ls-files", "-z", "--", "bios"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        if listed.returncode != 0 or not listed.stdout:
            self.skipTest("not a git checkout with bios/")
        paths = [p for p in listed.stdout.split("\0") if p]
        self.assertEqual(twin_consoles(paths), [])

    def test_spaces_dashes_and_dots_do_not_make_a_new_console(self) -> None:
        self.assertEqual(
            twin_consoles([
                "bios/Sega/Mega CD/a.bin",
                "bios/Sega/Mega-CD/b.bin",
                "bios/VTech/V.Smile/c.bin",
                "bios/VTech/VSmile/d.bin",
                "bios/Atari/Lynx/e.bin",
                "bios/Camputers/Lynx/f.bin",
            ]),
            [["Sega/Mega CD", "Sega/Mega-CD"], ["VTech/V.Smile", "VTech/VSmile"]],
        )

    def test_database_paths_name_each_console_once(self) -> None:
        db_path = REPO_ROOT / "database.json"
        if not db_path.is_file():
            self.skipTest("database.json not generated")
        files = json.loads(db_path.read_text(encoding="utf-8"))["files"]
        self.assertEqual(twin_consoles([f["path"] for f in files.values()]), [])

    def test_alpha_abbreviation_is_the_same_core(self) -> None:
        self.assertEqual(
            twin_consoles([
                "bios/Arcade/FBAlpha 2012/samples/dkong.zip",
                "bios/Arcade/fba2012/samples/ghox.zip",
            ]),
            [["Arcade/FBAlpha 2012", "Arcade/fba2012"]],
        )

    def test_fbalpha2012_samples_sit_where_the_profile_reads(self) -> None:
        db_path = REPO_ROOT / "database.json"
        if not db_path.is_file():
            self.skipTest("database.json not generated")
        files = json.loads(db_path.read_text(encoding="utf-8"))["files"]
        samples = sorted(
            f["path"] for f in files.values()
            if f["path"].startswith("bios/Arcade/")
            and "/samples/" in f["path"] and "fba" in f["path"].casefold()
        )
        self.assertEqual(
            samples,
            [f"bios/Arcade/fba2012/samples/{name}.zip" for name in (
                "dkong", "dkongjr", "fireshrk", "galaga", "ghox", "tekipaki", "vimana",
            )],
        )


if __name__ == "__main__":
    unittest.main()
