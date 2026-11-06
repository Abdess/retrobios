"""generate_site --db reaches every page.

The run loaded the given database, but the page-finishing pass reloaded the
repository's database.json: a card held only by the given collection stopped
the whole run on a KeyError.
"""

from __future__ import annotations

import ast
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import siteinputs  # noqa: E402

SHA1 = "0123456789ab" + "c" * 28


class _Inputs(unittest.TestCase):
    def use(self, **paths: Path) -> None:
        siteinputs.use(siteinputs.SiteInputs(**paths))
        self.addCleanup(siteinputs.use, siteinputs.SiteInputs())


class TheGivenDatabase(_Inputs):
    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir() else None))
        self.addCleanup(shutil.rmtree, tmp)
        self.db = tmp / "database.json"
        self.db.write_text(json.dumps({"files": {SHA1: {"path": "bios/X/only-here.bin"}}}))

    def test_a_card_held_elsewhere_resolves_in_the_given_collection(self) -> None:
        self.use(db=self.db)
        page = generate_site._cards_elsewhere("[x](#sha1-0123456789ab) ")
        self.assertIn(f"files/?sha1={SHA1}", page)

    def test_paths_are_read_from_the_given_collection(self) -> None:
        self.use(db=self.db)
        self.assertEqual(generate_site._collection_sha1_by_path(), {"bios/X/only-here.bin": SHA1})


class GenerateInstallsTheInputs(unittest.TestCase):
    def test_generate_installs_the_inputs_first(self) -> None:
        source = ast.get_source_segment(
            (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8"),
            next(n for n in ast.parse((REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")).body
                 if isinstance(n, ast.FunctionDef) and n.name == "_generate"))
        self.assertLess(source.index("siteinputs.use("), source.index("load_database("))


if __name__ == "__main__":
    unittest.main()
