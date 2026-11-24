"""Every script a tracked text cites exists at the path or module it gives.

Comments, messages and pages kept naming scripts/sitebootstrap.py and
scripts/region.py long after the code moved into packages, and a reader
following one found nothing. A path (`scripts/sitegen/wanted.py`) or a
module run with `-m` (`python -m scripts.scraper.arcade.mame_hash_scraper`)
must name a file of the tree.
"""

from __future__ import annotations

import tests

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Where a script is cited: the code, the tests, the pages, the workflows,
# the site's own sources, the installer and its bootstraps, the platform files
# and the unattended jobs.
CITING = ("scripts", "tests", "wiki", ".github", "website/src", "installer", "install.sh", "install.ps1",
          "platforms/*.yml", "platforms/**/*.yml", "automation")

# Modules that check a checker: the missing names they cite are the point.
CHECKER_TESTS = frozenset({"tests/test_cited_scripts.py", "tests/test_doc_pages_tools.py",
                           "tests/test_autorun.py"})

# A module a guide asks the reader to write (`myplatform_scraper`).
PLACEHOLDERS = ("myplatform",)

SCRIPT_PATH = re.compile(r"(?<![\w/.-])scripts/[\w/.-]*?\.py\b")
# `-m scripts.x.y` on a command line, or `"-m", "scripts.x.y"` in an argv list.
SCRIPT_MODULE = re.compile(r"-m\b[\"',\s]+(scripts(?:\.\w+)+)(?![.\w])")


def cited(text: str) -> list[tuple[int, str]]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        found += [(number, m.group()) for m in SCRIPT_PATH.finditer(line)]
        found += [(number, m.group(1).replace(".", "/") + ".py") for m in SCRIPT_MODULE.finditer(line)]
    return found


def exists(path: str) -> bool:
    file = ROOT / path
    return file.is_file() or (file.with_suffix("") / "__init__.py").is_file()


def citing_files() -> list[str]:
    listed = subprocess.run(["git", "ls-files", "--", *CITING], cwd=ROOT, capture_output=True,
                            text=True, check=True).stdout.split()
    return sorted(set(listed) - CHECKER_TESTS)


class CitedScripts(unittest.TestCase):
    def test_every_cited_script_exists(self):
        missing = []
        for name in citing_files():
            path = ROOT / name
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            missing += [f"{name}:{number}: {script}" for number, script in cited(text)
                        if not exists(script) and not any(word in script for word in PLACEHOLDERS)]
        self.assertEqual(missing, [])

    def test_the_check_reads_both_spellings(self):
        text = ('# built by scripts/sitebootstrap.py\n'
                'python -m scripts.scraper.mame_hash_scraper --dry-run\n'
                '[sys.executable, "-m", "scripts.scraper.game_dat_importer"]\n')
        self.assertEqual(cited(text), [(1, "scripts/sitebootstrap.py"),
                                       (2, "scripts/scraper/mame_hash_scraper.py"),
                                       (3, "scripts/scraper/game_dat_importer.py")])
        self.assertFalse(any(exists(script) for _, script in cited(text)))


if __name__ == "__main__":
    unittest.main()
