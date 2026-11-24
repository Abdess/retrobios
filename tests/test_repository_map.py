"""The repository's root says what each of its entries is and which files are generated.

The directory map of the architecture page left out games/, packaging/,
measurements/ and four root data files, and README.md and CONTRIBUTING.md
gave no sign that a generator writes them.
"""

from __future__ import annotations

import tests

import re
import subprocess
import unittest
from pathlib import Path

import yaml

from core.generated import GENERATED
from sitegen.readme import GENERATED_MARKER

REPO_ROOT = Path(__file__).resolve().parent.parent
# Named by the map, never tracked: written by a run.
UNTRACKED = {"data/", "dist/", ".cache/"}


def _tracked_root() -> set[str]:
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True,
    ).stdout.decode("utf-8").split("\0")
    return {
        path.split("/", 1)[0] + ("/" if "/" in path else "")
        for path in listed if path
    }


def _map_block() -> str:
    page = (REPO_ROOT / "wiki" / "architecture.md").read_text(encoding="utf-8")
    section = page.split("## Directory structure", 1)[1]
    return section.split("```", 2)[1]


class TheMapNamesEveryRootEntry(unittest.TestCase):
    def setUp(self) -> None:
        if not (REPO_ROOT / ".git").exists():
            self.skipTest("not a git checkout")

    def test_every_tracked_root_entry_is_in_the_map(self):
        names = set(re.findall(r"[\w.-]+/?", _map_block()))
        self.assertEqual(sorted(_tracked_root() - names), [])

    def test_every_root_entry_of_the_map_exists(self):
        named = {word.split("/", 1)[0] + ("/" if "/" in word else "")
                 for word in (line.split()[0] for line in _map_block().splitlines()
                              if line and not line[0].isspace())}
        self.assertEqual(sorted(named - _tracked_root() - UNTRACKED), [])


class GeneratedFilesAreMarked(unittest.TestCase):
    def test_gitattributes_marks_what_a_pipeline_run_writes(self):
        text = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
        marked = re.findall(r"(?m)^/(\S+)\s+linguist-generated=true$", text)
        self.assertEqual(marked, list(GENERATED))

    def test_readme_and_contributing_name_their_generator(self):
        for name in ("README.md", "CONTRIBUTING.md"):
            with self.subTest(file=name):
                text = (REPO_ROOT / name).read_text(encoding="utf-8")
                self.assertTrue(text.startswith(GENERATED_MARKER))

    def test_a_hand_edit_fails_validation(self):
        workflow = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8"))
        on = workflow.get("on", workflow.get(True))
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                self.assertLessEqual({"README.md", "CONTRIBUTING.md"}, set(on[event]["paths"]))
        runs = [str(step.get("run", "")) for job in workflow["jobs"].values()
                for step in job["steps"]]
        self.assertIn(
            "python scripts/generate_readme.py --db database.json --platforms-dir platforms --check",
            runs)

    def test_the_check_names_a_hand_edit(self):
        import io
        from contextlib import redirect_stdout
        from tempfile import TemporaryDirectory
        from unittest import mock

        from sitegen import readme

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {"README_PATH": root / "README.md", "CONTRIBUTING_PATH": root / "CONTRIBUTING.md"}
            with mock.patch.multiple(readme, **paths):
                with redirect_stdout(io.StringIO()):
                    readme.write_readme("body\n")
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(readme.check_readme("body\n"), 0)
                paths["README_PATH"].write_text(GENERATED_MARKER + "edited\n", encoding="utf-8")
                with redirect_stdout(out):
                    self.assertEqual(readme.check_readme("body\n"), 1)
            self.assertIn("README.md differs", out.getvalue())
            self.assertNotIn("CONTRIBUTING.md differs", out.getvalue())


if __name__ == "__main__":
    unittest.main()
