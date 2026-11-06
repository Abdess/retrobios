"""The suite runs with only the build dependencies installed.

jsonschema is needed by the schema validator and by CI, nowhere else. Six
tests imported it unguarded, so a contributor with stdlib and pyyaml saw
fifteen errors instead of skipped schema checks.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

HIDE_AND_RUN = """
import io
import sys
import unittest

sys.modules["jsonschema"] = None
names = sys.argv[1:]
suite = unittest.defaultTestLoader.loadTestsFromNames(names)
result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
for test, trace in result.errors + result.failures:
    print(test.id())
    print(trace.strip().splitlines()[-1])
sys.exit(0 if result.wasSuccessful() else 1)
"""


class SuiteWithoutJsonschema(unittest.TestCase):
    def test_every_module_skips_instead_of_erroring(self):
        names = sorted(
            f"tests.{path.stem}"
            for path in (REPO_ROOT / "tests").glob("test_*.py")
            if path.stem != Path(__file__).stem
            and any(
                token in path.read_text(encoding="utf-8")
                for token in ("jsonschema", "validate_schemas")
            )
        )
        completed = subprocess.run(
            [sys.executable, "-c", HIDE_AND_RUN, *names],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            text=True,
            timeout=600,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr[-2000:])


# Tools a maintainer runs by hand when a logo or a card changes. Their output
# is committed under docs_assets/ and the build only reads it, so the build
# keeps to the standard library and pyyaml.
MAINTENANCE_TOOLS = {
    "fetch_site_images.py": "PIL",
    "make_og_cards.py": "playwright",
    "make_site_icons.py": "playwright",
}


class ScriptsNeedOnlyPyyaml(unittest.TestCase):
    """The build scripts need the standard library and pyyaml. jsonschema is
    validate_schemas.py's alone. CI installs jsonschema with its whole tree
    (attrs, referencing, rpds-py), so an import of any of them would pass
    there and fail for a contributor following the documented setup."""

    def test_no_script_imports_another_package(self):
        import ast  # noqa: PLC0415

        scripts = Path(__file__).resolve().parents[1] / "scripts"
        local = {p.stem for p in scripts.rglob("*.py")} | {
            p.name for p in scripts.iterdir() if p.is_dir()
        } | {"scripts", "__future__"}
        # install.py is the repository's own single file, stdlib only (its
        # tests hold it to that): generate_games_index reads its narrowing.
        local.add("install")
        allowed = {"yaml"}
        found = []
        for path in sorted(scripts.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module.split(".")[0]]
                else:
                    continue
                for name in names:
                    if name in sys.stdlib_module_names or name in local or name in allowed:
                        continue
                    if name == "jsonschema" and path.name == "validate_schemas.py":
                        continue
                    if MAINTENANCE_TOOLS.get(path.name) == name:
                        continue
                    found.append(f"{path.relative_to(scripts)}: {name}")
        self.assertEqual(found, [])


class TheDownloaderRunsWithoutPyyaml(unittest.TestCase):
    """download.py is the documented Windows downloader, "stdlib only". It
    stays so only because common.py imports yaml optionally: made a plain
    import, every CI job (which installs pyyaml) would stay green."""

    def test_help_runs_with_yaml_unimportable(self):
        import subprocess  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        code = (
            "import sys, runpy; sys.modules['yaml'] = None; "
            "sys.path.insert(0, 'scripts'); sys.argv = ['download.py', '--help']; "
            "runpy.run_path('scripts/download.py', run_name='__main__')"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", code], cwd=root, capture_output=True,
            text=True, timeout=120, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-1500:])


if __name__ == "__main__":
    unittest.main()
