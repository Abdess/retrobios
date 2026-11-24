"""The suite runs with only the build dependencies installed.

jsonschema is needed by the schema validator and by CI, nowhere else. Six
tests imported it unguarded, so a contributor with stdlib and pyyaml saw
fifteen errors instead of skipped schema checks.
"""

from __future__ import annotations

import tests

import ast
import re
import subprocess
import sys
import unittest
from collections.abc import Iterator
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


IMPORTS_SCHEMA_CODE = re.compile(r"^\s*(?:import|from)\s+(?:jsonschema|validate_schemas|schemas)\b", re.M)


class SuiteWithoutJsonschema(unittest.TestCase):
    def test_every_module_skips_instead_of_erroring(self):
        # The modules that import either, at the top or inside a test: a
        # module that only names them in a string has nothing to skip.
        names = sorted(
            f"tests.{path.stem}"
            for path in (REPO_ROOT / "tests").glob("test_*.py")
            if path.stem != Path(__file__).stem
            and IMPORTS_SCHEMA_CODE.search(path.read_text(encoding="utf-8"))
        )
        completed = subprocess.run(
            [sys.executable, "-c", HIDE_AND_RUN, *names],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            text=True,
            # The CI runner takes about twice this host's time: 600 s cut
            # the run short there while it passed here.
            timeout=1800,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr[-2000:])


# Tools a maintainer runs by hand when a logo or a card changes. Their output
# is committed under website/assets/ and the build only reads it, so the build
# keeps to the standard library and pyyaml.
MAINTENANCE_TOOLS = {
    "sitegen/imagenormalize.py": "PIL",
    "sitegen/chromium.py": "playwright",
}


def _is_type_checking(test: ast.expr) -> bool:
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            and isinstance(test.value, ast.Name) and test.value.id == "typing")


def _runtime_nodes(node: ast.AST) -> Iterator[ast.AST]:
    """Every node that can run: the body of an `if TYPE_CHECKING:` never does."""
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.If) and _is_type_checking(child.test):
            for branch in child.orelse:
                yield from _runtime_nodes(branch)
            continue
        yield from _runtime_nodes(child)


def _foreign_imports(source: str, file_name: str, local: set[str]) -> list[str]:
    """The top-level packages a script imports at run time beyond the
    standard library, pyyaml and the repository's own modules. ``file_name``
    is the path under scripts/."""
    allowed = {"yaml"}
    found = []
    for node in _runtime_nodes(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module.split(".")[0]]
        else:
            continue
        for name in names:
            if name in sys.stdlib_module_names or name in local or name in allowed:
                continue
            if name == "jsonschema" and file_name.startswith("schemas/"):
                continue
            if MAINTENANCE_TOOLS.get(file_name) == name:
                continue
            found.append(name)
    return found


class ScriptsNeedOnlyPyyaml(unittest.TestCase):
    """The build scripts need the standard library and pyyaml. jsonschema is
    the schemas package's alone, behind validate_schemas.py. CI installs
    jsonschema with its whole tree (attrs, referencing, rpds-py), so an
    import of any of them would pass there and fail for a contributor
    following the documented setup."""

    def test_no_script_imports_another_package(self):
        scripts = Path(__file__).resolve().parents[1] / "scripts"
        local = {p.stem for p in scripts.rglob("*.py")} | {
            p.name for p in scripts.iterdir() if p.is_dir()
        } | {"scripts", "__future__"}
        # install.py is the repository's own single file, stdlib only (its
        # tests hold it to that): games.fallback reads its narrowing.
        local.add("install")
        found = [
            f"{path.relative_to(scripts)}: {name}"
            for path in sorted(scripts.rglob("*.py"))
            for name in _foreign_imports(path.read_text(encoding="utf-8"),
                                         path.relative_to(scripts).as_posix(), local)
        ]
        self.assertEqual(found, [])

    def test_an_import_only_a_type_checker_runs_is_no_dependency(self):
        guarded = (
            "from typing import TYPE_CHECKING\n"
            "import typing\n"
            "if TYPE_CHECKING:\n"
            "    from typing_extensions import Unpack\n"
            "if typing.TYPE_CHECKING:\n"
            "    import typing_extensions\n"
        )
        self.assertEqual(_foreign_imports(guarded, "x.py", set()), [])
        self.assertEqual(_foreign_imports("import typing_extensions\n", "x.py", set()),
                         ["typing_extensions"])
        # The else branch of the guard runs: it stays a dependency.
        branch = (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    pass\n"
            "else:\n"
            "    import typing_extensions\n"
        )
        self.assertEqual(_foreign_imports(branch, "x.py", set()), ["typing_extensions"])


class TheDownloaderRunsWithoutPyyaml(unittest.TestCase):
    """download.py is the documented Windows downloader, "stdlib only". It
    stays so only because the core modules it imports use the standard
    library alone (tests/test_layers.py): had one imported yaml as a plain
    import, every CI job (which installs pyyaml) would stay green."""

    def test_help_runs_with_yaml_unimportable(self):
        import subprocess

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


class ProfilesWithoutPyyamlStopOnOneLine(unittest.TestCase):
    """load_emulator_profiles warned and returned {} without PyYAML: every
    caller then read a repository that documents no emulator, zero coverage
    and nothing to fix, and exited 0."""

    def test_the_loader_exits_with_the_shared_message(self):
        root = Path(__file__).resolve().parents[1]
        code = (
            "import sys; sys.modules['yaml'] = None; sys.path.insert(0, 'scripts'); "
            "from model.profiles import load_emulator_profiles; "
            "load_emulator_profiles('emulators')"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", code], cwd=root, capture_output=True,
            text=True, timeout=120, check=False,
        )
        self.assertEqual(completed.returncode, 1, completed.stderr[-1500:])
        self.assertEqual(completed.stderr.strip(), "Error: PyYAML required (pip install pyyaml)")


if __name__ == "__main__":
    unittest.main()
