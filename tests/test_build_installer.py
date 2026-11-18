"""install.py is built from the installer/ package.

The installer ships as one stdlib-only file that the bootstraps pin by hash,
and its source is a package of modules that import from each other. These
tests hold the committed file to what the package builds and the joining to
what one namespace can hold.
"""

from __future__ import annotations

import tests

import ast
import tempfile
import textwrap
import unittest
from pathlib import Path

from installer_build import amalgamate

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCSTRING = '"""A test installer."""\n'


def _package(root: Path, modules: dict[str, str]) -> Path:
    package = root / "installer"
    package.mkdir()
    (package / "__init__.py").write_text(DOCSTRING, encoding="utf-8")
    for name, body in modules.items():
        (package / f"{name}.py").write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
    return package


class TheCommittedFileIsTheBuiltOne(unittest.TestCase):
    def test_install_py_is_what_the_package_builds(self):
        built = amalgamate.build(REPO_ROOT / "installer")
        self.assertEqual(built, (REPO_ROOT / "install.py").read_text(encoding="utf-8"),
                         f"install.py differs from installer/: run {amalgamate.COMMAND}")

    def test_two_builds_give_the_same_bytes(self):
        self.assertEqual(amalgamate.build(REPO_ROOT / "installer"),
                         amalgamate.build(REPO_ROOT / "installer"))

    def test_the_file_says_it_is_generated(self):
        head = (REPO_ROOT / "install.py").read_text(encoding="utf-8").splitlines()[:3]
        self.assertEqual(head[0], "#!/usr/bin/env python3")
        self.assertIn("scripts/build_installer.py", head[1])

    def test_every_module_keeps_the_3_8_grammar_and_annotations_unevaluated(self):
        for path in sorted((REPO_ROOT / "installer").glob("*.py")):
            source = path.read_text(encoding="utf-8")
            with self.subTest(module=path.name):
                ast.parse(source, filename=path.name, feature_version=(3, 8))
                if path.name != "__init__.py":
                    self.assertIn("from __future__ import annotations\n", source)

    def test_every_module_says_its_concern_in_one_line(self):
        for path in sorted((REPO_ROOT / "installer").glob("*.py")):
            if path.name == "__init__.py":
                continue
            docstring = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8")), clean=False) or ""
            with self.subTest(module=path.name):
                self.assertTrue(docstring.strip())
                self.assertNotIn("\n", docstring)

    def test_the_architecture_page_names_every_module(self):
        """wiki/architecture.md groups the modules by concern: a module added,
        renamed or merged changes the table in the same commit."""
        page = (REPO_ROOT / "wiki" / "architecture.md").read_text(encoding="utf-8")
        section = page.split("## Installer modules", 1)[1].split("\n## ", 1)[0]
        listed = [name for row in section.splitlines() if row.startswith("| ") and "`" in row
                  for name in row.split("|")[2].replace("`", "").replace(",", " ").split()]
        modules = sorted(path.stem for path in (REPO_ROOT / "installer").glob("*.py")
                         if path.name != "__init__.py")
        self.assertEqual(sorted(listed), modules)


class JoiningRefusesWhatOneNamespaceCannotHold(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def assert_refused(self, modules: dict[str, str], words: str) -> None:
        package = _package(self.root, modules)
        with self.assertRaises(amalgamate.BuildError) as caught:
            amalgamate.build(package)
        self.assertIn(words, str(caught.exception))

    def test_a_package_joins_in_import_order(self):
        package = _package(self.root, {
            "b": '''
                """B."""
                from __future__ import annotations

                import os

                from installer.a import A

                B = A + os.sep
            ''',
            "a": '''
                """A."""
                from __future__ import annotations

                import sys
                import zlib

                A = sys.platform + str(zlib.crc32(b""))
            ''',
        })
        text = amalgamate.build(package)
        self.assertLess(text.index("A = sys.platform"), text.index("B = A + os.sep"))
        self.assertIn("import os\nimport sys\n", text)
        self.assertNotIn("from installer", text)
        self.assertIn("try:\n    import zlib\nexcept ImportError as _missing:", text)
        self.assertNotIn("\nimport zlib\n", text)
        namespace: dict[str, object] = {}
        exec(compile(text, "install.py", "exec"), namespace)
        self.assertTrue(str(namespace["B"]).endswith("0/"))

    def test_an_import_outside_the_standard_library(self):
        self.assert_refused({"a": '''
            """A."""
            from __future__ import annotations

            import yaml
        '''}, "not in the standard library")

    def test_a_name_two_modules_define(self):
        self.assert_refused({
            "a": '"""A."""\nfrom __future__ import annotations\n\nX = 1\n',
            "b": '"""B."""\nfrom __future__ import annotations\n\nX = 2\n',
        }, "X is defined in a.py and b.py")

    def test_an_import_cycle(self):
        self.assert_refused({
            "a": '"""A."""\nfrom __future__ import annotations\n\nfrom installer.b import g\n\n\ndef f():\n    return g\n',
            "b": '"""B."""\nfrom __future__ import annotations\n\nfrom installer.a import f\n\n\ndef g():\n    return f\n',
        }, "import cycle among a, b")

    def test_a_type_checking_import_is_no_cycle(self):
        package = _package(self.root, {
            "a": ('"""A."""\nfrom __future__ import annotations\n\nfrom typing import TYPE_CHECKING\n\n'
                  'if TYPE_CHECKING:\n    from installer.b import B\n\n\ndef f(b: B) -> None:\n    return None\n'),
            "b": '"""B."""\nfrom __future__ import annotations\n\nfrom installer.a import f\n\n\nclass B:\n    pass\n',
        })
        text = amalgamate.build(package)
        self.assertNotIn("TYPE_CHECKING", text)
        self.assertLess(text.index("def f("), text.index("class B:"))

    def test_an_import_under_another_name(self):
        self.assert_refused({
            "a": '"""A."""\nfrom __future__ import annotations\n\nX = 1\n',
            "b": '"""B."""\nfrom __future__ import annotations\n\nfrom installer.a import X as Y\n\nZ = Y\n',
        }, "imported as Y")

    def test_a_name_the_imported_module_does_not_define(self):
        self.assert_refused({
            "a": '"""A."""\nfrom __future__ import annotations\n\nX = 1\n',
            "b": '"""B."""\nfrom __future__ import annotations\n\nfrom installer.a import W\n\nZ = W\n',
        }, "imports W from a.py, which does not define it")

    def test_a_name_read_at_import_from_a_later_module(self):
        # c reads b's name when it runs without importing b: b sorts after c.
        self.assert_refused({
            "c": '"""C."""\nfrom __future__ import annotations\n\nfrom installer.a import A\n\nC = A + D\n',
            "a": '"""A."""\nfrom __future__ import annotations\n\nA = 1\n',
            "d": '"""D."""\nfrom __future__ import annotations\n\nD = 2\n',
        }, "D is read at import time but d.py comes later")

    def test_a_module_without_unevaluated_annotations(self):
        self.assert_refused({"a": '"""A."""\nX = 1\n'}, "from __future__ import annotations")

    def test_an_import_below_the_header(self):
        self.assert_refused({
            "a": '"""A."""\nfrom __future__ import annotations\n\nX = 1\nimport os\n',
        }, "import os below the header")


if __name__ == "__main__":
    unittest.main()
