"""The site redeploys whenever a script it runs changes.

Deploy Site listed five scripts by hand while the build imports forty:
a change to siterender.py, which writes every page, published nothing
until some unrelated file moved.
"""

from __future__ import annotations

import ast
import fnmatch
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def _module_file(name: str) -> Path | None:
    name = name.removeprefix("scripts.")
    for candidate in (
        SCRIPTS / (name.replace(".", "/") + ".py"),
        SCRIPTS / name.replace(".", "/") / "__init__.py",
    ):
        if candidate.exists():
            return candidate
    return None


def _imports(path: Path) -> set[Path]:
    found: set[Path] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
        elif isinstance(node, ast.ImportFrom):
            base = path.parent / (node.module or "").replace(".", "/")
            candidates = [base / f"{a.name}.py" for a in node.names]
            candidates += [base.with_suffix(".py"), base / "__init__.py"]
            found.update(c for c in candidates if c.is_file())
            continue
        else:
            continue
        found.update(f for f in map(_module_file, names) if f)
    return found


def closure(entry_points: list[str]) -> set[str]:
    seen: set[Path] = set()
    stack = [SCRIPTS / name for name in entry_points]
    while stack:
        path = stack.pop()
        if path not in seen:
            seen.add(path)
            stack.extend(_imports(path))
    return {str(p.relative_to(REPO_ROOT)) for p in seen}


class DeploySiteTriggers(unittest.TestCase):
    def test_every_script_the_build_imports_triggers_it(self):
        workflow = yaml.safe_load(
            (REPO_ROOT / ".github/workflows/deploy-site.yml").read_text(encoding="utf-8")
        )
        on = workflow.get("on", workflow.get(True))
        patterns = on["push"]["paths"]
        run = "\n".join(
            step.get("run", "") for job in workflow["jobs"].values() for step in job["steps"]
        )
        entry_points = sorted(
            {
                word.removeprefix("scripts/")
                for word in run.split()
                if word.startswith("scripts/") and word.endswith(".py")
            }
        )
        self.assertIn("generate_site.py", entry_points)
        uncovered = sorted(
            path
            for path in closure(entry_points)
            if not any(fnmatch.fnmatch(path, p.replace("**", "*")) for p in patterns)
        )
        self.assertEqual(uncovered, [])


class DocumentedSteps(unittest.TestCase):
    def test_the_release_page_names_every_installed_package(self):
        """The page listed pyyaml and mkdocs and left out jsonschema: a
        maintainer following it could not run the contract check."""
        sys.path.insert(0, str(SCRIPTS))
        from check_freshness import parse_pip_pins  # noqa: PLC0415

        workflow = (REPO_ROOT / ".github/workflows/deploy-site.yml").read_text(encoding="utf-8")
        page = (REPO_ROOT / "wiki/release-process.md").read_text(encoding="utf-8")
        missing = sorted(name for name in parse_pip_pins(workflow) if name not in page)
        self.assertEqual(missing, [])
        self.assertIn("validate_schemas.py", page)


if __name__ == "__main__":
    unittest.main()
