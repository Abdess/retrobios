"""A dataclass field typed as a container defaults to an empty one.

ProfileReport declared `entries: list[EntryReport] = None`: the annotation
promised a list, the public constructor gave None, and format_report raised
TypeError on the first loop.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _is_dataclass(node: ast.ClassDef) -> bool:
    for deco in node.decorator_list:
        target = deco.func if isinstance(deco, ast.Call) else deco
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if name == "dataclass":
            return True
    return False


class ContainerFieldsAreNotNone(unittest.TestCase):
    def test_no_container_annotation_defaults_to_none(self):
        for path in sorted([*(REPO_ROOT / "scripts").rglob("*.py"), REPO_ROOT / "install.py"]):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.ClassDef) and _is_dataclass(node)):
                    continue
                for stmt in node.body:
                    if not isinstance(stmt, ast.AnnAssign) or stmt.value is None:
                        continue
                    annotation = ast.unparse(stmt.annotation)
                    is_none = isinstance(stmt.value, ast.Constant) and stmt.value.value is None
                    if is_none and annotation.split("[")[0] in ("list", "dict", "set") \
                            and "None" not in annotation:
                        with self.subTest(module=path.name, cls=node.name,
                                          field=ast.unparse(stmt.target)):
                            self.fail(f"{annotation} defaults to None")


if __name__ == "__main__":
    unittest.main()
