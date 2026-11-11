"""What the configgen launchers of Batocera and Recalbox have in common.

Both platforms start their emulators from a Python configgen, so their
launcher layers are read the same way: parse each generator with ast,
locate one known shape, and cite the lines it spans at the pinned revision.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, NoReturn


class LauncherShapeError(ValueError):
    """A generator no longer has the shape its extractor reads."""


@dataclass
class Launcher:
    """One thing a launcher looks for or hands over, as its code says it."""

    emulator: str
    build: str
    kind: str
    names: list[str]
    source_ref: str
    slot: str | None = None
    expands: dict[str, list[str]] | None = None
    case_insensitive: bool | None = None
    search_dir: str | None = None
    passes_to: str | None = None
    fails_when_missing: bool | str = False
    fails_scope: str | None = None
    depends_on_option: str | None = None
    device: str | None = None
    # The machines the platform offers under the record's systems.
    machines: list[str] | None = None
    # The platform systems the record is written for, none for every one.
    systems: list[str] | None = None
    # For a record citing a config: where the platform's code puts it
    # ({path, source_ref}), whether that leaves a file already there, and
    # the launch code rewriting its keys ([] when none does).
    installs: dict[str, str] | None = None
    kept_if_present: bool | None = None
    overrides: list[str] | None = None
    # The feature or option file listing the values the option written takes.
    choices_from: str | None = None

    def entry(self) -> dict[str, Any]:
        """The platform YAML form, in a fixed key order, unset keys left out."""
        order = (
            "emulator", "systems", "build", "kind", "slot", "names", "expands",
            "case_insensitive", "search_dir", "passes_to",
            "fails_when_missing", "fails_scope", "depends_on_option",
            "device", "machines", "installs", "kept_if_present", "overrides",
            "choices_from", "source_ref",
        )
        return {key: getattr(self, key) for key in order if getattr(self, key) is not None}


class Source:
    """One configgen file, parsed, with the lines its nodes span."""

    def __init__(self, path: str, text: str) -> None:
        self.path = path
        self.lines = text.splitlines()
        try:
            self.tree = ast.parse(text)
        except SyntaxError as e:
            raise LauncherShapeError(f"{path}: {e}") from e

    def fail(self, what: str) -> NoReturn:
        raise LauncherShapeError(f"{self.path}: {what}")

    def function(self, name: str) -> ast.FunctionDef:
        found = [
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        if len(found) != 1:
            self.fail(f"expected one function {name}, found {len(found)}")
        return found[0]

    def assignment(self, name: str, scope: ast.AST | None = None) -> ast.Assign | ast.AnnAssign:
        found = [
            node for node in ast.walk(scope or self.tree)
            if _assigned_name(node) == name
        ]
        if len(found) != 1:
            self.fail(f"expected one assignment to {name}, found {len(found)}")
        return found[0]

    def literal(self, node: ast.AST | None, what: str) -> Any:
        try:
            return ast.literal_eval(node)  # type: ignore[arg-type]
        except (ValueError, TypeError, SyntaxError) as e:
            self.fail(f"{what} is not a literal: {e}")

    def span(self, node: ast.AST) -> tuple[int, int]:
        """Lines of a node, with the comment lines written right above it."""
        start = node.lineno  # type: ignore[attr-defined]
        while start > 1 and self.lines[start - 2].strip().startswith("#"):
            start -= 1
        return start, node.end_lineno  # type: ignore[attr-defined]

    def ref(self, spans: list[tuple[int, int]]) -> str:
        """`path:a-b, c-d`, ranges joined across blank and comment lines."""
        merged: list[list[int]] = []
        for start, end in sorted(spans):
            if merged and self._only_filler(merged[-1][1] + 1, start - 1):
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        parts = [f"{a}" if a == b else f"{a}-{b}" for a, b in merged]
        return f"{self.path}:{', '.join(parts)}"

    def _only_filler(self, first: int, last: int) -> bool:
        return all(
            not line.strip() or line.strip().startswith("#")
            for line in self.lines[max(first - 1, 0):max(last, 0)]
        )


def _assigned_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        target = node.target
    else:
        return None
    return target.id if isinstance(target, ast.Name) else None


def _statement_lists(node: ast.AST) -> Iterator[list[ast.stmt]]:
    for child in ast.walk(node):
        for attr in ("body", "orelse", "finalbody"):
            value = getattr(child, attr, None)
            if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                yield value


def _locate(
    scope: ast.AST, wanted: Callable[[ast.stmt], bool]
) -> tuple[list[ast.stmt], int] | None:
    """The innermost statement list holding a statement that satisfies `wanted`."""
    for body in _statement_lists(scope):
        for index, stmt in enumerate(body):
            if wanted(stmt):
                return body, index
    return None


def _outermost(scope: ast.FunctionDef, node: ast.AST) -> ast.stmt:
    """The statement of the function body that contains `node`."""
    for stmt in scope.body:
        if any(child is node for child in ast.walk(stmt)):
            return stmt
    line = getattr(node, "lineno", "?")
    raise LauncherShapeError(f"node at line {line} is outside {scope.name}")


def _mentions(stmt: ast.AST, constants: set[str], names: set[str]) -> bool:
    for node in ast.walk(stmt):
        if isinstance(node, ast.Constant) and node.value in constants:
            return True
        if isinstance(node, ast.Name) and node.id in names:
            return True
    return False


def _run(
    body: list[ast.stmt], index: int, keep: Callable[[ast.stmt], bool]
) -> tuple[ast.stmt, ast.stmt]:
    """The contiguous statements around body[index] that `keep` accepts."""
    first = last = index
    while first > 0 and keep(body[first - 1]):
        first -= 1
    while last + 1 < len(body) and keep(body[last + 1]):
        last += 1
    return body[first], body[last]


def _calls(scope: ast.AST, attr: str | None = None, name: str | None = None) -> list[ast.Call]:
    found = []
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if attr is not None and isinstance(func, ast.Attribute) and func.attr == attr:
            found.append(node)
        elif name is not None and isinstance(func, ast.Name) and func.id == name:
            found.append(node)
    return sorted(found, key=lambda call: (call.lineno, call.col_offset))


def _enclosing_test(scope: ast.AST, node: ast.AST) -> str | None:
    for parent in ast.walk(scope):
        if isinstance(parent, ast.If) and any(
            child is node for stmt in parent.body for child in ast.walk(stmt)
        ):
            return ast.unparse(parent.test)
    return None


def _innermost_function(src: Source, node: ast.AST) -> ast.FunctionDef:
    holders = [
        f for f in ast.walk(src.tree)
        if isinstance(f, ast.FunctionDef) and any(child is node for child in ast.walk(f))
    ]
    if not holders:
        src.fail(f"line {node.lineno} is outside any function")  # type: ignore[attr-defined]
    return max(holders, key=lambda f: f.lineno)
