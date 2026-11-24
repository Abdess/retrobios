"""Recalbox's configgen at one tag, its string constants and the conditions of each setting write."""

from __future__ import annotations

import ast
import posixpath
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any

from .configgen_launchers import LauncherShapeError, Source, _calls, assigned_value
from model.launcherrecords import join_emulators


CONFIGGEN = "projects/configgen/configgen"
GENERATORS = f"{CONFIGGEN}/generators"
FILES_MODULE = f"{CONFIGGEN}/recalboxFiles.py"
LAUNCHER = f"{CONFIGGEN}/emulatorlauncher.py"
RETROARCH = f"{GENERATORS}/libretro/libretroRetroarch.py"
CORES = f"{GENERATORS}/libretro/libretroCores.py"
LIBRETRO_GENERATOR = f"{GENERATORS}/libretro/libretroGenerator.py"
HATARI = f"{GENERATORS}/hatari/hatariGenerator.py"
GSPLUS = f"{GENERATORS}/gsplus/gsplusGenerator.py"
XROAR = f"{GENERATORS}/xroar/xroarGenerator.py"
AMIBERRY_GENERATOR = f"{GENERATORS}/amiberry/amiberryGenerator.py"
AMIBERRY_KICKSTARTS = f"{GENERATORS}/amiberry/amiberryKickstarts.py"
AMIBERRY_SUBSYSTEMS = f"{GENERATORS}/amiberry/amiberrySubSystems.py"
AMIBERRY_CONFIG = f"{GENERATORS}/amiberry/amiberryConfig.py"
AMIBERRY_GLOBAL = f"{GENERATORS}/amiberry/amiberryGlobalConfig.py"
PCSX2 = f"{GENERATORS}/pcsx2/pcsx2Generator.py"
DOLPHIN = f"{GENERATORS}/dolphin/dolphinGenerator.py"
XEMU = f"{GENERATORS}/xemu/xemuGenerator.py"
MUPEN_GENERATOR = f"{GENERATORS}/mupen/mupenGenerator.py"
MUPEN_CONFIG = f"{GENERATORS}/mupen/mupenConfig.py"


# Recalbox's system.ini runs every libretro core as `emulator = libretro`:
# the name a record carries when the code applies to any core.
ALL_CORES = "libretro"
SYSTEM_PLACEHOLDER = "<system>"
SYSTEM_NAMES = ("self.system.Name", "system.Name")
SYSTEM_DIRECTORY = "system_directory"
CORE_ASSETS = "core_assets_directory"

# libretroCores functions that build a TOS path through a cascade.
TOS_FUNCTIONS = ("configureAtariST", "configureAtariSTNew")
# libretro core options whose value names the file the core opens.
FILE_OPTIONS = {"o2em_bios": "o2em"}

# A name the core resolves itself, such as hatarib's <etos1024k>.
BUILTIN_TOKEN = re.compile(r"<[^<>/]+>")


def string(node: ast.AST | None) -> str | None:
    """The value of a string constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def string_constant(source: Source, node: ast.AST | None, what: str) -> str | None:
    """The value of a string constant, None for any other node. A constant
    that is not a string is a shape the reader does not know."""
    if not isinstance(node, ast.Constant):
        return None
    if not isinstance(node.value, str):
        source.fail(f"line {node.lineno}: {what} is not a string: {node.value!r}")
    return node.value


def assignments(
    nodes: Iterable[ast.AST],
) -> Iterator[tuple[ast.Assign | ast.AnnAssign, str, ast.expr]]:
    """Each single-name assignment among `nodes`, its name and its value."""
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            assigned = assigned_value(node)
            if assigned is not None:
                yield node, assigned[0], assigned[1]


def spell(node: ast.AST | None, env: Mapping[str, str]) -> str | None:
    """The string an expression always evaluates to, if it can be read."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, (ast.Name, ast.Attribute)):
        return env.get(ast.unparse(node))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = spell(node.left, env), spell(node.right, env)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if value.conversion != -1 or value.format_spec is not None:
                    return None
                value = value.value
            part = spell(value, env)
            if part is None:
                return None
            parts.append(part)
        return "".join(parts)
    if isinstance(node, ast.Call) and not node.keywords:
        spelled = [spell(arg, env) for arg in node.args]
        args = [arg for arg in spelled if arg is not None]
        if len(args) != len(spelled):
            return None
        func = ast.unparse(node.func)
        if func == "os.path.join" and args:
            return posixpath.join(*args)
        if func == "str" and len(args) == 1:
            return args[0]
    return None


def module_strings(source: Source, prefix: str) -> dict[str, str]:
    """Module-level string constants, keyed as `prefix.NAME`."""
    local: dict[str, str] = {}
    for _node, name, expr in assignments(source.tree.body):
        value = spell(expr, local)
        if value is not None:
            local[name] = value
    return {f"{prefix}.{name}": value for name, value in local.items()}


def class_strings(source: Source, env: dict[str, str]) -> dict[str, Any]:
    """Class attributes readable as strings or as tuples of strings."""
    found: dict[str, Any] = {}
    for cls in source.tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        # The class body reads its own attributes by their bare names.
        bare: dict[str, str] = {}
        for _node, name, expr in assignments(cls.body):
            scope = {**env, **found, **bare}
            value: Any = spell(expr, scope)
            if value is None and isinstance(expr, ast.Tuple):
                items = [spell(e, scope) for e in expr.elts]
                value = items if all(isinstance(i, str) for i in items) else None
            if value is None:
                continue
            if isinstance(value, str):
                bare[name] = value
            for owner in ("self", cls.name):
                found[f"{owner}.{name}"] = value
    return found


def _bound_once(scope: ast.AST, env: dict[str, str]) -> dict[str, str]:
    """Names a function binds exactly once to a readable string."""
    counts: dict[str, int] = {}
    found = list(assignments(ast.walk(scope)))
    for _node, name, _expr in found:
        counts[name] = counts.get(name, 0) + 1
    local: dict[str, str] = {}
    for _node, name, expr in sorted(found, key=lambda item: item[0].lineno):
        if counts[name] == 1:
            value = spell(expr, {**env, **local})
            if value is not None:
                local[name] = value
    return local


def launcher_names(source: Source) -> dict[str, list[str]]:
    """Generator module -> the emulator names getGenerator loads it for."""
    names: dict[str, list[str]] = {}
    for node in ast.walk(source.function("getGenerator")):
        if not (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.ops[0], ast.Eq)
        ):
            continue
        emulator = string_constant(source, node.test.comparators[0], "emulator name")
        if emulator is None:
            continue
        for call in _calls(ast.Module(body=node.body, type_ignores=[]), name="__import__"):
            module = string_constant(source, call.args[0], "generator module") if call.args else None
            if module is not None:
                names.setdefault(module, []).append(emulator)
    if not names:
        source.fail("getGenerator imports no generator module")
    return names


def handler_map(source: Source, function: str, table: str) -> dict[str, list[str]]:
    """Function name -> the keys a dispatch table of `function` sends to it."""
    node = source.assignment(table, source.function(function)).value
    if not isinstance(node, ast.Dict):
        source.fail(f"{table} is not a dict display")
    handlers: dict[str, list[str]] = {}
    for key, value in zip(node.keys, node.values):
        name = string_constant(source, key, f"{table} key")
        if name is not None and isinstance(value, ast.Attribute):
            handlers.setdefault(value.attr, []).append(name)
    if not handlers:
        source.fail(f"{table} sends nothing to a handler")
    return handlers


class Configgen:
    """Recalbox's configgen at one tag, read through `read(path)`."""

    def __init__(self, read: Callable[[str], str]) -> None:
        self._read = read
        self._sources: dict[str, Source] = {}
        files = self.source(FILES_MODULE)
        self.files = module_strings(files, "recalboxFiles")
        if "recalboxFiles.BIOS" not in self.files:
            files.fail("no BIOS path constant")
        self.bios = self.files["recalboxFiles.BIOS"]
        self._emulators = launcher_names(self.source(LAUNCHER))

    def source(self, path: str) -> Source:
        if path not in self._sources:
            self._sources[path] = Source(path, self._read(path))
        return self._sources[path]

    def emulator(self, path: str) -> str:
        """The emulator names getGenerator loads the generator at `path` for."""
        module = "configgen." + path.removeprefix(f"{CONFIGGEN}/").removesuffix(".py")
        module = module.replace("/", ".")
        if module not in self._emulators:
            raise LauncherShapeError(f"{LAUNCHER}: no emulator loads {module}")
        return join_emulators(self._emulators[module])

    def core(self, function: str) -> str:
        """The libretro cores fillCoresConfiguration hands to `function`."""
        cores = handler_map(self.source(CORES), "fillCoresConfiguration", "specificCoreHandlers")
        if function not in cores:
            self.source(CORES).fail(f"no core is configured by {function}")
        return join_emulators(cores[function])

    def env(self, source: Source, scope: ast.AST | None = None) -> dict[str, Any]:
        """recalboxFiles, the module's class attributes and the strings
        `scope` binds once, with the system name left as a placeholder."""
        env: dict[str, Any] = dict(self.files)
        env.update(class_strings(source, env))
        env.update({name: SYSTEM_PLACEHOLDER for name in SYSTEM_NAMES})
        if scope is not None:
            env.update(_bound_once(scope, env))
        return env

    def under_bios(self, value: str | None) -> str | None:
        """`value` relative to the BIOS directory, or None outside it."""
        if value is None:
            return None
        value = value.strip("'\"")
        prefix = self.bios.rstrip("/") + "/"
        return value[len(prefix):] if value.startswith(prefix) else None

    def bios_dir(self, value: str | None, source: Source, what: str) -> str:
        if value is None or not (value == self.bios or self.under_bios(value) is not None):
            source.fail(f"{what} is not a directory under {self.bios}")
        return value.rstrip("/")


def is_setter_call(call: ast.Call, key: str, attr: str = "setString") -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == attr
        and bool(call.args)
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == key
    )


def expr_call(stmt: ast.stmt) -> ast.Call | None:
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        return stmt.value
    return None


def accepted_systems(
    source: Source, test: ast.expr, lists: Mapping[str, list[str]]
) -> list[str] | None:
    """The systems a `system.Name == x`, `or` or `in list` test accepts."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        parts = [accepted_systems(source, value, lists) for value in test.values]
        systems: list[str] = []
        for part in parts:
            if part is None:
                return None
            systems += part
        return systems
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and ast.unparse(test.left) in SYSTEM_NAMES
    ):
        right = test.comparators[0]
        system = string_constant(source, right, "system name")
        if isinstance(test.ops[0], ast.Eq) and system is not None:
            return [system]
        if isinstance(test.ops[0], ast.In) and isinstance(right, ast.Name) and right.id in lists:
            return list(lists[right.id])
    return None


def _flag(test: ast.expr) -> str | None:
    """X for a bare `self.system.X` test."""
    if isinstance(test, ast.Attribute) and ast.unparse(test.value) == "self.system":
        return test.attr
    return None


def _condition(source: Source, tests: list[ast.expr], negated: bool,
               lists: Mapping[str, list[str]]) -> str:
    """A branch condition in words, for the taken branch or the else."""
    systems: list[str] = []
    flags: list[str] = []
    for test in tests:
        found = accepted_systems(source, test, lists)
        flag = _flag(test)
        if found is not None:
            systems += found
        elif flag is not None:
            flags.append(flag)
        else:
            source.fail(f"line {test.lineno}: branch test {ast.unparse(test)} is not read")
    words = []
    if systems:
        words.append(("system other than " if negated else "system ") + ", ".join(systems))
    if flags:
        words.append(("without system flag " if negated else "system flag ") + ", ".join(flags))
    return ", ".join(words)


def _is_elif(source: Source, node: ast.If) -> bool:
    return source.lines[node.lineno - 1].lstrip().startswith("elif")


def _else_line(source: Source, first: ast.stmt) -> int:
    line = first.lineno - 1
    while line > 0 and source.lines[line - 1].strip() != "else:":
        line -= 1
    return line if line > 0 else first.lineno


def setter_branches(
    source: Source, stmts: list[ast.stmt], key: str, lists: Mapping[str, list[str]]
) -> list[tuple[str | None, ast.Call, int]]:
    """(condition, setter call, first line) for each branch writing `key`."""
    found: list[tuple[str | None, ast.Call, int]] = []
    for stmt in stmts:
        call = expr_call(stmt)
        if call is not None and is_setter_call(call, key):
            found.append((None, call, stmt.lineno))
            continue
        if not isinstance(stmt, ast.If):
            if any(is_setter_call(c, key) for c in _calls(stmt, attr="setString")):
                source.fail(f"line {stmt.lineno}: {key} is written outside an if chain")
            continue
        node, tests = stmt, []
        while True:
            tests.append(node.test)
            found += _branch(source, node.body, key, _condition(source, [node.test], False, lists),
                             node.lineno)
            orelse = node.orelse
            if len(orelse) == 1 and isinstance(orelse[0], ast.If) and _is_elif(source, orelse[0]):
                node = orelse[0]
                continue
            if orelse:
                found += _branch(source, orelse, key, _condition(source, tests, True, lists),
                                 _else_line(source, orelse[0]))
            break
    return found


def _branch(
    source: Source, stmts: list[ast.stmt], key: str, condition: str, start: int
) -> list[tuple[str | None, ast.Call, int]]:
    calls = [c for stmt in stmts if (c := expr_call(stmt)) is not None and is_setter_call(c, key)]
    nested = [c for stmt in stmts for c in _calls(stmt, attr="setString") if is_setter_call(c, key)]
    if len(calls) != len(nested) or len(calls) > 1:
        source.fail(f"line {start}: {key} is written in a nested branch")
    return [(condition, call, start) for call in calls]


def local_string_lists(source: Source, scope: ast.AST) -> dict[str, tuple[list[str], ast.stmt]]:
    found: dict[str, tuple[list[str], ast.stmt]] = {}
    for node, name, value in assignments(ast.walk(scope)):
        if isinstance(value, ast.List):
            values = [text for e in value.elts
                      if (text := string_constant(source, e, f"{name} item")) is not None]
            if len(values) == len(value.elts):
                found[name] = (values, node)
    return found
