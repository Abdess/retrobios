"""Recalbox's launcher layer, read from the configgen generators.

Recalbox's configgen decides which file name each emulator is given and
where it is handed over: Hatari's generator walks a TOS cascade per machine,
PCSX2's picks a BIOS by the region token of the rom name, and for every
libretro core libretroRetroarch chooses the directory RetroArch receives as
system_directory. That is the platform's behaviour, so it is recorded here
with the lines of the pinned tag that say it.

Each extractor reads one known shape with ast and raises LauncherShapeError
when the shape is gone, as the Batocera reader does.
"""

from __future__ import annotations

import ast
import posixpath
import re
from collections.abc import Callable, Mapping
from functools import partial
from typing import Any

from .configgen_launchers import (
    Launcher,
    LauncherShapeError,
    Source,
    _assigned_name,
    _calls,
    _enclosing_test,
    _innermost_function,
    _locate,
)

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

SOURCE_FILES = (
    FILES_MODULE, LAUNCHER, RETROARCH, CORES, LIBRETRO_GENERATOR, HATARI, GSPLUS,
    AMIBERRY_KICKSTARTS, AMIBERRY_SUBSYSTEMS, AMIBERRY_CONFIG, AMIBERRY_GLOBAL, PCSX2, DOLPHIN, XEMU,
    MUPEN_CONFIG, XROAR,
)

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
        args = [spell(arg, env) for arg in node.args]
        if any(arg is None for arg in args):
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
    for node in source.tree.body:
        name = _assigned_name(node)
        if name is not None:
            value = spell(node.value, local)
            if value is not None:
                local[name] = value
    return {f"{prefix}.{name}": value for name, value in local.items()}


def _class_strings(source: Source, env: dict[str, str]) -> dict[str, Any]:
    """Class attributes readable as strings or as tuples of strings."""
    found: dict[str, Any] = {}
    for cls in source.tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        # The class body reads its own attributes by their bare names.
        bare: dict[str, str] = {}
        for node in cls.body:
            name = _assigned_name(node)
            if name is None:
                continue
            scope = {**env, **found, **bare}
            value: Any = spell(node.value, scope)
            if value is None and isinstance(node.value, ast.Tuple):
                items = [spell(e, scope) for e in node.value.elts]
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
    nodes = []
    for node in ast.walk(scope):
        name = _assigned_name(node)
        if name is not None:
            counts[name] = counts.get(name, 0) + 1
            nodes.append(node)
    local: dict[str, str] = {}
    for node in sorted(nodes, key=lambda n: n.lineno):
        name = _assigned_name(node)
        if name is not None and counts[name] == 1:
            value = spell(node.value, {**env, **local})
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
            and isinstance(node.test.comparators[0], ast.Constant)
        ):
            continue
        for call in _calls(ast.Module(body=node.body, type_ignores=[]), name="__import__"):
            if call.args and isinstance(call.args[0], ast.Constant):
                names.setdefault(call.args[0].value, []).append(node.test.comparators[0].value)
    if not names:
        source.fail("getGenerator imports no generator module")
    return names


def _handler_map(source: Source, function: str, table: str) -> dict[str, list[str]]:
    """Function name -> the keys a dispatch table of `function` sends to it."""
    node = source.assignment(table, source.function(function)).value
    if not isinstance(node, ast.Dict):
        source.fail(f"{table} is not a dict display")
    handlers: dict[str, list[str]] = {}
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and isinstance(value, ast.Attribute):
            handlers.setdefault(value.attr, []).append(key.value)
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
        return ", ".join(self._emulators[module])

    def core(self, function: str) -> str:
        """The libretro cores fillCoresConfiguration hands to `function`."""
        cores = _handler_map(self.source(CORES), "fillCoresConfiguration", "specificCoreHandlers")
        if function not in cores:
            self.source(CORES).fail(f"no core is configured by {function}")
        return ", ".join(cores[function])

    def env(self, source: Source, scope: ast.AST | None = None) -> dict[str, Any]:
        """recalboxFiles, the module's class attributes and the strings
        `scope` binds once, with the system name left as a placeholder."""
        env: dict[str, Any] = dict(self.files)
        env.update(_class_strings(source, env))
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


def _setter(call: ast.Call, key: str, attr: str = "setString") -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == attr
        and bool(call.args)
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == key
    )


def _expr_call(stmt: ast.stmt) -> ast.Call | None:
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        return stmt.value
    return None


def _systems(test: ast.expr, lists: Mapping[str, list[str]]) -> list[str] | None:
    """The systems a `system.Name == x`, `or` or `in list` test accepts."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        parts = [_systems(value, lists) for value in test.values]
        if any(part is None for part in parts):
            return None
        return [system for part in parts for system in part]
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and ast.unparse(test.left) in SYSTEM_NAMES
    ):
        right = test.comparators[0]
        if isinstance(test.ops[0], ast.Eq) and isinstance(right, ast.Constant):
            return [right.value]
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
        found = _systems(test, lists)
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


def _setter_branches(
    source: Source, stmts: list[ast.stmt], key: str, lists: Mapping[str, list[str]]
) -> list[tuple[str | None, ast.Call, int]]:
    """(condition, setter call, first line) for each branch writing `key`."""
    found: list[tuple[str | None, ast.Call, int]] = []
    for stmt in stmts:
        call = _expr_call(stmt)
        if call is not None and _setter(call, key):
            found.append((None, call, stmt.lineno))
            continue
        if not isinstance(stmt, ast.If):
            if any(_setter(c, key) for c in _calls(stmt, attr="setString")):
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
    calls = [c for stmt in stmts if (c := _expr_call(stmt)) is not None and _setter(c, key)]
    nested = [c for stmt in stmts for c in _calls(stmt, attr="setString") if _setter(c, key)]
    if len(calls) != len(nested) or len(calls) > 1:
        source.fail(f"line {start}: {key} is written in a nested branch")
    return [(condition, call, start) for call in calls]


def _local_lists(source: Source, scope: ast.AST) -> dict[str, tuple[list[str], ast.stmt]]:
    found = {}
    for node in ast.walk(scope):
        name = _assigned_name(node)
        if name is not None and isinstance(node.value, ast.List):
            values = [e.value for e in node.value.elts if isinstance(e, ast.Constant)]
            if len(values) == len(node.value.elts):
                found[name] = (values, node)
    return found


def system_directories(cg: Configgen) -> list[Launcher]:
    """`match self.system.Core` per core, then the overrides per system."""
    src = cg.source(RETROARCH)
    matches = [
        node for node in ast.walk(src.tree)
        if isinstance(node, ast.Match)
        and ast.unparse(node.subject) == "self.system.Core"
        and any(_setter(c, SYSTEM_DIRECTORY) for c in _calls(node, attr="setString"))
    ]
    if len(matches) != 1:
        src.fail(f"expected one match on the core writing {SYSTEM_DIRECTORY}, "
                 f"found {len(matches)}")
    match = matches[0]
    scope = _innermost_function(src, match)
    env = cg.env(src, scope)
    local_lists = _local_lists(src, scope)
    lists = {name: values for name, (values, _node) in local_lists.items()}

    def record(emulator: str, condition: str | None, call: ast.Call,
               spans: list[tuple[int, int]]) -> Launcher:
        directory = cg.bios_dir(spell(call.args[1], env), src, f"line {call.lineno}")
        return Launcher(
            emulator=emulator, build="libretro", kind="passes_path", names=[],
            search_dir=directory, passes_to=f"retroarch {SYSTEM_DIRECTORY}",
            depends_on_option=condition, source_ref=src.ref(spans),
        )

    launchers = []
    for case in match.cases:
        if case.guard is not None:
            src.fail(f"line {case.pattern.lineno}: a guarded case is not read")
        pattern = case.pattern
        options = pattern.patterns if isinstance(pattern, ast.MatchOr) else [pattern]
        cores = [p.value.value for p in options
                 if isinstance(p, ast.MatchValue) and isinstance(p.value, ast.Constant)]
        wildcard = isinstance(pattern, ast.MatchAs) and pattern.pattern is None
        if not wildcard and len(cores) != len(options):
            src.fail(f"line {pattern.lineno}: case pattern is not a list of core names")
        branches = _setter_branches(src, case.body, SYSTEM_DIRECTORY, lists)
        if not branches:
            src.fail(f"line {pattern.lineno}: case writes no {SYSTEM_DIRECTORY}")
        for condition, call, start in branches:
            if wildcard:
                words = ["core with no case of its own"] + ([condition] if condition else [])
                condition = ", ".join(words)
            launchers.append(record(
                ", ".join(cores) or ALL_CORES, condition, call,
                [(pattern.lineno, pattern.lineno), (start, call.end_lineno)],
            ))

    body, index = _locate(scope, lambda stmt: stmt is match)
    overrides = _setter_branches(src, body[index + 1:], SYSTEM_DIRECTORY, lists)
    if not overrides:
        src.fail(f"no per-system {SYSTEM_DIRECTORY} after the match on the core")
    tests = {node.lineno: node.test for node in ast.walk(scope) if isinstance(node, ast.If)}
    for condition, call, start in overrides:
        if condition is None:
            src.fail(f"line {call.lineno}: {SYSTEM_DIRECTORY} rewritten for every system")
        read = {n.id for n in ast.walk(tests[start]) if isinstance(n, ast.Name)} \
            if start in tests else set()
        spans = [(start, call.end_lineno)]
        spans += [src.span(node) for name, (_v, node) in local_lists.items() if name in read]
        launchers.append(record(
            ALL_CORES, f"{condition}, replacing the directory chosen by core", call, spans,
        ))
    return launchers


def core_directory(directories: list[Launcher], core: str) -> Launcher:
    """The unconditional system_directory record that applies to `core`."""
    for launcher in directories:
        if core in launcher.emulator.split(", ") and launcher.depends_on_option is None:
            return launcher
    for launcher in directories:
        if launcher.emulator == ALL_CORES and launcher.depends_on_option == \
                "core with no case of its own":
            return launcher
    raise LauncherShapeError(f"{RETROARCH}: no {SYSTEM_DIRECTORY} applies to {core}")


def core_assets(cg: Configgen) -> list[Launcher]:
    """`if self.system.Core == x: setString("core_assets_directory", dir)`."""
    src = cg.source(RETROARCH)
    env = cg.env(src)
    launchers = []
    for node in ast.walk(src.tree):
        if not (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and ast.unparse(node.test.left) == "self.system.Core"
            and isinstance(node.test.ops[0], ast.Eq)
            and isinstance(node.test.comparators[0], ast.Constant)
        ):
            continue
        calls = [c for stmt in node.body if (c := _expr_call(stmt)) and _setter(c, CORE_ASSETS)]
        if len(calls) != 1:
            continue
        call = calls[0]
        launchers.append(Launcher(
            emulator=node.test.comparators[0].value, build="libretro", kind="passes_path",
            names=[], search_dir=cg.bios_dir(spell(call.args[1], env), src, CORE_ASSETS),
            passes_to=f"retroarch {CORE_ASSETS}",
            source_ref=src.ref([(node.lineno, call.end_lineno)]),
        ))
    if not launchers:
        src.fail(f"no core is given a {CORE_ASSETS}")
    return launchers


def _exists_arg(test: ast.expr) -> ast.expr | None:
    """X in `not os.path.exists(X)`."""
    if (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and isinstance(test.operand, ast.Call)
        and ast.unparse(test.operand.func) == "os.path.exists"
        and len(test.operand.args) == 1
    ):
        return test.operand.args[0]
    return None


def _assigns(stmt: ast.stmt, var: str) -> ast.expr | None:
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and _assigned_name(stmt) == var:
        return stmt.value
    return None


def _skip_imports(body: list[ast.stmt], index: int) -> int:
    while index < len(body) and isinstance(body[index], (ast.Import, ast.ImportFrom)):
        index += 1
    return index


def tos_cascade(cg: Configgen, src: Source, scope: ast.FunctionDef, emulator: str,
                build: str) -> list[Launcher]:
    """A TOS path chosen per machine, then tried down an existence cascade."""
    env = cg.env(src, scope)
    paths = {
        name for node in ast.walk(scope)
        if (name := _assigned_name(node)) is not None
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "os.path.join"
    }
    setters = [
        call for call in _calls(scope, attr="setString")
        if call.args
        and isinstance(call.args[-1], ast.Call)
        and ast.unparse(call.args[-1].func) == "str"
        and isinstance(call.args[-1].args[0], ast.Name)
        and call.args[-1].args[0].id in paths
    ]
    if len(setters) != 1:
        src.fail(f"{scope.name}: expected one setting written from str(<path>)")
    setter = setters[0]
    var = setter.args[-1].args[0].id
    keys = [spell(arg, env) for arg in setter.args[:-1]]
    if None in keys or len(keys) not in (1, 2):
        src.fail(f"{scope.name}: the TOS is written under a key that is not read")
    passes_to = f"[{keys[0]}] {keys[1]}" if len(keys) == 2 else f"core option {keys[0]}"

    located = _locate(scope, lambda stmt: _assigns(stmt, var) is not None)
    if located is None:
        src.fail(f"{scope.name}: {var} is never assigned")
    body, index = located
    initial = spell(body[index].value, env)
    chosen: dict[str, str] = {}
    fallbacks: list[str] = []
    absolute = None
    override: tuple[str, str] | None = None
    end = body[index]
    i = _skip_imports(body, index + 1)
    while i < len(body) and body[i] is not _outermost_stmt(body, setter):
        stmt = body[i]
        if not isinstance(stmt, ast.If):
            src.fail(f"line {stmt.lineno}: unexpected statement in the TOS cascade")
        if (
            isinstance(stmt.test, ast.Compare)
            and isinstance(stmt.test.comparators[0], ast.Name)
            and stmt.test.comparators[0].id.startswith("MACHINE_")
        ):
            node: ast.If | None = stmt
            while node is not None:
                value = _assigns(node.body[0], var) if len(node.body) == 1 else None
                machine = node.test.comparators[0]
                if value is None or not isinstance(machine, ast.Name):
                    src.fail(f"line {node.lineno}: machine branch does not set {var}")
                chosen[machine.id] = spell(value, env)
                orelse = node.orelse
                node = orelse[0] if len(orelse) == 1 and isinstance(orelse[0], ast.If) else None
        elif _exists_arg(stmt.test) is not None:
            node = stmt
            while node is not None:
                tested = _exists_arg(node.test)
                is_abs = isinstance(tested, ast.Name) and tested.id == var
                is_rel = (
                    isinstance(tested, ast.Call)
                    and ast.unparse(tested.func) == "os.path.join"
                    and spell(tested.args[0], env) == cg.bios
                    and ast.unparse(tested.args[1]) == var
                )
                if not (is_abs or is_rel) or (absolute is not None and absolute != is_abs):
                    src.fail(f"line {node.lineno}: the cascade tests something else than {var}")
                absolute = is_abs
                value = _assigns(node.body[0], var)
                if value is None:
                    src.fail(f"line {node.lineno}: cascade step does not set {var}")
                fallbacks.append(spell(value, env))
                inner = node.body[1:]
                node = inner[0] if len(inner) == 1 and isinstance(inner[0], ast.If) else None
        elif (
            isinstance(stmt.test, ast.Compare)
            and isinstance(stmt.test.left, ast.Constant)
            and isinstance(stmt.test.ops[0], ast.In)
            and ast.unparse(stmt.test.comparators[0]) in ("rom", "self.rom", "args.rom")
            and len(stmt.body) == 1
            and _assigns(stmt.body[0], var) is not None
        ):
            override = (stmt.test.left.value, spell(_assigns(stmt.body[0], var), env))
        else:
            src.fail(f"line {stmt.lineno}: unexpected branch in the TOS cascade")
        end = stmt
        i = _skip_imports(body, i + 1)
    machines = [
        (name, name.removeprefix("MACHINE_").replace("_", "").lower())
        for node in scope.body if (name := _assigned_name(node)) and name.startswith("MACHINE_")
        and name != "MACHINE_UNKNOWN"
    ]
    if not chosen or not fallbacks or absolute is None or not machines or initial is None:
        src.fail(f"{scope.name}: no machine choice followed by an existence cascade")

    def relative(value: str | None) -> str:
        name = cg.under_bios(value) if absolute else value
        if name is None:
            src.fail(f"{scope.name}: {value} is not under {cg.bios}")
        return name

    tokens = [v for v in fallbacks if BUILTIN_TOKEN.fullmatch(posixpath.basename(v))]
    files = [relative(v) for v in fallbacks if v not in tokens]
    if tokens:
        passes_to += f" ({', '.join(tokens)} when none is found)"
    dicts = [
        node for node in scope.body
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Dict)
        and all(isinstance(v, ast.Name) and v.id.startswith("MACHINE_") for v in node.value.values)
    ]
    if len(dicts) != 1:
        src.fail(f"{scope.name}: no single rom path -> machine table")
    bound = {a.arg for a in scope.args.args} | {
        n for node in ast.walk(scope) if (n := _assigned_name(node))
    }
    options = [
        call.args[0].value for call in _calls(scope, attr="getInt")
        if call.args and isinstance(call.args[0], ast.Constant)
        and isinstance(call.func.value, ast.Name) and call.func.value.id in bound
    ]
    depends = f"machine read from the rom path through {_assigned_name(dicts[0])}"
    if options:
        depends += f", else option {', '.join(options)}"
    machine_lines = [n.lineno for n in scope.body if _assigned_name(n) in dict(machines)]
    cascade = body[index:body.index(_outermost_stmt(body, setter)) + 1]
    read = {n.id for stmt in cascade for n in ast.walk(stmt) if isinstance(n, ast.Name)}
    helpers = [src.span(n) for n in scope.body
               if _assigned_name(n) in read - {var} and spell(n.value, env) is not None]
    ref = src.ref([
        (min(machine_lines), max(machine_lines)),
        src.span(dicts[0]),
        *helpers,
        (src.span(body[index])[0], max(end.end_lineno, setter.end_lineno)),
    ])
    launchers = []
    for constant, slot in machines:
        first = relative(chosen.get(constant, initial))
        launchers.append(Launcher(
            emulator=emulator, build=build, kind="names_searched", slot=slot,
            names=list(dict.fromkeys([first, *files])), case_insensitive=False,
            search_dir=cg.bios, passes_to=passes_to, fails_when_missing=False,
            depends_on_option=depends, source_ref=ref,
        ))
    if override is not None and not BUILTIN_TOKEN.search(override[1]):
        launchers.append(Launcher(
            emulator=emulator, build=build, kind="fixed_name", slot=override[0],
            names=[relative(override[1])], case_insensitive=False, search_dir=cg.bios,
            passes_to=passes_to, fails_when_missing=False,
            depends_on_option=f'"{override[0]}" in the rom path', source_ref=ref,
        ))
    return launchers


def _outermost_stmt(body: list[ast.stmt], node: ast.AST) -> ast.stmt | None:
    for stmt in body:
        if any(child is node for child in ast.walk(stmt)):
            return stmt
    return None


def hatari(cg: Configgen) -> list[Launcher]:
    src = cg.source(HATARI)
    return tos_cascade(cg, src, src.function("SetMachineAndBios"), cg.emulator(HATARI),
                       "standalone")


def hatari_libretro(cg: Configgen) -> list[Launcher]:
    src = cg.source(CORES)
    return [
        launcher for function in TOS_FUNCTIONS
        for launcher in tos_cascade(cg, src, src.function(function), cg.core(function), "libretro")
    ]


def gsplus(cg: Configgen) -> list[Launcher]:
    """A path tried with os.path.exists down an else chain, and the
    placeholders a per-game .gsplus file can name."""
    src = cg.source(GSPLUS)
    generate = src.function("generate")
    env = cg.env(src, generate)
    emulator = cg.emulator(GSPLUS)

    def exists_of(test: ast.expr, var: str) -> bool:
        return (
            isinstance(test, ast.Call)
            and ast.unparse(test.func) == "os.path.exists"
            and ast.unparse(test.args[0]) == var
        )

    located = _locate(generate, lambda stmt: (
        _assigned_name(stmt) is not None
        and cg.under_bios(spell(stmt.value, env)) is not None
    ))
    if located is None:
        src.fail("generate assigns no path under BIOS")
    body, index = located
    names: list[str] = []
    key = None
    stmts, i = body, index
    last: ast.stmt = body[index]
    while True:
        var = _assigned_name(stmts[i])
        name = cg.under_bios(spell(stmts[i].value, env))
        test = stmts[i + 1] if i + 1 < len(stmts) else None
        tried = isinstance(test, ast.If) and var is not None and exists_of(test.test, var)
        if name is None or not tried:
            src.fail(f"line {stmts[i].lineno}: path is not tried with os.path.exists")
        written = [
            c for stmt in test.body
            if (c := _expr_call(stmt)) and c.func.attr == "setString"
            and ast.unparse(c.args[1]) == var
        ]
        if len(written) != 1 or (key is not None and written[0].args[0].value != key):
            src.fail(f"line {test.lineno}: the found path is not written to one key")
        key = written[0].args[0].value
        names.append(name)
        last = test
        orelse = test.orelse
        if len(orelse) == 2 and isinstance(orelse[1], ast.If):
            stmts, i = orelse, 0
            continue
        removed = [
            c for stmt in orelse if (c := _expr_call(stmt)) and _setter(c, key, "removeOption")
        ]
        if len(orelse) != 1 or not removed:
            src.fail(f"line {test.lineno}: the last miss does not remove {key}")
        break
    guard = next(
        node for node in ast.walk(generate)
        if isinstance(node, ast.If) and any(child is body[index] for child in node.orelse)
    )
    if not (isinstance(guard.test, ast.Compare) and isinstance(guard.test.left, ast.Constant)):
        src.fail("the BIOS search is not the else of a rom path test")
    marker = guard.test.left.value
    launchers = [Launcher(
        emulator=emulator, build="standalone", kind="names_searched", names=names,
        case_insensitive=False, search_dir=cg.bios, passes_to=key, fails_when_missing=False,
        depends_on_option=f'rom path without "{marker}"',
        source_ref=src.ref([(src.span(body[index])[0], last.end_lineno)]),
    )]
    for node in ast.walk(ast.Module(body=guard.body, type_ignores=[])):
        if not (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Call)
            and _setter(node.test.left, key, "getString")
            and isinstance(node.test.comparators[0], ast.Constant)
        ):
            continue
        written = [c for stmt in node.body if (c := _expr_call(stmt)) and _setter(c, key)]
        name = cg.under_bios(spell(written[0].args[1], env)) if len(written) == 1 else None
        if name is None:
            src.fail(f"line {node.lineno}: placeholder branch writes no BIOS path")
        placeholder = node.test.comparators[0].value
        launchers.append(Launcher(
            emulator=emulator, build="standalone", kind="fixed_name", slot=placeholder,
            names=[name], case_insensitive=False, search_dir=cg.bios, passes_to=key,
            fails_when_missing=False,
            depends_on_option=f'"{marker}" game file whose {key} is {placeholder}',
            source_ref=src.ref([(node.lineno, written[0].end_lineno)]),
        ))
    if len(launchers) == 1:
        src.fail("no placeholder of a .gsplus game file is replaced")
    return launchers


def amiberry(cg: Configgen) -> list[Launcher]:
    """BIOS_PER_SYSTEM tried in order, the AROS pair, then Amiberry's own."""
    kick = cg.source(AMIBERRY_KICKSTARTS)
    subsystems = _class_strings(cg.source(AMIBERRY_SUBSYSTEMS), {})
    computers = subsystems.get("SubSystems.COMPUTERS")
    if not isinstance(computers, list):
        cg.source(AMIBERRY_SUBSYSTEMS).fail("SubSystems.COMPUTERS is not a tuple of systems")

    helper = kick.function("AmigaBios")
    returned = helper.body[-1]
    if not (
        isinstance(returned, ast.Return)
        and isinstance(returned.value, ast.Call)
        and ast.unparse(returned.value.func) == "os.path.join"
        and ast.unparse(returned.value.args[-1]) == helper.args.args[0].arg
    ):
        kick.fail("AmigaBios no longer joins a directory and the name")
    search_dir = cg.bios_dir(
        spell(ast.Call(func=returned.value.func, args=returned.value.args[:-1], keywords=[]),
              cg.env(kick)),
        kick, "AmigaBios",
    )

    table = kick.assignment("BIOS_PER_SYSTEM")
    if not isinstance(table.value, ast.Dict):
        kick.fail("BIOS_PER_SYSTEM is not a dict display")
    chooser = kick.function("GetKickstartsFor")
    messages = [
        node.exc.args[0].value for node in ast.walk(chooser)
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
        and node.exc.args and isinstance(node.exc.args[0], ast.Constant)
    ]
    aros = [
        call.args[0].value for call in _calls(chooser, name="AmigaBios")
        if call.args and isinstance(call.args[0], ast.Constant)
    ]
    builtin = [
        node.value.value for node in ast.walk(chooser)
        if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]) == "self.rom"
        and isinstance(node.value, ast.Constant)
    ]
    if len(messages) != 2 or len(aros) != 2 or len(builtin) != 1:
        kick.fail("GetKickstartsFor no longer has two failures, the AROS pair and a built-in")
    config = cg.source(AMIBERRY_CONFIG)
    setter = config.function("SetKickstarts")
    keys = [c.args[0].value for c in _calls(setter, attr="setString")
            if isinstance(c.args[0], ast.Constant)]
    if len(keys) != 2:
        config.fail("SetKickstarts no longer writes a kickstart and an extended ROM")
    rom_key, ext_key = keys
    tail = [(helper.lineno, helper.end_lineno), (chooser.lineno, chooser.end_lineno)]
    config_ref = config.ref([(setter.lineno, setter.end_lineno)])

    emulator = cg.emulator(AMIBERRY_GENERATOR)
    launchers = []
    for key, value in zip(table.value.keys, table.value.values):
        system = subsystems.get(ast.unparse(key)) if key is not None else None
        if not isinstance(system, str) or not isinstance(value, ast.List):
            kick.fail(f"line {table.lineno}: BIOS_PER_SYSTEM key is not a SubSystems name")
        for entry in value.elts:
            if not (isinstance(entry, ast.Tuple) and len(entry.elts) == 2
                    and isinstance(entry.elts[0], ast.List)):
                kick.fail(f"line {entry.lineno}: entry is not (rom types, names)")
            types = ", ".join(ast.unparse(t).removeprefix("RomType.") for t in entry.elts[0].elts)
            names = kick.literal(entry.elts[1], "kickstart names")
            ref = f"{kick.ref([kick.span(entry), *tail])}, {config_ref}"
            make = partial(Launcher, emulator=emulator, build="standalone", slot=system,
                           case_insensitive=False, search_dir=search_dir,
                           depends_on_option=f"rom type {types}", source_ref=ref)
            if any("|" in name for name in names):
                if len(names) != 1:
                    kick.fail(f"line {entry.lineno}: several kickstart pairs are not read")
                launchers.append(make(
                    kind="fixed_name", names=names[0].split("|"),
                    passes_to=f"{rom_key}, {ext_key}",
                    fails_when_missing=", ".join(messages),
                ))
            else:
                launchers.append(make(
                    kind="names_searched", names=names, passes_to=rom_key,
                    fails_when_missing=False if system in computers else messages[0],
                ))
    launchers.append(Launcher(
        emulator=emulator, build="standalone", kind="fixed_name", slot=", ".join(computers),
        names=aros, case_insensitive=False, search_dir=search_dir,
        passes_to=f"{rom_key}, {ext_key} ({builtin[0]} built in when either is missing)",
        fails_when_missing=False, depends_on_option="none of the listed kickstarts found",
        source_ref=f"{kick.ref(tail)}, {config_ref}",
    ))
    launchers.append(_amiberry_rom_path(cg, emulator))
    return launchers


def _amiberry_rom_path(cg: Configgen, emulator: str) -> Launcher:
    """amiberry.conf rom_path, the folder Amiberry scans for every ROM."""
    src = cg.source(AMIBERRY_GLOBAL)
    create = src.function("createGlobalSettings")
    found = [c for c in _calls(create, attr="setString") if _setter(c, "rom_path")]
    if len(found) != 1 or len(found[0].args) != 2:
        src.fail(f"expected one rom_path setter, found {len(found)}")
    call = found[0]
    directory = cg.bios_dir(spell(call.args[1], cg.env(src, create)), src, "rom_path")
    return Launcher(
        emulator=emulator, build="standalone", kind="passes_path", names=[],
        search_dir=directory, passes_to="written: rom_path in amiberry.conf",
        source_ref=src.ref([(call.lineno, call.end_lineno)]),
    )


def pcsx2(cg: Configgen) -> list[Launcher]:
    """A region token of the rom name picks a BIOS, then a fixed order."""
    src = cg.source(PCSX2)
    env = cg.env(src)
    chooser = src.function("__CheckPs2Bios")
    exists = next((f for f in chooser.body if isinstance(f, ast.FunctionDef)), None)
    joined = exists.body[-1].value.args[0] if exists and isinstance(exists.body[-1], ast.Return) \
        and isinstance(exists.body[-1].value, ast.Call) and exists.body[-1].value.args else None
    if not (
        isinstance(joined, ast.Call) and ast.unparse(joined.func) == "os.path.join"
        and ast.unparse(joined.args[-1]) == exists.args.args[0].arg
    ):
        src.fail("__CheckPs2Bios has no existence helper joining a directory and a name")
    search_dir = cg.bios_dir(
        spell(ast.Call(func=joined.func, args=joined.args[:-1], keywords=[]), env), src, "Exists"
    )
    helper = exists.name

    groups: dict[tuple[str, str], list[str]] = {}
    chain = next((s for s in chooser.body if isinstance(s, ast.If)), None)
    node = chain
    while node is not None:
        test = node.test
        ok = (
            isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) and len(test.values) == 2
            and isinstance(test.values[0], ast.Compare)
            and isinstance(test.values[0].left, ast.Constant)
            and isinstance(test.values[1], ast.Call)
            and ast.unparse(test.values[1].func) == helper
            and len(node.body) == 1 and isinstance(node.body[0], ast.Return)
        )
        if not ok:
            src.fail(f"line {node.lineno}: region branch is not `token in rom and Exists(name)`")
        tested = spell(test.values[1].args[0], env)
        given = spell(node.body[0].value, env)
        if tested is None or given is None:
            src.fail(f"line {node.lineno}: region branch names no BIOS constant")
        groups.setdefault((given, tested), []).append(test.values[0].left.value)
        orelse = node.orelse
        node = orelse[0] if len(orelse) == 1 and isinstance(orelse[0], ast.If) else None
    loops = [s for s in chooser.body if isinstance(s, ast.For) and isinstance(s.iter, ast.Tuple)]
    if not groups or len(loops) != 1:
        src.fail("__CheckPs2Bios no longer tries region tokens then a fixed order")
    fallback = [spell(e, env) for e in loops[0].iter.elts]
    if None in fallback:
        src.fail(f"line {loops[0].lineno}: fallback names are not BIOS constants")

    writes = [
        call for call in _calls(src.tree, attr="setString")
        if len(call.args) == 3 and isinstance(call.args[2], ast.Call)
        and isinstance(call.args[2].func, ast.Attribute)
        and call.args[2].func.attr == chooser.name
    ]
    section = spell(writes[0].args[0], env) if len(writes) == 1 else None
    key = spell(writes[0].args[1], env) if len(writes) == 1 else None
    if section is None or key is None:
        src.fail("the chosen BIOS is not written to one config key")
    constants = {v: k.removeprefix("self.").removeprefix("Pcsx2Generator.")
                 for k, v in env.items() if k.startswith("Pcsx2Generator.BIOS_")}
    names_lines = [n.lineno for n in ast.walk(src.tree)
                   if _assigned_name(n) in {c for c in constants.values()}]
    ref = src.ref([(min(names_lines), max(names_lines)), (chooser.lineno, chooser.end_lineno),
                   (writes[0].lineno, writes[0].end_lineno)])
    make = partial(Launcher, emulator=cg.emulator(PCSX2), build="standalone",
                   case_insensitive=False, search_dir=search_dir,
                   passes_to=f"[{section}] {key}", fails_when_missing=False, source_ref=ref)
    launchers = []
    for (given, tested), tokens in groups.items():
        slot = constants.get(given, given).removeprefix("BIOS_")
        depends = f"rom name contains {', '.join(tokens)}"
        if tested == given:
            launchers.append(make(
                kind="names_searched", slot=slot,
                names=list(dict.fromkeys([given, *fallback])),
                depends_on_option=depends,
            ))
        else:
            # The name written is not the one tested: no search, one name.
            launchers.append(make(
                kind="fixed_name", slot=slot, names=[given],
                depends_on_option=f"{depends} and {tested} is present",
            ))
    launchers.append(make(
        kind="names_searched", slot="default", names=fallback,
        depends_on_option="rom name with no region token, or its BIOS absent",
    ))
    return launchers


def _presence(cg: Configgen, src: Source, scope: ast.FunctionDef) -> tuple[list[str], ast.If]:
    """Paths tested with `os.path.exists(a) or os.path.exists(b) ...`."""
    env = cg.env(src, scope)
    for node in ast.walk(scope):
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.BoolOp)
                and isinstance(node.test.op, ast.Or)):
            continue
        names = [
            cg.under_bios(spell(value.args[0], env)) for value in node.test.values
            if isinstance(value, ast.Call) and ast.unparse(value.func) == "os.path.exists"
        ]
        if names and len(names) == len(node.test.values) and None not in names:
            return names, node
    src.fail(f"{scope.name}: no presence test of BIOS paths")


def _returned(stmts: list[ast.stmt]) -> str | None:
    if len(stmts) == 1 and isinstance(stmts[0], ast.Return):
        value = stmts[0].value
        return value.value if isinstance(value, ast.Constant) else None
    return None


def dolphin(cg: Configgen) -> list[Launcher]:
    """The IPL is only tested for presence, to decide whether to skip it."""
    src = cg.source(DOLPHIN)
    env = cg.env(src)
    checker = src.function("CheckGamecubeIpl")
    names, test = _presence(cg, src, checker)
    found, missing = _returned(test.body), _returned(test.orelse)
    calls = [
        call for call in _calls(src.tree, attr="setString")
        if len(call.args) == 3 and isinstance(call.args[2], ast.Name)
        and any(
            _assigned_name(n) == call.args[2].id and isinstance(n.value, ast.Call)
            and isinstance(n.value.func, ast.Attribute) and n.value.func.attr == checker.name
            for n in ast.walk(src.tree)
        )
    ]
    if found is None or missing is None or len(calls) != 1:
        src.fail("CheckGamecubeIpl's answer is not written to one config key")
    call = calls[0]
    section, key = spell(call.args[0], env), spell(call.args[1], env)
    binding = next(n for n in ast.walk(src.tree)
                   if _assigned_name(n) == call.args[2].id)
    standalone = Launcher(
        emulator=cg.emulator(DOLPHIN), build="standalone", kind="fixed_name", names=names,
        case_insensitive=False, search_dir=cg.bios,
        passes_to=f"[{section}] {key} ({found} when one is present, else {missing})",
        fails_when_missing=False,
        source_ref=src.ref([(checker.lineno, checker.end_lineno), src.span(binding),
                            (call.lineno, call.end_lineno)]),
    )
    cores = cg.source(CORES)
    configure = cores.function("configureDolphin")
    names, test = _presence(cg, cores, configure)
    options = [(c.args[0].value, c.args[1].value) for branch in (test.body, test.orelse)
               for stmt in branch if (c := _expr_call(stmt)) and len(c.args) == 2
               and all(isinstance(a, ast.Constant) for a in c.args)]
    if len(options) != 2 or options[0][0] != options[1][0]:
        cores.fail("configureDolphin's presence test does not set one core option both ways")
    option = options[0][0]
    on, off = (value.strip('"') for _o, value in options)
    first = min(n.lineno for n in ast.walk(configure)
                if _assigned_name(n) is not None and cg.under_bios(
                    spell(n.value, cg.env(cores, configure))) is not None)
    libretro = Launcher(
        emulator=cg.core("configureDolphin"), build="libretro", kind="fixed_name", names=names,
        case_insensitive=False, search_dir=cg.bios,
        passes_to=f"core option {option} ({on} when one is present, else {off})",
        fails_when_missing=False, source_ref=cores.ref([(first, test.end_lineno)]),
    )
    return [standalone, libretro]


def _config_paths(cg: Configgen, path: str, emulator: str) -> Launcher:
    """setString(section, key, <path under BIOS>) calls of one module."""
    src = cg.source(path)
    writes = []
    for function in (n for n in ast.walk(src.tree) if isinstance(n, ast.FunctionDef)):
        env = cg.env(src, function)
        for call in _calls(function, attr="setString"):
            if len(call.args) != 3:
                continue
            section, key = spell(call.args[0], env), spell(call.args[1], env)
            name = cg.under_bios(spell(call.args[2], env))
            if section is not None and key is not None and name is not None:
                writes.append((function, call, section, key, name))
    if not writes:
        src.fail("writes no BIOS path into its config")
    conditions: list[str] = []
    spans = []
    for function, call, *_rest in writes:
        spans.append((call.lineno, call.end_lineno))
        test = next(
            (n for n in ast.walk(function) if isinstance(n, ast.If)
             and any(child is call for stmt in n.body for child in ast.walk(stmt))), None,
        )
        if test is not None:
            spans.append((test.lineno, test.lineno))
            systems = _systems(test.test, {})
            words = f"system {', '.join(systems)}" if systems else _enclosing_test(function, call)
            if words not in conditions:
                conditions.append(words)
        read = {ast.unparse(n) for arg in call.args for n in ast.walk(arg)
                if isinstance(n, (ast.Name, ast.Attribute))}
        spans += [src.span(n) for n in function.body
                  if _assigned_name(n) is not None and _assigned_name(n) in read]
        spans += [src.span(n) for cls in src.tree.body if isinstance(cls, ast.ClassDef)
                  for n in cls.body if _assigned_name(n) is not None
                  and {f"self.{_assigned_name(n)}", f"{cls.name}.{_assigned_name(n)}"} & read]
    return Launcher(
        emulator=emulator, build="standalone", kind="fixed_name",
        names=list(dict.fromkeys(name for *_rest, name in writes)), case_insensitive=False,
        search_dir=cg.bios,
        passes_to=", ".join(dict.fromkeys(f"[{s}] {k}" for _f, _c, s, k, _n in writes)),
        fails_when_missing=False, depends_on_option=", ".join(conditions) or None,
        source_ref=src.ref(spans),
    )


def xemu(cg: Configgen) -> list[Launcher]:
    return [_config_paths(cg, XEMU, cg.emulator(XEMU))]


def mupen64plus(cg: Configgen) -> list[Launcher]:
    return [_config_paths(cg, MUPEN_CONFIG, cg.emulator(MUPEN_GENERATOR))]


def content_files(cg: Configgen) -> list[Launcher]:
    """`if core == x:` writing a BIOS path into a file loaded as the content."""
    src = cg.source(LIBRETRO_GENERATOR)
    files = cg.source(FILES_MODULE)
    env = cg.env(src)
    launchers = []
    for node in ast.walk(src.tree):
        if not (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and ast.unparse(node.test.left) == "core"
            and isinstance(node.test.comparators[0], ast.Constant)
        ):
            continue
        refs = [n for n in ast.walk(node) if isinstance(n, ast.Attribute)
                and ast.unparse(n.value) == "recalboxFiles"]
        names = list(dict.fromkeys(
            name for n in refs if (name := cg.under_bios(spell(n, env))) is not None
        ))
        opened = [c for c in _calls(node, name="open")
                  if len(c.args) == 2 and spell(c.args[1], env) == "w"]
        if not names:
            continue
        target = spell(opened[0].args[0], env) if len(opened) == 1 else None
        returned = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
        if target is None or not returned:
            src.fail(f"line {node.lineno}: BIOS path is not written to a file passed on")
        constants = {n.attr for n in refs if cg.under_bios(spell(n, env)) is not None}
        lines = [n.lineno for n in files.tree.body if _assigned_name(n) in constants]
        launchers.append(Launcher(
            emulator=node.test.comparators[0].value, build="libretro", kind="fixed_name",
            names=names, case_insensitive=False, search_dir=cg.bios,
            passes_to=f"written into {target}, which is loaded as the content",
            fails_when_missing=False,
            source_ref=f"{src.ref([(node.lineno, node.end_lineno)])}, "
                       f"{files.ref([(line, line) for line in lines])}",
        ))
    if not launchers:
        src.fail("no core is given a BIOS path through a content file")
    return launchers


def core_file_options(cg: Configgen, directories: list[Launcher]) -> list[Launcher]:
    """System handlers that set a core option naming the file the core opens."""
    src = cg.source(CORES)
    handlers = _handler_map(src, "fillCoresConfiguration", "specificSystemHandlers")
    table = src.assignment("specificSystemHandlers", src.function("fillCoresConfiguration"))
    defined = {n.name: n for n in ast.walk(src.tree) if isinstance(n, ast.FunctionDef)}
    launchers = []
    for function_name, systems in handlers.items():
        function = defined.get(function_name)
        if function is None:
            continue
        for call in _calls(function, attr="setString"):
            if not (len(call.args) == 2 and all(isinstance(a, ast.Constant) for a in call.args)
                    and call.args[0].value in FILE_OPTIONS):
                continue
            option = call.args[0].value
            core = FILE_OPTIONS[option]
            directory = core_directory(directories, core)
            spans = [(k.lineno, k.lineno) for k, v in zip(table.value.keys, table.value.values)
                     if isinstance(v, ast.Attribute) and v.attr == function_name]
            launchers.append(Launcher(
                emulator=core, build="libretro", kind="core_option",
                names=[call.args[1].value.strip('"')], search_dir=directory.search_dir,
                passes_to=f"core option {option}",
                depends_on_option=f"system {', '.join(systems)}",
                source_ref=f"{src.ref([(function.lineno, function.end_lineno or function.lineno), *spans])}, "
                           f"{directory.source_ref}",
            ))
    found = {str(launcher.passes_to).split()[-1] for launcher in launchers}
    missing = sorted(set(FILE_OPTIONS) - found)
    if missing:
        src.fail(f"no system handler sets {', '.join(missing)}")
    return launchers


def xroar(cg: Configgen) -> list[Launcher]:
    """-rompath os.path.join(recalboxFiles.BIOS, args.system) on the command line."""
    src = cg.source(XROAR)
    generate = src.function("generate")
    # args.system is the ES system name, as self.system.Name is elsewhere.
    env = {**cg.env(src, generate), "args.system": SYSTEM_PLACEHOLDER}
    found = [
        (flag, value)
        for node in ast.walk(generate)
        if isinstance(node, ast.List)
        for flag, value in zip(node.elts, node.elts[1:])
        if isinstance(flag, ast.Constant) and flag.value == "-rompath"
    ]
    if len(found) != 1:
        src.fail(f"expected one -rompath on the command line, found {len(found)}")
    flag, value = found[0]
    directory = cg.bios_dir(spell(value, env), src, "-rompath")
    return [Launcher(
        emulator=cg.emulator(XROAR), build="standalone", kind="passes_path", names=[],
        search_dir=directory, passes_to="command line -rompath",
        source_ref=src.ref([(flag.lineno, value.end_lineno or value.lineno)]),
    )]


STANDALONE: tuple[Callable[[Configgen], list[Launcher]], ...] = (
    hatari, gsplus, amiberry, pcsx2, xemu, mupen64plus, xroar,
)
LIBRETRO: tuple[Callable[[Configgen], list[Launcher]], ...] = (
    core_assets, hatari_libretro, content_files,
)


def extract_launchers(read: Callable[[str], str]) -> list[dict[str, Any]]:
    """Every launcher record, read through `read(repo-relative path)`."""
    cg = Configgen(read)
    directories = system_directories(cg)
    launchers = [launcher for extractor in STANDALONE for launcher in extractor(cg)]
    launchers += dolphin(cg)
    launchers += directories
    launchers += [launcher for extractor in LIBRETRO for launcher in extractor(cg)]
    launchers += core_file_options(cg, directories)
    return [launcher.entry() for launcher in launchers]
