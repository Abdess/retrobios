"""KNULLI's launcher layer, read from its configgen and its board scripts.

KNULLI is built on Batocera and keeps configgen under its own package
(package/system/knulli-configgen). Where a generator is still Batocera's
code (DuckStation, xemu, mupen64plus, x16emu, the flycast environment, the
hatari and melonDS forms batocera_launchers accepts), Batocera's extractor
reads it. The others are older or KNULLI's own: the lexaloffle generator logs
and returns instead of raising, libretroOptions is one function of
`if (system.config['core'] == ...)` blocks, and the PICO-8 binary is
installed by board/fsoverlay/usr/bin/knulli-install-pico8.

The remaining generators name a /userdata/bios path in a command line, a
config key, an environment variable, a copy or a presence test. bios_sites()
reads each of those uses with ast and the context that consumes it, and
GENERIC_SITES says, per generator, whether the path is a file or a directory.
A generator in that table that no longer names a BIOS path raises
LauncherShapeError, as every other extractor does.
"""

from __future__ import annotations

import ast
import posixpath
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import yaml

try:
    from .batocera_launchers import (
        PATH_PATCHES,
        Configgen,
        config_directories,
        _path_value,
        _render,
        _system_branches,
        duckstation,
        duckstation_legacy,
        environment_directories,
        hatari,
        melonds,
        mupen64plus,
        patched_paths,
        x16emu,
        working_directories,
        xemu,
    )
    from .configgen_launchers import (
        Launcher,
        LauncherShapeError,
        Source,
        _assigned_name,
    )
    from .shell_launchers import LauncherPatternMissing, Script, source_ref
except ImportError:
    from batocera_launchers import (  # type: ignore[no-redef]
        PATH_PATCHES,
        Configgen,
        config_directories,
        _path_value,
        _render,
        _system_branches,
        duckstation,
        duckstation_legacy,
        environment_directories,
        hatari,
        melonds,
        mupen64plus,
        patched_paths,
        x16emu,
        working_directories,
        xemu,
    )
    from configgen_launchers import (  # type: ignore[no-redef]
        Launcher,
        LauncherShapeError,
        Source,
        _assigned_name,
    )
    from shell_launchers import (  # type: ignore[no-redef]
        LauncherPatternMissing,
        Script,
        source_ref,
    )

CONFIGGEN = "package/system/knulli-configgen/configgen/configgen"
GENERATORS = f"{CONFIGGEN}/generators"
LIBRETRO_OPTIONS = f"{GENERATORS}/libretro/libretroOptions.py"
PICO8_INSTALLER = "board/fsoverlay/usr/bin/knulli-install-pico8"
ES_FEATURES = "package/emulationstation/knulli-es-system/es_features.yml"

# The generators of Batocera's config_directories that KNULLI keeps in the
# same shape: openMSX's filepool lines and amiberry's rom_path.
CONFIG_DIRECTORY_GENERATORS = ("openmsx.openmsxGenerator", "amiberry.amiberryGenerator")


def knulli_config_directories(cg: Configgen) -> list[Launcher]:
    return config_directories(cg, CONFIG_DIRECTORY_GENERATORS)


# Batocera's extractors that read KNULLI's generators unchanged.
SHARED = (
    duckstation, duckstation_legacy, hatari, xemu, melonds, mupen64plus, x16emu,
    environment_directories, working_directories, knulli_config_directories,
)


def _lines(node: ast.AST) -> tuple[int, int]:
    """First and last line of a node."""
    first: int = getattr(node, "lineno", 0)
    return first, getattr(node, "end_lineno", None) or first


def _bound(node: ast.AST) -> ast.expr | None:
    """The value of an assignment statement."""
    value = getattr(node, "value", None)
    return value if isinstance(value, ast.expr) else None


def configgen(read: Callable[[str], str]) -> Configgen:
    """KNULLI's configgen: Batocera's reader at KNULLI's package, no legacy map."""
    return Configgen(read, CONFIGGEN, legacy_map=False)


def _error_guard(
    src: Source, scope: ast.FunctionDef, test: Callable[[ast.expr], bool], what: str
) -> tuple[ast.If, ast.JoinedStr]:
    """`if <test>: eslog.error(f"..."); return -1` and its message."""
    found = []
    for node in ast.walk(scope):
        if not (isinstance(node, ast.If) and test(node.test) and len(node.body) == 2):
            continue
        logged, returned = node.body
        if (
            isinstance(logged, ast.Expr)
            and isinstance(logged.value, ast.Call)
            and ast.unparse(logged.value.func) == "eslog.error"
            and logged.value.args
            and isinstance(logged.value.args[0], ast.JoinedStr)
            and isinstance(returned, ast.Return)
        ):
            found.append((node, logged.value.args[0]))
    if len(found) != 1:
        src.fail(f"expected one `if {what}: eslog.error(...); return`, found {len(found)}")
    return found[0]


def lexaloffle(cg: Configgen) -> list[Launcher]:
    """Per system, BIN_PATH under /userdata/bios run as the emulator binary."""
    module = "lexaloffle.lexaloffleGenerator"
    src = cg.generator(module)
    generate = src.function("generate")
    defined = {
        name: node for node in src.tree.body if (name := _assigned_name(node)) is not None
    }
    constants = dict(cg.paths)
    for name, node in defined.items():
        value = _path_value(_bound(node), constants)
        if value is not None:
            constants[name] = value
    missing, missing_message = _error_guard(
        src, generate,
        lambda t: isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not)
        and isinstance(t.operand, ast.Call) and ast.unparse(t.operand.func).endswith(".exists"),
        "not <binary>.exists()",
    )
    binary = ast.unparse(missing.test.operand.func).removesuffix(".exists")  # type: ignore[attr-defined]
    access, access_message = _error_guard(
        src, generate,
        lambda t: isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not)
        and ast.unparse(t.operand).startswith(f"os.access({binary}"),
        f"not os.access({binary}, ...)",
    )
    commands = [
        node for node in ast.walk(generate)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.List)
        and node.value.elts and ast.unparse(node.value.elts[0]) == binary
    ]
    if len(commands) != 1:
        src.fail(f"expected one command line starting with {binary}, found {len(commands)}")
    prefix = cg.bios.rstrip("/") + "/"
    launchers = []
    for system, branch in _system_branches(generate):
        bound = [
            stmt for stmt in branch.body
            if _assigned_name(stmt) == binary and isinstance(_bound(stmt), ast.Name)
        ]
        if len(bound) != 1:
            src.fail(f"the {system} branch does not set {binary} once")
        constant = ast.unparse(bound[0].value)  # type: ignore[attr-defined]
        path = constants.get(constant)
        if path is None or not path.startswith(prefix):
            src.fail(f"{constant} is not a path under {cg.bios}")
        messages = [_render(m, binary, path) for m in (missing_message, access_message)]
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="fixed_name",
            slot=system, names=[path[len(prefix):]], case_insensitive=False,
            search_dir=cg.bios, passes_to="exec",
            fails_when_missing=", ".join(messages),
            source_ref=src.ref([
                src.span(defined[constant]), src.span(branch.test), src.span(bound[0]),
                _lines(missing), _lines(access),
                src.span(commands[0]),
            ]),
        ))
    if not launchers:
        src.fail("generate no longer branches on system.name")
    return launchers


def pico8_installer(read: Callable[[str], str], bios: str) -> list[Launcher]:
    """knulli-install-pico8: unzips the Raspberry Pi build and moves it into the BIOS folder."""
    script = Script(PICO8_INSTALLER, read(PICO8_INSTALLER))
    lines: set[int] = set()
    archive_line, archive = script.find(r"\$\(ls -d (\S+\.zip)", "the PICO-8 zip lookup")
    lines.add(archive_line)
    guard_line, _ = script.find(r'^if \[ -z \$PICO_8_ZIPFILE \]', "the missing zip test")
    message_line, message = script.find(r'^\s*echo "([^"]+)"', "the missing zip message", guard_line)
    lines |= {guard_line, message_line}
    names: list[str] = []
    prefix = bios.rstrip("/") + "/"
    for number, line in script.code():
        moved = re.match(r"\s*mv\s+(\S+)\s+(\S+)\s*$", line)
        if moved is None:
            continue
        used: set[int] = set()
        source = script.expand(moved.group(1), number, used)
        target = script.expand(moved.group(2).strip('"'), number, used)
        if not target.startswith(prefix):
            continue
        if target.endswith("/"):
            target += source.rsplit("/", 1)[-1]
        names.append(target[len(prefix):])
        lines |= used | {number}
    if not names:
        raise script.missing(f"mv into {bios}")
    folder = names[0].rsplit("/", 1)[0]
    return [Launcher(
        emulator="lexaloffle", build="standalone", kind="moves", names=names,
        case_insensitive=False, search_dir=bios,
        passes_to=f"moved from {archive.group(1)} into {prefix}{folder}",
        fails_when_missing=message.group(1),
        source_ref=source_ref([(PICO8_INSTALLER, lines)]),
    )]


def _quoted(node: ast.AST) -> str | None:
    """The value of a '"name"' core option literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value
        if len(value) >= 2 and value[0] == value[-1] == '"':
            return value[1:-1]
    return None


def _cores_of(test: ast.expr) -> list[str]:
    """Core names `system.config['core'] == 'x'`, `in [...]` or an `or` of them tests."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return [core for value in test.values for core in _cores_of(value)]
    if (
        isinstance(test, ast.Compare)
        and ast.unparse(test.left) == "system.config['core']"
        and len(test.ops) == 1
    ):
        right = test.comparators[0]
        if isinstance(test.ops[0], ast.Eq) and isinstance(right, ast.Constant):
            return [str(right.value)]
        if isinstance(test.ops[0], ast.In) and isinstance(right, (ast.List, ast.Tuple)):
            return [str(e.value) for e in right.elts if isinstance(e, ast.Constant)]
    return []


# libretro core options whose value names the BIOS file the core opens,
# the same two batocera_launchers.FILE_OPTIONS reads.
FILE_OPTIONS = ("o2em_bios", "neocd_bios")


def core_file_options(cg: Configgen) -> list[Launcher]:
    """if isOptSet(o): save(o, option) elif ...: save(o, '"a"') else: save(o, '"b"')."""
    src = cg.source(LIBRETRO_OPTIONS)
    function = src.function("generateCoreSettings")
    launchers = []
    for setting in FILE_OPTIONS:
        chains = [
            node for node in ast.walk(function)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == f"system.isOptSet({setting!r})"
        ]
        if len(chains) != 1:
            src.fail(f"expected one `if system.isOptSet({setting!r})`, found {len(chains)}")
        chain = chains[0]
        names: list[str] = []
        conditions: list[str] = []
        branch: ast.If | None = chain
        tail: list[ast.stmt] = chain.orelse
        while branch is not None:
            tail = branch.orelse
            if branch is not chain:
                saved = _saved(branch.body, setting)
                if saved is None:
                    src.fail(f"a branch of {setting} saves no literal name")
                names.append(saved)
                conditions.append(ast.unparse(branch.test))
            branch = tail[0] if len(tail) == 1 and isinstance(tail[0], ast.If) else None
        default = _saved(tail, setting)
        if default is None:
            src.fail(f"{setting} has no literal default")
        names.append(default)
        holder = next(
            (
                node for node in ast.walk(function)
                if isinstance(node, ast.If) and _cores_of(node.test)
                and any(child is chain for child in ast.walk(node))
            ),
            None,
        )
        if holder is None:
            src.fail(f"{setting} is not set under a core test")
        depends = setting if not conditions else f"{setting} (default by {', '.join(conditions)})"
        launchers.append(Launcher(
            emulator=", ".join(_cores_of(holder.test)), build="libretro", kind="core_option",
            names=names, passes_to=f"core option {setting}", depends_on_option=depends,
            source_ref=src.ref([src.span(holder.test), _lines(chain)]),
        ))
    return launchers


def _saved(body: list[ast.stmt], setting: str) -> str | None:
    """The literal a one-statement body saves under setting."""
    if len(body) != 1 or not isinstance(body[0], ast.Expr):
        return None
    call = body[0].value
    if (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "save"
        and len(call.args) == 2
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == setting
    ):
        return _quoted(call.args[1])
    return None


# ---------------------------------------------------------------------------
# Generic reading of the /userdata/bios paths a generator hands over.


@dataclass(frozen=True)
class GenericSites:
    """A generator module whose BIOS path uses bios_sites() reads.

    kind is fixed_name when the path names a file, passes_path when it names
    a directory. A copy is recorded as `copies` whatever the kind, its names
    read from the folder the code copies from and passes_to the target. caller
    names the module and function whose core test selects the cores this
    helper module runs for, emulator the name when no core test does.
    """

    path: str
    kind: str
    build: str = "standalone"
    emulator: str | None = None
    caller: tuple[str, str] | None = None


# The names configgen gives the command it builds.
COMMAND_NAMES = {"commandArray", "commandLine"}

GENERIC_SITES = (
    GenericSites("dolphin/dolphinGenerator.py", "fixed_name"),
    GenericSites("yabasanshiro/yabasanshiroGenerator.py", "fixed_name"),
    GenericSites("rpcs3/rpcs3Generator.py", "fixed_name"),
    GenericSites("ryujinx/ryujinxGenerator.py", "fixed_name"),
    GenericSites("pcsx2/pcsx2Generator.py", "fixed_name"),
    GenericSites("aethersx2/aethersx2Generator.py", "fixed_name"),
    GenericSites("gsplus/gsplusGenerator.py", "passes_path"),
    GenericSites("tsugaru/tsugaruGenerator.py", "passes_path"),
    GenericSites("scummvm/scummvmGenerator.py", "passes_path"),
    GenericSites("fsuae/fsuaeGenerator.py", "passes_path"),
    GenericSites("mame/mameGenerator.py", "passes_path"),
    GenericSites("fpinball/fpinballGenerator.py", "passes_path"),
    GenericSites(
        "libretro/libretroRetroarchCustom.py", "passes_path", "libretro", emulator="retroarch"
    ),
    GenericSites("libretro/libretroConfig.py", "passes_path", "libretro"),
    GenericSites(
        "libretro/libretroMAMEConfig.py", "passes_path", "libretro",
        caller=("libretro/libretroConfig.py", "generateMAMEConfigs"),
    ),
)


@dataclass
class _Site:
    """One use of a BIOS path, and the record fields it contributes."""

    path: str
    passes_to: str
    kind: str | None
    lines: list[tuple[int, int]]
    conditions: list[str]
    cores: list[str]
    expands: dict[str, list[str]] = field(default_factory=dict)
    # A copy reads its file from `source` and hands it to `passes_to`.
    source: str | None = None


class _Reader:
    """The BIOS path uses of one generator module."""

    def __init__(self, cg: Configgen, src: Source) -> None:
        self.cg = cg
        self.src = src
        self.bios = cg.bios.rstrip("/")
        self.parents: dict[int, ast.AST] = {}
        self.copy_sources: dict[int, str] = {}
        for parent in ast.walk(src.tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[id(child)] = parent
        self.constants = dict(cg.paths)
        folder = src.path.rsplit("/", 1)[0]
        for node in src.tree.body:
            if (
                isinstance(node, ast.ImportFrom)
                and node.level == 1
                and node.module
                and node.module.endswith("Paths")
            ):
                paths = cg.source(f"{folder}/{node.module}.py")
                self._define(paths.tree.body)
        self._define(src.tree.body)

    def _define(self, body: list[ast.stmt]) -> None:
        for node in body:
            name = _assigned_name(node)
            value = self.resolve(getattr(node, "value", None))
            if name is not None and value is not None:
                self.constants[name] = value

    def under_bios(self, value: str | None) -> bool:
        return value is not None and (
            value.rstrip("/") == self.bios or f"{self.bios}/" in value
        )

    def resolve(self, node: ast.AST | None) -> str | None:
        """The path an expression spells, unknown parts of an f-string as <expr>."""
        if node is None:
            return None
        value = _path_value(node, self.constants)
        if value is not None:
            return value
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value.strip('"')
            return text if text.startswith("/") else None
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "str" and len(node.args) == 1:
            return self.resolve(node.args[0])
        if isinstance(node, ast.JoinedStr):
            parts = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    parts.append(str(part.value))
                else:
                    inner = self.resolve(part.value)  # type: ignore[attr-defined]
                    parts.append(inner if inner is not None else f"<{ast.unparse(part.value)}>")  # type: ignore[attr-defined]
            return "".join(parts).strip('"')
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Div)
            and isinstance(node.right, (ast.Constant, ast.Name))
        ):
            left = self.resolve(node.left)
            right = node.right.value if isinstance(node.right, ast.Constant) else None
            if isinstance(node.right, ast.Name):
                right = self._placeholder(node.right)
            if left is not None and isinstance(right, str):
                return f"{left.rstrip('/')}/{right}"
        return None

    def _placeholder(self, name: ast.Name) -> str | None:
        """{var} for a comprehension variable over a literal list."""
        comprehension = self._comprehension(name)
        if comprehension is None:
            return None
        return "{" + name.id + "}"

    def _comprehension(self, name: ast.Name) -> tuple[str, list[str]] | None:
        node: ast.AST | None = name
        while node is not None:
            node = self.parents.get(id(node))
            if isinstance(node, (ast.GeneratorExp, ast.ListComp)):
                for generator in node.generators:
                    if isinstance(generator.target, ast.Name) and generator.target.id == name.id:
                        values = self._literal_list(generator.iter, node)
                        return (name.id, values) if values else None
        return None

    def _literal_list(self, node: ast.AST, scope_of: ast.AST) -> list[str] | None:
        if isinstance(node, ast.List):
            return [str(e.value) for e in node.elts if isinstance(e, ast.Constant)]
        if isinstance(node, ast.Name):
            scope = self.function_of(scope_of)
            bound = [
                n for n in ast.walk(scope or self.src.tree)
                if _assigned_name(n) == node.id and isinstance(_bound(n), ast.List)
            ]
            if len(bound) == 1:
                return self._literal_list(_bound(bound[0]), scope_of)  # type: ignore[arg-type]
        return None

    def function_of(self, node: ast.AST) -> ast.FunctionDef | None:
        while node is not None:
            node = self.parents.get(id(node))  # type: ignore[assignment]
            if isinstance(node, ast.FunctionDef):
                return node
        return None

    def statement_of(self, node: ast.AST) -> ast.stmt:
        while not isinstance(node, ast.stmt):
            node = self.parents[id(node)]
        return node

    def maximal(self) -> Iterator[tuple[ast.AST, str]]:
        """Each expression spelling a BIOS path that no larger one contains."""
        for node in ast.walk(self.src.tree):
            if not isinstance(node, ast.expr):
                continue
            value = self.resolve(node)
            if value is None and isinstance(node, ast.Constant) and isinstance(node.value, str):
                # A line written to a config file: openmsx's settings.tcl.
                written = re.search(rf"{re.escape(self.bios)}(?:/[^\s\"';]*)?", node.value)
                parent = self.parents.get(id(node))
                if written and isinstance(parent, ast.Call) and ast.unparse(parent.func).endswith(".write"):
                    yield node, written.group(0)
                continue
            if not self.under_bios(value):
                continue
            parent = self.parents.get(id(node))
            if isinstance(parent, (ast.FormattedValue, ast.JoinedStr)):
                continue
            if isinstance(parent, ast.expr) and self.under_bios(self.resolve(parent)):
                continue
            if isinstance(parent, ast.Call) and ast.unparse(parent.func) == "str":
                continue
            yield node, value  # type: ignore[misc]

    def conditions(
        self, node: ast.AST, guards: bool = False
    ) -> tuple[list[str], list[tuple[int, int]]]:
        """Tests of the ifs a node sits in, outermost first, and their lines.

        A presence test of a BIOS path is a guard, kept for its lines only,
        unless guards is set: a copy made only when its source or its target
        is there carries the test as a condition.
        """
        tests: list[str] = []
        spans: list[tuple[int, int]] = []
        child, parent = node, self.parents.get(id(node))
        while parent is not None and not isinstance(parent, ast.FunctionDef):
            if isinstance(parent, ast.If) and child is not parent.test:
                spans.append(self.src.span(parent.test))
                text = ast.unparse(parent.test)
                if guards or not self._is_guard(parent.test):
                    in_else = any(child is stmt for stmt in parent.orelse)
                    tests.append(f"not ({text})" if in_else else text)
            child, parent = parent, self.parents.get(id(parent))
        return list(reversed(tests)), spans

    def _is_guard(self, test: ast.expr) -> bool:
        for n in ast.walk(test):
            if not (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "exists"
            ):
                continue
            receiver = n.func.value
            if self.under_bios(self.resolve(receiver)):
                return True
            if isinstance(receiver, ast.Name) and self.local_value(receiver) is not None:
                return True
        return False

    def cores(self, node: ast.AST) -> list[str]:
        child, parent = node, self.parents.get(id(node))
        while parent is not None:
            if isinstance(parent, ast.If) and child is not parent.test and _cores_of(parent.test):
                return _cores_of(parent.test)
            child, parent = parent, self.parents.get(id(parent))
        return []

    def uses(self, node: ast.AST, value: str) -> Iterator[tuple[ast.AST, str | None, str | None]]:
        """(node read, passes_to, kind) for each consumer of a BIOS path expression.

        A path bound to a local name is followed to each read of that name.
        A use with no consumer (a presence test, a mkdir) yields passes_to None.
        """
        parent = self.parents.get(id(node))
        if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
            target = parent.targets[0]
            if isinstance(target, ast.Name):
                scope = self.function_of(parent)
                if scope is None:
                    return
                for read in ast.walk(scope):
                    if (
                        isinstance(read, ast.Name)
                        and read.id == target.id
                        and isinstance(read.ctx, ast.Load)
                        and read.lineno > parent.lineno
                    ):
                        yield from self.uses(read, value)
                return
            if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                yield node, str(target.slice.value), None
                return
        yield node, *self.consumer(node, value)

    def _command_line(self, display: ast.List | ast.Tuple) -> bool:
        """Whether a list display is (part of) the command configgen runs.

        It is assigned or added to commandArray (or commandLine for the
        libretro MAME cmd file), or it starts with an absolute binary path.
        """
        first = display.elts[0] if display.elts else None
        if isinstance(first, ast.Constant) and str(first.value).startswith("/"):
            return True
        holder = self.parents.get(id(display))
        targets: list[ast.expr] = []
        if isinstance(holder, ast.Assign):
            targets = holder.targets
        elif isinstance(holder, ast.AugAssign):
            targets = [holder.target]
        elif (
            isinstance(holder, ast.Call)
            and isinstance(holder.func, ast.Attribute)
            and holder.func.attr in ("extend", "append")
        ):
            targets = [holder.func.value]
        names = {
            ast.unparse(t.value if isinstance(t, ast.Subscript) else t) for t in targets
        }
        return bool(names & COMMAND_NAMES)

    def local_value(self, name: ast.Name) -> str | None:
        """The BIOS path a local name is bound to once in its function."""
        scope = self.function_of(name)
        if scope is None:
            return None
        bound = [
            self.resolve(_bound(n))
            for n in ast.walk(scope) if _assigned_name(n) == name.id
        ]
        return bound[0] if len(bound) == 1 and self.under_bios(bound[0]) else None

    def consumer(self, node: ast.AST, value: str) -> tuple[str | None, str | None]:
        parent = self.parents.get(id(node))
        if isinstance(parent, ast.Attribute):
            return None, None
        if isinstance(parent, (ast.List, ast.Tuple)):
            holder = self.parents.get(id(parent))
            if isinstance(holder, (ast.For, ast.comprehension)):
                return None, None
            if not self._command_line(parent):
                return None, None
            index = next(i for i, e in enumerate(parent.elts) if e is node)
            if isinstance(node, ast.JoinedStr) and isinstance(node.values[0], ast.Constant):
                flag = str(node.values[0].value)
                if flag.startswith("-") and flag.endswith("=") and value.startswith(flag):
                    return f"command line {flag[:-1]}", None
            previous = parent.elts[index - 1] if index else None
            if isinstance(previous, ast.Constant) and str(previous.value).startswith("-"):
                return f"command line {previous.value!s}", None
            if index:
                return f"command line argument {index}", None
            return None, None
        if isinstance(parent, ast.Call):
            func = parent.func
            attr = func.attr if isinstance(func, ast.Attribute) else None
            consts = [a.value for a in parent.args if isinstance(a, ast.Constant)]
            if attr == "save" and len(parent.args) == 2 and parent.args[1] is node and consts:
                return str(consts[0]), None
            if attr == "set" and len(parent.args) == 3 and parent.args[2] is node and len(consts) >= 2:
                return f"[{consts[0]!s}] {consts[1]!s}", None
            receiver = func.value if isinstance(func, ast.Attribute) else None
            if attr in ("copy", "copyfile", "copy2") and receiver is not None and ast.unparse(receiver) == "shutil":
                source, target = parent.args[0], parent.args[1]
                self.copy_sources[id(node)] = value if source is node else (
                    self.resolve(source) or ast.unparse(source)
                )
                return (value if target is node else self.resolve(target) or ast.unparse(target)), "copies"
            if (
                attr == "append"
                and isinstance(receiver, ast.Name)
                and receiver.id in COMMAND_NAMES
                and isinstance(node, ast.JoinedStr)
                and isinstance(node.values[0], ast.Constant)
            ):
                flag = str(node.values[0].value)
                if flag.startswith("-") and flag.endswith("=") and value.startswith(flag):
                    return f"command line {flag[:-1]}", None
            if attr == "write" and isinstance(node, ast.Constant):
                return f"written: {str(node.value).strip()}", None
            return None, None
        if isinstance(parent, ast.Dict):
            key = next(
                (k for k, v in zip(parent.keys, parent.values) if v is node), None
            )
            if isinstance(key, ast.Constant):
                holder = self.parents.get(id(parent))
                is_env = (
                    isinstance(holder, ast.keyword) and holder.arg == "env"
                ) or _assigned_name(holder) == "env"  # type: ignore[arg-type]
                return (f"environment {key.value!s}" if is_env else str(key.value)), None
        return None, None

    def sites(self) -> list[_Site]:
        found: list[_Site] = []
        guards: list[tuple[ast.AST, str]] = []
        for node, value in self.maximal():
            if isinstance(self.statement_of(node), (ast.Import, ast.ImportFrom)):
                continue
            if self.function_of(node) is None and isinstance(self.parents.get(id(node)), ast.Assign):
                continue
            for read, passes_to, kind in self.uses(node, value):
                parent = self.parents.get(id(read))
                if (
                    passes_to is None
                    and isinstance(parent, ast.Attribute)
                    and parent.attr == "exists"
                ):
                    guards.append((read, value))
                if passes_to is None:
                    continue
                found.append(self._site(read, value, passes_to, kind, node))
        for read, value in guards:
            if any(site.path == value for site in found):
                site = next(s for s in found if s.path == value)
                site.lines.append(self.src.span(self.statement_of(read)))
                continue
            found.append(self._guard_site(read, value))
        return sorted(found, key=lambda site: site.lines[0])

    def _site(
        self, read: ast.AST, value: str, passes_to: str, kind: str | None, defined: ast.AST
    ) -> _Site:
        tests, spans = self.conditions(read, guards=kind == "copies")
        lines = [self.src.span(self.statement_of(read)), *spans]
        if defined is not read:
            # A path bound in one branch and read after the if: the branch
            # that bound it is a condition of the read.
            bound_tests, bound_spans = self.conditions(defined)
            tests = list(dict.fromkeys([*bound_tests, *tests]))
            lines += [self.src.span(self.statement_of(defined)), *bound_spans]
        return _Site(
            value, passes_to, kind, lines, tests, self.cores(read), self._expands(read),
            self.copy_sources.get(id(read)),
        )

    def _guard_site(self, read: ast.AST, value: str) -> _Site:
        """A presence test whose if body is the only consumer of the path."""
        test = self.statement_of(read)
        if not isinstance(test, ast.If):
            self.src.fail(f"line {test.lineno} tests a BIOS path outside an if")
        first = test.body[0]
        described = ast.unparse(first)
        call = first.value if isinstance(first, ast.Expr) else None
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "set":
            literal = [a.value for a in call.args if isinstance(a, ast.Constant)]
            if len(literal) == 3:
                described = f"[{literal[0]!s}] {literal[1]!s} = {literal[2]!s}"
        tests, spans = self.conditions(test)
        return _Site(
            value, f"presence sets {described}", None,
            [(test.lineno, first.end_lineno), *spans],  # type: ignore[list-item]
            tests, self.cores(test), self._expands(read),
        )

    def _expands(self, node: ast.AST) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for name in ast.walk(node):
            if isinstance(name, ast.Name):
                bound = self._comprehension(name)
                if bound is not None:
                    found[bound[0]] = bound[1]
        return found


def _caller_cores(cg: Configgen, caller: tuple[str, str]) -> list[str]:
    path, function = caller
    src = cg.source(f"{cg.generators}/{path}")
    for node in ast.walk(src.tree):
        if not isinstance(node, ast.If) or not _cores_of(node.test):
            continue
        if any(
            isinstance(n, ast.Call) and ast.unparse(n.func).endswith(f".{function}")
            for stmt in node.body for n in ast.walk(stmt)
        ):
            return _cores_of(node.test)
    src.fail(f"no core test calls {function}")


def bios_sites(cg: Configgen, spec: GenericSites) -> list[Launcher]:
    """One record per BIOS path and consumer of a generator module."""
    src = cg.source(f"{cg.generators}/{spec.path}")
    reader = _Reader(cg, src)
    sites = reader.sites()
    if not sites:
        src.fail("hands over no /userdata/bios path")
    module = spec.path.removesuffix(".py").replace("/", ".")
    caller_cores = _caller_cores(cg, spec.caller) if spec.caller else []
    grouped: dict[tuple[str, str, str, tuple[str, ...]], list[_Site]] = {}
    for site in sites:
        flag = site.passes_to.removeprefix("command line ")
        if site.path.startswith(f"{flag}="):
            site.path = site.path[len(flag) + 1:]
        emulator = (
            spec.emulator
            or ", ".join(site.cores or caller_cores)
            or (cg.emulator(module) if spec.build == "standalone" else "")
        )
        if not emulator:
            src.fail(f"no core runs the {site.passes_to} use at line {site.lines[0][0]}")
        key = (emulator, site.path, site.passes_to, tuple(site.conditions))
        grouped.setdefault(key, []).append(site)
    prefix = cg.bios.rstrip("/") + "/"
    launchers = []
    for (emulator, path, passes_to, _conditions), group in grouped.items():
        kind = group[0].kind or spec.kind
        conditions = list(dict.fromkeys(c for site in group for c in site.conditions))
        expands = {k: v for site in group for k, v in site.expands.items()}
        names: list[str] = []
        search_dir = path
        source = group[0].source
        if kind == "copies" and source is not None and not source.startswith(prefix):
            # Copied into BIOS: the file is read from the folder it comes from.
            search_dir, _, name = source.rpartition("/")
            names = [name]
        elif kind in ("fixed_name", "copies"):
            if not path.startswith(prefix):
                src.fail(f"{path} names no file under {cg.bios}")
            names, search_dir = [path[len(prefix):]], cg.bios
        launchers.append(Launcher(
            emulator=emulator, build=spec.build, kind=kind, names=names,
            expands=expands or None,
            case_insensitive=False if names else None,
            search_dir=search_dir, passes_to=passes_to, fails_when_missing=False,
            depends_on_option=" and ".join(conditions) or None,
            source_ref=src.ref([span for site in group for span in site.lines]),
        ))
    return launchers


# Generators that write a [Folders] path relative to the config folder they
# are given. PCSX2 and AetherSX2 resolve those paths against their data root,
# the folder holding inis/, which configureINI receives as config_directory.
RELATIVE_FOLDERS = (
    ("pcsx2/pcsx2Generator.py", "configureINI"),
    ("aethersx2/aethersx2Generator.py", "configureINI"),
)


def relative_folders(
    cg: Configgen, specs: tuple[tuple[str, str], ...] = RELATIVE_FOLDERS
) -> list[Launcher]:
    """parser.set(section, key, "../<path>") resolved against config_directory."""
    launchers = []
    for path, function_name in specs:
        src = cg.source(f"{cg.generators}/{path}")
        reader = _Reader(cg, src)
        function = src.function(function_name)
        if not function.args.args:
            src.fail(f"{function_name} takes no config folder")
        folder = function.args.args[0].arg
        ini = [
            node for node in ast.walk(function)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.BinOp)
            and ast.unparse(node.value).startswith(f"{folder} /")
            and ast.unparse(node.value).endswith(".ini'")
        ]
        if len(ini) != 1:
            src.fail(f"{function_name} builds no one ini path under {folder}")
        parts = sorted(
            (n for n in ast.walk(ini[0].value)
             if isinstance(n, ast.Constant) and isinstance(n.value, str)),
            key=lambda n: (n.lineno, n.col_offset),
        )
        ini_name = posixpath.join(*(str(n.value) for n in parts))
        calls = [
            node for node in ast.walk(src.tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == function_name and node.args
        ]
        if len(calls) != 1:
            src.fail(f"expected one call of {function_name}, found {len(calls)}")
        base = reader.resolve(calls[0].args[0])
        if base is None or not base.startswith("/"):
            src.fail(f"{function_name} is given a folder that is not a path")
        found = 0
        for call in ast.walk(function):
            if not (
                isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "set" and len(call.args) == 3
                and all(isinstance(a, ast.Constant) for a in call.args)
            ):
                continue
            section, key, value = (str(a.value) for a in call.args)  # type: ignore[attr-defined]
            if not value.startswith("../"):
                continue
            resolved = posixpath.normpath(posixpath.join(base, value))
            if not reader.under_bios(resolved):
                continue
            found += 1
            launchers.append(Launcher(
                emulator=cg.emulator(path.removesuffix(".py").replace("/", ".")),
                build="standalone", kind="passes_path", names=[], search_dir=resolved,
                passes_to=f"{ini_name} [{section}] {key} = {value}, relative to {base}",
                fails_when_missing=False,
                source_ref=src.ref([
                    src.span(reader.statement_of(calls[0])), src.span(ini[0]), _lines(call),
                ]),
            ))
        if not found:
            src.fail(f"{function_name} writes no relative folder under {cg.bios}")
    return launchers


def _yaml_node(root: yaml.Node, keys: tuple[str, ...], path: str) -> yaml.Node:
    node = root
    for key in keys:
        if not isinstance(node, yaml.MappingNode):
            raise LauncherShapeError(f"{path}: {key} is not under a mapping")
        found = [v for k, v in node.value if isinstance(k, yaml.ScalarNode) and k.value == key]
        if len(found) != 1:
            raise LauncherShapeError(f"{path}: no {'/'.join(keys)}")
        node = found[0]
    return node


def option_choices(read: Callable[[str], str], keys: tuple[str, ...]) -> tuple[list[str], tuple[int, int]]:
    """The values es_features.yml offers for an option, and their lines."""
    node = _yaml_node(yaml.compose(read(ES_FEATURES)), (*keys, "choices"), ES_FEATURES)
    if not isinstance(node, yaml.MappingNode) or not node.value:
        raise LauncherShapeError(f"{ES_FEATURES}: {'/'.join(keys)} has no choices")
    values = [str(v.value) for _k, v in node.value if isinstance(v, yaml.ScalarNode)]
    return values, (node.start_mark.line + 1, node.end_mark.line)


@dataclass(frozen=True)
class BootDisk:
    """A generator that names a BIOS file from an option value, and the ES feature offering it."""

    path: str
    feature: tuple[str, ...]
    build: str = "standalone"
    caller: tuple[str, str] | None = None


BOOT_DISKS = (
    BootDisk("mame/mameGenerator.py", ("mame", "systems", "macintosh", "cfeatures")),
    BootDisk(
        "libretro/libretroMAMEConfig.py",
        ("libretro", "cores", "mame", "systems", "macintosh", "cfeatures"), "libretro",
        ("libretro/libretroConfig.py", "generateMAMEConfigs"),
    ),
)


def _option_template(reader: _Reader, node: ast.AST) -> tuple[str, str] | None:
    """(option, name) for '<bios>/' + system.config[option] + '<suffix>'."""
    if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)):
        return None
    left, suffix = node.left, node.right
    if not (
        isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add)
        and isinstance(left.left, ast.Constant) and isinstance(suffix, ast.Constant)
        and isinstance(left.right, ast.Subscript)
        and ast.unparse(left.right.value) == "system.config"
        and isinstance(left.right.slice, ast.Constant)
    ):
        return None
    prefix = str(left.left.value).strip('"')
    if not prefix.startswith(reader.bios + "/"):
        return None
    option = str(left.right.slice.value)
    name = prefix[len(reader.bios) + 1:] + "{" + option + "}" + str(suffix.value).strip('"')
    return option, name


def boot_disks(
    cg: Configgen, read: Callable[[str], str], specs: tuple[BootDisk, ...] = BOOT_DISKS
) -> list[Launcher]:
    """`if system.config[o] in [...]: X = bios + o + ext else: X = bios + o + ext2`."""
    launchers = []
    for spec in specs:
        src = cg.source(f"{cg.generators}/{spec.path}")
        reader = _Reader(cg, src)
        module = spec.path.removesuffix(".py").replace("/", ".")
        emulator = (
            ", ".join(_caller_cores(cg, spec.caller)) if spec.caller else cg.emulator(module)
        )
        found = 0
        for chain in ast.walk(src.tree):
            if not (
                isinstance(chain, ast.If) and isinstance(chain.test, ast.Compare)
                and isinstance(chain.test.ops[0], ast.In)
                and isinstance(chain.test.comparators[0], ast.List)
                and ast.unparse(chain.test.left).startswith("system.config[")
            ):
                continue
            branches = [(chain.body, True), (chain.orelse, False)]
            templates = []
            for body, listed in branches:
                flag = next(
                    (str(s.value.value) for s in body if isinstance(s, ast.Assign)
                     and isinstance(s.value, ast.Constant) and str(s.value.value).startswith("-")),
                    None,
                )
                named = [
                    (s, t) for s in body if isinstance(s, ast.Assign)
                    and (t := _option_template(reader, s.value)) is not None
                ]
                if flag is None or len(named) != 1:
                    break
                templates.append((listed, flag, *named[0]))
            if len(templates) != 2:
                continue
            option = templates[0][3][0]
            if option != templates[1][3][0] or ast.unparse(chain.test.left) != f"system.config[{option!r}]":
                src.fail(f"line {chain.lineno} names a file from two options")
            listed_values = [
                str(e.value) for e in chain.test.comparators[0].elts if isinstance(e, ast.Constant)
            ]
            offered, lines = option_choices(read, (*spec.feature, option))
            holder = reader.parents.get(id(chain))
            body = getattr(holder, "body", [])
            index = next(i for i, stmt in enumerate(body) if stmt is chain)
            added = body[index + 1] if index + 1 < len(body) else None
            if not (
                isinstance(added, ast.AugAssign) and isinstance(added.value, ast.List)
                and ast.unparse(added.target) in COMMAND_NAMES
            ):
                src.fail(f"the file chosen at line {chain.lineno} is not put on the command line")
            for listed, flag, statement, (_, name) in templates:
                values = listed_values if listed else [v for v in offered if v not in listed_values]
                if not values:
                    src.fail(f"no {option} value reaches the branch at line {statement.lineno}")
                tests, spans = reader.conditions(statement)
                found += 1
                launchers.append(Launcher(
                    emulator=emulator, build=spec.build, kind="fixed_name", names=[name],
                    expands={option: values}, case_insensitive=False, search_dir=cg.bios,
                    passes_to=f"command line {flag}", fails_when_missing=False,
                    depends_on_option=f"{option} ({' and '.join(tests)})",
                    source_ref=", ".join([
                        src.ref([*spans, src.span(statement), _lines(added)]),
                        f"{ES_FEATURES}:{lines[0]}-{lines[1]}" if not listed else "",
                    ]).rstrip(", "),
                ))
        if not found:
            src.fail("names no BIOS file from an option value")
    return launchers


EXTRACTORS: tuple[Callable[[Configgen], list[Launcher]], ...] = (
    *SHARED, lexaloffle, core_file_options, relative_folders,
)


# KNULLI builds Batocera's emulator packages from this submodule, at the
# batocera.linux commit it pins: Citron's path patch is there.
BATOCERA_SUBMODULE = "batocera"


def extract_launchers(
    read: Callable[[str], str], batocera: Callable[[str], str] | None = None
) -> list[dict[str, Any]]:
    """Every launcher record, read through `read(repo-relative path)`.

    `batocera` reads the batocera submodule at its pinned commit. The
    records it gives name the file by its path in KNULLI's repository.
    """
    cg = configgen(read)
    launchers = [launcher for extractor in EXTRACTORS for launcher in extractor(cg)]
    launchers += pico8_installer(read, cg.bios)
    launchers += boot_disks(cg, read)
    for spec in GENERIC_SITES:
        launchers += bios_sites(cg, spec)
    if batocera is not None:
        prefix = f"{BATOCERA_SUBMODULE}/"
        launchers += patched_paths(
            lambda path: batocera(path.removeprefix(prefix)),
            tuple(prefix + patch for patch in PATH_PATCHES),
        )
    return [launcher.entry() for launcher in launchers]


__all__ = [
    "CONFIGGEN", "GENERIC_SITES", "LauncherPatternMissing", "LauncherShapeError",
    "bios_sites", "configgen", "core_file_options", "extract_launchers", "lexaloffle",
    "pico8_installer",
]
