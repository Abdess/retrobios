"""Every /userdata/bios path a configgen generator names, with its context.

A generator names a BIOS path in a command line, a config key, an
environment variable, a copy or a presence test. bios_sites() reads each of
those uses with ast, and a GenericSites spec says whether the path is a file
or a directory. KNULLI reads most of its generators this way, Batocera its
MAME search paths."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from .batocera_configgen import Configgen, _path_value
from .configgen_launchers import Launcher, Source, _assigned_name, end_line


def _bound(node: ast.AST) -> ast.expr | None:
    """The value of an assignment statement."""
    value = getattr(node, "value", None)
    return value if isinstance(value, ast.expr) else None


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
                    # The other parts of an f-string are its {placeholders}.
                    expr = part.value if isinstance(part, ast.FormattedValue) else part
                    inner = self.resolve(expr)
                    parts.append(inner if inner is not None else f"<{ast.unparse(expr)}>")
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

    def _literal_list(self, node: ast.AST | None, scope_of: ast.AST) -> list[str] | None:
        if isinstance(node, ast.List):
            return [str(e.value) for e in node.elts if isinstance(e, ast.Constant)]
        if isinstance(node, ast.Name):
            scope = self.function_of(scope_of)
            bound = [
                n for n in ast.walk(scope or self.src.tree)
                if _assigned_name(n) == node.id and isinstance(_bound(n), ast.List)
            ]
            if len(bound) == 1:
                return self._literal_list(_bound(bound[0]), scope_of)
        return None

    def function_of(self, node: ast.AST) -> ast.FunctionDef | None:
        current: ast.AST | None = node
        while current is not None:
            current = self.parents.get(id(current))
            if isinstance(current, ast.FunctionDef):
                return current
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
            if value is None or not self.under_bios(value):
                continue
            parent = self.parents.get(id(node))
            if isinstance(parent, (ast.FormattedValue, ast.JoinedStr)):
                continue
            if isinstance(parent, ast.expr) and self.under_bios(self.resolve(parent)):
                continue
            if isinstance(parent, ast.Call) and ast.unparse(parent.func) == "str":
                continue
            yield node, value

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
        if isinstance(parent, (ast.List, ast.Tuple)):
            return self._listed_consumer(node, parent, value)
        if isinstance(parent, ast.Call):
            return self._call_consumer(node, parent, value)
        if isinstance(parent, ast.Dict):
            return self._dict_consumer(node, parent)
        return None, None

    def _listed_consumer(
        self, node: ast.AST, parent: ast.List | ast.Tuple, value: str
    ) -> tuple[str | None, str | None]:
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

    def _call_consumer(
        self, node: ast.AST, parent: ast.Call, value: str
    ) -> tuple[str | None, str | None]:
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

    def _dict_consumer(self, node: ast.AST, parent: ast.Dict) -> tuple[str | None, str | None]:
        key = next(
            (k for k, v in zip(parent.keys, parent.values) if v is node), None
        )
        if not isinstance(key, ast.Constant):
            return None, None
        holder = self.parents.get(id(parent))
        is_env = (
            isinstance(holder, ast.keyword) and holder.arg == "env"
        ) or (holder is not None and _assigned_name(holder) == "env")
        return (f"environment {key.value!s}" if is_env else str(key.value)), None

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
            [(test.lineno, end_line(first)), *spans],
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
    return src.fail(f"no core test calls {function}")


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
