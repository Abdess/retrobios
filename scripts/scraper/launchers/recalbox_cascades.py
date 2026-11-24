"""Recalbox paths tried with os.path.exists down a chain: Hatari's TOS and the GSplus ROM."""

from __future__ import annotations

import ast
import posixpath
from collections.abc import Mapping
from dataclasses import dataclass, field

from .configgen import (
    Launcher,
    Source,
    _assigned_name,
    _calls,
    _locate,
    assigned_value,
    end_line,
)
from .recalbox_configgen import (
    BUILTIN_TOKEN,
    CORES,
    Configgen,
    GSPLUS,
    HATARI,
    TOS_FUNCTIONS,
    assignments,
    expr_call,
    is_setter_call,
    string,
    string_constant,
    spell,
)


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


def _written_path(call: ast.Call, paths: set[str]) -> str | None:
    """X when the last argument of `call` is str(X), X one of `paths`."""
    if not call.args:
        return None
    last = call.args[-1]
    if (
        isinstance(last, ast.Call)
        and ast.unparse(last.func) == "str"
        and isinstance(last.args[0], ast.Name)
        and last.args[0].id in paths
    ):
        return last.args[0].id
    return None


def _tos_setter(
    src: Source, scope: ast.FunctionDef, env: Mapping[str, str]
) -> tuple[ast.Call, str, str]:
    """The setting written from str(<path>), the path variable, and where it goes."""
    paths = {
        name for _node, name, value in assignments(ast.walk(scope))
        if isinstance(value, ast.Call) and ast.unparse(value.func) == "os.path.join"
    }
    setters = [
        (call, var) for call in _calls(scope, attr="setString")
        if (var := _written_path(call, paths)) is not None
    ]
    if len(setters) != 1:
        src.fail(f"{scope.name}: expected one setting written from str(<path>)")
    setter, var = setters[0]
    keys = [spell(arg, env) for arg in setter.args[:-1]]
    if None in keys or len(keys) not in (1, 2):
        src.fail(f"{scope.name}: the TOS is written under a key that is not read")
    passes_to = f"[{keys[0]}] {keys[1]}" if len(keys) == 2 else f"core option {keys[0]}"
    return setter, var, passes_to


@dataclass
class _Cascade:
    """What the branches between the TOS assignment and its setter decide."""

    end: ast.stmt
    chosen: dict[str, str | None] = field(default_factory=dict)
    fallbacks: list[str] = field(default_factory=list)
    absolute: bool | None = None
    override: tuple[str, str] | None = None


def _is_machine_branch(stmt: ast.If) -> bool:
    return (
        isinstance(stmt.test, ast.Compare)
        and isinstance(stmt.test.comparators[0], ast.Name)
        and stmt.test.comparators[0].id.startswith("MACHINE_")
    )


def _machine_branches(
    src: Source, env: Mapping[str, str], stmt: ast.If, var: str, cascade: _Cascade
) -> None:
    """`if machine == MACHINE_X: var = ...` down its elif chain."""
    node: ast.If | None = stmt
    while node is not None:
        value = _assigns(node.body[0], var) if len(node.body) == 1 else None
        machine = node.test.comparators[0] if isinstance(node.test, ast.Compare) else None
        if value is None or not isinstance(machine, ast.Name):
            src.fail(f"line {node.lineno}: machine branch does not set {var}")
        cascade.chosen[machine.id] = spell(value, env)
        orelse = node.orelse
        node = orelse[0] if len(orelse) == 1 and isinstance(orelse[0], ast.If) else None


def _existence_steps(
    cg: Configgen, src: Source, env: Mapping[str, str], stmt: ast.If, var: str,
    cascade: _Cascade,
) -> None:
    """`if not os.path.exists(var): var = ...`, each step nested in the last."""
    node: ast.If | None = stmt
    while node is not None:
        tested = _exists_arg(node.test)
        is_abs = isinstance(tested, ast.Name) and tested.id == var
        is_rel = (
            isinstance(tested, ast.Call)
            and ast.unparse(tested.func) == "os.path.join"
            and spell(tested.args[0], env) == cg.bios
            and ast.unparse(tested.args[1]) == var
        )
        if not (is_abs or is_rel) or (
            cascade.absolute is not None and cascade.absolute != is_abs
        ):
            src.fail(f"line {node.lineno}: the cascade tests something else than {var}")
        cascade.absolute = is_abs
        value = _assigns(node.body[0], var)
        if value is None:
            src.fail(f"line {node.lineno}: cascade step does not set {var}")
        fallback = spell(value, env)
        if fallback is None:
            src.fail(f"line {node.lineno}: cascade step sets {var} to a path that is not read")
        cascade.fallbacks.append(fallback)
        inner = node.body[1:]
        node = inner[0] if len(inner) == 1 and isinstance(inner[0], ast.If) else None


def _rom_override(src: Source, stmt: ast.If, var: str) -> tuple[str, ast.expr] | None:
    """(marker, value) for `if "marker" in rom: var = value`."""
    if not (
        isinstance(stmt.test, ast.Compare)
        and isinstance(stmt.test.ops[0], ast.In)
        and ast.unparse(stmt.test.comparators[0]) in ("rom", "self.rom", "args.rom")
        and len(stmt.body) == 1
    ):
        return None
    marker = string_constant(src, stmt.test.left, "rom path marker")
    value = _assigns(stmt.body[0], var)
    return None if marker is None or value is None else (marker, value)


def _read_cascade(
    cg: Configgen, src: Source, env: Mapping[str, str], body: list[ast.stmt], index: int,
    setter_stmt: ast.stmt | None, var: str,
) -> _Cascade:
    """The machine choice, the existence cascade and the rom path override."""
    cascade = _Cascade(end=body[index])
    i = _skip_imports(body, index + 1)
    while i < len(body) and body[i] is not setter_stmt:
        stmt = body[i]
        if not isinstance(stmt, ast.If):
            src.fail(f"line {stmt.lineno}: unexpected statement in the TOS cascade")
        override = _rom_override(src, stmt, var)
        if _is_machine_branch(stmt):
            _machine_branches(src, env, stmt, var, cascade)
        elif _exists_arg(stmt.test) is not None:
            _existence_steps(cg, src, env, stmt, var, cascade)
        elif override is not None:
            value = spell(override[1], env)
            if value is None:
                src.fail(f"line {stmt.lineno}: rom path override sets {var} to a path that is not read")
            cascade.override = (override[0], value)
        else:
            src.fail(f"line {stmt.lineno}: unexpected branch in the TOS cascade")
        cascade.end = stmt
        i = _skip_imports(body, i + 1)
    return cascade


def _machine_table(src: Source, scope: ast.FunctionDef) -> ast.stmt:
    """The one dict display mapping rom paths to MACHINE_ constants."""
    dicts = [
        node for node in scope.body
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Dict)
        and all(isinstance(v, ast.Name) and v.id.startswith("MACHINE_") for v in node.value.values)
    ]
    if len(dicts) != 1:
        src.fail(f"{scope.name}: no single rom path -> machine table")
    return dicts[0]


def _machine_depends(src: Source, scope: ast.FunctionDef, table: ast.stmt) -> str:
    """The machine comes from the rom path table, else from the config options read."""
    bound = {a.arg for a in scope.args.args} | {
        n for node in ast.walk(scope) if (n := _assigned_name(node))
    }
    options = [
        option for call in _calls(scope, attr="getInt")
        if call.args and (option := string_constant(src, call.args[0], "machine option")) is not None
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name) and call.func.value.id in bound
    ]
    depends = f"machine read from the rom path through {_assigned_name(table)}"
    if options:
        depends += f", else option {', '.join(options)}"
    return depends


def tos_cascade(cg: Configgen, src: Source, scope: ast.FunctionDef, emulator: str,
                build: str) -> list[Launcher]:
    """A TOS path chosen per machine, then tried down an existence cascade."""
    env = cg.env(src, scope)
    setter, var, passes_to = _tos_setter(src, scope, env)

    located = _locate(scope, lambda stmt: _assigns(stmt, var) is not None)
    if located is None:
        src.fail(f"{scope.name}: {var} is never assigned")
    body, index = located
    initial = spell(_assigns(body[index], var), env)
    setter_stmt = _outermost_stmt(body, setter)
    cascade = _read_cascade(cg, src, env, body, index, setter_stmt, var)
    machines = [
        (name, name.removeprefix("MACHINE_").replace("_", "").lower())
        for node in scope.body if (name := _assigned_name(node)) and name.startswith("MACHINE_")
        and name != "MACHINE_UNKNOWN"
    ]
    absolute = cascade.absolute
    if (
        not cascade.chosen or not cascade.fallbacks or absolute is None or not machines
        or initial is None
    ):
        src.fail(f"{scope.name}: no machine choice followed by an existence cascade")

    def relative(value: str | None) -> str:
        name = cg.under_bios(value) if absolute else value
        if name is None:
            src.fail(f"{scope.name}: {value} is not under {cg.bios}")
        return name

    tokens = [v for v in cascade.fallbacks if BUILTIN_TOKEN.fullmatch(posixpath.basename(v))]
    files = [relative(v) for v in cascade.fallbacks if v not in tokens]
    if tokens:
        passes_to += f" ({', '.join(tokens)} when none is found)"
    table = _machine_table(src, scope)
    depends = _machine_depends(src, scope, table)
    machine_lines = [n.lineno for n in scope.body if _assigned_name(n) in dict(machines)]
    if setter_stmt is None:
        src.fail(f"{scope.name}: the setting is not written in the block assigning {var}")
    read = {
        n.id for stmt in body[index:body.index(setter_stmt) + 1]
        for n in ast.walk(stmt) if isinstance(n, ast.Name)
    }
    helpers = [src.span(node) for node, name, value in assignments(scope.body)
               if name in read - {var} and spell(value, env) is not None]
    ref = src.ref([
        (min(machine_lines), max(machine_lines)),
        src.span(table),
        *helpers,
        (src.span(body[index])[0], max(end_line(cascade.end), end_line(setter))),
    ])
    launchers = []
    for constant, slot in machines:
        first = relative(cascade.chosen.get(constant, initial))
        launchers.append(Launcher(
            emulator=emulator, build=build, kind="names_searched", slot=slot,
            names=list(dict.fromkeys([first, *files])), case_insensitive=False,
            search_dir=cg.bios, passes_to=passes_to, fails_when_missing=False,
            depends_on_option=depends, source_ref=ref,
        ))
    override = cascade.override
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


def _gsplus_tries(
    cg: Configgen, src: Source, env: Mapping[str, str], body: list[ast.stmt], index: int
) -> tuple[list[str], str, ast.stmt]:
    """The paths tried down the else chain, the key the found one is written to,
    and the last statement of the chain."""

    def exists_of(test: ast.expr, var: str) -> bool:
        return (
            isinstance(test, ast.Call)
            and ast.unparse(test.func) == "os.path.exists"
            and ast.unparse(test.args[0]) == var
        )

    names: list[str] = []
    key: str | None = None
    stmts, i = body, index
    while True:
        assigned = assigned_value(stmts[i])
        var = assigned[0] if assigned is not None else None
        name = cg.under_bios(spell(assigned[1], env)) if assigned is not None else None
        test = stmts[i + 1] if i + 1 < len(stmts) else None
        if name is None or not (
            isinstance(test, ast.If) and var is not None and exists_of(test.test, var)
        ):
            src.fail(f"line {stmts[i].lineno}: path is not tried with os.path.exists")
        calls = [c for stmt in test.body if (c := expr_call(stmt))]
        for c in calls:
            if not isinstance(c.func, ast.Attribute):
                src.fail(f"line {c.lineno}: a call of the found branch is not a method call")
        written = [
            c for c in calls
            if isinstance(c.func, ast.Attribute) and c.func.attr == "setString"
            and ast.unparse(c.args[1]) == var
        ]
        found = string(written[0].args[0]) if len(written) == 1 else None
        if found is None or (key is not None and found != key):
            src.fail(f"line {test.lineno}: the found path is not written to one key")
        key = found
        names.append(name)
        orelse = test.orelse
        if len(orelse) == 2 and isinstance(orelse[1], ast.If):
            stmts, i = orelse, 0
            continue
        removed = [
            c for stmt in orelse if (c := expr_call(stmt)) and is_setter_call(c, key, "removeOption")
        ]
        if len(orelse) != 1 or not removed:
            src.fail(f"line {test.lineno}: the last miss does not remove {key}")
        return names, key, test


def gsplus(cg: Configgen) -> list[Launcher]:
    """A path tried with os.path.exists down an else chain, and the
    placeholders a per-game .gsplus file can name."""
    src = cg.source(GSPLUS)
    generate = src.function("generate")
    env = cg.env(src, generate)
    emulator = cg.emulator(GSPLUS)

    located = _locate(generate, lambda stmt: (
        (assigned := assigned_value(stmt)) is not None
        and cg.under_bios(spell(assigned[1], env)) is not None
    ))
    if located is None:
        src.fail("generate assigns no path under BIOS")
    body, index = located
    names, key, last = _gsplus_tries(cg, src, env, body, index)
    guard = next(
        node for node in ast.walk(generate)
        if isinstance(node, ast.If) and any(child is body[index] for child in node.orelse)
    )
    marker = string(guard.test.left) if isinstance(guard.test, ast.Compare) else None
    if marker is None:
        src.fail("the BIOS search is not the else of a rom path test")
    launchers = [Launcher(
        emulator=emulator, build="standalone", kind="names_searched", names=names,
        case_insensitive=False, search_dir=cg.bios, passes_to=key, fails_when_missing=False,
        depends_on_option=f'rom path without "{marker}"',
        source_ref=src.ref([(src.span(body[index])[0], end_line(last))]),
    )]
    for node in ast.walk(ast.Module(body=guard.body, type_ignores=[])):
        if not (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Call)
            and is_setter_call(node.test.left, key, "getString")
        ):
            continue
        placeholder = string_constant(src, node.test.comparators[0], "placeholder")
        if placeholder is None:
            continue
        written = [c for stmt in node.body if (c := expr_call(stmt)) and is_setter_call(c, key)]
        name = cg.under_bios(spell(written[0].args[1], env)) if len(written) == 1 else None
        if name is None:
            src.fail(f"line {node.lineno}: placeholder branch writes no BIOS path")
        launchers.append(Launcher(
            emulator=emulator, build="standalone", kind="fixed_name", slot=placeholder,
            names=[name], case_insensitive=False, search_dir=cg.bios, passes_to=key,
            fails_when_missing=False,
            depends_on_option=f'"{marker}" game file whose {key} is {placeholder}',
            source_ref=src.ref([(node.lineno, end_line(written[0]))]),
        ))
    if len(launchers) == 1:
        src.fail("no placeholder of a .gsplus game file is replaced")
    return launchers
