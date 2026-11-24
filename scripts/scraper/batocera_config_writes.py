"""Batocera generators that write a BIOS path into a configuration or onto the command line."""

from __future__ import annotations

import ast
from collections.abc import Callable

from .batocera_configgen import Configgen, _path_value
from .batocera_searches import option_names
from .configgen_launchers import (
    Launcher,
    Source,
    _assigned_name,
    _calls,
    _enclosing_test,
    _innermost_function,
    _mentions,
    _outermost,
    assigned_value,
    end_line,
)


def _config_writes(cg: Configgen, src: Source, emulator: str) -> Launcher:
    """parser.set(section, key, <path under BIOS>) calls of one module."""
    writes = []
    for call in _calls(src.tree, attr="set"):
        if len(call.args) != 3:
            continue
        section_node, key_node, path = call.args
        if not (isinstance(section_node, ast.Constant) and isinstance(key_node, ast.Constant)):
            continue
        name = cg.bios_name(path)
        if name is not None:
            writes.append((call, str(section_node.value), str(key_node.value), name))
    if not writes:
        src.fail("writes no /userdata/bios path into its config")
    spans = []
    conditions = []
    for call, _section, _key, _name in writes:
        scope = _innermost_function(src, call)
        spans.append(src.span(_outermost(scope, call)))
        test = _enclosing_test(scope, call)
        if test is not None and test not in conditions:
            conditions.append(test)
    keys = []
    for _call, section, key, _name in writes:
        label = f"[{section}] {key}"
        if label not in keys:
            keys.append(label)
    return Launcher(
        emulator=emulator, build="standalone", kind="fixed_name",
        names=list(dict.fromkeys(name for *_rest, name in writes)),
        case_insensitive=False, search_dir=cg.bios, passes_to=", ".join(keys),
        depends_on_option=", ".join(conditions) or None, source_ref=src.ref(spans),
    )


def xemu(cg: Configgen) -> list[Launcher]:
    module = "xemu.xemuGenerator"
    return [_config_writes(cg, cg.helper(module, "xemuConfig"), cg.emulator(module))]


def mupen64plus(cg: Configgen) -> list[Launcher]:
    module = "mupen.mupenGenerator"
    return [_config_writes(cg, cg.helper(module, "mupenConfig"), cg.emulator(module))]


def melonds(cg: Configgen) -> list[Launcher]:
    """One record per base_config section whose values are BIOS paths."""
    module = "melonds.melondsGenerator"
    src = cg.generator(module)
    generate = src.function("generate")
    base = src.assignment("base_config", generate)
    if not isinstance(base.value, ast.Dict):
        src.fail("base_config is not a dict display")
    console = [
        node for node in ast.walk(generate)
        if isinstance(node, ast.Assign)
        and ast.unparse(node.targets[0]).startswith("base_config['Emu']['ConsoleType']")
        and option_names(node.value)
    ]
    enabled = [
        (key, value) for key, value in zip(base.value.keys, base.value.values)
        if isinstance(value, ast.Dict)
        and any(
            isinstance(k, ast.Constant) and k.value == "ExternalBIOSEnable" for k in value.keys
        )
    ]
    if len(console) != 1 or len(enabled) != 1:
        src.fail("generate no longer sets Emu.ConsoleType from an option with external BIOS on")
    option = option_names(console[0].value)[0]
    enabled_key, enabled_value = enabled[0]
    if enabled_key is None:
        src.fail("base_config unpacks the section that enables the external BIOS")
    launchers = []
    for key, value in zip(base.value.keys, base.value.values):
        if not isinstance(value, ast.Dict) or not isinstance(key, ast.Constant):
            continue
        read = [
            (str(k.value), cg.bios_name(v)) for k, v in zip(value.keys, value.values)
            if isinstance(k, ast.Constant)
        ]
        entries = [(k, name) for k, name in read if name is not None]
        if not entries:
            continue
        section = str(key.value)
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="fixed_name",
            names=[name for _k, name in entries], case_insensitive=False,
            search_dir=cg.bios,
            passes_to=", ".join(f"{section}.{k}" for k, _n in entries),
            depends_on_option=option,
            source_ref=src.ref([
                (key.lineno, end_line(value)),
                (enabled_key.lineno, end_line(enabled_value)),
                src.span(console[0]),
            ]),
        ))
    if not launchers:
        src.fail("base_config names no BIOS path")
    return launchers


def x16emu(cg: Configgen) -> list[Launcher]:
    """A command-line flag followed by a path under BIOS."""
    module = "x16emu.x16emuGenerator"
    src = cg.generator(module)
    found = []
    for node in ast.walk(src.function("generate")):
        if isinstance(node, ast.List):
            for flag, value in zip(node.elts, node.elts[1:]):
                name = cg.bios_name(value)
                if (
                    isinstance(flag, ast.Constant)
                    and str(flag.value).startswith("-")
                    and name is not None
                ):
                    found.append((flag, str(flag.value), value, name))
    if not found:
        src.fail("the command line passes no /userdata/bios path")
    return [Launcher(
        emulator=cg.emulator(module), build="standalone", kind="fixed_name",
        names=[name for _f, _t, _v, name in found], case_insensitive=False,
        search_dir=cg.bios,
        passes_to=", ".join(f"command line {text}" for _f, text, _v, _n in found),
        source_ref=src.ref([(f.lineno, end_line(v)) for f, _t, v, _n in found]),
    )]


def gsplus(cg: Configgen) -> list[Launcher]:
    """config.save(key, f"{BIOS}/{system.config.get(option, default)}")."""
    module = "gsplus.gsplusGenerator"
    src = cg.generator(module)
    found = []
    for call in _calls(src.tree, attr="save"):
        if len(call.args) == 2 and isinstance(call.args[0], ast.Constant):
            named = cg.option_name(call.args[1])
            if named is not None:
                found.append((call, str(call.args[0].value), *named))
    if len(found) != 1:
        src.fail(f"expected one ROM path built from an option, found {len(found)}")
    call, key, name, option = found[0]
    return [Launcher(
        emulator=cg.emulator(module), build="standalone", kind="fixed_name",
        names=[name], case_insensitive=False, search_dir=cg.bios,
        passes_to=key, depends_on_option=option,
        source_ref=src.ref([src.span(_outermost(src.function("generate"), call))]),
    )]


def system_branches(scope: ast.FunctionDef) -> list[tuple[str, ast.If]]:
    """(system, branch) for each `if system.name == "<name>":` of an if/elif chain."""
    branches: list[tuple[str, ast.If]] = []
    for node in ast.walk(scope):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if (
            isinstance(test, ast.Compare)
            and ast.unparse(test.left) == "system.name"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.comparators[0], ast.Constant)
        ):
            branches.append((str(test.comparators[0].value), node))
    return sorted(branches, key=lambda item: item[1].lineno)


def _guard_message(
    src: Source, scope: ast.FunctionDef, test: Callable[[ast.expr], bool], what: str
) -> tuple[ast.If, ast.JoinedStr]:
    """The `if not <test>: raise X(f"...")` statement and its message."""
    found = [
        (node, message) for node in ast.walk(scope)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.UnaryOp)
        and isinstance(node.test.op, ast.Not)
        and test(node.test.operand)
        and (message := _raised_fstring(node)) is not None
    ]
    if len(found) != 1:
        src.fail(f"expected one `if not {what}: raise` with a message, found {len(found)}")
    return found[0]


def _raised_fstring(node: ast.If) -> ast.JoinedStr | None:
    """The f-string message of `raise X(f"...")` opening the if body."""
    first = node.body[0]
    if (
        isinstance(first, ast.Raise)
        and isinstance(first.exc, ast.Call)
        and first.exc.args
        and isinstance(first.exc.args[0], ast.JoinedStr)
    ):
        return first.exc.args[0]
    return None


def render(message: ast.JoinedStr, var: str, value: str) -> str:
    parts = []
    for part in message.values:
        if isinstance(part, ast.Constant):
            parts.append(str(part.value))
            continue
        # The other parts of an f-string are its {placeholders}.
        expr = part.value if isinstance(part, ast.FormattedValue) else part
        if isinstance(expr, ast.Name) and expr.id == var:
            parts.append(value)
        else:
            parts.append(f"{{{ast.unparse(expr)}}}")
    return "".join(parts)


def lexaloffle(cg: Configgen) -> list[Launcher]:
    """Per system, a binary under BIOS run as the command, its folder on LD_LIBRARY_PATH."""
    module = "lexaloffle.lexaloffleGenerator"
    src = cg.generator(module)
    constants = dict(cg.paths)
    defined: dict[str, ast.stmt] = {}
    for node in src.tree.body:
        name = _assigned_name(node)
        value = _path_value(getattr(node, "value", None), constants)
        if name is not None and value is not None:
            constants[name] = value
            defined[name] = node
    generate = src.function("generate")

    command = [
        (node, head.id) for node in ast.walk(generate)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and (assigned := assigned_value(node)) is not None
        and assigned[0] == "commandArray"
        and isinstance(assigned[1], ast.List)
        and assigned[1].elts
        and isinstance((head := assigned[1].elts[0]), ast.Name)
    ]
    if len(command) != 1:
        src.fail("generate no longer starts commandArray with the binary it runs")
    command_stmt, binary = command[0]

    exists, missing = _guard_message(src, generate, lambda test: (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Attribute)
        and test.func.attr == "exists"
        and ast.unparse(test.func.value) == binary
    ), f"{binary}.exists()")
    access, not_executable = _guard_message(src, generate, lambda test: (
        isinstance(test, ast.Call)
        and ast.unparse(test.func) == "os.access"
        and [ast.unparse(a) for a in test.args] == [binary, "os.X_OK"]
    ), f"os.access({binary}, os.X_OK)")

    env = [
        (key, value)
        for call in _calls(generate, attr="Command")
        for keyword in call.keywords
        if keyword.arg == "env" and isinstance(keyword.value, ast.Dict)
        for key, value in zip(keyword.value.keys, keyword.value.values)
        if isinstance(key, ast.Constant) and key.value == "LD_LIBRARY_PATH"
    ]
    if len(env) != 1:
        src.fail("the command environment no longer sets LD_LIBRARY_PATH once")
    env_key, env_value = env[0]

    prefix = cg.bios.rstrip("/") + "/"
    launchers = []
    for system, branch in system_branches(generate):
        bound = {
            assigned[0]: (stmt, assigned[1], _path_value(assigned[1], constants))
            for stmt in branch.body if (assigned := assigned_value(stmt)) is not None
        }
        if binary not in bound or not (bound[binary][2] or "").startswith(prefix):
            src.fail(f"the {system} branch binds {binary} to no path under {cg.bios}")
        library = [
            name for name in bound
            if name != binary and _mentions(env_value, set(), {name})
        ]
        if len(library) != 1 or not (bound[library[0]][2] or "").startswith(prefix):
            src.fail(f"the {system} branch puts no /userdata/bios folder on LD_LIBRARY_PATH")
        binary_stmt, binary_value, path = bound[binary]
        library_stmt, _library_value, folder = bound[library[0]]
        if path is None:
            src.fail(f"the {system} branch binds {binary} to no path under {cg.bios}")
        test_line = src.span(branch.test)
        constant = next(
            (defined[n.id] for n in ast.walk(binary_value)
             if isinstance(n, ast.Name) and n.id in defined),
            None,
        )
        spans = [test_line, src.span(binary_stmt), src.span(exists), src.span(access),
                 src.span(command_stmt)]
        if constant is not None:
            spans.append(src.span(constant))
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="fixed_name",
            slot=system, names=[path[len(prefix):]],
            case_insensitive=False, search_dir=cg.bios, passes_to="exec",
            fails_when_missing=", ".join(
                render(message, binary, path) for message in (missing, not_executable)
            ),
            source_ref=src.ref(spans),
        ))
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="passes_path",
            slot=system, names=[], search_dir=folder,
            passes_to="environment LD_LIBRARY_PATH",
            source_ref=src.ref([test_line, src.span(library_stmt),
                                (src.span(env_key)[0], src.span(env_value)[1])]),
        ))
    if not launchers:
        src.fail("generate no longer branches on system.name")
    return launchers
