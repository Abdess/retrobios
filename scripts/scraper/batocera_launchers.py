"""Batocera's launcher layer, read from the configgen generators.

Between the file a user drops in /userdata/bios and the emulator, configgen
decides which name is looked for and where it is handed over: the DuckStation
generator walks a list of 22 names per region, Hatari's tries each TOS
version in each language, xemu writes one fixed path into its config. That is
the platform's behaviour, not the emulator's, so it is recorded here with the
lines of the pinned revision that say it.

Every extractor reads a known shape with ast. A generator that no longer has
that shape raises LauncherShapeError: an empty list would read as "this
launcher looks for nothing".
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterable
from typing import Any

from .configgen_launchers import (
    Launcher,
    LauncherShapeError,
    Source,
    assigned_value,
    end_line,
    _assigned_name,
    _calls,
    _enclosing_test,
    _innermost_function,
    _locate,
    _mentions,
    _outermost,
    _run,
)
from .batocera_configgen import Configgen, GENERATORS, _config_option, _path_value
from .configgen_sites import GenericSites, bios_sites

LIBRETRO_OPTIONS = f"{GENERATORS}/libretro/libretroOptions.py"

# The placeholder a Hatari TOS name carries for its language suffix.
LANGUAGE_PLACEHOLDER = "L"


def _option_names(node: ast.AST) -> list[str]:
    """Options a node reads: system.config.get*(o), system.config[o], system.isOptSet(o)."""
    found: list[str] = []
    for child in ast.walk(node):
        option = _config_option(child)
        if option is None and (
            isinstance(child, ast.Subscript)
            and ast.unparse(child.value) == "system.config"
            and isinstance(child.slice, ast.Constant)
        ):
            option = (str(child.slice.value), None)
        if option is None and (
            isinstance(child, ast.Call)
            and ast.unparse(child.func) == "system.isOptSet"
            and child.args
            and isinstance(child.args[0], ast.Constant)
        ):
            option = (str(child.args[0].value), None)
        if option is not None and option[0] not in found:
            found.append(option[0])
    return found


def _raise_message(source: Source, scope: ast.AST, guard: str | None) -> str:
    """The message of `if not <guard>: raise X("...")` in scope."""
    for node in ast.walk(scope):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.UnaryOp)
            and isinstance(node.test.op, ast.Not)
            and isinstance(node.test.operand, ast.Name)
            and node.test.operand.id == guard
            and isinstance(node.body[0], ast.Raise)
        ):
            exc = node.body[0].exc
            if isinstance(exc, ast.Call) and exc.args and isinstance(exc.args[0], ast.Constant):
                return str(exc.args[0].value)
    return source.fail(f"no `if not {guard}: raise` with a message")


def _string_lists(source: Source, node: ast.AST, what: str) -> dict[str, list[str]]:
    value = source.literal(node, what)
    if not (
        isinstance(value, dict)
        and value
        and all(
            isinstance(v, list) and v and all(isinstance(n, str) for n in v)
            for v in value.values()
        )
    ):
        source.fail(f"{what} is not a mapping of name lists")
    return value


def duckstation(cg: Configgen) -> list[Launcher]:
    """bios_lists searched case-insensitively, first hit per region."""
    module = "duckstation.duckstationGenerator"
    src = cg.generator(module)
    lists_node = src.assignment("bios_lists")
    lists = _string_lists(src, lists_node.value, "bios_lists")
    finder = src.function("find_bios")
    listed = [
        call.func.value.id for call in _calls(finder, attr="iterdir")
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
    ]
    lowered = _calls(finder, attr="lower")
    if len(listed) != 1 or not lowered:
        src.fail("find_bios no longer lists the BIOS directory and compares lowercased names")
    search_dir = cg.paths.get(listed[0])
    if search_dir is None:
        src.fail("find_bios lists a directory that is not a batoceraPaths constant")

    generate = src.function("generate")
    located = _locate(generate, lambda stmt: (
        isinstance(stmt, ast.Assign)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Name)
        and stmt.value.func.id == "find_bios"
    ))
    if located is None:
        src.fail("generate no longer calls find_bios")
    body, index = located
    found_var = _assigned_name(body[index])
    if found_var is None:
        src.fail("find_bios result is not bound to a name")
    message = _raise_message(src, generate, found_var)

    region_mapping = src.literal(
        src.assignment("region_mapping", generate).value, "region_mapping"
    )
    branches = [
        (node, node.test.left.value) for node in ast.walk(generate)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Constant)
        and isinstance(node.test.ops[0], ast.In)
        and ast.unparse(node.test.comparators[0]) == found_var
    ]
    if len(branches) != 1:
        src.fail(f"generate no longer branches once on a slot found in {found_var}")
    branch, branch_slot = branches[0]
    writes = _calls(branch, attr="set")
    sections = {
        str(call.args[0].value) for call in writes if isinstance(call.args[0], ast.Constant)
    }
    if len(sections) != 1 or not any(
        isinstance(call.args[1], ast.Subscript)
        and ast.unparse(call.args[1].value) == "region_mapping"
        for call in writes
    ):
        src.fail("the region paths are not written to one config section through region_mapping")
    section = sections.pop()
    shared = {
        branch_slot: [
            str(call.args[1].value) for stmt in branch.body for call in _calls(stmt, attr="set")
            if isinstance(call.args[1], ast.Constant)
        ]
    }

    first, last = _run(body, index, lambda stmt: _mentions(stmt, {section}, {found_var}))
    ref = src.ref([
        (src.span(first)[0], end_line(last)),
        (finder.lineno, end_line(finder)),
        src.span(lists_node),
    ])
    launchers = []
    for slot, names in lists.items():
        keys = shared.get(slot) or ([region_mapping[slot]] if slot in region_mapping else None)
        if not keys:
            src.fail(f"bios_lists slot {slot} is written nowhere")
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="names_searched",
            slot=slot, names=names, case_insensitive=True, search_dir=search_dir,
            passes_to=f"[{section}] {', '.join(keys)}",
            fails_when_missing=message, fails_scope="emulator", source_ref=ref,
        ))
    return launchers


def duckstation_legacy(cg: Configgen) -> list[Launcher]:
    """One name list per region, tried with Path.exists, first hit kept."""
    module = "duckstation_legacy.duckstationLegacyGenerator"
    src = cg.generator(module)
    generate = src.function("generate")
    loops = []
    for node in ast.walk(generate):
        if not (
            isinstance(node, ast.For)
            and isinstance(node.iter, ast.Name)
            and isinstance(node.target, ast.Name)
        ):
            continue
        guard = node.body[0]
        if not isinstance(guard, ast.If):
            continue
        test = guard.test
        if not (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr == "exists"
            and isinstance(test.func.value, ast.BinOp)
            and isinstance(test.func.value.left, ast.Name)
            and ast.unparse(test.func.value.right) == node.target.id
        ):
            continue
        bound = {
            _assigned_name(stmt): stmt for stmt in guard.body
            if isinstance(stmt, ast.Assign) and ast.unparse(stmt.value) == node.target.id
        }
        flags = {
            _assigned_name(stmt) for stmt in guard.body
            if isinstance(stmt, ast.Assign)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is True
        }
        if len(bound) != 1 or len(flags) != 1:
            src.fail(f"the loop over {node.iter.id} no longer keeps one file and one flag")
        loops.append((node.iter.id, next(iter(bound)), flags.pop(), test.func.value.left.id))
    if not loops:
        src.fail("generate no longer tries BIOS names with Path.exists")
    flags = {flag for _l, _v, flag, _d in loops}
    dirs = {directory for _l, _v, _f, directory in loops}
    if len(flags) != 1 or len(dirs) != 1 or next(iter(dirs)) not in cg.paths:
        src.fail("the region loops no longer share one flag and one BIOS directory")
    flag = flags.pop()
    search_dir = cg.paths[dirs.pop()]
    message = _raise_message(src, generate, flag)

    writes: dict[str, tuple[str, str]] = {}
    for call in _calls(generate, attr="set"):
        if len(call.args) != 3:
            continue
        section_node, key_node, var_node = call.args
        if (
            isinstance(section_node, ast.Constant)
            and isinstance(key_node, ast.Constant)
            and isinstance(var_node, ast.Name)
        ):
            writes[var_node.id] = (str(section_node.value), str(key_node.value))

    list_nodes = {name: src.assignment(name, generate) for name, _v, _f, _d in loops}
    # A name never bound (None) is mentioned by no statement.
    tracked = {
        name for name in (*list_nodes, *(v for _l, v, _f, _d in loops), flag)
        if name is not None
    }
    first_list = min(list_nodes.values(), key=lambda node: node.lineno).node
    located = _locate(generate, lambda stmt: stmt is first_list)
    if located is None:
        src.fail(f"line {first_list.lineno} is outside generate")
    body, index = located
    sections = {section for section, _key in writes.values()}
    first, last = _run(body, index, lambda stmt: _mentions(stmt, sections, tracked))
    ref = src.ref([(src.span(first)[0], end_line(last))])

    launchers = []
    for list_name, var, _flag, _dir in loops:
        if var not in writes:
            src.fail(f"{var} is written to no config key")
        section, key = writes[var]
        names = src.literal(list_nodes[list_name].value, list_name)
        if not (isinstance(names, list) and names and all(isinstance(n, str) for n in names)):
            src.fail(f"{list_name} is not a list of names")
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="names_searched",
            slot=key.removeprefix("Path"), names=names, case_insensitive=False,
            search_dir=search_dir, passes_to=f"[{section}] {key}",
            fails_when_missing=message, fails_scope="emulator", source_ref=ref,
        ))
    return launchers


def _loaded(stmt: ast.stmt) -> set[str]:
    """Names an assignment reads on its right-hand side."""
    value = getattr(stmt, "value", None)
    return {n.id for n in ast.walk(value) if isinstance(n, ast.Name)} if value else set()


def _branch_assigns(stmt: ast.stmt, needed: set[str]) -> bool:
    """Whether an if statement assigns one of the names in any branch."""
    return isinstance(stmt, ast.If) and any(
        _assigned_name(node) in needed for node in ast.walk(stmt)
    )


def _trace(body: list[ast.stmt], index: int) -> list[ast.stmt]:
    """body[index], the assignments before it that bind what it reads, and
    the command-line additions that read any of those names.

    An if statement that assigns a name read is kept with what its test
    reads (KNULLI's `if system.isOptSet("model") ...: machine = ...`)."""
    kept = [body[index]]
    needed = _loaded(body[index])
    for stmt in reversed(body[:index]):
        if _assigned_name(stmt) in needed:
            kept.append(stmt)
            needed |= _loaded(stmt)
        elif _branch_assigns(stmt, needed):
            kept.append(stmt)
            needed |= {n.id for n in ast.walk(stmt) if isinstance(n, ast.Name)}
    produced = {name for stmt in kept if (name := _assigned_name(stmt)) is not None}
    kept += [
        stmt for stmt in body
        if isinstance(stmt, ast.AugAssign) and _mentions(stmt.value, set(), produced)
    ]
    return sorted(kept, key=lambda stmt: stmt.lineno)


def _tos_name_parts(src: Source, finder: ast.FunctionDef) -> tuple[str, str, str]:
    """(marker, prefix, suffix) of the names findBestTos builds."""
    marker = prefix = suffix = None
    for node in ast.walk(finder):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Constant)
            and isinstance(node.test.ops[0], ast.In)
            and len(node.orelse) == 1
            and isinstance(node.orelse[0], ast.Assign)
            and isinstance(node.orelse[0].value, ast.JoinedStr)
        ):
            parts = node.orelse[0].value.values
            if (
                len(parts) == 2
                and isinstance(parts[0], ast.Constant)
                and isinstance(parts[1], ast.FormattedValue)
            ):
                marker, prefix = str(node.test.left.value), str(parts[0].value)
    # Batocera: tos_path = biosdir / f"{biosversion}{v_language}.img".
    # KNULLI: filename = f"{biosversion}{v_language}.img".
    names_built = []
    for node in ast.walk(finder):
        value = node.value if isinstance(node, ast.Assign) else None
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
            value = value.right
        if isinstance(value, ast.JoinedStr):
            parts = value.values
            if (
                len(parts) == 3
                and all(isinstance(p, ast.FormattedValue) for p in parts[:2])
                and isinstance(parts[2], ast.Constant)
            ):
                names_built.append(str(parts[2].value))
    if len(names_built) == 1:
        suffix = names_built[0]
    if marker is None or prefix is None or suffix is None:
        src.fail("findBestTos no longer builds <tos{version} or etos*><language>.img")
    return marker, prefix, suffix


def _tos_command_args(
    kept: list[ast.stmt], *, machine_var: str | None, tos_var: str | None,
    search_dir: str, paths: dict[str, str],
) -> list[str]:
    """The command-line additions of the traced statements, the TOS as <file>."""
    args: list[str] = []
    for stmt in kept:
        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.value, ast.List):
            for element in stmt.value.elts:
                if isinstance(element, ast.Constant):
                    args.append(str(element.value))
                elif isinstance(element, ast.Name) and element.id == machine_var:
                    args.append("{machine}")
                elif isinstance(element, ast.Name) and element.id == tos_var:
                    args.append("<file>")
                elif (
                    isinstance(element, ast.BinOp)
                    and isinstance(element.right, ast.Name)
                    and element.right.id == tos_var
                    and _path_value(element.left, paths) == search_dir
                ):
                    # KNULLI returns the bare name and joins it: BIOS / tos.
                    args.append("<file>")
    return args


def hatari(cg: Configgen) -> list[Launcher]:
    """findBestTos: per machine, each TOS version in each language."""
    module = "hatari.hatariGenerator"
    src = cg.generator(module)
    finder = src.function("findBestTos")
    languages = src.literal(src.assignment("all_languages", finder).value, "all_languages")
    machines = _string_lists(
        src, src.assignment("all_machines_bios", finder).value, "all_machines_bios"
    )
    if not (
        isinstance(languages, list) and languages and all(isinstance(x, str) for x in languages)
    ):
        src.fail("all_languages is not a list of strings")

    marker, prefix, suffix = _tos_name_parts(src, finder)
    raised = [node for node in ast.walk(finder) if isinstance(node, ast.Raise)]
    exc = raised[0].exc if len(raised) == 1 else None
    if not (isinstance(exc, ast.Call) and exc.args and isinstance(exc.args[0], ast.JoinedStr)):
        src.fail("findBestTos no longer raises one formatted message")
    template = exc.args[0]

    generate = src.function("generate")
    located = _locate(generate, lambda stmt: (
        isinstance(stmt, ast.Assign)
        and isinstance(stmt.value, ast.Call)
        and ast.unparse(stmt.value.func).endswith(".findBestTos")
    ))
    if located is None:
        src.fail("generate no longer calls findBestTos")
    body, index = located
    found = body[index]
    if not (isinstance(found, ast.Assign) and isinstance(found.value, ast.Call)):
        src.fail("generate no longer calls findBestTos")
    call = found.value
    if not call.args or not isinstance(call.args[0], ast.Name) or call.args[0].id not in cg.paths:
        src.fail("findBestTos is not given a batoceraPaths directory")
    search_dir = cg.paths[call.args[0].id]
    kept = _trace(body, index)
    options = list(dict.fromkeys(name for stmt in kept for name in _option_names(stmt)))
    spans = [src.span(stmt) for stmt in kept] + [(finder.lineno, end_line(finder))]
    second = call.args[1] if len(call.args) > 1 else None
    args = _tos_command_args(
        kept, machine_var=second.id if isinstance(second, ast.Name) else None,
        tos_var=_assigned_name(found), search_dir=search_dir, paths=cg.paths,
    )
    if "<file>" not in args:
        src.fail("the TOS findBestTos returns is not put on the command line")

    ref = src.ref(spans)
    launchers = []
    for machine, versions in machines.items():
        message = "".join(
            str(part.value) if isinstance(part, ast.Constant) else machine
            for part in template.values
        )
        names = [
            f"{v if marker in v else prefix + v}{{{LANGUAGE_PLACEHOLDER}}}{suffix}"
            for v in versions
        ]
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="names_searched",
            slot=machine, names=names, expands={LANGUAGE_PLACEHOLDER: languages},
            case_insensitive=False, search_dir=search_dir,
            passes_to=" ".join(args).replace("{machine}", machine),
            fails_when_missing=message, depends_on_option=", ".join(options),
            source_ref=ref,
        ))
    return launchers


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
        and _option_names(node.value)
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
    option = _option_names(console[0].value)[0]
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


def _system_branches(scope: ast.FunctionDef) -> list[tuple[str, ast.If]]:
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


def _render(message: ast.JoinedStr, var: str, value: str) -> str:
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
    for system, branch in _system_branches(generate):
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
                _render(message, binary, path) for message in (missing, not_executable)
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


# Generators that hand a directory of /userdata/bios to the emulator through
# its environment, with the module holding their path constants.
ENVIRONMENT_GENERATORS = (("flycast.flycastGenerator", "flycast/flycastPaths.py"),)


def environment_directories(cg: Configgen) -> list[Launcher]:
    """Command(..., env={KEY: <path under BIOS>}) in the generator."""
    launchers: list[Launcher] = []
    for module, paths_module in ENVIRONMENT_GENERATORS:
        src = cg.generator(module)
        constants = dict(cg.paths)
        for node in cg.source(f"{cg.generators}/{paths_module}").tree.body:
            name = _assigned_name(node)
            value = _path_value(getattr(node, "value", None), constants)
            if name is not None and value is not None:
                constants[name] = value
        prefix = cg.bios.rstrip("/")
        found = [
            (str(key.value), value, key)
            for call in _calls(src.tree, attr="Command")
            for keyword in call.keywords
            if keyword.arg == "env" and isinstance(keyword.value, ast.Dict)
            for key, item in zip(keyword.value.keys, keyword.value.values)
            if isinstance(key, ast.Constant)
            and (value := _path_value(item, constants)) is not None
            and (value == prefix or value.startswith(prefix + "/"))
        ]
        if not found:
            src.fail("the command environment names no /userdata/bios directory")
        launchers.extend(
            Launcher(
                emulator=cg.emulator(module), build="standalone", kind="passes_path",
                names=[], search_dir=value, passes_to=f"environment {key}",
                source_ref=src.ref([(node.lineno, end_line(node))]),
            )
            for key, value, node in found
        )
    return launchers


# Generators that hand the emulator a /userdata/bios directory through its
# configuration: a line written to the file it reads (openMSX's script.tcl
# filepool entries, xroar.conf rompath) or a key saved to it (amiberry.conf
# rom_path).
CONFIG_DIRECTORY_GENERATORS = (
    "openmsx.openmsxGenerator",
    "xroar.xroarGenerator",
    "amiberry.amiberryGenerator",
)


def config_directories(
    cg: Configgen, modules: Iterable[str] = CONFIG_DIRECTORY_GENERATORS
) -> list[Launcher]:
    """file.write("<line naming a BIOS directory>") and settings.save(key, <BIOS directory>)."""
    prefix = cg.bios.rstrip("/")
    inside = re.compile(rf"{re.escape(prefix)}(?:/[^\s\"';]*)?")
    launchers: list[Launcher] = []
    for module in modules:
        src = cg.generator(module)
        constants = dict(cg.paths)
        for node in src.tree.body:
            name = _assigned_name(node)
            value = _path_value(getattr(node, "value", None), constants)
            if name is not None and value is not None:
                constants[name] = value
        found: list[tuple[str, str, ast.Call]] = []
        for call in _calls(src.tree, attr="write"):
            text = call.args[0] if len(call.args) == 1 else None
            if isinstance(text, ast.Constant) and isinstance(text.value, str):
                line = text.value.strip()
                named = inside.search(line)
                if named:
                    found.append((named.group(0), f"written: {line}", call))
        for call in _calls(src.tree, attr="save"):
            if len(call.args) != 2 or not isinstance(call.args[0], ast.Constant):
                continue
            value = _path_value(call.args[1], constants)
            if value is None and isinstance(call.args[1], ast.Constant):
                value = str(call.args[1].value)
            if value is not None and (value.rstrip("/") == prefix or value.startswith(prefix + "/")):
                found.append((value, str(call.args[0].value), call))
        if not found:
            src.fail("hands no /userdata/bios directory through its config")
        launchers.extend(
            Launcher(
                emulator=cg.emulator(module), build="standalone", kind="passes_path",
                names=[], search_dir=directory, passes_to=passes_to,
                source_ref=src.ref([src.span(call)]),
            )
            for directory, passes_to, call in found
        )
    return launchers


# Generators that start the emulator from a folder they enter with os.chdir.
WORKING_DIRECTORY_GENERATORS = ("shadps4.shadps4Generator",)


def working_directories(cg: Configgen) -> list[Launcher]:
    """os.chdir(<folder>) in the generators above, before the command runs.

    shadPS4 reads its user folder below the working directory first
    (std::filesystem::current_path() / "user"): Batocera enters
    /userdata/system/configs/shadps4.
    """
    launchers = []
    for module in WORKING_DIRECTORY_GENERATORS:
        src = cg.generator(module)
        calls = _calls(src.tree, attr="chdir")
        if len(calls) != 1 or len(calls[0].args) != 1:
            src.fail("one os.chdir(folder) call")
        call = calls[0]
        argument = call.args[0]
        constants = dict(cg.paths)
        spans = [(call.lineno, call.end_lineno or call.lineno)]
        if isinstance(argument, ast.Name):
            scope = _innermost_function(src, call)
            assigned = src.assignment(argument.id, scope)
            spans.append((assigned.lineno, assigned.end_lineno or assigned.lineno))
            folder = _path_value(assigned.value, constants)
        else:
            folder = _path_value(argument, constants)
        if folder is None:
            src.fail("os.chdir names no folder")
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="passes_path", names=[],
            search_dir=folder, passes_to=f"working directory of {src.path.rsplit('/', 1)[-1]}",
            source_ref=src.ref(spans),
        ))
    return launchers


# libretro core options whose value names the BIOS file the core opens.
FILE_OPTIONS = (("_o2em_options", "o2em_bios"), ("_neocd_options", "neocd_bios"))


def core_file_options(cg: Configgen) -> list[Launcher]:
    """_set_from_system(settings, option, system, [name], default=...)."""
    src = cg.source(cg.libretro_options)
    table = src.assignment("_option_functions").value
    if not isinstance(table, ast.Dict):
        src.fail("_option_functions is not a dict display")
    cores: dict[str, list[str]] = {}
    for key, value in zip(table.keys, table.values):
        if isinstance(key, ast.Constant) and isinstance(value, ast.Name):
            cores.setdefault(value.id, []).append(str(key.value))
    launchers = []
    for function_name, setting in FILE_OPTIONS:
        function = src.function(function_name)
        if function_name not in cores:
            src.fail(f"no core is configured by {function_name}")
        calls = [
            call for call in _calls(function, name="_set_from_system")
            if len(call.args) >= 2
            and isinstance(call.args[1], ast.Constant)
            and call.args[1].value == setting
        ]
        if len(calls) != 1:
            src.fail(f"{function_name} no longer sets {setting} once")
        call = calls[0]
        named = call.args[3] if len(call.args) > 3 else None
        option = str(named.value) if isinstance(named, ast.Constant) else setting
        default = next((k.value for k in call.keywords if k.arg == "default"), None)
        if isinstance(default, ast.Constant):
            names = [str(default.value)]
            condition = None
        elif (
            isinstance(default, ast.IfExp)
            and isinstance(default.body, ast.Constant)
            and isinstance(default.orelse, ast.Constant)
        ):
            names = [str(default.body.value), str(default.orelse.value)]
            condition = ast.unparse(default.test)
        else:
            src.fail(f"{setting} has no literal default")
        depends = option if condition is None else f"{option} (default by {condition})"
        launchers.append(Launcher(
            emulator=", ".join(cores[function_name]), build="libretro", kind="core_option",
            names=names, passes_to=f"core option {setting}", depends_on_option=depends,
            source_ref=src.ref([src.span(_outermost(function, call))]),
        ))
    return launchers


# Batocera's patches to an emulator's own path code. Each rewrites one of
# the folders the emulator derives (yuzu's family generates every user
# folder through Generate<Name>Path) to a fixed folder of /userdata.
PATH_PATCHES = ("package/batocera/emulators/citron/002-adjust-paths.patch",)
_PATH_REMOVED = re.compile(r"^-\s*Generate\w+Path\((\w+Path::\w+),\s*(.+?)\);\s*$")
_PATH_ADDED = re.compile(r'^\+\s*Generate\w+Path\((\w+Path::\w+),\s*"(/userdata/bios[^"]*)"\);\s*$')


def patched_paths(read: Callable[[str], str], patches: tuple[str, ...] = PATH_PATCHES) -> list[Launcher]:
    """The emulator folders a path patch points at the BIOS tree.

    A patch line replacing `GenerateCitronPath(CitronPath::KeysDir,
    citron_path / KEYS_DIR)` with a literal /userdata/bios folder hands
    that folder to the emulator under the handle the code names it by.
    The emulator is the package the patch belongs to.
    """
    launchers: list[Launcher] = []
    for path in patches:
        lines = read(path).splitlines()
        target = ""
        removed: dict[str, tuple[int, str]] = {}
        found = 0
        for number, line in enumerate(lines, 1):
            if line.startswith("+++ b/"):
                target = line[len("+++ b/"):]
                continue
            if (old := _PATH_REMOVED.match(line)):
                removed[old.group(1)] = (number, old.group(2))
                continue
            if not (new := _PATH_ADDED.match(line)):
                continue
            handle, folder = new.groups()
            if handle not in removed or not target:
                raise LauncherShapeError(f"{path}:{number}: {handle} added with no line it replaces")
            first, original = removed[handle]
            found += 1
            launchers.append(Launcher(
                emulator=path.split("/")[-2], build="standalone", kind="passes_path", names=[],
                search_dir=folder,
                passes_to=f"{handle} in {target} returns it, in place of {original}",
                fails_when_missing=False,
                source_ref=f"{path}:{first}-{number}",
            ))
        if not found:
            raise LauncherShapeError(f"{path}: no path rewritten to /userdata/bios")
    return launchers


# Generators whose command line hands the emulator /userdata/bios folders as
# search paths: MAME's `-rompath` and `-samplepath` (mame/mameGenerator.py).
SEARCH_PATH_GENERATORS = ("mame/mameGenerator.py",)


def search_paths(cg: Configgen) -> list[Launcher]:
    """Every /userdata/bios path a generator's command line names, read as
    KNULLI's generic reader reads its fork of the same generator."""
    # A boot disk image the command line names (the Macintosh's
    # /userdata/bios/<boot_disk>.img) is a file, no search path.
    return [
        launcher
        for path in SEARCH_PATH_GENERATORS
        for launcher in bios_sites(cg, GenericSites(path, "passes_path"))
        if re.match(r"command line -\w", launcher.passes_to or "")
    ]


EXTRACTORS: tuple[Callable[[Configgen], list[Launcher]], ...] = (
    duckstation, duckstation_legacy, hatari, xemu, melonds, mupen64plus,
    x16emu, gsplus, lexaloffle, environment_directories, config_directories,
    core_file_options, working_directories, search_paths,
)


def extract_launchers(read: Callable[[str], str]) -> list[dict[str, Any]]:
    """Every launcher record, read through `read(repo-relative path)`."""
    cg = Configgen(read)
    launchers = [launcher for extractor in EXTRACTORS for launcher in extractor(cg)]
    launchers += patched_paths(read)
    return [launcher.entry() for launcher in launchers]
