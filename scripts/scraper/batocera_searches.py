"""Batocera generators that search BIOS names: DuckStation's region lists and Hatari's TOS."""

from __future__ import annotations

import ast

from .batocera_configgen import Configgen, _config_option, _path_value
from .configgen_launchers import (
    Launcher,
    Source,
    _assigned_name,
    _calls,
    _locate,
    _mentions,
    _run,
    end_line,
)


# The placeholder a Hatari TOS name carries for its language suffix.
LANGUAGE_PLACEHOLDER = "L"


def option_names(node: ast.AST) -> list[str]:
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
    options = list(dict.fromkeys(name for stmt in kept for name in option_names(stmt)))
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
