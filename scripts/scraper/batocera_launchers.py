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
    _assigned_name,
    _calls,
    _enclosing_test,
    _innermost_function,
    _locate,
    _mentions,
    _outermost,
    _run,
)

CONFIGGEN = "package/batocera/core/batocera-configgen/configgen/configgen"
GENERATORS = f"{CONFIGGEN}/generators"
PATHS_MODULE = f"{CONFIGGEN}/batoceraPaths.py"
IMPORTER = f"{GENERATORS}/importer.py"
LIBRETRO_OPTIONS = f"{GENERATORS}/libretro/libretroOptions.py"

# The placeholder a Hatari TOS name carries for its language suffix.
LANGUAGE_PLACEHOLDER = "L"


def _config_option(node: ast.AST) -> tuple[str, Any] | None:
    """(option, default) when `node` is system.config.get*(option, default)."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.startswith("get")
        and ast.unparse(node.func.value) == "system.config"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    ):
        return None
    second = node.args[1] if len(node.args) > 1 else None
    default = second.value if isinstance(second, ast.Constant) else None
    return node.args[0].value, default


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


def path_constants(source: Source) -> dict[str, str]:
    """batoceraPaths' module constants that are plain paths."""
    constants: dict[str, str] = {}
    for node in source.tree.body:
        name = _assigned_name(node)
        if name is None:
            continue
        value = _path_value(node.value, constants)  # type: ignore[union-attr]
        if value is not None:
            constants[name] = value
    if "BIOS" not in constants:
        source.fail("no BIOS path constant")
    return constants


def configs_root(cg: Configgen) -> dict[str, str]:
    """Where configgen keeps the emulators' configs, relative to the BIOS folder.

    batoceraPaths' CONFIGS (/userdata/system/configs), the folder a generator
    starts an emulator from (shadPS4's configs/shadps4), with the lines that
    build it and BIOS.
    """
    import posixpath  # noqa: PLC0415

    src = cg.source(f"{cg.generators.rsplit('/', 1)[0]}/batoceraPaths.py")
    if "CONFIGS" not in cg.paths:
        src.fail("no CONFIGS path constant")
    wanted: set[str] = {"CONFIGS", "BIOS"}
    spans = []
    for node in reversed(src.tree.body):
        name = _assigned_name(node)
        if name in wanted and isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value:
            spans.append((node.lineno, node.end_lineno or node.lineno))
            wanted |= {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
    return {
        "path": cg.paths["CONFIGS"],
        "from_bios": posixpath.relpath(cg.paths["CONFIGS"], cg.bios),
        "source_ref": src.ref(spans),
    }


def _path_value(node: ast.AST | None, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Path"
        and len(node.args) == 1
    ):
        if isinstance(node.args[0], ast.Constant):
            return str(node.args[0].value)
        return _path_value(node.args[0], constants)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _path_value(node.left, constants)
        right = node.right.value if isinstance(node.right, ast.Constant) else None
        if left is not None and isinstance(right, str):
            return f"{left.rstrip('/')}/{right}"
    return None


def generator_names(source: Source, legacy_map: bool = True) -> dict[str, list[str]]:
    """Generator module -> the emulator or core names configgen loads it for.

    legacy_map is false for a configgen written before _LEGACY_GENERATOR_MAP
    (KNULLI's), whose importer has the plain map only.
    """
    names: dict[str, list[str]] = {}
    plain = source.literal(source.assignment("_GENERATOR_MAP").value, "_GENERATOR_MAP")
    for emulator, (module, _cls) in plain.items():
        names.setdefault(module, []).append(emulator)
    if not legacy_map:
        return names
    legacy = source.literal(
        source.assignment("_LEGACY_GENERATOR_MAP").value, "_LEGACY_GENERATOR_MAP"
    )
    for cores in legacy.values():
        for core, (module, _cls) in cores.items():
            names.setdefault(module, []).append(core)
    return names


class Configgen:
    """The configgen tree at one revision, read through `read(path)`.

    root is the configgen package in the repository: Batocera's by default,
    KNULLI keeps the same package under its own path.
    """

    def __init__(
        self, read: Callable[[str], str], root: str = CONFIGGEN, legacy_map: bool = True
    ) -> None:
        self._read = read
        self._sources: dict[str, Source] = {}
        self.generators = f"{root}/generators"
        self.importer = f"{self.generators}/importer.py"
        self.libretro_options = f"{self.generators}/libretro/libretroOptions.py"
        self.paths = path_constants(self.source(f"{root}/batoceraPaths.py"))
        self.bios = self.paths["BIOS"]
        self._generators = generator_names(self.source(self.importer), legacy_map)

    def source(self, path: str) -> Source:
        if path not in self._sources:
            self._sources[path] = Source(path, self._read(path))
        return self._sources[path]

    def generator(self, module: str) -> Source:
        return self.source(f"{self.generators}/{module.replace('.', '/')}.py")

    def helper(self, module: str, helper: str) -> Source:
        """A module the generator imports with `from . import helper`."""
        generator = self.generator(module)
        imported = any(
            isinstance(node, ast.ImportFrom)
            and node.level == 1
            and node.module is None
            and any(alias.name == helper for alias in node.names)
            for node in ast.walk(generator.tree)
        )
        if not imported:
            generator.fail(f"does not import {helper}")
        return self.source(f"{self.generators}/{module.split('.')[0]}/{helper}.py")

    def emulator(self, module: str) -> str:
        """The name configgen loads `module` for (importer.get_generator)."""
        if module in self._generators:
            return ", ".join(self._generators[module])
        package, _, leaf = module.partition(".")
        if leaf == f"{package}Generator":
            return package
        raise LauncherShapeError(f"{self.importer}: no emulator loads {module}")

    def bios_name(self, node: ast.AST) -> str | None:
        """The name under /userdata/bios that an expression spells, if any."""
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "str"
            and node.args
        ):
            return self.bios_name(node.args[0])
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.strip('"')
            prefix = self.bios.rstrip("/") + "/"
            return value[len(prefix):] if value.startswith(prefix) else None
        value = _path_value(node, self.paths)
        prefix = self.bios.rstrip("/") + "/"
        if value is not None and value.startswith(prefix):
            return value[len(prefix):]
        return None

    def option_name(self, node: ast.AST) -> tuple[str, str] | None:
        """(default name, option) for f"{BIOS}/{system.config.get(option, default)}"."""
        if not isinstance(node, ast.JoinedStr) or len(node.values) != 3:
            return None
        head, sep, tail = node.values
        if not (
            isinstance(head, ast.FormattedValue)
            and _path_value(head.value, self.paths) == self.bios
            and isinstance(sep, ast.Constant)
            and sep.value == "/"
            and isinstance(tail, ast.FormattedValue)
        ):
            return None
        option = _config_option(tail.value)
        if option is None or not isinstance(option[1], str):
            return None
        return option[1], option[0]


def _raise_message(source: Source, scope: ast.AST, guard: str) -> str:
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
    source.fail(f"no `if not {guard}: raise` with a message")


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
        call for call in _calls(finder, attr="iterdir")
        if isinstance(call.func.value, ast.Name)  # type: ignore[attr-defined]
    ]
    lowered = _calls(finder, attr="lower")
    if len(listed) != 1 or not lowered:
        src.fail("find_bios no longer lists the BIOS directory and compares lowercased names")
    search_dir = cg.paths.get(listed[0].func.value.id)  # type: ignore[attr-defined]
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
        node for node in ast.walk(generate)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Constant)
        and isinstance(node.test.ops[0], ast.In)
        and ast.unparse(node.test.comparators[0]) == found_var
    ]
    if len(branches) != 1:
        src.fail(f"generate no longer branches once on a slot found in {found_var}")
    branch = branches[0]
    writes = _calls(branch, attr="set")
    sections = {call.args[0].value for call in writes if isinstance(call.args[0], ast.Constant)}
    if len(sections) != 1 or not any(
        isinstance(call.args[1], ast.Subscript)
        and ast.unparse(call.args[1].value) == "region_mapping"
        for call in writes
    ):
        src.fail("the region paths are not written to one config section through region_mapping")
    section = sections.pop()
    shared = {
        branch.test.left.value: [
            call.args[1].value for stmt in branch.body for call in _calls(stmt, attr="set")
            if isinstance(call.args[1], ast.Constant)
        ]
    }

    first, last = _run(body, index, lambda stmt: _mentions(stmt, {section}, {found_var}))
    ref = src.ref([
        (src.span(first)[0], last.end_lineno),
        (finder.lineno, finder.end_lineno),
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
        test = node.body[0].test if isinstance(node.body[0], ast.If) else None
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
            _assigned_name(stmt): stmt for stmt in node.body[0].body
            if isinstance(stmt, ast.Assign) and ast.unparse(stmt.value) == node.target.id
        }
        flags = {
            _assigned_name(stmt) for stmt in node.body[0].body
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
        if (
            len(call.args) == 3
            and all(isinstance(a, ast.Constant) for a in call.args[:2])
            and isinstance(call.args[2], ast.Name)
        ):
            writes[call.args[2].id] = (call.args[0].value, call.args[1].value)

    list_nodes = {name: src.assignment(name, generate) for name, _v, _f, _d in loops}
    tracked = {*list_nodes, *(v for _l, v, _f, _d in loops), flag}
    first_list = min(list_nodes.values(), key=lambda node: node.lineno)
    body, index = _locate(generate, lambda stmt: stmt is first_list)  # type: ignore[misc]
    sections = {section for section, _key in writes.values()}
    first, last = _run(body, index, lambda stmt: _mentions(stmt, sections, tracked))
    ref = src.ref([(src.span(first)[0], last.end_lineno)])

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
                marker, prefix = node.test.left.value, parts[0].value
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
                names_built.append(parts[2].value)
    if len(names_built) == 1:
        suffix = names_built[0]
    if marker is None or prefix is None or suffix is None:
        src.fail("findBestTos no longer builds <tos{version} or etos*><language>.img")
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
    call = body[index].value  # type: ignore[attr-defined]
    if not call.args or not isinstance(call.args[0], ast.Name) or call.args[0].id not in cg.paths:
        src.fail("findBestTos is not given a batoceraPaths directory")
    search_dir = cg.paths[call.args[0].id]
    kept = _trace(body, index)
    options = list(dict.fromkeys(name for stmt in kept for name in _option_names(stmt)))
    spans = [src.span(stmt) for stmt in kept] + [(finder.lineno, finder.end_lineno)]
    args: list[str] = []
    second = call.args[1] if len(call.args) > 1 else None
    machine_var = second.id if isinstance(second, ast.Name) else None
    tos_var = _assigned_name(body[index])
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
                    and _path_value(element.left, cg.paths) == search_dir
                ):
                    # KNULLI returns the bare name and joins it: BIOS / tos.
                    args.append("<file>")
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
        if len(call.args) != 3 or not all(isinstance(a, ast.Constant) for a in call.args[:2]):
            continue
        name = cg.bios_name(call.args[2])
        if name is not None:
            writes.append((call, call.args[0].value, call.args[1].value, name))
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
    option = _option_names(console[0].value)[0]  # type: ignore[attr-defined]
    launchers = []
    for key, value in zip(base.value.keys, base.value.values):
        if not isinstance(value, ast.Dict) or not isinstance(key, ast.Constant):
            continue
        entries = [
            (k.value, cg.bios_name(v)) for k, v in zip(value.keys, value.values)
            if isinstance(k, ast.Constant)
        ]
        entries = [(k, name) for k, name in entries if name is not None]
        if not entries:
            continue
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="fixed_name",
            names=[name for _k, name in entries], case_insensitive=False,
            search_dir=cg.bios,
            passes_to=", ".join(f"{key.value}.{k}" for k, _n in entries),
            depends_on_option=option,
            source_ref=src.ref([
                (key.lineno, value.end_lineno),
                (enabled[0][0].lineno, enabled[0][1].end_lineno),
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
                is_flag = isinstance(flag, ast.Constant) and str(flag.value).startswith("-")
                if is_flag and name is not None:
                    found.append((flag, value, name))
    if not found:
        src.fail("the command line passes no /userdata/bios path")
    return [Launcher(
        emulator=cg.emulator(module), build="standalone", kind="fixed_name",
        names=[name for _f, _v, name in found], case_insensitive=False,
        search_dir=cg.bios,
        passes_to=", ".join(f"command line {f.value}" for f, _v, _n in found),
        source_ref=src.ref([(f.lineno, v.end_lineno) for f, v, _n in found]),
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
                found.append((call, call.args[0].value, *named))
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
        node for node in ast.walk(scope)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.UnaryOp)
        and isinstance(node.test.op, ast.Not)
        and test(node.test.operand)
        and isinstance(node.body[0], ast.Raise)
        and isinstance(node.body[0].exc, ast.Call)
        and node.body[0].exc.args
        and isinstance(node.body[0].exc.args[0], ast.JoinedStr)
    ]
    if len(found) != 1:
        src.fail(f"expected one `if not {what}: raise` with a message, found {len(found)}")
    return found[0], found[0].body[0].exc.args[0]  # type: ignore[attr-defined, no-any-return]


def _render(message: ast.JoinedStr, var: str, value: str) -> str:
    parts = []
    for part in message.values:
        if isinstance(part, ast.Constant):
            parts.append(str(part.value))
        elif isinstance(part.value, ast.Name) and part.value.id == var:  # type: ignore[attr-defined]
            parts.append(value)
        else:
            parts.append(f"{{{ast.unparse(part.value)}}}")  # type: ignore[attr-defined]
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
        node for node in ast.walk(generate)
        if _assigned_name(node) == "commandArray"
        and isinstance(node.value, ast.List)  # type: ignore[attr-defined]
        and node.value.elts  # type: ignore[attr-defined]
        and isinstance(node.value.elts[0], ast.Name)  # type: ignore[attr-defined]
    ]
    if len(command) != 1:
        src.fail("generate no longer starts commandArray with the binary it runs")
    binary = command[0].value.elts[0].id  # type: ignore[attr-defined]

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
            name: (stmt, _path_value(stmt.value, constants))  # type: ignore[attr-defined]
            for stmt in branch.body if (name := _assigned_name(stmt)) is not None
        }
        if binary not in bound or not (bound[binary][1] or "").startswith(prefix):
            src.fail(f"the {system} branch binds {binary} to no path under {cg.bios}")
        library = [
            name for name in bound
            if name != binary and _mentions(env_value, set(), {name})
        ]
        if len(library) != 1 or not (bound[library[0]][1] or "").startswith(prefix):
            src.fail(f"the {system} branch puts no /userdata/bios folder on LD_LIBRARY_PATH")
        binary_stmt, path = bound[binary]
        library_stmt, folder = bound[library[0]]
        test_line = src.span(branch.test)
        constant = next(
            (defined[n.id] for n in ast.walk(binary_stmt.value)  # type: ignore[attr-defined]
             if isinstance(n, ast.Name) and n.id in defined),
            None,
        )
        spans = [test_line, src.span(binary_stmt), src.span(exists), src.span(access),
                 src.span(command[0])]
        if constant is not None:
            spans.append(src.span(constant))
        launchers.append(Launcher(
            emulator=cg.emulator(module), build="standalone", kind="fixed_name",
            slot=system, names=[path[len(prefix):]],  # type: ignore[index]
            case_insensitive=False, search_dir=cg.bios, passes_to="exec",
            fails_when_missing=", ".join(
                _render(message, binary, path) for message in (missing, not_executable)  # type: ignore[arg-type]
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
    launchers = []
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
            (key.value, value, key)
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
                source_ref=src.ref([(node.lineno, node.end_lineno)]),
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
            cores.setdefault(value.id, []).append(key.value)
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
        option = named.value if isinstance(named, ast.Constant) else setting
        default = next((k.value for k in call.keywords if k.arg == "default"), None)
        if isinstance(default, ast.Constant):
            names = [default.value]
            condition = None
        elif (
            isinstance(default, ast.IfExp)
            and isinstance(default.body, ast.Constant)
            and isinstance(default.orelse, ast.Constant)
        ):
            names = [default.body.value, default.orelse.value]
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


EXTRACTORS: tuple[Callable[[Configgen], list[Launcher]], ...] = (
    duckstation, duckstation_legacy, hatari, xemu, melonds, mupen64plus,
    x16emu, gsplus, lexaloffle, environment_directories, config_directories,
    core_file_options, working_directories,
)


def extract_launchers(read: Callable[[str], str]) -> list[dict[str, Any]]:
    """Every launcher record, read through `read(repo-relative path)`."""
    cg = Configgen(read)
    launchers = [launcher for extractor in EXTRACTORS for launcher in extractor(cg)]
    launchers += patched_paths(read)
    return [launcher.entry() for launcher in launchers]
