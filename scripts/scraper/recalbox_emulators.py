"""Recalbox standalone generators that search for or write a BIOS path, Amiberry to XRoar."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from functools import partial

from .configgen_launchers import (
    Launcher,
    LauncherShapeError,
    Source,
    _assigned_name,
    _calls,
    _enclosing_test,
    end_line,
)
from .recalbox_configgen import (
    AMIBERRY_CONFIG,
    AMIBERRY_GENERATOR,
    AMIBERRY_GLOBAL,
    AMIBERRY_KICKSTARTS,
    AMIBERRY_SUBSYSTEMS,
    CORES,
    Configgen,
    DOLPHIN,
    MUPEN_CONFIG,
    MUPEN_GENERATOR,
    PCSX2,
    SYSTEM_PLACEHOLDER,
    XEMU,
    XROAR,
    assignments,
    class_strings,
    expr_call,
    is_setter_call,
    string,
    accepted_systems,
    string_constant,
    spell,
)


def amiberry(cg: Configgen) -> list[Launcher]:
    """BIOS_PER_SYSTEM tried in order, the AROS pair, then Amiberry's own."""
    kick = cg.source(AMIBERRY_KICKSTARTS)
    subsystems = class_strings(cg.source(AMIBERRY_SUBSYSTEMS), {})
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
        message for node in ast.walk(chooser)
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
        and node.exc.args
        and (message := string_constant(kick, node.exc.args[0], "failure message")) is not None
    ]
    aros = [
        aros_name for call in _calls(chooser, name="AmigaBios")
        if call.args and (aros_name := string_constant(kick, call.args[0], "AROS name")) is not None
    ]
    builtin = [
        rom for node in ast.walk(chooser)
        if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]) == "self.rom"
        and (rom := string_constant(kick, node.value, "built-in rom")) is not None
    ]
    if len(messages) != 2 or len(aros) != 2 or len(builtin) != 1:
        kick.fail("GetKickstartsFor no longer has two failures, the AROS pair and a built-in")
    config = cg.source(AMIBERRY_CONFIG)
    setter = config.function("SetKickstarts")
    keys = [setting for c in _calls(setter, attr="setString")
            if (setting := string_constant(config, c.args[0], "kickstart key")) is not None]
    if len(keys) != 2:
        config.fail("SetKickstarts no longer writes a kickstart and an extended ROM")
    rom_key, ext_key = keys
    tail = [(helper.lineno, end_line(helper)), (chooser.lineno, end_line(chooser))]
    config_ref = config.ref([(setter.lineno, end_line(setter))])

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
    found = [c for c in _calls(create, attr="setString") if is_setter_call(c, "rom_path")]
    if len(found) != 1 or len(found[0].args) != 2:
        src.fail(f"expected one rom_path setter, found {len(found)}")
    call = found[0]
    directory = cg.bios_dir(spell(call.args[1], cg.env(src, create)), src, "rom_path")
    return Launcher(
        emulator=emulator, build="standalone", kind="passes_path", names=[],
        search_dir=directory, passes_to="written: rom_path in amiberry.conf",
        source_ref=src.ref([(call.lineno, end_line(call))]),
    )


def _ps2_exists_helper(
    cg: Configgen, src: Source, env: Mapping[str, str], chooser: ast.FunctionDef
) -> tuple[str, str]:
    """The directory the nested existence helper joins a name to, and its name."""
    exists = next((f for f in chooser.body if isinstance(f, ast.FunctionDef)), None)
    returned = exists.body[-1] if exists is not None else None
    joined = returned.value.args[0] if isinstance(returned, ast.Return) \
        and isinstance(returned.value, ast.Call) and returned.value.args else None
    if exists is None or not (
        isinstance(joined, ast.Call) and ast.unparse(joined.func) == "os.path.join"
        and ast.unparse(joined.args[-1]) == exists.args.args[0].arg
    ):
        src.fail("__CheckPs2Bios has no existence helper joining a directory and a name")
    search_dir = cg.bios_dir(
        spell(ast.Call(func=joined.func, args=joined.args[:-1], keywords=[]), env), src, "Exists"
    )
    return search_dir, exists.name


def _region_branch(node: ast.If, helper: str) -> tuple[str, ast.expr, ast.expr | None] | None:
    """(token, name tested, name returned) for `if token in rom and Exists(name): return x`."""
    test = node.test
    if not (
        isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) and len(test.values) == 2
    ):
        return None
    compare, call = test.values
    token = string(compare.left) if isinstance(compare, ast.Compare) else None
    if not (
        token is not None
        and isinstance(call, ast.Call)
        and ast.unparse(call.func) == helper
        and len(node.body) == 1 and isinstance(node.body[0], ast.Return)
    ):
        return None
    return token, call.args[0], node.body[0].value


def _ps2_region_groups(
    src: Source, env: Mapping[str, str], chooser: ast.FunctionDef, helper: str
) -> dict[tuple[str, str], list[str]]:
    """(name returned, name tested) -> the rom name tokens that pick it."""
    groups: dict[tuple[str, str], list[str]] = {}
    node = next((s for s in chooser.body if isinstance(s, ast.If)), None)
    while node is not None:
        branch = _region_branch(node, helper)
        if branch is None:
            src.fail(f"line {node.lineno}: region branch is not `token in rom and Exists(name)`")
        token, tested_node, given_node = branch
        tested = spell(tested_node, env)
        given = spell(given_node, env)
        if tested is None or given is None:
            src.fail(f"line {node.lineno}: region branch names no BIOS constant")
        groups.setdefault((given, tested), []).append(token)
        orelse = node.orelse
        node = orelse[0] if len(orelse) == 1 and isinstance(orelse[0], ast.If) else None
    return groups


def pcsx2(cg: Configgen) -> list[Launcher]:
    """A region token of the rom name picks a BIOS, then a fixed order."""
    src = cg.source(PCSX2)
    env = cg.env(src)
    chooser = src.function("__CheckPs2Bios")
    search_dir, helper = _ps2_exists_helper(cg, src, env, chooser)

    groups = _ps2_region_groups(src, env, chooser, helper)
    loops = [
        (s, s.iter) for s in chooser.body
        if isinstance(s, ast.For) and isinstance(s.iter, ast.Tuple)
    ]
    if not groups or len(loops) != 1:
        src.fail("__CheckPs2Bios no longer tries region tokens then a fixed order")
    loop, names = loops[0]
    fallback = [name for e in names.elts if (name := spell(e, env)) is not None]
    if len(fallback) != len(names.elts):
        src.fail(f"line {loop.lineno}: fallback names are not BIOS constants")

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
    names_lines = [node.lineno for node, name, _value in assignments(ast.walk(src.tree))
                   if name in set(constants.values())]
    ref = src.ref([(min(names_lines), max(names_lines)), (chooser.lineno, end_line(chooser)),
                   (writes[0].lineno, end_line(writes[0]))])
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
        found = [
            cg.under_bios(spell(value.args[0], env)) for value in node.test.values
            if isinstance(value, ast.Call) and ast.unparse(value.func) == "os.path.exists"
        ]
        names = [name for name in found if name is not None]
        if names and len(names) == len(node.test.values) and len(names) == len(found):
            return names, node
    raise LauncherShapeError(f"{src.path}: {scope.name}: no presence test of BIOS paths")


def _returned(stmts: list[ast.stmt]) -> str | None:
    if len(stmts) == 1 and isinstance(stmts[0], ast.Return):
        return string(stmts[0].value)
    return None


def dolphin(cg: Configgen) -> list[Launcher]:
    """The IPL is only tested for presence, to decide whether to skip it."""
    src = cg.source(DOLPHIN)
    env = cg.env(src)
    checker = src.function("CheckGamecubeIpl")
    names, test = _presence(cg, src, checker)
    found, missing = _returned(test.body), _returned(test.orelse)
    calls = [
        (call, bound.id) for call in _calls(src.tree, attr="setString")
        if len(call.args) == 3 and isinstance(bound := call.args[2], ast.Name)
        and any(
            name == bound.id and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute) and value.func.attr == checker.name
            for _node, name, value in assignments(ast.walk(src.tree))
        )
    ]
    if found is None or missing is None or len(calls) != 1:
        src.fail("CheckGamecubeIpl's answer is not written to one config key")
    call, answer = calls[0]
    section, key = spell(call.args[0], env), spell(call.args[1], env)
    binding = next(node for node, name, _value in assignments(ast.walk(src.tree))
                   if name == answer)
    standalone = Launcher(
        emulator=cg.emulator(DOLPHIN), build="standalone", kind="fixed_name", names=names,
        case_insensitive=False, search_dir=cg.bios,
        passes_to=f"[{section}] {key} ({found} when one is present, else {missing})",
        fails_when_missing=False,
        source_ref=src.ref([(checker.lineno, end_line(checker)), src.span(binding),
                            (call.lineno, end_line(call))]),
    )
    cores = cg.source(CORES)
    configure = cores.function("configureDolphin")
    names, test = _presence(cg, cores, configure)
    options = [(option, value) for branch in (test.body, test.orelse)
               for stmt in branch if (c := expr_call(stmt)) and len(c.args) == 2
               and (option := string_constant(cores, c.args[0], "core option")) is not None
               and (value := string_constant(cores, c.args[1], "core option value")) is not None]
    if len(options) != 2 or options[0][0] != options[1][0]:
        cores.fail("configureDolphin's presence test does not set one core option both ways")
    option = options[0][0]
    on, off = (value.strip('"') for _o, value in options)
    first = min(node.lineno for node, _name, value in assignments(ast.walk(configure))
                if cg.under_bios(spell(value, cg.env(cores, configure))) is not None)
    libretro = Launcher(
        emulator=cg.core("configureDolphin"), build="libretro", kind="fixed_name", names=names,
        case_insensitive=False, search_dir=cg.bios,
        passes_to=f"core option {option} ({on} when one is present, else {off})",
        fails_when_missing=False, source_ref=cores.ref([(first, end_line(test))]),
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
    spans: list[tuple[int, int]] = []
    for function, call, *_rest in writes:
        spans.append((call.lineno, end_line(call)))
        test = next(
            (n for n in ast.walk(function) if isinstance(n, ast.If)
             and any(child is call for stmt in n.body for child in ast.walk(stmt))), None,
        )
        if test is not None:
            spans.append((test.lineno, test.lineno))
            systems = accepted_systems(src, test.test, {})
            words = f"system {', '.join(systems)}" if systems else _enclosing_test(function, call)
            if words is not None and words not in conditions:
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
