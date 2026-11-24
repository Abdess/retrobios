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
from collections.abc import Callable
from typing import Any

from model.launcherrecords import emulator_names, join_emulators
from .configgen_launchers import (
    Launcher,
    LauncherShapeError,
    _assigned_name,
    _calls,
    _innermost_function,
    _locate,
    end_line,
)
from .recalbox_cascades import gsplus, hatari, hatari_libretro
from .recalbox_configgen import (
    ALL_CORES,
    AMIBERRY_CONFIG,
    AMIBERRY_GLOBAL,
    AMIBERRY_KICKSTARTS,
    AMIBERRY_SUBSYSTEMS,
    CORES,
    CORE_ASSETS,
    Configgen,
    DOLPHIN,
    FILES_MODULE,
    FILE_OPTIONS,
    GSPLUS,
    HATARI,
    LAUNCHER,
    LIBRETRO_GENERATOR,
    MUPEN_CONFIG,
    PCSX2,
    RETROARCH,
    SYSTEM_DIRECTORY,
    XEMU,
    XROAR,
    _expr_call,
    _handler_map,
    _local_lists,
    _setter,
    _setter_branches,
    _string,
    _text,
    spell,
)
from .recalbox_emulators import amiberry, dolphin, mupen64plus, pcsx2, xemu, xroar


SOURCE_FILES = (
    FILES_MODULE, LAUNCHER, RETROARCH, CORES, LIBRETRO_GENERATOR, HATARI, GSPLUS,
    AMIBERRY_KICKSTARTS, AMIBERRY_SUBSYSTEMS, AMIBERRY_CONFIG, AMIBERRY_GLOBAL, PCSX2, DOLPHIN, XEMU,
    MUPEN_CONFIG, XROAR,
)


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
        cores = [core for p in options
                 if isinstance(p, ast.MatchValue)
                 and (core := _text(src, p.value, "core name")) is not None]
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
                join_emulators(cores) or ALL_CORES, condition, call,
                [(pattern.lineno, pattern.lineno), (start, end_line(call))],
            ))

    located = _locate(scope, lambda stmt: stmt is match)
    if located is None:
        src.fail(f"no statement list holds the match on the core writing {SYSTEM_DIRECTORY}")
    body, index = located
    overrides = _setter_branches(src, body[index + 1:], SYSTEM_DIRECTORY, lists)
    if not overrides:
        src.fail(f"no per-system {SYSTEM_DIRECTORY} after the match on the core")
    tests = {node.lineno: node.test for node in ast.walk(scope) if isinstance(node, ast.If)}
    for condition, call, start in overrides:
        if condition is None:
            src.fail(f"line {call.lineno}: {SYSTEM_DIRECTORY} rewritten for every system")
        read = {n.id for n in ast.walk(tests[start]) if isinstance(n, ast.Name)} \
            if start in tests else set()
        spans = [(start, end_line(call))]
        spans += [src.span(node) for name, (_v, node) in local_lists.items() if name in read]
        launchers.append(record(
            ALL_CORES, f"{condition}, replacing the directory chosen by core", call, spans,
        ))
    return launchers


def core_directory(directories: list[Launcher], core: str) -> Launcher:
    """The unconditional system_directory record that applies to `core`."""
    for launcher in directories:
        if core in emulator_names(launcher.emulator) and launcher.depends_on_option is None:
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
        ):
            continue
        core = _text(src, node.test.comparators[0], "core name")
        if core is None:
            continue
        calls = [c for stmt in node.body if (c := _expr_call(stmt)) and _setter(c, CORE_ASSETS)]
        if len(calls) != 1:
            continue
        call = calls[0]
        launchers.append(Launcher(
            emulator=core, build="libretro", kind="passes_path",
            names=[], search_dir=cg.bios_dir(spell(call.args[1], env), src, CORE_ASSETS),
            passes_to=f"retroarch {CORE_ASSETS}",
            source_ref=src.ref([(node.lineno, end_line(call))]),
        ))
    if not launchers:
        src.fail(f"no core is given a {CORE_ASSETS}")
    return launchers


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
        ):
            continue
        core = _text(src, node.test.comparators[0], "core name")
        if core is None:
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
            emulator=core, build="libretro", kind="fixed_name",
            names=names, case_insensitive=False, search_dir=cg.bios,
            passes_to=f"written into {target}, which is loaded as the content",
            fails_when_missing=False,
            source_ref=f"{src.ref([(node.lineno, end_line(node))])}, "
                       f"{files.ref([(line, line) for line in lines])}",
        ))
    if not launchers:
        src.fail("no core is given a BIOS path through a content file")
    return launchers


def core_file_options(cg: Configgen, directories: list[Launcher]) -> list[Launcher]:
    """System handlers that set a core option naming the file the core opens."""
    src = cg.source(CORES)
    handlers = _handler_map(src, "fillCoresConfiguration", "specificSystemHandlers")
    table = src.assignment(
        "specificSystemHandlers", src.function("fillCoresConfiguration")
    ).value
    if not isinstance(table, ast.Dict):
        src.fail("specificSystemHandlers is not a dict display")
    defined = {n.name: n for n in ast.walk(src.tree) if isinstance(n, ast.FunctionDef)}
    launchers = []
    for function_name, systems in handlers.items():
        function = defined.get(function_name)
        if function is None:
            continue
        for call in _calls(function, attr="setString"):
            if not (len(call.args) == 2 and all(isinstance(a, ast.Constant) for a in call.args)
                    and _string(call.args[0]) in FILE_OPTIONS):
                continue
            option = _text(src, call.args[0], "core option")
            value = _text(src, call.args[1], "core option value")
            if option is None or value is None:
                continue
            core = FILE_OPTIONS[option]
            directory = core_directory(directories, core)
            spans = [(k.lineno, k.lineno) for k, v in zip(table.keys, table.values)
                     if k is not None and isinstance(v, ast.Attribute) and v.attr == function_name]
            launchers.append(Launcher(
                emulator=core, build="libretro", kind="core_option",
                names=[value.strip('"')], search_dir=directory.search_dir,
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
