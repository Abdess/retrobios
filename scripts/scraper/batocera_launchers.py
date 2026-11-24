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
from dataclasses import dataclass
from typing import Any

from model.launcherrecords import emulator_names, join_emulators
from .configgen_launchers import (
    Launcher,
    LauncherShapeError,
    end_line,
    _assigned_name,
    _calls,
    _innermost_function,
    _outermost,
)
from .batocera_configgen import Configgen, GENERATORS, _path_value
from .configgen_sites import GenericSites, bios_sites
from .batocera_config_writes import gsplus, lexaloffle, melonds, mupen64plus, x16emu, xemu
from .batocera_searches import duckstation, duckstation_legacy, hatari

LIBRETRO_OPTIONS = f"{GENERATORS}/libretro/libretroOptions.py"


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
            emulator=join_emulators(cores[function_name]), build="libretro", kind="core_option",
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


@dataclass(frozen=True)
class Extraction:
    """A configgen's launcher records, and the emulators it runs from the BIOS folder."""

    records: list[dict[str, Any]]
    # The emulators whose program the launcher runs from the BIOS folder
    # (lexaloffle, /userdata/bios/pico-8/pico8): the user supplies it, no
    # package builds it.
    bios_programs: frozenset[str]


def extraction(launchers: list[Launcher], bios: str) -> Extraction:
    """The records of `launchers`, and those that run a program from `bios`."""
    root = bios.rstrip("/")
    return Extraction(
        records=[launcher.entry() for launcher in launchers],
        bios_programs=frozenset(
            name
            for launcher in launchers
            if launcher.passes_to == "exec"
            and launcher.search_dir is not None
            and (launcher.search_dir.rstrip("/") == root
                 or launcher.search_dir.startswith(f"{root}/"))
            for name in emulator_names(launcher.emulator)
        ),
    )


def extract_launchers(read: Callable[[str], str]) -> Extraction:
    """Every launcher record, read through `read(repo-relative path)`."""
    cg = Configgen(read)
    launchers = [launcher for extractor in EXTRACTORS for launcher in extractor(cg)]
    launchers += patched_paths(read)
    return extraction(launchers, cg.bios)
