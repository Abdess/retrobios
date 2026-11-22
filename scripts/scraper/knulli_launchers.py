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
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import yaml

from model.launcherrecords import emulator_names, join_emulators
from .batocera_launchers import (
    PATH_PATCHES,
    config_directories,
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
from .batocera_configgen import Configgen, _path_value
from .configgen_launchers import (
    Launcher,
    LauncherShapeError,
    Source,
    _assigned_name,
)
from scraper.shell_launchers import LauncherPatternMissing, Script, source_ref
from .configgen_sites import (
    COMMAND_NAMES,
    GenericSites,
    _Reader,
    _bound,
    _caller_cores,
    _cores_of,
    bios_sites,
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
    tested = missing.test
    if not (isinstance(tested, ast.UnaryOp) and isinstance(tested.operand, ast.Call)):
        src.fail("not <binary>.exists() tests no call")
    binary = ast.unparse(tested.operand.func).removesuffix(".exists")
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
            (stmt, held) for stmt in branch.body
            if _assigned_name(stmt) == binary and isinstance((held := _bound(stmt)), ast.Name)
        ]
        if len(bound) != 1:
            src.fail(f"the {system} branch does not set {binary} once")
        bound_stmt, bound_value = bound[0]
        constant = ast.unparse(bound_value)
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
                src.span(defined[constant]), src.span(branch.test), src.span(bound_stmt),
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
            emulator=join_emulators(_cores_of(holder.test)), build="libretro", kind="core_option",
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
            section, key, value = (str(a.value) for a in call.args if isinstance(a, ast.Constant))
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
            join_emulators(_caller_cores(cg, spec.caller)) if spec.caller else cg.emulator(module)
        )
        if spec.caller and spec.feature[:2] == ("libretro", "cores"):
            # The option is offered for one core of the system: es_features
            # lists it under that core, the other cores the generator serves
            # never see it (KNULLI's macintosh offers mame alone).
            core = spec.feature[2]
            if core not in emulator_names(emulator):
                src.fail(f"es_features offers the option for {core}, which the generator does not serve")
            emulator = core
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
                    # The values the menu offers come from es_features.yml;
                    # the generator writing the choice is the evidence.
                    choices_from=None if listed else f"{ES_FEATURES}:{lines[0]}-{lines[1]}",
                    source_ref=src.ref([*spans, src.span(statement), _lines(added)]),
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
