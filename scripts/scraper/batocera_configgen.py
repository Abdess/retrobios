"""Batocera's configgen tree as the launcher readers open it: the generator
modules, the importer that names them, and the paths of batoceraPaths.
KNULLI keeps the same package under its own path."""

from __future__ import annotations

import ast
import posixpath
from collections.abc import Callable
from typing import Any

from model.launcherrecords import join_emulators
from .configgen_launchers import LauncherShapeError, Source, _assigned_name, assigned_value


CONFIGGEN = "package/batocera/core/batocera-configgen/configgen/configgen"
GENERATORS = f"{CONFIGGEN}/generators"
PATHS_MODULE = f"{CONFIGGEN}/batoceraPaths.py"
IMPORTER = f"{GENERATORS}/importer.py"


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
    return str(node.args[0].value), default


def path_constants(source: Source) -> dict[str, str]:
    """batoceraPaths' module constants that are plain paths."""
    constants: dict[str, str] = {}
    for node in source.tree.body:
        assigned = assigned_value(node)
        if assigned is None:
            continue
        name, expr = assigned
        value = _path_value(expr, constants)
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
            return join_emulators(self._generators[module])
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
        path = _path_value(node, self.paths)
        prefix = self.bios.rstrip("/") + "/"
        if path is not None and path.startswith(prefix):
            return path[len(prefix):]
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
