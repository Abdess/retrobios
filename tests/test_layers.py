"""The import layers of scripts/: core, model, resolve, domain packages, commands.

A module imports only from its own layer or below. core is the standard
library's only client, model loads data, resolve turns declarations into
files, the domain packages build on them, and the top-level scripts are the
commands. No module imports a command: library code lives in a package, and
the only top-level files other modules may import are the SELF_CONTAINED ones.
"""

from __future__ import annotations

import tests
import ast
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"

PACKAGE_LAYERS = {"core": 0, "model": 1, "resolve": 2, "packs": 3, "scraper": 3, "exporter": 3,
                  "probes": 3, "profiling": 3, "sitegen": 3, "romrecipes": 3, "acquire": 3,
                  "release": 3, "installer_build": 3, "devtools": 3, "unattended": 3,
                  "freshness": 3, "orchestrate": 3, "schemas": 3, "collection": 3, "games": 3}
LIBRARY_LAYER = 3
COMMAND_LAYER = 4

# The other domain packages a domain package may import. A package listed
# here imports no sibling outside its set.
SIBLING_IMPORTS: dict[str, frozenset[str]] = {
    # A search starts from what verify finds missing.
    "acquire": frozenset({"packs"}),
    "collection": frozenset(),
    "packs": frozenset(),
    # A campaign commits its findings the way the unattended jobs commit, and a
    # standalone probe lists an emulator's releases through the one GitHub reader.
    "probes": frozenset({"unattended", "scraper"}),
    # A pass that wrote profiles rebuilds the site's record of cited source paths,
    # and the MAME ref audit reads machine declarations as the MAME scraper parses them.
    "profiling": frozenset({"sitegen", "scraper"}),
    "romrecipes": frozenset(),
    # The site prints the recipe counts and the dump-catalog coverage report
    # those two packages compute, serves the handheld launchers and prints the
    # CI checks. The logo copier downloads through the scrapers' fetch_bytes.
    "sitegen": frozenset({"acquire", "packs", "romrecipes", "installer_build", "devtools", "scraper"}),
    # The record names its packs as the pack builder does.
    "release": frozenset({"packs"}),
    # The launcher archives are written by the pack member writer.
    "installer_build": frozenset({"packs"}),
    # The bios/ migration reads the legacy branches through acquire's fetch.
    "devtools": frozenset({"acquire"}),
    # A job's commit subjects are checked against the repository's commit rules.
    "unattended": frozenset({"devtools"}),
    # The installer event schema is checked against the one the build writes.
    "schemas": frozenset({"installer_build"}),
    # Each layer is asked through the code that writes it: the scrapers, the
    # native export, the data directory refresh, the installer pins, the
    # site's source trees and profile_sync's report.
    "freshness": frozenset({"scraper", "exporter", "packs", "installer_build", "sitegen", "profiling"}),
    # Step 5 builds the packs in memory, and the offline export refusal asks
    # the exporters which ones patch a cached original.
    "orchestrate": frozenset({"packs", "exporter"}),
    "games": frozenset(),
}

# Top-level files that stay whole at their path although packages import them:
# the file is the unit. core_probe.py runs alone in its sandbox, where nothing
# beside the standard library exists, and its records name and hash this file.
SELF_CONTAINED = frozenset({"core_probe"})

# Commands copied and run alone, outside a checkout: the file is all the user
# has, so its checks stay in it. check_platform_folder.py reads the site's
# public API from a card or a folder anywhere.
STANDALONE_COMMANDS = frozenset({"check_platform_folder"})

# What a command defines: its entry point and the parser that reads its
# options. Everything else, option checks and run modes included, lives in a
# package, where the tests reach it.
COMMAND_DEFINITIONS = frozenset({"main", "build_parser"})

# "download.sh" names a file beside a command, not an attribute of it.
FILE_SUFFIXES = frozenset({"py", "sh", "ps1", "json", "txt", "yml", "md"})


def module_name(path: Path) -> str:
    parts = list(path.relative_to(SCRIPTS).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def scripts_modules() -> dict[str, Path]:
    modules = {}
    for path in SCRIPTS.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        name = module_name(path)
        if name:
            modules[name] = path
    return modules


def imported_names(path: Path, name: str, modules: dict[str, Path]) -> tuple[set[str], set[str]]:
    """(modules of scripts/ this file imports, top-level names of everything else)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    package = name if path.name == "__init__.py" else name.rpartition(".")[0]
    internal: set[str] = set()
    external: set[str] = set()

    def add(target: str) -> None:
        target = target.removeprefix("scripts.")
        if target == "scripts":
            return
        if target in modules:
            internal.add(target)
        else:
            external.add(target.split(".")[0])

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.removeprefix("scripts.").split(".")
                found = next((".".join(parts[:i]) for i in range(len(parts), 0, -1)
                              if ".".join(parts[:i]) in modules), None)
                if found:
                    internal.add(found)
                else:
                    add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".") if package else []
                base = base[: len(base) - (node.level - 1)]
                source = ".".join(base + ([node.module] if node.module else []))
            else:
                source = (node.module or "").removeprefix("scripts.")
                if node.module == "scripts":
                    source = ""
            if source == "__future__":
                continue
            subs = [f"{source}.{a.name}" if source else a.name for a in node.names]
            held = [s for s in subs if s in modules]
            internal.update(held)
            if source and (len(held) < len(subs) or source not in {s.rpartition(".")[0] for s in held}):
                add(source)
    internal.discard(name)
    return internal, external


def layer_of(name: str) -> int:
    top = name.split(".")[0]
    if "." in name or top in PACKAGE_LAYERS:
        return PACKAGE_LAYERS[top]
    return LIBRARY_LAYER if name in SELF_CONTAINED else COMMAND_LAYER


def is_package_module(name: str) -> bool:
    return name.split(".")[0] in PACKAGE_LAYERS


class Graph:
    def __init__(self) -> None:
        self.modules = scripts_modules()
        self.internal: dict[str, set[str]] = {}
        self.external: dict[str, set[str]] = {}
        for name, path in self.modules.items():
            self.internal[name], self.external[name] = imported_names(path, name, self.modules)

    def edges(self):
        for src, targets in sorted(self.internal.items()):
            for dst in sorted(targets):
                yield src, dst


def find_cycle(nodes: set[str], edges: dict[str, set[str]]) -> list[str] | None:
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        state[node] = 1
        stack.append(node)
        for nxt in sorted(edges.get(node, ())):
            if nxt not in nodes:
                continue
            if state.get(nxt) == 1:
                return stack[stack.index(nxt):] + [nxt]
            if nxt not in state:
                found = visit(nxt)
                if found:
                    return found
        stack.pop()
        state[node] = 2
        return None

    for node in sorted(nodes):
        if node not in state:
            found = visit(node)
            if found:
                return found
    return None


class ImportLayers(unittest.TestCase):
    graph: Graph

    @classmethod
    def setUpClass(cls) -> None:
        cls.graph = Graph()

    def test_no_import_reaches_a_higher_layer(self):
        upward = [f"{src} (layer {layer_of(src)}) imports {dst} (layer {layer_of(dst)})"
                  for src, dst in self.graph.edges() if layer_of(src) < layer_of(dst)]
        self.assertEqual(upward, [])

    def test_packages_form_no_cycle(self):
        edges: dict[str, set[str]] = {}
        for src, dst in self.graph.edges():
            a, b = src.split(".")[0], dst.split(".")[0]
            if a != b and is_package_module(src) and is_package_module(dst):
                edges.setdefault(a, set()).add(b)
        self.assertIsNone(find_cycle(set(PACKAGE_LAYERS), edges))

    def test_domain_packages_import_declared_siblings_only(self):
        found = sorted(
            f"{src} imports {dst}" for src, dst in self.graph.edges()
            if (a := src.split(".")[0]) in SIBLING_IMPORTS and (b := dst.split(".")[0]) != a
            and PACKAGE_LAYERS.get(b) == LIBRARY_LAYER and b not in SIBLING_IMPORTS[a]
        )
        self.assertEqual(found, [])

    def test_foundation_modules_form_no_cycle(self):
        """Inside core, model and resolve, no two modules import each other,
        not even through a function-level import."""
        nodes = {n for n in self.graph.modules if n.split(".")[0] in ("core", "model", "resolve")}
        self.assertIsNone(find_cycle(nodes, self.graph.internal))

    def test_package_modules_import_no_top_level_module(self):
        found = sorted(f"{src} imports {dst}" for src, dst in self.graph.edges()
                       if is_package_module(src) and not is_package_module(dst) and dst not in SELF_CONTAINED)
        self.assertEqual(found, [])

    def test_core_imports_the_standard_library_only(self):
        stdlib = set(sys.stdlib_module_names)
        found = []
        for name, external in sorted(self.graph.external.items()):
            if name.split(".")[0] != "core":
                continue
            found += [f"{name} imports {e}" for e in sorted(external - stdlib)]
            found += [f"{name} imports {i}" for i in sorted(self.graph.internal[name])
                      if i.split(".")[0] != "core"]
        self.assertEqual(found, [])

    def test_self_contained_files_load_the_standard_library_only(self):
        """What a self-contained file imports when it loads is the standard
        library: in its sandbox, the file is all of the repository there is."""
        stdlib = set(sys.stdlib_module_names) | {"__future__"}
        found = []
        for name in sorted(SELF_CONTAINED):
            tree = ast.parse(self.graph.modules[name].read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.Import):
                    found += [f"{name} imports {a.name}" for a in node.names
                              if a.name.split(".")[0] not in stdlib]
                elif isinstance(node, ast.ImportFrom) and (node.level or (node.module or "").split(".")[0]
                                                           not in stdlib):
                    found.append(f"{name} imports from {node.module}")
        self.assertEqual(found, [])

    def test_no_module_imports_a_command(self):
        found = sorted(f"{src} imports {dst}" for src, dst in self.graph.edges()
                       if not is_package_module(dst) and dst not in SELF_CONTAINED)
        self.assertEqual(found, [], "a top-level module became a library: move its code into a package")



def commands() -> dict[str, Path]:
    return {path.stem: path for path in sorted(SCRIPTS.glob("*.py"))
            if path.stem != "__init__" and path.stem not in SELF_CONTAINED | STANDALONE_COMMANDS
            and tracked(path)}


def tracked(path: Path) -> bool:
    """Files kept out of git by the owner (.git/info/exclude) are not the repository's."""
    import subprocess
    result = subprocess.run(["git", "ls-files", "--error-unmatch", str(path)], cwd=SCRIPTS.parent,
                            capture_output=True, check=False)
    return result.returncode == 0


class ThinCommands(unittest.TestCase):
    """A command reads its options and calls a package. Code left in a command
    can only be tested by importing the command, and a command imported by its
    tests grows: check_freshness.py had reached 80 definitions."""

    def test_a_command_defines_its_entry_point_and_parser_only(self):
        found = []
        for name, path in commands().items():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            found += [f"{name}.{node.name}" for node in tree.body
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                      and node.name not in COMMAND_DEFINITIONS]
        self.assertEqual(found, [], "move it into the package the command calls")

    def test_tests_reach_a_command_through_its_entry_point_only(self):
        names = set(commands())
        found = []
        for path in sorted(Path(__file__).parent.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            bound: dict[str, str] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and not node.level and node.module:
                    module = node.module.removeprefix("scripts.")
                    if module in names:
                        found += [f"{path.name}: {module}.{a.name}" for a in node.names
                                  if a.name not in COMMAND_DEFINITIONS]
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        module = alias.name.removeprefix("scripts.")
                        if module in names:
                            bound[alias.asname or alias.name] = module
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    # mock.patch("verify.load_database") reaches into the command too.
                    module, _, attr = node.value.partition(".")
                    if (module in names and attr.isidentifier() and attr not in FILE_SUFFIXES
                            and attr not in COMMAND_DEFINITIONS):
                        found.append(f"{path.name}: {node.value}")
                if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                        and node.value.id in bound and node.attr not in COMMAND_DEFINITIONS
                        and not node.attr.startswith("__")):
                    found.append(f"{path.name}: {bound[node.value.id]}.{node.attr}")
        self.assertEqual(sorted(set(found)), [], "import it from the package that holds it")


if __name__ == "__main__":
    unittest.main()
