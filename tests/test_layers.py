"""The import layers of scripts/: core, model, resolve, domain packages, commands.

A module imports only from its own layer or below. core is the standard
library's only client, model loads data, resolve turns declarations into
files, the domain packages build on them, and the top-level scripts are the
commands. Library code still waiting at the top level is listed in
NOT_YET_PACKAGED, and the edges a domain package still has to it in
PENDING_TOP_LEVEL_IMPORTS: both lists must be exact, so a later move that
empties an entry also removes it.
"""

from __future__ import annotations

import tests
import ast
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"

PACKAGE_LAYERS = {"core": 0, "model": 1, "resolve": 2, "packs": 3, "scraper": 3, "exporter": 3, "profiling": 3}
LIBRARY_LAYER = 3
COMMAND_LAYER = 4

# The other domain packages a domain package may import. A package listed
# here imports no sibling outside its set.
SIBLING_IMPORTS: dict[str, frozenset[str]] = {
    "packs": frozenset(),
    "profiling": frozenset(),
}

# Top-level modules other modules of scripts/ import: library code that a
# later wave moves into a package.
NOT_YET_PACKAGED = frozenset({
    "archive_build", "autorun", "build_port", "campaign", "campaign_profiles", "campaign_rules",
    "check_buildbot_system", "check_release_assets", "commit_rules", "core_probe", "derivations",
    "generate_event_schema", "generate_readme", "generate_site", "measurement_records",
    "pin_installer", "pr_checks", "provenance_report", "release_record", "romfolders",
    "romset_recipes", "siteagents", "sitebootstrap", "sitecollection", "sitediagrams",
    "siteentries", "siteexports", "siteguides", "sitehandheld", "siteinputs", "sitemarkup",
    "sitemeasurements", "siterender", "sitesources", "sitestarlight", "sitesteps", "sitewanted",
    "sitewrite",
})

# Imports from a package module to a top-level module, left for the wave that
# packages the top-level side.
PENDING_TOP_LEVEL_IMPORTS = frozenset({
    ("packs.readme", "siteguides"),
    ("packs.scope", "siterender"),
})


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
    return LIBRARY_LAYER if name in NOT_YET_PACKAGED else COMMAND_LAYER


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
        found = {(src, dst) for src, dst in self.graph.edges()
                 if is_package_module(src) and not is_package_module(dst)}
        self.assertEqual(sorted(found - PENDING_TOP_LEVEL_IMPORTS), [])
        self.assertEqual(sorted(PENDING_TOP_LEVEL_IMPORTS - found), [],
                         "a pending import no longer exists: remove it from the list")

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

    def test_not_yet_packaged_is_the_exact_set_of_top_level_libraries(self):
        imported = {dst for _src, dst in self.graph.edges() if not is_package_module(dst)}
        self.assertEqual(sorted(imported - NOT_YET_PACKAGED), [],
                         "a top-level module became a library: package it or list it")
        self.assertEqual(sorted(NOT_YET_PACKAGED - imported), [],
                         "listed modules no longer imported by scripts/ (moved, or now a command only)")


if __name__ == "__main__":
    unittest.main()
