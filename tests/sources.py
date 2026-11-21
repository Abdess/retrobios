"""The source text of a script, read across the package modules that hold its code.

A test that reads a tool's code to hold an invariant (one decision function,
no hand-built pack name) reads every module the tool's code lives in: a
command keeps its options, the packages keep the rest.
"""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

# Each command whose library code lives in packages, with those modules.
COMMANDS = {
    "generate_pack.py": (
        "packs/archive.py", "packs/naming.py", "packs/scope.py", "packs/datatrees.py",
        "packs/platformpack.py", "packs/emulatorpack.py", "packs/md5pack.py", "packs/targets.py",
        "packs/manifestentry.py", "packs/manifestcores.py", "packs/standalone.py",
        "packs/manifest.py", "packs/finalize.py",
    ),
    "verify.py": (
        "packs/verdicts.py", "packs/gaps.py", "packs/coverage.py", "packs/emulatorcheck.py",
        "packs/report.py",
    ),
    "cross_reference.py": ("packs/crossref.py",),
    "slots.py": ("packs/slots.py", "resolve/collisions.py"),
    "validate_pr.py": ("resolve/review.py", "core/gitclone.py"),
    "refresh_data_dirs.py": ("packs/datadirs.py",),
    "split_pack.py": ("packs/parts.py",),
    "dedup.py": ("model/nodedup.py",),
    "release_record.py": ("model/releaserecord.py", "release/record.py"),
    "release_notes.py": ("release/notes.py",),
    "check_release.py": ("release/check.py",),
    "check_release_assets.py": ("release/assets.py",),
    "sync_release_assets.py": ("release/sync.py",),
    "restore_large_files.py": ("release/restore.py",),
    "build_installer.py": ("installer_build/amalgamate.py",),
    "pin_installer.py": ("installer_build/pins.py",),
    "build_port.py": ("installer_build/port.py",),
    "build_pypi.py": ("installer_build/pypi.py",),
    "generate_launcher_index.py": ("installer_build/launcherindex.py",),
    "generate_event_schema.py": ("installer_build/eventschema.py",),
    "generate_installer_doc.py": ("installer_build/installerdoc.py",),
    "commit_rules.py": ("devtools/commitrules.py",),
    "pr_checks.py": ("devtools/prchecks.py",),
    "check_buildbot_system.py": ("scraper/buildbot_system.py",),
    "generate_site.py": (
        "sitegen/config.py",
        "sitegen/emulatorsindex.py",
        "sitegen/places.py",
        "sitegen/home.py",
        "sitegen/versions.py",
        "sitegen/guidepage.py",
        "sitegen/install.py",
        "sitegen/getpages.py",
        "sitegen/dataexports.py",
        "sitegen/lookup.py",
        "sitegen/apiitems.py",
        "sitegen/publish.py",
        "sitegen/datapage.py",
        "sitegen/descriptions.py",
        "sitegen/structured.py",
        "sitegen/cards.py",
        "sitegen/decorate.py",
        "sitegen/platformindex.py",
        "sitegen/parts.py",
        "sitegen/platformfiles.py",
        "sitegen/platformpage.py",
        "sitegen/systemsindex.py",
        "sitegen/provenance.py",
        "sitegen/fields.py",
        "sitegen/consolecards.py",
        "sitegen/startwith.py",
        "sitegen/systempages.py",
        "sitegen/emulatorcards.py",
        "sitegen/emulatorpage.py",
        "sitegen/gaps.py",
        "sitegen/crossref.py",
        "sitegen/reference.py",
        "sitegen/whichpack.py",
        "sitegen/nav.py",
        "sitegen/build.py",
    ),
    "sitediagrams.py": ("sitegen/diagrams.py",),
    "sitesources.py": ("sitegen/sources.py",),
    "site_markdown.py": ("sitegen/pagemarkdown.py",),
    "validate_site.py": ("sitegen/validate.py",),
    "validate_schemas.py": (
        "schemas/validators.py", "schemas/sources.py", "schemas/profilechecks.py",
        "schemas/citations.py", "schemas/platformchecks.py", "schemas/sourcetree.py",
        "schemas/registry.py", "schemas/documents.py", "schemas/installs.py",
        "schemas/packmanifests.py", "schemas/events.py", "schemas/measurements.py",
        "schemas/romfolders.py", "schemas/games.py", "schemas/run.py",
    ),
    "site_insights.py": ("sitegen/insights.py",),
    "generate_readme.py": ("sitegen/readme.py",),
    "romset_recipes.py": (
        "romrecipes/romsets.py", "romrecipes/pool.py", "romrecipes/pins.py", "romrecipes/identify.py",
        "romrecipes/ledger.py", "romrecipes/members.py", "romrecipes/capture.py", "romrecipes/build.py",
    ),
    "provenance_report.py": ("acquire/provenance.py",),
    "auto_fetch.py": ("acquire/fetch.py",),
    "find_embedded.py": ("acquire/embedded.py",),
    "find_pinned_revision.py": ("acquire/history.py",),
}


def script_paths(name: str) -> tuple[Path, ...]:
    """A script under scripts/, then the package modules that hold its code."""
    return tuple(SCRIPTS / n for n in (name, *COMMANDS.get(name, ())))


def script_source(name: str) -> str:
    """The text of a script and of the package modules that hold its code."""
    return "\n".join(path.read_text(encoding="utf-8") for path in script_paths(name))


def _helper_options(function: str) -> frozenset[str]:
    """The long options a core.cli helper declares through add_argument."""
    tree = ast.parse((SCRIPTS / "core" / "cli.py").read_text(encoding="utf-8"))
    body = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function)
    return frozenset(_add_argument_flags(body))


def _add_argument_flags(tree: ast.AST) -> set[str]:
    return {
        arg.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("--")
    }


@lru_cache(maxsize=None)
def declared_options(source: str) -> frozenset[str]:
    """The long options a script's source declares: its add_argument calls and
    the shared ones core.cli's add_repo_inputs and add_emulator_selection add."""
    from core.cli import REPO_INPUTS

    tree = ast.parse(source)
    found = _add_argument_flags(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id == "add_repo_inputs":
            found |= {REPO_INPUTS[arg.value][0] for arg in node.args[1:]
                      if isinstance(arg, ast.Constant) and arg.value in REPO_INPUTS}
        elif node.func.id == "add_emulator_selection":
            found |= _helper_options("add_emulator_selection")
    return frozenset(found)
