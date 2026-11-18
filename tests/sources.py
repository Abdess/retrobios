"""The source text of a script, read across the package modules that hold its code.

A test that reads a tool's code to hold an invariant (one decision function,
no hand-built pack name) reads every module the tool's code lives in: a
command keeps its options, the packages keep the rest.
"""

from __future__ import annotations

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
    "site_insights.py": ("sitegen/insights.py",),
    "generate_readme.py": ("sitegen/readme.py",),
}


def script_paths(name: str) -> tuple[Path, ...]:
    """A script under scripts/, then the package modules that hold its code."""
    return tuple(SCRIPTS / n for n in (name, *COMMANDS.get(name, ())))


def script_source(name: str) -> str:
    """The text of a script and of the package modules that hold its code."""
    return "\n".join(path.read_text(encoding="utf-8") for path in script_paths(name))
