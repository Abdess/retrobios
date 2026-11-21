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
        "packs/manifest.py", "packs/finalize.py", "packs/outputdir.py", "packs/variants.py",
        "packs/manifestrun.py", "packs/packcheck.py", "packs/runscope.py", "packs/platformrun.py",
        "packs/packoptions.py", "packs/packmodes.py", "packs/packcounts.py",
        "packs/emulatorentries.py", "packs/integrity.py",
        "packs/hashinput.py", "packs/hashlookup.py", "packs/executable.py",
    ),
    "verify.py": (
        "packs/verdicts.py", "packs/gaps.py", "packs/coverage.py", "packs/emulatorcheck.py",
        "packs/report.py", "packs/shares.py", "packs/verifyplatforms.py", "packs/verifysummary.py",
        "packs/verifyoutput.py", "packs/strictgate.py", "packs/verifyoptions.py",
        "packs/verifyprint.py", "packs/runscope.py", "packs/verifyrun.py",
        "packs/emulatorentries.py",
    ),
    "cross_reference.py": (
        "packs/crossref.py", "packs/crossrefscope.py", "packs/crossrefrun.py",
        "packs/crossreflaunchers.py", "packs/crossreftext.py", "packs/crossrefreport.py",
    ),
    "slots.py": ("packs/slots.py", "resolve/collisions.py", "packs/slotscan.py", "packs/slotreport.py"),
    "validate_pr.py": (
        "resolve/review.py", "devtools/reviewfiles.py", "devtools/reviewreport.py",
        "core/gitclone.py",
    ),
    "refresh_data_dirs.py": ("packs/datadirs.py", "packs/datadirextract.py"),
    "split_pack.py": ("packs/parts.py", "release/sums.py"),
    "retired_files.py": ("model/retired.py", "collection/retiredhistory.py"),
    "region_audit.py": ("resolve/regionaudit.py",),
    "dedup.py": (
        "model/nodedup.py", "collection/dedup.py", "collection/duplicates.py",
        "collection/clonemap.py",
    ),
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
    "check_buildbot_system.py": (
        "scraper/buildbot_system.py", "packs/datadirs.py", "packs/datadirextract.py",
    ),
    "generate_site.py": (
        "sitegen/config.py", "sitegen/emulatorsindex.py", "sitegen/places.py", "sitegen/home.py",
        "sitegen/versions.py", "sitegen/guidepage.py", "sitegen/install.py", "sitegen/getpages.py",
        "sitegen/dataexports.py", "sitegen/lookup.py", "sitegen/apiitems.py", "sitegen/publish.py",
        "sitegen/datapage.py", "sitegen/descriptions.py", "sitegen/structured.py",
        "sitegen/cards.py", "sitegen/decorate.py", "sitegen/pageprep.py", "sitegen/platformindex.py",
        "sitegen/parts.py", "sitegen/platformfiles.py", "sitegen/platformpage.py",
        "sitegen/systemsindex.py",
        "sitegen/provenance.py", "sitegen/fields.py", "sitegen/consolecards.py",
        "sitegen/startwith.py", "sitegen/systempages.py", "sitegen/emulatorcards.py",
        "sitegen/emulatorpage.py", "sitegen/gaps.py", "sitegen/crossref.py", "sitegen/reference.py",
        "sitegen/whichpack.py", "sitegen/nav.py", "sitegen/build.py", "sitegen/coverage.py",
        "sitegen/extraction.py", "sitegen/releasepacks.py",
    ),
    "sitediagrams.py": ("sitegen/diagrams.py",),
    "sitesources.py": ("sitegen/sources.py",),
    "site_markdown.py": ("sitegen/pagemarkdown.py",),
    "validate_site.py": ("sitegen/validate.py",),
    "site_insights.py": ("sitegen/insights.py",),
    "generate_readme.py": (
        "sitegen/readme.py", "sitegen/coverage.py", "sitegen/extraction.py",
        "sitegen/releasepacks.py",
    ),
    "indexnow.py": ("sitegen/indexnow.py",),
    "generate_report_excerpt.py": ("sitegen/reportexcerpt.py",),
    "romset_recipes.py": (
        "romrecipes/romsets.py", "romrecipes/pool.py", "romrecipes/pins.py",
        "romrecipes/identify.py", "romrecipes/ledger.py", "romrecipes/members.py",
        "romrecipes/capture.py", "romrecipes/build.py", "romrecipes/survey.py",
        "romrecipes/text.py", "romrecipes/runs.py",
    ),
    "provenance_report.py": ("acquire/provenance.py",),
    "auto_fetch.py": ("acquire/fetch.py",),
    "find_embedded.py": ("acquire/embedded.py",),
    "find_pinned_revision.py": ("acquire/history.py",),
    "check_freshness.py": (
        "freshness/findings.py", "freshness/platformdiff.py", "freshness/rescrape.py",
        "freshness/scrapers.py", "freshness/platforms.py", "freshness/native.py",
        "freshness/targets.py",
        "freshness/romfolders.py", "freshness/coreinfo.py", "freshness/data.py",
        "freshness/catalogs.py", "freshness/ci.py", "freshness/pinbuilds.py",
        "freshness/profiles.py", "freshness/report.py",
    ),
    "refresh_stale.py": (
        "freshness/stalejob.py", "freshness/stalefindings.py", "freshness/stalecommands.py",
        "freshness/staleplan.py", "freshness/stalerun.py", "freshness/stalereport.py",
        "freshness/scrapers.py",
    ),
    "pipeline.py": (
        "orchestrate/labels.py", "orchestrate/results.py", "orchestrate/runner.py",
        "orchestrate/guards.py", "orchestrate/locks.py", "orchestrate/prepare.py",
        "orchestrate/build.py", "orchestrate/checks.py", "orchestrate/docs.py",
        "orchestrate/compare.py", "orchestrate/consistency.py",
        "orchestrate/emulatorpacks.py", "orchestrate/narrowed.py", "orchestrate/splitcheck.py",
    ),
    "validate_schemas.py": (
        "schemas/validators.py", "schemas/sources.py", "schemas/profilechecks.py",
        "schemas/citations.py", "schemas/platformchecks.py", "schemas/sourcetree.py",
        "schemas/registry.py", "schemas/documents.py", "schemas/installs.py",
        "schemas/packmanifests.py", "schemas/events.py", "schemas/measurements.py",
        "schemas/romfolders.py", "schemas/games.py", "schemas/run.py",
    ),
    "generate_db.py": (
        "collection/scan.py", "collection/hashcache.py", "collection/releaseassets.py",
        "collection/declared.py", "collection/aliases.py", "collection/indexes.py",
        "collection/record.py", "collection/run.py",
    ),
    "bios_integrity.py": ("collection/integrity.py", "collection/gitrestore.py"),
    "game_rules.py": (
        "games/inputs.py", "games/profileindex.py", "games/headerreaders.py", "games/rulecheck.py",
        "games/rulesummary.py",
    ),
    "generate_games_index.py": (
        "games/inputs.py", "games/profileindex.py", "games/fallback.py", "games/folders.py",
        "games/setups.py", "games/systems.py", "games/arcadesets.py", "games/render.py",
        "games/coverage.py", "games/changes.py", "games/publish.py", "games/run.py",
    ),
    "download.py": (
        "release/latest.py", "release/packgroups.py", "release/transfer.py", "release/packfetch.py",
        "release/packinfo.py",
    ),
    "cleanup_disk.py": ("devtools/diskcleanup.py",),
    "migrate.py": ("devtools/biosclassify.py", "devtools/biosmigrate.py"),
    "run_tests.py": ("devtools/testrunner.py",),
    "make_demo.py": (
        "sitegen/demovariants.py", "sitegen/democard.py", "sitegen/demosession.py",
        "sitegen/demorecord.py",
    ),
    "campaign.py": (
        "probes/campaign.py", "probes/host.py", "probes/content.py", "probes/cores.py",
        "probes/rules.py", "probes/state.py", "probes/gate.py", "probes/reports.py",
        "probes/profileedit.py", "probes/entries.py", "probes/campaignmodes.py",
    ),
    "standalone_probe.py": (
        "probes/standaloneemulators.py", "probes/appimage.py", "probes/xvfb.py",
        "probes/standalonerun.py", "probes/standalonerecord.py", "probes/standalonemodes.py",
    ),
    "profile_sync.py": (
        "profiling/citations.py", "profiling/anchoring.py", "profiling/repos.py",
        "profiling/resolver.py", "profiling/reports.py", "profiling/versions.py",
        "profiling/version_basis.py", "profiling/detection.py", "profiling/triage.py",
        "profiling/yamledit.py", "profiling/proseedit.py", "profiling/rebase.py",
        "profiling/bump.py", "profiling/realign.py", "profiling/run.py", "profiling/worktree.py",
        "profiling/quota.py", "profiling/sourcepaths.py", "profiling/realignpass.py",
        "profiling/versioncheck.py", "profiling/selection.py", "profiling/flagchecks.py",
    ),
    "generate_truth.py": ("resolve/truth.py",),
    "diff_truth.py": ("exporter/truthdiff.py", "exporter/diffreport.py"),
    "fetch_site_images.py": ("sitegen/imagefetch.py", "sitegen/imagenormalize.py"),
    "make_site_icons.py": ("sitegen/brand.py", "sitegen/chromium.py"),
    "make_og_cards.py": ("sitegen/ogcards.py", "sitegen/chromium.py"),
    "mame_ref_audit.py": ("profiling/mamerefs.py",),
    "fileless_audit.py": ("profiling/fileless.py",),
    "bundled_only.py": ("packs/bundledonly.py",),
    "export_native.py": (
        "exporter/runner.py", "exporter/native.py", "exporter/originals.py", "exporter/landed.py",
    ),
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
