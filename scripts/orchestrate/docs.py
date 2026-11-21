"""Steps 7 to 8b: README and generated pages, the site pages, the rendered site."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from orchestrate import runner
from orchestrate.labels import STEP_LABELS, skip_notice
from orchestrate.results import SKIPPED


def docs_steps(args: argparse.Namespace, results: dict) -> bool:
    """Steps 7 to 8b: README and pages, site pages, the rendered site."""
    all_ok = True
    # Step 7: Generate README
    if not args.skip_docs:
        ok, _ = runner.run(
            [
                sys.executable,
                "scripts/generate_readme.py",
                "--db",
                "database.json",
                "--platforms-dir",
                "platforms",
            ],
            STEP_LABELS["generate_readme"],
        )
        # The run samples of wiki/installer.md, printed by install.py from
        # the manifests step 4b just wrote.
        doc_ok, _ = runner.run([sys.executable, "scripts/generate_installer_doc.py"],
                               "7 generate installer page")
        # The verify excerpt of wiki/reading-reports.md, from this run's data.
        excerpt_ok, _ = runner.run([sys.executable, "scripts/generate_report_excerpt.py"],
                                   "7 generate report excerpt")
        ok = ok and doc_ok and excerpt_ok
        results["generate_readme"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("generate_readme", "--skip-docs")
        results["generate_readme"] = SKIPPED

    # Step 8: Generate site pages
    if not args.skip_docs:
        ok, _ = runner.run(
            [sys.executable, "scripts/generate_site.py"],
            STEP_LABELS["generate_site"],
        )
        results["generate_site"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("generate_site", "--skip-docs")
        results["generate_site"] = SKIPPED

    # Step 8b: the render the site deploy runs. Generating the pages without
    # rendering them let 20 pages with duplicate ids through to CI.
    if args.skip_docs:
        skip_notice("render_site", "--skip-docs")
        results["render_site"] = SKIPPED
    elif shutil.which("npm") is None or not Path("website/node_modules").is_dir():
        skip_notice("render_site", "Node not set up: npm ci --prefix website")
        results["render_site"] = SKIPPED
    else:
        # Starlight's link check runs inside the build and fails it.
        ok, _ = runner.run(["npm", "run", "build", "--prefix", "website"], STEP_LABELS["render_site"])
        if ok:
            ok, _ = runner.run([sys.executable, "scripts/validate_site.py", "--site-dir", "website/dist"],
                               "8b validate site")
        results["render_site"] = ok
        all_ok = all_ok and ok
    return all_ok
