#!/usr/bin/env python3
"""Upload the large-files assets the release lacks or serves out of date.

check_release_assets.py names every gitignored file the release does not
serve as the collection holds it: missing, another size, another sha256.
install.py refuses a download whose size differs from the manifest, so each
of these breaks every install of the file until it is uploaded again.

A file is uploaded only when its SHA-1, read twice from disk, gives the same
value both times and equals the SHA-1 database.json records for its path:
the bytes that go out are the bytes the manifests describe, and a read this
host got wrong is never published. The asset keeps the name
largefiles.asset_names() gives the path. After the uploads the release is
read again and every finding still open is reported.

Dry run by default: --apply uploads. The release description is not edited
here, check_release_assets.py --notes renders it.

Usage:
    python scripts/sync_release_assets.py
    python scripts/sync_release_assets.py --apply
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from core.cli import add_repo_inputs
from model.database import load_database
from release.sync import OUT_OF_DATE, open_findings, plan_uploads, upload_all


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true", help="upload (default: dry run)")
    add_repo_inputs(parser, "db")
    args = parser.parse_args()

    root = Path.cwd()
    gitignore_text = (root / ".gitignore").read_text(encoding="utf-8")
    db = load_database(args.db)
    try:
        findings = open_findings(db, gitignore_text)
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError) as exc:
        print(f"ERROR: cannot list release assets: {exc}", file=sys.stderr)
        return 2
    plans = plan_uploads(root, db, gitignore_text, findings)
    for plan in plans:
        if plan.verdict == "upload":
            verb = "uploading" if args.apply else "would upload"
            print(f"{verb:13} {plan.kind:8} {plan.path} as {plan.asset}")
        else:
            print(f"{'refused':13} {plan.kind:8} {plan.path}: {plan.reason}")
    if not plans:
        print("release assets match the collection")
        return 0
    if not args.apply:
        return 1
    failed = upload_all(root, plans)
    for path in failed:
        print(f"FAILED upload of {path}, twice", file=sys.stderr)
    remaining = [f for f in open_findings(db, gitignore_text) if f.kind in OUT_OF_DATE]
    for kind, path, _size, _published in remaining:
        print(f"still {kind}: {path}")
    return 1 if remaining or failed else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
