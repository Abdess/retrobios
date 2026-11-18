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
import hashlib
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_release_assets import compare, expected_assets, expected_digests, fetch_release
from model.database import load_database
from model.largefiles import LARGE_FILES_RELEASE, LARGE_FILES_REPO, asset_names, registered_paths

STAGING = Path("tmp") / "sync_release_assets"
OUT_OF_DATE = ("missing", "size", "content")


@dataclass(frozen=True)
class Upload:
    path: str
    asset: str
    kind: str
    verdict: str  # upload, refused
    reason: str = ""


def sha1_of(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def database_sha1(db: dict) -> dict[str, str]:
    return {
        entry["path"]: str(entry.get("sha1") or key).lower()
        for key, entry in db.get("files", {}).items()
        if entry.get("path")
    }


def plan_uploads(
    root: Path,
    db: dict,
    gitignore_text: str,
    findings: list,
    hasher: Callable[[Path], str] = sha1_of,
) -> list[Upload]:
    """Each out-of-date asset, cleared for upload or refused with its reason."""
    names = asset_names([*registered_paths(gitignore_text),
                         *expected_assets(db, gitignore_text)])
    recorded = database_sha1(db)
    plans = []
    for kind, path, _size, _published in findings:
        if kind not in OUT_OF_DATE:
            continue
        local = root / path
        if not local.is_file():
            plans.append(Upload(path, names[path], kind, "refused", "no local file"))
            continue
        first, second = hasher(local), hasher(local)
        if first != second:
            plans.append(Upload(path, names[path], kind, "refused",
                                f"two reads disagree ({first[:12]} != {second[:12]})"))
        elif first != recorded.get(path):
            plans.append(Upload(path, names[path], kind, "refused",
                                f"sha1 {first[:12]} is not the database's "
                                f"{str(recorded.get(path))[:12]}"))
        else:
            plans.append(Upload(path, names[path], kind, "upload"))
    return plans


def gh_upload(staged: Path) -> int:
    return subprocess.run(
        ["gh", "release", "upload", LARGE_FILES_RELEASE, str(staged), "--clobber",
         "-R", LARGE_FILES_REPO],
        check=False,
    ).returncode


def stage(root: Path, plan: Upload) -> Path:
    """The file under its asset name: gh names an asset after the file."""
    staged = root / STAGING / plan.asset
    staged.parent.mkdir(parents=True, exist_ok=True)
    if staged.exists():
        staged.unlink()
    try:
        os.link(root / plan.path, staged)
    except OSError:
        shutil.copy2(root / plan.path, staged)
    return staged


def upload_all(
    root: Path, plans: list[Upload], upload: Callable[[Path], int] = gh_upload
) -> list[str]:
    """Upload every cleared plan, twice at most, and return the failures."""
    failed = []
    for plan in plans:
        if plan.verdict != "upload":
            continue
        staged = stage(root, plan)
        try:
            if upload(staged) != 0 and upload(staged) != 0:
                failed.append(plan.path)
        finally:
            staged.unlink()
    return failed


def open_findings(
    db: dict, gitignore_text: str, fetch: Callable[[], tuple] = fetch_release
) -> list:
    assets, _body, digests = fetch()
    return compare(
        expected_assets(db, gitignore_text),
        assets,
        registered=registered_paths(gitignore_text),
        expected_digests=expected_digests(db, gitignore_text),
        asset_digests=digests,
    )


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true", help="upload (default: dry run)")
    parser.add_argument("--db", default="database.json",
                        help="database file to read (default: %(default)s)")
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
