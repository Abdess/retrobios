"""Upload of the large-files assets the release lacks or serves out of date."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from core.hashing import file_digest
from model.largefiles import LARGE_FILES_RELEASE, LARGE_FILES_REPO, asset_names, registered_paths
from release.assets import compare, expected_assets, expected_digests, fetch_release


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
    return file_digest(path)


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
