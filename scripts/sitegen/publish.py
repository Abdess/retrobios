"""Manifests, target lists and reports copied where the site serves them."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from model import siteinputs
from core.paths import REPO_ROOT
from sitegen.write import record_written, write_if_changed


def write_release_advertised(generated: Path) -> None:
    """The release record as the pages read it, for the file picker.

    The picker imported release.json whole and offered the ZIP of six setups
    the registry no longer releases, while their pages said "No ZIP". It
    reads this file instead: the platforms marked release_pack only.
    """
    generated.mkdir(parents=True, exist_ok=True)
    write_if_changed(
        str(generated / "release-advertised.json"),
        json.dumps(siteinputs.advertised(), ensure_ascii=False, indent=1,
                   sort_keys=True) + "\n",
    )


def publish_manifests(api: Path) -> list[tuple]:
    """The install manifests and the release record, beside the API.

    The platform's list says what a setup checks. The manifest says what its
    pack installs: Batocera's list holds 353 files, its pack 14,508. The
    only copy was install/<platform>.json on the repository's main branch,
    which no page named. Copied byte for byte: the SHA256 the catalog gives
    is the repository file's. Read from the folder the pages link from
    (siteinputs.manifests_dir), so a run on another collection serves the
    manifests its pages and DATs describe.
    """
    manifests = siteinputs.manifests_dir()
    folder = api / "manifests"
    folder.mkdir(parents=True, exist_ok=True)
    assets: list[tuple] = []
    for source in sorted(manifests.glob("*.json")):
        target = folder / source.name
        shutil.copy2(source, target)
        record_written(target)
        assets.append((target, f"Install manifest: {source.stem}", "application/json",
                       "schemas/install-manifest.schema.json"))
    # The target lists install.py --target reads: no catalog entry, and
    # api/v1/targets/ answered 404.
    targets = api / "targets"
    targets.mkdir(parents=True, exist_ok=True)
    for source in sorted((manifests / "targets").glob("*.json")):
        shutil.copy2(source, targets / source.name)
        record_written(targets / source.name)
        assets.append((targets / source.name, f"Target list: {source.stem}",
                       "application/json", "schemas/target-manifest.schema.json"))
    # Every change each updated platform file carries, for a maintainer who
    # reviews them by script: the Exports page linked only the files.
    exports = api / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for source in sorted((REPO_ROOT / "exports").glob("*.json")):
        shutil.copy2(source, exports / source.name)
        record_written(exports / source.name)
        assets.append((exports / source.name, f"Updated platform file, its changes: {source.stem}",
                       "application/json", None))
    release = siteinputs.release_record_path()
    if release.is_file():
        shutil.copy2(release, api / "release.json")
        record_written(api / "release.json")
        assets.append((api / "release.json", "Latest release: packs, sizes and assets",
                       "application/json", "schemas/release.schema.json"))
    return assets
