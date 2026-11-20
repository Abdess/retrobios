"""What the packs of a release hold, read from the archives when the release is cut."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from core.paths import PLATFORMS_DIR
from core.artifacts import artifact_lock
from model.registry import list_release_pack_platforms
from model.releaserecord import SCHEMA_VERSION, pack_name_for
from packs import parts


class UnfinishedSplitError(Exception):
    """A pack lies beside its own parts: a split is running or was killed."""


class NotAReleasePackError(Exception):
    """A pack in the directory is not the full pack of a registered platform."""


def release_owners(platforms_dir: str = PLATFORMS_DIR) -> dict[str, list[str]]:
    """Full pack file name to the platforms it serves, as the builder names it.

    Rebuilt from the name builder, never matched by substring: matched by
    substring, RetroArch_v1.22.2_AndroidArm64V8A_BIOS_Pack.zip sorts before
    the full pack and was taken for the RetroArch pack. Only the platforms
    marked release_pack own a release pack.
    """
    from packs import naming

    platforms = list_release_pack_platforms(platforms_dir)
    owners: dict[str, list[str]] = {}
    for platform, names in naming.expected_pack_names(
        platforms, platforms_dir, None, None
    ).items():
        for name in names:
            owners.setdefault(name, []).append(platform)
    return {name: sorted(serves) for name, serves in owners.items()}


def build_record(
    dist: Path,
    tag: str,
    platforms_dir: str = PLATFORMS_DIR,
    owners: dict[str, list[str]] | None = None,
) -> dict:
    """Read every pack of a directory, parts counted once across them.

    Read under the shared artifact lock, so a split that is reading its parts
    back cannot be recorded half done. A pack still beside its parts after
    that is a split that never finished: summed, it doubled the download size
    and named an asset that is never published. Each pack carries the
    platforms it serves, so a reader finds a platform's pack by that list
    after a later version or grouping has renamed the pack main would build.
    """
    if owners is None:
        owners = release_owners(platforms_dir)
    with artifact_lock(str(dist), exclusive=False):
        return _read_record(Path(dist), tag, owners)


def _read_record(dist: Path, tag: str, owners: dict[str, list[str]]) -> dict:
    assets: dict[str, list[Path]] = {}
    for path in sorted(dist.glob("*_BIOS_Pack*.zip")):
        assets.setdefault(parts.pack_of(path.name), []).append(path)
    for paths in assets.values():
        whole = [p for p in paths if not parts.is_part(p.name)]
        if whole and len(paths) > len(whole):
            raise UnfinishedSplitError(
                f"{whole[0].name} lies beside its parts: the split did not finish"
            )
    foreign = sorted(name for name in assets if name not in owners)
    if foreign:
        raise NotAReleasePackError(
            f"not the full pack of a registered platform: {', '.join(foreign)}"
            " (a narrowed or older build left in the directory)"
        )

    packs = {}
    for name, paths in sorted(assets.items()):
        members: dict[str, int] = {}
        for path in paths:
            with zipfile.ZipFile(path) as archive:
                # A part's marker names its siblings and is not pack content:
                # the manifest's pack_files is counted before any split.
                for info in archive.infolist():
                    if not parts.is_marker(info.filename):
                        members[info.filename] = info.file_size
        packs[name] = {
            "files": len(members),
            "extracted_size": sum(members.values()),
            "download_size": sum(path.stat().st_size for path in paths),
            "assets": [path.name for path in paths],
            "platforms": owners[name],
        }
    return {"schema_version": SCHEMA_VERSION, "tag": tag, "packs": packs}


def manifest_mismatches(record: dict, install_dir: str | Path) -> list[str]:
    """Packs whose archive does not hold what their install manifest expects."""
    found = []
    for manifest_path in sorted(Path(install_dir).glob("*.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.get("pack_files")
        name = pack_name_for(manifest_path.stem, record)
        if expected is None or name is None:
            continue
        pack = record["packs"][name]
        if pack["files"] != expected:
            found.append(
                f"{name} holds {pack['files']} files, "
                f"install/{manifest_path.name} expects {expected}"
            )
    return found


def size_text(count: int) -> str:
    if count >= 1024**3:
        return f"{count / 1024**3:.1f} GB"
    return f"{count / 1024**2:.0f} MB"
