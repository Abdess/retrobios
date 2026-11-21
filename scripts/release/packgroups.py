"""The assets of a release grouped into platform packs, and the pack of a platform."""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.paths import REPO_ROOT
from model.releaserecord import PACK_SUFFIX, RECORD, load_record, match_key, pack_label, recorded_pack
from packs.parts import part_of

_VOLUME_RE = re.compile(rf"^(?P<base>.+{re.escape(PACK_SUFFIX)})\.(?P<index>\d+)$")


@dataclass(frozen=True)
class Pack:
    """A platform pack: one asset, or the files it was published in.

    `joined` says the files are byte ranges of one archive. `expected_parts`
    is the count a part's own name declares, so a release that lists fewer
    is recognised before anything is downloaded.
    """

    name: str
    platform: str
    parts: tuple[dict, ...]
    size: int
    joined: bool = False
    expected_parts: int = 1


def group_packs(release: dict) -> list[Pack]:
    """Group release assets into packs, the files of one pack folded together."""
    groups: dict[str, list[tuple[int, dict]]] = {}
    joined: set[str] = set()
    expected: dict[str, int] = {}
    for asset in release.get("assets", []):
        name = asset["name"]
        volume = _VOLUME_RE.match(name)
        part = part_of(name)
        if volume:
            groups.setdefault(volume["base"], []).append((int(volume["index"]), asset))
            joined.add(volume["base"])
        elif part:
            base, index, count = part
            groups.setdefault(base, []).append((index, asset))
            expected[base] = count
        elif name.endswith(PACK_SUFFIX):
            groups.setdefault(name, []).append((0, asset))

    packs = []
    for base, volumes in sorted(groups.items()):
        parts = tuple(asset for _, asset in sorted(volumes, key=lambda v: v[0]))
        packs.append(
            Pack(
                name=base,
                platform=pack_label(base),
                parts=parts,
                size=sum(part.get("size", 0) for part in parts),
                joined=base in joined,
                expected_parts=expected.get(base, len(parts)),
            )
        )
    return packs


def list_platforms(release: dict) -> list[str]:
    """List available platform packs from release assets."""
    return sorted(pack.platform for pack in group_packs(release))


def find_pack(release: dict, platform: str) -> Pack | None:
    """Find the pack for a platform name.

    release.json names the platforms each pack serves, and is read when it
    records this release. Otherwise the platform is matched against the pack
    names, the shortest first: RetroArch_v1.22.2 is the full pack, and
    RetroArch_v1.22.2_AndroidArm64V8A one target's.
    """
    packs = group_packs(release)
    record = load_record(REPO_ROOT / RECORD)
    if record.get("tag") and record.get("tag") == release.get("tag_name"):
        name = recorded_pack(platform, record)
        return next((pack for pack in packs if pack.name == name), None)
    needle = match_key(platform)
    if not needle:
        return None
    matches = [pack for pack in packs if needle in match_key(pack.name)]
    return min(matches, key=lambda pack: (len(match_key(pack.name)), pack.name), default=None)
