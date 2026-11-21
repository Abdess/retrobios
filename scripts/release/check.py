"""A dated release compared with release.json and the checksum list."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from model.largefiles import LARGE_FILES_REPO, digests_of
from release.sums import SUMS


SIGNATURE = SUMS + ".sig"
@dataclass(frozen=True)
class Asset:
    size: int
    sha256: str | None


@dataclass(frozen=True)
class Finding:
    kind: str
    name: str
    detail: str


def _registry_findings(packs: dict, released: set[str]) -> list[Finding]:
    """Each platform marked release_pack has a pack, and each pack serves one."""
    served = {p for pack in packs.values() for p in pack.get("platforms", ())}
    findings = [Finding("no-pack", platform, "release_pack: true, no pack in release.json")
                for platform in sorted(released - served)]
    findings.extend(Finding(
        "not-released", pack_name,
        "serves no platform marked release_pack in platforms/_registry.yml",
    ) for pack_name, pack in sorted(packs.items()) if not set(pack.get("platforms", ())) & released)
    return findings


def compare_release(
    record: dict,
    sums: dict[str, str],
    assets: dict[str, Asset],
    tag: str,
    local_files: dict[str, str] | None = None,
    released: set[str] | None = None,
) -> list[Finding]:
    """Every way the release can differ from what was built.

    *local_files* maps a file kept beside the packs (the checksum list, its
    signature) to its local sha256: the copy on the release must be that one.
    *released* names the platforms the registry marks release_pack: each one
    has a recorded pack, and no recorded pack serves only other platforms.
    """
    findings: list[Finding] = []
    if record.get("tag") != tag:
        findings.append(Finding("tag", tag, f"release.json records {record.get('tag')}"))
    if released is not None:
        findings += _registry_findings(record.get("packs", {}), released)

    recorded = {
        name: pack_name
        for pack_name, pack in record.get("packs", {}).items()
        for name in pack.get("assets", [])
    }
    expected = set(recorded) | set(sums) | {SUMS} | set(local_files or ())
    allowed = expected | {SIGNATURE}

    findings.extend(Finding("missing", name, "not attached to the release")
                    for name in sorted(expected - set(assets)))
    findings.extend(Finding("extra", name, "attached but neither recorded nor listed")
                    for name in sorted(set(assets) - allowed))
    findings.extend(Finding("unlisted", name, f"absent from {SUMS}")
                    for name in sorted(set(recorded) - set(sums)))
    findings.extend(Finding("unrecorded", name, f"listed in {SUMS}, absent from release.json")
                    for name in sorted(set(sums) - set(recorded)))

    wanted = {**sums, **(local_files or {})}
    for name, digest in sorted(wanted.items()):
        asset = assets.get(name)
        if asset is None:
            continue
        if asset.sha256 is None:
            findings.append(Finding("unverified", name, "the release gives no sha256"))
        elif asset.sha256 != digest:
            findings.append(Finding(
                "content", name, f"release sha256 {asset.sha256[:12]} != {digest[:12]}"
            ))

    for pack_name, pack in sorted(record.get("packs", {}).items()):
        parts = [assets[name].size for name in pack.get("assets", []) if name in assets]
        if len(parts) == len(pack.get("assets", [])) and sum(parts) != pack.get("download_size"):
            findings.append(Finding(
                "size", pack_name,
                f"assets total {sum(parts)} bytes, release.json says {pack.get('download_size')}",
            ))
    return findings


def fetch_assets(tag: str) -> tuple[dict[str, Asset], bool]:
    """Name, size and sha256 of every asset of *tag*, and whether it is a draft."""
    result = subprocess.run(
        ["gh", "release", "view", tag, "-R", LARGE_FILES_REPO, "--json", "assets,isDraft"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(result.stdout)
    digests = digests_of(data["assets"])
    return (
        {a["name"]: Asset(a["size"], digests.get(a["name"])) for a in data["assets"]},
        bool(data.get("isDraft")),
    )


def fetch_sums(tag: str) -> str:
    """The checksum list as attached to *tag*."""
    result = subprocess.run(
        ["gh", "release", "download", tag, "-R", LARGE_FILES_REPO,
         "--pattern", SUMS, "--output", "-"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout
