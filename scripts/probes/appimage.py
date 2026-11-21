"""The release AppImage a platform picks, fetched and unpacked without running it."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from collections.abc import Sequence
from pathlib import Path

import core_probe as cp
from core import upstream
from core.paths import REPO_ROOT
from core.statefile import now_iso
from probes.standaloneemulators import Emulator
from scraper.base_scraper import github_json

CACHE = REPO_ROOT / ".cache" / "standalone"


def select_asset(releases: Sequence[dict], endswith: str, contains: str) -> dict | None:
    """The asset EmuDeck's getReleaseURLGH returns: the first, over the
    releases in the API's order, whose name contains and ends as asked."""
    for release in releases:
        for asset in release.get("assets") or ():
            name = asset.get("name", "")
            if contains in name and name.endswith(endswith):
                return {"tag": release.get("tag_name"), "name": name,
                        "url": asset.get("browser_download_url"),
                        "prerelease": bool(release.get("prerelease"))}
    return None


def appimage_offset(head: bytes) -> int:
    """Where an AppImage's squashfs starts: the end of its ELF runtime,
    read from the section header table, as the runtime computes it."""
    if head[:4] != b"\x7fELF":
        raise cp.ProbeError("not an ELF file, not an AppImage")
    if head[4] == 2:
        shoff = struct.unpack_from("<Q", head, 0x28)[0]
        shentsize, shnum = struct.unpack_from("<HH", head, 0x3A)
    else:
        shoff = struct.unpack_from("<I", head, 0x20)[0]
        shentsize, shnum = struct.unpack_from("<HH", head, 0x2E)
    return shoff + shentsize * shnum


def github_releases(repo: str) -> list[dict]:
    return github_json(f"https://api.github.com/repos/{repo}/releases",
                       f"cannot list the releases of {repo}", timeout=60, error=cp.ProbeError)


def fetch(emu: Emulator, cache: Path = CACHE) -> dict:
    """Download the asset the platform picks, unpack it, and describe it."""
    asset = select_asset(github_releases(emu.repo), emu.asset_endswith, emu.asset_contains)
    if not asset:
        raise cp.ProbeError(f"{emu.repo}: no release asset matches the {emu.platform} rule")
    folder = cache / emu.name
    folder.mkdir(parents=True, exist_ok=True)
    partial = folder / f"{asset['name']}.part"
    # Whole or absent, retried on a cut stream (core.upstream.download).
    upstream.download(asset["url"], partial, timeout=600)
    sha256 = cp.file_digest(partial, "sha256")
    target = folder / sha256 / asset["name"]
    target.parent.mkdir(parents=True, exist_ok=True)
    partial.replace(target)
    unpack(target)
    meta = {**asset, "sha256": sha256, "repo": emu.repo, "platform": emu.platform,
            "installer_ref": emu.installer_ref, "fetched_at": now_iso()}
    (target.parent / "asset.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def unpack(appimage: Path) -> Path:
    """The AppImage's tree, unpacked with unsquashfs: the runtime is never run."""
    tree = appimage.parent / "tree"
    if tree.is_dir():
        return tree
    unsquashfs = shutil.which("unsquashfs")
    if not unsquashfs:
        raise cp.ProbeError("unsquashfs not found (squashfs-tools)")
    with appimage.open("rb") as handle:
        offset = appimage_offset(handle.read(64))
    scratch = appimage.parent / "tree.part"
    shutil.rmtree(scratch, ignore_errors=True)
    subprocess.run([unsquashfs, "-q", "-n", "-o", str(offset), "-d", str(scratch), str(appimage)],
                   check=True, stdout=subprocess.DEVNULL)
    scratch.replace(tree)
    return tree


def installed(emu: Emulator, sha256: str | None, cache: Path = CACHE) -> tuple[dict, Path]:
    """The fetched asset to run: the one named by sha256, else the newest."""
    folder = cache / emu.name
    metas = sorted(folder.glob("*/asset.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in metas:
        meta = json.loads(path.read_text(encoding="utf-8"))
        if sha256 in (None, meta["sha256"]):
            return meta, unpack(path.parent / meta["name"])
    raise cp.ProbeError(f"{emu.name}: no fetched asset{' ' + sha256 if sha256 else ''}, "
                        f"run `standalone_probe.py fetch {emu.name}`")
