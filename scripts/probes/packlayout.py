"""A pack as a user installs it: extracted, or written by the installer, and its files."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from core.hashing import file_digest
from core.paths import REPO_ROOT
from core.ziptools import safe_extract_zip


class ProbeFailure(RuntimeError):
    """The probe cannot go on: no pack, no installer layout, a busy host."""


# --------------------------------------------------------------------------
# Layouts: the platform's BIOS folder as a user ends up with it
# --------------------------------------------------------------------------

@dataclass
class Layout:
    """A BIOS folder: every file by its path under the folder, and the pack
    or manifest entry that put it there (None for a file nothing declares)."""

    install: str
    root: Path
    files: dict[str, str | None]
    source: dict
    sizes: dict[str, int] = field(default_factory=dict)

    def size(self, rel: str) -> int:
        if rel not in self.sizes:
            self.sizes[rel] = (self.root / rel).stat().st_size
        return self.sizes[rel]


def walk(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())



def pack_layout(pack: Path, root: Path, identity: dict) -> Layout:
    """The pack extracted as a user does, at the root of the BIOS folder.
    Each file's entry is the archive member it came from."""
    if root.exists():
        shutil.rmtree(root)
    safe_extract_zip(str(pack), str(root))
    with zipfile.ZipFile(pack) as handle:
        members = {info.filename for info in handle.infolist() if not info.is_dir()}
    files = {rel: rel if rel in members else None for rel in walk(root)}
    return Layout("pack", root, files, {"pack": identity, "manifest": None})


def pack_identity(pack: Path) -> dict:
    with zipfile.ZipFile(pack) as handle:
        members = sum(1 for info in handle.infolist() if not info.is_dir())
    return {"file": pack.name, "sha256": file_digest(pack, "sha256"), "size": pack.stat().st_size,
            "members": members}


def manifest_entries(manifest: dict) -> dict[str, str]:
    """Destination -> the manifest entry that names it, as the installer
    places it under --dest: a file by its dest, a data directory member
    under its directory's dest."""
    out: dict[str, str] = {}
    for item in manifest.get("files") or ():
        out[item["dest"]] = f"files:{item['dest']}"
    for item in manifest.get("case_variants") or ():
        out.setdefault(item["dest"], f"case_variants:{item['dest']}")
    for directory in manifest.get("data_directories") or ():
        base = str(directory.get("dest") or "").strip("/")
        for member in directory.get("files") or {}:
            dest = f"{base}/{member}" if base else member
            out.setdefault(dest, f"data_directories:{directory['ref']}:{member}")
    return out


def installer_summary(stdout: str, system_dir: Path, save_dir: Path) -> str:
    """The end of the installer's output, as a record keeps it. The scratch
    folders are written as the options that named them: a record read
    elsewhere has no use for the path of the machine that ran the probe."""
    text = stdout.replace(str(system_dir), "<dest>").replace(str(save_dir), "<save-dir>")
    return " ".join(text.split())[-400:]


def installer_layout(platform: str, pack: Path, identity: dict, manifest_path: Path,
                     root: Path, narrow: Sequence[str] = ()) -> Layout:
    """install.py --dest on a scratch root, from the pack, offline. The
    manifest is the published one, the file a user's installer reads.
    ``narrow`` passes install.py options such as --system, for the tests."""
    system_dir, save_dir = root / "system", root / "saves"
    if root.exists():
        shutil.rmtree(root)
    argv = [sys.executable, str(REPO_ROOT / "install.py"), "--platform", platform, "--dest", str(system_dir),
            "--save-dir", str(save_dir), "--from-pack", str(pack), "--manifest", str(manifest_path),
            "--offline", "--yes", "--quiet", *narrow]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=REPO_ROOT)
    if proc.returncode != 0 or not system_dir.is_dir():
        raise ProbeFailure(f"install.py exited {proc.returncode}: {(proc.stderr or proc.stdout)[-1500:]}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest_entries(manifest)
    files = {rel: entries.get(rel) for rel in walk(system_dir)}
    source = {
        "pack": identity,
        "manifest": {"path": manifest_path.relative_to(REPO_ROOT).as_posix() if manifest_path.is_relative_to(REPO_ROOT)
                     else manifest_path.name,
                     "sha256": file_digest(manifest_path, "sha256"),
                     "generated": manifest.get("generated"), "pack_files": manifest.get("pack_files")},
        "save_dir_files": len(walk(save_dir)) if save_dir.is_dir() else 0,
        "installer_summary": installer_summary(proc.stdout, system_dir, save_dir),
    }
    return Layout("installer", system_dir, files, source)


def build_pack(platform: str, out_dir: Path, narrow: Sequence[str] = ()) -> Path:
    """The platform's pack, built from this checkout as a release builds it.
    ``narrow`` passes generate_pack.py options such as --system, for the tests."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*_BIOS_Pack*.zip"):
        old.unlink()
    argv = [sys.executable, str(REPO_ROOT / "scripts" / "generate_pack.py"), "--platform", platform,
            "--offline", "--output-dir", str(out_dir), *narrow]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=REPO_ROOT)
    packs = sorted(p for p in out_dir.glob("*_BIOS_Pack*.zip") if ".part" not in p.name)
    if proc.returncode != 0 or len(packs) != 1:
        raise ProbeFailure(f"generate_pack.py exited {proc.returncode} with {len(packs)} packs: "
                           f"{proc.stderr[-1500:]}")
    return packs[0]
