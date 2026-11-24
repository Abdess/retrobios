"""Where a fetched file is written: its bios/ folder, or the acquire folder when none is settled."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from core.hashing import parse_hash_list
from core.paths import REPO_ROOT
from resolve.review import placement

# Found files the collection has not placed yet, by sha1. Under the
# repository whatever the working directory: a run from another folder wrote
# them somewhere nobody looked.
ACQUIRE_DIR = REPO_ROOT / "tmp" / "acquire"


@dataclass(frozen=True)
class Placement:
    """Where a fetched file was written, and the folders that left it out of bios/."""

    path: str
    kept_out: bool = False
    folders: tuple[str, ...] = ()


def place_file(
    data: bytes, entry: dict, bios_dir: str, db: dict,
    platform_hashes: dict, profile_hashes: dict, acquire_dir: Path = ACQUIRE_DIR,
) -> Placement:
    """Write a fetched file where the review would accept it.

    The folder is resolve.review.placement()'s, the rule validate_pr and the
    wanted page read: a slug matched against folder names sent nintendo-ds
    to Nintendo/3DS and snk-neogeo to a new Unknown/ folder. A system whose
    folder is not settled leaves the file in acquire_dir, never in bios/.
    """
    name = os.path.basename(entry["name"])
    system = str(entry.get("system") or "")
    root = Path(bios_dir)

    def local(path: str) -> Path:
        # placement() speaks repository paths, bios/<Manufacturer>/...
        return root.joinpath(*path.rstrip("/").split("/")[1:])

    values = [
        *parse_hash_list(entry.get("sha1")),
        *parse_hash_list(entry.get("md5")),
        *parse_hash_list(entry.get("sha256")),
    ]
    spot = placement(
        values, name, db, platform_hashes, profile_hashes, declared=bool(values),
        systems=[system] if system else [], exists=lambda path: local(path).exists(),
    )
    folders: tuple[str, ...] = spot.folders or ((spot.home,) if spot.home else ())
    sha1 = hashlib.sha1(data).hexdigest()
    kept_out = len(folders) != 1
    if kept_out:
        dest = acquire_dir / sha1
    else:
        folder = local(folders[0])
        dest = folder / (spot.name or name)
        if dest.exists() and dest.read_bytes() != data:
            # Another revision under the same name: the collection keeps it
            # beside, never in place of, the file already there.
            dest = folder / ".variants" / f"{dest.name}.{hashlib.md5(data).hexdigest()[:8]}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return Placement(str(dest), kept_out, folders)


def keep_acquired(data: bytes, sha1: str, acquire_dir: Path | None = None) -> Path:
    """Write found bytes as <acquire_dir>/<sha1>, out of bios/: placing them is the collection's decision."""
    folder = acquire_dir or ACQUIRE_DIR
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / sha1
    out.write_bytes(data)
    return out
