"""Extraction of a downloaded data directory archive into a local tree."""

from __future__ import annotations

import os
import shutil
import tarfile
import zipfile
from pathlib import Path

from core.ziptools import safe_extract_zip


def _is_safe_tar_member(member: tarfile.TarInfo, dest: Path) -> bool:
    """Reject path traversal, absolute paths, and symlinks in tar members."""
    if member.issym() or member.islnk():
        return False
    if member.name.startswith("/") or ".." in member.name.split("/"):
        return False
    resolved = (dest / member.name).resolve()
    dest_str = str(dest.resolve()) + os.sep
    return str(resolved).startswith(dest_str) or str(resolved) == str(dest.resolve())


def extract_tar_subtree(
    archive_path: Path, extract_dir: Path, source_path: str, exclude: list[str],
) -> tuple[int, list[str]]:
    """Write the files under source_path of a gzipped tarball to extract_dir,
    paths relative to source_path, top directories in exclude left out.

    Returns the number of files written and the unsafe members skipped.
    """
    prefix = source_path.rstrip("/") + "/"
    file_count = 0
    skipped: list[str] = []
    with tarfile.open(archive_path, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.name.startswith(prefix) and member.name != source_path:
                continue
            rel = member.name[len(prefix) :]
            if not rel or rel.split("/")[0] in exclude:
                continue
            if not _is_safe_tar_member(member, extract_dir):
                skipped.append(member.name)
                continue
            if member.isdir():
                (extract_dir / rel).mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                dest_file = extract_dir / rel
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    continue
                with src, open(dest_file, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                file_count += 1
    return file_count, skipped


def extract_zip_tree(
    archive_path: Path, extract_dir: Path, exclude: list[str], strip_components: int = 0,
) -> int:
    """Write the files of a ZIP to extract_dir under core.ziptools' limits.

    strip_components removes N leading path components from each entry
    (like tar --strip-components), then top directories in exclude are left
    out. Returns the number of files written.
    """

    def select(info: zipfile.ZipInfo, parts: list[str]) -> list[str] | None:
        if info.is_dir():
            return None
        if strip_components > 0:
            if len(parts) <= strip_components:
                return None
            parts = parts[strip_components:]
        if (parts[0] if parts else "") in exclude:
            return None
        return parts

    return safe_extract_zip(str(archive_path), str(extract_dir), select=select)
