"""Files too large for the repository.

They live as release assets and are fetched at build time, verified
against the hash the caller declares."""

from __future__ import annotations

import os
import tempfile
import urllib.error
import urllib.request

from hashing import compute_hashes


LARGE_FILES_RELEASE = "large-files"

LARGE_FILES_RELEASE = "large-files"
LARGE_FILES_REPO = "Abdess/retrobios"

LARGE_FILES_REPO = "Abdess/retrobios"
LARGE_FILES_CACHE = ".cache/large"

def fetch_large_file(
    name: str,
    dest_dir: str = LARGE_FILES_CACHE,
    expected_sha1: str = "",
    expected_md5: str = "",
    *,
    offline: bool = False,
) -> str | None:
    """Return a verified cached large file, downloading it only when allowed."""
    cached = os.path.join(dest_dir, name)
    if os.path.exists(cached):
        if expected_sha1 or expected_md5:
            hashes = compute_hashes(cached)
            if expected_sha1 and hashes["sha1"].lower() != expected_sha1.lower():
                os.unlink(cached)
            elif expected_md5:
                md5_list = [
                    m.strip().lower() for m in expected_md5.split(",") if m.strip()
                ]
                if hashes["md5"].lower() not in md5_list:
                    os.unlink(cached)
                else:
                    return cached
            else:
                return cached
        else:
            return cached

    if offline:
        return None

    os.makedirs(dest_dir, exist_ok=True)
    # A per-process scratch name: two runs fetching the same asset into one
    # shared path interleave their writes into a full-size, corrupt file.
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=dest_dir, prefix=os.path.basename(cached) + ".", suffix=".tmp"
    )
    os.close(tmp_fd)
    # GitHub rewrites spaces to dots in release asset names, so a file whose
    # name contains spaces is published under a dotted name.
    candidates = [name]
    if " " in name:
        candidates.append(name.replace(" ", "."))

    downloaded = False
    for candidate in candidates:
        encoded_name = urllib.parse.quote(candidate)
        url = (
            f"https://github.com/{LARGE_FILES_REPO}/releases/download/"
            f"{LARGE_FILES_RELEASE}/{encoded_name}"
        )
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "retrobios/1.0"})
            with urllib.request.urlopen(req, timeout=300) as resp:
                with open(tmp_path, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
            downloaded = True
            break
        except (urllib.error.URLError, urllib.error.HTTPError):
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    if not downloaded:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return None

    if expected_sha1 or expected_md5:
        hashes = compute_hashes(tmp_path)
        if expected_sha1 and hashes["sha1"].lower() != expected_sha1.lower():
            os.unlink(tmp_path)
            return None
        if expected_md5:
            md5_list = [m.strip().lower() for m in expected_md5.split(",") if m.strip()]
            if hashes["md5"].lower() not in md5_list:
                os.unlink(tmp_path)
                return None
    os.replace(tmp_path, cached)
    return cached
