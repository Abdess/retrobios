"""What git records for a collection file, and restoring its bytes from the blob in HEAD."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

from core.hashing import git_blob_sha


class GitFailed(RuntimeError):
    """A git command failed: its empty output says nothing about the file."""


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    """Run git in root. A failure raises: an unreadable index read as an empty
    status made a session's working change look unmodified, and --apply wrote
    HEAD's bytes over it."""
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    if done.returncode:
        message = done.stderr.decode(errors="replace").strip()
        raise GitFailed(f"git {' '.join(args)} exited {done.returncode}: {message}")
    return done


def head_blob(root: Path, path: str) -> str:
    """The blob HEAD records for path, empty when HEAD has none."""
    out = git(root, "ls-tree", "HEAD", "--", path).stdout.decode()
    parts = out.split()
    return parts[2] if len(parts) >= 3 and parts[1] == "blob" else ""


def modified_for_git(root: Path, path: str) -> bool:
    return bool(git(root, "status", "--porcelain", "--", path).stdout.strip())


def restore_from_blob(root: Path, path: str, blob: str, expected: str) -> str:
    """Write the blob's bytes over path, after checking them. Empty on success."""
    data = git(root, "cat-file", "blob", blob).stdout
    object_id = git_blob_sha(data)
    if object_id != blob:
        return f"blob read back as {object_id[:12]}, not {blob[:12]}"
    if hashlib.sha1(data).hexdigest() != expected:
        return "HEAD holds other bytes than database.json records"
    target = root / path
    handle, scratch = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
        os.chmod(scratch, target.stat().st_mode & 0o777)
        os.replace(scratch, target)
    except OSError:
        if os.path.exists(scratch):
            os.unlink(scratch)
        raise
    return ""
