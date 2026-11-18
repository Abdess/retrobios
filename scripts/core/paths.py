"""The repository root, and pack-relative destinations normalized the same way by every reader."""

from __future__ import annotations

from pathlib import Path


# The repository: scripts/core/ is two levels below it.
REPO_ROOT = Path(__file__).resolve().parents[2]


def sanitize_pack_path(raw: str) -> str:
    """Strip traversal components from a relative destination.

    The builder and the coverage report key their region grouping on this
    value, so they have to derive it the same way: a destination normalized on
    one side only would be looked up under a key the other side never emits.
    """
    raw = raw.replace("\\", "/")
    return "/".join(p for p in raw.split("/") if p and p not in ("..", "."))
