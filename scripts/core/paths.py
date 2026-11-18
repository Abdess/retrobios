"""The repository root, and pack-relative destinations normalized the same way by every reader."""

from __future__ import annotations

from pathlib import Path

# The repository: scripts/core/ is two levels below it.
REPO_ROOT = Path(__file__).resolve().parents[2]
