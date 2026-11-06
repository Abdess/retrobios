"""A profile names each repository under the name its forge answers today.

GitHub follows a renamed or transferred repository's old name in silence:
flycast2021 declared libretro/flycast, which answers as libretro/parallel-dc,
and reicast declared reicast/reicast-emulator, which answers as
skmp/reicast-emulator. profile_sync counts such a move as review work. This
test reads the forge answers profile_sync has cached and fails on any
profile still declaring an old name. Without a cache it has nothing to read
and skips.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import upstream  # noqa: E402
from profile_sync import declared_repositories  # noqa: E402

CACHE = Path(upstream.CACHE_DIR)
if not CACHE.is_absolute():
    CACHE = REPO_ROOT / CACHE


class DeclaredRepositoriesAreCurrent(unittest.TestCase):
    def test_no_profile_declares_a_moved_repository(self) -> None:
        if not (CACHE / "_api").is_dir():
            self.skipTest("no forge answers cached")
        checked = 0
        moved = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for field, _key, url in declared_repositories(profile):
                repo = upstream.parse_repo(url)
                if repo is None:
                    continue
                current = upstream.current_slug(repo, str(CACHE), offline=True)
                if current is None:
                    continue
                checked += 1
                if current.lower() != repo.slug.lower():
                    moved.append(f"{path.stem} {field}: {repo.slug} answers as {current}")
        if not checked:
            self.skipTest("no declared repository has a cached forge answer")
        self.assertEqual(moved, [])


if __name__ == "__main__":
    unittest.main()
