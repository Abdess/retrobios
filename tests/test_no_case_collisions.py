from __future__ import annotations

import os
import unittest
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BIOS_ROOT = REPO_ROOT / "bios"


class TestNoCaseCollisions(unittest.TestCase):
    """Guard against case-colliding paths in bios/.

    On case-insensitive filesystems (Windows, macOS default), git can only
    check out one path per casefold-equivalence class, silently corrupting
    clones. Issue #33 and #49 both stemmed from this.

    .variants/ subdirs are exempt: they intentionally hold genuine content
    variants disambiguated by hash suffix (e.g., BIOS.ROM.910fae67).
    """

    def test_bios_has_no_case_colliding_paths(self) -> None:
        if not BIOS_ROOT.is_dir():
            self.skipTest("bios/ directory not present")

        collisions: list[str] = []
        for root, dirs, files in os.walk(BIOS_ROOT):
            if ".variants" in Path(root).parts:
                continue

            dir_groups: dict[str, list[str]] = defaultdict(list)
            for d in dirs:
                dir_groups[d.casefold()].append(d)
            for variants in dir_groups.values():
                if len(variants) > 1:
                    rel = Path(root).relative_to(REPO_ROOT)
                    collisions.append(f"DIR  {rel}: {sorted(variants)}")

            file_groups: dict[str, list[str]] = defaultdict(list)
            for f in files:
                file_groups[f.casefold()].append(f)
            for variants in file_groups.values():
                if len(variants) > 1:
                    rel = Path(root).relative_to(REPO_ROOT)
                    collisions.append(f"FILE {rel}: {sorted(variants)}")

        self.assertEqual(
            collisions,
            [],
            "Case-colliding paths in bios/ would break Windows/macOS clones:\n"
            + "\n".join(collisions),
        )


if __name__ == "__main__":
    unittest.main()
