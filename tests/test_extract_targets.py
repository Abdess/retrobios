"""Where a pack extracts is read from the registry, by the README and the site.

Both kept a hand table keyed by display name. RomM's row said
`bios/{platform_slug}/` while the pack already carries one folder per slug
at its root, so following it nested every file one level too deep. The
README's RetroDECK sentence sat inside the archived-platforms block and
would have vanished the day RetroPie became active again.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import load_platform_config, load_platform_registry
from generate_readme import extract_notes, extract_targets

PLATFORMS = str(REPO_ROOT / "platforms")


class ExtractTargets(unittest.TestCase):
    def test_every_registered_platform_says_where_it_extracts(self):
        registry = load_platform_registry(PLATFORMS)
        missing = sorted(k for k, v in registry.items() if not v.get("extract_to"))
        self.assertEqual(missing, [])
        self.assertEqual(len(extract_targets(PLATFORMS)), len(registry))

    def test_a_folder_names_no_placeholder(self):
        """The pack lays out the per-system folders itself."""
        templated = [d for d, folder in extract_targets(PLATFORMS) if "{" in folder]
        self.assertEqual(templated, [])

    def test_a_pack_with_its_own_root_is_explained_whatever_is_archived(self):
        rooted = sorted(
            load_platform_config(key, PLATFORMS).get("platform", key)
            for key in load_platform_registry(PLATFORMS)
            if load_platform_config(key, PLATFORMS).get("base_destination") == ""
        )
        explained = sorted(
            display for display in rooted
            if any(note.startswith(f"The {display} pack") for note in extract_notes(PLATFORMS))
        )
        self.assertTrue(rooted)
        self.assertEqual(explained, rooted)

    def test_no_generator_keeps_its_own_table(self):
        """The which-pack page describes setups per OS; these two were the
        per-platform copies of the registry."""
        readme = (REPO_ROOT / "scripts" / "generate_readme.py").read_text(encoding="utf-8")
        site = (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        self.assertNotIn('"RetroDECK": "`~/retrodeck/`"', readme)
        self.assertNotIn('"    | RetroDECK | `~/retrodeck/` |"', site)


if __name__ == "__main__":
    unittest.main()
