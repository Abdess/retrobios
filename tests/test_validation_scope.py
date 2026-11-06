"""The validation index only hears from the emulators the platform runs.

Built over every profile, ZEsarUX (standalone, a 48K cpc6128.rom) and ePSXe
judged RetroArch packs and the gaps page listed five hash mismatches with no
object. verify and the builder pass resolve_platform_cores' selection, and this
test fails if either hands the index the whole profile set again.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class ValidationIndexScope(unittest.TestCase):
    def test_no_index_over_every_profile(self):
        pattern = re.compile(r"_build_validation_index\(\s*(emu_)?profiles\s*\)")
        for name in ("verify.py", "generate_pack.py", "packverify.py", "packextras.py"):
            source = (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
            with self.subTest(module=name):
                self.assertIsNone(pattern.search(source))

    def test_platform_paths_select_by_platform_cores(self):
        verify = (REPO_ROOT / "scripts" / "verify.py").read_text(encoding="utf-8")
        builder = (REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertRegex(
            verify,
            r"plat_cores = resolve_platform_cores\(config, profiles\)\s+"
            r"platform_profiles = \{name: profiles\[name\] for name in plat_cores\}",
        )
        self.assertIn("validation_index = _build_validation_index(platform_profiles)", verify)
        self.assertRegex(
            builder,
            r"for name in resolve_platform_cores\(config, emu_profiles\)\s*\}\s*"
            r"validation_index = _build_validation_index\(platform_profiles\)",
        )


class HleIndexScope(unittest.TestCase):
    def test_hle_index_reads_the_platform_cores(self):
        verify = (REPO_ROOT / "scripts" / "verify.py").read_text(encoding="utf-8")
        start = verify.index("    hle_index = {")
        block = verify[start:verify.index("}", start)]
        self.assertIn("for profile in platform_profiles.values()", block)
        self.assertNotIn("profiles.values()", block.replace("platform_profiles.values()", ""))


class ContentFoundLabelsTakeTheirRegionSlot(unittest.TestCase):
    """rustation scans its folder by sha256, so its scph1001.bin entry is a
    label. ROCKNIX ships the v2.0 dump under that name, which rustation
    boots (labelled scph1001_v20.bin), and verify called it a mismatch."""

    def test_an_alternative_dump_passes_under_the_label(self):
        import hashlib
        import sys
        import tempfile

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from validation import _build_validation_index, check_file_validation

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scph1001.bin"
            path.write_bytes(b"v2.0")
            v20 = hashlib.sha256(b"v2.0").hexdigest()
            profile = {
                "found_by": "content",
                "systems": ["sony-playstation"],
                "files": [
                    {"name": "scph1001.bin", "region": ["north-america"],
                     "validation": ["sha256"], "sha256": "a" * 64},
                    {"name": "scph1001_v20.bin", "region": ["north-america"],
                     "validation": ["sha256"], "sha256": v20},
                    {"name": "scph5500.bin", "region": ["japan"],
                     "validation": ["sha256"], "sha256": "b" * 64},
                ],
            }
            index = _build_validation_index({"rustation": profile})
            self.assertIsNone(check_file_validation(str(path), "scph1001.bin", index))
            # Another region is another slot.
            self.assertIsNotNone(check_file_validation(str(path), "scph5500.bin", index))
            # A core that opens the file by name rejects it.
            index = _build_validation_index({"rustation": {**profile, "found_by": "name"}})
            self.assertIsNotNone(check_file_validation(str(path), "scph1001.bin", index))


if __name__ == "__main__":
    unittest.main()
