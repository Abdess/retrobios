"""The validation index only hears from the emulators the platform runs.

Built over every profile, ZEsarUX (standalone, a 48K cpc6128.rom) and ePSXe
judged RetroArch packs and the gaps page listed five hash mismatches with no
object. verify and the builder pass resolve_platform_cores' selection; this
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
        start = verify.index("hle_index: dict[str, bool] = {}")
        self.assertIn("for profile in platform_profiles.values():", verify[start:start + 200])

if __name__ == "__main__":
    unittest.main()
