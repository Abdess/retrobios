"""The README inside a pack sends files where the platform reads them.

RetroDECK's pack holds bios/ and roms/ at its root, and its guide said to
extract into ~/retrodeck/bios/, giving ~/retrodeck/bios/bios/. MiSTer and
ROCKNIX had no guide and were told "your BIOS directory", a folder MiSTer
does not have, while the registry names the path.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from packreadme import _build_readme  # noqa: E402


def _extract_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if "Extract all files" in line]


class GuidesPointAtTheReadPath(unittest.TestCase):
    def test_retrodeck_is_extracted_at_its_root(self):
        text = _build_readme("retrodeck", "RetroDECK", "", 1, 1)
        for line in _extract_lines(text):
            self.assertNotIn("retrodeck/bios", line)

    def test_unguided_platforms_name_the_registry_path(self):
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        for name, data in registry["platforms"].items():
            paths = [
                str(d.get("bios_path", ""))
                for d in (data.get("install", {}) or {}).get("detect", [])
            ]
            if not any(paths):
                continue
            text = _build_readme(name, name, "", 1, 1, bios_paths=paths)
            with self.subTest(platform=name):
                self.assertFalse(
                    any("your BIOS directory" in line for line in _extract_lines(text))
                )


if __name__ == "__main__":
    unittest.main()
