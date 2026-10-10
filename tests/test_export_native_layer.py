"""An export starts from the platform's own file, not from what we add to it.

load_platform_config folds _shared.yml groups into a platform for the pack,
the RomM scraper repeats tg16's firmware under turbografx-cd, and the
libretro scraper adds files it traced in the cores' source. None of them is
in the platform's file. The export counted them kept and wrote them into
libretro's System.dat (N88EXT0-3.ROM) as if libretro declared them.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
from export_native import load_inputs  # noqa: E402


class TheNativeLayerIsThePlatformsOwn(unittest.TestCase):
    def setUp(self):
        common._platform_config_cache.clear()
        common._shared_yml_cache.clear()
        self.addCleanup(common._platform_config_cache.clear)
        self.addCleanup(common._shared_yml_cache.clear)

    def test_shared_and_mirrored_entries_are_left_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            platforms = Path(tmp)
            (platforms / "_shared.yml").write_text(
                "shared_groups:\n  quasi88:\n"
                "    - name: N88EXT0.ROM\n      destination: quasi88/N88EXT0.ROM\n"
            )
            (platforms / "demo.yml").write_text(
                "platform: Demo\nsystems:\n"
                "  nec-pc-88:\n    includes: [quasi88]\n    files:\n"
                "      - name: n88.rom\n        destination: quasi88/n88.rom\n"
                "  tg16:\n    files:\n"
                "      - name: syscard3.pce\n        destination: tg16/syscard3.pce\n"
                "      - name: syscard3.pce\n        destination: turbografx-cd/syscard3.pce\n"
                "        mirror_of: tg16\n"
                "  nintendo-gamecube:\n    files:\n"
                "      - name: dsp_rom.bin\n        destination: dolphin-emu/Sys/GC/dsp_rom.bin\n"
                "        curated: true\n"
            )
            pack_view = common.load_platform_config("demo", str(platforms))
            _truth, native = load_inputs("demo", platforms, str(platforms))

        self.assertEqual(
            [f["name"] for f in pack_view["systems"]["nec-pc-88"]["files"]],
            ["n88.rom", "N88EXT0.ROM"],
        )
        self.assertEqual(
            [f["name"] for f in native["systems"]["nec-pc-88"]["files"]], ["n88.rom"]
        )
        self.assertEqual(
            [f["destination"] for f in native["systems"]["tg16"]["files"]],
            ["tg16/syscard3.pce"],
        )
        self.assertEqual(native["systems"]["nintendo-gamecube"]["files"], [])


if __name__ == "__main__":
    unittest.main()
