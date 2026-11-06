"""An export starts from the platform's own file, not from what we add to it.

load_platform_config folds _shared.yml groups into a platform for the pack,
the RomM scraper repeats tg16's firmware under turbografx-cd, and the
libretro scraper adds files it traced in the cores' source. None of them is
in the platform's file. The export counted them kept and wrote them into
libretro's System.dat (N88EXT0-3.ROM) as if libretro declared them.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

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
            _truth, native = load_inputs("demo", platforms / "truth", str(platforms))

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


class TheTruthDiffReadsTheSameLayer(unittest.TestCase):
    """diff_truth credited libretro with the files our scraper adds.

    Compared against the pack view, RetroArch's curated DSP ROMs, fonts and
    DSi files counted as declared by System.dat: 1008 missing instead of
    1016, while the export of the same input added them as missing.
    """

    def test_a_curated_file_is_missing_from_the_platform(self):
        import json  # noqa: PLC0415
        import subprocess  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=str(REPO_ROOT / "tmp")) as tmp:
            root = Path(tmp)
            (root / "demo.yml").write_text(
                "platform: Demo\nsystems:\n"
                "  nintendo-gamecube:\n    files:\n"
                "      - name: dsp_rom.bin\n        destination: dolphin-emu/Sys/GC/dsp_rom.bin\n"
                "        curated: true\n"
                "      - name: IPL.bin\n        destination: dolphin-emu/Sys/GC/USA/IPL.bin\n"
            )
            truth = root / "truth"
            truth.mkdir()
            (truth / "demo.yml").write_text(
                "systems:\n  nintendo-gamecube:\n    files:\n"
                "      - name: dsp_rom.bin\n        _cores: [dolphin]\n"
                "      - name: IPL.bin\n        _cores: [dolphin]\n"
            )
            proc = subprocess.run(
                [sys.executable, "scripts/diff_truth.py", "--platform", "demo", "--json",
                 "--platforms-dir", str(root), "--truth-dir", str(truth)],
                capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=300, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        (report,) = json.loads(proc.stdout)
        missing = [
            entry["name"]
            for system in report["divergences"].values()
            for entry in system.get("missing", [])
        ]
        self.assertEqual(missing, ["dsp_rom.bin"])

    def test_every_truth_diff_caller_reads_the_native_layer(self):
        """The site's platform-vs-source table answers the same question."""
        import re  # noqa: PLC0415

        for path in sorted((REPO_ROOT / "scripts").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(
                r"(?<!def )diff_platform_truth\(\s*[^,()]+,\s*(native_layer\(|\w+)", text
            ):
                scraped = match.group(1)
                with self.subTest(path=path.name):
                    self.assertTrue(
                        scraped == "native_layer("
                        or re.search(rf"\b{scraped} = native_layer\(", text),
                        f"{path.name}: diff_platform_truth reads {scraped}, the pack view",
                    )


if __name__ == "__main__":
    unittest.main()
