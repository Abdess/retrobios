"""A target keeps a system whose files an on-target core reads.

Batocera files the Enterprise under enterprise-64-128. ep128emu, the core
that reads ep128emu/roms/exos21.rom, declares enterprise-64 and
enterprise-128; only CLK carries the joined id. With a target that has
ep128emu and not CLK, the system was dropped from the report while the
builder still shipped its ROMs as ep128emu extras.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import filter_systems_by_target  # noqa: E402

PROFILES = {
    "ep128emu_core": {
        "type": "libretro",
        "systems": ["enterprise-64", "enterprise-128"],
        "files": [{"name": "exos21.rom", "path": "ep128emu/roms/exos21.rom"}],
    },
    "clk": {
        "type": "standalone",
        "systems": ["enterprise-64-128"],
        "files": [{"name": "exos10.bin", "path": "Enterprise/exos10.bin"}],
    },
    "generic": {
        "type": "libretro",
        "systems": ["other"],
        "files": [{"name": "bios.bin", "path": "bios.bin"}],
    },
}


def systems(*files: str) -> dict:
    return {"enterprise-64-128": {"files": [
        {"name": f.rsplit("/", 1)[-1], "destination": f} for f in files
    ]}}


class TargetSystems(unittest.TestCase):
    def kept(self, declared: dict) -> list[str]:
        return sorted(filter_systems_by_target(
            declared, PROFILES, {"ep128emu_core"},
            platform_cores={"ep128emu_core", "clk"},
        ))

    def test_a_core_reading_the_system_destination_keeps_it(self):
        self.assertEqual(self.kept(systems("ep128emu/roms/exos21.rom")), ["enterprise-64-128"])

    def test_without_that_evidence_the_off_target_core_drops_it(self):
        self.assertEqual(self.kept(systems("Enterprise/exos10.bin")), [])

    def test_a_path_an_off_target_core_reads_excludes_nothing(self):
        """Batocera's bbc runs on MAME, which no profile ties to bbcb.zip; CLK
        reads two of its ROMs. With CLK off the target the system stayed
        unknown before and must stay kept."""
        declared = {"bbc": {"files": [
            {"name": "os12.rom", "destination": "BBCMicro/os12.rom"},
            {"name": "bbcb.zip", "destination": "bbcb.zip"},
        ]}}
        profiles = dict(PROFILES)
        profiles["clk"] = dict(PROFILES["clk"], files=[
            {"name": "os12.rom", "path": "BBCMicro/os12.rom"}])
        self.assertEqual(
            sorted(filter_systems_by_target(
                declared, profiles, {"ep128emu_core"},
                platform_cores={"ep128emu_core", "clk"},
            )),
            ["bbc"],
        )

    def test_a_bare_name_is_no_evidence(self):
        declared = {"enterprise-64-128": {"files": [{"name": "bios.bin"}]}}
        self.assertEqual(
            sorted(filter_systems_by_target(
                declared, PROFILES, {"generic"},
                platform_cores={"generic", "clk"},
            )),
            [],
        )


if __name__ == "__main__":
    unittest.main()
