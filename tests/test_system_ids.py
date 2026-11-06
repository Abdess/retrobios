"""A machine has one system id in the profiles, and a file goes to its own.

picodrive filed the Mega CD as sega-segacd and fbneo the disk system as
nes-fds, where every other profile and every platform says sega-megacd and
nintendo-fds. On RomM, which keeps firmware per system folder, picodrive's
Mega CD BIOS went to gamegear/, the first of its systems, and fbneo's
channelf.zip and SNES DSP sets to colecovision/.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import SYSTEM_ALIASES, _norm_system_id, load_emulator_profiles  # noqa: E402
from packextras import _names_content, _slug_for  # noqa: E402


class ProfilesSpellEachMachineOnce(unittest.TestCase):
    def test_no_profile_uses_an_alias_spelling(self):
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        found = sorted(
            f"{name}: {sid}"
            for name, profile in profiles.items()
            for sid in [
                *profile.get("systems", []),
                *(f.get("system") for f in profile.get("files", []) if f.get("system")),
            ]
            if str(sid).lower() in SYSTEM_ALIASES
        )
        self.assertEqual(sorted(set(found)), [])


class PlatformNamesReachTheProfileSystem(unittest.TestCase):
    """Folder and system names a platform gives a machine, joined to the
    profile that runs it there. Each pair fell back to the whole profile in
    a survey of the rom folders of 38 setups, the two spellings not meeting
    once normalized."""

    # (name a platform uses, profile running it there)
    PAIRS = [
        ("apple-iigs", "mame"),
        ("apple2gs", "gsplus-legacy"),
        ("astrocde", "mame"),
        ("astrocade", "mame"),
        ("creativision", "mame"),
        ("gamepocketcomputer", "mame"),
        ("nintendo-sgb", "bsnes"),
        ("nintendo-sgb", "mesen-s"),
        ("capcom-cps1", "fbalpha2012_cps1"),
        ("capcom-cps2", "fbalpha2012_cps2"),
        ("capcom-cps3", "fbalpha2012_cps3"),
        ("capcom-cps1", "fbalpha2012"),
        ("igs-pgm", "fbalpha2012"),
    ]

    def test_each_name_meets_a_system_of_its_profile(self):
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        unmet = [
            f"{name} -> {emulator}"
            for name, emulator in self.PAIRS
            if _norm_system_id(name)
            not in {_norm_system_id(str(s)) for s in profiles[emulator].get("systems", [])}
        ]
        self.assertEqual(unmet, [])

    def test_both_spellings_normalize_alike(self):
        for alias, canonical in SYSTEM_ALIASES.items():
            with self.subTest(alias=alias):
                self.assertEqual(_norm_system_id(alias), _norm_system_id(canonical))

    def test_each_id_is_normalized_once(self):
        """A manifest run asked 1.7 million times for about a thousand ids,
        1.5 seconds of prefix loops: the answer is kept per id."""
        _norm_system_id.cache_clear()
        for _ in range(3):
            _norm_system_id("Nintendo_WiiU")
        info = _norm_system_id.cache_info()
        self.assertEqual((info.misses, info.hits), (1, 2))
        self.assertEqual(
            _norm_system_id("Nintendo_WiiU"), _norm_system_id.__wrapped__("Nintendo_WiiU")
        )


class AFoldedClaimKeepsItsProof(unittest.TestCase):
    """One spelling per machine folds bsnes-hd's SGB1.sfc onto bsnes's: the
    entry still pins the bytes, so it is placed before nSide's SGB1.sfc/
    tree and the file keeps its path."""

    def test_a_hash_on_a_folded_claim_counts(self):
        entry = {
            "name": "SGB1.sfc", "md5": None, "sha1": None,
            "other_claims": [{"name": "SGB1.sfc", "md5": "b15ddb15721c657d82c5bab6db982ee9"}],
        }
        self.assertTrue(_names_content(entry))

    def test_names_alone_name_no_content(self):
        self.assertFalse(_names_content({"name": "SGB1.sfc", "other_claims": [{"name": "SGB1.sfc"}]}))


class AFileGoesToItsOwnSystemFolder(unittest.TestCase):
    PROFILES = {"picodrive": {"systems": ["sega-game-gear", "sega-megacd"]}}
    SYSTEMS = {"sega-game-gear", "sega-mega-cd"}
    NORM = {"gamegear": "sega-game-gear", "megacd": "sega-mega-cd"}
    SLUGS = {"sega-game-gear": "gamegear", "sega-mega-cd": "segacd"}

    def slug(self, entry):
        return _slug_for(entry, self.PROFILES, self.SYSTEMS, self.NORM, self.SLUGS)

    def test_the_entry_system_decides(self):
        self.assertEqual(
            self.slug({"profile": "picodrive", "system": "sega-megacd"}), "segacd"
        )

    def test_without_one_the_emulator_systems_decide(self):
        self.assertEqual(self.slug({"profile": "picodrive"}), "gamegear")


if __name__ == "__main__":
    unittest.main()
