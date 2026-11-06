"""Slot arbitration: who decides what goes at a destination."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import slots  # noqa: E402
from slots import Claim, Conflict, arbitrate, format_decision  # noqa: E402


def _db(entries: dict[str, dict]) -> dict:
    """Minimal database shaped like the generated one, keyed by sha1.

    The resolver reads the disk before it answers, so the fixture writes the
    files it indexes and the caller runs from the directory holding them.
    """
    files, by_md5, by_name, by_path_suffix = {}, {}, {}, {}
    for sha1, info in entries.items():
        path = info["path"]
        name = path.rsplit("/", 1)[-1]
        files[sha1] = {
            "path": path,
            "md5": info.get("md5", ""),
            "name": name,
            "crc32": info.get("crc32", ""),
            "size": info.get("size", 0),
            "sha1": sha1,
        }
        if info.get("md5"):
            by_md5[info["md5"]] = sha1
        by_name.setdefault(name, []).append(sha1)
        parts = path.split("/")
        for depth in range(1, len(parts)):
            by_path_suffix.setdefault("/".join(parts[-depth:]), []).append(sha1)
    return {
        "files": files,
        "indexes": {
            "by_md5": by_md5,
            "by_name": by_name,
            "by_crc32": {},
            "by_path_suffix": by_path_suffix,
        },
    }


_ROOT = Path(tempfile.mkdtemp(prefix="slots-"))
_ENTRIES = {
    "a" * 40: {"path": "bios/Console/GC/USA/IPL.bin", "md5": "m" * 32, "size": 3},
    "b" * 40: {"path": "bios/Console/GC/JAP/IPL.bin", "md5": "n" * 32, "size": 3},
}
for _info in _ENTRIES.values():
    _target = _ROOT / _info["path"]
    _target.parent.mkdir(parents=True, exist_ok=True)
    _target.write_bytes(b"rom")

REGIONS_DB = _db(_ENTRIES)


def setUpModule():
    global _PREVIOUS_CWD
    _PREVIOUS_CWD = os.getcwd()
    os.chdir(_ROOT)


def tearDownModule():
    os.chdir(_PREVIOUS_CWD)
    shutil.rmtree(_ROOT, ignore_errors=True)


class TestConflicts(unittest.TestCase):
    """A proven profile claim contradicting what the baseline would ship."""

    def _config(self, md5: str) -> dict:
        return {
            "systems": {
                "console": {
                    "files": [
                        {
                            "name": "IPL.bin",
                            "destination": "GC/JAP/IPL.bin",
                            "md5": md5,
                        }
                    ]
                }
            }
        }

    def _profile(self, *paths: str) -> dict:
        return {
            "dolphin": {
                "files": [{"name": "IPL.bin", "path": p} for p in paths]
            }
        }

    def test_a_core_claim_sits_where_the_pack_puts_it(self):
        """RetroDECK writes bios/ into every destination and leaves its base
        empty, so core files go under bios/ too. Claimed at the root, they never
        met the platform's and four contradictions went unreported."""
        config = {"base_destination": "", "systems": {"console": {"files": [
            {"name": "IPL.bin", "destination": "bios/GC/JAP/IPL.bin", "md5": "m" * 32},
            {"name": "other.bin", "destination": "bios/other.bin"},
        ]}}}
        conflicts = slots.find_conflicts(config, self._profile("GC/JAP/IPL.bin"), REGIONS_DB)
        self.assertEqual([c.destination for c in conflicts], ["bios/GC/JAP/IPL.bin"])

    def test_a_core_found_by_content_takes_any_dump_it_accepts(self):
        """DuckStation identifies its BIOS by content, so the name of its
        scph1001.bin entry is a label. Batocera ships the v2.0 dump there,
        which the profile accepts under scph1001_v20.bin: no conflict."""
        files = [
            {"name": "IPL.bin", "path": "GC/JAP/IPL.bin", "md5": "n" * 32,
             "region": ["japan"]},
            {"name": "IPL_alt.bin", "md5": "m" * 32, "region": ["japan"]},
        ]
        by_name = slots.find_conflicts(
            self._config("m" * 32), {"dolphin": {"files": files}}, REGIONS_DB
        )
        self.assertEqual(len(by_name), 1)
        by_content = slots.find_conflicts(
            self._config("m" * 32),
            {"dolphin": {"found_by": "content", "files": files}},
            REGIONS_DB,
        )
        self.assertEqual(by_content, [])
        # Another region is another slot: openMSX finds each ROM by sha1 too,
        # and one machine's ROM never stands for another's.
        files[1]["region"] = ["north-america"]
        other_slot = slots.find_conflicts(
            self._config("m" * 32),
            {"dolphin": {"found_by": "content", "files": files}},
            REGIONS_DB,
        )
        self.assertEqual(len(other_slot), 1)

    def test_wrong_region_under_a_region_slot_is_reported(self):
        conflicts = slots.find_conflicts(
            self._config("m" * 32), self._profile("GC/JAP/IPL.bin"), REGIONS_DB
        )
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].destination, "GC/JAP/IPL.bin")
        self.assertTrue(conflicts[0].platform_claim.local_path.endswith("USA/IPL.bin"))
        self.assertTrue(
            conflicts[0].profile_claims[0].local_path.endswith("JAP/IPL.bin")
        )
        self.assertEqual(conflicts[0].emulators, ["dolphin"])

    def test_agreement_is_not_a_conflict(self):
        conflicts = slots.find_conflicts(
            self._config("n" * 32), self._profile("GC/JAP/IPL.bin"), REGIONS_DB
        )
        self.assertEqual(conflicts, [])

    def test_one_matching_revision_among_several_settles_the_slot(self):
        # A profile listing every acceptable revision agrees with the platform
        # as soon as one of them is what ships.
        profile = {
            "dosbox": {
                "files": [
                    {"name": "IPL.bin", "path": "GC/JAP/IPL.bin", "md5": "n" * 32},
                    {"name": "IPL.bin", "path": "GC/JAP/IPL.bin", "md5": "m" * 32},
                ]
            }
        }
        conflicts = slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB)
        self.assertEqual(conflicts, [])

    def test_a_platform_list_naming_the_profile_file_is_agreement(self):
        """Recalbox names both scph1001.bin revisions. The resolver stops on
        the first, the profile pins the other, and --strict reported a
        contradiction nobody has to correct."""
        conflicts = slots.find_conflicts(
            self._config(f"{'m' * 32},{'n' * 32}"),
            self._profile("GC/JAP/IPL.bin"),
            REGIONS_DB,
        )
        self.assertEqual(conflicts, [])

    def test_a_profile_list_naming_the_shipped_file_is_agreement(self):
        """mesence accepts four BS-X dumps, one of which System.dat pins;
        the slot read as contested and the pack swapped the catalogued
        dump for an uncatalogued one."""
        profile = {
            "mesence": {
                "files": [
                    {"name": "IPL.bin", "path": "GC/JAP/IPL.bin",
                     "md5": [ "n" * 32, "m" * 32 ]},
                ]
            }
        }
        conflicts = slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB)
        self.assertEqual(conflicts, [])

    def test_an_entry_the_pack_never_carries_claims_nothing(self):
        """A file read from the save directory, declared with the sha1 of
        another dump, arbitrated the platform's file off its own path."""
        profile = {
            "core": {
                "files": [
                    {"name": "IPL.bin", "path": "GC/JAP/IPL.bin", "md5": "n" * 32,
                     "load_from": "save_dir"},
                ]
            }
        }
        conflicts = slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB)
        self.assertEqual(conflicts, [])

    def test_a_name_only_resolution_asserts_nothing(self):
        # No hash and no path that the repository carries: the entry is
        # answered by filename alone and cannot contradict anything.
        config = {
            "systems": {
                "console": {
                    "files": [{"name": "IPL.bin", "destination": "slot/IPL.bin"}]
                }
            }
        }
        profile = {"dolphin": {"files": [{"name": "IPL.bin", "path": "slot/IPL.bin"}]}}
        self.assertEqual(slots.find_conflicts(config, profile, REGIONS_DB), [])

    def test_a_bare_sibling_met_first_does_not_hide_the_contradiction(self):
        """RetroArch declares dsi_bios7.bin bare under one system and with a
        hash under another. The pack ships the hashed one, so the slot is
        judged on it, whichever system is read first."""
        config = {
            "systems": {
                "a-console": {"files": [{"name": "IPL.bin", "destination": "GC/JAP/IPL.bin"}]},
                "b-console": {"files": [
                    {"name": "IPL.bin", "destination": "GC/JAP/IPL.bin", "md5": "m" * 32}]},
            }
        }
        conflicts = slots.find_conflicts(config, self._profile("GC/JAP/IPL.bin"), REGIONS_DB)
        self.assertEqual([c.destination for c in conflicts], ["GC/JAP/IPL.bin"])

    def test_launchers_and_aliases_never_claim(self):
        profile = {
            "launcher": {
                "type": "launcher",
                "files": [{"name": "IPL.bin", "path": "GC/JAP/IPL.bin"}],
            }
        }
        self.assertEqual(
            slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB), []
        )

    def test_the_arbitration_reads_the_same_evidence_as_the_builder(self):
        """A verdict decided on less evidence than its consumers apply.

        slots resolved without the ZIP index and without the data-directory
        registry, while generate_pack and verify pass both, so an entry only
        a ZIP member or a data directory can satisfy looked unproven here and
        proven there.
        """
        import inspect

        import generate_pack
        import verify

        for function in (
            slots.platform_claims,
            slots.profile_claims,
            slots.find_conflicts,
            slots.find_collisions,
        ):
            parameters = inspect.signature(function).parameters
            with self.subTest(function=function.__name__):
                self.assertIn("zip_contents", parameters)
                self.assertIn("data_dir_registry", parameters)

        parameters = inspect.signature(slots.pack_overrides).parameters
        self.assertIn("zip_contents", parameters)
        self.assertIn("data_dir_registry", parameters)

        # Every consumer reads the one decision and hands its indexes over:
        # the ZIP builder, the install manifest and the report. The manifest
        # deciding nothing gave the installer other bytes than the ZIP.
        for module, calls in ((generate_pack, 2), (verify, 1)):
            source = inspect.getsource(module)
            with self.subTest(module=module.__name__):
                self.assertNotIn("slots.arbitrate(", source)
                self.assertNotIn("slots.find_conflicts(", source)
                self.assertEqual(source.count("slots.pack_overrides("), calls)
                for start in range(len(source)):
                    start = source.find("slots.pack_overrides(", start)
                    if start < 0:
                        break
                    self.assertIn("zip_contents", source[start:start + 200])
                    start += 1

    def test_a_rom_inside_a_romset_claims_nothing_of_its_own(self):
        """The archive occupies the destination, not the ROM it holds.

        FBNeo declares msx.rom and kanji.rom with archive: msx.zip and no
        path, so the member was claimed at the platform's BIOS root and
        contradicted whatever really lives there.
        """
        profile = {
            "fbneo": {
                "type": "libretro",
                "files": [
                    {"name": "IPL.bin", "archive": "romset.zip"},
                ],
            }
        }
        self.assertEqual(
            slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB), []
        )
        self.assertEqual(slots.profile_claims(profile, REGIONS_DB), [])

    def test_a_filename_agnostic_profile_claims_nothing(self):
        """The gap report skips a `bios_mode: agnostic` profile whole: the
        builder carries its scan candidates, never its named entries.
        ARMSX2's GameIndex.yaml replaced the one RetroArch declares."""
        profile = self._profile("GC/JAP/IPL.bin")
        self.assertTrue(
            slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB)
        )
        profile["dolphin"]["bios_mode"] = "agnostic"
        self.assertEqual(slots.profile_claims(profile, REGIONS_DB), [])
        self.assertEqual(
            slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB), []
        )

    def test_base_destination_prefixes_both_sides(self):
        conflicts = slots.find_conflicts(
            self._config("m" * 32),
            self._profile("GC/JAP/IPL.bin"),
            REGIONS_DB,
            base_dest="bios",
        )
        self.assertEqual(conflicts[0].destination, "bios/GC/JAP/IPL.bin")

    def test_report_line_names_both_answers(self):
        conflicts = slots.find_conflicts(
            self._config("m" * 32), self._profile("GC/JAP/IPL.bin"), REGIONS_DB
        )
        line = slots.format_conflict(conflicts[0])
        self.assertIn("USA/IPL.bin", line)
        self.assertIn("JAP/IPL.bin", line)
        self.assertIn("dolphin", line)


class TestArbitration(unittest.TestCase):
    """A pack answers to whoever asked for it, and serves both when it can."""

    def _conflict(self):
        platform = slots.Claim(
            "platform", "GC/JAP/IPL.bin", "IPL.bin",
            entry={"md5": "m" * 32, "sha1": "a" * 40},
            local_path="bios/Console/GC/USA/IPL.bin", status="md5_exact",
        )
        profile = slots.Claim(
            "profile", "GC/JAP/IPL.bin", "IPL.bin", emulator="dolphin",
            local_path="bios/Console/GC/JAP/IPL.bin", status="path_exact",
        )
        return slots.Conflict("GC/JAP/IPL.bin", platform, [profile])

    def test_existence_mode_serves_both(self):
        decision = slots.arbitrate(self._conflict(), "existence")
        self.assertEqual(decision.winner.origin, "profile")
        self.assertTrue(decision.serves_both)

    def test_md5_mode_keeps_the_frontend_green(self):
        decision = slots.arbitrate(self._conflict(), "md5")
        self.assertEqual(decision.winner.origin, "platform")
        self.assertFalse(decision.serves_both)

    def test_sha1_mode_is_content_checking_too(self):
        decision = slots.arbitrate(self._conflict(), "sha1")
        self.assertEqual(decision.winner.origin, "platform")

    def test_an_emulator_pack_answers_to_the_emulator(self):
        decision = slots.arbitrate(self._conflict(), "md5", addressee="emulator")
        self.assertEqual(decision.winner.origin, "profile")
        self.assertFalse(decision.serves_both)

    def test_a_hashless_entry_is_a_path_in_an_md5_platform(self):
        """EmuDeck declares neocdz.zip with no md5 and checkBIOS.sh never
        names it: the frontend checks nothing there, so the core's file
        serves both."""
        conflict = self._conflict()
        conflict.platform_claim.entry = {"name": "IPL.bin"}
        for mode in ("md5", "sha1"):
            with self.subTest(mode=mode):
                self.assertTrue(slots.arbitrate(conflict, mode).serves_both)
        # RomM compares size then any hash: a hash of another kind is content.
        conflict.platform_claim.entry = {"name": "IPL.bin", "sha1": "a" * 40, "size": 3}
        self.assertFalse(
            slots.arbitrate(conflict, "md5", rule="size_and_any_hash").serves_both
        )
        conflict.platform_claim.entry = {"name": "x.zip", "zipped_file": "IPL.bin"}
        self.assertFalse(slots.arbitrate(conflict, "md5").serves_both)

    def test_the_pack_serves_the_proven_file_at_a_hashless_md5_entry(self):
        config = {
            "verification_mode": "md5",
            "cores": ["dolphin"],
            "systems": {"console": {"files": [
                {"name": "IPL.bin", "destination": "IPL.bin"},
                {"name": "IPL.bin", "destination": "hashed/IPL.bin", "md5": "m" * 32},
            ]}},
        }
        profiles = {"dolphin": {"type": "libretro", "systems": ["console"], "files": [
            {"name": "IPL.bin", "md5": "n" * 32},
            {"name": "IPL.bin", "path": "hashed/IPL.bin", "md5": "n" * 32},
        ]}}
        overrides = slots.pack_overrides(config, profiles, REGIONS_DB)
        # The hashed declaration keeps the file the frontend checks.
        self.assertEqual(overrides, {"IPL.bin": "bios/Console/GC/JAP/IPL.bin"})

    def test_the_report_and_the_pack_decide_alike(self):
        """The report prints arbitrate(), the pack, the manifest and verify
        read slot_choices(): both must name the same file for a slot."""
        for mode in ("existence", "md5"):
            config = {
                "verification_mode": mode,
                "cores": ["dolphin"],
                "systems": {"console": {"files": [
                    {"name": "IPL.bin", "destination": "GC/JAP/IPL.bin", "md5": "m" * 32},
                ]}},
            }
            profiles = {"dolphin": {"type": "libretro", "systems": ["console"], "files": [
                {"name": "IPL.bin", "path": "GC/JAP/IPL.bin"},
            ]}}
            with self.subTest(mode=mode):
                [conflict] = slots.find_conflicts(config, profiles, REGIONS_DB)
                decision = slots.arbitrate(conflict, mode)
                served = slots.pack_overrides(config, profiles, REGIONS_DB).get(
                    "GC/JAP/IPL.bin", conflict.platform_claim.local_path
                )
                self.assertEqual(served, decision.winner.local_path)

    def test_the_reported_line_gives_the_ground_for_the_decision(self):
        kept = slots.format_decision(slots.arbitrate(self._conflict(), "md5"))
        self.assertIn("verifies content", kept)
        # A fact about each layer, no verdict on the platform's list.
        self.assertIn("the file dolphin reads", kept)
        self.assertNotIn("wrong", slots.__loader__.get_source("slots").lower())
        served = slots.format_decision(slots.arbitrate(self._conflict(), "existence"))
        self.assertIn("both are satisfied", served)

    def test_each_emulator_is_given_the_file_it_reads(self):
        """Recalbox's neocdz.zip line said geolith reads the archive fbneo
        reads, while geolith pins another one."""
        conflict = self._conflict()
        conflict.profile_claims = [
            slots.Claim("profile", "neocdz.zip", "neocdz.zip", emulator="fbneo",
                        local_path="a/neocdz.zip.ba20a7be", status="members_held"),
            slots.Claim("profile", "neocdz.zip", "neocdz.zip", emulator="geolith",
                        local_path="b/neocdz.zip.712816a3", status="md5_exact"),
        ]
        kept = slots.format_decision(slots.arbitrate(conflict, "md5"))
        self.assertIn("a/neocdz.zip.ba20a7be, the file fbneo reads", kept)
        self.assertIn("b/neocdz.zip.712816a3, the file geolith reads", kept)
        self.assertEqual(conflict.files_read(), [
            ("a/neocdz.zip.ba20a7be", ["fbneo"], "members_held"),
            ("b/neocdz.zip.712816a3", ["geolith"], "md5_exact"),
        ])


class TheStrongestProofTakesAnUndeclaredPath(unittest.TestCase):
    """No platform declares RetroDECK's hiscore.dat. fbalpha2012 asks for it
    by name, mame2015 pins it by sha1: the first in profile order took the
    path, whatever the proof, and mame2015 received another revision."""

    def test_a_held_hash_beats_a_bare_name_whatever_the_order(self):
        from packextras import _collect_emulator_extras

        config = {
            "platform": "P", "verification_mode": "existence",
            "cores": ["aaa", "zzz"],
            "systems": {"console": {"files": [{"name": "other.bin", "destination": "other.bin"}]}},
        }
        profiles = {
            "aaa": {"emulator": "Aaa", "type": "libretro", "systems": ["console"],
                    "files": [{"name": "IPL.bin", "required": True}]},
            "zzz": {"emulator": "Zzz", "type": "libretro", "systems": ["console"],
                    "files": [{"name": "IPL.bin", "required": True, "md5": "n" * 32}]},
        }
        extras = _collect_emulator_extras(config, "", REGIONS_DB, set(), "", profiles)
        winner = next(e for e in extras if e["destination"] == "IPL.bin")
        self.assertEqual(winner["source_profile"], "zzz")
        self.assertEqual({c["source_profile"] for c in winner["other_claims"]}, {"aaa"})


class TestBuilderAndVerifierAgree(unittest.TestCase):
    """The two tools must settle a contested destination the same way."""

    def test_both_read_the_same_decision_function(self):
        # The rule lives in one place. A second copy would let the pack and the
        # report describe different files, which the project forbids outright.
        builder = Path(__file__).resolve().parents[1] / "scripts" / "generate_pack.py"
        verifier = Path(__file__).resolve().parents[1] / "scripts" / "verify.py"
        for source in (builder, verifier):
            text = source.read_text(encoding="utf-8")
            self.assertIn("slots.pack_overrides(", text, source.name)
            self.assertNotIn("decision.serves_both", text, source.name)
        self.assertIn(
            "decision.serves_both",
            (builder.parent / "slots.py").read_text(encoding="utf-8"),
        )

    def test_neither_reimplements_the_mode_test(self):
        # A local "if mode == md5" beside the override would drift from the
        # arbitration rule the moment either side is edited. The anchor is the
        # override lookup both sides must perform. The old anchor was a string
        # the test above forbids, so the window was the whole file.
        mode_test = re.compile(r"""[=!]=\s*["'](?:md5|sha1|existence)["']""")
        for name in ("generate_pack.py", "verify.py"):
            source = Path(__file__).resolve().parents[1] / "scripts" / name
            body = source.read_text(encoding="utf-8")
            anchors = [m.start() for m in re.finditer(r"slot_overrides\.get\(", body)]
            self.assertTrue(anchors, name)
            for at in anchors:
                window = body[max(0, at - 600):at + 600]
                self.assertIsNone(mode_test.search(window), name)


class TestSelfContradictingDestinations(unittest.TestCase):
    """One path holds one file, whatever the upstream list says."""

    def _config(self, *entries: dict) -> dict:
        return {"systems": {"console": {"files": list(entries)}}}

    def test_two_declarations_landing_on_two_files_are_reported(self):
        config = self._config(
            {"name": "IPL.bin", "destination": "disk.rom", "md5": "m" * 32},
            {"name": "IPL.bin", "destination": "disk.rom", "md5": "n" * 32},
        )
        collisions = slots.find_collisions(config, REGIONS_DB)
        self.assertEqual(len(collisions), 1)
        self.assertEqual(len(collisions[0].resolved), 2)

    def test_the_line_names_each_system_and_the_file_packed(self):
        """The line named two files and neither the system that declares
        each nor the one the pack ships: the reader went to the YAML."""
        config = {"systems": {
            "zeta": {"files": [{"name": "IPL.bin", "destination": "disk.rom",
                                "md5": "m" * 32}]},
            "alpha": {"files": [{"name": "IPL.bin", "destination": "disk.rom",
                                 "md5": "n" * 32}]},
        }}
        collision = slots.find_collisions(config, REGIONS_DB)[0]
        line = slots.format_collision(collision)
        left, packed = collision.resolved
        # The builder walks the systems sorted: alpha's declaration ships.
        self.assertIn(f"{packed} (alpha) packed", line)
        self.assertIn(f"{left} (zeta) left out", line)
        self.assertEqual(collision.shipped, packed)

    def test_one_archive_named_by_its_inner_roms_is_not_a_collision(self):
        # The documented zipped_file pattern: several md5s, one archive.
        config = self._config(
            {"name": "IPL.bin", "destination": "a.zip", "md5": "m" * 32,
             "zipped_file": "one.bin"},
            {"name": "IPL.bin", "destination": "a.zip", "md5": "m" * 32,
             "zipped_file": "two.bin"},
        )
        self.assertEqual(slots.find_collisions(config, REGIONS_DB), [])

    def test_a_file_both_declarations_accept_settles_the_path(self):
        """RetroDECK: ATARIOSB.ROM under one system with one md5, under
        another with a list naming that same md5. The shipped file passes
        both, so --strict has nothing to correct there."""
        config = self._config(
            {"name": "IPL.bin", "destination": "disk.rom", "md5": "m" * 32},
            {"name": "IPL.bin", "destination": "disk.rom",
             "md5": f"{'n' * 32},{'m' * 32}"},
        )
        self.assertEqual(slots.find_collisions(config, REGIONS_DB), [])

    def test_a_primary_and_its_pinned_variant_are_one_family(self):
        self.assertTrue(
            slots._same_file_family(
                ["bios/M/C/rom.zip", "bios/M/C/.variants/rom.zip.abcd1234"]
            )
        )

    def test_a_variant_kept_under_its_plain_name_is_one_family(self):
        # 63 variants carry no hash suffix, aes.zip among them.
        self.assertTrue(
            slots._same_file_family(
                ["bios/SNK/Neo Geo/aes.zip", "bios/SNK/Neo Geo/.variants/aes.zip"]
            )
        )

    def test_only_a_hash_suffix_is_stripped(self):
        self.assertFalse(
            slots._same_file_family(
                ["bios/M/C/rom.zip", "bios/M/C/.variants/rom.zip.zip"]
            )
        )

    def test_the_database_and_the_arbiter_read_one_rule(self):
        import generate_db  # noqa: PLC0415

        variant = Path("bios/M/C/.variants/aes.zip")
        self.assertEqual(generate_db._canonical_name(variant), "aes.zip")
        for module in ("slots.py", "generate_db.py"):
            source = (Path(__file__).resolve().parents[1] / "scripts" / module).read_text()
            with self.subTest(module=module):
                self.assertIn("variant_base_name(", source)
                self.assertNotIn('rsplit(".", 1)[0]', source)

    def test_two_machines_are_not_one_family(self):
        self.assertFalse(
            slots._same_file_family(
                ["bios/Microsoft/MSX/DISK.ROM", "bios/Tandy/CoCo/disk.rom"]
            )
        )

    def test_a_destination_declared_once_is_never_a_collision(self):
        config = self._config(
            {"name": "IPL.bin", "destination": "disk.rom", "md5": "m" * 32}
        )
        self.assertEqual(slots.find_collisions(config, REGIONS_DB), [])

    def test_the_line_names_every_file_claiming_the_path(self):
        config = self._config(
            {"name": "IPL.bin", "destination": "disk.rom", "md5": "m" * 32},
            {"name": "IPL.bin", "destination": "disk.rom", "md5": "n" * 32},
        )
        line = slots.format_collision(slots.find_collisions(config, REGIONS_DB)[0])
        self.assertIn("USA/IPL.bin", line)
        self.assertIn("JAP/IPL.bin", line)


class TestBuildModeDecidesWhoClaims(unittest.TestCase):
    """A platform runs some emulators as cores and others standalone."""

    def _config(self, standalone=None) -> dict:
        config = {
            "systems": {
                "console": {
                    "files": [
                        {"name": "IPL.bin", "destination": "GC/JAP/IPL.bin",
                         "md5": "m" * 32}
                    ]
                }
            }
        }
        if standalone:
            config["standalone_cores"] = standalone
        return config

    def _profile(self, mode=None, standalone_path=None) -> dict:
        entry = {"name": "IPL.bin", "path": "GC/JAP/IPL.bin"}
        if mode:
            entry["mode"] = mode
        if standalone_path:
            entry["standalone_path"] = standalone_path
        return {"ares": {"type": "standalone + libretro", "cores": ["ares"],
                         "files": [entry]}}

    def test_a_standalone_only_file_does_not_claim_a_core_slot(self):
        conflicts = slots.find_conflicts(
            self._config(), self._profile(mode="standalone"), REGIONS_DB
        )
        self.assertEqual(conflicts, [])

    def test_it_claims_when_the_platform_runs_that_emulator_standalone(self):
        conflicts = slots.find_conflicts(
            self._config(standalone=["ares"]),
            self._profile(mode="standalone"),
            REGIONS_DB,
            standalone_cores={"ares"},
        )
        self.assertEqual(len(conflicts), 1)

    def test_a_libretro_only_file_is_silent_in_standalone_mode(self):
        conflicts = slots.find_conflicts(
            self._config(standalone=["ares"]),
            self._profile(mode="libretro"),
            REGIONS_DB,
            standalone_cores={"ares"},
        )
        self.assertEqual(conflicts, [])

    def test_standalone_mode_reads_the_standalone_destination(self):
        claims = slots.profile_claims(
            self._profile(standalone_path="elsewhere/IPL.bin"),
            REGIONS_DB,
            standalone_cores={"ares"},
        )
        self.assertEqual(claims[0].destination, "elsewhere/IPL.bin")

    def test_the_mode_follows_a_core_alias_not_only_the_profile_name(self):
        profile = {"ares_core": {"type": "standalone + libretro",
                                 "cores": ["ares"],
                                 "files": [{"name": "IPL.bin",
                                            "path": "GC/JAP/IPL.bin",
                                            "mode": "standalone"}]}}
        conflicts = slots.find_conflicts(
            self._config(standalone=["ares"]), profile, REGIONS_DB,
            standalone_cores={"ares"},
        )
        self.assertEqual(len(conflicts), 1)

    def test_a_profile_without_a_standalone_build_keeps_its_core_layout(self):
        profile = {"ares": {"type": "libretro", "cores": ["ares"],
                            "files": [{"name": "IPL.bin",
                                       "path": "GC/JAP/IPL.bin",
                                       "standalone_path": "elsewhere/IPL.bin"}]}}
        claims = slots.profile_claims(
            profile, REGIONS_DB, standalone_cores={"ares"}
        )
        self.assertEqual(claims[0].destination, "GC/JAP/IPL.bin")


class TestProvenEvidence(unittest.TestCase):
    """What counts as proof that a claim is about content, not about a name."""

    def test_hash_evidence_is_proof(self):
        self.assertTrue(slots.Claim("profile", "d", "n", status="sha1_exact").is_proven)
        self.assertTrue(slots.Claim("profile", "d", "n", status="md5_exact").is_proven)

    def test_path_evidence_is_proof(self):
        # Dolphin declares no checksum for the GameCube boot ROM because its
        # source declares none, so the path is then the whole assertion.
        self.assertTrue(slots.Claim("profile", "d", "n", status="path_exact").is_proven)

    def test_a_name_is_not_proof(self):
        self.assertFalse(slots.Claim("profile", "d", "n", status="name_exact").is_proven)
        self.assertFalse(
            slots.Claim("profile", "d", "n", status="hash_mismatch").is_proven
        )



class AnExactSizeContestsAnotherSize(unittest.TestCase):
    """System.dat pinned the 2 KiB X1 font as xmil/IPLROM.X1T, where xmil
    reads a 32 KiB Turbo IPL. The profile's name-only claim could not
    contest it, and RetroArch packs shipped the font as the IPL."""

    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.ipl = root / "IPLROM.X1T"
        self.ipl.write_bytes(b"i" * 32768)
        self.font = root / "FNT0808.X1"
        self.font.write_bytes(b"f" * 2048)

    def test_a_held_copy_of_the_declared_size_proves_the_claim(self):
        entry = {"name": "IPLROM.X1T", "size": 32768}
        self.assertTrue(slots._size_the_code_reads(entry, str(self.ipl)))
        self.assertFalse(slots._size_the_code_reads(entry, str(self.font)))
        self.assertTrue(slots.Claim("profile", "d", "n", status=slots.SIZE_EXACT).is_proven)

    def test_retroarch_ships_the_turbo_ipl(self):
        import json as _json

        manifest = _json.loads(
            (Path(__file__).resolve().parents[1] / "install" / "retroarch.json").read_text()
        )
        entry = next(f for f in manifest["files"] if f["dest"] == "xmil/IPLROM.X1T")
        self.assertEqual(entry["size"], 32768)


class ManifestFollowsTheArbitration(unittest.TestCase):
    """The installer is handed the file the ZIP carries on a contested slot."""

    def test_retroarch_manifest_serves_every_override(self):
        repo = Path(__file__).resolve().parents[1]
        if not (repo / "database.json").is_file():
            self.skipTest("no database.json")
        # The database names files relative to the repository root, and this
        # module's fixtures move the working directory elsewhere.
        previous = os.getcwd()
        os.chdir(repo)
        self.addCleanup(os.chdir, previous)
        import generate_pack
        from common import (
            build_zip_contents_index,
            load_data_dir_registry,
            load_database,
            load_emulator_profiles,
            load_platform_config,
        )

        db = load_database(str(repo / "database.json"))
        config = load_platform_config("retroarch", str(repo / "platforms"))
        profiles = load_emulator_profiles(str(repo / "emulators"))
        overrides = slots.pack_overrides(
            config, profiles, db, build_zip_contents_index(db),
            load_data_dir_registry(str(repo / "platforms")),
        )
        # RetroArch serves a core's own copy at contested slots (ATARIOSB.ROM,
        # dsi_bios7/9.bin): an arbitration that settles nothing is the
        # failure, not a reason to skip.
        self.assertTrue(overrides, "pack_overrides settles no RetroArch slot")
        manifest = generate_pack.generate_manifest(
            "retroarch", str(repo / "platforms"), db, str(repo / "bios"),
            str(repo / "platforms" / "_registry.yml"),
            emulators_dir=str(repo / "emulators"), emu_profiles=profiles, offline=True,
        )
        base = config.get("base_destination", "")
        by_dest = {f["dest"]: f for f in manifest["files"]}
        for destination, path in overrides.items():
            dest = destination[len(base) + 1:] if base else destination
            with self.subTest(destination=destination):
                self.assertEqual(by_dest[dest]["repo_path"], path)


class StrongestProfileClaimWins(unittest.TestCase):
    """yaps2 pins GameIndex.yaml by sha1 while armsx2 matched a path only."""

    def test_hash_proof_beats_path_proof(self):
        def claim(emu, path, status):
            return Claim("profile", "pcsx2/resources/GameIndex.yaml", "GameIndex.yaml",
                         emulator=emu, local_path=path, status=status)

        conflict = Conflict(
            "pcsx2/resources/GameIndex.yaml",
            Claim("platform", "pcsx2/resources/GameIndex.yaml", "GameIndex.yaml",
                  local_path="p", status="path_exact"),
            [claim("armsx2", "a", "path_exact"), claim("yaps2", "y", "sha1_exact")],
        )
        decision = arbitrate(conflict, "existence")
        self.assertEqual(decision.winner.emulator, "yaps2")
        # armsx2 names no content: the file at the path answers it too.
        line = format_decision(decision)
        self.assertIn("(armsx2, yaps2)", line)
        self.assertNotIn("expected another file", line)

        pinned = Conflict(
            conflict.destination,
            conflict.platform_claim,
            [claim("armsx2", "a", "md5_exact"), claim("yaps2", "y", "sha1_exact")],
        )
        # Both pin content: the tie goes to the first, the other is named.
        self.assertIn(
            "yaps2 expected another file",
            format_decision(arbitrate(pinned, "existence")),
        )


class AnArchiveIsClaimedByItsMembers(unittest.TestCase):
    """System.dat pins fbneo/neocdz.zip to a copy holding neocd.bin alone;
    FBNeo also requires 000-lo.lo inside it. Members were skipped by the
    claims, so nothing contested the pin and RetroArch shipped an archive
    the core cannot boot from."""

    def setUp(self):
        import hashlib
        import zipfile
        import zlib

        roms = {"neocd.bin": b"bios" * 8, "000-lo.lo": b"zoom" * 8}
        entries = {}
        self.paths = {}
        for label, members in (("short", ["neocd.bin"]), ("full", list(roms))):
            path = Path(f"bios/Arc/{label}/neocdz.zip")
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "w") as zf:
                for member in members:
                    zf.writestr(member, roms[member])
            data = path.read_bytes()
            entries[hashlib.sha1(data).hexdigest()] = {
                "path": str(path), "md5": hashlib.md5(data).hexdigest(), "size": len(data),
            }
            self.paths[label] = (str(path), hashlib.md5(data).hexdigest())
        self.addCleanup(shutil.rmtree, "bios/Arc", True)
        self.db = _db(entries)
        self.profiles = {"fbneo": {
            "emulator": "FBNeo", "type": "libretro", "systems": ["snk-neogeo-cd"],
            "archive_prefix": "fbneo",
            "files": [
                {"name": name, "archive": "neocdz.zip", "system": "snk-neogeo-cd",
                 "required": True, "crc32": format(zlib.crc32(data), "08x")}
                for name, data in roms.items()
            ],
        }}

    def _config(self, mode: str, pinned: str) -> dict:
        return {
            "platform": "P", "verification_mode": mode, "base_destination": "system",
            "cores": ["fbneo"],
            "systems": {"snk-neogeo-cd": {"files": [{
                "name": "neocdz.zip", "destination": "fbneo/neocdz.zip",
                "md5": self.paths[pinned][1],
            }]}},
        }

    def test_existence_serves_the_copy_the_core_boots_from(self):
        overrides = slots.pack_overrides(self._config("existence", "short"), self.profiles, self.db)
        self.assertEqual(overrides, {"system/fbneo/neocdz.zip": self.paths["full"][0]})

    def test_a_content_check_keeps_the_pin_and_reports_it(self):
        config = self._config("md5", "short")
        self.assertEqual(slots.pack_overrides(config, self.profiles, self.db), {})
        conflicts = slots.find_conflicts(config, self.profiles, self.db, "system")
        self.assertEqual([c.destination for c in conflicts], ["system/fbneo/neocdz.zip"])

    def test_a_pin_nobody_holds_yields_where_only_the_path_is_checked(self):
        """RetroArch's root neocdz.zip pins an md5 no local file has: the
        name answered with the short copy, and no claim was ever compared."""
        config = self._config("existence", "short")
        config["systems"]["snk-neogeo-cd"]["files"][0].update(
            destination="neocdz.zip", md5="f" * 32
        )
        overrides = slots.pack_overrides(config, self.profiles, self.db)
        self.assertEqual(overrides, {"system/neocdz.zip": self.paths["full"][0]})
        config["verification_mode"] = "md5"
        self.assertEqual(slots.find_conflicts(config, self.profiles, self.db, "system"), [])

    def test_a_target_without_the_core_keeps_the_pin(self):
        """DuckStation exists on no RetroArch target and still replaced the
        scph5000.bin System.dat pins in every --target pack."""
        config = self._config("existence", "short")
        self.assertTrue(slots.pack_overrides(config, self.profiles, self.db))
        self.assertEqual(
            slots.pack_overrides(config, self.profiles, self.db, target_cores={"other"}), {}
        )

    def test_a_baseline_pack_serves_the_baseline(self):
        config = self._config("existence", "short")
        self.assertEqual(
            slots.pack_overrides(config, self.profiles, self.db, source="platform"), {}
        )

    def test_a_pin_holding_the_members_is_agreement(self):
        config = self._config("md5", "full")
        self.assertEqual(slots.find_conflicts(config, self.profiles, self.db, "system"), [])



class SlotsJudgeWhatVerifyJudged(unittest.TestCase):
    """Step 3b ran slots.py without the run's --target and arbitrated cores
    the target does not ship."""

    def test_the_pipeline_passes_the_target(self):
        source = (Path(__file__).resolve().parents[1] / "scripts" / "pipeline.py").read_text()
        step = source[source.index('slots_cmd = [sys.executable, "scripts/slots.py"]'):]
        step = step[:step.index("3b slot arbitration")]
        self.assertIn('slots_cmd.extend(["--target", args.target])', step)


class ARecordIsFoundByItsPathOnce(unittest.TestCase):
    """_accepted_by_all walked all 19 000 records for every path asked."""

    def test_the_files_are_walked_once(self):
        import slots  # noqa: PLC0415

        class Counted(dict):
            walks = 0

            def values(self):
                Counted.walks += 1
                return super().values()

        files = Counted({"a" * 40: {"path": "bios/x.bin"}, "b" * 40: {"path": "bios/y.bin"}})
        db = {"files": files}
        for _ in range(50):
            self.assertEqual(slots._record_at("bios/y.bin", db)["path"], "bios/y.bin")
        self.assertIsNone(slots._record_at("bios/z.bin", db))
        self.assertEqual(Counted.walks, 1)


class TwoPathsHoldingOneContentAgree(unittest.TestCase):
    """AmberELEC's bluemsx declarations resolve into the data/bluemsx cache,
    the profile into bios/. Neither declares a hash and the bytes are the
    same, yet the paths differed and 56 destinations read as contradicted."""

    def test_same_bytes_under_two_paths_satisfy(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp, "data", "MSX2EXT.rom")
            stored = Path(tmp, "bios", "MSX2EXT.rom")
            other = Path(tmp, "bios", "other.rom")
            for path, payload in ((cache, b"rom"), (stored, b"rom"), (other, b"xyz")):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            db = {"files": {}}
            platform = Claim("platform", "Machines/MSX2EXT.rom", "MSX2EXT.rom",
                             local_path=str(cache), status="path_exact")
            same = Claim("profile", "Machines/MSX2EXT.rom", "MSX2EXT.rom",
                         emulator="bluemsx", local_path=str(stored),
                         status="path_exact")
            different = Claim("profile", "Machines/MSX2EXT.rom", "MSX2EXT.rom",
                              emulator="bluemsx", local_path=str(other),
                              status="path_exact")
            self.assertTrue(slots._satisfies(same, platform, db))
            self.assertFalse(slots._satisfies(different, platform, db))


class ACopierHeaderIsNotAnotherImage(unittest.TestCase):
    """Geargrafx drops a 512-byte header before the crc32 (src/media.cpp:
    754-773). EmuELEC's headered syscard3.pce was reported contested, though
    the core reads it as the 6d9a73ef image its profile lists."""

    def test_headered_file_satisfies_the_profile(self):
        import zlib  # noqa: PLC0415

        image = b"S" * 1024
        with tempfile.TemporaryDirectory() as tmp:
            headered = Path(tmp, "headered.pce")
            headered.write_bytes(b"\0" * 512 + image)
            plain = Path(tmp, "plain.pce")
            plain.write_bytes(image)
            crc = f"{zlib.crc32(image):08x}"
            db = {"files": {
                "a" * 40: {"path": str(headered), "size": 1536,
                           "crc32": f"{zlib.crc32(headered.read_bytes()):08x}"},
                "b" * 40: {"path": str(plain), "size": 1024, "crc32": crc},
            }}
            platform = Claim("platform", "syscard3.pce", "syscard3.pce",
                             local_path=str(headered), status="md5_exact")
            profile = Claim(
                "profile", "syscard3.pce", "syscard3.pce", emulator="geargrafx",
                local_path=str(plain), status="crc32_exact",
                entry={"name": "syscard3.pce", "crc32": [crc], "size": [1024, 1536]},
            )
            self.assertTrue(slots._satisfies(profile, platform, db))
            one_size = Claim(
                "profile", "syscard3.pce", "syscard3.pce", emulator="geargrafx",
                local_path=str(plain), status="crc32_exact",
                entry={"name": "syscard3.pce", "crc32": [crc], "size": 1024},
            )
            self.assertFalse(slots._satisfies(one_size, platform, db))


class TheSlotsSummaryClosesTheRun(unittest.TestCase):
    """The totals came before the collision section and ignored it, and the
    help said the default run fails on conflicts the pack should settle,
    which it never does."""

    def test_order_and_help(self):
        import subprocess  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        if not (root / "database.json").exists():
            self.skipTest("database.json is not built")
        proc = subprocess.run(
            [sys.executable, "scripts/slots.py"], cwd=root, capture_output=True,
            text=True, timeout=600, check=False,
        )
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(proc.returncode, 0)
        totals = next(i for i, line in enumerate(lines) if "contested destinations." in line)
        self.assertIn("declared twice.", lines[totals])
        self.assertFalse(any(line.endswith("destinations declared twice") for line in lines[totals:]))
        helped = subprocess.run(
            [sys.executable, "scripts/slots.py", "--help"], cwd=root, capture_output=True,
            text=True, timeout=60, check=False,
        ).stdout
        self.assertIn("exits 0", " ".join(helped.split()))


if __name__ == "__main__":
    unittest.main()
