"""Region vocabulary, hierarchy, and rank resolution."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import common  # noqa: E402
import region  # noqa: E402
from packextras import emulator_region_drops  # noqa: E402


class TestVocabulary(unittest.TestCase):
    def test_world_is_a_region(self):
        self.assertIn(region.WORLD, region.REGIONS)

    def test_super_regions_and_members_are_all_regions(self):
        for parent, members in region.REGION_TREE.items():
            self.assertIn(parent, region.REGIONS)
            for member in members:
                self.assertIn(member, region.REGIONS)

    def test_hierarchy_is_two_levels(self):
        for members in region.REGION_TREE.values():
            for member in members:
                self.assertNotIn(member, region.REGION_TREE)

    def test_no_member_has_two_parents(self):
        seen: set[str] = set()
        for members in region.REGION_TREE.values():
            for member in members:
                self.assertNotIn(member, seen)
                seen.add(member)


class TestComparable(unittest.TestCase):
    def test_equal(self):
        self.assertTrue(region.comparable("japan", "japan"))

    def test_parent_matches_child(self):
        self.assertTrue(region.comparable("europe", "france"))

    def test_child_matches_parent(self):
        self.assertTrue(region.comparable("france", "europe"))

    def test_siblings_do_not_match(self):
        self.assertFalse(region.comparable("france", "germany"))

    def test_disjoint_super_regions_do_not_match(self):
        self.assertFalse(region.comparable("europe", "asia"))

    def test_saturn_fused_slug_is_under_asia(self):
        self.assertTrue(region.comparable("asia", "asia-ntsc"))

    def test_an_area_matches_the_territory_it_serves(self):
        """kronos tags the ST-V BIOS epr-19854.ic8 taiwan, mednafen_stv tags
        it asia-ntsc, the SMPC area Mednafen names for Taiwan."""
        self.assertTrue(region.comparable("taiwan", "asia-ntsc"))
        self.assertTrue(region.comparable("asia-ntsc", "taiwan"))
        self.assertTrue(region.comparable("china", "asia-pal"))

    def test_an_area_does_not_match_other_territories(self):
        self.assertFalse(region.comparable("japan", "asia-ntsc"))
        self.assertFalse(region.comparable("taiwan", "asia-pal"))


class TestNormalizeDeclared(unittest.TestCase):
    def test_none_is_empty(self):
        self.assertEqual(region.normalize_declared(None), set())

    def test_list_passes_through(self):
        self.assertEqual(region.normalize_declared(["japan"]), {"japan"})

    def test_legacy_signal_string_maps_to_geography(self):
        self.assertEqual(region.normalize_declared("NTSC-J"), {"japan"})
        self.assertEqual(region.normalize_declared("NTSC-U"), {"north-america"})
        self.assertEqual(region.normalize_declared("PAL"), {"europe"})

    def test_legacy_auto_and_world_map_to_world(self):
        self.assertEqual(region.normalize_declared("Auto"), {region.WORLD})
        self.assertEqual(region.normalize_declared("World"), {region.WORLD})

    def test_unknown_value_raises(self):
        with self.assertRaises(ValueError):
            region.normalize_declared("atlantis")


class TestParseRequested(unittest.TestCase):
    def test_single_alias(self):
        self.assertEqual(region.parse_requested("us"), ["north-america"])

    def test_order_is_preserved(self):
        self.assertEqual(
            region.parse_requested("us,eu,jp"),
            ["north-america", "europe", "japan"],
        )

    def test_duplicates_collapse_keeping_first_position(self):
        self.assertEqual(
            region.parse_requested("us,usa,eu"), ["north-america", "europe"]
        )

    def test_whitespace_and_case_tolerated(self):
        self.assertEqual(
            region.parse_requested(" US , Eu "), ["north-america", "europe"]
        )

    def test_unknown_region_raises(self):
        with self.assertRaises(ValueError):
            region.parse_requested("us,atlantis")

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            region.parse_requested("  ")


class TestRank(unittest.TestCase):
    def test_exact_match_is_zero(self):
        self.assertEqual(region.rank({"north-america"}, ["north-america"]), 0)

    def test_second_choice_is_one(self):
        self.assertEqual(region.rank({"europe"}, ["north-america", "europe"]), 1)

    def test_no_match_is_lowest(self):
        self.assertEqual(region.rank({"japan"}, ["north-america", "europe"]), 2)

    def test_child_matches_requested_parent(self):
        self.assertEqual(region.rank({"france"}, ["europe"]), 0)

    def test_parent_matches_requested_child(self):
        self.assertEqual(region.rank({"europe"}, ["france"]), 0)

    def test_best_of_several_declared_regions_wins(self):
        self.assertEqual(
            region.rank({"japan", "north-america"}, ["north-america", "japan"]), 0
        )

    def test_empty_declared_is_lowest(self):
        self.assertEqual(region.rank(set(), ["north-america"]), 1)


class TestRegionTag(unittest.TestCase):
    def test_single(self):
        self.assertEqual(region.region_tag(["north-america"]), "NorthAmerica")

    def test_multiple_joined(self):
        self.assertEqual(
            region.region_tag(["north-america", "japan"]), "NorthAmerica_Japan"
        )


class TestRegionIndex(unittest.TestCase):
    def setUp(self):
        self.profiles = {
            "dolphin": {
                "files": [
                    {
                        "name": "IPL.bin",
                        "path": "GC/USA/IPL.bin",
                        "region": ["north-america"],
                    },
                    {
                        "name": "IPL.bin",
                        "path": "GC/EUR/IPL.bin",
                        "region": ["europe"],
                    },
                    {
                        "name": "IPL.bin",
                        "path": "GC/JAP/IPL.bin",
                        "region": ["japan"],
                    },
                    {"name": "dsp_rom.bin"},
                ]
            },
            "beetle_psx": {
                "files": [
                    {"name": "scph5501.bin", "region": "NTSC-U"},
                    {"name": "psxonpsp660.bin", "region": "Auto"},
                ]
            },
            "swanstation": {
                "files": [{"name": "scph5501.bin", "region": "NTSC-U"}]
            },
            "launcher_profile": {
                "type": "launcher",
                "files": [{"name": "ignored.bin", "region": ["japan"]}],
            },
        }
        self.index = region.build_region_index(self.profiles)

    def test_path_keyed_entries_stay_separate(self):
        self.assertEqual(
            region.lookup_regions(self.index, "GC/USA/IPL.bin", "IPL.bin"),
            {"north-america"},
        )
        self.assertEqual(
            region.lookup_regions(self.index, "GC/JAP/IPL.bin", "IPL.bin"),
            {"japan"},
        )

    def test_bare_name_lookup_unions_ambiguous_entries(self):
        self.assertEqual(
            region.lookup_regions(self.index, "", "IPL.bin"),
            {"north-america", "europe", "japan"},
        )

    def test_destination_suffix_bridges_platform_entry(self):
        self.assertEqual(
            region.lookup_regions(
                self.index, "dolphin-emu/GC/EUR/IPL.bin", "IPL.bin"
            ),
            {"europe"},
        )

    def test_untagged_file_has_no_regions(self):
        self.assertEqual(
            region.lookup_regions(self.index, "dsp_rom.bin", "dsp_rom.bin"), set()
        )

    def test_unknown_file_has_no_regions(self):
        self.assertEqual(
            region.lookup_regions(self.index, "nope.bin", "nope.bin"), set()
        )

    def test_legacy_string_values_are_normalised(self):
        self.assertEqual(
            region.lookup_regions(self.index, "scph5501.bin", "scph5501.bin"),
            {"north-america"},
        )
        self.assertEqual(
            region.lookup_regions(self.index, "psxonpsp660.bin", "psxonpsp660.bin"),
            {region.WORLD},
        )

    def test_two_profiles_agreeing_merge(self):
        entry = self.index["scph5501.bin"]
        self.assertEqual(entry["regions"], {"north-america"})
        self.assertEqual(entry["emulators"], ["beetle_psx", "swanstation"])

    def test_launcher_profiles_are_skipped(self):
        self.assertEqual(
            region.lookup_regions(self.index, "ignored.bin", "ignored.bin"), set()
        )

    def test_unknown_value_names_the_profile_and_file(self):
        with self.assertRaises(ValueError) as ctx:
            region.build_region_index(
                {"badcore": {"files": [{"name": "x.bin", "region": ["atlantis"]}]}}
            )
        self.assertIn("badcore", str(ctx.exception))
        self.assertIn("x.bin", str(ctx.exception))


class TestStandaloneLayoutIsIndexed(unittest.TestCase):
    """GC/EUR/IPL.bin, Dolphin's standalone path, was looked up by its bare
    name and got the union of five regions: never reduced in a Batocera
    pack nor in --emulator dolphin --standalone."""

    def test_the_standalone_path_carries_its_own_regions(self):
        import slot

        profiles = {"dolphin": {"files": [
            {"name": "IPL.bin", "path": "dolphin-emu/Sys/GC/USA/IPL.bin",
             "standalone_path": "GC/USA/IPL.bin", "region": ["north-america"]},
            {"name": "IPL.bin", "path": "dolphin-emu/Sys/GC/EUR/IPL.bin",
             "standalone_path": "GC/EUR/IPL.bin", "region": ["europe"]},
        ]}}
        index = region.build_region_index(profiles)
        self.assertEqual(region.lookup_regions(index, "GC/EUR/IPL.bin", "IPL.bin"), {"europe"})
        self.assertIn("GC/EUR/IPL.bin", slot.build_slot_index(profiles))

    def test_an_alias_carries_the_region_of_its_file(self):
        """scph5552.bin, the name beetle_psx also opens for its European
        BIOS, stayed in a --region jp pack once scph5502.bin went."""
        index = region.build_region_index({"beetle_psx": {"files": [
            {"name": "scph5502.bin", "aliases": ["scph5552.bin"],
             "region": ["europe", "oceania"]},
        ]}})
        self.assertEqual(
            region.lookup_regions(index, "scph5552.bin", "scph5552.bin"),
            {"europe", "oceania"},
        )


class TestResolveRegionDrops(unittest.TestCase):
    def setUp(self):
        self.index = region.build_region_index(
            {
                "psx": {
                    "files": [
                        {"name": "scph5501.bin", "region": ["north-america"]},
                        {"name": "scph5500.bin", "region": ["japan"]},
                        {"name": "scph5502.bin", "region": ["europe"]},
                        {"name": "psxonpsp660.bin", "region": ["world"]},
                        {"name": "gamepad.cfg"},
                    ]
                },
                "fds": {"files": [{"name": "disksys.rom", "region": ["japan"]}]},
                "o2em": {"files": [{"name": "c52.bin", "region": ["france"]}]},
            }
        )

    def _drops(self, groups, requested):
        return region.resolve_region_drops(groups, self.index, requested)

    def test_a_lone_file_never_vetoes_its_system(self):
        """Dolphin's GC/EUR/IPL.bin came back as a core extra alone in its
        group, and that group's keep cancelled the drop the GameCube group
        decided: the full pack kept what --source platform dropped."""
        groups = {
            "psx": [("scph5501.bin", "scph5501.bin"), ("scph5502.bin", "scph5502.bin")],
            "core:file:scph5502.bin": [("scph5502.bin", "scph5502.bin")],
        }
        self.assertEqual(self._drops(groups, ["north-america"]), {"scph5502.bin"})
        alone = {"core:file:scph5502.bin": [("scph5502.bin", "scph5502.bin")]}
        self.assertEqual(self._drops(alone, ["north-america"]), set())

    def test_a_missing_match_never_displaces_a_held_file(self):
        """Grouped so the report can withdraw it, a missing file must not
        take a held one's place: a Japanese request with only the American
        BIOS held kept nothing for the PlayStation."""
        groups = {"psx": [("scph5501.bin", "scph5501.bin"),
                          ("scph5500.bin", "scph5500.bin")]}
        held = {"scph5501.bin"}
        drop = region.resolve_region_drops
        self.assertEqual(drop(groups, self.index, ["japan"], held), set())
        self.assertEqual(
            drop(groups, self.index, ["japan", "north-america"], held), set()
        )
        self.assertEqual(
            drop(groups, self.index, ["north-america"], held), {"scph5500.bin"}
        )
        self.assertEqual(drop(groups, self.index, ["japan"]), {"scph5501.bin"})

    def test_a_missing_world_file_never_displaces_a_held_one(self):
        groups = {"psx": [("scph5500.bin", "scph5500.bin"),
                          ("psxonpsp660.bin", "psxonpsp660.bin")]}
        self.assertEqual(
            region.resolve_region_drops(
                groups, self.index, ["europe"], {"scph5500.bin"}
            ),
            set(),
        )

    def test_a_world_file_the_code_ranks_lower_keeps_the_regional_ones(self):
        """DuckStation looks for its PS1 images (5) before the world PS2 ones
        (100): asked for Brazil, it kept only the PS2 fallbacks."""
        index = region.build_region_index({"duckstation": {"files": [
            {"name": "scph5501.bin", "region": ["north-america"], "priority": 5},
            {"name": "ps2_scph30001.bin", "region": ["north-america"], "priority": 150},
            {"name": "ps2_scph10000.bin", "region": ["world"], "priority": 100},
        ]}})
        groups = {"psx": [(n, n) for n in ("scph5501.bin", "ps2_scph30001.bin",
                                            "ps2_scph10000.bin")]}
        self.assertEqual(
            region.resolve_region_drops(groups, index, ["brazil"]), {"ps2_scph30001.bin"}
        )

    def test_without_ranks_the_world_file_still_wins(self):
        groups = {"psx": [("scph5501.bin", "scph5501.bin"),
                          ("psxonpsp660.bin", "psxonpsp660.bin")]}
        self.assertEqual(self._drops(groups, ["brazil"]), {"scph5501.bin"})

    def test_best_rank_wins_and_siblings_drop(self):
        groups = {
            "psx": [
                ("scph5501.bin", "scph5501.bin"),
                ("scph5500.bin", "scph5500.bin"),
                ("scph5502.bin", "scph5502.bin"),
            ]
        }
        self.assertEqual(
            self._drops(groups, ["north-america"]),
            {"scph5500.bin", "scph5502.bin"},
        )

    def test_priority_order_selects_second_choice(self):
        groups = {
            "psx": [
                ("scph5500.bin", "scph5500.bin"),
                ("scph5502.bin", "scph5502.bin"),
            ]
        }
        self.assertEqual(
            self._drops(groups, ["north-america", "europe", "japan"]),
            {"scph5500.bin"},
        )

    def test_group_with_no_match_is_kept_whole(self):
        groups = {"fds": [("disksys.rom", "disksys.rom")]}
        self.assertEqual(self._drops(groups, ["north-america"]), set())

    def test_world_never_competes(self):
        groups = {
            "psx": [
                ("scph5501.bin", "scph5501.bin"),
                ("scph5500.bin", "scph5500.bin"),
                ("psxonpsp660.bin", "psxonpsp660.bin"),
            ]
        }
        self.assertEqual(self._drops(groups, ["north-america"]), {"scph5500.bin"})

    def test_untagged_files_never_drop(self):
        groups = {
            "psx": [
                ("scph5501.bin", "scph5501.bin"),
                ("gamepad.cfg", "gamepad.cfg"),
                ("scph5500.bin", "scph5500.bin"),
            ]
        }
        self.assertEqual(self._drops(groups, ["north-america"]), {"scph5500.bin"})

    def test_child_region_satisfies_requested_parent(self):
        groups = {"o2em": [("c52.bin", "c52.bin")]}
        self.assertEqual(self._drops(groups, ["europe"]), set())

    def test_destination_kept_by_any_group_is_not_dropped(self):
        groups = {
            "psx": [
                ("scph5501.bin", "scph5501.bin"),
                ("scph5500.bin", "scph5500.bin"),
            ],
            "psx-import": [("scph5500.bin", "scph5500.bin")],
        }
        self.assertEqual(self._drops(groups, ["north-america"]), set())

    def test_no_requested_regions_drops_nothing(self):
        groups = {"psx": [("scph5500.bin", "scph5500.bin")]}
        self.assertEqual(self._drops(groups, []), set())


class TestFallbackGroups(unittest.TestCase):
    def setUp(self):
        self.index = region.build_region_index(
            {
                "psx": {
                    "files": [
                        {"name": "scph5501.bin", "region": ["north-america"]}
                    ]
                },
                "fds": {"files": [{"name": "disksys.rom", "region": ["japan"]}]},
            }
        )

    def test_only_unmatched_groups_are_reported(self):
        groups = {
            "psx": [("scph5501.bin", "scph5501.bin")],
            "fds": [("disksys.rom", "disksys.rom")],
        }
        self.assertEqual(
            region.fallback_groups(groups, self.index, ["north-america"]), ["fds"]
        )

    def test_an_untagged_bios_answers_every_region(self):
        """VICE's generic kernal is untagged beside its Japanese one: the C64
        was reported as having no BIOS for North America."""
        groups = {"fds": [("disksys.rom", "disksys.rom"), ("generic.rom", "generic.rom")]}
        self.assertEqual(region.fallback_groups(groups, self.index, ["north-america"]), [])

    def test_a_file_no_system_claims_is_no_fallback(self):
        """Dolphin's GC/EUR/IPL.bin, alone in its group, named the GameCube
        in the pack README as lacking a North American BIOS it carries."""
        groups = {"Dolphin:file:GC/EUR/IPL.bin": [("GC/EUR/IPL.bin", "IPL.bin")],
                  "fds": [("disksys.rom", "disksys.rom")]}
        self.assertEqual(
            region.fallback_groups(groups, self.index, ["north-america"]), ["fds"]
        )

    def test_the_readme_names_a_slot_as_a_reader_does(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from packreadme import _group_label

        self.assertEqual(_group_label("PicoDrive:variant:megacd"), "megacd (PicoDrive)")
        self.assertEqual(_group_label("sega-mega-cd"), "sega-mega-cd")

    def test_no_requested_regions_reports_nothing(self):
        groups = {"fds": [("disksys.rom", "disksys.rom")]}
        self.assertEqual(region.fallback_groups(groups, self.index, []), [])


class OneCodeOneRegionAnswer(unittest.TestCase):
    """mednafen, beetle_saturn, saturn-emu and mednafen_stv read the same
    ss.cpp, where area E (Australia included) selects the PAL BIOS: only
    two of them answered oceania. CLK and Kronos are pinned here too."""

    PROFILES = os.path.join(os.path.dirname(__file__), "..", "emulators")

    def test_the_mednafen_saturn_profiles_agree(self):
        profiles = common.load_emulator_profiles(self.PROFILES)
        seen: dict[str, dict[str, frozenset]] = {}
        for name in ("mednafen", "beetle_saturn", "saturn-emu", "mednafen_stv"):
            for entry in profiles[name]["files"]:
                if entry["name"] in ("mpr-17933.bin", "sega_100a.bin"):
                    seen.setdefault(entry["name"], {})[name] = frozenset(
                        entry.get("region") or ()
                    )
        for file_name, tags in seen.items():
            with self.subTest(file=file_name):
                self.assertEqual(len(set(tags.values())), 1, tags)
                self.assertIn("oceania", next(iter(tags.values())))

    def test_export_cartridges_and_allowed_regions(self):
        profiles = common.load_emulator_profiles(self.PROFILES)
        bios_sms = next(e for e in profiles["clk"]["files"] if e["name"] == "bios.sms")
        self.assertIn("oceania", bios_sms["region"])
        # A Mexican export cartridge is analysed as Europe or USA and boots the
        # western BIOS: only Japan selects the other one.
        self.assertEqual(
            region.rank(region.normalize_declared(bios_sms["region"]), ["mexico"]), 0
        )
        tagged = {
            e["name"]: e.get("region") for e in profiles["kronos"]["files"]
            if e.get("archive") == "stvbios.zip" and e["name"].startswith("epr-")
        }
        self.assertTrue(all(tagged.values()), tagged)


class AustraliaReadsThePalIpl(unittest.TestCase):
    """Dolphin files the Australian country code U under Region::PAL
    (Source/Core/DiscIO/Enums.cpp), whose IPL is GC/EUR. Tagged [europe]
    alone, `--region australia` dropped it and kept the American one."""

    def test_the_pal_ipl_answers_oceania(self):
        profiles = common.load_emulator_profiles(
            os.path.join(os.path.dirname(__file__), "..", "emulators")
        )
        for name in ("dolphin", "primehack", "ishiiruka", "triforce"):
            with self.subTest(profile=name):
                pal = [f for f in profiles[name]["files"]
                       if "/EUR/" in str(f.get("path", ""))]
                self.assertTrue(pal)
                self.assertTrue(all("oceania" in f.get("region", []) for f in pal))


class TestProfileConformance(unittest.TestCase):
    """Every region: value in the repo is a list of canonical slugs."""

    def setUp(self):
        import glob

        import yaml

        self.repo_profiles = sorted(
            glob.glob(
                os.path.join(os.path.dirname(__file__), "..", "emulators", "*.yml")
            )
        )
        if not self.repo_profiles:
            self.skipTest("emulators/ not present")
        self.yaml = yaml

    def test_all_region_values_are_canonical_lists(self):
        offenders: list[str] = []
        for path in self.repo_profiles:
            with open(path, encoding="utf-8") as fh:
                profile = self.yaml.safe_load(fh) or {}
            for f in profile.get("files") or []:
                if not isinstance(f, dict) or "region" not in f:
                    continue
                raw = f["region"]
                if not isinstance(raw, list):
                    offenders.append(
                        f"{os.path.basename(path)}: {f.get('name')} not a list"
                    )
                    continue
                for value in raw:
                    if value not in region.REGIONS:
                        offenders.append(
                            f"{os.path.basename(path)}: {f.get('name')} -> {value!r}"
                        )
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_index_builds_over_every_repo_profile(self):
        profiles = {}
        for path in self.repo_profiles:
            with open(path, encoding="utf-8") as fh:
                profiles[os.path.basename(path)[:-4]] = self.yaml.safe_load(fh) or {}
        index = region.build_region_index(profiles)
        self.assertGreater(len(index), 0)


class TestSchemaMatchesModule(unittest.TestCase):
    def test_schema_enum_equals_module_regions(self):
        import json

        path = os.path.join(
            os.path.dirname(__file__), "..", "schemas", "emulator.schema.json"
        )
        if not os.path.exists(path):
            self.skipTest("schema not present")
        with open(path, encoding="utf-8") as fh:
            schema = json.load(fh)
        node = schema["properties"]["files"]["items"]["properties"]["region"]
        self.assertEqual(set(node["items"]["enum"]), set(region.REGIONS))


class TestVerifyModesHonourRegion(unittest.TestCase):
    """verify.py must apply --region in every mode, or refuse it.

    It silently ignored the flag in --emulator and --system mode: the report
    was identical with and without, so a filtered pack could not be checked.
    """

    def _run(self, *args: str) -> str:
        """The report, from a run that succeeded.

        A run that crashed produced an empty stdout, different from the
        plain report, and the test read the difference as narrowing.
        """
        import subprocess

        repo = os.path.join(os.path.dirname(__file__), "..")
        completed = subprocess.run(
            [sys.executable, "scripts/verify.py", *args],
            capture_output=True, text=True, cwd=repo, timeout=900, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        self.assertTrue(completed.stdout.strip(), "an empty report is not a report")
        return completed.stdout

    def test_emulator_mode_narrows(self):
        plain = self._run("--emulator", "duckstation")
        if "duckstation" not in plain:
            self.skipTest("duckstation profile not present")
        filtered = self._run("--emulator", "duckstation", "--region", "us")
        self.assertNotEqual(plain, filtered)

    def test_system_mode_narrows(self):
        plain = self._run("--system", "sony-playstation")
        filtered = self._run("--system", "sony-playstation", "--region", "us")
        self.assertNotEqual(plain, filtered)


class TestReportAndBuilderNarrowTogether(unittest.TestCase):
    """A region run must withdraw the same files from report and pack.

    The two sides grouped their candidates separately: the builder grouped the
    platform files and the core extras, the report only the platform files.
    So the report kept every core extra a region run withdraws from the pack
    -on recalbox --region us, 59 files it described as covered.
    """

    def _fixture(self):
        import hashlib
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        (root / "emulators").mkdir()
        db = {"files": {}, "indexes": {
            "by_name": {}, "by_md5": {}, "by_sha256": {},
            "by_crc32": {}, "by_path_suffix": {},
        }}
        # Two regional alternatives of one system, both held locally.
        for fname, tag in (("us.bin", b"US BYTES"), ("jp.bin", b"JP BYTES")):
            blob = root / fname
            blob.write_bytes(tag)
            sha1 = hashlib.sha1(tag).hexdigest()
            db["files"][sha1] = {
                "path": str(blob), "name": fname, "size": len(tag),
                "sha1": sha1, "md5": hashlib.md5(tag).hexdigest(),
                "sha256": hashlib.sha256(tag).hexdigest(), "crc32": "00000000",
            }
            db["indexes"]["by_name"][fname] = [sha1]
            db["indexes"]["by_md5"][db["files"][sha1]["md5"]] = sha1
        (root / "emulators" / "demo.yml").write_text(
            "emulator: demo\n"
            "type: libretro\n"
            "display_name: Demo\n"
            "systems: [demo-system]\n"
            "cores: [demo]\n"
            "files:\n"
            "  - name: us.bin\n"
            "    system: demo-system\n"
            "    region: [north-america]\n"
            "    required: true\n"
            "  - name: jp.bin\n"
            "    system: demo-system\n"
            "    region: [japan]\n"
            "    required: true\n"
        )
        config = {
            "platform": "Demo",
            "verification_mode": "existence",
            "cores": ["demo"],
            "base_destination": "",
            "systems": {},
        }
        return tmp, root, db, config

    def test_the_report_withdraws_what_the_builder_withdraws(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
        import common
        import generate_pack as builder
        import verify as reporter

        tmp, root, db, config = self._fixture()
        try:
            common._emulator_profiles_cache.clear()
            profiles = common.load_emulator_profiles(str(root / "emulators"))
            groups, extra_dests = builder.platform_region_groups(
                config, config["systems"], str(root / "emulators"),
                db, "", profiles,
            )
            drops = region.resolve_region_drops(
                groups, region.build_region_index(profiles), ["north-america"]
            )
            self.assertEqual(
                {d for d in drops}, {"jp.bin"},
                "the builder must drop the Japanese alternative, not the US one",
            )

            plain = reporter.verify_platform(
                config, db, str(root / "emulators"), profiles,
            )
            narrowed = reporter.verify_platform(
                config, db, str(root / "emulators"), profiles,
                regions=["north-america"],
            )
            before = {u["name"] for u in plain["undeclared_files"]}
            after = {u["name"] for u in narrowed["undeclared_files"]}
            self.assertEqual(before, {"us.bin", "jp.bin"})
            self.assertEqual(
                before - after,
                {d for d in drops},
                "the report must withdraw exactly the builder's drop set",
            )
        finally:
            common._emulator_profiles_cache.clear()
            tmp.cleanup()

    def test_a_missing_regional_core_file_is_withdrawn_too(self):
        """A missing platform file is grouped and withdrawn under --region, but a
        missing core file was never grouped and stayed "required missing"
        for a region the request excludes."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
        import common
        import verify as reporter

        tmp, root, db, config = self._fixture()
        try:
            jp = next(k for k, v in db["files"].items() if v["name"] == "jp.bin")
            del db["files"][jp]
            del db["indexes"]["by_name"]["jp.bin"]
            common._emulator_profiles_cache.clear()
            profiles = common.load_emulator_profiles(str(root / "emulators"))
            plain = reporter.verify_platform(
                config, db, str(root / "emulators"), profiles,
            )
            narrowed = reporter.verify_platform(
                config, db, str(root / "emulators"), profiles,
                regions=["north-america"],
            )
            missing = [u["name"] for u in plain["undeclared_files"] if not u["in_repo"]]
            self.assertEqual(missing, ["jp.bin"])
            self.assertEqual(
                {u["name"] for u in narrowed["undeclared_files"]}, {"us.bin"}
            )
        finally:
            common._emulator_profiles_cache.clear()
            tmp.cleanup()

    def test_the_report_names_the_fallback_groups(self):
        """The pack README lists the systems kept whole because nothing
        answers the request. verify said all OK and named none."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
        import common
        import verify as reporter

        tmp, root, db, config = self._fixture()
        try:
            common._emulator_profiles_cache.clear()
            profiles = common.load_emulator_profiles(str(root / "emulators"))
            result = reporter.verify_platform(
                config, db, str(root / "emulators"), profiles,
                regions=["brazil"],
            )
            self.assertEqual(result["region_fallbacks"], ["demo-system"])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                reporter.print_platform_result(result, ["Demo"])
            self.assertIn("all kept (1): demo-system", out.getvalue())
        finally:
            common._emulator_profiles_cache.clear()
            tmp.cleanup()

    def test_one_grouping_pass_serves_both_sides(self):
        """A second hand-rolled grouping is how the two drifted apart.

        Every module is read, not only the two that once held a copy: the
        builder was split into several modules and a grouping can move with
        it. packextras.py holds the two shared passes, platform and emulator.
        """
        scripts = Path(__file__).resolve().parent.parent / "scripts"
        for path in sorted(scripts.rglob("*.py")):
            if path.name == "packextras.py":
                continue
            with self.subTest(module=path.name):
                self.assertNotIn(
                    "region_groups.setdefault(", path.read_text(encoding="utf-8"),
                    "region grouping belongs to packextras: platform_region_groups "
                    "or emulator_region_drops",
                )

    def test_the_verifier_reads_the_grouping_where_it_lives(self):
        """Imported through the builder's CLI module, the verdict of a
        --region run depended on that module compiling, and seven scripts
        entered the site workflow's trigger paths for one function."""
        source = (Path(__file__).resolve().parent.parent / "scripts" / "verify.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("from generate_pack import platform_region_groups", source)
        self.assertIn("from packextras import platform_region_groups", source)

    def test_emulator_report_keeps_what_the_emulator_pack_keeps(self):
        """O2EM: --region us left the Videopac BIOSes in the pack, not in the report."""
        repo = Path(__file__).resolve().parent.parent
        if not (repo / "emulators" / "o2em.yml").is_file():
            self.skipTest("no o2em profile")
        from verify import verify_emulator
        from common import load_database

        db = load_database(str(repo / "database.json"))
        full = verify_emulator(["o2em"], str(repo / "emulators"), db)
        narrowed = verify_emulator(["o2em"], str(repo / "emulators"), db, regions=["north-america"])
        names = {d["name"] for d in narrowed["details"]}
        for kept in ("c52.bin", "g7400.bin", "jopac.bin"):
            self.assertIn(kept, names, "a system with no candidate in the region falls back")
        self.assertEqual(full["total_files"], narrowed["total_files"])

    def test_every_grouping_call_carries_the_target(self):
        """Integrity grouped every core's extras while the builder grouped the target's.

        Under --target with --region, a fallback the pack kept was withdrawn
        from the check: 14 Batocera rk3568 files were never verified.
        """
        import ast

        scripts = Path(__file__).resolve().parent.parent / "scripts"
        for path in sorted(scripts.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for func in ast.walk(tree):
                if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                params = {a.arg for a in func.args.args + func.args.kwonlyargs}
                if "target_cores" not in params:
                    continue
                for call in ast.walk(func):
                    if (
                        isinstance(call, ast.Call)
                        and getattr(call.func, "id", None) == "platform_region_groups"
                    ):
                        with self.subTest(module=path.name, function=func.name):
                            self.assertIn(
                                "target_cores", {k.arg for k in call.keywords}
                            )

    def test_pal_console_region_reaches_oceania(self):
        """PSX cores pick these BIOSes for the PAL console region, not for Europe alone.

        DuckStation's ConsoleRegion::PAL, Beetle PSX, SwanStation, PCSX ReARMed's
        EU slot and Rustation all serve Australian and New Zealand discs from the
        same images. Annotated [europe] only, --region australia dropped them.
        """
        import yaml

        repo = Path(__file__).resolve().parent.parent
        for emu in ("duckstation", "beetle_psx", "swanstation", "pcsx_rearmed", "rustation"):
            profile = yaml.safe_load((repo / "emulators" / f"{emu}.yml").read_text())
            for entry in profile.get("files", []):
                regions = entry.get("region") or []
                if "europe" in regions:
                    with self.subTest(emulator=emu, name=entry.get("name")):
                        self.assertIn("oceania", regions)



class RegionalRequestsKeepWhatTheCodeLoads(unittest.TestCase):
    """A --region request never drops the file the core opens for it.

    mednafen_pce_fast tagged option-selected cards with territories, beetle_psx
    tagged its override BIOS [world], mednafen tagged the ST-V NA BIOS for
    America alone and the PAL PSX BIOS for Europe alone.
    """

    CASES = (
        ("mednafen_pce_fast", ["north-america"], "syscard3.pce"),
        ("beetle_psx", ["brazil"], "scph5501.bin"),
        ("mednafen", ["south-korea", "europe"], "epr-17952a.ic8"),
        ("mednafen", ["australia", "north-america"], "scph5502.bin"),
        ("bluemsx", ["south-korea"], "Machines/Shared Roms/KANJI.rom"),
        ("bluemsx", ["south-korea"], "Machines/Shared Roms/MSXKANJI.rom"),
        ("bluemsx", ["japan"], "Machines/Shared Roms/HANGUL.rom"),
        ("ace-dl", ["france"], "private/firmware/OS6128_UK.rom"),
        ("ace-dl", ["spain"], "private/firmware/OS664_UK.rom"),
        ("ace-dl", ["spain"], "private/firmware/OS464_FR.rom"),
        ("ace-dl", ["denmark"], "private/firmware/XMEM_FW_3_15_UK.rom"),
        ("ace-dl", ["spain"], "private/hacker/hacker481fr.rom"),
        ("ace-dl", ["france"], "private/firmware/Amstrad_s4.cpr"),
        ("duckstation", ["brazil"], "scph5501.bin"),
        ("duckstation", ["south-korea"], "scph5500.bin"),
        ("mednafen_stv", ["taiwan", "north-america"], "epr-19854.ic8"),
        ("kronos", ["asia-ntsc", "north-america"], "epr-19854.ic8"),
        ("beetle_saturn", ["taiwan", "north-america"], "sega_101.bin"),
        ("pcsx_rearmed", ["brazil", "japan"], "scph5501.bin"),
        ("pcsx_rearmed", ["brazil", "japan"], "scph1001.bin"),
        ("blastem", ["australia", "north-america"], "bios_CD_E.bin"),
        ("kega-fusion", ["australia", "north-america"], "eu_mcd1_9210.bin"),
        ("ares", ["brazil", "japan"], "scph5501.bin"),
        ("beetle_psx", ["brazil", "japan"], "scph5501.bin"),
        ("mednafen", ["brazil", "japan"], "scph5501.bin"),
        ("swanstation", ["brazil", "japan"], "scph5501.bin"),
        ("rustation", ["brazil", "japan"], "scph5501.bin"),
        ("rustation", ["brazil", "japan"], "scph101.bin"),
        ("duckstation", ["brazil", "japan"], "scph5501.bin"),
        ("duckstation", ["brazil", "japan"], "scph7001.bin"),
        ("duckstation", ["brazil", "japan"], "ps2_scph39001.bin"),
        ("bizhawk", ["north-america"], "DSi_Nand_USA.bin"),
        ("bizhawk", ["oceania"], "DSi_Nand_AUS.bin"),
        ("bizhawk", ["china", "japan"], "DSi_Nand_CHN.bin"),
        ("genesis_plus_gx", ["australia", "japan"], "bios_U.sms"),
        ("genesis_plus_gx", ["brazil", "japan"], "bios_U.sms"),
        ("genesis_plus_gx_wide", ["australia", "japan"], "bios_U.sms"),
        ("genesis_plus_gx_expanded", ["brazil", "japan"], "bios_U.sms"),
        ("dolphin", ["brazil", "europe"], "dolphin-emu/Sys/GC/USA/IPL.bin"),
        ("ishiiruka", ["brazil", "europe"], "dolphin-emu/Sys/GC/USA/IPL.bin"),
        ("dolphin-mmjr", ["brazil", "europe"], "GC/USA/IPL.bin"),
        ("dolphin-mmjr2", ["brazil", "europe"], "GC/USA/IPL.bin"),
        ("primehack", ["brazil", "europe"], "GC/USA/IPL.bin"),
        ("triforce", ["brazil", "europe"], "GC/USA/IPL.bin"),
        ("triforce", ["brazil", "europe"], "GC/USA/IPL_TRI.bin"),
    )

    def test_each_request_keeps_its_file(self):
        profiles = common.load_emulator_profiles(
            os.path.join(os.path.dirname(__file__), "..", "emulators")
        )
        for name, regions, kept in self.CASES:
            with self.subTest(profile=name, regions=regions):
                drops = emulator_region_drops([(name, profiles[name])], False, regions)
                self.assertNotIn(kept, drops)



class DsiNandFollowsTheHeaderRegion(unittest.TestCase):
    """BizHawk's DecideNAND keeps, for a DSi title, only the NAND slots whose
    bit is set in header byte 0x1B0 (MelonDS.cs:684-706): JPN, USA, EUR, AUS,
    CHN, KOR. The six DSi_Nand_<REGION>.bin entries carried no region, so a
    --region request kept all six 240 MB images."""

    SLOTS = {
        "JPN": ["japan"],
        "USA": ["north-america", "latin-america"],
        "EUR": ["europe"],
        "AUS": ["oceania"],
        "CHN": ["china"],
        "KOR": ["south-korea"],
    }

    def _profile(self) -> dict:
        return common.load_emulator_profiles(
            os.path.join(os.path.dirname(__file__), "..", "emulators")
        )["bizhawk"]

    def test_each_slot_carries_its_territory(self):
        files = {f["name"]: f for f in self._profile()["files"]}
        for slot, expected in self.SLOTS.items():
            with self.subTest(slot=slot):
                declared = files[f"DSi_Nand_{slot}.bin"].get("region")
                self.assertEqual(declared, expected)
                self.assertTrue(set(declared) <= region.REGIONS)

    def test_a_request_keeps_its_nand_and_withdraws_the_others(self):
        nands = {f"DSi_Nand_{slot}.bin" for slot in self.SLOTS}
        drops = emulator_region_drops([("bizhawk", self._profile())], False, ["north-america"])
        self.assertEqual(nands & drops, nands - {"DSi_Nand_USA.bin"})


class FontRomsCarryNoTerritory(unittest.TestCase):
    """A CJK font ROM is a language, not a territory. blueMSX tagged KANJI.rom
    and MSXKANJI.rom [japan], which a --region south-korea request withdrew
    from the generic MSX2+ machine whose config.ini loads both."""

    def test_no_kanji_or_hangul_font_declares_a_region(self):
        profiles = common.load_emulator_profiles(
            os.path.join(os.path.dirname(__file__), "..", "emulators")
        )
        tagged = [
            f"{name}:{entry['name']}"
            for name, profile in profiles.items()
            for entry in profile.get("files", [])
            if any(word in entry.get("name", "").lower() for word in ("kanji", "hangul"))
            and entry.get("region")
        ]
        self.assertEqual(tagged, [])

class EmulatorModeKeepsAHeldFile(unittest.TestCase):
    """Platform mode never lets a missing file displace a held one. Emulator
    mode did. A held scph5501.bin (north-america) was withdrawn under
    --region jp for a Japanese image the collection lacks, and the pack
    shipped no PlayStation BIOS."""

    def test_a_missing_match_does_not_withdraw_the_held_file(self):
        import hashlib  # noqa: PLC0415
        import shutil  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        root = Path(tempfile.mkdtemp(dir=Path(__file__).resolve().parents[1] / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        held = root / "scph5501.bin"
        held.write_bytes(b"us bios")
        sha1 = hashlib.sha1(b"us bios").hexdigest()
        db = {"files": {sha1: {"path": str(held), "name": held.name, "sha1": sha1}},
              "indexes": {"by_name": {held.name: [sha1]}, "by_md5": {},
                          "by_crc32": {}, "by_path_suffix": {}}}
        profile = {"systems": ["sony-playstation"], "files": [
            {"name": "scph5501.bin", "region": ["north-america"]},
            {"name": "scph5500.bin", "region": ["japan"]},
        ]}
        selected = [("psx", profile)]
        self.assertEqual(
            emulator_region_drops(selected, False, ["japan"], db=db), set()
        )
        # Without the collection to ask, the old reading stands.
        self.assertEqual(
            emulator_region_drops(selected, False, ["japan"]), {"scph5501.bin"}
        )



class UnknownRegionSaysWhatToType(unittest.TestCase):
    """`unknown region: 'uss'` named nothing to type instead."""

    def test_the_build_scripts_suggest_and_list_short_forms(self):
        import region

        with self.assertRaises(ValueError) as caught:
            region.parse_requested("uss")
        message = str(caught.exception)
        self.assertIn("Did you mean: us", message)
        self.assertIn("Short forms: jp", message)

    def test_the_installer_says_the_same(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "install_under_test", Path(__file__).resolve().parents[1] / "install.py"
        )
        install = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(install)
        with self.assertRaises(ValueError) as caught:
            install.canonical_region("europ")
        self.assertIn("Did you mean: europe", str(caught.exception))
        self.assertIn("Short forms:", str(caught.exception))


class CountryCodesNameTheirTerritory(unittest.TestCase):
    """`au` was unknown while `jp`, `us`, `kr` and `gb` were aliases, and the
    first spelling offered for it was `auto`, which means world."""

    def test_au_is_australia(self):
        self.assertEqual(region.parse_requested("au,jp"), ["australia", "japan"])

    def test_every_territory_answers_to_a_two_letter_code(self):
        areas = set(region.AREA_TERRITORIES)
        territories = {
            member for members in region.REGION_TREE.values() for member in members
        } - areas
        coded = {
            target for alias, target in region.ALIASES.items() if len(alias) == 2
        } | {slug for slug in territories if len(slug) == 2}
        self.assertEqual(territories - coded, set())



class GenesisPlusGxUsBiosServesEurope(unittest.TestCase):
    """sms_cart_region_detect returns REGION_USA for any export header
    outside the PAL CRC list, European cartridges included, and REGION_USA
    loads bios_U.sms. Tagged north-america only, --region eu,jp dropped it."""

    def test_eu_jp_keeps_bios_u(self):
        from pathlib import Path

        from common import load_emulator_profiles
        from region import build_region_index, parse_requested, resolve_region_drops

        root = Path(__file__).resolve().parents[1]
        profiles = load_emulator_profiles(str(root / "emulators"))
        for name in ("genesis_plus_gx", "genesis_plus_gx_wide"):
            with self.subTest(profile=name):
                index = build_region_index({name: profiles[name]})
                group = {"sega-mastersystem": [
                    (f"bios/{n}", n) for n in ("bios_U.sms", "bios_E.sms", "bios_J.sms")
                ]}
                drops = resolve_region_drops(
                    group, index, parse_requested("eu,jp"), None
                )
                self.assertNotIn("bios/bios_U.sms", drops)



def _real_drops(profile: str, members: list[str], requested: str) -> set[str]:
    from pathlib import Path

    from common import load_emulator_profiles
    from region import build_region_index, parse_requested, resolve_region_drops

    root = Path(__file__).resolve().parents[1]
    profiles = load_emulator_profiles(str(root / "emulators"))
    index = build_region_index({profile: profiles[profile]})
    group = {"g": [(m, m.rsplit("/", 1)[-1]) for m in members]}
    return resolve_region_drops(group, index, parse_requested(requested), None)


class MegaCdUsBiosIsTheDefaultBranch(unittest.TestCase):
    """GPGX and PicoDrive load the US Mega CD BIOS for any disc whose
    security byte is neither 0x64 nor 0xa1, Brazilian discs included:
    --region brazil,jp dropped it and those discs found no BIOS."""

    def test_brazil_keeps_the_us_bios(self):
        cases = {
            "genesis_plus_gx": ["bios_CD_U.bin", "bios_CD_E.bin", "bios_CD_J.bin"],
            "genesis_plus_gx_wide": ["bios_CD_U.bin", "bios_CD_E.bin", "bios_CD_J.bin"],
            "picodrive": ["us_scd2_9306.bin", "eu_mcd2_9306.bin", "jp_mcd2_921222.bin"],
        }
        for profile, members in cases.items():
            with self.subTest(profile=profile):
                drops = _real_drops(profile, members, "brazil,jp")
                self.assertNotIn(members[0], drops)


class KoreanGameCubeDiscsReadTheJapaneseIpl(unittest.TestCase):
    """Dolphin's ToGameCubeRegion maps NTSC-K to NTSC-J, so a Korean disc
    boots from GC/JAP/IPL.bin; --region south-korea,us dropped it."""

    def test_korea_keeps_the_jap_ipl(self):
        for profile in ("dolphin", "dolphin-mmjr", "dolphin-mmjr2", "ishiiruka",
                        "primehack", "triforce"):
            with self.subTest(profile=profile):
                from common import load_emulator_profiles

                entries = [
                    f for f in load_emulator_profiles("emulators")[profile]["files"]
                    if "JAP/" in (f.get("path") or "")
                ]
                self.assertTrue(entries)
                for entry in entries:
                    self.assertIn("south-korea", entry.get("region") or [])


class ANameNoCodeOpensCarriesNoRegion(unittest.TestCase):
    """Beetle PSX never opens scph5903.bin: its Japanese list and scan want
    scph5500.bin. Tagged japan, --region jp shipped a 1 MB file the core
    does not read and --region us removed it, on a selection that does not
    exist."""

    def test_scph5903_is_unregioned(self):
        from common import load_emulator_profiles

        entry = next(
            f for f in load_emulator_profiles("emulators")["beetle_psx"]["files"]
            if f["name"] == "scph5903.bin"
        )
        self.assertNotIn("region", entry)


class MegaCdAmericasIsOneCode(unittest.TestCase):
    """A Sega CD disc carries one region code for all the Americas, so every
    emulator picking the US BIOS by that code picks it for a Brazilian disc
    too. jgenesis, md-emu and ares tagged it north-america alone, and a
    --region brazil pack dropped the BIOS those discs boot with."""

    def test_a_us_mega_cd_bios_includes_latin_america(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        narrow = []
        for path in sorted((root / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in profile.get("files") or []:
                system = str(entry.get("system", ""))
                regions = entry.get("region") or []
                if system in ("sega-megacd", "mega-cd") and "north-america" in regions \
                        and "latin-america" not in regions:
                    narrow.append(f"{path.stem}: {entry.get('name')}")
        self.assertEqual(narrow, [])


class MegaCdEuropeServesOceania(unittest.TestCase):
    """A Mega CD disc carries one PAL code for Europe and Australia, so every
    emulator picking the European BIOS by that code picks it for an
    Australian disc too. blastem and kega-fusion tagged it europe alone, and a
    --region au,us pack dropped the BIOS those discs boot with."""

    def test_a_european_mega_cd_bios_includes_oceania(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        narrow = []
        for path in sorted((root / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in profile.get("files") or []:
                system = str(entry.get("system", ""))
                regions = entry.get("region") or []
                if system in ("sega-megacd", "mega-cd") and "europe" in regions \
                        and "oceania" not in regions:
                    narrow.append(f"{path.stem}: {entry.get('name')}")
        self.assertEqual(narrow, [])


class PcsxRearmedUsSlotIsTheDefault(unittest.TestCase):
    """CheckCdrom sets PSX_REGION_US before reading the licence and only
    "Inc." or "Euro pe" move it (libpcsxcore/misc.c:422-453): a disc of any
    other market boots the US slot."""

    def test_every_us_slot_bios_includes_latin_america(self):
        from common import load_emulator_profiles

        tagged = [
            f for f in load_emulator_profiles("emulators")["pcsx_rearmed"]["files"]
            if "north-america" in (f.get("region") or [])
        ]
        self.assertEqual(len(tagged), 4)
        for entry in tagged:
            with self.subTest(name=entry["name"]):
                self.assertIn("latin-america", entry["region"])


class PlayStationUsImageAnswersTheAmericaLicence(unittest.TestCase):
    """Every PlayStation core here picks its US image for a disc licensed by
    Sony Computer Entertainment America, the licence the Americas share:
    ares (mia/medium/playstation.cpp:66-73), Beetle PSX (libretro.c:2249-2254),
    Mednafen (psx.cpp:1372-1376), SwanStation and DuckStation
    (GetRegionFromSystemArea, plus every unread region), Rustation
    (src/cdrom/disc/mod.rs:81-90). Tagged north-america alone, a --region
    brazil,japan pack withdrew the image those discs boot with."""

    COUNTS = {"ares": 1, "beetle_psx": 1, "mednafen": 1, "swanstation": 1,
              "rustation": 6, "duckstation": 28}

    def test_every_us_image_includes_latin_america(self):
        from common import load_emulator_profiles

        profiles = load_emulator_profiles("emulators")
        for name, count in self.COUNTS.items():
            tagged = [
                f for f in profiles[name]["files"]
                if "north-america" in (f.get("region") or [])
                and f.get("system", "sony-playstation") == "sony-playstation"
            ]
            with self.subTest(profile=name):
                self.assertEqual(len(tagged), count)
            for entry in tagged:
                with self.subTest(profile=name, name=entry["name"]):
                    self.assertIn("latin-america", entry["region"])


class FusionSmsExportBiosFollowsTheSetting(unittest.TestCase):
    """Kega Fusion tells a Japanese Master System cart from an export one by
    the header, then picks USA or EUR from its CountryOrder setting or a CRC32
    list. Neither export BIOS is chosen for a territory the cart names."""

    def test_the_export_bioses_are_unregioned(self):
        from common import load_emulator_profiles

        files = {f["name"]: f for f in load_emulator_profiles("emulators")["kega-fusion"]["files"]}
        for name in ("bios_U.sms", "bios_E.sms"):
            with self.subTest(name=name):
                self.assertNotIn("region", files[name])


class NoMarketStopsAtAustralia(unittest.TestCase):
    """simple64 tagged its PAL PIF [europe, australia]. New Zealand is not
    under australia, so --region new-zealand kept only the NTSC PIF, though
    New Zealand carts carry the European or Australian PAL codes."""

    def test_no_profile_tags_australia_alone(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        tagged = [
            f"{path.stem}: {entry.get('name')}"
            for path in sorted((root / "emulators").glob("*.yml"))
            for entry in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("files") or []
            if "australia" in (entry.get("region") or [])
            and "new-zealand" not in (entry.get("region") or [])
        ]
        self.assertEqual(tagged, [])


class ARefusedRegionalFileHoldsNoSlot(unittest.TestCase):
    """rg_us.bin is held but its md5 contradicts the one the core checks, so
    the emulator pack refuses it. Counted held, it won the region and the
    Japanese BIOS was withdrawn: --emulator --region us shipped no BIOS for
    the system, and verify, reading the same drops, did not see it."""

    def test_the_fallback_stays_in_pack_and_report(self):
        import hashlib
        import shutil
        import tempfile
        import zipfile

        import yaml

        from generate_pack import generate_emulator_pack
        from verify import verify_emulator

        common._emulator_profiles_cache.clear()
        repo = Path(__file__).resolve().parents[1]
        (repo / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=repo / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        files, by_name = {}, {}
        for name, data in (("rg_us.bin", b"NOT THE US DUMP"), ("rg_jp.bin", b"JP DUMP")):
            path = Path("bios") / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            files[sha1] = {"path": str(path), "name": name, "size": len(data),
                           "md5": hashlib.md5(data).hexdigest()}
            by_name[name] = [sha1]
        db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                          "by_crc32": {}, "by_path_suffix": {}}}
        Path("emulators").mkdir()
        Path("emulators/rgemu.yml").write_text(yaml.safe_dump({
            "emulator": "RgEmu", "type": "libretro", "systems": ["sys"],
            "files": [
                {"name": "rg_us.bin", "region": ["north-america"], "required": True,
                 "md5": hashlib.md5(b"THE US DUMP").hexdigest(), "validation": ["md5"]},
                {"name": "rg_jp.bin", "region": ["japan"], "required": True},
            ],
        }))
        with contextlib.redirect_stdout(io.StringIO()):
            zip_path = generate_emulator_pack(
                ["rgemu"], "emulators", db, "bios", "out", regions=["north-america"],
                offline=True, platforms_dir="platforms",
            )
        with zipfile.ZipFile(zip_path) as zf:
            self.assertIn("rg_jp.bin", zf.namelist())
        report = verify_emulator(
            ["rgemu"], "emulators", db, regions=["north-america"], platforms_dir="platforms",
        )
        self.assertIn("rg_jp.bin", report["pack_destinations"])


class YmirLibretroRegions(unittest.TestCase):
    """ymir's libretro port gives sega_101.bin the Japan region and
    mpr-17933.bin US_EU (apps/ymir-libretro/src/libretro.cpp:596-606) and
    loads the candidate a region asks for (627-648, 1290-1306). One entry for
    all three names put no region on any of them."""

    def test_each_name_carries_the_region_the_port_gives_it(self):
        import yaml

        profile = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "emulators" / "ymir.yml").read_text()
        )
        libretro = {
            entry["name"]: entry for entry in profile["files"]
            if entry.get("mode") == "libretro"
            and entry["name"] in ("sega_101.bin", "mpr-17933.bin", "saturn_bios.bin")
        }
        self.assertEqual(sorted(libretro), ["mpr-17933.bin", "saturn_bios.bin", "sega_101.bin"])
        self.assertEqual(libretro["sega_101.bin"]["region"], ["japan"])
        self.assertTrue(
            {"north-america", "europe"} <= set(libretro["mpr-17933.bin"]["region"])
        )
        self.assertNotIn("japan", libretro["mpr-17933.bin"]["region"])
        self.assertNotIn("region", libretro["saturn_bios.bin"])
        self.assertEqual(
            [libretro[n]["priority"] for n in ("sega_101.bin", "mpr-17933.bin", "saturn_bios.bin")],
            [1, 2, 3],
        )
        self.assertFalse(any(e.get("aliases") for e in profile["files"]
                             if e["name"] == "sega_101.bin"))


class MachineModelRomsCarryNoTerritory(unittest.TestCase):
    """XRoar reads d200e_1.rom for the dragon200e machine and alice.rom for
    the alice machine (src/xroar.c:437-444, 552-558), and VICE the Japanese
    kernal and chargen for the C64 JAP and VIC-1001 models, which a file name
    tagged (Japan) never selects (libretro-core.c:2018-2034 sets NTSC). The
    site told a Spanish Dragon 64 owner to start with d200e_1.rom."""

    CASES = {
        "xroar": ("d200e_1.rom", "d200e_2.rom", "d200e_26.rom", "alice.rom"),
        "x64sdl": ("jpkernal", "jpchrgen"),
        "vice_xvic": ("kernal.901486-02.bin", "chargen-901460-02.bin"),
    }

    def test_model_roms_are_unregioned(self):
        profiles = common.load_emulator_profiles(
            os.path.join(os.path.dirname(__file__), "..", "emulators")
        )
        for profile, names in self.CASES.items():
            for entry in profiles[profile]["files"]:
                if entry["name"] in names:
                    with self.subTest(profile=profile, name=entry["name"]):
                        self.assertNotIn("region", entry)
        self.assertFalse(
            [e["name"] for e in profiles["c64-emu"]["files"] if e.get("region")]
        )


class UsaRegionServesTheAmericas(unittest.TestCase):
    """A code that knows a USA region and no Latin America one selects the
    USA file there: Citra's shared font for CFG USA is 0x00014002
    (apt.cpp:128-140), and a --region br,cn pack dropped it for the Chinese
    archive alone."""

    PROFILE = Path(__file__).resolve().parents[1] / "emulators" / "citra-mmj.yml"
    FONT = (
        "nand/00000000000000000000000000000000/title/0004009b/00014002/"
        "content/00000000.app.romfs"
    )

    def test_brazil_ranks_the_default_shared_font(self):
        import yaml

        profile = yaml.safe_load(self.PROFILE.read_text(encoding="utf-8"))
        index = region.build_region_index({"citra-mmj": profile})
        requested = region.parse_requested("br,cn")
        for destination, name in (
            (self.FONT, "00000000.app.romfs"),
            ("sysdata/cbf_std.bcfnt", "cbf_std.bcfnt"),
        ):
            with self.subTest(file=destination):
                regions = region.lookup_regions(index, destination, name)
                self.assertEqual(region.rank(regions, requested), 0)

    def test_brazil_ranks_the_usa_dsi_nand_before_the_japanese_one(self):
        """BizHawk's DecideNAND knows JPN, USA, EUR, AUS, CHN and KOR region
        bits (MelonDS.cs:684-706): a DSi title from the Americas carries USA."""
        import yaml

        bizhawk = self.PROFILE.with_name("bizhawk.yml")
        profile = yaml.safe_load(bizhawk.read_text(encoding="utf-8"))
        index = region.build_region_index({"bizhawk": profile})
        requested = region.parse_requested("br,jp")
        usa = region.lookup_regions(index, "", "DSi_Nand_USA.bin")
        jpn = region.lookup_regions(index, "", "DSi_Nand_JPN.bin")
        self.assertEqual(region.rank(usa, requested), 0)
        self.assertEqual(region.rank(jpn, requested), 1)


class RegionWordsInAPackReadme(unittest.TestCase):
    """The pack README title-cased each slug: asia-ntsc read "Asia Ntsc"."""

    def test_the_priority_line_reads_as_written(self):
        from packreadme import _build_readme  # noqa: PLC0415

        readme = _build_readme(
            "retroarch", "RetroArch", "system", 1, 1,
            regions=region.parse_requested("us,asia-ntsc,jp"),
        )
        self.assertIn("Region priority: North America, Asia (NTSC), Japan", readme)

    def test_every_region_has_a_label(self):
        for slug in region.REGIONS:
            with self.subTest(slug=slug):
                self.assertNotRegex(region.label(slug), r"\bNtsc\b|\bPal\b|\bUk\b")


if __name__ == "__main__":
    unittest.main()
