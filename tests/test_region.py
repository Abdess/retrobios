"""Region vocabulary, hierarchy, and rank resolution."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import region


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

    def test_no_requested_regions_reports_nothing(self):
        groups = {"fds": [("disksys.rom", "disksys.rom")]}
        self.assertEqual(region.fallback_groups(groups, self.index, []), [])


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
        import subprocess

        repo = os.path.join(os.path.dirname(__file__), "..")
        return subprocess.run(
            [sys.executable, "scripts/verify.py", *args],
            capture_output=True, text=True, cwd=repo, timeout=900,
        ).stdout

    def test_emulator_mode_narrows(self):
        plain = self._run("--emulator", "duckstation")
        filtered = self._run("--emulator", "duckstation", "--region", "us")
        if "duckstation" not in plain:
            self.skipTest("duckstation profile not present")
        self.assertNotEqual(plain, filtered)

    def test_system_mode_narrows(self):
        plain = self._run("--system", "sony-playstation")
        filtered = self._run("--system", "sony-playstation", "--region", "us")
        if not plain.strip():
            self.skipTest("system not present")
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
                supplemental_names=set(),
            )
            narrowed = reporter.verify_platform(
                config, db, str(root / "emulators"), profiles,
                supplemental_names=set(), regions=["north-america"],
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

    def test_one_grouping_pass_serves_both_sides(self):
        """A second hand-rolled grouping is how the two drifted apart."""
        scripts = Path(__file__).resolve().parent.parent / "scripts"
        hand_rolled = 0
        for name in ("generate_pack.py", "verify.py"):
            for line in (scripts / name).read_text().splitlines():
                if "region_groups.setdefault(" in line:
                    hand_rolled += 1
        self.assertLessEqual(
            hand_rolled, 2,
            "platform region grouping belongs to platform_region_groups; "
            "the only other pass is the per-emulator pack shape",
        )


if __name__ == "__main__":
    unittest.main()
