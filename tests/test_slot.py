"""Slot resolution: keep one BIOS per slot only where the code declares an order."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import slot


def _pairs(*names: str) -> list[tuple[str, str]]:
    return [(n, n) for n in names]


class TestSlotIndex(unittest.TestCase):
    def setUp(self):
        self.index = slot.build_slot_index(
            {
                "picodrive": {
                    "files": [
                        {"name": "us_scd2_9306.bin", "search_rank": 1},
                        {"name": "SegaCDBIOS9303.bin", "search_rank": 2},
                        {"name": "us_scd1_9210.bin", "search_rank": 3},
                        {"name": "bios_CD_U.bin", "search_rank": 4},
                    ]
                },
                "duckstation": {
                    "files": [
                        {"name": "scph5501.bin", "priority": 5},
                        {"name": "scph1001.bin", "priority": 10},
                    ]
                },
                "launcher_profile": {
                    "type": "launcher",
                    "files": [{"name": "ignored.bin", "search_rank": 1}],
                },
                "engine": {
                    "files": [
                        {"name": "assets.pk3", "category": "game_data",
                         "search_rank": 1},
                    ]
                },
            }
        )

    def test_search_rank_is_indexed(self):
        self.assertEqual(self.index["us_scd2_9306.bin"]["rank"], 1)

    def test_priority_is_not_read(self):
        self.assertIsNone(self.index["scph5501.bin"]["rank"])

    def test_launcher_profiles_are_skipped(self):
        self.assertNotIn("ignored.bin", self.index)

    def test_non_bios_categories_are_skipped(self):
        self.assertNotIn("assets.pk3", self.index)

    def test_lookup_falls_back_from_destination_to_name(self):
        entry = slot.lookup_slot(
            self.index, "picodrive/us_scd2_9306.bin", "us_scd2_9306.bin"
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry["rank"], 1)


class TestResolveSlotDrops(unittest.TestCase):
    def setUp(self):
        self.index = slot.build_slot_index(
            {
                "picodrive": {
                    "files": [
                        {"name": "a.bin", "search_rank": 1},
                        {"name": "b.bin", "search_rank": 2},
                        {"name": "c.bin", "search_rank": 3},
                    ]
                },
                "other": {
                    "files": [
                        {"name": "x.bin"},
                        {"name": "y.bin"},
                        {"name": "tie1.bin", "search_rank": 1},
                        {"name": "tie2.bin", "search_rank": 1},
                    ]
                },
            }
        )

    def test_first_rank_wins_and_the_rest_drop(self):
        drops, undecidable = slot.resolve_slot_drops(
            {"segacd|us": _pairs("a.bin", "b.bin", "c.bin")}, self.index
        )
        self.assertEqual(drops, {"b.bin", "c.bin"})
        self.assertEqual(undecidable, [])

    def test_an_unranked_candidate_makes_the_group_undecidable(self):
        drops, undecidable = slot.resolve_slot_drops(
            {"psx|us": _pairs("a.bin", "x.bin")}, self.index
        )
        self.assertEqual(drops, set())
        self.assertEqual(undecidable, ["psx|us"])

    def test_no_rank_at_all_is_undecidable(self):
        drops, undecidable = slot.resolve_slot_drops(
            {"psx|us": _pairs("x.bin", "y.bin")}, self.index
        )
        self.assertEqual(drops, set())
        self.assertEqual(undecidable, ["psx|us"])

    def test_a_tie_on_the_first_rank_is_undecidable(self):
        drops, undecidable = slot.resolve_slot_drops(
            {"t|us": _pairs("tie1.bin", "tie2.bin")}, self.index
        )
        self.assertEqual(drops, set())
        self.assertEqual(undecidable, ["t|us"])

    def test_a_lone_candidate_is_never_dropped(self):
        drops, undecidable = slot.resolve_slot_drops(
            {"solo|us": _pairs("b.bin")}, self.index
        )
        self.assertEqual(drops, set())
        self.assertEqual(undecidable, [])

    def test_a_destination_kept_by_another_group_survives(self):
        drops, _u = slot.resolve_slot_drops(
            {
                "segacd|us": _pairs("a.bin", "b.bin", "c.bin"),
                "segacd|world": _pairs("b.bin"),
            },
            self.index,
        )
        self.assertNotIn("b.bin", drops)

    def test_unknown_files_are_never_dropped(self):
        drops, undecidable = slot.resolve_slot_drops(
            {"u|us": _pairs("a.bin", "b.bin", "nowhere.bin")}, self.index
        )
        self.assertNotIn("nowhere.bin", drops)


class TestRepoProfiles(unittest.TestCase):
    def test_declared_ranks_are_positive_and_unique_per_group(self):
        import collections
        import glob

        import yaml

        paths = sorted(
            glob.glob(
                os.path.join(os.path.dirname(__file__), "..", "emulators", "*.yml")
            )
        )
        if not paths:
            self.skipTest("emulators/ not present")
        offenders: list[str] = []
        for path in paths:
            with open(path, encoding="utf-8") as fh:
                profile = yaml.safe_load(fh) or {}
            groups: dict[tuple, list[int]] = collections.defaultdict(list)
            for f in profile.get("files") or []:
                if not isinstance(f, dict) or f.get("search_rank") is None:
                    continue
                rank = f["search_rank"]
                if not isinstance(rank, int) or rank < 1:
                    offenders.append(f"{os.path.basename(path)}: {f.get('name')}")
                    continue
                key = (f.get("system", ""), tuple(f.get("region") or []))
                groups[key].append(rank)
            for key, ranks in groups.items():
                if len(ranks) != len(set(ranks)):
                    offenders.append(
                        f"{os.path.basename(path)}: duplicate rank in {key}"
                    )
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
