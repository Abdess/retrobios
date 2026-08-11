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
                        {"name": "us_scd2_9306.bin", "priority": 1},
                        {"name": "SegaCDBIOS9303.bin", "priority": 2},
                        {"name": "us_scd1_9210.bin", "priority": 3},
                        {"name": "bios_CD_U.bin", "priority": 4},
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
                    "files": [{"name": "ignored.bin", "priority": 1}],
                },
                "engine": {
                    "files": [
                        {"name": "assets.pk3", "category": "game_data",
                         "priority": 1},
                    ]
                },
            }
        )

    def test_priority_is_indexed(self):
        self.assertEqual(self.index["us_scd2_9306.bin"]["rank"], 1)

    def test_duckstation_priorities_are_read(self):
        self.assertEqual(self.index["scph5501.bin"]["rank"], 5)

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
                        {"name": "a.bin", "priority": 1},
                        {"name": "b.bin", "priority": 2},
                        {"name": "c.bin", "priority": 3},
                    ]
                },
                "other": {
                    "files": [
                        {"name": "x.bin"},
                        {"name": "y.bin"},
                        {"name": "tie1.bin", "priority": 1},
                        {"name": "tie2.bin", "priority": 1},
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
    """Guards on the real profiles, not on synthetic fixtures."""

    def setUp(self):
        import glob

        import yaml

        self.paths = sorted(
            glob.glob(
                os.path.join(os.path.dirname(__file__), "..", "emulators", "*.yml")
            )
        )
        if not self.paths:
            self.skipTest("emulators/ not present")
        self.profiles = {}
        for path in self.paths:
            with open(path, encoding="utf-8") as fh:
                self.profiles[os.path.basename(path)[:-4]] = yaml.safe_load(fh) or {}

    def test_declared_priorities_are_non_negative_integers(self):
        offenders = [
            f"{name}: {f.get('name')} -> {f['priority']!r}"
            for name, profile in self.profiles.items()
            for f in (profile.get("files") or [])
            if isinstance(f, dict)
            and f.get("priority") is not None
            and (not isinstance(f["priority"], int) or f["priority"] < 0)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_lowest_priority_picks_the_reference_playstation_bios(self):
        """DuckStation ranks scph5501 at 5 and de-prioritizes by raising the
        number, so on its own scale the US slot resolves to it. The merged
        index is a different story: pcsx1 disagrees, and the conflict test
        below asserts that neither order wins there."""
        index = slot.build_slot_index(
            {"duckstation": self.profiles["duckstation"]}
        )
        ds = self.profiles.get("duckstation")
        if not ds:
            self.skipTest("duckstation profile not present")
        members = [
            (f["name"], f["name"])
            for f in ds["files"]
            if f.get("region") == ["north-america"] and f.get("priority") is not None
        ]
        if len(members) < 2:
            self.skipTest("no US candidate set to decide")
        drops, undecidable = slot.resolve_slot_drops(
            {"sony-playstation": members}, index
        )
        self.assertEqual(undecidable, [])
        kept = {n for n, _ in members} - drops
        self.assertEqual(kept, {"scph5501.bin"})

    def test_conflicting_cross_profile_orders_decide_nothing(self):
        """pcsx1 walks scph1001 first; DuckStation prefers scph5501. The pack
        serves both cores, so neither order may drop the other's first pick."""
        index = slot.build_slot_index(self.profiles)
        for name in ("scph1001.bin", "scph5501.bin"):
            entry = index.get(name)
            if entry is None:
                self.skipTest(f"{name} not in any profile")
        if not index["scph1001.bin"].get("conflict"):
            self.skipTest("no conflicting ranks declared yet")
        drops, _u = slot.resolve_slot_drops(
            {"psx": _pairs("scph1001.bin", "scph5501.bin", "scph7001.bin")},
            index,
        )
        self.assertEqual(drops & {"scph1001.bin", "scph5501.bin"}, set())

    def test_numero_search_order_decides_its_slot(self):
        """numero is alone on ti-83 and ranks all three ROMs, so this is the
        one slot the repo can currently decide end to end."""
        index = slot.build_slot_index(self.profiles)
        if "ti83se.rom" not in index:
            self.skipTest("numero profile not present")
        drops, undecidable = slot.resolve_slot_drops(
            {"ti-83": _pairs("ti83se.rom", "ti83plus.rom", "ti83.rom")}, index
        )
        self.assertEqual(drops, {"ti83plus.rom", "ti83.rom"})
        self.assertEqual(undecidable, [])

    def test_ties_leave_the_group_untouched(self):
        """Japanese PlayStation ties at 5, so nothing may be dropped there."""
        index = slot.build_slot_index(self.profiles)
        ds = self.profiles.get("duckstation")
        if not ds:
            self.skipTest("duckstation profile not present")
        members = [
            (f["name"], f["name"])
            for f in ds["files"]
            if f.get("region") == ["japan"] and f.get("priority") is not None
        ]
        drops, undecidable = slot.resolve_slot_drops(
            {"sony-playstation": members}, index
        )
        self.assertEqual(drops, set())
        self.assertEqual(undecidable, ["sony-playstation|japan"])


if __name__ == "__main__":
    unittest.main()
