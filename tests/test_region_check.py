"""region_check: the variants a region game runs under and what their
records settle."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import region_check as rc  # noqa: E402

PROFILE = {
    "systems": ["sony-playstation"],
    "files": [
        {"name": "scph5500.bin", "region": ["japan"]},
        {"name": "scph5501.bin", "region": ["north-america", "latin-america"]},
        {"name": "scph5502.bin", "region": ["europe", "oceania"]},
        {"name": "openbios.bin"},
        {"name": "ps1_rom.bin", "region": ["world"]},
        {"name": "standalone.bin", "region": ["japan"], "mode": "standalone"},
        {"name": "other.bin", "region": ["japan"], "system": "sony-playstation-2"},
    ],
}


def record(rid: str, staged: list[str], opened: list[str], hashes: list, verdict: str = "unknown",
           loaded: bool = True, bios_used: str = "unknown") -> dict:
    return {"id": rid, "variants": [{
        "label": "default", "verdict": verdict, "bios_used": bios_used,
        "system_files": {name: "0" * 40 for name in staged},
        "repetitions": [{"loaded": loaded, "files_opened": [{"path": p} for p in opened],
                         "observables": {"frame_hashes": hashes}}]}]}


class Entries(unittest.TestCase):
    def test_only_regional_bios_of_the_system_in_the_libretro_build(self) -> None:
        names = [e["name"] for e in rc.region_entries(PROFILE, "sony-playstation")]
        self.assertEqual(names, ["scph5500.bin", "scph5501.bin", "scph5502.bin"])

    def test_variants_split_by_the_game_region(self) -> None:
        entries = rc.region_entries(PROFILE, "sony-playstation")
        plan = rc.plan_variants(entries, "japan", lambda e: Path("/bios") / e["name"])
        self.assertEqual(sorted(plan["full"]), ["scph5500.bin", "scph5501.bin", "scph5502.bin"])
        self.assertEqual(sorted(plan["own"]), ["scph5500.bin"])
        self.assertEqual(sorted(plan["others"]), ["scph5501.bin", "scph5502.bin"])

    def test_a_file_the_collection_lacks_is_in_no_variant(self) -> None:
        entries = rc.region_entries(PROFILE, "sony-playstation")
        plan = rc.plan_variants(entries, "europe",
                                lambda e: None if e["name"] == "scph5502.bin" else Path(e["name"]))
        self.assertEqual(plan["own"], {})
        self.assertNotIn("scph5502.bin", plan["full"])

    def test_subject_names_core_game_and_variant(self) -> None:
        slug = rc.subject("mednafen_psx", "Puzzle Bobble 2 (Japan)", "own")
        self.assertEqual(slug, "region-mednafen_psx-puzzle-bobble-2-japan-own")
        self.assertRegex(slug, rc.SUBJECT)


class BusyHost(unittest.TestCase):
    def _run(self, codes: list[int], max_wait: float) -> tuple[int, int]:
        import subprocess

        now = [0.0]
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, codes[min(len(calls), len(codes)) - 1], "", "")

        def pause(seconds: float) -> None:
            now[0] += seconds

        proc = rc.probe_when_idle(["probe"], max_wait, clock=lambda: now[0], pause=pause, runner=runner)
        return proc.returncode, len(calls)

    def test_a_refused_run_is_tried_again_once_the_host_settles(self) -> None:
        self.assertEqual(self._run([rc.BUSY, rc.BUSY, 0], 600), (0, 3))

    def test_it_gives_up_after_the_wait(self) -> None:
        code, calls = self._run([rc.BUSY], 60)
        self.assertEqual(code, rc.BUSY)
        self.assertEqual(calls, 60 // rc.POLL_S + 1)

    def test_another_failure_is_not_retried(self) -> None:
        self.assertEqual(self._run([1, 0], 600), (1, 1))


class Outcome(unittest.TestCase):
    ENTRIES = rc.region_entries(PROFILE, "sony-playstation")
    ALL = ["scph5500.bin", "scph5501.bin", "scph5502.bin"]

    def test_locked_bios_by_verdict(self) -> None:
        records = {
            "full": record("f", self.ALL, ["scph5500.bin"], [[0, "a"]], "boots"),
            "own": record("o", ["scph5500.bin"], ["scph5500.bin"], [[0, "a"]], "boots"),
            "others": record("x", self.ALL[1:], [], [[0, "b"]], "bios_error", loaded=False),
            "pack": record("p", ["scph5500.bin"], ["scph5500.bin"], [[0, "a"]], "boots"),
        }
        result = rc.outcome(records, self.ENTRIES, "japan")
        self.assertEqual(result["selected"], ["scph5500.bin"])
        self.assertEqual(result["claim"], "confirmed")
        self.assertEqual((result["own_boots"], result["others_boot"], result["pack_boots"]),
                         (True, False, True))
        self.assertEqual(result["judged_by"], "verdict")
        self.assertEqual(rc.sentence("japan", result),
                         "The Japanese BIOS boots the Japanese game, the other regions' BIOS do not.")

    def test_interim_rule_counts_the_same_frames_as_a_boot_and_nothing_else(self) -> None:
        records = {
            "full": record("f", self.ALL, ["scph5501.bin"], [[0, "a"], [10, "b"]]),
            "own": record("o", ["scph5501.bin"], ["scph5501.bin"], [[0, "a"], [10, "b"]]),
            "others": record("x", ["scph5500.bin", "scph5502.bin"], ["scph5500.bin"], [[0, "a"], [10, "c"]]),
        }
        result = rc.outcome(records, self.ENTRIES, "north-america")
        self.assertEqual(result["judged_by"], "full_run_frames")
        self.assertTrue(result["own_boots"])
        # Other frames are no verdict: a US disc reaches its game on the
        # Japanese BIOS through another licence screen.
        self.assertIsNone(result["others_boot"])
        self.assertIsNone(result["pack_boots"])
        self.assertEqual(rc.sentence("north-america", result),
                         "The US BIOS boots the US game. The other regions' BIOS have no verdict yet.")

    def test_no_interim_answer_when_the_full_run_fails(self) -> None:
        records = {"full": record("f", self.ALL, [], [[0, "a"]], "bios_error"),
                   "own": record("o", ["scph5502.bin"], [], [[0, "a"]])}
        result = rc.outcome(records, self.ENTRIES, "europe")
        self.assertIsNone(result["own_boots"])
        self.assertEqual(result["claim"], "unread")

    def test_a_core_reading_another_region_contradicts_the_claim(self) -> None:
        records = {"full": record("f", self.ALL, ["scph5501.bin"], [[0, "a"]], "boots")}
        self.assertEqual(rc.outcome(records, self.ENTRIES, "japan")["claim"], "contradicted")

    def test_a_core_opening_every_region_file_settles_nothing(self) -> None:
        """PCSX-ReARMed opens the three regional files whatever the disc."""
        records = {"full": record("f", self.ALL, self.ALL, [[0, "a"]], "boots")}
        self.assertEqual(rc.outcome(records, self.ENTRIES, "japan")["claim"], "ambiguous")

    def test_region_free_bios(self) -> None:
        records = {"full": record("f", self.ALL, ["scph5501.bin"], [[0, "a"]], "boots"),
                   "own": record("o", ["scph5502.bin"], [], [[0, "a"]], "boots"),
                   "others": record("x", ["scph5501.bin"], ["scph5501.bin"], [[0, "a"]], "boots")}
        result = rc.outcome(records, self.ENTRIES, "europe")
        # The log names no BIOS: the boot is not said to be the other region's.
        self.assertEqual(rc.sentence("europe", result),
                         "The European BIOS boots the European game, and with the others' files on a "
                         "BIOS its log does not name.")
        records["others"] = record("x", ["scph5501.bin"], ["scph5501.bin"], [[0, "a"]], "boots",
                                   bios_used="staged:scph5501.bin")
        self.assertEqual(rc.sentence("europe", rc.outcome(records, self.ENTRIES, "europe")),
                         "The European BIOS boots the European game, and so does scph5501.bin, "
                         "another region's BIOS.")

    def test_a_boot_on_the_built_in_bios_is_never_another_regions(self) -> None:
        """Beetle PSX logs "Firmware is missing" and maps OpenBIOS: the other
        regions' files were opened, hashed and refused."""
        records = {"full": record("f", self.ALL, self.ALL, [[0, "a"]], "boots",
                                  bios_used="staged:scph5501.bin"),
                   "own": record("o", ["scph5501.bin"], ["scph5501.bin"], [[0, "a"]], "boots",
                                 bios_used="staged:scph5501.bin"),
                   "others": record("x", ["scph5500.bin", "scph5502.bin"], ["scph5500.bin", "scph5502.bin"],
                                    [[0, "a"]], "boots", bios_used="builtin")}
        result = rc.outcome(records, self.ENTRIES, "north-america")
        text = rc.sentence("north-america", result)
        self.assertEqual(text, "The US BIOS boots the US game, and on its built-in BIOS with the "
                               "others' files refused.")
        self.assertNotIn("so do the other regions", text)

    def test_no_own_run(self) -> None:
        self.assertEqual(rc.sentence("japan", rc.outcome({}, self.ENTRIES, "japan")),
                         "The Japanese game has no run with its own BIOS yet.")


class ContentList(unittest.TestCase):
    def test_every_region_system_has_a_game_per_region_or_says_why(self) -> None:
        """A system whose BIOS a profile ties to JP, US and EU has a game for
        each of the three, or the content list says why it has none."""
        from common import load_emulator_profiles

        import yaml

        data = yaml.safe_load(rc.CONTENT_FILE.read_text(encoding="utf-8"))
        content = rc.load_content()
        uncovered = data.get("uncovered") or {}
        profiles = load_emulator_profiles(str(ROOT / "emulators"))
        regional: set[str] = set()
        for profile in profiles.values():
            for system in profile.get("systems") or ():
                regions = {r for e in rc.region_entries(profile, system) for r in rc.regions_of(e)}
                if {"japan", "north-america", "europe"} <= regions:
                    regional.add(system)
        for system in sorted(regional):
            if system in uncovered:
                continue
            held = {item.get("region") for item in content.get(system, [])}
            missing = {"japan", "north-america", "europe"} - held
            # One cartridge sold in two territories counts for both.
            missing -= {r for item in content.get(system, []) for r in item.get("also_regions") or ()}
            self.assertFalse(missing, f"{system}: no game for {sorted(missing)}")


class RequiredFromTheRegionRuns(unittest.TestCase):
    def test_beetle_psx_boots_each_region_without_its_bios(self) -> None:
        """libretro.c maps its built-in OpenBIOS when the region's file is
        absent: the evidence of required: false is a record where the file
        was not staged and the oracle judged the run a boot."""
        import json

        import yaml

        profile = yaml.safe_load((ROOT / "emulators" / "beetle_psx.yml").read_text(encoding="utf-8"))
        records = {}
        for line in (ROOT / "measurements" / "beetle_psx.jsonl").read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            records[record["id"]] = record
        regional = [e for e in profile["files"] if e["name"] in ("scph5500.bin", "scph5501.bin", "scph5502.bin")]
        self.assertEqual(len(regional), 3)
        for entry in regional:
            with self.subTest(entry=entry["name"]):
                self.assertIs(entry["required"], False)
                self.assertIn("3425-3511", entry["source_ref"])
                ids = entry["evidence"]["required"]
                self.assertTrue(ids)
                for rid in ids:
                    record = records[rid]
                    self.assertEqual(record["record_version"], 5)
                    variant = record["variants"][0]
                    self.assertNotIn(entry["name"], variant["system_files"])
                    self.assertEqual(variant["verdict"], "boots")
                    # The boot was on OpenBIOS, never on another region's file.
                    self.assertEqual(variant["bios_used"], "builtin")
                    self.assertIn("OpenBIOS", entry["note"])
                    self.assertIn("game", variant["verdict_evidence"].get("stages", []))


class SitePages(unittest.TestCase):
    def test_a_region_run_reaches_a_page_only_as_the_proof_of_a_field(self) -> None:
        """No page shows region outcomes. The Beetle PSX page names the runs
        its required: false rests on, each with the BIOS the core ran."""
        import measurement_records as mr
        import sitemeasurements as sm

        stored = mr.read_records(ROOT)
        index = sm.build_index(stored, {"repo": sm.REPO, "commit": "0" * 40}, sm.load_profiles(ROOT / "emulators"),
                               None, sm.load_observations(ROOT / sm.OBSERVATIONS))
        items = sm.by_emulator(index).get("beetle_psx") or []
        if not items:
            self.skipTest("no beetle_psx record")
        text = "\n".join(sm.proof_section(items))
        self.assertNotIn("Region check", text)
        lines = [line for line in text.splitlines() if line.startswith("- ")]
        required = [line for line in lines if line.startswith("- required of scph55")]
        self.assertEqual(len(required), 3)
        for line in required:
            # The run staged only the other regions' files and booted OpenBIOS.
            self.assertIn("it boots on the core&#x27;s built-in BIOS", line)
            self.assertIn(", it boots", line)


if __name__ == "__main__":
    unittest.main()
