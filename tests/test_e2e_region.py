"""End-to-end region filtering, pack narrowings and gap analysis."""

from __future__ import annotations

import tests
from tests.sources import script_source
import os
import sys
import unittest
import zipfile
import yaml
from tests.e2esupport import E2EFixture


class TestE2ERegion(E2EFixture):
    """Region filter, narrowing names and the reports that follow them."""

    # ---------------------------------------------------------------
    # Region filter
    # ---------------------------------------------------------------

    def _region_profiles(self) -> dict:
        return {
            "rgncore": {
                "emulator": "RegionCore",
                "type": "libretro",
                "cores": ["rgncore"],
                "systems": ["region-console"],
                "files": [
                    {"name": "rgn_us.bin", "region": ["north-america"]},
                    {"name": "rgn_jp.bin", "region": ["japan"]},
                    {"name": "rgn_eu.bin", "region": ["europe"]},
                    {"name": "rgn_world.bin", "region": ["world"]},
                    {"name": "rgn_plain.bin"},
                ],
            }
        }

    def _create_region_fixtures(self) -> None:
        names = (
            "rgn_us.bin",
            "rgn_jp.bin",
            "rgn_eu.bin",
            "rgn_world.bin",
            "rgn_plain.bin",
        )
        for name in names:
            self._make_file(name, name.encode())
        self.db = self._build_db()
        config = {
            "platform": "RegionPlat",
            "version": "3.0",
            "verification_mode": "existence",
            "systems": {
                "region-console": {
                    "files": [
                        {
                            "name": n,
                            "destination": n,
                            "required": n
                            in ("rgn_us.bin", "rgn_jp.bin", "rgn_eu.bin"),
                        }
                        for n in names
                    ]
                }
            },
        }
        with open(
            os.path.join(self.platforms_dir, "regionplat.yml"), "w", encoding="utf-8"
        ) as fh:
            yaml.safe_dump(config, fh)

    def _region_pack(self, **kwargs) -> str:
        from packs.platformpack import generate_pack

        self._create_region_fixtures()
        out = generate_pack(
            "regionplat",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            self.root,
            emu_profiles=self._region_profiles(),
            **kwargs,
        )
        self.assertIsNotNone(out)
        return out

    @staticmethod
    def _names_in(zip_path: str) -> set[str]:
        with zipfile.ZipFile(zip_path) as zf:
            return {os.path.basename(n) for n in zf.namelist()}

    def test_region_filter_drops_other_regions(self):
        names = self._names_in(self._region_pack(regions=["north-america"]))
        self.assertIn("rgn_us.bin", names)
        self.assertNotIn("rgn_jp.bin", names)
        self.assertNotIn("rgn_eu.bin", names)

    def test_region_priority_selects_second_choice(self):
        names = self._names_in(self._region_pack(regions=["oceania", "europe"]))
        self.assertIn("rgn_eu.bin", names)
        self.assertNotIn("rgn_us.bin", names)
        self.assertNotIn("rgn_jp.bin", names)

    def test_region_filter_uses_world_when_no_regional_match(self):
        names = self._names_in(self._region_pack(regions=["oceania"]))
        self.assertIn("rgn_world.bin", names)
        for expected in ("rgn_us.bin", "rgn_jp.bin", "rgn_eu.bin"):
            self.assertNotIn(expected, names)

    def test_region_filter_keeps_untagged_and_world(self):
        names = self._names_in(self._region_pack(regions=["north-america"]))
        self.assertIn("rgn_plain.bin", names)
        self.assertIn("rgn_world.bin", names)

    def test_region_tag_in_pack_name(self):
        out = self._region_pack(regions=["north-america", "japan"])
        self.assertIn("NorthAmerica_Japan", os.path.basename(out))

    def test_no_region_argument_changes_nothing(self):
        names = self._names_in(self._region_pack())
        for expected in (
            "rgn_us.bin",
            "rgn_jp.bin",
            "rgn_eu.bin",
            "rgn_plain.bin",
            "rgn_world.bin",
        ):
            self.assertIn(expected, names)

    def test_region_composes_with_required_only(self):
        out = self._region_pack(regions=["north-america"], required_only=True)
        names = self._names_in(out)
        self.assertIn("rgn_us.bin", names)
        self.assertNotIn("rgn_jp.bin", names)
        self.assertNotIn("rgn_eu.bin", names)
        self.assertIn("NorthAmerica", os.path.basename(out))
        self.assertIn("Required", os.path.basename(out))

    def test_region_composes_with_source_platform(self):
        names = self._names_in(
            self._region_pack(regions=["north-america"], source="platform")
        )
        self.assertIn("rgn_us.bin", names)
        self.assertNotIn("rgn_jp.bin", names)
        self.assertNotIn("rgn_eu.bin", names)
        self.assertIn("rgn_world.bin", names)
        self.assertIn("rgn_plain.bin", names)

    def test_region_composes_with_split(self):
        from packs.platformpack import generate_split_packs

        self._create_region_fixtures()
        paths = generate_split_packs(
            "regionplat",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            self.root,
            emu_profiles=self._region_profiles(),
            regions=["north-america"],
            offline=True,
        )
        self.assertTrue(paths)
        for p in paths:
            self.assertIn("NorthAmerica", os.path.basename(p))
            names = self._names_in(p)
            self.assertNotIn("rgn_jp.bin", names)
            self.assertNotIn("rgn_eu.bin", names)

    def test_region_composes_with_split_and_target(self):
        from packs.platformpack import generate_split_packs

        self._create_region_fixtures()
        paths = generate_split_packs(
            "regionplat",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            self.root,
            emu_profiles=self._region_profiles(),
            target_cores={"rgncore"},
            regions=["north-america"],
        )
        self.assertTrue(paths)
        for p in paths:
            self.assertIn("NorthAmerica", os.path.basename(p))
            names = self._names_in(p)
            self.assertNotIn("rgn_jp.bin", names)
            self.assertNotIn("rgn_eu.bin", names)
        self.assertTrue(
            any("rgn_us.bin" in self._names_in(p) for p in paths),
            "target filtering removed the whole system",
        )

    def test_region_composes_with_manifest(self):
        from packs.manifest import generate_manifest

        self._create_region_fixtures()
        registry_path = os.path.join(self.platforms_dir, "_registry.yml")
        if not os.path.exists(registry_path):
            with open(registry_path, "w", encoding="utf-8") as fh:
                yaml.safe_dump({"platforms": {}}, fh)
        manifest = generate_manifest(
            "regionplat",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            registry_path,
            emu_profiles=self._region_profiles(),
            regions=["north-america"],
        )
        packed = {os.path.basename(f["dest"]) for f in manifest["files"]}
        self.assertEqual(manifest["regions"], ["north-america"])
        self.assertIn("rgn_us.bin", packed)
        self.assertNotIn("rgn_jp.bin", packed)
        self.assertNotIn("rgn_eu.bin", packed)

    def test_manifest_without_region_keeps_every_variant(self):
        from packs.manifest import generate_manifest

        self._create_region_fixtures()
        registry_path = os.path.join(self.platforms_dir, "_registry.yml")
        if not os.path.exists(registry_path):
            with open(registry_path, "w", encoding="utf-8") as fh:
                yaml.safe_dump({"platforms": {}}, fh)
        manifest = generate_manifest(
            "regionplat",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            registry_path,
            emu_profiles=self._region_profiles(),
            offline=True,
        )
        packed = {os.path.basename(f["dest"]) for f in manifest["files"]}
        for expected in ("rgn_us.bin", "rgn_jp.bin", "rgn_eu.bin"):
            self.assertIn(expected, packed)

    def test_region_composes_with_system_pack(self):
        from packs.emulatorpack import generate_system_pack

        self._create_region_fixtures()
        os.makedirs(self.emulators_dir, exist_ok=True)
        with open(
            os.path.join(self.emulators_dir, "rgncore.yml"), "w", encoding="utf-8"
        ) as fh:
            yaml.safe_dump(self._region_profiles()["rgncore"], fh)
        out = generate_system_pack(
            ["region-console"],
            self.emulators_dir,
            self.db,
            self.bios_dir,
            self.root,
            regions=["north-america"],
        )
        self.assertIsNotNone(out)
        self.assertIn("NorthAmerica", os.path.basename(out))
        names = self._names_in(out)
        self.assertIn("rgn_us.bin", names)
        self.assertNotIn("rgn_jp.bin", names)

    def test_verify_platform_region_matches_the_pack(self):
        from model.platforms import load_platform_config
        from packs.coverage import verify_platform

        self._create_region_fixtures()
        profiles = self._region_profiles()
        config = load_platform_config("regionplat", self.platforms_dir)

        full = verify_platform(config, self.db, self.emulators_dir, profiles)
        filtered = verify_platform(
            config,
            self.db,
            self.emulators_dir,
            profiles,
            regions=["north-america"],
        )
        checked = {d["name"] for d in filtered["details"]}
        self.assertIn("rgn_us.bin", checked)
        self.assertNotIn("rgn_jp.bin", checked)
        self.assertNotIn("rgn_eu.bin", checked)
        self.assertLess(len(filtered["details"]), len(full["details"]))

        packed = self._names_in(self._region_pack(regions=["north-america"]))
        self.assertTrue(checked.issubset(packed), checked - packed)

    def test_verify_emulator_region_matches_the_pack(self):
        from packs.emulatorpack import generate_emulator_pack
        from packs.emulatorcheck import verify_emulator

        self._create_region_fixtures()
        with open(
            os.path.join(self.emulators_dir, "rgncore.yml"), "w", encoding="utf-8"
        ) as fh:
            yaml.safe_dump(self._region_profiles()["rgncore"], fh)

        full = verify_emulator(["rgncore"], self.emulators_dir, self.db)
        filtered = verify_emulator(
            ["rgncore"], self.emulators_dir, self.db, regions=["north-america"]
        )
        checked = {d["name"] for d in filtered["details"]}
        self.assertIn("rgn_us.bin", checked)
        self.assertNotIn("rgn_jp.bin", checked)
        self.assertLess(len(filtered["details"]), len(full["details"]))

        out = generate_emulator_pack(
            ["rgncore"],
            self.emulators_dir,
            self.db,
            self.bios_dir,
            self.root,
            regions=["north-america"],
        )
        self.assertTrue(checked.issubset(self._names_in(out)))

    def test_every_narrowing_names_itself_and_says_so(self):
        """A dimension that removes files must show in the pack name and in the
        README. Both are built from pack_narrowings, so this holds for any new one."""
        from packs.readme import build_readme
        from packs.naming import pack_narrowings

        dimensions = [
            {"source": "platform"},
            {"source": "truth"},
            {"regions": ["north-america"]},
            {"target_name": "switch"},
            {"one_per_slot": True},
            {"required_only": True},
            {"no_game_data": True},
        ]
        for kwargs in dimensions:
            applied = pack_narrowings(
                kwargs.get("source", "full"),
                kwargs.get("regions"),
                kwargs.get("target_name"),
                kwargs.get("one_per_slot", False),
                kwargs.get("required_only", False),
                no_game_data=kwargs.get("no_game_data", False),
            )
            self.assertEqual(len(applied), 1, kwargs)
            tag, label = applied[0]
            self.assertTrue(tag.startswith("_") and len(tag) > 1, kwargs)
            self.assertTrue(label.strip(), kwargs)
            readme = build_readme("p", "P", "", 1, 1, narrowings=applied)
            self.assertIn("PACK TYPE: Narrowed", readme)
            self.assertIn(label, readme)

    def test_no_mode_swallows_a_narrowing_flag(self):
        """Every mode either honours a narrowing flag or refuses it.

        Silently ignoring one is how --manifest-targets accepted --region and
        wrote seven unfiltered manifests, and how --manifest accepted
        --one-per-slot. A mode that cannot apply a flag must say so.
        """
        import subprocess

        repo = os.path.join(os.path.dirname(__file__), "..")
        matrix = [
            (["--manifest-targets"], ["--region", "us"], "refuse"),
            (["--manifest-targets"], ["--one-per-slot"], "refuse"),
            (["--platform", "retroarch", "--manifest"], ["--one-per-slot"], "refuse"),
            (["--emulator", "duckstation"], ["--one-per-slot"], "refuse"),
            (["--system", "sony-playstation"], ["--one-per-slot"], "refuse"),
            (["--platform", "retroarch", "--system", "sony-playstation"],
             ["--one-per-slot"], "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"], ["--region", "us"],
             "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"], ["--one-per-slot"],
             "refuse"),
            # --verify-packs returns before the argument checks run, so it
            # used to accept these and answer about the pack sitting in the
            # output directory. --target is honoured instead of refused: the
            # check narrows by it.
            (["--platform", "retroarch", "--verify-packs"], ["--one-per-slot"],
             "refuse"),
            (["--platform", "retroarch", "--verify-packs"], ["--required-only"],
             "refuse"),
            (["--platform", "retroarch", "--verify-packs"], ["--source", "truth"],
             "refuse"),
            # Modes that read none of these: the flag reached the filename or
            # nothing at all, never the selection.
            (["--emulator", "duckstation"], ["--source", "truth"], "refuse"),
            (["--system", "sony-playstation"], ["--source", "truth"], "refuse"),
            (["--manifest-targets"], ["--target", "switch"], "refuse"),
            (["--manifest-targets"], ["--required-only"], "refuse"),
            (["--manifest-targets"], ["--source", "truth"], "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"],
             ["--target", "switch"], "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"],
             ["--required-only"], "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"],
             ["--source", "truth"], "refuse"),
            (["--platform", "retroarch", "--manifest"],
             ["--system", "sony-playstation"], "refuse"),
            (["--platform", "retroarch", "--split"],
             ["--system", "sony-playstation"], "refuse"),
            # --all took the same filter and wrote twelve complete manifests.
            (["--all", "--manifest"], ["--system", "sony-playstation"], "refuse"),
            (["--all", "--split"], ["--system", "sony-playstation"], "refuse"),
            # A pack built with --system is named after its systems, but the check
            # looked for the full pack instead.
            (["--platform", "retroarch", "--verify-packs"],
             ["--system", "sony-playstation"], "refuse"),
            # --all-variants builds its own six combinations: it overrode these
            # and the single-pack modes never read it at all.
            (["--platform", "retroarch", "--all-variants"], ["--source", "truth"],
             "refuse"),
            (["--platform", "retroarch", "--all-variants"], ["--required-only"],
             "refuse"),
            # The default value typed out is still the flag: compared with its
            # default, `--source full` and `--group-by system` went through.
            (["--platform", "retroarch", "--all-variants"], ["--source", "full"],
             "refuse"),
            (["--manifest-targets"], ["--source", "full"], "refuse"),
            (["--emulator", "handy"], ["--source", "full"], "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"],
             ["--source", "full"], "refuse"),
            (["--platform", "retroarch", "--offline"], ["--group-by", "system"],
             "refuse"),
            (["--platform", "retroarch", "--verify-packs"], ["--group-by", "system"],
             "refuse"),
            (["--emulator", "duckstation"], ["--all-variants"], "refuse"),
            (["--system", "sony-playstation"], ["--all-variants"], "refuse"),
            (["--emulator", "duckstation", "--verify-packs"], ["--all-variants"],
             "refuse"),
            (["--all", "--manifest", "--all-variants"], ["--verify-packs"],
             "refuse"),
            (["--all", "--all-variants", "--verify-packs"], ["--one-per-slot"],
             "refuse"),
            (["--all", "--all-variants", "--verify-packs"], ["--split"],
             "refuse"),
            # Every flag a quick mode does not read, from one table.
            (["--platform", "retroarch", "--verify-packs"], ["--split"], "refuse"),
            (["--platform", "retroarch", "--verify-packs"], ["--manifest"], "refuse"),
            (["--platform", "retroarch", "--verify-packs"], ["--emulator", "handy"],
             "refuse"),
            (["--manifest-targets"], ["--platform", "batocera"], "refuse"),
            (["--manifest-targets"], ["--system", "sony-playstation"], "refuse"),
            (["--manifest-targets"], ["--all"], "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"], ["--manifest"],
             "refuse"),
            (["--list-systems"], ["--region", "us"], "refuse"),
            (["--list-emulators"], ["--target", "switch"], "refuse"),
            # Only the platform path refreshes data directories.
            (["--emulator", "dolphin"], ["--refresh-data"], "refuse"),
            (["--system", "sony-playstation"], ["--refresh-data"], "refuse"),
            (["--from-md5", "d8f1"], ["--refresh-data"], "refuse"),
            (["--platform", "retroarch", "--offline"], ["--refresh-data"], "refuse"),
            (["--emulator", "dolphin"], ["--no-refresh-data"], "refuse"),
            (["--system", "sony-playstation"], ["--no-refresh-data"], "refuse"),
            (["--platform", "retroarch", "--offline"], ["--no-refresh-data"], "refuse"),
            (["--platform", "retroarch", "--refresh-data"], ["--no-refresh-data"],
             "refuse"),
            # Documented as adding core files, read by nothing.
            (["--emulator", "handy"], ["--include-extras"], "refuse"),
            (["--system", "atari-lynx"], ["--include-extras"], "refuse"),
            # Game data is categorized against a platform's list and the
            # cores it runs: the modes without a platform refuse it, and
            # --all-variants builds its own fixed set.
            (["--emulator", "handy"], ["--no-game-data"], "refuse"),
            (["--system", "atari-lynx"], ["--no-game-data"], "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"], ["--no-game-data"],
             "refuse"),
            (["--from-md5", "d8f1"], ["--no-game-data"], "refuse"),
            (["--manifest-targets"], ["--no-game-data"], "refuse"),
            (["--platform", "retroarch", "--all-variants"], ["--no-game-data"],
             "refuse"),
            (["--list-systems"], ["--no-game-data"], "refuse"),
            (["--list"], ["--no-game-data"], "refuse"),
            # --counts records the full platform packs the pipeline compares
            # with verify: a mode that builds none refuses it.
            (["--emulator", "handy"], ["--counts", "counts.json"], "refuse"),
            (["--platform", "retroarch", "--manifest"], ["--counts", "counts.json"], "refuse"),
            (["--platform", "retroarch", "--split"], ["--counts", "counts.json"], "refuse"),
            (["--platform", "retroarch", "--system", "sony-playstation"],
             ["--counts", "counts.json"], "refuse"),
            (["--platform", "retroarch", "--from-md5", "d8f1"], ["--counts", "counts.json"],
             "refuse"),
            (["--platform", "retroarch", "--verify-packs"], ["--counts", "counts.json"],
             "refuse"),
            (["--list"], ["--counts", "counts.json"], "refuse"),
        ]
        for mode, flag, expected in matrix:
            with self.subTest(mode=mode, flag=flag):
                self.assertEqual(expected, "refuse")
                result = subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", *mode, *flag,
                     "--output-dir", os.path.join(self.root, "modecheck")],
                    capture_output=True, text=True, cwd=repo, timeout=120,
                    check=False,
                )
                combined = result.stdout + result.stderr
                self.assertNotEqual(
                    result.returncode, 0,
                    f"{' '.join(mode + flag)} was accepted and ignored:\n{combined}",
                )
                self.assertIn("error:", combined)
                # The refusal names a flag the command carries: "requires
                # --platform or --all" answered --platform --system
                # --one-per-slot, and the user could not tell what to drop.
                message = combined[combined.index("error:"):].splitlines()[0]
                passed = [arg for arg in mode + flag if arg.startswith("--")]
                self.assertTrue(
                    any(arg in message for arg in passed),
                    f"{' '.join(mode + flag)}: {message}",
                )
                demanded = message.partition(" requires ")[2].replace(",", " ").split()
                self.assertFalse(
                    [arg for arg in passed if arg in demanded],
                    f"{' '.join(mode + flag)} asks for a flag it was given: {message}",
                )

    def test_conformance_narrows_by_target_like_it_does_by_region(self):
        """A targeted pack is checked against the targeted expectation.

        --target narrowed the build and nothing else: the conformance stage
        held every targeted pack to the platform's whole system list and
        core set, so a correct build exited non-zero on hundreds of files it
        was never asked to carry. Region was already passed to the check, and
        target has to travel the same way, which is why the pack is checked
        as a full pack.
        """
        import inspect

        from packs import platformcheck
        from packs.naming import pack_narrowings, pack_variant

        source = inspect.getsource(platformcheck.verify_pack_against_platform)
        self.assertIn(
            "target_cores",
            inspect.signature(platformcheck.verify_pack_against_platform).parameters,
            "the pack verifier takes no target, so it cannot narrow by one",
        )
        self.assertIn(
            "platform_scope_systems(config, emu_profiles, target_cores)",
            source,
            "the baseline expectation is not narrowed by the target, as the pack and verify narrow it",
        )
        self.assertIn(
            "target_cores=target_cores",
            source,
            "the core-extras expectation is not narrowed by the target",
        )

        # And the pack must not be skipped instead: skipping checks nothing.
        for target in ("nintendo-switch", "switch", "rpi4"):
            tag = pack_narrowings("full", None, target, False, False)[0][0]
            self.assertEqual(
                pack_variant(f"Platform_1.0{tag}_BIOS_Pack.zip"), ("full", False),
                f"a pack built for {target} would be checked as a narrowed variant",
            )

    def test_standalone_mode_names_itself(self):
        """--emulator --standalone ships a different file set, and without a tag it
        overwrote the pack built without it."""
        from packs.naming import pack_narrowings

        applied = pack_narrowings("full", None, None, False, False, standalone=True)
        self.assertEqual([tag for tag, _l in applied], ["_Standalone"])

    def test_every_name_builder_uses_the_same_list(self):
        """Four places name a pack or a manifest. None may assemble tags by
        hand: that is how --one-per-slot reached --split unnamed."""
        source = script_source("generate_pack.py")
        for hand_rolled in (
            'req_tag = "_Required"',
            'source_tag = {"platform": "_Platform"',
            'req_suffix = "_required"',
            'slot_tag = "_OnePerSlot"',
            # The --system rename kept the region tag alone, the custom pack
            # took no tag at all, and the skip list retyped four of them.
            '_Custom_BIOS_Pack.zip"',
            '{rgn_tag}_BIOS_Pack.zip"',
            '("_Platform_", "_Truth_"',
        ):
            self.assertNotIn(hand_rolled, source, hand_rolled)
        self.assertGreaterEqual(source.count("pack_narrowings("), 8)

    def test_a_narrowed_system_pack_does_not_take_the_full_name(self):
        """Every dimension has to show in the filename or two builds collide.

        --system X --required-only produced the same name as --system X and
        overwrote it, because the rename kept only the region tag.
        """
        import subprocess

        repo = os.path.join(os.path.dirname(__file__), "..")
        names = {}
        for label, extra in (("full", []), ("required", ["--required-only"])):
            out = os.path.join(self.root, f"sysname_{label}")
            proc = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--system",
                 "atari-lynx", "--offline", *extra, "--output-dir", out],
                capture_output=True, text=True, cwd=repo, timeout=300,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            names[label] = sorted(
                f for f in os.listdir(out) if f.endswith("_BIOS_Pack.zip")
            )
        self.assertTrue(names["full"] and names["required"])
        self.assertNotEqual(
            names["full"], names["required"],
            "a required-only system pack took the name of the full one",
        )

    def test_a_platform_without_cores_has_no_truth_pack(self):
        """MiSTer declares cores: []: its truth pack held nothing, passed
        its check and exited 0 under a name claiming a content."""
        import subprocess

        repo = os.path.join(os.path.dirname(__file__), "..")
        out = os.path.join(self.root, "truth_empty")
        proc = subprocess.run(
            [sys.executable, "scripts/generate_pack.py", "--platform", "misterfpga",
             "--offline", "--source", "truth", "--output-dir", out],
            capture_output=True, text=True, cwd=repo, timeout=300,
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("a truth pack would hold nothing", proc.stderr)
        self.assertFalse(
            [f for f in os.listdir(out) if f.endswith(".zip")] if os.path.isdir(out) else []
        )

    def test_an_emulator_needing_no_file_succeeds_like_verify(self):
        """Handy requires no file. --required-only removed the empty ZIP,
        printed its path and exited 1, while verify reported 0/0 OK."""
        import subprocess

        repo = os.path.join(os.path.dirname(__file__), "..")
        out = os.path.join(self.root, "no_file_needed")
        proc = subprocess.run(
            [sys.executable, "scripts/generate_pack.py", "--emulator", "handy",
             "--required-only", "--offline", "--output-dir", out],
            capture_output=True, text=True, cwd=repo, timeout=300,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("no file needed, no pack written", proc.stdout)
        self.assertNotIn(".zip", proc.stdout)
        verify = subprocess.run(
            [sys.executable, "scripts/verify.py", "--emulator", "handy", "--required-only"],
            capture_output=True, text=True, cwd=repo, timeout=300,
            check=False,
        )
        self.assertEqual(verify.returncode, proc.returncode)

    def test_a_platform_without_cores_refuses_profile_narrowings(self):
        """MiSTer and BizHawk declare cores: []. --region, --one-per-slot
        and --no-game-data read the profiles, so their packs withdrew
        nothing under a name and README that said otherwise."""
        import subprocess

        repo = os.path.join(os.path.dirname(__file__), "..")
        out = os.path.join(self.root, "blind")
        runs = [
            ["scripts/generate_pack.py", "--platform", "misterfpga", "--region", "us"],
            ["scripts/generate_pack.py", "--platform", "misterfpga", "--one-per-slot"],
            ["scripts/generate_pack.py", "--platform", "misterfpga", "--no-game-data"],
            ["scripts/generate_pack.py", "--platform", "bizhawk", "--manifest",
             "--region", "us"],
            ["scripts/verify.py", "--platform", "bizhawk", "--region", "us"],
        ]
        for argv in runs:
            extra = ["--offline", "--output-dir", out] if "generate_pack" in argv[0] else []
            with self.subTest(argv=argv):
                proc = subprocess.run(
                    [sys.executable, *argv, *extra],
                    capture_output=True, text=True, cwd=repo, timeout=300,
                    check=False,
                )
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("runs no core a profile describes", proc.stderr)
        self.assertFalse(os.listdir(out) if os.path.isdir(out) else [])

    def test_a_full_pack_is_not_announced_as_narrowed(self):
        from packs.readme import build_readme
        from packs.naming import pack_narrowings

        self.assertEqual(pack_narrowings("full", None, None, False, False), [])
        self.assertNotIn(
            "PACK TYPE: Narrowed", build_readme("p", "P", "", 1, 1)
        )

    def test_system_filter_is_announced_too(self):
        from packs.readme import build_readme

        readme = build_readme(
            "p", "P", "", 1, 1, system_filter=["sony-playstation"]
        )
        self.assertIn("PACK TYPE: Narrowed", readme)
        self.assertIn("sony-playstation", readme)

    def test_extras_group_under_their_system_not_a_shared_bucket(self):
        """A core extra competes in its system's group: the chain from the
        gap report (system, systems) to platform_region_groups, not a
        dictionary built by hand. Without it every extra stood alone and
        --region compared nothing."""
        import hashlib

        from packs.extraregions import platform_region_groups

        files, by_name = {}, {}
        for name in ("core_us.bin", "core_jp.bin"):
            payload = name.encode()
            path = os.path.join(self.bios_dir, name)
            with open(path, "wb") as handle:
                handle.write(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {"path": path, "name": name, "size": len(payload),
                           "md5": hashlib.md5(payload).hexdigest()}
            by_name[name] = [sha1]
        db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                          "by_crc32": {}, "by_path_suffix": {}}}
        profiles = {"psxcore": {
            "emulator": "PSX Core (Display Name)", "type": "libretro",
            "systems": ["sony-playstation"],
            "files": [{"name": "core_us.bin", "region": ["north-america"]},
                      {"name": "core_jp.bin", "region": ["japan"]}],
        }}
        config = {"platform": "P", "cores": ["psxcore"], "base_destination": "system",
                  "systems": {"sony-playstation": {"files": [
                      {"name": "declared.bin", "destination": "declared.bin"}]}}}
        groups, _ = platform_region_groups(
            config, config["systems"], self.emulators_dir, db, "system", profiles,
        )
        self.assertEqual(
            sorted(groups["sony-playstation"]),
            [("core_jp.bin", "core_jp.bin"), ("core_us.bin", "core_us.bin"),
             ("declared.bin", "declared.bin")],
        )

    def test_a_system_spelled_two_ways_is_one_group(self):
        """RetroDECK files the Master System as sega-master-system, the
        profiles as sega-mastersystem. Two groups reduced apart, and a
        --region us pack kept the declared Japanese BIOS."""
        import hashlib

        from packs.extraregions import platform_region_groups

        files, by_name = {}, {}
        for name in ("bios_U.sms", "bios_J.sms"):
            payload = name.encode()
            path = os.path.join(self.bios_dir, name)
            with open(path, "wb") as handle:
                handle.write(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {"path": path, "name": name, "size": len(payload),
                           "md5": hashlib.md5(payload).hexdigest()}
            by_name[name] = [sha1]
        db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                          "by_crc32": {}, "by_path_suffix": {}}}
        profiles = {"smscore": {
            "emulator": "SMS Core", "type": "libretro",
            "systems": ["sega-mastersystem"],
            "files": [{"name": "bios_U.sms", "region": ["north-america"]},
                      {"name": "bios_J.sms", "region": ["japan"]}],
        }}
        config = {"platform": "P", "cores": ["smscore"], "base_destination": "system",
                  "systems": {"sega-master-system": {"files": [
                      {"name": "bios_J.sms", "destination": "bios/bios_J.sms"}]}}}
        groups, _ = platform_region_groups(
            config, config["systems"], self.emulators_dir, db, "system", profiles,
        )
        self.assertNotIn("sega-mastersystem", groups)
        self.assertEqual(
            sorted(dest for dest, _ in groups["sega-master-system"]),
            ["bios/bios_J.sms", "bios_J.sms", "bios_U.sms"],
        )

    def test_slot_narrowed_pack_gets_its_own_name(self):
        names = {
            os.path.basename(self._region_pack()),
            os.path.basename(self._region_pack(one_per_slot=True)),
        }
        self.assertEqual(len(names), 2, names)
        self.assertTrue(any("OnePerSlot" in n for n in names))

    def test_verify_pack_return_matches_its_annotation(self):
        import inspect
        import typing

        from packs.platformpack import generate_pack
        from packs.platformcheck import verify_pack_against_platform

        self._create_region_fixtures()
        profiles = self._region_profiles()
        out = generate_pack(
            "regionplat",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            self.root,
            emu_profiles=profiles,
        )
        result = verify_pack_against_platform(
            out, "regionplat", self.platforms_dir, db=self.db, emu_profiles=profiles
        )
        annotated = typing.get_args(
            inspect.signature(
                verify_pack_against_platform, eval_str=True
            ).return_annotation
        )
        self.assertEqual(len(result), len(annotated))

    def test_narrowed_variants_are_checked_as_built(self):
        from packs.naming import pack_variant

        for narrowed, variant in (
            ("EmuDeck_2.3.8_Required_BIOS_Pack.zip", ("full", True)),
            ("EmuDeck_2.3.8_Platform_BIOS_Pack.zip", ("platform", False)),
            ("EmuDeck_2.3.8_Truth_Required_BIOS_Pack.zip", ("truth", True)),
            ("EmuDeck_2.3.8_NorthAmerica_Required_BIOS_Pack.zip", ("full", True)),
        ):
            self.assertEqual(pack_variant(narrowed), variant, narrowed)

        for full in (
            "EmuDeck_2.3.8_BIOS_Pack.zip",
            "EmuDeck_2.3.8_NorthAmerica_BIOS_Pack.zip",
            "RetroArch_v1.22.2_Switch_BIOS_Pack.zip",
        ):
            self.assertEqual(pack_variant(full), ("full", False), full)

    def test_target_tag_formats_hardware_names(self):
        from packs.naming import _target_tag

        self.assertEqual(_target_tag("switch"), "Switch")
        self.assertEqual(_target_tag("rpi4"), "Rpi4")
        self.assertEqual(_target_tag("x86_64"), "X86 64".replace(" ", ""))

    def test_targeted_pack_does_not_overwrite_the_full_one(self):
        names = {
            os.path.basename(self._region_pack()),
            os.path.basename(self._region_pack(target_name="switch")),
        }
        self.assertEqual(len(names), 2, names)
        self.assertTrue(any("Switch" in n for n in names))

    def test_target_and_region_tags_compose_in_the_name(self):
        name = os.path.basename(
            self._region_pack(regions=["north-america"], target_name="switch")
        )
        self.assertIn("NorthAmerica", name)
        self.assertIn("Switch", name)

    def test_readme_region_section_lists_fallback_systems(self):
        from packs.readme import build_readme

        text = build_readme(
            "regionplat",
            "RegionPlat",
            "",
            10,
            2,
            regions=["north-america"],
            fallback_systems=["nintendo-fds"],
        )
        self.assertIn("PACK TYPE: Region Filtered", text)
        self.assertIn("Region priority: North America", text)
        self.assertIn("nintendo-fds", text)
        self.assertIn("This pack was filtered", text)
        self.assertNotIn("All are included", text)

    def test_readme_without_region_keeps_the_regional_note(self):
        from packs.readme import build_readme

        text = build_readme("regionplat", "RegionPlat", "", 10, 2)
        self.assertNotIn("PACK TYPE: Region Filtered", text)
        self.assertIn("All are included", text)

    def test_verify_agrees_with_region_filtered_pack(self):
        from packs.platformcheck import verify_pack_against_platform

        out = self._region_pack(regions=["north-america"])
        result = verify_pack_against_platform(
            out,
            "regionplat",
            self.platforms_dir,
            db=self.db,
            emu_profiles=self._region_profiles(),
            regions=["north-america"],
        )
        ok, _checked, _present, errors = result[:4]
        self.assertTrue(ok, errors)

    def test_verify_reports_the_gap_without_the_region_filter(self):
        from packs.platformcheck import verify_pack_against_platform

        out = self._region_pack(regions=["north-america"])
        result = verify_pack_against_platform(
            out,
            "regionplat",
            self.platforms_dir,
            db=self.db,
            emu_profiles=self._region_profiles(),
        )
        ok, _checked, _present, errors = result[:4]
        self.assertFalse(ok)
        self.assertTrue(any("rgn_jp.bin" in e for e in errors), errors)

    def test_region_composes_with_source_truth(self):
        names = self._names_in(
            self._region_pack(regions=["north-america"], source="truth")
        )
        self.assertIn("rgn_us.bin", names)
        self.assertNotIn("rgn_jp.bin", names)


class TestE2EGapAnalysis(E2EFixture):
    """Gap analysis resolves files the pack can already ship."""

    # ---- gap analysis resolves files the pack can already ship ----

    @staticmethod
    def _gap_db(repo_name: str, sha1: str, crc32: str) -> dict:
        return {
            "files": {sha1: {"path": f"bios/{repo_name}", "size": 8192, "crc32": crc32}},
            "indexes": {
                "by_name": {repo_name: [sha1]},
                "by_md5": {},
                "by_crc32": {crc32: sha1},
                "by_sha256": {},
                "by_path_suffix": {},
            },
        }

    def _gap_source(self, entry: dict, db: dict) -> str:
        from packs.crossref import cross_reference

        report = cross_reference(
            {"gapemu": {"emulator": "GapEmu", "systems": ["s"], "files": [entry]}},
            {"s": set()},
            db,
        )
        return report["gapemu"]["gap_details"][0]["source"]

    def test_gap_analysis_resolves_by_alias(self):
        """A file stored under an alias is in the repo, not a sourcing target."""
        db = self._gap_db("REPO_chip.rom", "a" * 40, "465c4e1c")
        entry = {"name": "chip.rom", "aliases": ["REPO_chip.rom"], "required": True}
        self.assertEqual(self._gap_source(entry, db), "bios")

    def test_gap_analysis_resolves_by_crc32(self):
        """crc32 is the only hash some emulators declare."""
        db = self._gap_db("REPO_chip.rom", "a" * 40, "465c4e1c")
        entry = {"name": "chip.rom", "crc32": "465c4e1c", "required": True}
        self.assertEqual(self._gap_source(entry, db), "bios")

    def test_gap_analysis_reports_unknown_file_missing(self):
        db = self._gap_db("REPO_chip.rom", "a" * 40, "465c4e1c")
        entry = {"name": "chip.rom", "aliases": ["OTHER.rom"], "crc32": "deadbeef"}
        self.assertEqual(self._gap_source(entry, db), "missing")

    def test_gap_analysis_resolves_renamed_mame_set(self):
        """A renamed set is held under the name dedup kept, as verify reads it."""
        from model import database

        db = self._gap_db("v4bios.zip", "a" * 40, "465c4e1c")
        original = database.get_mame_clone_map
        database.get_mame_clone_map = lambda *_a: {"bctvidbs.zip": "v4bios.zip"}
        try:
            entry = {"name": "bctvidbs.zip", "required": True}
            self.assertEqual(self._gap_source(entry, db), "bios")
        finally:
            database.get_mame_clone_map = original


if __name__ == "__main__":
    unittest.main()
