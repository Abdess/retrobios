"""A hardware target names its artifacts by the name it is filed under.

`switch`, `nx` and `nintendo-switch` are one RetroArch target. The tag came
from the name as typed, so one target gave three pack and manifest names,
and `--verify-packs --target nx` looked for a pack nobody had built.
"""

from __future__ import annotations

import tests
from tests.sources import script_source

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from model.targets import canonical_target_name

REPO_ROOT = Path(__file__).resolve().parent.parent


class EveryBuildbotCoreIsNamed(unittest.TestCase):
    """A core RetroArch installs that its manifest does not name is "a core
    this list does not know" to --installed-cores (issue 87). 2048, gong,
    radio, video_processor and test were typed by their role, which hid
    their libretro build from all_libretro."""

    def test_retroarch_names_every_buildbot_core(self):
        import yaml

        from model.profiles import load_emulator_profiles, upstream_profile_index
        from model.platforms import load_platform_config
        from model.targets import load_target_config
        from resolve.cores import resolve_platform_cores

        platforms = str(REPO_ROOT / "platforms")
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        runs = resolve_platform_cores(load_platform_config("retroarch", platforms), profiles)
        index = upstream_profile_index(profiles, include_aliases=True)
        targets = yaml.safe_load((REPO_ROOT / "platforms" / "targets" / "retroarch.yml").read_text())
        names = {
            name for target in targets["targets"]
            for name in load_target_config("retroarch", target, platforms) or ()
        }
        unnamed = sorted(name for name in names if not (index.get(name, set()) & runs))
        self.assertEqual(unnamed, [])


class AliasesResolveToOneName(unittest.TestCase):
    def test_retroarch_switch_aliases(self):
        platforms = str(REPO_ROOT / "platforms")
        for typed in ("switch", "nx", "nintendo-switch"):
            with self.subTest(typed=typed):
                self.assertEqual(
                    canonical_target_name(["retroarch"], typed, platforms),
                    "nintendo-switch",
                )

    def test_raspberry_pi_models_reach_batocera_boards(self):
        """`--target rpi4`, the example every --help gives, was refused on
        Batocera: its boards are named by SoC and no alias pointed there."""
        platforms = str(REPO_ROOT / "platforms")
        for typed, board in (("rpi4", "bcm2711"), ("rpi5", "bcm2712"),
                             ("rpi3", "bcm2837"), ("rpi-zero", "bcm2835")):
            with self.subTest(typed=typed):
                self.assertEqual(canonical_target_name(["batocera"], typed, platforms), board)

    def test_linux_on_arm_and_32_bit_x86_is_a_target(self):
        """The buildbot's linux/aarch64 (232 cores) and linux/x86 builds were
        not scraped: --target refused RetroArch on Raspberry Pi OS 64-bit."""
        import yaml

        platforms = str(REPO_ROOT / "platforms")
        targets = yaml.safe_load((REPO_ROOT / "platforms" / "targets" / "retroarch.yml")
                                 .read_text())["targets"]
        for typed, target in (("arm64", "linux-aarch64"), ("i686", "linux-x86")):
            with self.subTest(typed=typed):
                self.assertEqual(canonical_target_name(["retroarch"], typed, platforms), target)
                self.assertGreater(len(targets[target]["cores"]), 100)

    def test_an_unknown_name_is_left_for_the_target_check(self):
        self.assertEqual(
            canonical_target_name(["retroarch"], "bogus", str(REPO_ROOT / "platforms")),
            "bogus",
        )


class TheBuilderNamesByTheCanonicalTarget(unittest.TestCase):
    def test_an_alias_writes_the_canonical_manifest(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        with tempfile.TemporaryDirectory() as out:
            proc = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--platform", "retroarch",
                 "--target", "nx", "--manifest", "--offline", "--output-dir", out],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(
                sorted(p.name for p in Path(out).glob("*.json")),
                ["retroarch_nintendoswitch.json"],
            )



class EachPlatformNamesTheTargetItsOwnWay(unittest.TestCase):
    """rpi4 is Batocera's bcm2711, Recalbox's rpi4_64 and RetroPie's rpi4.
    Named once for the run, --all kept "rpi4" for all three while
    --platform batocera named the same pack Bcm2711, so --verify-packs
    answered SKIP for a pack the --all build had written."""

    def test_the_all_run_and_the_platform_run_agree(self):
        import contextlib
        import io

        from packs import naming

        platforms_dir = str(REPO_ROOT / "platforms")
        with contextlib.redirect_stdout(io.StringIO()):
            expected = naming.expected_pack_names(
                ["batocera", "recalbox"], platforms_dir, None, "rpi4"
            )
        self.assertTrue(any("_Bcm2711_" in name for name in expected["batocera"]))
        self.assertTrue(any("_Rpi464_" in name for name in expected["recalbox"]))
        for platform, tag in (("batocera", "bcm2711"), ("recalbox", "rpi4_64")):
            self.assertEqual(
                naming.platform_target(platform, "rpi4", platforms_dir), tag
            )

    def test_no_naming_site_reads_the_typed_target(self):
        source = script_source("generate_pack.py")
        self.assertNotIn("target_name=args.target,\n                        one_per_slot", source)
        self.assertNotIn("args.target = canonical_target_name(", source)


class OneTruthModelPerTarget(unittest.TestCase):
    """generate_truth slugged the typed name: --target nx, switch and
    nintendo-switch wrote three copies of one model, and the pipeline's diff
    rebuilt the same slug by hand to find it."""

    def test_aliases_share_a_directory(self):
        from model.targets import truth_target_dir

        platforms = str(REPO_ROOT / "platforms")
        dirs = {
            truth_target_dir("truth", ["retroarch"], alias, platforms)
            for alias in ("nx", "switch", "nintendo-switch")
        }
        self.assertEqual(dirs, {str(Path("truth") / "nintendo-switch")})
        # Lakka builds an image named switch: its own target, its own model.
        self.assertEqual(
            truth_target_dir("truth", ["lakka"], "switch", platforms),
            str(Path("truth") / "switch"),
        )

    def test_writer_and_reader_call_one_function(self):
        for module in ("generate_truth.py", "diff_truth.py"):
            source = (REPO_ROOT / "scripts" / module).read_text()
            with self.subTest(module=module):
                self.assertIn("truth_target_dir(", source)
                self.assertNotIn('re.sub(\n            r"[^a-z0-9]+"', source)
        pipeline = script_source("pipeline.py")
        self.assertIn('diff_cmd.extend(["--target", args.target])', pipeline)


class TheListingCountsWhatTheFilterUses(unittest.TestCase):
    """--list-targets showed Batocera x86_64 with 198 cores; --target x86_64
    filters on 187 once _overrides.yml removes machine variants and launchers."""

    def test_every_listed_count_is_the_filtered_set(self):
        from model.targets import list_available_targets, load_target_config

        platforms = str(REPO_ROOT / "platforms")
        checked = 0
        for target_file in sorted((REPO_ROOT / "platforms" / "targets").glob("[!_]*.yml")):
            platform = target_file.stem
            for row in list_available_targets(platform, platforms):
                with self.subTest(platform=platform, target=row["name"]):
                    resolved = load_target_config(platform, row["name"], platforms)
                    self.assertEqual(row["core_count"],
                                     None if resolved is None else len(resolved))
                checked += 1
        self.assertGreater(checked, 0)


class ASingleTargetFiltersNothing(unittest.TestCase):
    """The single-target rule, held on the real data: RetroBat, RetroDECK and RomM
    have one target each, and hand-kept lists dropped 98, 300 and 132 cores
    from a pack the user had only asked to name."""

    def test_the_only_target_resolves_every_declared_core(self):
        import glob

        import yaml

        from model.profiles import load_emulator_profiles
        from model.platforms import load_platform_config
        from model.targets import load_target_config
        from resolve.cores import resolve_platform_cores

        platforms = str(REPO_ROOT / "platforms")
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        checked = 0
        for path in sorted(glob.glob(str(REPO_ROOT / "platforms" / "targets" / "*.yml"))):
            name = Path(path).stem
            if name.startswith("_"):
                continue
            targets = yaml.safe_load(Path(path).read_text())["targets"]
            if len(targets) != 1:
                continue
            with self.subTest(platform=name):
                config = load_platform_config(name, platforms)
                only = load_target_config(name, next(iter(targets)), platforms)
                self.assertEqual(resolve_platform_cores(config, profiles, target_cores=only),
                                 resolve_platform_cores(config, profiles))
                checked += 1
        self.assertGreaterEqual(checked, 3)

class PublishedListsAreNotNarrowed(unittest.TestCase):
    """pipeline --target switch wrote install/retroarch_nintendoswitch.json
    next to the published lists. The site picker then replaced RetroArch's
    file list with the Switch one and check_release asked for it as an asset."""

    def test_pipeline_writes_install_unfiltered(self):
        pipeline = script_source("pipeline.py")
        self.assertNotIn('manifest_cmd.extend(["--target"', pipeline)

    def test_every_install_list_is_a_whole_platform(self):
        import json

        for path in sorted((REPO_ROOT / "install").glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(path=path.name):
                self.assertEqual(path.stem, data["platform"])
                self.assertNotIn("target", data)
                self.assertNotIn("no_game_data", data)
                self.assertEqual(data["source"], "full")
                self.assertEqual(data["regions"], [])


class AnEmptyOverrideIsNoOverride(unittest.TestCase):
    """`batocera:` or `board:` with no value raised AttributeError in the
    builder and the installer lists, where check_freshness read it as none."""

    def test_every_reader_takes_an_empty_value(self):
        from model.targets import list_available_targets, load_target_config
        from packs.targets import target_list

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            targets = Path(tmp) / "targets"
            targets.mkdir()
            for platform in ("p", "q"):
                (targets / f"{platform}.yml").write_text(
                    "targets:\n  board:\n    cores: [a]\n", encoding="utf-8"
                )
            (targets / "_overrides.yml").write_text(
                "p:\nq:\n  targets:\n    board:\n", encoding="utf-8"
            )
            for platform in ("p", "q"):
                with self.subTest(platform=platform):
                    self.assertEqual(load_target_config(platform, "board", tmp), {"a"})
                    self.assertEqual(list_available_targets(platform, tmp)[0]["aliases"], [])
                    self.assertEqual(target_list(targets / f"{platform}.yml"), {"board": ["a"]})
            self.assertEqual(canonical_target_name(["p", "q"], "board", tmp), "board")


class TheOutputGuardKnowsEveryTargetShape(unittest.TestCase):
    """A board with images is written {"cores", "images"}: the guard read
    only lists, and --manifest replaced install/targets/batocera.json."""

    def test_a_list_with_board_images_is_refused_to_a_manifest_run(self):
        import contextlib
        import io
        import json

        from packs.outputdir import holds_other_kind, json_artifact_kind
        from packs.targets import generate_target_manifests

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            targets = Path(tmp) / "targets"
            targets.mkdir()
            (targets / "p.yml").write_text(
                "targets:\n  board:\n    cores: [a]\n    images: [board-x]\n",
                encoding="utf-8",
            )
            out = Path(tmp) / "out"
            generate_target_manifests(str(targets), str(out))
            written = out / "p.json"
            self.assertEqual(json.loads(written.read_text(encoding="utf-8")),
                             {"board": {"cores": ["a"], "images": ["board-x"]}})
            self.assertEqual(json_artifact_kind(written), "targets")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertTrue(holds_other_kind(str(out), "manifest"))
            self.assertIn("p.json", err.getvalue())


if __name__ == "__main__":
    unittest.main()
