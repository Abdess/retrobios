"""A launcher record resting on a config file binds only when its chain holds.

The platform's code installs the file (installs), its launch code was read
for what replaces it (overrides), and the emulator's profile says where the
build the platform ships loads the file and reads each key (config_reads).
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import yaml  # noqa: E402

from common import load_platform_config  # noqa: E402
from launchers import (  # noqa: E402
    bound_launchers,
    config_evidence,
    config_target,
    handed_directories,
    launcher_places,
    launcher_unproven,
)
from profile_sync import _check_build_refs, shipped_build_holders  # noqa: E402
from scraper.retrobat_launchers import _choices_apart  # noqa: E402
from scraper.shell_launchers import (  # noqa: E402
    LauncherPatternMissing,
    Script,
    config_placement,
    config_ref,
    is_feature_ref,
)
from validate_schemas import (  # noqa: E402
    _config_reads_without_build,
    _config_records_without_evidence,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def record(**fields: object) -> dict:
    """A ROCKNIX-like DuckStation record citing its shipped settings.ini."""
    base = {
        "emulator": "duck", "build": "standalone", "kind": "scans_dir", "names": [],
        "search_dir": "/storage/roms/bios",
        "passes_to": "settings.ini [BIOS] SearchDirectory = /storage/roms/bios, [BIOS] PathPAL unset",
        "installs": {"path": "/storage/.config/duck/settings.ini", "source_ref": "setup.sh:13"},
        "overrides": [],
        "source_ref": "duck/config/settings.ini:4, duck/package.mk:33",
    }
    return {**base, **fields}


def profile(**fields: object) -> dict:
    base = {
        "emulator": "Duck", "type": "standalone", "cores": ["duck"],
        "standalone_directories": ["[BIOS] SearchDirectory"],
        "config_reads": [{
            "file": "settings.ini", "source_ref": "src/core.cpp:10",
            "keys": [
                {"key": "[BIOS] SearchDirectory", "source_ref": "src/settings.cpp:20"},
                {"key": ["[BIOS] PathPAL", "[BIOS] PathNTSCU"], "source_ref": "src/bios.cpp:30"},
            ],
        }],
    }
    return {**base, **fields}


class ConfigRefs(unittest.TestCase):
    def test_config_option_and_feature_files_are_cited_apart(self) -> None:
        ref = "a/settings.ini:4, 6, a/start.sh:3, b/MAME.opt:19, .emulationstation/es_features.cfg:9"
        self.assertEqual(
            config_ref(ref),
            ["a/settings.ini:4, 6", "b/MAME.opt:19", ".emulationstation/es_features.cfg:9"],
        )
        self.assertEqual([is_feature_ref(p) for p in config_ref(ref)], [False, True, True])

    def test_passes_to_names_the_file_and_its_keys(self) -> None:
        cases = {
            "settings.ini [BIOS] SearchDirectory (-settings), [BIOS] PathNTSCU, PathPAL unset":
                ("settings.ini", ["[BIOS] SearchDirectory", "[BIOS] PathNTSCU", "[BIOS] PathPAL"]),
            "melonDS.toml [DS] BIOS9Path [DSi] NANDPath, first file whose name holds the region":
                ("melonDS.toml", ["[DS] BIOS9Path", "[DSi] NANDPath"]),
            "settings.ini [BIOS] PathNTSCJ = PathNTSCU = <value>":
                ("settings.ini", ["[BIOS] PathNTSCJ", "[BIOS] PathNTSCU"]),
            "AmigaA500-default.uae kickstart_rom_file, $(FILE_PATH) = /storage/k/":
                ("AmigaA500-default.uae", ["kickstart_rom_file", "$(FILE_PATH)"]),
            "command line -rompath bios/coco": ("command line", ["-rompath"]),
            "core option pcsx2_bios": ("core options", ["pcsx2_bios"]),
        }
        for passes_to, expected in cases.items():
            with self.subTest(passes_to=passes_to):
                self.assertEqual(config_target({"passes_to": passes_to}), expected)
        core = {"build": "libretro", "kind": "core_option", "passes_to": "hatarib_tos = x/<value>"}
        self.assertEqual(config_target(core), ("core options", ["hatarib_tos"]))

    def test_a_record_naming_no_file_takes_the_config_it_installs(self) -> None:
        romlist = record(
            passes_to="romlist coco",
            installs={"path": "$xroar_config", "source_ref": "prepare.sh:13"},
            source_ref="xroar/rd_config/xroar.conf:305, xroar/prepare.sh:13",
        )
        self.assertEqual(config_target(romlist), ("xroar.conf", ["romlist coco"]))


class Evidence(unittest.TestCase):
    profiles = {"duck": profile()}

    def test_a_record_resting_on_code_holds(self) -> None:
        code = {"emulator": "duck", "kind": "fixed_name", "source_ref": "start.sh:3"}
        self.assertTrue(config_evidence(code, {}).proven)

    def test_the_whole_chain_holds(self) -> None:
        evidence = config_evidence(record(), self.profiles, "rocknix")
        self.assertTrue(evidence.proven, evidence.missing)
        self.assertEqual(evidence.readers, ("duck",))

    def test_each_missing_link_is_named(self) -> None:
        bare = {k: v for k, v in record().items() if k not in ("installs", "overrides")}
        missing = config_evidence(bare, self.profiles).missing
        self.assertEqual(len(missing), 2)
        self.assertTrue(missing[0].startswith("installs"))
        self.assertTrue(missing[1].startswith("overrides"))

    def test_a_profile_that_reads_no_such_file_proves_nothing(self) -> None:
        missing = config_evidence(record(), {"duck": profile(config_reads=[])}).missing
        self.assertEqual(missing, ("config_reads: an emulator that loads settings.ini",))

    def test_a_key_the_build_does_not_read_is_named(self) -> None:
        unread = record(passes_to="settings.ini [BIOS] PathNTSCJ")
        self.assertEqual(
            config_evidence(unread, self.profiles).missing,
            ("config_reads: no read of [BIOS] PathNTSCJ",),
        )

    def test_a_handle_with_its_code_ref_reads_the_key(self) -> None:
        handled = profile(
            config_reads=[{"file": "settings.ini", "source_ref": "src/core.cpp:10", "keys": [
                {"key": "[BIOS] PathPAL", "source_ref": "src/bios.cpp:30"}]}],
            standalone_directories=[
                {"handle": "[BIOS] SearchDirectory", "source_ref": "src/settings.cpp:20"}
            ],
        )
        self.assertTrue(config_evidence(record(), {"duck": handled}).proven)

    def test_an_option_list_is_never_the_source(self) -> None:
        listed = record(source_ref="gen.cs:3, .emulationstation/es_features.cfg:9")
        self.assertIn(
            "an option list cited as source, not as choices_from",
            config_evidence(listed, self.profiles).missing,
        )

    def test_an_option_choice_needs_the_emulator_side_too(self) -> None:
        chosen = {
            "emulator": "duck", "kind": "core_option", "passes_to": "settings.ini [BIOS] PathPAL = <value>",
            "choices_from": "es_features.cfg:9", "source_ref": "gen.cs:3",
        }
        self.assertTrue(config_evidence(chosen, self.profiles).proven)
        self.assertFalse(config_evidence(chosen, {"duck": profile(config_reads=[])}).proven)

    def test_reads_written_for_a_shipped_build_apply_to_its_platform_only(self) -> None:
        built = profile(
            source_commit="a" * 40,
            pin_build=[{"platform": "rocknix", "value": "b" * 40}],
            config_reads=[{**profile()["config_reads"][0], "platforms": ["rocknix"]}],
        )
        self.assertTrue(config_evidence(record(), {"duck": built}, "rocknix").proven)
        self.assertFalse(config_evidence(record(), {"duck": built}, "emuelec").proven)

    def test_reads_at_the_pin_skip_a_platform_shipping_another_build(self) -> None:
        other = profile(source_commit="a" * 40, pin_build=[{"platform": "rocknix", "value": "b" * 40}])
        self.assertFalse(config_evidence(record(), {"duck": other}, "rocknix").proven)
        self.assertTrue(config_evidence(record(), {"duck": other}, "emuelec").proven)


class Gate(unittest.TestCase):
    def config(self, *records: dict) -> dict:
        return {"_key": "rocknix", "base_destination": "bios", "launchers": list(records)}

    def test_an_unproven_record_hands_no_directory(self) -> None:
        proven = handed_directories(self.config(record()), {"duck": profile()})
        self.assertEqual([h.folder for h in proven], [""])
        self.assertEqual(handed_directories(self.config(record()), {"duck": profile(config_reads=[])}), [])

    def test_an_unproven_record_places_no_file(self) -> None:
        named = record(
            kind="fixed_name", names=["tos.img"], passes_to="settings.ini [BIOS] PathPAL",
        )
        self.assertEqual(len(launcher_places(self.config(named), {"duck": profile()})), 1)
        self.assertEqual(launcher_places(self.config(named), {"duck": profile(config_reads=[])}), [])

    def test_the_unproven_are_reported_with_what_they_lack(self) -> None:
        config = self.config({"emulator": "x", "kind": "links", "source_ref": "a.sh:1"}, record())
        self.assertEqual(launcher_unproven({"rocknix": config}, {"duck": profile()}), [])
        (row,) = launcher_unproven({"rocknix": config}, {"duck": profile(config_reads=[])})
        self.assertEqual((row["platform"], row["index"], row["emulator"]), ("rocknix", 1, "duck"))
        self.assertEqual(row["config"], ["duck/config/settings.ini:4"])
        self.assertEqual(len(bound_launchers(config, {"duck": profile(config_reads=[])})), 1)


class StartScripts(unittest.TestCase):
    SCRIPT = (
        'CONF_DIR="/storage/.config/duck"\n'
        'CONF_FILE="${CONF_DIR}/settings.ini"\n'
        '[ ! -d "${CONF_DIR}" ] && cp -r /usr/config/duck /storage/.config\n'
        'if [ ! -f "${CONF_FILE}" ]; then\n'
        '  cp /usr/config/duck/settings.ini ${CONF_FILE}\n'
        'fi\n'
        "sed -i '/^AspectRatio/c\\\\AspectRatio = 4:3' ${CONF_FILE}\n"
        "sed -i '/^PathPAL/c\\\\PathPAL = x.bin' ${CONF_FILE}\n"
        'cp /usr/config/duck/other.ini ${CONF_DIR}/ >/dev/null 2>&1\n'
    )

    def test_a_guarded_copy_keeps_the_file_and_a_key_rewrite_is_an_override(self) -> None:
        placement = config_placement(
            Script("start.sh", self.SCRIPT), "/storage/.config/duck/settings.ini", ["[BIOS] PathPAL"]
        )
        self.assertEqual(placement.install, {3, 5})
        self.assertTrue(placement.kept_if_present)
        self.assertEqual(placement.overrides, {8})

    def test_a_copy_at_each_launch_replaces_the_file(self) -> None:
        script = Script("start.sh", 'cp /usr/config/duck/settings.ini /storage/.config/duck/settings.ini\n')
        self.assertFalse(config_placement(script, "/storage/.config/duck/settings.ini").kept_if_present)

    def test_a_script_installing_nothing_raises(self) -> None:
        with self.assertRaises(LauncherPatternMissing):
            config_placement(Script("start.sh", "echo hi\n"), "/storage/.config/duck/settings.ini")

    def test_retrobat_moves_the_option_list_to_choices_from(self) -> None:
        moved = _choices_apart({
            "emulator": "x", "passes_to": "p",
            "source_ref": "Gen.cs:3-4, .emulationstation/es_features.cfg:9-12",
        })
        self.assertEqual(moved["source_ref"], "Gen.cs:3-4")
        self.assertEqual(moved["choices_from"], ".emulationstation/es_features.cfg:9-12")
        self.assertEqual(list(moved)[-1], "source_ref")


class Invariants(unittest.TestCase):
    def test_a_config_record_without_its_platform_links_is_an_error(self) -> None:
        path = REPO_ROOT / "platforms" / "x.yml"
        bare = {k: v for k, v in record().items() if k not in ("installs", "overrides")}
        listed = record(source_ref="gen.cs:3, es_features.yml:9")
        errors = _config_records_without_evidence(path, {"launchers": [record(), bare, listed]})
        self.assertEqual(len(errors), 2)
        self.assertIn("without installs and overrides", errors[0])
        self.assertIn("choices_from holds it", errors[1])

    def test_reads_naming_a_platform_need_its_build(self) -> None:
        path = REPO_ROOT / "emulators" / "x.yml"
        reads = [{"file": "a.ini", "platforms": ["rocknix"], "source_ref": "a:1", "keys": []}]
        self.assertEqual(len(_config_reads_without_build(path, {"config_reads": reads})), 1)
        self.assertEqual(_config_reads_without_build(
            path, {"config_reads": reads, "pin_build": [{"platform": "rocknix"}]}
        ), [])
        pinned = [{**reads[0], "revision": "c" * 40, "revision_from": "the exe"}]
        self.assertEqual(_config_reads_without_build(path, {"config_reads": pinned}), [])
        closed = [{**reads[0], "binary_sha256": "d" * 64, "revision_from": "the archive"}]
        self.assertEqual(_config_reads_without_build(path, {"config_reads": closed}), [])


class ShippedBuild(unittest.TestCase):
    def test_a_platform_an_entry_names_is_read_there_only(self) -> None:
        """RetroDECK ships GZDoom 4.14.2: the entry read at the pin does not
        also stand for it, so a key only the pin reads proves nothing there."""
        duck = profile(config_reads=[
            {"file": "settings.ini", "source_ref": "src/core.cpp:10",
             "keys": [{"key": "[BIOS] SearchDirectory", "source_ref": "src/settings.cpp:20"},
                      {"key": ["[BIOS] PathPAL", "[BIOS] PathNTSCU"], "source_ref": "src/bios.cpp:30"}]},
            {"file": "settings.ini", "platforms": ["rocknix"], "revision": "a" * 40,
             "revision_from": "the AppImage", "source_ref": "src/core.cpp:12",
             "keys": [{"key": "[BIOS] SearchDirectory", "source_ref": "src/settings.cpp:22"}]},
        ])
        evidence = config_evidence(record(), {"duck": duck}, "rocknix")
        self.assertEqual(evidence.missing, ("config_reads: no read of [BIOS] PathPAL",))
        self.assertTrue(config_evidence(record(), {"duck": duck}, "emuelec").proven)


class CoreOptions(unittest.TestCase):
    def test_a_core_option_is_read_by_the_core_not_the_frontend(self) -> None:
        """RetroDECK's retroarch component writes pcsx2_bios: the frontend
        names the record, the core RetroArch runs reads the option."""
        profiles = {
            "retroarch": {"emulator": "RetroArch", "type": "utility", "cores": ["retroarch"],
                          "config_reads": [{"file": "retroarch.cfg", "source_ref": "a.c:1",
                                            "keys": [{"key": "system_directory",
                                                      "source_ref": "a.c:2"}]}]},
            "lrps2": {"emulator": "LRPS2", "type": "libretro", "cores": ["lrps2"],
                      "config_reads": [{"file": "core options", "source_ref": "main.cpp:1",
                                        "keys": [{"key": "pcsx2_bios",
                                                  "source_ref": "main.cpp:2"}]}]},
        }
        option = {
            "emulator": "retroarch", "build": "libretro", "kind": "core_option",
            "names": ["scph10000.bin"], "passes_to": "core option pcsx2_bios",
            "installs": {"path": "$core_options", "source_ref": "prepare.sh:24"},
            "overrides": [], "source_ref": "rd_config/retroarch-core-options.cfg:515",
        }
        evidence = config_evidence(option, profiles, "retrodeck")
        self.assertTrue(evidence.proven, evidence.missing)
        self.assertEqual(evidence.readers, ("lrps2",))
        system = {**option, "kind": "passes_path", "passes_to": "retroarch.cfg system_directory",
                  "source_ref": "rd_config/retroarch.cfg:44"}
        self.assertEqual(config_evidence(system, profiles, "retrodeck").readers, ("retroarch",))


class BuildRefs(unittest.TestCase):
    def test_reads_for_a_shipped_build_are_read_at_that_build(self) -> None:
        document = {
            "pin_build": [{"platform": "rocknix", "value": "b" * 40}],
            "config_reads": [{
                "file": "a.ini", "platforms": ["rocknix"], "source_ref": "src/a.c:2",
                "keys": [{"key": "k", "source_ref": "src/a.c:9, ROCKNIX x.patch:1"}],
            }],
        }
        held = shipped_build_holders(document)
        self.assertEqual(len(held), 2)

        class View:
            repo, field = "repo", "source"

        class Citation:
            def __init__(self, ref: str, field: str) -> None:
                self.ref, self.field = ref, field

        asked: list[tuple[str, str]] = []

        def fetch(_repo: str, revision: str, path: str) -> list[str] | None:
            asked.append((revision, path))
            return ["line"] * 5 if path == "src/a.c" else None

        rows = _check_build_refs(
            document,
            [(Citation("src/a.c:2", "c"), document["config_reads"][0]),
             (Citation("src/a.c:9, ROCKNIX x.patch:1", "k"), document["config_reads"][0])],
            [View()], fetch,
        )
        self.assertEqual([r["status"] for r in rows], ["BUILD_OK", "BUILD_GONE"])
        self.assertTrue(all(revision == "b" * 40 for revision, _ in asked))
        self.assertNotIn(("b" * 40, "ROCKNIX x.patch"), asked)


    def test_a_closed_build_is_read_in_its_binary(self) -> None:
        """An address ref is read in the binary binary_sha256 names, never
        fetched; a source path cannot exist at a closed build."""
        read = {
            "file": "SSF.ini", "platforms": ["retrobat"], "binary_sha256": "e" * 64,
            "revision_from": "the archive", "source_ref": "SSF.exe 0x10-0x20", "keys": [],
        }

        class View:
            repo, field = "repo", "source"

        class Citation:
            def __init__(self, ref: str) -> None:
                self.ref, self.field = ref, "c"

        asked: list[str] = []

        def fetch(_repo: str, _revision: str, path: str) -> list[str] | None:
            asked.append(path)
            return None

        rows = _check_build_refs(
            {"config_reads": [read]},
            [(Citation("SSF.exe 0x10-0x20"), read), (Citation("src/a.c:3"), read)],
            [View()], fetch,
        )
        self.assertEqual([r["status"] for r in rows], ["BUILD_OK", "BUILD_GONE"])
        self.assertEqual({r["revision"] for r in rows}, {"e" * 64})
        self.assertEqual(asked, ["src/a.c"])


class RepositoryRecords(unittest.TestCase):
    """The placement chains the audit of 2026-11-10 found moving files."""

    def test_the_chains_that_move_placements_still_bind(self) -> None:
        platforms = REPO_ROOT / "platforms"
        cases = (
            ("rocknix", "armsx2", "/storage/roms/bios/armsx2"),
            ("retrodeck", "gzdoom", "$roms_path/doom"),
            ("retrodeck", "xroar", "$roms_path/coco"),
            ("retrobat", "xroar", "bios/coco"),
        )
        for platform, emulator, directory in cases:
            with self.subTest(platform=platform, emulator=emulator):
                handed = handed_directories(load_platform_config(platform, str(platforms)))
                self.assertIn(
                    directory, {h.directory for h in handed if h.emulator == emulator}
                )

    def test_every_config_record_carries_its_platform_links(self) -> None:
        for path in sorted((REPO_ROOT / "platforms").glob("*.yml")):
            if path.name.startswith("_"):
                continue
            with self.subTest(platform=path.stem):
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertEqual(_config_records_without_evidence(path, document), [])


if __name__ == "__main__":
    unittest.main()
