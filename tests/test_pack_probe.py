"""pack_probe.py tests a platform's pack the way a user installs it.

The rules (which cores a platform runs, what is staged, how a run maps back
to the pack, the verdict read from a record, the line written) are checked
on synthetic data. Two classes lay a real BIOS folder out from this
checkout, one per install path: the pack generate_pack.py builds, extracted,
and install.py --dest from that pack and the published manifest. They are
narrowed to one system to stay short, and skip when the collection is not
on disk.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import io
import json
import re
import shutil
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

import sys  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import measurement_records as mr  # noqa: E402
import pack_probe as pp  # noqa: E402

TMP = REPO_ROOT / "tmp" / "tests" / "pack_probe"

SATURN = {
    "type": "libretro",
    "cores": ["mednafen_saturn", "beetle-saturn"],
    "systems": ["sega-saturn"],
    "files": [
        {"name": "sega_101.bin", "region": ["japan"]},
        {"name": "mpr-17933.bin", "aliases": ["saturn_bios.bin"]},
        {"name": "standalone.bin", "mode": "standalone"},
    ],
}
SCANNER = {
    "type": "libretro",
    "cores": ["swanstation"],
    "systems": ["sony-playstation"],
    "found_by": "content",
    "files": [{"name": "scph5501.bin", "size": 524288},
              {"name": "ps2.bin", "size": [524288, 4194304]}],
}
KRONOS = {
    "type": "libretro",
    "cores": ["kronos"],
    "systems": ["sega-saturn"],
    "files": [{"name": "saturn_bios.bin", "path": "kronos/saturn_bios.bin"}],
}


def layout(files: dict[str, int], entries: dict[str, str | None] | None = None) -> pp.Layout:
    """A layout whose sizes are given, nothing on disk."""
    return pp.Layout("pack", Path("/nonexistent"), entries or {rel: rel for rel in files}, {},
                     sizes=dict(files))


class CoreChoice(unittest.TestCase):
    def test_system_ids_compare_normalised(self) -> None:
        config = {"systems": {"megacd": {}, "psx": {}}}
        self.assertEqual(pp.platform_system(config, "sega-mega-cd"), "megacd")
        self.assertIsNone(pp.platform_system(config, "sega-saturn"))

    def test_standalone_only_is_not_run_as_a_core(self) -> None:
        both = {"type": "standalone + libretro", "cores": ["duckstation", "duckstation-sa"]}
        self.assertTrue(pp.libretro_build_runs("duckstation", both, {}))
        self.assertFalse(pp.libretro_build_runs("duckstation", both, {"standalone_cores": ["duckstation"]}))
        self.assertTrue(pp.libretro_build_runs("duckstation", both, {
            "standalone_cores": ["duckstation"], "dual_mode_cores": ["duckstation-sa"]}))
        self.assertFalse(pp.libretro_build_runs("x", {"type": "standalone"}, {}))
        self.assertFalse(pp.libretro_build_runs("x", {"type": "alias"}, {}))

    def test_buildbot_name(self) -> None:
        buildbot = {"mednafen_psx", "mednafen_psx_hw", "kronos"}
        beetle = {"cores": ["beetle_psx", "mednafen_psx", "mednafen_psx_hw"]}
        # The target names both builds: both run.
        self.assertEqual(pp.so_names("beetle_psx", beetle, buildbot, {"mednafen_psx", "mednafen_psx_hw"}),
                         ["mednafen_psx", "mednafen_psx_hw"])
        # A target in the platform's own names: the first buildbot name.
        self.assertEqual(pp.so_names("beetle_psx", beetle, buildbot, {"beetle-psx"}), ["mednafen_psx"])
        self.assertEqual(pp.so_names("kronos", {"cores": ["kronos"]}, buildbot, None), ["kronos"])
        self.assertEqual(pp.so_names("gone", {"cores": ["gone"]}, buildbot, None), [])

    def test_choose_cores(self) -> None:
        profiles = {"beetle_saturn": SATURN, "kronos": KRONOS, "swanstation": SCANNER,
                    "ssf": {"type": "standalone", "cores": ["ssf"], "systems": ["sega-saturn"]}}
        config = {"_key": "p", "cores": ["beetle-saturn", "kronos", "ssf", "swanstation"],
                  "systems": {"saturn": {}}}
        buildbot = {"mednafen_saturn", "kronos", "swanstation"}
        self.assertEqual(pp.choose_cores(config, profiles, "sega-saturn", buildbot, None),
                         [pp.CoreChoice("beetle_saturn", "mednafen_saturn"), pp.CoreChoice("kronos", "kronos")])


class Staging(unittest.TestCase):
    FILES = {"sega_101.bin": 524288, "saturn_bios.bin": 524288, "scph5501.bin": 524288,
             "big.bin": 4194304, "other.rom": 1000, "kronos/saturn_bios.bin": 524288,
             "kronos/stvbios.zip": 10, "mame/hash/saturn.xml": 5, "standalone.bin": 1}

    def test_declared_names_aliases_and_platform_list(self) -> None:
        staged = pp.initial_stage(layout(self.FILES), SATURN, ["other.rom", "absent.bin"])
        self.assertEqual(staged, {"sega_101.bin", "saturn_bios.bin", "other.rom"})

    def test_a_folder_comes_whole(self) -> None:
        staged = pp.initial_stage(layout(self.FILES), KRONOS, [])
        self.assertEqual(staged, {"kronos/saturn_bios.bin", "kronos/stvbios.zip"})

    def test_a_core_that_scans_gets_every_root_file_of_its_sizes(self) -> None:
        staged = pp.initial_stage(layout(self.FILES), SCANNER, [])
        self.assertEqual(staged, {"sega_101.bin", "saturn_bios.bin", "scph5501.bin", "big.bin"})

    def test_grow_to_a_fixed_point(self) -> None:
        staged = {"sega_101.bin"}
        added = pp.grow_stage(self.FILES, staged, ["other.rom", "absent.bin", "mame/hash", "kronos"])
        self.assertEqual(added, {"other.rom", "mame/hash/saturn.xml", "kronos/saturn_bios.bin",
                                 "kronos/stvbios.zip"})
        self.assertEqual(pp.grow_stage(self.FILES, staged | added, ["absent.bin"]), set())


class Mapping(unittest.TestCase):
    def test_opened_files_map_to_their_entry_and_probes_to_findings(self) -> None:
        lay = layout({"sega_101.bin": 1, "BIOS/Saturn_BIOS.bin": 1, "extra.bin": 1},
                     {"sega_101.bin": "sega_101.bin", "BIOS/Saturn_BIOS.bin": "BIOS/Saturn_BIOS.bin",
                      "extra.bin": None})
        rep = {"files_opened": [{"path": "sega_101.bin", "sha1_after": "a" * 40},
                                {"path": "extra.bin", "sha1_after": "b" * 40},
                                {"path": "bkram.bin", "sha1_after": "c" * 40}],
               "files_probed_absent": ["saturn_bios.bin", "mpr-17933.bin", "cfg.ini"]}
        opened, findings = pp.map_run(lay, {"sega_101.bin", "extra.bin"}, rep, SATURN)
        self.assertEqual(opened, [
            {"path": "sega_101.bin", "entry": "sega_101.bin", "sha1": "a" * 40, "created": False},
            {"path": "extra.bin", "entry": None, "sha1": "b" * 40, "created": False},
            {"path": "bkram.bin", "entry": None, "sha1": "c" * 40, "created": True}])
        self.assertEqual(findings, [
            {"kind": "elsewhere", "path": "saturn_bios.bin", "declared_by": ["mpr-17933.bin"],
             "paths": ["BIOS/Saturn_BIOS.bin"]},
            {"kind": "missing_declared", "path": "mpr-17933.bin", "declared_by": ["mpr-17933.bin"], "paths": []},
            {"kind": "missing_undeclared", "path": "cfg.ini", "declared_by": [], "paths": []},
            {"kind": "unlisted", "path": "extra.bin", "declared_by": [], "paths": []}])

    def test_a_name_tried_before_an_alias_that_is_read_is_no_finding(self) -> None:
        profile = {"files": [{"name": "tmss.md", "aliases": ["bios_MD.bin"]}, {"name": "bios_CD_U.bin"}]}
        lay = layout({"bios_MD.bin": 1})
        rep = {"files_opened": [{"path": "bios_MD.bin", "sha1_after": "a" * 40}],
               "files_probed_absent": ["tmss.md", "bios_CD_U.bin"]}
        _, findings = pp.map_run(lay, {"bios_MD.bin"}, rep, profile)
        self.assertEqual(findings, [{"kind": "missing_declared", "path": "bios_CD_U.bin",
                                     "declared_by": ["bios_CD_U.bin"], "paths": []}])

    def test_manifest_entries(self) -> None:
        manifest = {"files": [{"dest": "a.bin"}],
                    "case_variants": [{"dest": "A.BIN"}, {"dest": "a.bin"}],
                    "data_directories": [{"ref": "bluemsx", "dest": "", "files": {"Machines/x.ini": {}}},
                                         {"ref": "dolphin", "dest": "dolphin-emu/Sys/", "files": {"y": {}}}]}
        self.assertEqual(pp.manifest_entries(manifest), {
            "a.bin": "files:a.bin", "A.BIN": "case_variants:A.BIN",
            "Machines/x.ini": "data_directories:bluemsx:Machines/x.ini",
            "dolphin-emu/Sys/y": "data_directories:dolphin:y"})


class Verdict(unittest.TestCase):
    def test_a_record_before_the_oracle_is_unknown(self) -> None:
        self.assertEqual(pp.run_verdict(None), ("unknown", None))
        self.assertEqual(pp.run_verdict({"variants": [{"repetitions": [{}]}]}), ("unknown", None))

    def test_the_first_variant_decides(self) -> None:
        evidence = {"rule": "reference_frame", "detail": "frame 120"}
        record = {"variants": [{"verdict": "boots", "verdict_evidence": evidence, "repetitions": [{}]}]}
        self.assertEqual(pp.run_verdict(record), ("boots", evidence))
        self.assertEqual(pp.run_verdict({"variants": [{"verdict": "maybe"}]}), ("unknown", None))


class Line(unittest.TestCase):
    def setUp(self) -> None:
        self.root = TMP / "line"
        shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True)

    def line(self) -> dict:
        return {
            "schema_version": 1, "probed_at": "2026-10-27T12:00:00+00:00", "platform": "retroarch",
            "platform_version": "v1.22.2", "target": "linux-x86_64", "install": "pack",
            "source": {"pack": {"file": "RetroArch_BIOS_Pack.zip", "sha256": "0" * 64, "size": 1,
                                "members": 1}, "manifest": None, "repo_commit": "1" * 40},
            "system": "sega-saturn", "platform_system": "sega-saturn", "emulator": "beetle_saturn",
            "core": {"file": "mednafen_saturn_libretro.so", "sha256": "2" * 64,
                     "artifact": "https://buildbot.libretro.com/x.zip", "last_modified": None},
            "content": {"label": "Game (Japan)", "catalog": "redump", "region": "japan"},
            "records": ["2026-10-27-0123456789ab"], "rounds": 1, "staged": 3, "verdict": "unknown",
            "verdict_evidence": None,
            "files_opened": [{"path": "sega_101.bin", "entry": "sega_101.bin", "sha1": "3" * 40,
                              "created": False}],
            "findings": [{"kind": "missing_declared", "path": "x.bin", "declared_by": ["x.bin"], "paths": []}],
            "error": None,
        }

    def test_the_line_is_sealed_valid_and_read_back(self) -> None:
        sealed = pp.append_line(self.line(), self.root)
        self.assertEqual(mr.read_campaign(self.root, mr.PACK_PROBES), [sealed])
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")
        schema = json.loads((REPO_ROOT / "schemas" / "pack-probe.schema.json").read_text())
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(sealed)), [])

    def test_the_cli_refuses_an_unknown_platform(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            pp.main(["run", "--platform", "nowhere"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pp.main(["plan", "-p", "Lakka"]), 2)


class SitePages(unittest.TestCase):
    """A pack probe runs before a release: its records stay in measurements/
    and reach no page."""

    def test_the_pack_blocks_are_gone(self) -> None:
        import sitemeasurements as sm

        for name in ("pack_summary", "packs_section", "pack_tested_section", "by_platform"):
            self.assertFalse(hasattr(sm, name), name)

    def test_pack_runs_stay_off_the_emulator_page(self) -> None:
        import sitemeasurements as sm

        subject = pp.subject_for("retroarch", "pack", "sega-saturn", "mednafen_saturn", "Game (Japan)")
        self.assertEqual(subject, "pack-retroarch-pack-sega-saturn-mednafen-saturn-game-japan")
        index = {"items": [{"emulator": "beetle_saturn", "subject": subject},
                           {"emulator": "beetle_saturn", "subject": "boot-sega-101-bin"}]}
        self.assertEqual([i["subject"] for i in sm.by_emulator(index)["beetle_saturn"]],
                         ["boot-sega-101-bin"])

    def test_a_markdown_link_keeps_only_safe_targets(self) -> None:
        """A Markdown link in site text keeps only http(s) and relative targets."""
        import sitemarkup

        self.assertEqual(sitemarkup.inline_html("[x](javascript:alert(1))"), "[x](javascript:alert(1))")
        self.assertEqual(sitemarkup.inline_html('[x](https://a.org/"onmouseover=1)'),
                         '<a href="https://a.org/&quot;onmouseover=1">x</a>')
        self.assertEqual(sitemarkup.inline_html("[x](../a.md)"), '<a href="../a.md">x</a>')


class Lock(unittest.TestCase):
    """The probe lock is held for one core_probe run and released after it."""

    def test_held_for_each_run_only(self) -> None:
        import fcntl
        import subprocess
        import unittest.mock

        work = TMP / "lock"
        shutil.rmtree(work, ignore_errors=True)
        lock = work / "probe.lock"
        held = []

        def try_lock() -> bool:
            with lock.open("a") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return True
                fcntl.flock(handle, fcntl.LOCK_UN)
                return False

        def fake_run(command, **kwargs):
            held.append(try_lock())
            self.assertEqual(kwargs["env"]["RETROBIOS_PROBE_LOCK_HELD"], "1")
            self.assertEqual(kwargs["env"]["RETROBIOS_PROBE_LOCK"], str(lock))
            return subprocess.CompletedProcess(command, 2, "", "refused")

        lay = layout({"a.bin": 1})
        with unittest.mock.patch.object(pp, "PROBE_LOCK", lock), \
                unittest.mock.patch.object(pp.subprocess, "run", fake_run):
            for _ in range(2):
                self.assertEqual(pp.core_probe(["run"], {"a.bin"}, lay, work), (2, None, "refused"))
        self.assertEqual(held, [True, True])
        self.assertFalse(try_lock())


class RecordsNameNoLocalPath(unittest.TestCase):
    """A record is read on other machines: the probe's scratch folders are
    written as the options that named them."""

    def test_the_summary_names_the_options(self) -> None:
        root = Path("/srv/run/tmp/pack_probe/retroarch/installer")
        out = (f"Copy it from an owned copy of the game into {root / 'system'}/jazz2/Source/.\n"
               f"Saves go to {root / 'saves'}.\n")
        summary = pp.installer_summary(out, root / "system", root / "saves")
        self.assertEqual(summary, "Copy it from an owned copy of the game into <dest>/jazz2/Source/. "
                                  "Saves go to <save-dir>.")

    def test_a_probe_error_names_the_checkout(self) -> None:
        """A core_probe traceback spelled the worktree it ran from."""
        import subprocess
        import unittest.mock

        work = TMP / "error-paths"
        script = pp.ROOT / "scripts" / "core_probe.py"

        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, "", f'  File "{script}", line 9\n')

        with unittest.mock.patch.object(pp, "PROBE_LOCK", work / "probe.lock"), \
                unittest.mock.patch.object(pp.subprocess, "run", fake_run):
            code, record, error = pp.core_probe(["run"], set(), layout({}), work)
        self.assertEqual((code, record), (1, None))
        self.assertEqual(error, 'File "<repo>/scripts/core_probe.py", line 9')

    def test_no_committed_record_holds_a_local_path(self) -> None:
        """Ten records cut at 400 characters inside the scratch path kept
        its tail, which no absolute-path pattern sees."""
        absolute = re.compile(r"(?<![\w.<>-])/(?:home|root|tmp|mnt|Users|srv)/")
        # The tail of a scratch folder: a worktree, or the probes' own tmp/
        # subfolders.
        scratch = re.compile(r"worktrees/|\btmp/(?:pack_probe|tests|campaign)\b")
        found = [
            f"{path.name}:{number}"
            for path in sorted((REPO_ROOT / "measurements").glob("*.jsonl"))
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if absolute.search(line) or scratch.search(line)
        ]
        self.assertEqual(found, [])


def collection_on_disk() -> bool:
    return (REPO_ROOT / "bios" / "Sony" / "PlayStation" / "scph5501.bin").is_file()


@unittest.skipUnless(collection_on_disk(), "the collection is not on disk")
class RealLayouts(unittest.TestCase):
    """Both install paths, from this checkout, narrowed to PlayStation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.work = TMP / "real"
        shutil.rmtree(cls.work, ignore_errors=True)
        cls.pack = pp.build_pack("retroarch", cls.work / "dist", ["--system", "sony-playstation"])
        cls.identity = pp.pack_identity(cls.pack)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_pack_path(self) -> None:
        lay = pp.pack_layout(self.pack, self.work / "pack", self.identity)
        with zipfile.ZipFile(self.pack) as handle:
            members = {i.filename for i in handle.infolist() if not i.is_dir()}
        self.assertEqual(set(lay.files), members)
        self.assertEqual(lay.files["scph5501.bin"], "scph5501.bin")
        self.assertEqual(lay.source["pack"]["members"], len(members))
        swan = pp.load_emulator_profiles(str(REPO_ROOT / "emulators"))["swanstation"]
        self.assertIn("scph5501.bin", pp.initial_stage(lay, swan, []))

    def test_installer_path(self) -> None:
        lay = pp.installer_layout("retroarch", self.pack, self.identity,
                                  REPO_ROOT / "install" / "retroarch.json", self.work / "installer",
                                  ["--system", "sony-playstation"])
        self.assertEqual(lay.root, self.work / "installer" / "system")
        self.assertEqual(lay.files["scph5501.bin"], "files:scph5501.bin")
        self.assertEqual(lay.source["manifest"]["path"], "install/retroarch.json")
        self.assertTrue(all(entry for entry in lay.files.values()), lay.files)
        self.assertNotIn(str(self.work), lay.source["installer_summary"])


if __name__ == "__main__":
    unittest.main()
