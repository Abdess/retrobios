"""Names a platform's launch code reads that the collection does not hold.

The gap analysis compared the collection with the platforms' BIOS lists and
the emulator profiles only. PICO-8's pico8_64 went unseen although four
platforms' launchers run it. The fixtures give a synthetic platform launcher
records of every shape the scrapers write: held names, a name only a profile
alias answers, templates, folders and option values, missing names read by
two emulators, and a name held under another casing.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import yaml  # noqa: E402

import verify  # noqa: E402
from common import _emulator_profiles_cache, load_emulator_profiles, load_platform_config  # noqa: E402
from cross_reference import (  # noqa: E402
    LAUNCHER_READS_KEY,
    launcher_file_names,
    launcher_reads_not_held,
    print_launcher_reads,
)

ROOT = Path(__file__).resolve().parent.parent

CONTENT = {
    "held.bin": b"HELD_BY_NAME",
    "core.bin": b"CORE_FILE_ALIASED",
    "Mixed.ROM": b"HELD_UNDER_ONE_CASING",
}
# Kept as a release asset: in database.json, absent from the checkout.
ASSET = ("asset.bin", b"RELEASE_ASSET_BYTES")


def _record(emulator: str, kind: str, names: list[str], **extra: object) -> dict:
    return {
        "emulator": emulator, "build": "standalone", "kind": kind, "names": names,
        "search_dir": "/userdata/bios", "source_ref": f"gen/{emulator}.py:1", **extra,
    }


LAUNCHERS = [
    _record("heldemu", "names_searched", ["held.bin", "asset.bin"]),
    _record("aliasemu", "fixed_name", ["sub/alias.bin"]),
    _record("tplemu", "names_searched", ["tos{L}.img"], expands={"L": ["de", "fr"]}),
    _record("tplemu", "scans_dir", ["<first file 4-8 MiB>", "nand*{region}*.bin", "pat*.bin"]),
    _record("diremu", "links", ["EUR", "keys"]),
    _record("diremu", "core_option", ["default"]),
    _record("diremu", "passes_path", []),
    {"emulator": "pkg", "build": "standalone", "kind": "package", "names": [],
     "source_ref": "pkg.sh:1"},
    _record("missemu", "names_searched", ["absent.bin"]),
    _record("otheremu", "copies", ["absent.bin"]),
    _record("altemu", "names_searched", ["alt.bin", "held.bin", "late.bin"]),
    _record("pkgemu", "copies", ["shipped.bin"], search_dir="$md_inst"),
    {"emulator": "pkgemu", "build": "standalone", "kind": "copies",
     "names": ["written.ini"], "source_ref": "pkg.sh:2"},
    _record("setemu", "fixed_name", ["setname.bin"], passes_to="command line -romslot"),
    _record("aliasemu", "fixed_name", ["alias.bin.rom"]),
    _record("setemu", "copies", ["user.sf2"]),
    _record("caseemu", "fixed_name", ["mixed.rom"]),
    _record("foldemu", "fixed_name", ["MIXED.rom"], case_insensitive=True),
    _record("toolemu", "fixed_name", ["tool.exe"], search_dir="<emulatorLauncher folder>",
            passes_to="exec"),
    _record("labelemu", "core_option", ["labelled.rom (CDZ)"]),
]


class LauncherGapTest(unittest.TestCase):
    def setUp(self) -> None:
        _emulator_profiles_cache.clear()
        self.root = tempfile.mkdtemp()
        self.bios_dir = os.path.join(self.root, "bios")
        self.platforms_dir = os.path.join(self.root, "platforms")
        self.emulators_dir = os.path.join(self.root, "emulators")
        for d in (self.bios_dir, self.platforms_dir, self.emulators_dir):
            os.makedirs(d)
        files: dict[str, dict] = {}
        by_md5: dict[str, str] = {}
        by_name: dict[str, list[str]] = {}

        def add(name: str, data: bytes, write: bool) -> None:
            path = os.path.join(self.bios_dir, name)
            if write:
                Path(path).write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            files[sha1] = {"path": path, "name": name, "md5": md5, "sha1": sha1,
                           "size": len(data), "crc32": ""}
            by_md5[md5] = sha1
            by_name.setdefault(name, []).append(sha1)

        for name, data in CONTENT.items():
            add(name, data, write=True)
        add(*ASSET, write=False)
        self.db = {
            "files": files,
            "indexes": {"by_md5": by_md5, "by_name": by_name, "by_crc32": {},
                        "by_path_suffix": {}},
        }
        platform = {
            "platform": "GapTest",
            "verification_mode": "md5",
            "base_destination": "bios",
            "systems": {
                "test-sys": {
                    "files": [{"name": "held.bin", "destination": "held.bin",
                               "md5": hashlib.md5(CONTENT["held.bin"]).hexdigest(),
                               "required": True}],
                },
            },
            "launchers": LAUNCHERS,
        }
        (Path(self.platforms_dir) / "gaptest.yml").write_text(yaml.dump(platform))
        (Path(self.platforms_dir) / "_registry.yml").write_text(
            yaml.dump({"platforms": {"gaptest": {"config": "gaptest.yml"}}})
        )
        profiles = {
            "aliasemu": {
                "emulator": "AliasEmu", "type": "standalone", "systems": ["test-sys"],
                "files": [{"name": "core.bin", "aliases": ["alias.bin"], "required": True}],
            },
            "setemu": {
                "emulator": "SetEmu", "type": "standalone", "systems": ["test-sys"],
                "files": [{"name": "core.bin", "config_key": "romslot", "required": True},
                          {"name": "user.sf2", "required": False,
                           "unsourceable": "user supplied, no canonical file"}],
            },
            "missemu": {
                "emulator": "MissEmu", "type": "standalone", "systems": ["test-sys"],
                "files": [{"name": "absent.bin", "required": True, "md5": "0" * 32}],
            },
        }
        for key, profile in profiles.items():
            (Path(self.emulators_dir) / f"{key}.yml").write_text(yaml.dump(profile))
        self.config = load_platform_config("gaptest", self.platforms_dir)
        self.profiles = load_emulator_profiles(self.emulators_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    def _rows(self, configs: dict[str, dict] | None = None, emulator: str = "") -> dict:
        rows = launcher_reads_not_held(
            configs or {"gaptest": self.config}, self.db, self.profiles, {}, emulator
        )
        return {(r["platform"], r["name"]): r for r in rows}

    def test_a_program_of_the_launcher_itself_is_not_reported(self) -> None:
        """RetroBat runs its own xbox-iso-vfs.exe to mount an Xbox disc
        image: part of the platform, no file to collect."""
        self.assertNotIn("tool.exe", {name for _, name in self._rows()})

    def test_a_held_name_is_not_reported(self) -> None:
        names = {name for _, name in self._rows()}
        self.assertNotIn("held.bin", names)

    def test_a_release_asset_is_held_without_its_bytes(self) -> None:
        """The database answers for a file the checkout does not carry."""
        self.assertFalse(os.path.exists(os.path.join(self.bios_dir, "asset.bin")))
        self.assertNotIn("asset.bin", {name for _, name in self._rows()})

    def test_a_profile_alias_covers_a_launcher_name(self) -> None:
        """alias.bin is the name core.bin's profile entry also answers to."""
        self.assertNotIn("sub/alias.bin", {name for _, name in self._rows()})

    def test_templates_folders_and_option_values_are_skipped(self) -> None:
        for record in LAUNCHERS:
            if record["emulator"] in ("tplemu", "diremu", "pkg"):
                self.assertEqual(launcher_file_names(record), [], record)
        reported = {r["emulators"][0] for r in self._rows().values()}
        self.assertFalse(reported & {"tplemu", "diremu", "pkg"})

    def test_a_search_with_one_held_name_reads_nothing_missing(self) -> None:
        """The launcher keeps the first name it finds, so the held one fills it."""
        names = {name for _, name in self._rows()}
        self.assertFalse(names & {"alt.bin", "late.bin"})

    def test_a_copy_from_the_platform_package_is_not_owed(self) -> None:
        """RetroPie copies lr-vecx's system.bin from $md_inst and writes mame.ini."""
        names = {name for _, name in self._rows()}
        self.assertFalse(names & {"shipped.bin", "written.ini"})

    def test_a_name_with_an_appended_extension_is_held(self) -> None:
        """ROCKNIX's kick34005.A500.rom is Amiberry's kick34005.A500."""
        self.assertNotIn("alias.bin.rom", {name for _, name in self._rows()})

    def test_a_name_its_reader_declares_unsourceable_is_counted_apart(self) -> None:
        """RetroBat copies any SoundFont saved as Roland_SC-88.sf2: not a
        file to find, yet never dropped silently."""
        row = self._rows()[("gaptest", "user.sf2")]
        self.assertEqual(row["unsourceable"], "user supplied, no canonical file")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_launcher_reads(list(self._rows().values()))
        text = out.getvalue()
        self.assertIn("Launcher reads, not held: 3 names", text)
        self.assertIn("Launcher reads, unsourceable: 1 names across 1 platform", text)
        self.assertIn("gaptest: user.sf2 [setemu, gen/setemu.py:1]: user supplied, no canonical file",
                      text)
        held_part = text.split("Launcher reads, unsourceable")[0]
        self.assertNotIn("user.sf2", held_part)

    def test_a_name_handed_to_a_held_entry_setting_is_held(self) -> None:
        self.assertNotIn("setname.bin", {name for _, name in self._rows()})

    def test_a_label_after_the_name_is_dropped(self) -> None:
        self.assertEqual(launcher_file_names(LAUNCHERS[-1]), ["labelled.rom"])
        self.assertIn(("gaptest", "labelled.rom"), self._rows())

    def test_a_missing_name_is_reported_once_per_platform(self) -> None:
        rows = self._rows()
        row = rows[("gaptest", "absent.bin")]
        self.assertEqual(row["emulators"], ["missemu", "otheremu"])
        self.assertEqual(
            [(r["kind"], r["source_ref"]) for r in row["readers"]],
            [("names_searched", "gen/missemu.py:1"), ("copies", "gen/otheremu.py:1")],
        )
        self.assertEqual(row["readers"][0]["profiles"], ["missemu"])
        self.assertNotIn("held_as", row)
        self.assertEqual(sum(1 for _, name in rows if name == "absent.bin"), 1)

    def test_each_platform_reports_its_own_row(self) -> None:
        rows = self._rows({"gaptest": self.config, "second": self.config})
        self.assertIn(("gaptest", "absent.bin"), rows)
        self.assertIn(("second", "absent.bin"), rows)

    def test_an_emulator_keeps_its_own_records(self) -> None:
        rows = self._rows(emulator="missemu")
        self.assertEqual(list(rows), [("gaptest", "absent.bin")])
        self.assertEqual(rows[("gaptest", "absent.bin")]["emulators"], ["missemu"])

    def test_another_casing_satisfies_only_a_folding_launcher(self) -> None:
        rows = self._rows()
        self.assertEqual(rows[("gaptest", "mixed.rom")]["held_as"], "Mixed.ROM")
        self.assertEqual(rows[("gaptest", "mixed.rom")]["emulators"], ["caseemu"])
        self.assertNotIn(("gaptest", "MIXED.rom"), rows)

    def test_a_folding_filesystem_folds_every_record(self) -> None:
        config = {**self.config, "case_insensitive_fs": True}
        self.assertNotIn(("gaptest", "mixed.rom"), self._rows({"gaptest": config}))

    def test_the_text_report_names_the_category(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_launcher_reads(list(self._rows().values()))
        text = out.getvalue()
        self.assertIn("Launcher reads, not held: 3 names across 1 platform", text)
        self.assertIn("absent.bin [missemu, otheremu, names_searched, gen/missemu.py:1]", text)

    def test_json_carries_the_category_apart(self) -> None:
        db_path = Path(self.root) / "database.json"
        db_path.write_text(json.dumps(self.db))
        result = subprocess.run(
            [sys.executable, "scripts/cross_reference.py", "--platform", "gaptest",
             "--platforms-dir", self.platforms_dir, "--emulators-dir", self.emulators_dir,
             "--db", str(db_path), "--json"],
            cwd=ROOT, capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        names = {r["name"] for r in report[LAUNCHER_READS_KEY]}
        self.assertEqual(names, {"absent.bin", "mixed.rom", "labelled.rom", "user.sf2"})
        # The emulator rows keep their own shape and counts.
        self.assertEqual(set(report) - {LAUNCHER_READS_KEY}, {"aliasemu", "missemu", "setemu"})

    def test_verify_counts_and_exit_code_are_unchanged(self) -> None:
        """A launcher name is reported, not judged: nothing else moves."""
        with_rows = verify.verify_platform(
            self.config, self.db, self.emulators_dir, self.profiles, data_dir_registry={}
        )
        with mock.patch.object(verify, "launcher_reads_not_held", return_value=[]):
            without = verify.verify_platform(
                self.config, self.db, self.emulators_dir, self.profiles,
                data_dir_registry={},
            )
        rows = with_rows.pop("launcher_reads_not_held")
        without.pop("launcher_reads_not_held")
        self.assertEqual({r["name"] for r in rows},
                         {"absent.bin", "mixed.rom", "labelled.rom", "user.sf2"})
        self.assertEqual(with_rows, without)

        def exit_code(result: dict) -> int:
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    verify._exit_if_strict(True, [result])
            except SystemExit as exc:
                return int(exc.code or 0)
            return 0

        self.assertEqual(exit_code({**with_rows, "launcher_reads_not_held": rows}),
                         exit_code(without))

    def test_verify_prints_a_count_and_lists_on_verbose(self) -> None:
        result = verify.verify_platform(
            self.config, self.db, self.emulators_dir, self.profiles, data_dir_registry={}
        )
        for verbose, expected in ((False, "(--verbose lists them)"), (True, "absent.bin")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                verify.print_platform_result(result, ["GapTest"], verbose=verbose)
            self.assertIn("Launcher reads, not held: 3", out.getvalue())
            self.assertIn(expected, out.getvalue())


if __name__ == "__main__":
    unittest.main()
