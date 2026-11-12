"""The expert narrowings of the installer give what the pack builder gives.

`--one-per-slot`, `--emulator X --standalone` and `--source truth` replay,
from the install list alone, the pack builder's options of the same name.
The parity cases build the real packs in memory on every registered
platform and compare each (dest, sha1) with what the installer keeps.
`--find` picks one file by its hash, from the list.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)

# Boards whose cores rank a slot differently from the whole list.
TARGETS = (("retroarch", "switch"), ("batocera", "bcm2711"), ("retropie", "rpi4"),
           ("emudeck", "steamos"), ("knulli", "h700"))


class RealListParity(unittest.TestCase):
    """Each option against the pack builder, every registered platform."""

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        if sys.version_info < (3, 9):
            # The builder's floor: install.py alone keeps 3.8.
            raise unittest.SkipTest("generate_pack.py needs Python 3.9 or newer")
        import generate_pack as gp
        from common import (build_zip_contents_index, list_registered_platforms,
                            load_emulator_profiles, load_platform_config)

        cls.gp = gp
        cls.config = staticmethod(
            lambda plat: load_platform_config(plat, str(REPO_ROOT / "platforms")))
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.zip_contents = build_zip_contents_index(cls.db)
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cls.by_path = {entry["path"]: sha1 for sha1, entry in cls.db["files"].items()}
        cls.platforms = list_registered_platforms(str(REPO_ROOT / "platforms"))
        cls.manifests: dict[str, dict] = {}
        cls.baselines: dict[str, set[str]] = {}

    def manifest(self, plat: str) -> dict:
        if plat not in self.manifests:
            with contextlib.redirect_stdout(io.StringIO()):
                self.manifests[plat] = self.gp.generate_manifest(
                    plat, str(REPO_ROOT / "platforms"), self.db, str(REPO_ROOT / "bios"),
                    str(REPO_ROOT / "platforms" / "_registry.yml"),
                    emulators_dir=str(REPO_ROOT / "emulators"),
                    zip_contents=self.zip_contents, emu_profiles=self.profiles,
                    offline=True)
        return self.manifests[plat]

    def packed(self, plat: str, **options) -> dict[str, str | None]:
        """Each member of the platform pack, below its base, with its sha1,
        None for a member a data directory cache gave: the list carries the
        trees apart (data_directories), and a cache copy at a destination
        the list serves from the collection is no choice of either option."""
        base = self.config(plat).get("base_destination", "")
        record = self.gp.PackRecord()
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.gp.generate_pack(
                plat, str(REPO_ROOT / "platforms"), self.db, str(REPO_ROOT / "bios"),
                str(REPO_ROOT / "tmp"), emulators_dir=str(REPO_ROOT / "emulators"),
                zip_contents=self.zip_contents, emu_profiles=self.profiles,
                offline=True, record=record, **options)
        prefix = f"{base}/" if base else ""
        return {(m[len(prefix):] if prefix and m.startswith(prefix) else m):
                self.by_path.get(record.sources.get(m)) for m in record.members}

    def apart(self, plat: str) -> set[str]:
        """The destinations where the pack built without any option already
        holds other bytes than the list (a data directory cache filling a
        platform entry, held by the pack alone): no option decides them."""
        if plat not in self.baselines:
            fold = str.lower if self.config(plat).get("case_insensitive_fs") else str
            packed = {fold(d): sha1 for d, sha1 in self.packed(plat).items()}
            self.baselines[plat] = {
                fold(f["dest"]) for f in self.manifest(plat)["files"]
                if not f.get("root") and packed.get(fold(f["dest"])) != f["sha1"]}
        return self.baselines[plat]

    def assert_same(self, plat: str, files: list[dict], packed: dict) -> None:
        """The installer's BIOS-tree files and the pack's members the list can
        serve, (dest, sha1) for (dest, sha1). A member the list cannot serve
        (a data tree, a note, a file it omits) is no file of either."""
        full = self.manifest(plat)
        fold = str.lower if self.config(plat).get("case_insensitive_fs") else str
        cached = {fold(d) for d, sha1 in packed.items() if sha1 is None}
        listed = {fold(f["dest"]) for f in [*full["files"], *full.get("truth_files", [])]
                  if not f.get("root")} - cached - self.apart(plat)
        mine = {fold(f["dest"]): f["sha1"] for f in files
                if not f.get("root") and fold(f["dest"]) in listed}
        theirs = {fold(d): s for d, s in packed.items() if fold(d) in listed}
        self.assertEqual(mine, theirs)

    def test_one_per_slot(self):
        dropped = 0
        for plat in self.platforms:
            with self.subTest(platform=plat):
                full = self.manifest(plat)
                files, _omitted = install.one_per_slot(full["files"], full["omitted_files"])
                dropped += len(full["files"]) - len(files)
                self.assert_same(plat, files, self.packed(plat, one_per_slot=True))
        # Real slots decided, not a rule that never drops anything.
        self.assertGreater(dropped, 0)

    def test_one_per_slot_on_a_board(self):
        from common import load_target_config

        for plat, target in TARGETS:
            with self.subTest(platform=plat, target=target):
                cores = sorted(load_target_config(plat, target, str(REPO_ROOT / "platforms")))
                full = self.manifest(plat)
                files, omitted = install.narrow_to_cores(full, cores, target=target)
                files, _omitted = install.one_per_slot(
                    files, omitted, install.designated_cores(full, cores, target))
                self.assert_same(plat, files, self.packed(
                    plat, one_per_slot=True, target_cores=set(cores), target_name=target))

    def test_source_truth(self):
        for plat in self.platforms:
            with self.subTest(platform=plat):
                full = self.manifest(plat)
                files, _omitted = install.truth_lists(full, full["files"],
                                                      full["omitted_files"])
                self.assert_same(plat, files, self.packed(plat, source="truth"))

    def test_standalone(self):
        """Each emulator with a standalone build: every file of the pack
        `--emulator X --standalone` builds, at its place with its bytes,
        and beside them only the platform's own files of its systems."""
        checked = 0
        for plat in self.platforms:
            full = self.manifest(plat)
            for profile in sorted(full.get("standalone_layouts") or {}):
                with self.subTest(platform=plat, emulator=profile):
                    record = self.gp.PackRecord()
                    with contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(io.StringIO()):
                        self.gp.generate_emulator_pack(
                            [profile], str(REPO_ROOT / "emulators"), self.db,
                            str(REPO_ROOT / "bios"), str(REPO_ROOT / "tmp"),
                            standalone=True, zip_contents=self.zip_contents,
                            offline=True, record=record)
                        files, omitted = install._narrow_to_emulators(
                            [profile], full, plat, full["files"], full["omitted_files"])
                    files, _omitted = install.standalone_layout(full, [profile], files,
                                                                omitted)
                    packed = {member: self.by_path[record.sources[member]]
                              for member in record.files
                              if record.sources.get(member) in self.by_path}
                    installed = {entry["dest"]: entry["sha1"] for entry in files
                                 if not entry.get("root")}
                    self.assertEqual({dest: installed.get(dest) for dest in packed}, packed)
                    self.assertEqual(
                        [entry["dest"] for entry in files
                         if entry.get("cores") not in (None, [profile])], [])
                    checked += 1
        self.assertGreater(checked, 0)


def _copy(dest: str, body: bytes, cores: list[str] | None = None, **fields) -> dict:
    return {"dest": dest, "sha1": hashlib.sha1(body).hexdigest(),
            "sha256": hashlib.sha256(body).hexdigest(), "size": len(body),
            "repo_path": f"bios/Test/{dest}", "cores": cores, **fields}


def _claims(**ranks: object) -> dict:
    return {name: {"ranks": rank if isinstance(rank, list) else [rank]}
            for name, rank in ranks.items()}


def _slot(*keys: dict, groups: tuple = ("sony-playstation",)) -> dict:
    return {"groups": list(groups), "keys": list(keys)}


class TheSlotRuleIsTheBuilders(unittest.TestCase):
    """slot_drops against slot.resolve_slot_drops on the same claims."""

    def drops(self, entries: list[dict], reach=None) -> set[str]:
        held = {entry["dest"] for entry in entries}
        return install.slot_drops(entries, held, reach)

    def test_the_lowest_rank_stays(self):
        entries = [_copy("a.bin", b"a", slot=_slot(_claims(duckstation=10))),
                   _copy("b.bin", b"b", slot=_slot(_claims(duckstation=5)))]
        self.assertEqual(self.drops(entries), {"a.bin"})

    def test_an_unranked_candidate_keeps_every_file(self):
        entries = [_copy("a.bin", b"a", slot=_slot(_claims(duckstation=10))),
                   _copy("b.bin", b"b", slot=_slot(_claims(pcsx=None)))]
        self.assertEqual(self.drops(entries), set())

    def test_two_cores_ranking_one_file_differently_keep_it_open(self):
        entries = [_copy("a.bin", b"a", slot=_slot(_claims(duckstation=10, pcsx=1))),
                   _copy("b.bin", b"b", slot=_slot(_claims(duckstation=5)))]
        self.assertEqual(self.drops(entries), set())
        # On a board without pcsx, DuckStation's order decides.
        self.assertEqual(self.drops(entries, {"duckstation"}), {"a.bin"})

    def test_regions_split_a_slot(self):
        entries = [
            _copy("jp.bin", b"j", slot=_slot({"duckstation": {"ranks": [1],
                                                              "regions": ["japan"]}})),
            _copy("us.bin", b"u", slot=_slot({"duckstation": {"ranks": [2],
                                                              "regions": ["north-america"]}})),
        ]
        self.assertEqual(self.drops(entries), set())

    def test_a_file_listed_twice_in_a_group_ties_with_itself(self):
        entries = [_copy("a.bin", b"a", slot=_slot(
                       _claims(px68k=1), groups=("x68000", "x68000"))),
                   _copy("b.bin", b"b", slot=_slot(_claims(px68k=2), groups=("x68000",)))]
        self.assertEqual(self.drops(entries), set())

    @unittest.skipIf(sys.version_info < (3, 9), "slot.py needs Python 3.9 or newer")
    def test_random_slots_against_the_builder(self):
        import random

        import manifestselect
        import slot as slot_mod

        rng = random.Random(7)
        for _round in range(400):
            entries, profiles = [], {}
            for index in range(rng.randint(2, 6)):
                name = f"f{index}.bin"
                for emulator in rng.sample(["ds", "pcsx", "beetle"], rng.randint(1, 2)):
                    rank = rng.choice([None, 1, 2, 3])
                    region = rng.choice([[], ["japan"]])
                    group = rng.choice([None, "ipl", "font"])
                    profiles.setdefault(emulator, {"files": []})["files"].append(
                        {"name": name, "priority": rank, "region": region,
                         **({"group": group} if group else {})})
                entries.append(name)
            reach = set(rng.sample(sorted(profiles), rng.randint(1, len(profiles))))
            groups = {"sys": [(name, name) for name in entries]}
            claims = slot_mod.slot_claims(profiles)
            index_ = slot_mod.build_slot_index({k: v for k, v in profiles.items()
                                                if k in reach})
            expected, _undecided = slot_mod.resolve_slot_drops(groups, index_, set(entries))
            fields = manifestselect._slot_fields(groups, claims)
            listed = [_copy(name, name.encode(), **({"slot": fields[name]}
                                                    if name in fields else {}))
                      for name in entries]
            self.assertEqual(self.drops(listed, reach), expected)


class Lists(unittest.TestCase):
    """A list written for the runs below, in tmp/."""

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.dest = self.root / "bios"

    def write(self, manifest: dict) -> Path:
        path = self.root / "retroarch.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def run_install(self, manifest: dict, *argv: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, RETROBIOS_OS="linux", RETROBIOS_OFFLINE="1")
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", str(self.dest), "--manifest", str(self.write(manifest)),
             "--no-input", *argv],
            capture_output=True, text=True, timeout=120, env=env, check=False)


LIST = {
    "manifest_version": 2, "platform": "retroarch", "source": "full", "regions": [],
    "categorized": True, "slot_fields": True,
    "core_names": {"pcsx_rearmed": [], "duckstation": []},
    "system_cores": {"sony-playstation": ["duckstation", "pcsx_rearmed"]},
    "files": [
        _copy("scph1001.bin", b"one", systems=["sony-playstation"],
              slot=_slot(_claims(duckstation=10))),
        _copy("scph5501.bin", b"two", systems=["sony-playstation"],
              slot=_slot(_claims(duckstation=5)), md5=hashlib.md5(b"two").hexdigest()),
        _copy("pcsx/extra.bin", b"extra", ["pcsx_rearmed"], systems=["sony-playstation"],
              truth=False),
        _copy("copy.bin", b"two", systems=["sony-playstation"],
              md5=hashlib.md5(b"two").hexdigest()),
        _copy("x.bin", b"crc-a", crc32="aaaaaaaa"),
        _copy("y.bin", b"crc-b", crc32="aaaaaaaa"),
    ],
    "omitted_files": [],
    "truth_files": [_copy("ds/only.bin", b"truth", ["duckstation"])],
    "truth_omitted": [],
    "standalone_layouts": {"duckstation": [["ds/scph5501.bin",
                                            hashlib.sha1(b"two").hexdigest()]]},
}


class FindByHash(Lists):
    """--find, each kind of hash, with --json and without."""

    def found(self, value: str) -> dict:
        proc = self.run_install(LIST, "--find", value, "--json")
        self.assertIn(proc.returncode, (0, 2), proc.stderr)
        return json.loads(proc.stdout)

    def test_each_kind(self):
        two = LIST["files"][1]
        for kind in ("sha1", "sha256", "md5"):
            with self.subTest(kind=kind):
                said = self.found(two[kind].upper())
                self.assertEqual((said["kind"], said["result"]), (kind, "found"))
                # One content at two destinations: both are the file.
                self.assertEqual([m["dest"] for m in said["matches"]],
                                 ["scph5501.bin", "copy.bin"])
        said = self.found("aaaaaaaa")
        self.assertEqual((said["kind"], said["result"]), ("crc32", "ambiguous"))

    def test_the_shape_is_stable(self):
        said = self.found(LIST["files"][1]["sha1"])
        self.assertEqual(list(said), ["schema", "platform", "hash", "kind", "result",
                                      "matches"])
        self.assertEqual(said["schema"], 1)
        self.assertEqual(list(said["matches"][0]), ["dest", "root", "sha1", "sha256", "md5",
                                                    "size", "systems", "cores"])

    def test_unknown_ambiguous_and_unrecorded(self):
        unknown = self.run_install(LIST, "--find", "0" * 40, "--json")
        self.assertEqual(unknown.returncode, 2)
        self.assertEqual(json.loads(unknown.stdout)["result"], "unknown")
        for value, words in (("0" * 40, "no file of the retroarch list has the sha1"),
                             ("aaaaaaaa", "2 files of the retroarch list have the crc32")):
            with self.subTest(value=value):
                proc = self.run_install(LIST, "--find", value, "--dry-run")
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn(words, proc.stderr)
        bare = copy.deepcopy(LIST)
        for entry in bare["files"]:
            entry.pop("md5", None)
        proc = self.run_install(bare, "--find", "1" * 32, "--json")
        self.assertEqual(json.loads(proc.stdout)["result"], "unrecorded")

    def test_without_json_it_names_the_file_and_plans_it_alone(self):
        sha1 = LIST["files"][0]["sha1"]
        proc = self.run_install(LIST, "--find", sha1, "--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"{sha1} is scph1001.bin", proc.stdout)
        self.assertNotIn("scph5501.bin", proc.stdout)


class ExpertRuns(Lists):
    """The options on a run, and the lists that cannot apply them."""

    def plan(self, manifest: dict, *argv: str) -> str:
        proc = self.run_install(manifest, "--dry-run", "--verbose", *argv)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stdout

    def test_each_option_narrows_the_run(self):
        said = self.plan(LIST, "--one-per-slot")
        self.assertIn("One BIOS per console and region: 6 to 5 files", said)
        said = self.plan(LIST, "--source", "truth")
        self.assertIn("What the emulator profiles prove is read: 6 to 6 files", said)
        self.assertIn("ds/only.bin", said)
        self.assertNotIn("pcsx/extra.bin", said)
        said = self.plan(LIST, "--emulator", "duckstation", "--standalone")
        self.assertIn("ds/scph5501.bin", said)

    def test_a_list_without_the_fields_is_refused(self):
        older = copy.deepcopy(LIST)
        for field in ("slot_fields", "truth_files", "truth_omitted", "standalone_layouts"):
            older.pop(field)
        for argv, words in (
            (["--one-per-slot"], "which --one-per-slot needs"),
            (["--source", "truth"], "which --source truth needs"),
            (["--emulator", "duckstation", "--standalone"], "which --standalone needs"),
        ):
            with self.subTest(argv=argv):
                proc = self.run_install(older, "--dry-run", *argv)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn(words, proc.stderr)

    def test_an_emulator_without_a_standalone_build_is_refused(self):
        proc = self.run_install(LIST, "--dry-run", "--emulator", "pcsx_rearmed",
                                "--standalone")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("pcsx_rearmed has no standalone build", proc.stderr)

    def test_a_malformed_field_is_refused_at_the_boundary(self):
        for field, value in (("slot", {"groups": ["s"], "keys": [{"ds": {"ranks": ["1"]}}]}),
                             ("truth", True)):
            with self.subTest(field=field):
                bad = copy.deepcopy(LIST)
                bad["files"][0][field] = value
                with self.assertRaises(ValueError):
                    install._validate_manifest(bad, "retroarch")
        bad = copy.deepcopy(LIST)
        bad["standalone_layouts"]["duckstation"] = [["../x.bin", "0" * 40]]
        with self.assertRaises(ValueError):
            install._validate_manifest(bad, "retroarch")
        install._validate_manifest(copy.deepcopy(LIST), "retroarch")


class ChangeRows(unittest.TestCase):
    """The two rows of Change and the flags they give the runs."""

    def state(self, manifest: dict) -> install.TuiState:
        state = install.TuiState(os_type="linux")
        state.platform, state.dest = "retroarch", Path("/x/bios")
        state.manifest, state.manifest_for = manifest, "retroarch"
        state.stack = ["plan", "options"]
        return state

    def actions(self, state: install.TuiState) -> list[str]:
        return [row.action for row in install.tui_rows(state)]

    def test_one_per_slot_on_the_whole_list(self):
        state = self.state(LIST)
        self.assertIn("slot", self.actions(state))
        state.focus["options"] = self.actions(state).index("slot")
        install.tui_update(state, install.TuiKey("enter"))
        self.assertIn(("--one-per-slot", None), install.tui_flags(state))
        # A choice of emulator narrows the list first: the row and its flag go.
        state.emulators = ["duckstation"]
        self.assertNotIn("slot", self.actions(state))
        self.assertNotIn(("--one-per-slot", None), install.tui_flags(state))

    def test_standalone_when_the_emulator_has_a_build(self):
        state = self.state(LIST)
        self.assertNotIn("standalone", self.actions(state))
        state.emulators = ["duckstation"]
        state.focus["options"] = self.actions(state).index("standalone")
        install.tui_update(state, install.TuiKey("enter"))
        self.assertIn(("--standalone", None), install.tui_flags(state))
        state.emulators = ["pcsx_rearmed"]
        self.assertNotIn("standalone", self.actions(state))
        self.assertNotIn(("--standalone", None), install.tui_flags(state))

    def test_no_row_on_a_list_without_the_fields(self):
        older = {key: value for key, value in LIST.items()
                 if key not in ("slot_fields", "standalone_layouts")}
        state = self.state(older)
        state.emulators = ["duckstation"]
        self.assertFalse({"slot", "standalone"} & set(self.actions(state)))


if __name__ == "__main__":
    unittest.main()
