"""The RetroBIOS app put on a handheld's card from a computer (--add-app).

Cards are folders holding the files their systems write, the repository a
loopback copy of the launcher list and the files it names. What a console
then does with the files (the Archive Manager, the Ports list, the Tools
menu) is not exercised.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import install  # noqa: E402
from test_install_selection import FakeRepository  # noqa: E402

INDEX = REPO_ROOT / "install" / "launchers" / "index.json"


def make_card(root: Path, system: str) -> Path:
    """A card as each system leaves it, and the BIOS folder on it."""
    bios = _card_files(root, system)
    bios.mkdir(parents=True, exist_ok=True)
    return bios


def _card_files(root: Path, system: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if system == "muOS":
        (root / "MUOS" / "bios").mkdir(parents=True)
        return root / "MUOS" / "bios"
    if system == "KNULLI":
        (root / "system").mkdir()
        (root / "system" / "batocera.conf").write_text("system.hostname=KNULLI\n")
        return root / "bios"
    if system == "ROCKNIX":
        (root / ".config" / "system" / "configs").mkdir(parents=True)
        (root / ".config" / "system" / "configs" / "system.cfg").write_text(
            "root.password=rocknix\n")
        return root / "roms" / "bios"
    if system == "Onion":
        (root / ".tmp_update" / "onionVersion").mkdir(parents=True)
        (root / ".tmp_update" / "onionVersion" / "version.txt").write_text("4.3.1\n")
        return root / "BIOS"
    if system == "spruceOS":
        (root / "spruce").mkdir()
        return root / "BIOS"
    if system == "MinUI":
        (root / ".system").mkdir()
        (root / ".system" / "version.txt").write_text("MinUI-20250101\n")
        return root
    raise ValueError(system)


# The file list each card's system gets.
CARD_PLATFORMS = {"muOS": "retroarch", "KNULLI": "knulli", "ROCKNIX": "rocknix",
                  "Onion": "retroarch", "spruceOS": "retroarch", "MinUI": "minui"}


class AppRepository(FakeRepository):
    """The fake repository with the launcher list and every file it names,
    and the BIOS lists of the systems whose cards are tried."""

    def __enter__(self) -> AppRepository:
        super().__enter__()
        index = json.loads(INDEX.read_text(encoding="utf-8"))
        (self.root / "install" / "launchers").mkdir()
        (self.root / "install" / "launchers" / "index.json").write_text(json.dumps(index))
        for launcher in index["launchers"].values():
            for entry in launcher.get("files", launcher.get("members", [])):
                if "repo_path" in entry:
                    target = self.root / entry["repo_path"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(REPO_ROOT / entry["repo_path"], target)
        base = json.loads((self.root / "install" / "retroarch.json").read_text())
        for plat in ("knulli", "rocknix", "minui"):
            (self.root / "install" / f"{plat}.json").write_text(
                json.dumps({**base, "platform": plat}))
        return self

    def card(self, system: str) -> tuple[Path, Path]:
        root = self.root / "cards" / system
        return root, make_card(root, system)

    def tamper(self, repo_path: str) -> None:
        """One byte changed, the size kept: only the hash tells."""
        path = self.root / repo_path
        data = bytearray(path.read_bytes())
        data[-1] ^= 0x20
        path.write_bytes(bytes(data))

    def cli(self, *options: str, env: dict | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), *options],
            env={**self.env(), **(env or {})}, capture_output=True, text=True,
            timeout=120, check=False, stdin=subprocess.DEVNULL)


def _tempdir(test: unittest.TestCase) -> Path:
    (REPO_ROOT / "tmp").mkdir(exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
    test.addCleanup(shutil.rmtree, path, True)
    return path


class Placement(unittest.TestCase):
    def test_each_card_and_where_its_app_goes(self):
        root = _tempdir(self)
        expected = {"muOS": "ARCHIVE", "KNULLI": "roms/ports", "ROCKNIX": ".config/modules"}
        for system, folder in expected.items():
            with self.subTest(system=system):
                card = install.card_app(make_card(root / system, system))
                self.assertIsNotNone(card)
                self.assertEqual(card.system, system)
                self.assertEqual(card.root, root / system)
                self.assertEqual(card.place.folder, folder)
                self.assertEqual(card.why, "")

    def test_a_bios_folder_inside_the_card_finds_its_root(self):
        root = _tempdir(self)
        bios = make_card(root / "sd1", "muOS")
        bios.mkdir(parents=True, exist_ok=True)
        self.assertEqual(install.card_app(bios).root, root / "sd1")
        # The card's root itself is not its BIOS folder.
        self.assertIsNone(install.card_app(root / "sd1"))

    def test_cards_without_a_launcher_say_why(self):
        root = _tempdir(self)
        for system, words in (("Onion", "has no Python"), ("MinUI", "has no Python"),
                              ("spruceOS", "no RetroBIOS app for spruceOS")):
            with self.subTest(system=system):
                card = install.card_app(make_card(root / system, system))
                self.assertIsNone(card.place)
                self.assertIn(words, card.why)

    def test_a_folder_on_no_card(self):
        self.assertIsNone(install.card_app(_tempdir(self) / "bios"))

    def test_the_table_names_systems_detection_names(self):
        names = {rule.name for rule in install._card_rules()}
        names |= {install.display_name(name) for name, _f, _p in install._CARD_RULES}
        self.assertLessEqual(set(install.APP_PLACES), names)
        self.assertLessEqual(install.NO_PYTHON_CARDS, names)
        self.assertFalse(set(install.APP_PLACES) & install.NO_PYTHON_CARDS)

    def test_the_list_follows_the_table(self):
        index = json.loads(INDEX.read_text(encoding="utf-8"))
        for place in install.APP_PLACES.values():
            with self.subTest(key=place.key):
                targets = install.app_targets(index, place)
                for target in targets:
                    self.assertTrue(target["dest"].startswith(place.folder + "/"))
                    self.assertEqual(target.get("executable", False) and not place.executable,
                                     False, target["dest"])


class TheList(unittest.TestCase):
    def setUp(self):
        self.index = json.loads(INDEX.read_text(encoding="utf-8"))
        self.place = install.APP_PLACES["KNULLI"]

    def refused(self, change) -> str:
        data = json.loads(json.dumps(self.index))
        change(data["launchers"]["knulli"]["files"][0], data)
        with self.assertRaises(ValueError) as caught:
            install.app_targets(data, self.place)
        return str(caught.exception)

    def test_entries_are_held_to_their_folder(self):
        self.assertIn("outside", self.refused(
            lambda entry, _d: entry.update(dest="roms/RetroBIOS.sh")))
        self.assertIn("unsafe", self.refused(
            lambda entry, _d: entry.update(dest="roms/ports/../../bios/x")))
        self.assertIn("unsafe", self.refused(
            lambda entry, _d: entry.update(repo_path="/etc/passwd")))

    def test_hash_size_and_source_are_checked(self):
        self.assertIn("sha256", self.refused(lambda entry, _d: entry.update(sha256="ab")))
        self.assertIn("size", self.refused(lambda entry, _d: entry.update(size=0)))
        self.assertIn("repo_path or content", self.refused(
            lambda entry, _d: entry.update(content="x")))
        self.assertIn("schema", self.refused(lambda _e, data: data.update(schema=2)))
        self.assertIn("no launcher", self.refused(
            lambda _e, data: data["launchers"].pop("knulli")))

    def test_the_archive_rebuilds_to_its_recorded_hash(self):
        launcher = self.index["launchers"]["muos"]
        members = [(entry, (REPO_ROOT / entry["repo_path"]).read_bytes()
                    if "repo_path" in entry else entry["content"].encode())
                   for entry in launcher["members"]]
        data = install.app_archive(list(reversed(members)))
        # Under every Python the installer runs on: CI runs this under 3.8 too.
        self.assertEqual(hashlib.sha256(data).hexdigest(), launcher["archive"]["sha256"])
        self.assertEqual(len(data), launcher["archive"]["size"])

    @unittest.skipIf(sys.version_info < (3, 9), "the build scripts need Python 3.9")
    def test_the_archive_holds_what_the_release_archive_holds(self):
        launcher = self.index["launchers"]["muos"]
        members = [(entry, (REPO_ROOT / entry["repo_path"]).read_bytes()
                    if "repo_path" in entry else entry["content"].encode())
                   for entry in launcher["members"]]
        data = install.app_archive(members)
        import build_port  # noqa: PLC0415
        built = _tempdir(self) / build_port.MUOS_APP
        build_port.build_archive(build_port.MUOS_APP, built)
        with zipfile.ZipFile(built) as release, zipfile.ZipFile(io.BytesIO(data)) as ours:
            self.assertEqual(release.namelist(), ours.namelist())
            for name in release.namelist():
                self.assertEqual(release.read(name), ours.read(name), name)
                self.assertEqual(release.getinfo(name).external_attr,
                                 ours.getinfo(name).external_attr, name)


class PutTheApp(unittest.TestCase):
    def setUp(self):
        self.repo = AppRepository()
        self.repo.__enter__()
        self.addCleanup(self.repo.__exit__, None, None, None)
        install.KEPT.reset()
        patcher = mock.patch.multiple(
            install, LAUNCHERS_URL=f"{self.repo.env()['RETROBIOS_BASE_URL']}"
            "/install/launchers/index.json",
            RAW_FILE_URL=f"{self.repo.env()['RETROBIOS_BASE_URL']}/{{path}}")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.index = json.loads(INDEX.read_text(encoding="utf-8"))
        self.bios: dict[str, Path] = {}

    def put(self, system: str) -> tuple[install.CardApp, dict]:
        if system not in self.bios:
            self.bios[system] = self.repo.card(system)[1]
        card = install.card_app(self.bios[system])
        return card, install.put_app(card)

    def assertMatchesTheList(self, card: install.CardApp) -> None:
        for target in install.app_targets(self.index, card.place):
            path = card.root / target["dest"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), target["sha256"])

    def test_muos_gets_its_archive(self):
        card, fields = self.put("muOS")
        self.assertTrue(fields["ok"], fields)
        self.assertEqual(fields["written"], ["ARCHIVE/RetroBIOS.muxapp"])
        self.assertMatchesTheList(card)
        with zipfile.ZipFile(card.root / "ARCHIVE" / "RetroBIOS.muxapp") as archive:
            self.assertEqual(archive.read("RetroBIOS/install.py"),
                             (REPO_ROOT / "install.py").read_bytes())
            mode = archive.getinfo("RetroBIOS/mux_launch.sh").external_attr >> 16
            self.assertEqual(mode & 0o777, 0o755)

    def test_knulli_and_rocknix_get_the_files(self):
        for system, script, executable in (("KNULLI", "roms/ports/RetroBIOS.sh", False),
                                           ("ROCKNIX", ".config/modules/RetroBIOS.sh", True)):
            with self.subTest(system=system):
                card, fields = self.put(system)
                self.assertTrue(fields["ok"], fields)
                self.assertEqual(sorted(fields["written"]), sorted(fields["dests"]))
                self.assertMatchesTheList(card)
                mode = (card.root / script).stat().st_mode
                self.assertEqual(bool(mode & stat.S_IXUSR), executable)

    def test_a_second_run_writes_nothing(self):
        card, first = self.put("KNULLI")
        stamps = {path: path.stat().st_mtime_ns for path in card.root.rglob("*")}
        _card, second = self.put("KNULLI")
        self.assertTrue(second["ok"])
        self.assertEqual(second["written"], [])
        self.assertEqual(second["dests"], first["dests"])
        self.assertEqual({path: path.stat().st_mtime_ns for path in card.root.rglob("*")},
                         stamps)
        self.assertIn("already on the KNULLI card", install.app_lines(card, second)[0])

    def test_a_different_file_in_place_is_kept_aside(self):
        root, bios = self.repo.card("KNULLI")
        self.bios["KNULLI"] = bios
        mine = root / "roms" / "ports" / "RetroBIOS.sh"
        mine.parent.mkdir(parents=True)
        mine.write_text("my own script\n")
        card, fields = self.put("KNULLI")
        self.assertTrue(fields["ok"], fields)
        self.assertEqual(len(fields["kept"]), 1)
        self.assertEqual(fields["kept"][0]["files"], 1)
        kept = list(Path(fields["kept"][0]["folder"]).rglob("RetroBIOS.sh"))
        self.assertEqual([path.read_text() for path in kept], ["my own script\n"])
        self.assertMatchesTheList(card)
        self.assertTrue(any("kept in" in line for line in install.app_lines(card, fields)))

    def test_a_tampered_file_is_refused_and_nothing_written(self):
        self.repo.tamper("ports/shared/tui.txt")
        root, bios = self.repo.card("ROCKNIX")
        self.bios["ROCKNIX"] = bios
        before = sorted(root.rglob("*"))
        card, fields = self.put("ROCKNIX")
        self.assertFalse(fields["ok"])
        self.assertIn("SHA-256 mismatch", fields["reason"])
        self.assertEqual(fields["written"], [])
        self.assertEqual(sorted(root.rglob("*")), before)
        self.assertIn("could not be put", install.app_lines(card, fields)[0])

    def test_a_tampered_member_never_reaches_the_archive(self):
        self.repo.tamper("ports/muos/mux_launch.sh")
        root, bios = self.repo.card("muOS")
        self.bios["muOS"] = bios
        _card, fields = self.put("muOS")
        self.assertFalse(fields["ok"])
        self.assertFalse((root / "ARCHIVE").exists())

    def test_a_card_without_a_launcher_is_not_written(self):
        root, bios = self.repo.card("Onion")
        self.bios["Onion"] = bios
        _card, fields = self.put("Onion")
        self.assertFalse(fields["ok"])
        self.assertIn("has no Python", fields["reason"])
        self.assertEqual(sorted(p.name for p in root.iterdir()), [".tmp_update", "BIOS"])


class TheQuestion(unittest.TestCase):
    """Line mode at a terminal asks once, and only yes puts the app."""

    def run_finish(self, answer: str, system: str = "muOS", **given) -> list:
        root = _tempdir(self)
        bios = make_card(root / "card", system)
        args = mock.Mock(add_app=False, yes=False)
        for key, value in given.items():
            setattr(args, key, value)
        put = mock.Mock(return_value={"system": system, "folder": str(root / "card"),
                                      "ok": True, "reason": "", "dests": ["x"],
                                      "written": ["x"], "kept": []})
        out = io.StringIO()
        with mock.patch.object(install, "_ask", return_value=answer) as ask, \
                mock.patch.object(install, "put_app", put), \
                mock.patch("sys.stdout", out):
            install.finish_app(args, [("retroarch", bios)], [], interactive=True)
        self.output = out.getvalue()
        return [ask.call_args_list, put.call_args_list]

    def test_yes_puts_it(self):
        asked, put = self.run_finish("y")
        self.assertEqual(len(asked), 1)
        self.assertIn("[y/N]", asked[0][0][0])
        self.assertEqual(len(put), 1)
        self.assertIn("Archive Manager", self.output)

    def test_enter_or_no_leaves_the_card_alone(self):
        for answer in ("", "n", "no", "q"):
            with self.subTest(answer=answer):
                _asked, put = self.run_finish(answer)
                self.assertEqual(put, [])

    def test_yes_flag_asks_nothing(self):
        asked, put = self.run_finish("y", yes=True)
        self.assertEqual((asked, put), ([], []))

    def test_a_console_without_python_says_so_once(self):
        asked, put = self.run_finish("y", system="Onion")
        self.assertEqual((asked, put), ([], []))
        self.assertIn(install.no_python_words("Onion"), self.output)
        self.assertNotIn("This console", self.output)


class TheOption(unittest.TestCase):
    """--add-app is applied or refused, never ignored."""

    @classmethod
    def setUpClass(cls):
        cls.repo = AppRepository()
        cls.repo.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.repo.__exit__(None, None, None)

    def test_refused_where_it_cannot_apply(self):
        root = _tempdir(self)
        pack = root / "RetroArch_BIOS_Pack.zip"
        zipfile.ZipFile(pack, "w").close()
        for options, words in (
            (["--check"], "--check and --dry-run do not"),
            (["--dry-run"], "--check and --dry-run do not"),
            (["--list-systems"], "a listing does not"),
            (["--from-pack", str(pack)], "--from-pack makes no network request"),
            (["--offline"], "which --offline does not"),
            (["--restore", str(root)], "takes no --add-app"),
        ):
            with self.subTest(options=options):
                where = [] if "--restore" in options else ["--platform", "retroarch",
                                                            "--dest", str(root)]
                proc = self.repo.cli(*where, "--add-app", *options)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn("error:", proc.stderr)
                self.assertIn(words, proc.stderr)

    def test_refused_for_a_folder_on_no_card_or_no_launcher(self):
        root = _tempdir(self)
        for system, words in ((None, "is not on a card this installer recognises"),
                              ("Onion", "Onion has no Python"),
                              ("spruceOS", "no RetroBIOS app for spruceOS yet")):
            with self.subTest(system=system):
                bios = make_card(root / str(system), system) if system else root / "bios"
                proc = self.repo.cli("--platform", "retroarch", "--dest", str(bios),
                                     "--add-app", "--events")
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn(words, proc.stderr)
                events = [json.loads(line) for line in proc.stdout.splitlines()]
                app = [event for event in events if event["event"] == "app"]
                self.assertEqual(len(app), 1)
                self.assertFalse(app[0]["ok"])
                self.assertIn(words, app[0]["reason"])
                self.assertEqual(events[-1], {"event": "end", "code": 2})
                self.assertFalse([e for e in events if e["event"] == "download"])

    def test_applied_after_the_install_and_reported(self):
        root = _tempdir(self)
        for system in ("muOS", "KNULLI"):
            with self.subTest(system=system):
                bios = make_card(root / system, system)
                plat = CARD_PLATFORMS[system]
                command = ("--platform", plat, "--dest", str(root / system), "--add-app",
                           "--events")
                proc = self.repo.cli(*command)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                events = [json.loads(line) for line in proc.stdout.splitlines()]
                kinds = [event["event"] for event in events]
                self.assertEqual(kinds[-3:], ["summary", "app", "end"])
                app = events[-2]
                self.assertTrue(app["ok"], app)
                self.assertEqual(app["system"], system)
                self.assertEqual(app["folder"], str(root / system))
                self.assertEqual(sorted(app["written"]), sorted(app["dests"]))
                self.assertEqual(list(app), ["event", *install.EVENT_KEYS["app"]])
                self.assertEqual(len(list(bios.iterdir())), 5)
                self.assertIn("RetroBIOS is on the", proc.stderr)
                again = self.repo.cli(*command)
                app = [json.loads(line) for line in again.stdout.splitlines()][-2]
                self.assertEqual((again.returncode, app["ok"], app["written"]), (0, True, []))

    def test_not_added_when_the_install_does_not_finish(self):
        root = _tempdir(self)
        make_card(root / "card", "muOS")
        # A BIOS folder that is a file: every download fails.
        (root / "card" / "MUOS" / "bios").rmdir()
        (root / "card" / "MUOS" / "bios").write_text("in the way")
        proc = self.repo.cli("--platform", "retroarch", "--dest", str(root / "card"),
                             "--add-app", "--events")
        self.assertNotEqual(proc.returncode, 0)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        app = [event for event in events if event["event"] == "app"]
        self.assertEqual(len(app), 1, proc.stderr)
        self.assertEqual((app[0]["ok"], app[0]["reason"]),
                         (False, "the install did not finish"))
        self.assertFalse((root / "card" / "ARCHIVE").exists())


if __name__ == "__main__":
    unittest.main()
