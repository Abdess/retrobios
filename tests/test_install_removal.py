"""Removing what the installer placed, and putting a backup back.

Removal deletes for good by default, or moves into a backup with --backup.
Only the install record says what may go: a file it lists, still its
recorded bytes, that the collection can serve again. Each test drives the
real install.py against a loopback repository, or the planner directly for
records no install writes (a crafted one, a drive that folds case).
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

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import install  # noqa: E402
from test_install_selection import FakeRepository  # noqa: E402

try:
    import pty
except ImportError:  # Windows has no pseudo-terminal module.
    pty = None


class SharedRepository(FakeRepository):
    """The loopback repository with a file two systems read."""

    PAYLOADS = {**FakeRepository.PAYLOADS,
                "shared.bin": (b"shared", ["sony-playstation", "nintendo-gba"], None, None)}

    def run(self, *options: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        # --restore and --delete-backup name their folder alone.
        command = self.command(*options)
        if options[0] in ("--restore", "--delete-backup"):
            command = [*command[:2], *options]
        return subprocess.run(
            command, env=self.env(), capture_output=True, text=True,
            timeout=60, check=False, input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
        )

    def answer(self, reply: str, *options: str) -> tuple[int, str]:
        """A run at a terminal that answers reply to its question: (code, text)."""
        main, other = pty.openpty()
        try:
            proc = subprocess.Popen(self.command(*options), env=self.env(), stdin=other,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            os.write(main, reply.encode() + b"\n")
            out, _err = proc.communicate(timeout=60)
        finally:
            os.close(main)
            os.close(other)
        return proc.returncode, out.decode()

    @property
    def record(self) -> Path:
        return self.dest.parent / install.BACKUP_DIR / f"{self.dest.name}.install.json"

    def snapshot(self) -> dict[str, bytes]:
        return {path.relative_to(self.dest).as_posix(): path.read_bytes()
                for path in sorted(self.dest.rglob("*")) if path.is_file()}

    def events(self, proc: subprocess.CompletedProcess) -> list[dict]:
        return [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]

    def setup(self) -> dict:
        return json.loads(self.record.read_text())["setups"]["retroarch"]

    def install_both(self) -> None:
        proc = self.run("--system", "sony-playstation", "--system", "nintendo-gba", "--yes")
        assert proc.returncode == 0, proc.stdout + proc.stderr


GBA_ONLY = ["gba_bios.bin", "mgba/extra.bin"]
PSX = ["pcsx/extra.bin", "scph5500.bin", "scph5501.bin"]


class RemoveOneOfTwoSystems(unittest.TestCase):
    def test_the_shared_file_stays_and_a_backup_puts_the_folder_back(self):
        with SharedRepository() as repo:
            repo.install_both()
            before = repo.snapshot()
            self.assertEqual(sorted(before), sorted(GBA_ONLY + PSX + ["shared.bin"]))
            proc = repo.run("--remove", "--system", "nintendo-gba", "--backup", "--yes")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(sorted(repo.snapshot()), sorted(PSX + ["shared.bin"]))
            self.assertIn("shared.bin: still needed by sony-playstation", proc.stdout)
            setup = repo.setup()
            self.assertEqual(setup["choice"], ["--system", "sony-playstation"])
            self.assertEqual(sorted(item["dest"] for item in setup["files"]),
                             sorted(PSX + ["shared.bin"]))
            [backup] = install.list_backups(repo.dest)
            self.assertEqual((backup["files"], backup["source"]), (2, "remove"))
            proc = repo.run("--restore", str(backup["folder"]))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(repo.snapshot(), before)
            setup = repo.setup()
            self.assertEqual(sorted(item["dest"] for item in setup["files"]), sorted(before))
            self.assertEqual(install.record_options(setup["choice"]),
                             [("--system", "sony-playstation"), ("--system", "nintendo-gba")])

    def test_everything_into_a_backup_and_back_with_its_record(self):
        with SharedRepository() as repo:
            repo.install_both()
            before, setup = repo.snapshot(), repo.setup()
            proc = repo.run("--remove", "--backup", "--yes")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual((repo.snapshot(), repo.record.exists()), ({}, False))
            [backup] = install.list_backups(repo.dest)
            self.assertEqual(repo.run("--restore", str(backup["folder"])).returncode, 0)
            self.assertEqual(repo.snapshot(), before)
            self.assertEqual((repo.setup()["choice"], repo.setup()["files"]),
                             (setup["choice"], setup["files"]))

    def test_removal_deletes_for_good_by_default(self):
        with SharedRepository() as repo:
            repo.install_both()
            proc = repo.run("--remove", "--system", "nintendo-gba", "--yes")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("Removed 2 files, 12 B freed.", proc.stdout)
            self.assertEqual(install.list_backups(repo.dest), [])
            holder = repo.dest.parent / install.BACKUP_DIR
            self.assertEqual(sorted(path.name for path in holder.iterdir()),
                             [f"{repo.dest.name}.install.json"])

    def test_removing_everything_leaves_no_record(self):
        with SharedRepository() as repo:
            repo.install_both()
            proc = repo.run("--remove", "--yes")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(repo.snapshot(), {})
            self.assertFalse(repo.record.exists())

    def test_dry_run_lists_and_removes_nothing(self):
        with SharedRepository() as repo:
            repo.install_both()
            before = repo.snapshot()
            proc = repo.run("--remove", "--system", "nintendo-gba", "--dry-run")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            for dest in GBA_ONLY:
                self.assertIn(f"  {dest}\n", proc.stdout)
            self.assertIn("Nothing was removed (--dry-run).", proc.stdout)
            self.assertEqual(repo.snapshot(), before)

    def test_one_file(self):
        with SharedRepository() as repo:
            repo.install_both()
            proc = repo.run("--remove", "--file", "gba_bios.bin", "--file",
                            str(repo.dest / "not-ours.bin"), "--yes")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("gba_bios.bin", repo.snapshot())
            self.assertIn("not-ours.bin: not installed by RetroBIOS", proc.stdout)
            outside = repo.run("--remove", "--file", str(repo.root / "x.bin"), "--yes")
            self.assertEqual(outside.returncode, 2)
            self.assertIn("is not inside", outside.stderr)

    def test_a_core(self):
        with SharedRepository() as repo:
            repo.install_both()
            proc = repo.run("--remove", "--core", "mgba", "--yes")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(sorted(repo.snapshot()),
                             sorted(["gba_bios.bin", "shared.bin"] + PSX))
            self.assertIn(("--core", "pcsx_rearmed"),
                          install.record_options(repo.setup()["choice"]))


class NeverTouched(unittest.TestCase):
    def test_a_changed_file_and_one_added_by_hand_stay(self):
        with SharedRepository() as repo:
            repo.install_both()
            (repo.dest / "scph5501.bin").write_bytes(b"the user's own")
            (repo.dest / "mine.bin").write_bytes(b"added by hand")
            proc = repo.run("--remove", "--yes")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(repo.snapshot(), {"scph5501.bin": b"the user's own",
                                               "mine.bin": b"added by hand"})
            self.assertIn("1 file stays: 1 changed since it was installed.", proc.stdout)
            self.assertIn("scph5501.bin: changed since it was installed", proc.stdout)
            self.assertIn("1 other file stays, not installed by RetroBIOS.", proc.stdout)

    def test_a_link_in_place_of_a_file_stays_and_its_target_too(self):
        with SharedRepository() as repo:
            repo.install_both()
            target = repo.root / "elsewhere.bin"
            shutil.copy(repo.dest / "gba_bios.bin", target)
            (repo.dest / "gba_bios.bin").unlink()
            (repo.dest / "gba_bios.bin").symlink_to(target)
            proc = repo.run("--remove", "--system", "nintendo-gba", "--yes")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue((repo.dest / "gba_bios.bin").is_symlink())
            self.assertTrue(target.is_file())
            self.assertIn("gba_bios.bin: a link, never followed", proc.stdout)


class ExitCodes(unittest.TestCase):
    @unittest.skipIf(pty is None, "a question needs a pseudo-terminal")
    def test_zero_one_and_two(self):
        with SharedRepository() as repo:
            no_record = repo.run("--remove", "--yes")
            self.assertEqual(no_record.returncode, 2)
            repo.install_both()
            asked = repo.run("--remove")
            self.assertEqual(asked.returncode, 2)
            self.assertIn("add --yes", asked.stderr)
            declined, said = repo.answer("n", "--remove")
            self.assertEqual(declined, 2, said)
            self.assertIn("Remove them for good? [y/N]", said)
            self.assertIn("Nothing was removed.", said)
            self.assertEqual(len(repo.installed()), 6)
            if not (hasattr(os, "geteuid") and os.geteuid() == 0):
                (repo.dest / "pcsx").chmod(0o555)
                try:
                    failed = repo.run("--remove", "--system", "sony-playstation", "--yes")
                finally:
                    (repo.dest / "pcsx").chmod(0o755)
                self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
                self.assertIn("failed: pcsx/extra.bin", failed.stderr)
                # The record keeps what is still there.
                self.assertIn("pcsx/extra.bin",
                              [item["dest"] for item in repo.setup()["files"]])
            done = repo.run("--remove", "--yes")
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            nothing = repo.run("--remove", "--yes")
            self.assertEqual(nothing.returncode, 2)

    def test_options_an_action_does_not_read_are_refused(self):
        with SharedRepository() as repo:
            for argv, words in (
                (("--file", "a.bin"), "--file applies to --remove"),
                (("--backup",), "--backup applies to --remove"),
                (("--remove", "--region", "us"), "--remove takes no --region"),
                (("--remove", "--system", "nintendo-gba", "--core", "mgba"),
                 "not --system and --core"),
                (("--remove", "--backups"), "two actions"),
                (("--backups", "--yes"), "--backups takes no --yes"),
            ):
                with self.subTest(argv=argv):
                    proc = repo.run(*argv)
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn(words, proc.stderr)


class WithoutARecord(unittest.TestCase):
    def test_a_missing_or_damaged_record_removes_nothing_in_one_line(self):
        with SharedRepository() as repo:
            repo.install_both()
            before = repo.snapshot()
            repo.record.write_text("{not json")
            proc = repo.run("--remove", "--yes")
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(repo.snapshot(), before)
            self.assertEqual(proc.stderr.strip().count("\n"), 0, proc.stderr)
            self.assertIn("Nothing was removed", proc.stderr)
            self.assertIn("is damaged", proc.stderr)
            repo.record.unlink()
            proc = repo.run("--remove", "--yes")
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stderr.strip().count("\n"), 0, proc.stderr)
            self.assertIn("no install record", proc.stderr)
            self.assertEqual(repo.snapshot(), before)


class Events(unittest.TestCase):
    def test_every_new_kind(self):
        with SharedRepository() as repo:
            repo.install_both()
            plan = repo.events(repo.run("--remove", "--system", "nintendo-gba", "--dry-run",
                                        "--events"))
            self.assertEqual([event["event"] for event in plan],
                             ["start", "removal_plan", "end"])
            self.assertEqual(plan[0]["mode"], "remove")
            self.assertEqual((plan[1]["files"], plan[1]["bytes"], plan[1]["dests"]),
                             (2, 12, GBA_ONLY))
            self.assertEqual(plan[1]["kept"], [{"dest": "shared.bin", "reason": "shared"}])
            run = repo.events(repo.run("--remove", "--system", "nintendo-gba", "--backup",
                                       "--events", "--yes"))
            kinds = [event["event"] for event in run]
            self.assertEqual(kinds, ["start", "removal_plan", "removed", "removed", "backup",
                                     "end"])
            self.assertTrue(all(event["ok"] and event["moved_to"]
                                for event in run if event["event"] == "removed"))
            self.assertEqual(run[4]["status"], "made")
            listed = repo.events(repo.run("--backups", "--events"))
            self.assertEqual([event["event"] for event in listed], ["start", "backup", "end"])
            self.assertEqual((listed[0]["mode"], listed[1]["status"], listed[1]["files"]),
                             ("list", "listed", 2))
            folder = listed[1]["folder"]
            back = repo.events(repo.run("--restore", folder, "--events"))
            self.assertEqual([event["event"] for event in back],
                             ["start", "restored", "restored", "end"])
            self.assertEqual(back[0]["mode"], "restore")
            gone = repo.events(repo.run("--delete-backup", folder, "--events", "--yes"))
            self.assertEqual([event["event"] for event in gone], ["start", "backup", "end"])
            self.assertEqual((gone[1]["status"], gone[2]["code"]), ("deleted", 0))
            self.assertFalse(Path(folder).exists())
            for event in plan + run + listed + back + gone:
                self.assertEqual(sorted(event), sorted(
                    ["event", *install.EVENT_KEYS[event["event"]]]))


class DeleteABackup(unittest.TestCase):
    def test_only_a_backup_folder_and_only_with_a_yes(self):
        with SharedRepository() as repo:
            repo.install_both()
            repo.run("--remove", "--system", "nintendo-gba", "--backup", "--yes")
            [backup] = install.list_backups(repo.dest)
            asked = repo.run("--delete-backup", str(backup["folder"]))
            self.assertEqual(asked.returncode, 2)
            self.assertTrue(backup["folder"].is_dir())
            refused = repo.run("--delete-backup", str(repo.dest), "--yes")
            self.assertEqual(refused.returncode, 2)
            self.assertTrue((repo.dest / "shared.bin").is_file())
            done = repo.run("--delete-backup", str(backup["folder"]), "--yes")
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertFalse(backup["folder"].exists())


def _record(folder: Path, files: list[dict], others: dict | None = None,
            choice: list[str] | None = None) -> dict:
    setup = {"written": "2026-11-03T12:00:00Z", "list": {"version": "v1", "generated": ""},
             "choice": choice or ["--all-files"], "files": files}
    return {"schema": 1, "folder": str(folder), "setups": {"retroarch": setup, **(others or {})}}


def _item(dest: str, payload: bytes, root: str = "") -> dict:
    return {"dest": dest, "root": root, "sha1": hashlib.sha1(payload).hexdigest(),
            "size": len(payload), "from": "download"}


def _served(*dests_payloads: tuple[str, bytes]) -> dict:
    return {"files": [{"dest": dest, "sha1": hashlib.sha1(payload).hexdigest(),
                       "size": len(payload), "cores": None, "systems": ["nintendo-gba"]}
                      for dest, payload in dests_payloads]}


class ACraftedRecord(unittest.TestCase):
    """A record anyone could write never makes the installer delete outside
    the BIOS folder, through a link, or anything but a regular file."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.folder = self.root / "bios"
        self.folder.mkdir()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "a FIFO is POSIX")
    def test_nothing_outside_or_through_a_link_is_removed(self):
        payload = b"precious"
        (self.root / "outside.bin").write_bytes(payload)
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "deep.bin").write_bytes(payload)
        (self.folder / "linked").symlink_to(elsewhere)
        (self.folder / "link.bin").symlink_to(self.root / "outside.bin")
        os.mkfifo(self.folder / "pipe.bin")
        dests = ["../outside.bin", str(self.root / "outside.bin"), "linked/deep.bin",
                 "link.bin", "pipe.bin", "a/../../outside.bin", "C:/outside.bin"]
        record = _record(self.folder, [_item(dest, payload) for dest in dests]
                         + [_item("saved.bin", payload, "save")])
        manifest = _served(*[(dest, payload) for dest in [*dests, "saved.bin"]])
        removal = install.plan_removal("retroarch", self.folder, record, manifest)
        self.assertEqual(removal.remove, [])
        reasons = {item["dest"]: item["reason"] for item in removal.kept}
        self.assertEqual(reasons, {
            "../outside.bin": "outside", str(self.root / "outside.bin"): "outside",
            "linked/deep.bin": "link", "link.bin": "link", "pipe.bin": "not_a_file",
            "a/../../outside.bin": "outside", "C:/outside.bin": "outside",
            "saved.bin": "outside"})
        install.remove_files(removal, record["setups"]["retroarch"], False)
        self.assertEqual((self.root / "outside.bin").read_bytes(), payload)
        self.assertEqual((elsewhere / "deep.bin").read_bytes(), payload)

    def test_a_file_swapped_after_the_plan_stays(self):
        payload = b"ours"
        (self.folder / "a.bin").write_bytes(payload)
        record = _record(self.folder, [_item("a.bin", payload)])
        removal = install.plan_removal("retroarch", self.folder, record,
                                       _served(("a.bin", payload)))
        self.assertEqual(len(removal.remove), 1)
        (self.folder / "a.bin").unlink()
        (self.folder / "a.bin").symlink_to(self.root / "nowhere")
        removed, failed, _run = install.remove_files(removal, record["setups"]["retroarch"],
                                                     False)
        self.assertEqual((removed, [item["dest"] for item in failed]), ([], ["a.bin"]))
        self.assertTrue((self.folder / "a.bin").is_symlink())

    def test_a_file_the_list_no_longer_serves_stays(self):
        payload = b"a key the user supplied"
        (self.folder / "keys.bin").write_bytes(payload)
        record = _record(self.folder, [_item("keys.bin", payload)])
        removal = install.plan_removal("retroarch", self.folder, record, {"files": []})
        self.assertEqual([item["reason"] for item in removal.kept], ["not_servable"])
        other = install.plan_removal("retroarch", self.folder, record,
                                     _served(("keys.bin", b"another release")))
        self.assertEqual([item["reason"] for item in other.kept], ["not_servable"])


class AFoldingDrive(unittest.TestCase):
    """FAT and exFAT open a name whatever its case: the record, the list and
    another setup are compared folded there."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.folder = self.root / "bios"
        self.folder.mkdir()
        self.payload = b"bios"
        (self.folder / "SCPH5501.BIN").write_bytes(self.payload)

    def plan(self, keeps_case: bool, others: dict | None = None) -> install.Removal:
        record = _record(self.folder, [_item("SCPH5501.BIN", self.payload)], others)
        with mock.patch.object(install, "keeps_case", return_value=keeps_case):
            return install.plan_removal("retroarch", self.folder, record,
                                        _served(("scph5501.bin", self.payload)))

    def test_the_list_s_name_in_another_case_is_the_same_file(self):
        self.assertEqual([entry["dest"] for entry in self.plan(False).remove],
                         ["SCPH5501.BIN"])
        self.assertEqual([item["reason"] for item in self.plan(True).kept], ["not_servable"])

    def test_another_setup_s_file_in_another_case_stays(self):
        other = {"lakka": {"written": "", "choice": ["--all-files"],
                           "files": [_item("scph5501.bin", self.payload)]}}
        removal = self.plan(False, other)
        self.assertEqual([(item["reason"], item["what"]) for item in removal.kept],
                         [("shared", "Lakka")])

    def test_the_removal_runs_on_a_folding_drive(self):
        removal = self.plan(False)
        record = _record(self.folder, [_item("SCPH5501.BIN", self.payload)])
        with contextlib.redirect_stdout(io.StringIO()):
            removed, failed, _run = install.remove_files(
                removal, record["setups"]["retroarch"], False)
        self.assertEqual((len(removed), failed), (1, []))
        self.assertFalse((self.folder / "SCPH5501.BIN").exists())


class RestoreAnInstallBackup(unittest.TestCase):
    def test_the_record_lets_go_of_the_user_s_files_put_back(self):
        with SharedRepository() as repo:
            repo.dest.mkdir(parents=True)
            (repo.dest / "gba_bios.bin").write_bytes(b"the user's own")
            repo.install_both()
            [backup] = install.list_backups(repo.dest)
            self.assertEqual(backup["source"], "install")
            self.assertIn("gba_bios.bin", [item["dest"] for item in repo.setup()["files"]])
            proc = repo.run("--restore", str(backup["folder"]))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual((repo.dest / "gba_bios.bin").read_bytes(), b"the user's own")
            self.assertNotIn("gba_bios.bin", [item["dest"] for item in repo.setup()["files"]])


if __name__ == "__main__":
    unittest.main()
