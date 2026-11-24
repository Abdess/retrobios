"""A file the user had is kept: a differing BIOS is set aside and the run says where."""
from __future__ import annotations

import tests
from tests import scratch_dir

import contextlib
import hashlib
import io
import os
import stat
import shutil
import unittest
import unittest.mock
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import install, _install_run, _FakeResponse, _SyntheticTree, _events


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_kept")


class AFileYouHadIsKept(unittest.TestCase):
    """A BIOS file whose contents differ was replaced and lost: a personal
    dump or another revision could not be brought back by deleting what the
    installer wrote. It is moved beside the BIOS folder first, never inside,
    where a core that finds its BIOS by content could take it."""

    NEW = b"the collection's copy"
    OLD = b"a dump of my own"

    def setUp(self):
        install.KEPT.reset()
        self.addCleanup(install.KEPT.reset)
        self.home = scratch_dir(self)
        self.bios = self.home / "system"
        self.bios.mkdir()

    def _entry(self, dest: str) -> dict:
        return {"dest": dest, "repo_path": f"bios/{dest}", "size": len(self.NEW),
                "sha1": hashlib.sha1(self.NEW).hexdigest(),
                "sha256": hashlib.sha256(self.NEW).hexdigest()}

    def _download(self, dest: str):
        with unittest.mock.patch.object(install.urllib.request, "urlopen",
                                        lambda *a, **k: _FakeResponse(self.NEW)):
            return install._download_one(self._entry(dest), self.bios)

    def _run_folder(self) -> Path:
        runs = list((self.home / install.BACKUP_DIR).iterdir())
        self.assertEqual(len(runs), 1, runs)
        return runs[0]

    def test_a_differing_file_is_kept_with_its_relative_path(self):
        (self.bios / "sub").mkdir()
        (self.bios / "sub" / "x.bin").write_bytes(self.OLD)
        self.assertEqual(self._download("sub/x.bin"), ("sub/x.bin", True, ""))
        self.assertEqual((self.bios / "sub" / "x.bin").read_bytes(), self.NEW)
        run = self._run_folder()
        self.assertEqual((run / "system" / "sub" / "x.bin").read_bytes(), self.OLD)
        self.assertEqual(install.KEPT.summary(),
                         [{"folder": str(run), "files": 1, "bytes": len(self.OLD)}])
        # Nothing new sits inside the BIOS folder, where a scan would read it.
        self.assertEqual(sorted(p.name for p in self.bios.rglob("*")), ["sub", "x.bin"])

    def test_an_identical_file_is_not_copied(self):
        (self.bios / "x.bin").write_bytes(self.NEW)
        self.assertEqual(self._download("x.bin"), ("x.bin", True, ""))
        self.assertFalse((self.home / install.BACKUP_DIR).exists())
        self.assertEqual(install.KEPT.summary(), [])

    def test_a_missing_file_keeps_nothing(self):
        self.assertEqual(self._download("x.bin"), ("x.bin", True, ""))
        self.assertFalse((self.home / install.BACKUP_DIR).exists())

    def test_a_second_replacement_keeps_the_first_file(self):
        # Two lists in one run writing one path: what is kept is the user's.
        (self.bios / "x.bin").write_bytes(self.OLD)
        self._download("x.bin")
        (self.bios / "x.bin").write_bytes(b"what this run wrote first")
        self._download("x.bin")
        self.assertEqual((self._run_folder() / "system" / "x.bin").read_bytes(), self.OLD)

    def test_a_file_that_cannot_be_kept_stays(self):
        (self.bios / "x.bin").write_bytes(self.OLD)

        def refuse(*_args):
            raise PermissionError(13, "Permission denied")

        with unittest.mock.patch.object(install, "_move_aside", refuse):
            _dest, ok, reason = self._download("x.bin")
        self.assertFalse(ok)
        self.assertIn(install.NOT_KEPT, reason)
        self.assertEqual((self.bios / "x.bin").read_bytes(), self.OLD)
        self.assertEqual(sorted(p.name for p in self.bios.iterdir()), ["x.bin"])

    def test_a_symlinked_subfolder_keeps_working(self):
        elsewhere = self.home / "shadPS4" / "sys_modules"
        elsewhere.mkdir(parents=True)
        (elsewhere / "lib.sprx").write_bytes(self.OLD)
        (self.bios / "shadps4").mkdir()
        (self.bios / "shadps4" / "sys_modules").symlink_to(elsewhere)
        self.assertTrue(self._download("shadps4/sys_modules/lib.sprx")[1])
        self.assertEqual((elsewhere / "lib.sprx").read_bytes(), self.NEW)
        self.assertTrue((self.bios / "shadps4" / "sys_modules").is_symlink())
        run = self._run_folder()
        kept = run / "system" / "shadps4" / "sys_modules" / "lib.sprx"
        self.assertEqual(kept.read_bytes(), self.OLD)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.restore_kept(run), 0)
        self.assertEqual((elsewhere / "lib.sprx").read_bytes(), self.OLD)
        self.assertTrue((self.bios / "shadps4" / "sys_modules").is_symlink())

    def test_a_link_at_the_name_is_not_kept(self):
        # The replace takes the link's place: the file it points to is untouched.
        target = self.home / "mine.bin"
        target.write_bytes(self.OLD)
        (self.bios / "x.bin").symlink_to(target)
        self.assertTrue(self._download("x.bin")[1])
        self.assertEqual(target.read_bytes(), self.OLD)
        self.assertFalse((self.home / install.BACKUP_DIR).exists())

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes anywhere")
    def test_without_room_beside_the_folder_it_goes_inside(self):
        (self.bios / "x.bin").write_bytes(self.OLD)
        self.home.chmod(0o555)
        self.addCleanup(self.home.chmod, 0o755)
        self.assertTrue(self._download("x.bin")[1])
        runs = list((self.bios / install.BACKUP_DIR).iterdir())
        self.assertEqual(len(runs), 1)
        self.assertEqual((runs[0] / "x.bin").read_bytes(), self.OLD)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.restore_kept(runs[0]), 0)
        self.assertEqual((self.bios / "x.bin").read_bytes(), self.OLD)

    def test_a_data_tree_file_is_kept(self):
        import zipfile

        tree = self.bios / "dolphin-emu" / "Sys"
        tree.mkdir(parents=True)
        (tree / "a.ini").write_bytes(self.OLD)
        archive = self.home / "src.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("Sys/a.ini", self.NEW)
        entry = {"ref": "d", "dest": "dolphin-emu", "url": "https://example.invalid/d.zip",
                 "type": "zip", "files": {"Sys/a.ini": {
                     "sha1": hashlib.sha1(self.NEW).hexdigest(), "size": len(self.NEW)}}}

        def fetch(url, directory, progress=None, keep=None):
            copy = Path(directory) / "a.zip"
            shutil.copy(archive, copy)
            return copy

        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            counts = install.install_data_directory(entry, self.bios)
        self.assertEqual(counts["installed"], 1)
        self.assertEqual((tree / "a.ini").read_bytes(), self.NEW)
        kept = self._run_folder() / "system" / "dolphin-emu" / "Sys" / "a.ini"
        self.assertEqual(kept.read_bytes(), self.OLD)

    def test_a_standalone_copy_keeps_the_emulators_file(self):
        (self.bios / "ps2-0230a.bin").write_bytes(self.NEW)
        pcsx2 = self.home / "PCSX2" / "bios"
        pcsx2.mkdir(parents=True)
        (pcsx2 / "ps2-0230a.bin").write_bytes(self.OLD)
        manifest = {"files": [{"dest": "ps2-0230a.bin"}], "standalone_copies": [
            {"pattern": "ps2-*.bin", "emulator": "pcsx2", "targets": {"linux": [str(pcsx2)]}}]}
        self.assertEqual(install.do_standalone_copies(manifest, self.bios, "linux"), (1, 0, 0))
        self.assertEqual((pcsx2 / "ps2-0230a.bin").read_bytes(), self.NEW)
        runs = list((self.home / "PCSX2" / install.BACKUP_DIR).iterdir())
        self.assertEqual((runs[0] / "bios" / "ps2-0230a.bin").read_bytes(), self.OLD)
        # Copied again, the file is the same: nothing more is kept.
        self.assertEqual(install.do_standalone_copies(manifest, self.bios, "linux"), (1, 0, 0))
        self.assertEqual(install.KEPT.summary()[0]["files"], 1)

    def test_a_kept_file_inside_the_tree_is_no_copy_source(self):
        inside = self.bios / install.BACKUP_DIR / "20261022-153000"
        inside.mkdir(parents=True)
        (inside / "ps2-old.bin").write_bytes(self.OLD)
        pcsx2 = self.home / "PCSX2" / "bios"
        pcsx2.mkdir(parents=True)
        manifest = {"files": [{"dest": "ps2-0230a.bin"}], "standalone_copies": [
            {"pattern": "ps2-*.bin", "emulator": "pcsx2", "targets": {"linux": [str(pcsx2)]}}]}
        self.assertEqual(install.do_standalone_copies(manifest, self.bios, "linux"), (0, 0, 0))

    def test_restore_refuses_a_folder_that_is_no_backup(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(install.restore_kept(self.bios), 2)
        self.assertIn(install.BACKUP_DIR, err.getvalue())

    def test_a_linked_backup_holder_is_not_written_through(self):
        # Someone with write access to a shared parent folder placed a link
        # where the holder goes: the user's file must not land at its target.
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        (self.home / install.BACKUP_DIR).symlink_to(elsewhere)
        (self.bios / "x.bin").write_bytes(self.OLD)
        self.assertTrue(self._download("x.bin")[1])
        self.assertEqual(list(elsewhere.iterdir()), [])
        inside = list((self.bios / install.BACKUP_DIR).iterdir())
        self.assertEqual(len(inside), 1)
        self.assertEqual((inside[0] / "x.bin").read_bytes(), self.OLD)

    def test_a_holder_with_every_name_taken_is_not_reused(self):
        # Folders planted under every dated name of this run: none of them
        # may receive the user's file.
        holder = self.home / install.BACKUP_DIR
        stamp = "20260101-000000"
        for n in range(1, 1000):
            (holder / (stamp if n == 1 else f"{stamp}-{n}")).mkdir(parents=True)
        (self.bios / "x.bin").write_bytes(self.OLD)
        with unittest.mock.patch.object(install.time, "strftime", return_value=stamp):
            self.assertTrue(self._download("x.bin")[1])
        self.assertEqual(sum(1 for p in holder.rglob("x.bin")), 0)
        inside = list((self.bios / install.BACKUP_DIR).iterdir())
        self.assertEqual(len(inside), 1)
        self.assertEqual((inside[0] / "x.bin").read_bytes(), self.OLD)

    def test_a_holder_swapped_after_the_check_is_noticed(self):
        holder = self.home / install.BACKUP_DIR
        holder.mkdir()
        checked = install._check_holder(holder)
        self.assertTrue(install._same_folder(holder, checked))
        holder.rename(self.home / "moved")
        (self.home / "elsewhere").mkdir()
        holder.symlink_to(self.home / "elsewhere")
        self.assertFalse(install._same_folder(holder, checked))
        with self.assertRaises(OSError):
            install._check_holder(holder)

    @unittest.skipUnless(hasattr(os, "getuid"), "user ids are POSIX")
    def test_a_holder_another_user_owns_is_refused(self):
        holder = self.home / install.BACKUP_DIR
        holder.mkdir()
        real = os.lstat

        def planted(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            if Path(path) != holder:
                return info
            fields = list(info)
            fields[stat.ST_UID] = info.st_uid + 2
            return os.stat_result(fields)

        with self.assertRaises(OSError), \
                unittest.mock.patch.object(install.os, "lstat", side_effect=planted):
            install._check_holder(holder)
        install._check_holder(holder)

    @unittest.skipUnless(hasattr(os, "getuid"), "user ids are POSIX")
    def test_a_storage_with_one_owner_for_every_file_takes_the_holder(self):
        # Android's shared storage, seen from Termux on Android 17: a folder
        # the run has just made is shown as another user's, like every other
        # file there. Refusing it left 25 files unreplaced on a real phone.
        holder = self.home / install.BACKUP_DIR
        holder.mkdir()
        with unittest.mock.patch.object(install.os, "getuid", return_value=os.getuid() + 1):
            install._check_holder(holder)
            (self.bios / "x.bin").write_bytes(self.OLD)
            self.assertTrue(self._download("x.bin")[1])
        self.assertEqual((self._run_folder() / "system" / "x.bin").read_bytes(), self.OLD)

    def test_restore_refuses_a_folder_the_installer_did_not_write(self):
        planted = self.home / install.BACKUP_DIR / "20260101-000000"
        (planted / "system").mkdir(parents=True)
        (planted / "system" / "x.bin").write_bytes(b"not the user's")
        (self.bios / "x.bin").write_bytes(self.OLD)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(install.restore_kept(planted), 2)
        self.assertEqual((self.bios / "x.bin").read_bytes(), self.OLD)

    def test_restore_does_not_follow_links_inside_the_backup(self):
        (self.bios / "x.bin").write_bytes(self.OLD)
        self.assertTrue(self._download("x.bin")[1])
        run = self._run_folder()
        outside = self.home / "outside"
        (outside / "deep").mkdir(parents=True)
        (outside / "deep" / "y.bin").write_bytes(b"foreign")
        (run / "system" / "linked").symlink_to(outside)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.restore_kept(run), 0)
        self.assertEqual((self.bios / "x.bin").read_bytes(), self.OLD)
        self.assertFalse((self.bios / "linked").exists())


class KeptFilesEndToEnd(unittest.TestCase, _SyntheticTree):
    """The run says what it kept and where, --dry-run what it would keep
    and writes nothing, and --restore puts the original bytes back."""

    def setUp(self):
        self.env = self.serve_tree(self)

    def test_dry_run_says_what_would_be_kept_and_writes_nothing(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(self.bios),
                            "--dry-run", "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Would keep 1 file already there (11 B)", proc.stdout)
        self.assertIn(str(self.home / install.BACKUP_DIR), proc.stdout)
        self.assertFalse((self.home / install.BACKUP_DIR).exists())
        self.assertEqual((self.bios / "b.bin").read_bytes(), b"other bytes")
        events = _events(_install_run(self.env, "--platform", "retroarch", "--dest",
                                      str(self.bios), "--dry-run", "--events"))
        kept = events[-2]["kept"]
        self.assertEqual([(item["files"], item["bytes"]) for item in kept], [(1, 11)])
        self.assertFalse((self.home / install.BACKUP_DIR).exists())

    def test_install_then_restore(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(self.bios),
                            "--no-input", "--jobs", "1", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.bios / "b.bin").read_bytes(), self.FILES["bios/A/b.bin"])
        # The install record sits beside the run folders, a file of its own.
        held = list((self.home / install.BACKUP_DIR).iterdir())
        runs = [path for path in held if path.is_dir()]
        self.assertEqual(sorted(path.name for path in held if not path.is_dir()),
                         [f"{self.bios.name}.install.json"])
        self.assertEqual(len(runs), 1)
        self.assertIn("Kept 1 file already there (11 B), which the collection's copies "
                      f"replaced, in {runs[0]}", proc.stdout)
        self.assertIn(f"--restore {runs[0]}", proc.stdout)
        # a.bin held the expected bytes: it is not among the kept files.
        self.assertEqual([p.name for p in (runs[0] / "bios").iterdir()], ["b.bin"])

        refused = _install_run(self.env, "--restore", str(runs[0]), "--platform", "retroarch")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("--restore", refused.stderr)

        looked = _install_run(self.env, "--restore", str(runs[0]), "--dry-run")
        self.assertEqual(looked.returncode, 0, looked.stderr)
        self.assertIn(f"would put back {self.bios / 'b.bin'}", looked.stdout)
        self.assertEqual((self.bios / "b.bin").read_bytes(), self.FILES["bios/A/b.bin"])

        back = _install_run(self.env, "--restore", str(runs[0]))
        self.assertEqual(back.returncode, 0, back.stdout + back.stderr)
        self.assertEqual((self.bios / "b.bin").read_bytes(), b"other bytes")
        self.assertEqual((self.bios / "a.bin").read_bytes(), self.FILES["bios/A/a.bin"])
        self.assertIn("Put back 1 file", back.stdout)
        # The backup stays until the user deletes it.
        self.assertTrue((runs[0] / "bios" / "b.bin").is_file())

        # A second install keeps the restored file in a new folder.
        again = _install_run(self.env, "--platform", "retroarch", "--dest", str(self.bios),
                             "--no-input", "--jobs", "1")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(len([path for path in (self.home / install.BACKUP_DIR).iterdir()
                              if path.is_dir()]), 2)


if __name__ == "__main__":
    unittest.main()
