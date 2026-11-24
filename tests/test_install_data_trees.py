"""install.py installs the data directories a pack carries, as the pack builder lays them out."""
from __future__ import annotations

import tests
from tests import scratch_dir

import hashlib
import io
import json
import os
import shutil
import unittest
import unittest.mock
import zipfile
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_data_trees")


class DataDirectoriesAreInstalled(unittest.TestCase):
    """The README said the installer does what the pack does, but for RetroArch
    it left out 2,640 data files (Dolphin's Sys, PPSSPP's assets) and
    --check still said "All files up to date"."""

    def _zip(self, root: Path) -> Path:
        import zipfile

        archive = root / "Dolphin.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("Dolphin/Sys/GC/font.bin", b"font")
            zf.writestr("Dolphin/Sys/GC/dsp.bin", b"new bytes upstream")
            zf.writestr("Dolphin/Themes/x.png", b"theme")
        return archive

    def _entry(self) -> dict:
        return {
            "ref": "dolphin-sys", "dest": "dolphin-emu", "url": "https://example.invalid/D.zip",
            "type": "zip", "strip_components": 1, "exclude": ["Themes"],
            "systems": ["nintendo-gamecube"],
            "files": {
                "Sys/GC/font.bin": {"sha1": hashlib.sha1(b"font").hexdigest(), "size": 4},
                "Sys/GC/dsp.bin": {"sha1": hashlib.sha1(b"old").hexdigest(), "size": 3},
                "Sys/GC/gone.bin": {"sha1": "0" * 40, "size": 1},
            },
        }

    def test_required_only_leaves_out_an_optional_tree(self):
        """A GBA and a SNES game with --for-games --required-only took
        FBNeo's cheats and samples, 3,472 files no game opened."""
        cheats = {**self._entry(), "ref": "fbneo-cheats", "systems": ["snes"], "optional": True}
        sys_tree = {**self._entry(), "systems": ["snes"]}
        manifest = {"data_directories": [cheats, sys_tree]}
        files = [{"dest": "a.rom", "systems": ["snes"]}]
        self.assertEqual(install.select_data_directories(manifest, files, True), [cheats, sys_tree])
        self.assertEqual(install.select_data_directories(manifest, files, True, True), [sys_tree])
        self.assertEqual(install.select_data_directories(manifest, files, False, True), [sys_tree])
        install._check_data_directory(cheats, "data_directories[0]")
        with self.assertRaises(ValueError):
            install._check_data_directory({**cheats, "optional": False}, "data_directories[0]")

    def test_the_archive_is_drawn_and_counted(self):
        """82 MB of archives came with no progress line, and the run ended
        on "310.5 KB downloaded", the BIOS files alone."""
        work = scratch_dir(self)
        body = self._zip(work).read_bytes()
        attempts: list[int] = []

        class Response(io.BytesIO):
            headers = {"Content-Length": str(len(body))}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def urlopen(_url, timeout=None):
            attempts.append(1)
            if len(attempts) == 1:
                class Cut(Response):
                    def read(self, size=-1):
                        if self.tell():
                            raise ConnectionResetError("cut")
                        return super().read(5)
                return Cut(body)
            return Response(body)

        progress = install.Progress(1, 0, install.Terminal(io.StringIO()), events=False)
        with unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen), \
                unittest.mock.patch.object(install, "_network_allowed", lambda url: None), \
                unittest.mock.patch.object(install, "_retry_delay", lambda *a: 0), \
                unittest.mock.patch.object(install.EVENTS, "emit") as emit:
            path = install._fetch_archive("https://example.invalid/D.zip", work, progress)
        self.assertEqual(path.read_bytes(), body)
        self.assertEqual(len(attempts), 2)
        # The cut attempt's five bytes are taken back.
        self.assertEqual((progress.transferred(), progress.expected_bytes),
                         (len(body), len(body)))
        emit.assert_not_called()

    def test_a_cut_archive_resumes_where_it_stopped(self):
        """A data archive cut at 90% was deleted and fetched again from
        zero, on the retry and on the next run, while the run said that
        nothing was lost."""
        work = scratch_dir(self)
        body = self._zip(work).read_bytes()
        keep = work / ".dolphin-sys.archive.part"
        requests: list[dict] = []

        class Response(io.BytesIO):
            def __init__(self, data, status, headers):
                super().__init__(data)
                self.status, self.headers = status, headers

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def urlopen(request, timeout=None):
            sent = dict(request.header_items())
            requests.append(sent)
            if "Range" in sent:
                start = int(sent["Range"][len("bytes="):-1])
                if sent.get("If-range") != '"v1"':
                    return Response(body, 200, {"ETag": '"v2"'})
                return Response(body[start:], 206, {
                    "Content-Range": f"bytes {start}-{len(body) - 1}/{len(body)}",
                    "Content-Length": str(len(body) - start), "ETag": '"v1"'})
            cut = len(body) * 9 // 10

            class Cut(Response):
                def read(self, size=-1):
                    if self.tell() >= cut:
                        raise ConnectionResetError("cut")
                    return super().read(min(size, cut - self.tell()))
            return Cut(body, 200, {"Content-Length": str(len(body)), "ETag": '"v1"'})

        with unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen), \
                unittest.mock.patch.object(install, "_network_allowed", lambda url: None), \
                unittest.mock.patch.object(install, "_retry_delay", lambda *a: 0):
            # The next run, after a stop: what the cut attempt wrote is kept.
            with unittest.mock.patch.object(install, "MAX_RETRIES", 1), \
                    self.assertRaises(ConnectionResetError):
                install._fetch_archive("https://example.invalid/D.zip", work, None, keep)
            self.assertEqual(keep.stat().st_size, len(body) * 9 // 10)
            path = install._fetch_archive("https://example.invalid/D.zip", work, None, keep)
        self.assertEqual(path.read_bytes(), body)
        self.assertEqual(requests[-1]["Range"], f"bytes={len(body) * 9 // 10}-")
        self.assertEqual(requests[-1]["If-range"], '"v1"')

    def test_a_changed_archive_is_fetched_whole(self):
        work = scratch_dir(self)
        body = self._zip(work).read_bytes()
        keep = work / ".dolphin-sys.archive.part"
        keep.write_bytes(b"older revision")
        keep.with_name(keep.name + ".source").write_text(
            'https://example.invalid/D.zip\n"v0"\n')

        class Whole(io.BytesIO):
            status, headers = 200, {"ETag": '"v1"'}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with unittest.mock.patch.object(install.urllib.request, "urlopen",
                                        lambda request, timeout=None: Whole(body)), \
                unittest.mock.patch.object(install, "_network_allowed", lambda url: None):
            path = install._fetch_archive("https://example.invalid/D.zip", work, None, keep)
        self.assertEqual(path.read_bytes(), body)

    def test_a_tree_read_whole_leaves_no_archive(self):
        work = scratch_dir(self)
        archive = self._zip(work)
        bios = work / "system"
        bios.mkdir()

        def fetch(url, directory, progress=None, keep=None):
            shutil.copy(archive, keep)
            keep.with_name(keep.name + ".source").write_text(f"{url}\n\"v1\"\n")
            return keep

        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            install.install_data_directory(self._entry(), bios)
        self.assertEqual([p.name for p in (bios / "dolphin-emu").iterdir()], ["Sys"])

    def test_a_second_run_leaves_the_kept_archive_alone(self):
        """Two runs into one BIOS folder shared .dolphin-sys.archive.part: the
        one that finished first deleted the archive the other was still
        writing, and the other truncated the one being read."""
        work = scratch_dir(self)
        archive = self._zip(work)
        bios = work / "system"
        root = bios / "dolphin-emu"
        root.mkdir(parents=True)
        other = root / ".dolphin-sys.archive.part"
        other.write_bytes(b"another run is writing this")
        kept: list = []

        def fetch(url, directory, progress=None, keep=None):
            kept.append(keep)
            copy = Path(directory) / "private.zip"
            shutil.copy(archive, copy)
            return copy

        held = install._claim_partial(root / ".dolphin-sys.archive.lock")
        self.addCleanup(held.close)
        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            counts = install.install_data_directory(self._entry(), bios)
        self.assertEqual(kept, [None])
        self.assertEqual(counts["installed"], 1)
        self.assertEqual(other.read_bytes(), b"another run is writing this")
        self.assertTrue((root / ".dolphin-sys.archive.lock").exists())

    def test_a_lone_run_keeps_its_archive_beside_the_tree(self):
        work = scratch_dir(self)
        archive = self._zip(work)
        bios = work / "system"
        kept: list = []

        def fetch(url, directory, progress=None, keep=None):
            kept.append(keep)
            shutil.copy(archive, keep)
            return keep

        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            install.install_data_directory(self._entry(), bios)
        self.assertEqual(kept, [bios / "dolphin-emu" / ".dolphin-sys.archive.part"])
        self.assertEqual(sorted(p.name for p in (bios / "dolphin-emu").iterdir()), ["Sys"])

    def test_the_run_ends_on_the_archive_bytes_too(self):
        from tests.installsupport import FakeRepository

        member = os.urandom(300_000)
        with FakeRepository() as repo:
            with zipfile.ZipFile(repo.root / "tree.zip", "w") as zf:
                zf.writestr("Sys/big.bin", member)
            archive = (repo.root / "tree.zip").stat().st_size
            listed = json.loads((repo.root / "install" / "retroarch.json").read_text())
            listed["data_directories"] = [{
                "ref": "tree", "dest": "tree", "type": "zip",
                "url": f"http://127.0.0.1:{repo.httpd.server_address[1]}/tree.zip",
                "systems": ["nintendo-gba"],
                "files": {"Sys/big.bin": {"sha1": hashlib.sha1(member).hexdigest(),
                                          "size": len(member)}}}]
            (repo.root / "install" / "retroarch.json").write_text(json.dumps(listed))
            proc = repo.run("--no-input", "--verbose")
            bios = sum(len(payload) for payload, *_ in FakeRepository.PAYLOADS.values())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"{install.format_size(bios + archive)} downloaded in", proc.stdout)

    def test_the_plan_announces_the_archive_not_the_tree(self):
        """yaps2's tarball is 21.2 MB for a 6.5 MB tree, Cemu's 21.4 MB for
        9.9 KB: the plan announced the tree, and the run downloaded far more."""
        from tests.installsupport import FakeRepository

        member = b"profile"
        archive_size = 21_360_579
        with FakeRepository() as repo:
            listed = json.loads((repo.root / "install" / "retroarch.json").read_text())
            listed["data_directories"] = [{
                "ref": "cemu-gameprofiles", "dest": "cemu", "type": "tarball",
                "url": "https://example.invalid/Cemu.tar.gz", "source_path": "Cemu-1/bin",
                "systems": ["nintendo-gba"], "archive_size": archive_size,
                "files": {"gameProfiles/a.ini": {"sha1": hashlib.sha1(member).hexdigest(),
                                                 "size": len(member)}}}]
            (repo.root / "install" / "retroarch.json").write_text(json.dumps(listed))
            proc = repo.run("--no-input", "--dry-run")
            bios = sum(len(payload) for payload, *_ in FakeRepository.PAYLOADS.values())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"({install.format_size(bios + archive_size)})", proc.stdout)
        self.assertIn(f"(a {install.format_size(archive_size)} archive)", proc.stdout)

    def test_a_pack_or_an_old_list_counts_the_files_themselves(self):
        needed = {"a": {"size": 7}}
        entry = {"archive_size": 21_360_579}
        self.assertEqual(install.data_fetch_bytes(entry, needed), 21_360_579)
        self.assertEqual(install.data_fetch_bytes({}, needed), 7)
        self.assertEqual(install.data_fetch_bytes(entry, {}), 0)
        with unittest.mock.patch.object(install.LOCAL, "pack", object()):
            self.assertEqual(install.data_fetch_bytes(entry, needed), 7)

    def test_verified_members_land_the_rest_are_said(self):
        work = scratch_dir(self)
        archive = self._zip(work)
        bios = work / "system"
        bios.mkdir()

        def fetch(url, directory, progress=None, keep=None):
            copy = Path(directory) / "a.zip"
            shutil.copy(archive, copy)
            return copy

        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            counts = install.install_data_directory(self._entry(), bios)
            again = install.install_data_directory(self._entry(), bios)
        self.assertEqual((counts["installed"], counts["changed"], counts["absent"]), (1, 1, 1))
        self.assertEqual((bios / "dolphin-emu" / "Sys" / "GC" / "font.bin").read_bytes(), b"font")
        self.assertFalse((bios / "dolphin-emu" / "Sys" / "GC" / "dsp.bin").exists())
        self.assertFalse((bios / "dolphin-emu" / "Themes").exists())
        self.assertEqual(again["present"], 1)
        self.assertEqual(sorted(p.name for p in (bios / "dolphin-emu").iterdir()), ["Sys"])

    def _served(self, archive: Path):
        def fetch(url, directory, progress=None, keep=None):
            copy = Path(directory) / "a.zip"
            shutil.copy(archive, copy)
            return copy
        return fetch

    def test_a_rolling_tree_lands_what_its_source_serves(self):
        """The buildbot rebuilt PPSSPP.zip and 49 of its 169 files were
        refused on every install: a nightly source holds no other bytes.
        RetroArch's own downloader writes what the buildbot serves."""
        work = scratch_dir(self)
        bios = work / "system"
        bios.mkdir()
        entry = {**self._entry(), "rolling": True}
        with unittest.mock.patch.object(install, "_fetch_archive", self._served(self._zip(work))):
            counts = install.install_data_directory(entry, bios)
        self.assertEqual((counts["installed"], counts["updated"], counts["changed"],
                          counts["absent"]), (2, 1, 0, 1))
        dsp = bios / "dolphin-emu" / "Sys" / "GC" / "dsp.bin"
        self.assertEqual(dsp.read_bytes(), b"new bytes upstream")
        self.assertIn({"dest": "dolphin-emu/Sys/GC/dsp.bin",
                       "sha1": hashlib.sha1(b"new bytes upstream").hexdigest(),
                       "size": len(b"new bytes upstream")}, counts["written"])
        self.assertFalse((bios / "dolphin-emu" / "Themes").exists())

    def test_a_rolling_file_an_earlier_run_wrote_is_in_place(self):
        """Its bytes are not the list's, they are what the source served and
        the record names: the next run neither fetches nor rewrites it."""
        work = scratch_dir(self)
        bios = work / "system"
        bios.mkdir()
        entry = {**self._entry(), "rolling": True}
        with unittest.mock.patch.object(install, "_fetch_archive", self._served(self._zip(work))):
            counts = install.install_data_directory(entry, bios)
        files = [install.record_file(item, "download", "data") for item in counts["written"]]
        install.write_record(bios, "retroarch", {}, [], files)
        _root, needed, present = install.data_directory_state(entry, bios)
        self.assertEqual((sorted(needed), present), (["Sys/GC/gone.bin"], 2))
        # Changed on the drive since: neither the list's bytes nor the run's.
        (bios / "dolphin-emu" / "Sys" / "GC" / "dsp.bin").write_bytes(b"new bytes upstreaM")
        self.assertIn("Sys/GC/dsp.bin", install.data_directory_state(entry, bios)[1])
        # A tree listed at a commit takes only the list's bytes.
        self.assertIn("Sys/GC/dsp.bin", install.data_directory_state(self._entry(), bios)[1])

    def test_a_damaged_rolling_member_is_never_written(self):
        """No hash to hold a followed member to: its ZIP CRC-32 still is."""
        import zipfile

        work = scratch_dir(self)
        archive = self._zip(work)
        body = bytearray(archive.read_bytes())
        at = body.index(b"new bytes upstream")
        body[at] ^= 0x01
        archive.write_bytes(bytes(body))
        bios = work / "system"
        bios.mkdir()
        with unittest.mock.patch.object(install, "_fetch_archive", self._served(archive)):
            counts = install.install_data_directory({**self._entry(), "rolling": True}, bios)
        self.assertTrue(counts["error"])
        self.assertFalse((bios / "dolphin-emu" / "Sys" / "GC" / "dsp.bin").exists())
        self.assertEqual([p.name for p in (bios / "dolphin-emu" / "Sys" / "GC").iterdir()
                          if p.name.endswith(".part")], [])
        self.assertTrue(zipfile.is_zipfile(archive))

    def test_a_pack_rebuilds_a_rolling_tree_as_listed(self):
        """From a pack, the pack's copy is the tree: nothing newer exists."""
        work = scratch_dir(self)
        bios = work / "system"
        bios.mkdir()

        def tree(_dest):
            yield "Sys/GC/dsp.bin", 18, lambda: io.BytesIO(b"new bytes upstream")

        local = unittest.mock.Mock()
        local.tree = tree
        with unittest.mock.patch.object(install.LOCAL, "pack", local):
            counts = install.install_data_directory({**self._entry(), "rolling": True}, bios)
        self.assertEqual((counts["installed"], counts["updated"], counts["changed"]), (0, 0, 1))

    def test_a_rolling_member_past_its_cap_is_not_written(self):
        """A followed member is read to the size its archive declares: a
        source serving gigabytes where the list has 3 bytes fills no drive."""
        work = scratch_dir(self)
        entry = {**self._entry(), "rolling": True}
        served: list[int] = []

        def members(_archive, _entry):
            for rel, size in (("Sys/GC/dsp.bin", 900 * 1024 * 1024),
                              ("Sys/GC/font.bin", 4)):
                yield rel, size, lambda size=size: served.append(size) or io.BytesIO(b"font")

        with unittest.mock.patch.object(
                install, "_fetch_archive",
                lambda url, d, progress=None, keep=None: Path(d) / "a"), \
                unittest.mock.patch.object(install, "_archive_members", members):
            counts = install.install_data_directory(entry, work)
        self.assertEqual((counts["changed"], counts["installed"]), (1, 1))
        self.assertEqual(served, [4])
        self.assertEqual(install._follow_cap(3), 16 * 1024 * 1024 + 6)
        self.assertFalse(install._followable({"size": 3}, 40, [39]))

    def test_a_rolling_flag_is_true_or_absent(self):
        with self.assertRaisesRegex(ValueError, "rolling is invalid"):
            install._check_data_directory({**self._entry(), "rolling": False}, "d")
        install._check_data_directory({**self._entry(), "rolling": True}, "d")

    def test_a_member_that_inflates_is_cut_at_its_size(self):
        # A member whose header claims the recorded size and whose stream
        # never ends: reading stops one byte past it.
        class Endless(io.RawIOBase):
            served = 0

            def readable(self):
                return True

            def readinto(self, buffer):
                Endless.served += len(buffer)
                buffer[:] = b"x" * len(buffer)
                return len(buffer)

        work = scratch_dir(self)
        entry = self._entry()
        entry["files"] = {"Sys/GC/font.bin": {"sha1": "1" * 40, "size": 4}}

        def members(_archive, _entry):
            yield "Sys/GC/font.bin", 4, lambda: io.BufferedReader(Endless())

        with unittest.mock.patch.object(
                install, "_fetch_archive",
                lambda url, d, progress=None, keep=None: Path(d) / "a"), \
                unittest.mock.patch.object(install, "_archive_members", members):
            counts = install.install_data_directory(entry, work)
        self.assertEqual(counts["changed"], 1)
        self.assertLess(Endless.served, 64 * 1024)

    def test_a_damaged_member_is_a_reason_and_leaves_no_part(self):
        """zlib.error and EOFError from a damaged member ended the run on a
        traceback, and a failed write left its .part beside the tree."""
        import zlib

        work = scratch_dir(self)
        entry = self._entry()
        entry["files"] = {"Sys/GC/font.bin": {"sha1": "1" * 40, "size": 4}}
        for error in (zlib.error("invalid stored block lengths"), EOFError(),
                      OSError(28, "No space left on device")):
            with self.subTest(error=type(error).__name__):
                class Broken(io.RawIOBase):
                    def readable(self):
                        return True

                    def readinto(self, buffer, error=error):
                        raise error

                def members(_archive, _entry):
                    yield "Sys/GC/font.bin", 4, lambda: io.BufferedReader(Broken())

                with unittest.mock.patch.object(
                        install, "_fetch_archive",
                        lambda url, d, progress=None, keep=None: Path(d) / "a"), \
                        unittest.mock.patch.object(install, "_archive_members", members):
                    counts = install.install_data_directory(entry, work)
                self.assertTrue(counts["error"])
                self.assertEqual(counts["installed"], 0)
                self.assertEqual([p.name for p in work.rglob("*.part")], [])

    def test_offline_keeps_its_reason(self):
        work = scratch_dir(self)
        with unittest.mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            counts = install.install_data_directory(self._entry(), work)
        self.assertIsInstance(counts["error"], install.OfflineReason)

    def test_a_tarball_maps_through_source_path(self):
        import io as _io
        import tarfile

        work = scratch_dir(self)
        archive = work / "src.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            data = b"index"
            info = tarfile.TarInfo("pcsx2-v1/bin/resources/GameIndex.yaml")
            info.size = len(data)
            tf.addfile(info, _io.BytesIO(data))
        entry = {"type": "tarball", "source_path": "pcsx2-v1/bin/resources"}
        names = [rel for rel, _size, _open in install._archive_members(archive, entry)]
        self.assertEqual(names, ["GameIndex.yaml"])

    def test_the_trust_boundary(self):
        entry = self._entry()
        install._check_data_directory(entry, "d")
        for bad in ({"url": "http://example.com/x.zip"}, {"dest": "../up"},
                    {"files": {"../x": {"sha1": "0" * 40, "size": 1}}},
                    {"type": "rar"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                install._check_data_directory({**entry, **bad}, "d")

    def test_the_published_retroarch_list_carries_them(self):
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        dirs = manifest.get("data_directories") or []
        files = sum(len(d["files"]) for d in dirs)
        from packs import archive as packs_archive
        from packs import datatrees

        written = packs_archive.PACK_DOCUMENTS + datatrees.pack_markers(
            "retroarch", None, str(REPO_ROOT / "platforms"))
        self.assertEqual(written, ("README.txt", "manifest.json", ".nomedia"))
        self.assertEqual(
            manifest["pack_files"] - manifest["total_files"] - files, len(written),
            "the pack's two documents and its .nomedia are the only files the "
            "installer lacks",
        )


if __name__ == "__main__":
    unittest.main()
