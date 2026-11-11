"""--pack: the choice downloaded into a pack ZIP for another device.

The pack is read back by --from-pack, offline, and must install exactly
what a direct install of the same choice installs. Parts are each a whole
ZIP. Every member is checked against its SHA-1 before the ZIP is closed,
and a failure leaves no file behind.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import functools
import hashlib
import http.server
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _noise(seed: str, size: int) -> bytes:
    """Bytes deflate cannot shrink."""
    return b"".join(hashlib.sha256(f"{seed}{n}".encode()).digest()
                    for n in range(size // 32))


# dest: (bytes, systems, regions, cores). Two dests share one file: the
# pack stores it once.
PAYLOADS = {
    "scph5500.bin": (b"jp bios " * 64, ["sony-playstation"], ["japan"], None),
    "scph5501.bin": (b"us bios " * 64, ["sony-playstation"], ["north-america"], None),
    "gba_bios.bin": (b"gba bios" * 32, ["nintendo-gba"], None, None),
    "pcsx/extra.bin": (b"pcsx extra", ["sony-playstation"], None, ["pcsx_rearmed"]),
    "mgba/gba_bios.bin": (b"gba bios" * 32, ["nintendo-gba"], None, ["mgba"]),
}
TREE = {"Sys/GC/font.bin": b"font bytes", "Sys/Wii/setting.txt": b"setting"}
# Files too large for one part of MIN_PART_BYTES together.
BIG = {f"arcade/set{n}.zip": (_noise(str(n), 24 * 1024), ["arcade"], None, None)
       for n in range(5)}


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        return


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Repository(unittest.TestCase):
    """A loopback copy of the repository: a RetroArch list, its files and a
    data tree's archive."""

    payloads = PAYLOADS
    tree = TREE

    def setUp(self):
        scratch = REPO_ROOT / "tmp"
        scratch.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.served = self.root / "served"
        (self.served / "install").mkdir(parents=True)
        (self.served / "bios").mkdir()
        handler = functools.partial(_Quiet, directory=str(self.served))
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.out = self.root / "out"
        self.out.mkdir()
        self.write_list()

    def write_list(self) -> None:
        files = []
        for dest, (payload, systems, regions, cores) in self.payloads.items():
            stored = dest.replace("/", "_")
            (self.served / "bios" / stored).write_bytes(payload)
            entry = {"dest": dest, "sha1": _sha1(payload), "size": len(payload),
                     "repo_path": f"bios/{stored}", "cores": cores, "systems": systems}
            if regions:
                entry.update(regions=regions, region_system_groups=systems)
            files.append(entry)
        listed: dict = {"manifest_version": 2, "platform": "retroarch", "files": files,
                        "system_cores": {"sony-playstation": ["pcsx_rearmed"],
                                         "nintendo-gba": ["mgba"], "arcade": ["fbneo"]}}
        if self.tree:
            with zipfile.ZipFile(self.served / "tree.zip", "w") as archive:
                for rel, data in self.tree.items():
                    archive.writestr(rel, data)
            listed["data_directories"] = [{
                "ref": "dolphin-sys", "dest": "dolphin-emu", "type": "zip",
                "url": f"{self.base}/tree.zip", "systems": ["nintendo-gba"],
                "files": {rel: {"sha1": _sha1(data), "size": len(data)}
                          for rel, data in self.tree.items()}}]
        (self.served / "install" / "retroarch.json").write_text(json.dumps(listed))

    def env(self, offline: bool = False) -> dict:
        env = dict(os.environ)
        env.pop(install.OFFLINE_VARIABLE, None)
        env["RETROBIOS_BASE_URL"] = self.base
        if offline:
            env["RETROBIOS_BASE_URL"] = f"http://127.0.0.1:{_closed_port()}"
            env["HTTPS_PROXY"] = env["HTTP_PROXY"] = f"http://127.0.0.1:{_closed_port()}"
            env[install.OFFLINE_VARIABLE] = "1"
        return env

    def run_installer(self, *options: str, offline: bool = False,
                      code: str | None = None) -> subprocess.CompletedProcess:
        start = ([sys.executable, "-c", code] if code is not None
                 else [sys.executable, str(REPO_ROOT / "install.py")])
        return subprocess.run(
            [*start, "--platform", "retroarch", *options], env=self.env(offline),
            capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL, cwd=str(self.root))

    def make(self, *options: str, into: Path | None = None) -> subprocess.CompletedProcess:
        proc = self.run_installer("--pack", f"{into or self.out}{os.sep}", *options)
        return proc

    def installed(self, folder: Path) -> set[tuple[str, str]]:
        """(path, sha1) of every file below folder, the record and backups
        the installer keeps beside its files left out."""
        return {(path.relative_to(folder).as_posix(), _sha1(path.read_bytes()))
                for path in folder.rglob("*")
                if path.is_file() and not any("retrobios" in part.lower()
                                               for part in path.relative_to(folder).parts)}

    def direct(self, folder: Path, *options: str) -> set[tuple[str, str]]:
        proc = self.run_installer("--dest", str(folder), "--yes", *options)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return self.installed(folder)

    def from_pack(self, pack: Path, folder: Path, *options: str) -> set[tuple[str, str]]:
        proc = self.run_installer("--dest", str(folder), "--from-pack", str(pack), "--yes",
                                  *options, offline=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return self.installed(folder)

    def packs(self, folder: Path | None = None) -> list[Path]:
        return sorted((folder or self.out).iterdir())


class APackInstallsWhatADirectInstallDoes(Repository):
    def test_the_whole_list(self):
        expected = self.direct(self.root / "direct")
        self.assertIn(("dolphin-emu/Sys/GC/font.bin", _sha1(TREE["Sys/GC/font.bin"])),
                      expected)
        proc = self.make()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([path.name for path in self.packs()], ["RetroArch_BIOS_Pack.zip"])
        self.assertIn("Pack made: 6 files", proc.stdout)
        self.assertEqual(self.from_pack(self.packs()[0], self.root / "other"), expected)

    def test_a_narrowed_choice(self):
        options = ("--system", "sony-playstation", "--region", "us")
        expected = self.direct(self.root / "direct", *options)
        self.assertNotIn("gba_bios.bin", {path for path, _sha1 in expected})
        proc = self.make(*options)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        pack = self.out / "RetroArch_Custom_BIOS_Pack.zip"
        self.assertEqual(self.packs(), [pack])
        # The pack carries the choice: no option is needed on the other
        # device, and the same options give the same files.
        self.assertEqual(self.from_pack(pack, self.root / "plain"), expected)
        self.assertEqual(self.from_pack(pack, self.root / "again", *options), expected)

    def test_a_file_two_dests_share_is_stored_once(self):
        self.assertEqual(self.make().returncode, 0)
        with zipfile.ZipFile(self.packs()[0]) as archive:
            names = archive.namelist()
            listed = json.loads(archive.read("manifest.json"))
        self.assertEqual(names[0], "manifest.json")
        self.assertIn("gba_bios.bin", names)
        self.assertNotIn("mgba/gba_bios.bin", names)
        self.assertEqual(listed["platform"], "retroarch")
        self.assertEqual(sorted(entry["dest"] for entry in listed["install_list"]["files"]),
                         sorted(PAYLOADS))
        self.assertEqual([entry["ref"] for entry in
                          listed["install_list"]["data_directories"]], ["dolphin-sys"])

    def test_a_pack_made_from_a_pack(self):
        """No network is needed to make a pack of part of a pack."""
        self.assertEqual(self.make().returncode, 0)
        whole = self.packs()[0]
        smaller = self.root / "smaller"
        smaller.mkdir()
        proc = self.run_installer("--from-pack", str(whole), "--pack", f"{smaller}{os.sep}",
                                  "--system", "nintendo-gba", offline=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        expected = self.direct(self.root / "direct", "--system", "nintendo-gba")
        self.assertEqual(self.from_pack(self.packs(smaller)[0], self.root / "other"),
                         expected)

    def test_a_dry_run_lists_and_writes_nothing(self):
        proc = self.make("--dry-run", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Pack for RetroArch: 6 files", proc.stdout)
        self.assertIn("dolphin-emu/Sys/GC/font.bin", proc.stdout)
        self.assertEqual(self.packs(), [])


class APackIsDeterministic(Repository):
    def test_the_same_choice_gives_the_same_bytes(self):
        again = self.root / "again"
        again.mkdir()
        self.assertEqual(self.make().returncode, 0)
        self.assertEqual(self.make(into=again).returncode, 0)
        first, second = self.packs()[0], self.packs(again)[0]
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            infos = archive.infolist()
        self.assertEqual({info.date_time for info in infos}, {(1980, 1, 1, 0, 0, 0)})
        self.assertEqual({info.external_attr for info in infos}, {0o100644 << 16})
        names = [info.filename for info in infos]
        self.assertEqual(names[1:], sorted(names[1:]))


class Parts(Repository):
    payloads = {**PAYLOADS, **BIG}

    def test_each_part_is_a_whole_zip_and_their_union_is_the_pack(self):
        whole_dir = self.root / "whole"
        whole_dir.mkdir()
        self.assertEqual(self.make(into=whole_dir).returncode, 0)
        with zipfile.ZipFile(self.packs(whole_dir)[0]) as archive:
            whole = {info.filename: archive.read(info) for info in archive.infolist()}
        proc = self.make("--split", "64K")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        parts = self.packs()
        self.assertGreater(len(parts), 1)
        count = len(parts)
        self.assertEqual([part.name for part in parts],
                         [f"RetroArch_BIOS_Pack.part{n}of{count}.zip"
                          for n in range(1, count + 1)])
        self.assertIn(f"In {count} parts of at most 64.0 KB.", proc.stdout)
        union: dict[str, bytes] = {}
        markers = self.root / "markers"
        markers.mkdir()
        for index, part in enumerate(parts, 1):
            self.assertLess(part.stat().st_size, 64 * 1024)
            with zipfile.ZipFile(part) as archive:
                self.assertIsNone(archive.testzip())
                for info in archive.infolist():
                    data = archive.read(info)
                    if install._PART_MARKER.match(info.filename):
                        (markers / info.filename).write_bytes(data)
                        continue
                    self.assertNotIn(info.filename, union)
                    union[info.filename] = data
            marker = install.read_part_marker(
                markers / f"RetroArch_BIOS_Pack.part{index}of{count}.txt")
            self.assertIsNotNone(marker)
            self.assertEqual(marker.parts, tuple((p.name, p.stat().st_size) for p in parts))
        self.assertEqual(union, whole)
        expected = self.direct(self.root / "direct")
        self.assertEqual(self.from_pack(parts[1], self.root / "other"), expected)

    def test_a_pack_under_the_size_stays_one_zip(self):
        proc = self.make("--split", "100M")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([path.name for path in self.packs()], ["RetroArch_BIOS_Pack.zip"])

    def test_a_pack_made_again_in_parts_replaces_the_whole_one(self):
        self.assertEqual(self.make().returncode, 0)
        self.assertEqual(self.make("--split", "64K").returncode, 0)
        self.assertTrue(all(".part" in path.name for path in self.packs()))

    def test_a_file_larger_than_a_part_is_refused_before_any_download(self):
        self.payloads = {"big.bin": (_noise("x", 80 * 1024), ["arcade"], None, None)}
        self.write_list()
        proc = self.make("--split", "64K")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("big.bin (80.0 KB) does not fit in a part of 64.0 KB", proc.stderr)
        self.assertEqual(self.packs(), [])


# The installer run in a child with FAT32 said of every drive and its
# limit made small: a real 4 GiB pack is out of reach of a test.
FAT_CHILD = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("install", {script!r})
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)
install.fat32_drive = lambda folder: {fat}
install.FAT_FILE_LIMIT = 100 * 1024
install.FAT_PART_BYTES = 80 * 1024
sys.argv = ["install.py", *sys.argv[1:]]
install.main()
"""


class Fat32(Repository):
    payloads = {**PAYLOADS, **BIG}

    def child(self, fat: bool) -> str:
        return FAT_CHILD.format(script=str(REPO_ROOT / "install.py"), fat=fat)

    def test_a_pack_past_the_limit_is_split_by_itself(self):
        proc = self.run_installer("--pack", f"{self.out}{os.sep}", code=self.child(True))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        parts = self.packs()
        self.assertEqual(len(parts), 2)
        self.assertIn("In 2 parts of at most 80.0 KB, as FAT32 holds no file of 4 GB.",
                      proc.stdout)
        self.assertTrue(all(part.stat().st_size < 80 * 1024 for part in parts))

    def test_another_drive_keeps_one_zip(self):
        proc = self.run_installer("--pack", f"{self.out}{os.sep}", code=self.child(False))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([path.name for path in self.packs()], ["RetroArch_BIOS_Pack.zip"])
        self.assertNotIn("FAT32", proc.stdout)

    def test_the_mount_table_names_the_drive(self):
        table = ("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                 "36 22 179:1 / /media/me/SD\\040CARD rw,nosuid - vfat /dev/mmcblk0p1 rw\n"
                 "37 36 179:2 / /media/me/SD\\040CARD/inner rw - exfat /dev/mmcblk0p2 rw\n")
        mounts = install.mountinfo_types(table)
        self.assertEqual(mounts[1], ("/media/me/SD CARD", "vfat"))
        self.assertTrue(install.fat_mounted(Path("/media/me/SD CARD/packs"), mounts))
        self.assertFalse(install.fat_mounted(Path("/media/me/SD CARD/inner/x"), mounts))
        self.assertFalse(install.fat_mounted(Path("/home/me"), mounts))
        listing = "/dev/disk4s1 on /Volumes/CARD (msdos, local, nodev, nosuid)\n"
        self.assertTrue(install.fat_mounted(Path("/Volumes/CARD/x"),
                                            install.mount_list_types(listing)))


class AFailureLeavesNothing(Repository):
    def test_a_download_that_fails_leaves_no_file(self):
        (self.served / "bios" / "scph5501.bin").write_bytes(b"changed on the server")
        proc = self.make()
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("could not be had: no pack was written", proc.stderr)
        self.assertEqual(self.packs(), [])

    def test_an_earlier_pack_of_the_name_stays_as_it_was(self):
        self.assertEqual(self.make().returncode, 0)
        before = self.packs()[0].read_bytes()
        (self.served / "bios" / "gba_bios.bin").unlink()
        proc = self.make()
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual([path.name for path in self.packs()], ["RetroArch_BIOS_Pack.zip"])
        self.assertEqual(self.packs()[0].read_bytes(), before)

    def test_a_member_whose_bytes_changed_is_refused_before_the_zip_closes(self):
        source = self.root / "staged.bin"
        source.write_bytes(b"other bytes")
        member = install.PackMember("a.bin", _sha1(b"listed bytes"), 11, source)
        with self.assertRaises(install.PackError):
            install.write_pack(self.out / "RetroArch_BIOS_Pack.zip", b"{}", [member], None)
        self.assertEqual(self.packs(), [])


class Events(Repository):
    def events(self, *options: str) -> tuple[list[dict], int]:
        proc = self.make("--events", *options)
        return [json.loads(line) for line in proc.stdout.splitlines()], proc.returncode

    def test_the_pack_event(self):
        events, code = self.events("--dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(events[0]["mode"], "pack")
        pack = next(event for event in events if event["event"] == "pack")
        self.assertEqual(list(pack)[1:], list(install.EVENT_KEYS["pack"]))
        self.assertEqual(pack["status"], "planned")
        self.assertEqual(pack["files"], 6)
        self.assertEqual(pack["size"], 0)
        self.assertEqual(self.packs(), [])
        events, code = self.events()
        self.assertEqual(code, 0)
        pack = next(event for event in events if event["event"] == "pack")
        self.assertEqual(pack["status"], "written")
        self.assertEqual(pack["parts"], [str(self.out / "RetroArch_BIOS_Pack.zip")])
        self.assertEqual(pack["size"], self.packs()[0].stat().st_size)
        self.assertEqual(events[-1], {"event": "end", "code": 0})

    def test_a_failure_is_an_event(self):
        (self.served / "bios" / "scph5500.bin").unlink()
        events, code = self.events()
        self.assertEqual(code, 1)
        pack = next(event for event in events if event["event"] == "pack")
        self.assertEqual((pack["status"], pack["parts"]), ("failed", []))
        self.assertEqual(events[-1], {"event": "end", "code": 1})


class Refusals(Repository):
    def test_options_of_this_machine_s_folder_are_refused(self):
        for options in (("--check",), ("--dest", str(self.root / "x")),
                        ("--installed-cores",), ("--for-games",), ("--list-systems",)):
            with self.subTest(options=options):
                proc = self.make(*options)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn("install.py: error:", proc.stderr)

    def test_split_needs_pack_and_a_size(self):
        proc = self.run_installer("--split", "1G")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--split applies to --pack", proc.stderr)
        proc = self.make("--split", "1K")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("too small", proc.stderr)

    def test_a_name_the_reader_would_not_find_is_refused(self):
        proc = self.run_installer("--pack", str(self.out / "mine.zip"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("_BIOS_Pack.zip", proc.stderr)

    def test_a_pack_named_by_the_user_reads_its_platform_inside(self):
        named = self.out / "Living_Room_BIOS_Pack.zip"
        proc = self.run_installer("--pack", str(named))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        pack = install.PackSource([named])
        self.addCleanup(pack.close)
        self.assertEqual(pack.platforms(), ["retroarch"])


class PartSizes(unittest.TestCase):
    def test_a_size_reads_as_bytes_or_with_its_unit(self):
        self.assertEqual(install.parse_part_size("1900M"), 1900 * 1024 ** 2)
        self.assertEqual(install.parse_part_size("4g"), 4 * 1024 ** 3)
        self.assertEqual(install.parse_part_size("70000"), 70000)
        for text in ("big", "1K", "-5M"):
            with self.subTest(text=text), \
                    mock.patch("sys.stderr", io.StringIO()), \
                    self.assertRaises(Exception):
                install.parse_part_size(text)


if __name__ == "__main__":
    unittest.main()
