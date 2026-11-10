"""What --check says about a refused file, and an install with no network.

A user with the BIOS one folder too deep, still in its ZIP or under another
name read "missing: scph5501.bin" and nothing else. --check now names the
reason and where each core opens the file. A pack extracted from some of
its parts is named by the part it lacks. And a pack downloaded once
installs again from disk, --from-pack, every file checked by its hash.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import install  # noqa: E402
import split_pack  # noqa: E402
from test_install_selection import FakeRepository  # noqa: E402

US = b"us bios " * 64
JP = b"jp bios " * 64
EU = b"eu bios " * 64
GBA = b"gba bios" * 32
EXTRA = b"pcsx extra"


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _entry(dest: str, data: bytes, systems: list[str], **fields) -> dict:
    return {
        "dest": dest, "sha1": _sha1(data), "size": len(data),
        "repo_path": f"bios/{dest.replace('/', '_')}", "cores": None,
        "systems": systems, **fields,
    }


def manifest() -> dict:
    """A small RetroArch list: two regions of one BIOS, a core file with a
    second revision, a file in a subfolder."""
    return {
        "manifest_version": 2,
        "platform": "retroarch",
        "files": [
            _entry("scph5501.bin", US, ["sony-playstation"], regions=["north-america"]),
            _entry("scph5500.bin", JP, ["sony-playstation"], regions=["japan"]),
            _entry("gba_bios.bin", GBA, ["nintendo-gba"]),
            _entry("pcsx/extra.bin", EXTRA, ["sony-playstation"], cores=["pcsx_rearmed"],
                   alternatives=[{"sha1": _sha1(EU), "size": len(EU),
                                  "repo_path": "bios/eu", "cores": ["beetle_psx"]},
                                 {"sha1": _sha1(EXTRA), "size": len(EXTRA),
                                  "repo_path": "bios/x", "cores": ["pcsx_rearmed"]}]),
        ],
        "system_cores": {"sony-playstation": ["beetle_psx", "pcsx_rearmed"],
                         "nintendo-gba": ["mgba"]},
    }


PAYLOAD = {"scph5501.bin": US, "scph5500.bin": JP, "gba_bios.bin": GBA,
           "pcsx/extra.bin": EXTRA}


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _offline_env() -> dict:
    """An environment where any request the installer makes is refused."""
    env = dict(os.environ)
    env["RETROBIOS_BASE_URL"] = f"http://127.0.0.1:{_closed_port()}"
    env["HTTPS_PROXY"] = env["HTTP_PROXY"] = f"http://127.0.0.1:{_closed_port()}"
    return env


class Scratch(unittest.TestCase):
    def setUp(self):
        scratch = REPO_ROOT / "tmp"
        scratch.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.dest = self.root / "system"
        self.list = self.root / "retroarch.json"
        self.list.write_text(json.dumps(manifest()))

    def run_installer(self, *options: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", str(self.dest), *options],
            env=_offline_env(), capture_output=True, text=True, timeout=120,
            check=False, stdin=subprocess.DEVNULL,
        )

    def place(self, relative: str, data: bytes) -> Path:
        path = self.dest / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def check(self) -> str:
        proc = self.run_installer("--check", "--manifest", str(self.list), "--verbose")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        return proc.stdout

    def complete(self, *skip: str) -> None:
        for name, data in PAYLOAD.items():
            if name not in skip:
                self.place(name, data)


class CheckNamesWhyAFileIsRefused(Scratch):
    def test_another_region_is_named(self):
        self.complete("scph5501.bin")
        self.place("scph5501.bin", JP)
        out = self.check()
        self.assertIn("wrong copy: scph5501.bin", out)
        self.assertIn("another region: the contents of scph5500.bin (japan)", out)

    def test_another_revision_names_the_core_that_reads_it(self):
        self.complete("pcsx/extra.bin")
        self.place("pcsx/extra.bin", EU)
        out = self.check()
        self.assertIn("another revision: the copy beetle_psx reads", out)

    def test_a_wrong_size_is_measured(self):
        self.complete("gba_bios.bin")
        self.place("gba_bios.bin", b"short")
        self.assertIn(f"wrong size: 5 bytes, the list expects {len(GBA):,}", self.check())

    def test_a_zip_under_the_file_name_is_still_zipped(self):
        self.complete("gba_bios.bin")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("gba_bios.bin", GBA)
        self.place("gba_bios.bin", buffer.getvalue())
        self.assertIn("still zipped: this file is a ZIP archive", self.check())

    def test_a_file_inside_an_archive_is_still_zipped(self):
        self.complete("gba_bios.bin")
        self.dest.mkdir(exist_ok=True)
        with zipfile.ZipFile(self.dest / "GBA BIOS.zip", "w") as archive:
            archive.writestr("bios/gba_bios.bin", GBA)
        self.assertIn("still zipped: it is inside GBA BIOS.zip", self.check())

    def test_a_case_difference_is_named(self):
        probe = self.root / "CaseProbe"
        probe.write_text("x")
        if (self.root / "caseprobe").exists():
            self.skipTest("this filesystem does not keep case")
        self.complete("gba_bios.bin")
        self.place("GBA_BIOS.BIN", GBA)
        self.assertIn("case of the name: the folder holds GBA_BIOS.BIN", self.check())

    def test_a_case_twin_the_pack_leaves_out_is_not_a_wrong_folder(self):
        """np2kai/2608_bd.wav and np2/2608_bd.wav hold the same bytes. Told
        "wrong folder", a user moved np2's copy and broke that core."""
        probe = self.root / "CaseProbe"
        probe.write_text("x")
        if (self.root / "caseprobe").exists():
            self.skipTest("this filesystem does not keep case")
        data = json.loads(self.list.read_text())
        twin = next(f for f in data["files"] if f["dest"] == "gba_bios.bin")
        data["case_variants"] = [{**twin, "dest": "GBA_BIOS.BIN"}]
        self.list.write_text(json.dumps(data))
        self.complete()
        out = self.check()
        self.assertIn("missing: GBA_BIOS.BIN", out)
        self.assertIn("a second name the pack leaves out", out)
        self.assertNotIn("wrong folder: it is at gba_bios.bin", out)

    def test_a_case_twin_is_plain_missing_when_no_pack_was_used(self):
        """On an empty folder every case variant came first, uncapped, with
        a note on a pack never downloaded: the BIOS files the user looked
        for sat in "... and N more missing"."""
        probe = self.root / "CaseProbe"
        probe.write_text("x")
        if (self.root / "caseprobe").exists():
            self.skipTest("this filesystem does not keep case")
        data = json.loads(self.list.read_text())
        twin = next(f for f in data["files"] if f["dest"] == "gba_bios.bin")
        data["case_variants"] = [{**twin, "dest": "GBA_BIOS.BIN"}]
        self.list.write_text(json.dumps(data))
        out = self.check()
        self.assertIn("missing: GBA_BIOS.BIN", out)
        self.assertNotIn("a second name the pack leaves out", out)

    def test_a_nested_bios_folder_is_named(self):
        for name, data in PAYLOAD.items():
            self.place(f"system/{name}", data)
        out = self.check()
        self.assertIn("nested folder: it is at system/system/scph5501.bin", out)
        self.assertIn(f"4 files sit too deep, in {self.dest.resolve() / 'system'}", out)

    def test_a_wrong_folder_is_named(self):
        self.complete("pcsx/extra.bin")
        self.place("beetle/extra.bin", EXTRA)
        self.assertIn("wrong folder: it is at beetle/extra.bin", self.check())

    def test_a_folder_too_deep_is_named(self):
        self.complete("gba_bios.bin")
        self.place("gba/roms/gba_bios.bin", GBA)
        self.assertIn("2 folders too deep: it is at gba/roms/gba_bios.bin", self.check())

    def test_a_folder_too_high_is_named(self):
        self.complete("gba_bios.bin")
        (self.root / "gba_bios.bin").write_bytes(GBA)
        self.assertIn(f"one folder too high: it is at {self.root.resolve() / 'gba_bios.bin'}",
                      self.check())

    def test_a_name_no_core_opens_is_named(self):
        self.complete("scph5501.bin")
        self.place("PSX BIOS (USA).bin", US)
        self.assertIn("a name no core opens: its contents are at PSX BIOS (USA).bin, "
                      "rename it scph5501.bin", self.check())

    def test_a_save_directory_file_left_in_the_bios_folder_is_in_the_wrong_folder(self):
        """A pack carries the save directory's files under saves/: extracted
        into the BIOS folder they sit beside it, not too deep in it."""
        self.place("saves/azahar/keys.txt", b"keys")
        saves = self.root / "saves"
        saves.mkdir()
        install._SAVE_DIRS[self.dest] = install.SavePlace(saves, False)
        self.addCleanup(install._SAVE_DIRS.pop, self.dest, None)
        entry = _entry("azahar/keys.txt", b"keys", ["nintendo-3ds"], root="save")
        found = install.diagnose([entry], [], [entry], self.dest)
        self.assertEqual(found.reasons[id(entry)],
                         "wrong folder: it is at saves/azahar/keys.txt")
        self.assertEqual(found.deep, {})

    def test_each_flagged_file_says_where_its_cores_open_it(self):
        self.complete("scph5501.bin", "pcsx/extra.bin")
        out = self.check()
        here = self.dest.resolve()
        self.assertIn(f"read by beetle_psx, pcsx_rearmed at {here / 'scph5501.bin'}", out)
        self.assertIn(f"read by beetle_psx, pcsx_rearmed at {here / 'pcsx' / 'extra.bin'}",
                      out)
        # Never "opened" of a file that is not there.
        self.assertNotIn("opened at", out)

    def test_a_complete_folder_says_nothing_more(self):
        self.complete()
        proc = self.run_installer("--check", "--manifest", str(self.list))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("read by", proc.stdout)


class ArchivesInTheBiosFolder(Scratch):
    """The reason an archive gives is the first archive, in the order the
    folder is read, that holds the file or carries its name."""

    def zipped(self, relative: str, members: dict[str, bytes]) -> None:
        path = self.dest / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)

    def test_each_reason_names_the_first_archive_that_answers(self):
        self.zipped("a.zip", {"x.bin": b"x"})
        self.zipped("x.zip", {"other": b"o"})
        self.zipped("b.zip", {"other": b"o"})
        self.zipped("c.zip", {"bios/b.bin": b"b"})
        self.place("y.7z", b"7z")
        self.zipped("sub/z.zip", {"Z.BIN": b"z"})
        self.zipped("elsewhere/w.zip", {"w.bin": b"w"})
        self.zipped("listed.zip", {"v.bin": b"v"})
        entries = {dest: _entry(dest, dest.encode() * 3, ["x"]) for dest in (
            "x.bin", "b.bin", "y.bin", "sub/z.bin", "w.bin", "v.bin")}
        files = [*entries.values(), _entry("listed.zip", b"zip", ["x"])]
        found = install.diagnose(list(entries.values()), [], files, self.dest)
        self.assertEqual({dest: found.reasons.get(id(e), "") for dest, e in entries.items()}, {
            "x.bin": "still zipped: it is inside a.zip",
            "b.bin": "still zipped: b.zip needs extracting",
            "y.bin": "still zipped: y.7z needs extracting",
            "sub/z.bin": "still zipped: it is inside sub/z.zip",
            "w.bin": "",
            "v.bin": "",
        })

    def test_many_archives_and_many_missing_files_take_one_pass(self):
        """1,519 ZIPs and 2,000 missing files took 57 seconds: each missing
        file walked every archive of the folder."""
        self.dest.mkdir()
        for n in range(3000):
            with zipfile.ZipFile(self.dest / f"set{n:04}.zip", "w") as archive:
                archive.writestr(f"rom{n}.bin", b"x")
            (self.dest / f"same{n:04}.bin").write_bytes(b"%016d" % n)
        missing = [{"dest": f"file{n}.bin", "size": 16 if n % 2 else 1000 + n,
                    "sha1": f"{n:040}"} for n in range(3000)]
        missing.append(_entry("rom7.bin", b"r", ["x"]))
        start = time.monotonic()
        found = install.diagnose(missing, [], missing, self.dest)
        elapsed = time.monotonic() - start
        self.assertEqual(found.reasons, {
            id(missing[-1]): "still zipped: it is inside set0007.zip"})
        self.assertLess(elapsed, 30, f"{elapsed:.1f} s")


def _pack(directory: Path, name: str, members: dict[str, bytes]) -> Path:
    """A pack as generate_pack writes one: the files and a manifest.json."""
    listed = [{"path": path, "sha1": _sha1(data), "md5": hashlib.md5(data).hexdigest(),
               "size": len(data), "status": "verified", "name": path.rsplit("/", 1)[-1]}
              for path, data in members.items()]
    path = directory / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for member, data in members.items():
            archive.writestr(member, data)
        archive.writestr("README.txt", b"read me\n")
        archive.writestr("manifest.json", json.dumps({"files": listed}))
    return path


def _noise(seed: str, size: int) -> bytes:
    """Bytes deflate cannot shrink."""
    return b"".join(hashlib.sha256(f"{seed}{n}".encode()).digest()
                    for n in range(size // 32))


BIG = {f"dir{n}/file{n}.bin": _noise(str(n), 2048) for n in range(4)}


class SplitParts(Scratch):
    def split(self) -> list[Path]:
        downloads = self.root / "downloads"
        downloads.mkdir()
        pack = _pack(downloads, "RetroArch_v1_BIOS_Pack.zip", BIG)
        parts = split_pack.split_pack(pack, limit=pack.stat().st_size // 3)
        self.assertGreater(len(parts), 2)
        return parts

    def extract(self, parts: list[Path], into: Path | None = None) -> None:
        for part in parts:
            with zipfile.ZipFile(part) as archive:
                archive.extractall(into or self.dest)

    def list_of_pack(self) -> None:
        self.list.write_text(json.dumps({
            "manifest_version": 2, "platform": "retroarch",
            "files": [_entry(path, data, ["arcade"]) for path, data in BIG.items()],
        }))

    def test_check_names_the_part_missing_from_the_folder(self):
        parts = self.split()
        self.list_of_pack()
        self.extract(parts[:1] + parts[2:])
        out = self.check()
        count = len(parts)
        self.assertIn(f"RetroArch_v1_BIOS_Pack.zip comes in {count} parts, all needed.", out)
        self.assertIn(f"missing: part 2, RetroArch_v1_BIOS_Pack.part2of{count}.zip", out)
        self.assertNotIn("missing: part 1,", out)

    def test_check_names_a_part_extracted_into_a_folder_of_its_own(self):
        parts = self.split()
        self.list_of_pack()
        self.extract(parts[1:])
        own = self.dest / parts[0].stem
        self.extract(parts[:1], own)
        out = self.check()
        self.assertIn(f"Part 1 went into {own}, a folder of its own", out)
        self.assertNotIn("missing: part 1,", out)

    def test_a_complete_set_of_parts_says_nothing(self):
        parts = self.split()
        self.list_of_pack()
        self.extract(parts)
        proc = self.run_installer("--check", "--manifest", str(self.list))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("comes in", proc.stdout)

    def test_from_pack_finds_the_other_parts_beside_one(self):
        parts = self.split()
        proc = self.run_installer("--from-pack", str(parts[1]))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for path, data in BIG.items():
            self.assertEqual((self.dest / path).read_bytes(), data)

    def test_from_pack_names_a_part_that_is_not_there(self):
        parts = self.split()
        parts[1].unlink()
        proc = self.run_installer("--from-pack", str(parts[0]))
        self.assertEqual(proc.returncode, 1)
        self.assertIn(f"not in {parts[0].parent}: {parts[1].name}", proc.stderr)
        self.assertFalse(self.dest.exists())


def _carrying(pack: Path, extra: dict) -> None:
    """Add what a pack built since carries to its manifest.json."""
    with zipfile.ZipFile(pack) as archive:
        members = {info.filename: archive.read(info) for info in archive.infolist()}
    listed = {**json.loads(members["manifest.json"]), **extra}
    members["manifest.json"] = json.dumps(listed).encode()
    with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)


# A GBA board and a PlayStation board: PAYLOAD's files split between them.
BOARDS = {"gba-board": ["mgba"], "psx-board": ["pcsx_rearmed"]}


class ABoardWithoutTheNetwork(Scratch):
    """A pack alone, or --offline, never applied a board: --target was
    refused, and a board found on the device was ignored. A Batocera RPi4
    card took 8.9 GB from its pack where its board reads 5.8."""

    def setUp(self):
        super().setUp()
        self.downloads = self.root / "downloads"
        self.downloads.mkdir()
        self.pack = _pack(self.downloads, "RetroArch_v1_BIOS_Pack.zip", PAYLOAD)

    def installed(self) -> set[str]:
        return {p.relative_to(self.dest).as_posix() for p in self.dest.rglob("*")
                if p.is_file()}

    def test_the_builder_writes_both_into_the_pack_list(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack  # noqa: PLC0415

        install_list = manifest()
        board_file = REPO_ROOT / "platforms" / "targets" / "batocera.yml"
        boards = generate_pack.target_list(board_file)
        self.assertEqual(boards, json.loads(
            (REPO_ROOT / "install" / "targets" / "batocera.json").read_text()))
        pack_list = {"files": []}
        generate_pack.annotate_pack_systems(
            pack_list, generate_pack.pack_systems(install_list, boards))
        self.assertEqual(pack_list["install_list"], install_list)
        self.assertEqual(pack_list["targets"], boards)

    def test_the_pack_applies_its_board_list(self):
        _carrying(self.pack, {"install_list": manifest(), "targets": BOARDS})
        proc = self.run_installer("--from-pack", str(self.pack), "--target", "gba-board",
                                  "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.installed(), {"gba_bios.bin"})

    def test_a_list_beside_the_manifest_applies_offline(self):
        (self.root / "targets").mkdir()
        (self.root / "targets" / "retroarch.json").write_text(json.dumps(BOARDS))
        self.complete()
        proc = self.run_installer("--offline", "--check", "--manifest", str(self.list),
                                  "--target", "psx-board", "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("for target psx-board", proc.stdout)

    def test_the_boards_are_listed_from_where_target_reads_them(self):
        """Offline, the refusal of --list-targets named --manifest, and
        --manifest with --list-targets was refused: no form listed a board."""
        (self.root / "targets").mkdir()
        (self.root / "targets" / "retroarch.json").write_text(json.dumps(BOARDS))
        _carrying(self.pack, {"install_list": manifest(), "targets": BOARDS})
        for given in (["--offline", "--manifest", str(self.list)],
                      ["--from-pack", str(self.pack)]):
            with self.subTest(given=given[-1]):
                proc = self.run_installer(*given, "--list-targets", "--no-input")
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                for board in BOARDS:
                    self.assertIn(f"  {board} (", proc.stdout)
                self.assertFalse(self.dest.exists())

    def test_a_pack_without_a_list_says_why(self):
        proc = self.run_installer("--from-pack", str(self.pack), "--target", "gba-board",
                                  "--no-input")
        self.assertEqual(proc.returncode, 2)
        self.assertIn(f"{self.pack.name} carries none", proc.stderr)
        self.assertFalse(self.dest.exists())


class FromPackInstallsOffline(Scratch):
    def setUp(self):
        super().setUp()
        self.downloads = self.root / "downloads"
        self.downloads.mkdir()
        self.pack = _pack(self.downloads, "RetroArch_v1_BIOS_Pack.zip", PAYLOAD)

    def installed(self) -> dict[str, bytes]:
        return {p.relative_to(self.dest).as_posix(): p.read_bytes()
                for p in self.dest.rglob("*") if p.is_file()}

    def test_the_pack_installs_with_no_network(self):
        proc = self.run_installer("--from-pack", str(self.pack), "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.installed(), PAYLOAD)
        self.assertIn("Copying 4 files", proc.stdout)
        self.assertNotIn("Fetching", proc.stdout)

    def test_the_folder_holding_the_pack_is_enough(self):
        proc = self.run_installer("--from-pack", str(self.downloads))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.installed(), PAYLOAD)

    def test_the_platform_is_read_from_the_pack_name(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--dest", str(self.dest),
             "--from-pack", str(self.pack), "--no-input"],
            env=_offline_env(), capture_output=True, text=True, timeout=120,
            check=False, stdin=subprocess.DEVNULL,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.installed(), PAYLOAD)

    def test_a_pack_for_another_platform_is_refused(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "batocera",
             "--dest", str(self.dest), "--from-pack", str(self.pack)],
            env=_offline_env(), capture_output=True, text=True, timeout=120,
            check=False, stdin=subprocess.DEVNULL,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("is a pack for RetroArch, not Batocera", proc.stderr)

    def test_a_file_whose_bytes_differ_from_the_list_is_refused(self):
        """The hash is checked against the list the run reads, not trusted
        from the archive that carries both."""
        listed = manifest()
        listed["files"][0]["sha1"] = _sha1(b"something else")
        self.list.write_text(json.dumps(listed))
        proc = self.run_installer("--from-pack", str(self.pack), "--manifest", str(self.list))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("scph5501.bin", proc.stdout)
        self.assertFalse((self.dest / "scph5501.bin").exists())
        self.assertEqual((self.dest / "gba_bios.bin").read_bytes(), GBA)

    def test_with_a_saved_list_the_choice_options_apply(self):
        proc = self.run_installer("--from-pack", str(self.pack), "--manifest",
                                  str(self.list), "--system", "nintendo-gba")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.installed(), {"gba_bios.bin": GBA})

    def test_a_file_the_pack_does_not_hold_fails_by_name(self):
        listed = manifest()
        listed["files"].append(_entry("absent.bin", b"absent", ["nintendo-gba"]))
        self.list.write_text(json.dumps(listed))
        proc = self.run_installer("--from-pack", str(self.pack), "--manifest", str(self.list))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("absent.bin (not in the pack)", proc.stdout)

    def test_a_data_tree_is_rebuilt_from_the_pack(self):
        """The tree's source archive is never fetched: the pack holds it
        where it extracts."""
        tree = {"Sys/GC/font.bin": b"font bytes", "Sys/Wii/setting.txt": b"setting"}
        self.pack = _pack(self.downloads, "RetroArch_v1_BIOS_Pack.zip",
                          {**PAYLOAD, **{f"dolphin-emu/{k}": v for k, v in tree.items()}})
        listed = manifest()
        listed["data_directories"] = [{
            "ref": "dolphin-sys", "dest": "dolphin-emu", "type": "zip",
            "url": "https://example.invalid/dolphin.zip", "systems": ["nintendo-gba"],
            "files": {rel: {"sha1": _sha1(data), "size": len(data)}
                      for rel, data in tree.items()},
        }]
        self.list.write_text(json.dumps(listed))
        proc = self.run_installer("--from-pack", str(self.pack), "--manifest", str(self.list),
                                  "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("dolphin-sys: 2 installed", proc.stdout)
        for rel, data in tree.items():
            self.assertEqual((self.dest / "dolphin-emu" / rel).read_bytes(), data)

    def test_the_data_trees_say_what_they_weigh(self):
        """The plan read "and 2636 data files" with no
        size. The data event carries the bytes check's data_missing counts."""
        tree = {"Sys/GC/font.bin": b"font bytes", "Sys/Wii/setting.txt": b"setting"}
        listed = manifest()
        listed["data_directories"] = [{
            "ref": "dolphin-sys", "dest": "dolphin-emu", "type": "zip",
            "url": "https://example.invalid/dolphin.zip", "systems": ["nintendo-gba"],
            "files": {rel: {"sha1": _sha1(data), "size": len(data)}
                      for rel, data in tree.items()},
        }]
        self.list.write_text(json.dumps(listed))
        self.place("dolphin-emu/Sys/GC/font.bin", tree["Sys/GC/font.bin"])
        proc = self.run_installer("--check", "--events", "--manifest", str(self.list),
                                  "--from-pack", str(self.pack))
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        kinds = [event["event"] for event in events]
        self.assertEqual(kinds.index("data"), kinds.index("declared") + 1)
        data = events[kinds.index("data")]
        self.assertEqual(data, {"event": "data", "platform": "retroarch", "files": 1,
                                "bytes": len(tree["Sys/Wii/setting.txt"])})
        self.assertEqual(events[kinds.index("check")]["data_missing"], 1)

    def test_a_cut_download_is_named(self):
        self.pack.write_bytes(self.pack.read_bytes()[:100])
        proc = self.run_installer("--from-pack", str(self.pack))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("cannot be read as a ZIP", proc.stderr)

    def test_target_is_refused_with_from_pack(self):
        proc = self.run_installer("--from-pack", str(self.pack), "--target", "switch")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--target", proc.stderr)

    def test_no_request_leaves_the_process(self):
        """The guard holds in the code, not only in the test's dead proxy."""
        install.LOCAL.reset()
        install.LOCAL.pack = install.PackSource([self.pack])
        self.addCleanup(install.LOCAL.reset)
        with self.assertRaises(OSError):
            install._fetch_json("http://example.invalid/x.json", 10, "manifest")


class ManifestFromDisk(unittest.TestCase):
    def test_a_saved_list_installs_without_fetching_the_list(self):
        with FakeRepository() as repo:
            saved = repo.root / "saved.json"
            served = repo.root / "install" / "retroarch.json"
            saved.write_bytes(served.read_bytes())
            served.unlink()
            proc = repo.run("--manifest", str(saved))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(len(repo.installed()), 5)

    def test_a_list_for_another_platform_is_refused(self):
        with FakeRepository() as repo:
            saved = repo.root / "saved.json"
            data = json.loads((repo.root / "install" / "retroarch.json").read_text())
            data["platform"] = "batocera"
            saved.write_text(json.dumps(data))
            proc = repo.run("--manifest", str(saved))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("not valid for retroarch", proc.stderr)


def _sized(dest: str, size: int, systems: list[str], cores: list[str] | None = None) -> dict:
    return {"dest": dest, "size": size, "sha1": "0" * 40, "systems": systems,
            "cores": cores, "repo_path": f"bios/{dest}"}


MB = 1024 * 1024


class TheSummaryNamesTheBulk(unittest.TestCase):
    def test_a_core_pulling_most_of_a_system_is_named_with_the_saving(self):
        files = [
            _sized("opera.bin", 12 * MB, ["3do"]),
            _sized("mame/3do.zip", 300 * MB, ["3do"], ["mame"]),
            _sized("mame/3do_m2.zip", 37 * MB, ["3do"], ["mame"]),
        ]
        lines = install.bulk_hint(files, {"system_cores": {"3do": ["mame", "opera"]}},
                                  systems_chosen=True, cores_chosen=False,
                                  accepted={"mame", "opera"})
        self.assertEqual(lines, [
            "  mame pulls 337.0 MB of this 349.0 MB download for 3do. --core opera "
            "keeps 12.0 MB of it and saves 337.0 MB (96%)."
        ])

    def test_only_a_core_the_option_accepts_is_advised(self):
        """`--core ares keeps 11.0 MB` was printed, and `--core ares` then
        answered "unknown core": ares emulates the PlayStation and loads no
        file of its own, and --core takes only the cores that do."""
        files = [
            _sized("scph5501.bin", 1 * MB, ["sony-playstation"]),
            _sized("ps2_bios.bin", 300 * MB, ["sony-playstation"], ["duckstation"]),
            _sized("pcsx/extra.bin", 2 * MB, ["sony-playstation"], ["pcsx_rearmed"]),
        ]
        manifest = {"system_cores": {"sony-playstation": ["ares", "duckstation",
                                                          "pcsx_rearmed"]}}
        lines = install.bulk_hint(files, manifest, True, False,
                                  accepted={"duckstation", "pcsx_rearmed"})
        self.assertEqual(len(lines), 1)
        self.assertIn("--core pcsx_rearmed keeps 3.0 MB", lines[0])
        self.assertNotIn("ares", lines[0])
        self.assertEqual(install.bulk_hint(files, manifest, True, False,
                                           accepted={"duckstation"}), [])
        self.assertEqual(install.bulk_hint(files, manifest, True, False), [])

    def test_a_system_pulling_most_of_the_download_is_named(self):
        files = [_sized("a.zip", 400 * MB, ["arcade"]), _sized("b.bin", 50 * MB, ["nes"]),
                 _sized("c.bin", 10 * MB, ["gba"])]
        lines = install.bulk_hint(files, {}, systems_chosen=False, cores_chosen=False)
        self.assertEqual(len(lines), 1)
        self.assertIn("arcade pulls 400.0 MB of this 460.0 MB download", lines[0])
        self.assertIn("saves 400.0 MB (86%)", lines[0])

    def test_nothing_is_said_under_half(self):
        files = [_sized("a.zip", 100 * MB, ["arcade"]), _sized("b.bin", 100 * MB, ["nes"])]
        self.assertEqual(install.bulk_hint(files, {}, False, False), [])

    def test_nothing_is_said_for_a_small_download(self):
        files = [_sized("a.zip", 40 * MB, ["arcade"]), _sized("b.bin", 1 * MB, ["nes"])]
        self.assertEqual(install.bulk_hint(files, {}, False, False), [])

    def test_a_chosen_core_is_not_second_guessed(self):
        files = [_sized("opera.bin", 12 * MB, ["3do"]),
                 _sized("mame/3do.zip", 300 * MB, ["3do"], ["mame"])]
        self.assertEqual(install.bulk_hint(
            files, {"system_cores": {"3do": ["mame", "opera"]}}, True, True), [])

    def test_the_end_summary_prints_the_line(self):
        self.addCleanup(setattr, install.OUTPUT, "verbose", False)
        install.OUTPUT.verbose = True
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            install._report_outcome([Path("/x")], 3, 0, 0, 0, False,
                                    hints=["  arcade pulls most of it."])
        text = out.getvalue()
        self.assertIn("  arcade pulls most of it.", text)
        self.assertLess(text.index("Done."), text.index("arcade pulls"))


class OfflineMakesNoRequest(Scratch):
    """A handheld with no Wi-Fi ran --check against a loopback address to
    learn its platform, since nothing said "make no request"."""

    def _served(self, *options: str, env: dict | None = None):
        import test_install_selection  # noqa: PLC0415

        hits: list[str] = []
        with FakeRepository() as repo, unittest.mock.patch.object(
                test_install_selection._QuietHandler, "log_message",
                lambda handler, *args: hits.append(handler.path)):
            started = time.monotonic()
            proc = subprocess.run(
                repo.command(*options), env={**repo.env(), **(env or {})},
                capture_output=True, text=True, timeout=60, check=False,
                stdin=subprocess.DEVNULL)
            elapsed = time.monotonic() - started
            installed = repo.installed()
        return proc, hits, elapsed, installed

    def test_check_names_the_platform_and_stops_at_the_file_list(self):
        for options, env in (((("--offline",)), None),
                             ((), {"RETROBIOS_INSTALL_OFFLINE": "1"})):
            with self.subTest(options=options, env=env):
                proc, hits, elapsed, installed = self._served(
                    *options, "--check", "--events", env=env)
                self.assertEqual(hits, [])
                self.assertLess(elapsed, 30)
                self.assertEqual(proc.returncode, 1, proc.stderr)
                events = [json.loads(line) for line in proc.stdout.splitlines()]
                self.assertEqual([e["event"] for e in events],
                                 ["start", "detect", "error", "end"])
                self.assertEqual(events[1]["platforms"][0]["platform"], "retroarch")
                self.assertEqual((events[2]["stage"], events[2]["reason"]),
                                 ("manifest", "offline"))
                self.assertIn("no network request", events[2]["message"])
                self.assertIn("--manifest", proc.stderr)
                self.assertNotIn("attempts", proc.stderr)
                self.assertEqual(installed, [])

    def test_a_copy_lands_and_the_rest_fails_at_once(self):
        old = self.root / "old"
        old.mkdir()
        (old / "scph5501.bin").write_bytes(US)
        proc = self.run_installer("--offline", "--manifest", str(self.list),
                                  "--from", str(old), "--no-input")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual((self.dest / "scph5501.bin").read_bytes(), US)
        self.assertFalse((self.dest / "gba_bios.bin").exists())
        # Missing, never failed: no FAILED line per file.
        self.assertIn("3 still missing", proc.stdout + proc.stderr)
        self.assertNotIn("FAILED", proc.stdout + proc.stderr)
        self.assertIn("without --offline", proc.stdout + proc.stderr)
        self.assertNotIn("trying again", proc.stderr)

    def test_modes_that_need_the_network_refuse_it(self):
        for extra in (["--target", "switch"], ["--list-targets"]):
            with self.subTest(extra=extra):
                proc = self.run_installer("--offline", *extra)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn("--offline", proc.stderr)

    def test_a_listing_and_a_pack_need_no_network_anyway(self):
        # --platform alone with it is refused: the listing names every one.
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--offline", "--list-platforms"],
            env=_offline_env(), capture_output=True, text=True, timeout=120,
            check=False, stdin=subprocess.DEVNULL,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


class ANetworkThatDroppedFailsFast(unittest.TestCase):
    """A dropped network cost 93 s before the line-mode error: three tries
    of a 30-second timeout spent waiting for a connection that never opened."""

    def test_the_connection_is_bounded_and_the_read_is_not(self):
        calls: list[tuple] = []

        class Sock:
            def settimeout(self, value):
                calls.append(("read", value))

        def create(address, timeout, source_address=None):
            calls.append(("connect", timeout))
            return Sock()

        with unittest.mock.patch.object(install.socket, "create_connection", create):
            install._open_socket(("example.org", 443), 60)
            install._open_socket(("example.org", 443), 2)
        self.assertEqual(calls, [("connect", install.CONNECT_TIMEOUT), ("read", 60),
                                 ("connect", 2), ("read", 2)])

    def test_three_tries_that_never_connect_end_within_fifteen_seconds(self):
        waited = sum(install._retry_delay(n, None) for n in range(1, install.MAX_RETRIES))
        self.assertLessEqual(install.MAX_RETRIES * install.CONNECT_TIMEOUT + waited, 15)

    def test_a_slow_answer_on_an_open_connection_still_arrives(self):
        import http.server  # noqa: PLC0415
        import threading  # noqa: PLC0415

        delay = install.CONNECT_TIMEOUT + 1

        class Slow(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib name
                time.sleep(delay)
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Slow)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        install.install_bounded_opener()
        self.addCleanup(install.urllib.request.install_opener, None)
        url = f"http://127.0.0.1:{server.server_address[1]}/list.json"
        started = time.monotonic()
        self.assertEqual(install._fetch_json(url, 1024, "file list", attempts=1), {"ok": True})
        self.assertGreaterEqual(time.monotonic() - started, delay - 0.5)


class ADryRunOpensOnItsTotals(Scratch):
    """A full --dry-run printed 599 lines, the total scrolled away above
    eight file names for each of 66 systems."""

    def setUp(self):
        super().setUp()
        files = [
            {"dest": f"sys{n:02d}/file{k}.bin", "sha1": _sha1(b"%d-%d" % (n, k)),
             "size": 1000 * (n + 1), "repo_path": f"bios/sys{n:02d}_{k}", "cores": None,
             "systems": [f"system-{n:02d}"]}
            for n in range(40) for k in range(3)
        ]
        self.list.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                         "files": files}))

    def _plan(self, *options: str) -> list[str]:
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", str(self.dest), "--manifest", str(self.list), "--dry-run",
             "--no-input", *options],
            env={**_offline_env(), "LINES": "24", "COLUMNS": "80"},
            capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        lines = proc.stdout.splitlines()
        return lines[next(i for i, line in enumerate(lines)
                          if line.startswith("Would download")):]

    def test_the_total_comes_first_and_the_largest_systems_after(self):
        plan = self._plan()
        self.assertTrue(plan[0].startswith("Would download 120 files"), plan[0])
        self.assertLessEqual(len(plan), 24, "\n".join(plan))
        self.assertIn("system-39", plan[2])
        self.assertTrue(any("30 more systems" in line and "--verbose" in line
                            for line in plan), "\n".join(plan))
        self.assertFalse(any("file0.bin" in line for line in plan))
        self.assertEqual(plan[-1].strip(), "Nothing was written. Run without --dry-run to install.")

    def test_verbose_lists_every_system_and_its_files(self):
        plan = self._plan("--verbose")
        self.assertTrue(plan[0].startswith("Would download 120 files"), plan[0])
        for n in range(40):
            self.assertTrue(any(line.strip().startswith(f"system-{n:02d}") for line in plan), n)
        self.assertTrue(any("sys00/file0.bin" in line for line in plan))



class OfflineLeavesFilesMissing(Scratch):
    """The files --offline leaves out at a
    terminal were counted with a "no" to the size question. Once one file
    came from this machine, 14,696 missing ended on Done and exit 0."""

    def outcome(self, **counts) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as stop:
            install._report_outcome([self.dest], counts.get("installed", 0), 0,
                                    counts.get("errors", 0), 0, False,
                                    sources=counts.get("sources", ""),
                                    offline=counts["offline"])
        return stop.exception.code, out.getvalue()

    def test_some_installed_is_not_done(self):
        code, text = self.outcome(installed=4, offline=14696,
                                  sources="4 files copied from old, 14696 still missing.")
        self.assertEqual(code, 1)
        self.assertNotIn("Done", text)
        # One count, the sources line as the head, as the screen's result.
        self.assertIn("Finished with files missing. 4 files copied from old, 14696 still "
                      "missing.", text)
        self.assertEqual(text.count("14696"), 1)

    def test_nothing_installed_is_code_2(self):
        code, text = self.outcome(offline=14700)
        self.assertEqual(code, 2)
        self.assertIn("Nothing installed: 14700 files need the internet, which --offline "
                      "does not use.", text)
        # Nothing was up to date: the line said "0 files already up to date".
        self.assertNotIn("up to date", text)

    def test_the_folder_given_is_not_suggested_again(self):
        old = self.root / "old"
        old.mkdir()
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        install.LOCAL.folders = [install.FolderIndex(old)]
        _code, text = self.outcome(offline=3)
        self.assertIn(f"They are not in {old}", text)
        self.assertNotIn("(--from)", text)

    def test_a_dry_run_offline_says_no_download(self):
        proc = self.run_installer("--offline", "--dry-run", "--manifest", str(self.list))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("Would download", proc.stdout)
        self.assertIn("4 files (", proc.stdout)
        self.assertIn("need the internet, which --offline does not use. Run without "
                      "--offline, and they would go to", proc.stdout)

    def test_an_archive_not_read_is_only_its_error(self):
        listed = manifest()
        listed["data_directories"] = [{
            "ref": "bluemsx", "dest": "Machines", "type": "zip",
            "url": "https://example.invalid/blueMSX.zip", "systems": ["nintendo-gba"],
            "files": {"a.txt": {"sha1": _sha1(b"a"), "size": 1}},
        }]
        self.list.write_text(json.dumps(listed))
        self.complete()
        proc = self.run_installer("--offline", "--manifest", str(self.list), "--no-input",
                                  "--verbose")
        # Its files are missing, as the BIOS files --offline leaves out are,
        # with or without questions.
        self.assertIn("bluemsx: 0 already in place, 1 needs the internet (--offline)",
                      proc.stdout)
        self.assertNotIn("could not read", proc.stderr)
        self.assertNotIn("no longer in the source", proc.stdout)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a read-only folder is refused by POSIX permissions")
    def test_a_tree_in_a_folder_not_writable_is_not_fetched(self):
        """A read-only card blamed each data archive's URL with a raw
        errno, and that second cause split the one-line summary."""
        listed = manifest()
        listed["data_directories"] = [{
            "ref": "bluemsx", "dest": "Machines", "type": "zip",
            "url": "https://example.invalid/blueMSX.zip", "systems": ["nintendo-gba"],
            "files": {"a.txt": {"sha1": _sha1(b"a"), "size": 1}},
        }, {
            "ref": "fbneo-cheats", "dest": "fbneo/cheats", "type": "zip",
            "url": "https://example.invalid/cheats.zip", "systems": ["nintendo-gba"],
            "files": {"b.txt": {"sha1": _sha1(b"b"), "size": 1}},
        }]
        self.list.write_text(json.dumps(listed))
        self.complete()
        self.dest.chmod(0o555)
        self.addCleanup(self.dest.chmod, 0o755)
        proc = self.run_installer("--manifest", str(self.list), "--no-input")
        out = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 2, out)
        self.assertNotIn("could not read", out)
        self.assertNotIn("Errno", out)
        self.assertNotIn("Data directories:", out)
        self.assertIn("failed: 2 files (folder not writable), first bluemsx", out)


class OneOfflineVocabulary(Scratch):
    """--offline said one
    thing at a terminal and another without questions, on the screen and
    under --check."""

    def old(self) -> Path:
        old = self.root / "old"
        old.mkdir()
        (old / "scph5501.bin").write_bytes(US)
        return old

    def test_a_run_without_questions_says_missing_not_failed(self):
        """"Finished with errors ... 3 files failed" and "Run the
        same command again to retry only those"."""
        proc = self.run_installer("--offline", "--manifest", str(self.list),
                                  "--from", str(self.old()), "--no-input")
        out = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 1, out)
        self.assertIn(f"Finished with files missing. 1 file copied from {self.root / 'old'}, "
                      "3 still missing.", out)
        self.assertIn(f"They are not in {self.root / 'old'}", out)
        for said in ("Finished with errors", "files failed", "retry",
                     "copy them from your old card"):
            self.assertNotIn(said, out)

    def test_nothing_installed_is_said_so(self):
        """"Finished with files missing. 0 files installed"."""
        failures = [("a.bin", install.NOT_WRITABLE), ("b.bin", install.NOT_WRITABLE)]
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit) as stop:
            install._report_outcome([self.dest], 0, 0, 2, 0, False, failures=failures,
                                    offline=20)
        self.assertEqual(stop.exception.code, 2)
        self.assertIn("Nothing installed: 20 files not fetched (--offline), 2 failed.",
                      out.getvalue())
        self.assertNotIn("0 files installed", out.getvalue())

    def test_the_command_suggested_keeps_the_offline_setting(self):
        """Sudo does not pass RETROBIOS_INSTALL_OFFLINE on."""
        import test_install_tui as tui

        args = tui._args(platform="retroarch", declared_only=False, offline=False)
        hint = install.Invocation()
        with unittest.mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            hint.record(args)
        self.assertIn("--offline", hint.command("retroarch", self.dest, elevated=True))

    def test_check_offline_says_what_cannot_come(self):
        """"Run the same command without --check to fetch them"."""
        proc = self.run_installer("--check", "--offline", "--manifest", str(self.list))
        out = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 3, out)
        self.assertNotIn("to fetch them", out)
        self.assertIn("4 files need the internet, which --offline does not use.", out)
        self.assertIn("Copy them from an old card or a folder (--from)", out)

    def test_the_screen_says_missing_not_failed(self):
        """On the full screen: "Finished with errors, 20 failed"."""
        import test_install_tui as tui

        reason = f"not fetched: {install.OFFLINE_WORDS}"
        state = tui._installed_state(self.dest, 1, [{"dest": f"f{n}.bin", "reason": reason}
                                                    for n in range(20)])
        state.summary["installed"] = 2
        state.from_folders = [self.root / "from1"]
        title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Finished with files missing")
        text = " ".join(lines)
        self.assertIn("2 installed, 20 not fetched (--offline).", text)
        self.assertIn("They are not in", text)
        self.assertNotIn("failed", text)
        state.summary["installed"] = 0
        self.assertEqual(install.tui_outcome(state)[0], "Nothing installed")

    def test_the_line_menu_copies_from_a_folder(self):
        """No way to a folder, and an install of nothing
        offered."""
        old = self.old()
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        answers = iter(["f", str(old), ""])
        with unittest.mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                unittest.mock.patch.object(install, "_ask", lambda _prompt: next(answers)), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertIsNone(install._prompt_custom_selection("retroarch", [], []))
        text = out.getvalue()
        self.assertIn("Enter) check the BIOS folder, nothing can be downloaded", text)
        self.assertIn("f) copy from a folder or an old card", text)
        self.assertIn(f"Enter) install what is found in {old}", text)
        self.assertEqual([index.label for index in install.LOCAL.folders], [str(old)])
        self.assertNotIn("install everything", text)


class OfflineAndPackLeaveOut(Scratch):
    """What --offline and a
    pack leave out, and what a folder copied from holds, said as such."""

    def test_yes_offline_counts_the_rest_missing_never_failed(self):
        """The screen's own install (--yes): each file left out was
        "downloading", then FAILED, and pending and failed at once."""
        old = self.root / "old"
        old.mkdir()
        (old / "scph5501.bin").write_bytes(US)
        proc = self.run_installer("--offline", "--manifest", str(self.list), "--from",
                                  str(old), "--yes", "--events")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        summary = next(event for event in events if event["event"] == "summary")
        self.assertEqual((summary["installed"], summary["pending"], summary["failed"]),
                         (1, 3, []))
        self.assertNotIn("FAILED", proc.stderr)
        self.assertNotIn("downloading", proc.stderr)
        self.assertIn(f"1 file copied from {old}, 3 still missing", proc.stderr)
        download = next(event for event in events if event["event"] == "download")
        self.assertEqual(download["files"], 1)
        # The screen reads that summary as missing files, not failures.
        state = install.TuiState()
        state.summary = summary
        with unittest.mock.patch.dict(os.environ,
                                      {install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE}):
            title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Finished with files missing")
        self.assertIn("1 installed, 3 not fetched (--offline).", lines[0])

    def test_a_pack_is_copied_not_downloaded(self):
        downloads = self.root / "downloads"
        downloads.mkdir()
        pack = _pack(downloads, "RetroArch_v1_BIOS_Pack.zip", PAYLOAD)
        proc = self.run_installer("--from-pack", str(pack), "--dry-run", "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Would copy 4 files", proc.stdout)
        self.assertIn("from the pack to", proc.stdout)
        self.assertNotIn("download", proc.stdout.lower())

    def test_a_folder_holding_none_of_the_files_is_said_and_left(self):
        empty = self.root / "empty"
        (empty / "photos").mkdir(parents=True)
        (empty / "photos" / "a.jpg").write_bytes(b"jpeg")
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        files = manifest()["files"]
        answers = iter(["f", f"{self.root}/x/../empty", "q"])
        with unittest.mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                unittest.mock.patch.object(install, "_ask", lambda _prompt: next(answers)), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._prompt_custom_selection("retroarch", files, [], bios_path=self.dest)
        text = out.getvalue()
        self.assertIn("empty holds none of these files.", text)
        self.assertNotIn("install what is found", text)
        self.assertNotIn("..", text)
        self.assertEqual(install.LOCAL.folders, [])
        # One that holds some is counted.
        (empty / "scph5501.bin").write_bytes(US)
        answers = iter(["f", str(empty), "q"])
        with unittest.mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                unittest.mock.patch.object(install, "_ask", lambda _prompt: next(answers)), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._prompt_custom_selection("retroarch", files, [], bios_path=self.dest)
        self.assertIn("1 of 4 found in empty.", out.getvalue())
        self.assertIn("Enter) install what is found in", out.getvalue())


if __name__ == "__main__":
    unittest.main()
