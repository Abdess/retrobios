"""A pack too large for one release asset is published as ZIPs, not slices.

GitHub refuses a release file of 2 GiB or more, and seven packs are larger.
They used to be cut with split(1) into `.zip.001`, `.zip.002`: byte ranges
of one archive, each under a name that still said zip and each behind its
own download link. A range opened alone is not an archive, and no tool says
that a part is missing: 7-Zip answers "Unavailable start of archive",
PowerShell "not a supported archive file format", Windows has no handler
for `.002`. Five reports in six months took a part for a broken download.

Each part is now an archive of whole files. Any tool opens it, and the
parts extracted into one folder are the pack.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_pack as builder  # noqa: E402
from artifacts import artifact_lock  # noqa: E402
import split_pack  # noqa: E402

LIMIT = 4096


def _payload(seed: int, size: int) -> bytes:
    """Bytes deflate cannot shrink, so a member weighs what it says."""
    return bytes((seed * 131 + n * 7919 + (n * n) % 251) % 256 for n in range(size))


class SplitFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dist = Path(self._tmp.name)
        self.pack = self.dist / "Demo_1.0_BIOS_Pack.zip"
        self.members = {
            f"system/dir{n % 3}/file{n:02d}.bin": _payload(n, 900) for n in range(12)
        }
        self.members["README.txt"] = b"read me\n"
        self._build(self.pack, self.members)

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def _build(path: Path, members: dict[str, bytes]) -> None:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100000 | 0o644) << 16
                archive.writestr(info, data)

    def _read(self, parts: list[Path]) -> dict[str, bytes]:
        found: dict[str, bytes] = {}
        for part in parts:
            with zipfile.ZipFile(part) as archive:
                self.assertIsNone(archive.testzip())
                for name in archive.namelist():
                    if split_pack.is_marker(name):
                        continue
                    self.assertNotIn(name, found, "a file sits in two parts")
                    found[name] = archive.read(name)
        return found


class PartsAreArchives(SplitFixture):
    def test_a_pack_under_the_limit_stays_one_file(self):
        parts = split_pack.split_pack(self.pack, limit=1 << 20)
        self.assertEqual(parts, [self.pack])
        self.assertTrue(self.pack.is_file())

    def test_the_parts_extracted_together_are_the_pack(self):
        parts = split_pack.split_pack(self.pack, limit=LIMIT)
        self.assertGreater(len(parts), 1)
        self.assertEqual(self._read(parts), self.members)

    def test_every_part_fits_the_asset_limit(self):
        for part in split_pack.split_pack(self.pack, limit=LIMIT):
            self.assertLess(part.stat().st_size, LIMIT)

    def test_a_part_name_says_how_many_there_are(self):
        parts = split_pack.split_pack(self.pack, limit=LIMIT)
        count = len(parts)
        self.assertEqual(
            [part.name for part in parts],
            [
                f"Demo_1.0_BIOS_Pack.part{index}of{count}.zip"
                for index in range(1, count + 1)
            ],
        )

    def test_the_whole_archive_leaves_once_its_parts_are_checked(self):
        split_pack.split_pack(self.pack, limit=LIMIT)
        self.assertFalse(self.pack.exists())

    def test_the_same_pack_gives_the_same_parts(self):
        first = [p.read_bytes() for p in split_pack.split_pack(self.pack, limit=LIMIT)]
        other = self.dist / "again"
        other.mkdir()
        again = other / self.pack.name
        self._build(again, self.members)
        second = [p.read_bytes() for p in split_pack.split_pack(again, limit=LIMIT)]
        self.assertEqual(first, second)

    def test_a_file_no_part_can_hold_is_refused(self):
        big = self.dist / "Big_BIOS_Pack.zip"
        self._build(big, {"huge.bin": _payload(1, LIMIT * 2), "small.bin": b"x"})
        with self.assertRaises(ValueError):
            split_pack.split_pack(big, limit=LIMIT)
        self.assertTrue(big.is_file(), "the pack is kept when it cannot be split")
        self.assertEqual(sorted(p.name for p in self.dist.glob("Big*")), [big.name])

    def test_the_executable_bit_travels(self):
        tool = self.dist / "Tools_BIOS_Pack.zip"
        with zipfile.ZipFile(tool, "w", zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo("bin/engine", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100000 | 0o755) << 16
            archive.writestr(info, _payload(3, 3000))
            for n in range(4):
                archive.writestr(f"data{n}.bin", _payload(n, 900))
        parts = split_pack.split_pack(tool, limit=LIMIT)
        modes = {}
        for part in parts:
            with zipfile.ZipFile(part) as archive:
                for info in archive.infolist():
                    modes[info.filename] = info.external_attr >> 16
        self.assertTrue(modes["bin/engine"] & stat.S_IXUSR)


class EachPartNamesItsSiblings(SplitFixture):
    """A part extracted alone looked like a complete pack. Each part now
    carries a marker naming the pack, its number and every part with its
    size, so a missing one can be named from the extracted folder."""

    def _markers(self, parts: list[Path]) -> dict[str, str]:
        found = {}
        for part in parts:
            with zipfile.ZipFile(part) as archive:
                names = [n for n in archive.namelist() if split_pack.is_marker(n)]
                self.assertEqual(len(names), 1, part.name)
                found[part.name] = archive.read(names[0]).decode("utf-8")
        return found

    def test_every_part_carries_one_marker(self):
        parts = split_pack.split_pack(self.pack, limit=LIMIT)
        count = len(parts)
        for index, part in enumerate(parts, 1):
            with zipfile.ZipFile(part) as archive:
                self.assertIn(f"Demo_1.0_BIOS_Pack.part{index}of{count}.txt",
                              archive.namelist())

    def test_the_marker_names_the_pack_the_part_and_every_size(self):
        parts = split_pack.split_pack(self.pack, limit=LIMIT)
        count = len(parts)
        for index, (name, text) in enumerate(self._markers(parts).items(), 1):
            with self.subTest(part=name):
                lines = text.splitlines()
                self.assertIn("pack: Demo_1.0_BIOS_Pack.zip", lines)
                self.assertIn(f"part: {index} of {count}", lines)
                listed = [line.split()[1:] for line in lines if line.startswith("file:")]
                self.assertEqual(
                    listed,
                    [[str(p.stat().st_size), p.name] for p in parts],
                )

    def test_the_parts_still_fit_with_their_markers(self):
        for part in split_pack.split_pack(self.pack, limit=LIMIT):
            self.assertLess(part.stat().st_size, LIMIT)

    def test_a_pack_holding_a_marker_name_is_refused(self):
        members = dict(self.members)
        members["Demo_1.0_BIOS_Pack.part1of2.txt"] = b"x"
        self.pack.unlink()
        self._build(self.pack, members)
        with self.assertRaises(ValueError):
            split_pack.split_pack(self.pack, limit=LIMIT)
        self.assertTrue(self.pack.is_file())

    def test_a_marker_is_not_a_part(self):
        self.assertTrue(split_pack.is_marker("Demo_BIOS_Pack.part2of3.txt"))
        self.assertFalse(split_pack.is_part("Demo_BIOS_Pack.part2of3.txt"))
        self.assertFalse(split_pack.is_marker("Demo_BIOS_Pack.part2of3.zip"))


class SplitHoldsTheDirectory(SplitFixture):
    """split_pack read and deleted packs in a directory a build was writing:
    the build could truncate the pack under the split, or the split delete
    the pack the build had just written."""

    def test_a_held_directory_is_left_alone(self):
        for target in (self.dist, self.pack):
            with self.subTest(target=target.name), artifact_lock(str(self.dist)):
                proc = subprocess.run(
                    [sys.executable, "scripts/split_pack.py", str(target),
                     "--max-size", str(LIMIT)],
                    cwd=str(REPO_ROOT), capture_output=True, text=True,
                    timeout=60, check=False,
                )
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("in use by another run", proc.stderr)
                self.assertTrue(self.pack.exists())
                self.assertEqual(
                    sorted(p.name for p in self.dist.glob("*.zip")), [self.pack.name]
                )


class PartsAreNotTakenForPacks(SplitFixture):
    def test_a_part_is_recognised_by_its_name(self):
        self.assertTrue(split_pack.is_part("RetroArch_BIOS_Pack.part1of2.zip"))
        self.assertFalse(split_pack.is_part("RetroArch_BIOS_Pack.zip"))
        self.assertFalse(split_pack.is_part("RetroArch_BIOS_Pack.zip.001"))

    def test_pack_verification_skips_the_parts(self):
        """A part holds half a platform by design: judged as a pack it fails."""
        parts = split_pack.split_pack(self.pack, limit=LIMIT)
        self.assertEqual(
            builder._pack_archives(str(self.dist)), [],
            [p.name for p in parts],
        )

    def test_launcher_archives_are_not_packs(self):
        """build_port.py writes RetroBIOS.zip, RetroBIOS-tools.zip and
        RetroBIOS-batocera.zip to dist/: verify_and_finalize_packs judged
        them as packs, failed them and injected a manifest into each."""
        for name in ("RetroBIOS.zip", "RetroBIOS-tools.zip", "RetroBIOS-batocera.zip"):
            self._build(self.dist / name, {"RetroBIOS.sh": b"#!/bin/sh\n"})
        before = {p.name: p.read_bytes() for p in self.dist.glob("RetroBIOS*.zip")}
        self.assertEqual(builder._pack_archives(str(self.dist)), [self.pack.name])
        # A --system platform pack carries its system after the suffix.
        system = self.dist / "Demo_1.0_BIOS_Pack_Playstation.zip"
        self._build(system, {"one.bin": b"1"})
        self.assertEqual(builder._pack_archives(str(self.dist)),
                         sorted([self.pack.name, system.name]))
        system.unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            builder.verify_and_finalize_packs(str(self.dist), {"files": {}, "indexes": {}},
                                              skip_conformance=True)
        self.assertEqual({p.name: p.read_bytes() for p in self.dist.glob("RetroBIOS*.zip")},
                         before)

    def test_the_directory_form_splits_only_what_is_too_large(self):
        small = self.dist / "Small_BIOS_Pack.zip"
        self._build(small, {"one.bin": b"1"})
        written = split_pack.split_directory(self.dist, limit=LIMIT)
        names = sorted(path.name for path in written)
        self.assertIn("Small_BIOS_Pack.zip", names)
        self.assertNotIn("Demo_1.0_BIOS_Pack.zip", names)
        self.assertTrue(all(os.path.exists(path) for path in written))


class ReleaseProcessPublishesArchives(unittest.TestCase):
    def setUp(self):
        self.text = (REPO_ROOT / "wiki" / "release-process.md").read_text(
            encoding="utf-8"
        )

    def test_it_no_longer_cuts_byte_ranges(self):
        # assertIn would print the whole page on failure.
        self.assertFalse("split --bytes" in self.text)
        self.assertTrue("scripts/split_pack.py" in self.text)

    def test_the_checksums_are_those_of_the_published_files(self):
        self.assertLess(
            self.text.index("scripts/split_pack.py"),
            self.text.index("sha256sum *_BIOS_Pack*.zip"),
        )


class PartsAreExplainedWhereTheyAreDownloaded(unittest.TestCase):
    # getting-started.md now only links the pages that took its content: the
    # downloads are explained on Get your files, which generate_site.py writes.
    PAGES = (
        "scripts/generate_readme.py",
        "scripts/generate_site.py",
        "wiki/troubleshooting.md",
    )

    def _text(self, relative: str) -> str:
        return (REPO_ROOT / relative).read_text(encoding="utf-8")

    def test_every_page_names_the_parts(self):
        """Slices left the pages with the last release that used them
        (test_doc_surfaces.SlicesLeaveWithTheirRelease)."""
        for page in self.PAGES:
            with self.subTest(page=page):
                self.assertIn(".part1of2.zip", self._text(page))

    def test_the_windows_join_command_runs_from_powershell(self):
        """`copy /b A+B C` is a cmd builtin. Typed into PowerShell, the shell
        the install instructions open, it is Copy-Item and fails."""
        for page in self.PAGES:
            with self.subTest(page=page):
                for line in self._text(page).splitlines():
                    if "copy /b" in line:
                        self.assertTrue("cmd /c copy /b" in line, line.strip())


if __name__ == "__main__":
    unittest.main()
