"""One content, several identities: which crossings are a misfiling."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import identity  # noqa: E402


class TestCrossVendorDuplicates(unittest.TestCase):
    """A dump answering to two makers is a finding until it is explained."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="identity-"))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _write(self, relative: str, payload: bytes) -> None:
        path = self.root / "bios" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def _scan(self):
        return identity.scan(str(self.root / "bios"))

    def test_one_dump_under_two_makers_is_reported(self):
        self._write("Commodore/Amiga/kickstart.rom", b"kick")
        self._write("Sega/Saturn/cartridge.bin", b"kick")
        found = self._scan()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].manufacturers, ["Commodore", "Sega"])
        self.assertEqual(found[0].names, ["cartridge.bin", "kickstart.rom"])

    def test_two_copies_under_one_maker_are_not_a_finding(self):
        self._write("Sinclair/ZX Spectrum/48.rom", b"rom")
        self._write("Sinclair/ZX Spectrum/spectrum48.rom", b"rom")
        self.assertEqual(self._scan(), [])

    def test_the_same_name_twice_is_a_copy_not_a_contradiction(self):
        self._write("Coleco/ColecoVision/coleco.rom", b"rom")
        self._write("Microsoft/MSX/coleco.rom", b"rom")
        self.assertEqual(self._scan(), [])

    def test_shared_trees_do_not_count_as_a_maker(self):
        # Arcade and Other hold files belonging to many machines by design.
        self._write("Arcade/FBNeo/spectrum.rom", b"rom")
        self._write("Sinclair/ZX Spectrum/48.rom", b"rom")
        self.assertEqual(self._scan(), [])

    def test_an_explained_crossing_is_silent(self):
        self._write("Magnavox/Odyssey2/o2rom.bin", b"odyssey")
        self._write("Philips/Videopac/O2.bin", b"odyssey")
        first = self._scan()
        self.assertEqual(len(first), 1)
        identity.KNOWN_SHARED[first[0].sha1] = (
            frozenset({"Magnavox", "Philips"}), "one machine, two market names"
        )
        try:
            self.assertEqual(self._scan(), [])
        finally:
            del identity.KNOWN_SHARED[first[0].sha1]

    def test_an_exemption_does_not_cover_a_third_maker(self):
        # The four Roland ROMs were exempt by content alone, under a reason
        # naming a DOSBox tree, but the second copies sat in the Amiga tree and
        # nothing could tell.
        self._write("Magnavox/Odyssey2/o2rom.bin", b"odyssey")
        self._write("Philips/Videopac/O2.bin", b"odyssey")
        self._write("Commodore/Amiga/odyssey.bin", b"odyssey")
        sha1 = self._scan()[0].sha1
        identity.KNOWN_SHARED[sha1] = (
            frozenset({"Magnavox", "Philips"}), "one machine, two market names"
        )
        try:
            found = self._scan()
            self.assertEqual(len(found), 1)
            self.assertEqual(
                found[0].manufacturers, ["Commodore", "Magnavox", "Philips"]
            )
        finally:
            del identity.KNOWN_SHARED[sha1]

    def test_distinct_contents_are_never_grouped(self):
        self._write("Commodore/Amiga/kickstart.rom", b"kick")
        self._write("Sega/Saturn/cartridge.bin", b"other")
        self.assertEqual(self._scan(), [])

    def test_a_file_whose_size_no_other_shares_is_never_read(self):
        """Hashing the whole tree read 18 GB on every pipeline run."""
        from unittest import mock

        self._write("Commodore/Amiga/kickstart.rom", b"kick")
        self._write("Sega/Saturn/cartridge.bin", b"kick")
        self._write("Sony/PlayStation/scph5501.bin", b"a longer dump")
        self._write("Sega/Saturn/other.bin", b"same")
        with mock.patch.object(identity, "_sha1", wraps=identity._sha1) as hashed:
            found = self._scan()
        read = sorted(Path(call.args[0]).name for call in hashed.call_args_list)
        self.assertEqual(read, ["cartridge.bin", "kickstart.rom", "other.bin"])
        self.assertEqual(len(found), 1)

    def test_report_line_names_every_identity(self):
        self._write("Commodore/Amiga/kickstart.rom", b"kick")
        self._write("Sega/Saturn/cartridge.bin", b"kick")
        line = identity.format_duplicate(self._scan()[0])
        self.assertIn("kickstart.rom", line)
        self.assertIn("cartridge.bin", line)


class TestAllowList(unittest.TestCase):
    """Every exemption carries the reason it is one."""

    def test_each_entry_is_a_full_sha1_with_a_reason(self):
        for sha1, (makers, reason) in identity.KNOWN_SHARED.items():
            self.assertEqual(len(sha1), 40, sha1)
            self.assertTrue(all(c in "0123456789abcdef" for c in sha1), sha1)
            self.assertGreaterEqual(len(makers), 2, sha1)
            self.assertGreater(len(reason), 20, sha1)

    def test_every_exemption_is_still_needed(self):
        # An entry whose copies no longer cross its makers exempts nothing
        # today and would silently cover the next misfiling.
        repo = Path(__file__).resolve().parents[1] / "bios"
        if not repo.is_dir():
            self.skipTest("bios/ not present")
        saved = dict(identity.KNOWN_SHARED)
        identity.KNOWN_SHARED.clear()
        try:
            crossing = {d.sha1 for d in identity.scan(str(repo))}
        finally:
            identity.KNOWN_SHARED.update(saved)
        self.assertEqual(sorted(set(saved) - crossing), [])

    def test_the_repository_has_no_unexplained_crossing(self):
        repo = Path(__file__).resolve().parents[1] / "bios"
        if not repo.is_dir():
            self.skipTest("bios/ not present")
        found = identity.scan(str(repo))
        self.assertEqual(
            [identity.format_duplicate(d) for d in found],
            [],
            "explain the crossing in KNOWN_SHARED, or the file is misfiled",
        )


if __name__ == "__main__":
    unittest.main()
