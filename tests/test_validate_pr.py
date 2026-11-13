#!/usr/bin/env python3
"""The gate that inspects contributor files before a PR is reviewed.

validate.yml runs this on every added or modified file under bios/, and its
output is posted to the PR. It reads paths chosen by whoever opened the PR, so
it is an untrusted-input boundary with nothing behind it.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import validate_pr  # noqa: E402

EMPTY_HASHES: dict = {"sha1": set(), "md5": set(), "names": set()}


class _Fixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _bios_file(self, relative: str, data: bytes = b"BIOS") -> str:
        path = self.tmp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return relative


class FileShapeChecks(_Fixture):
    def test_missing_file_fails_without_hashing(self):
        result = validate_pr.validate_file("bios/nope.bin", None, EMPTY_HASHES)
        self.assertFalse(result.passed)
        self.assertEqual(result.sha1, "")

    def test_a_path_never_read_shows_no_digest(self):
        """Empty Size, SHA1, MD5 and CRC32 lines read as an empty file contributed."""
        result = validate_pr.validate_file("bios/nope.bin", None, EMPTY_HASHES)
        markdown = result.to_markdown()
        for label in ("**Size**", "**SHA1**", "**MD5**", "**CRC32**"):
            self.assertNotIn(label, markdown)
        self.assertIn("--changed", markdown)

    def test_a_folder_is_read_file_by_file(self):
        self._bios_file("card/bios/a.bin")
        self._bios_file("card/bios/sub/b.bin")
        (self.tmp / "empty").mkdir()
        self.assertEqual(
            validate_pr.expand_folders(["card", "empty", "loose.bin"]),
            [str(Path("card/bios/a.bin")), str(Path("card/bios/sub/b.bin")), "empty", "loose.bin"],
        )
        result = validate_pr.validate_file("empty", None, EMPTY_HASHES)
        self.assertIn("Folder with no file in it", result.to_markdown())

    def test_empty_file_fails(self):
        rel = self._bios_file("bios/Sony/PS/empty.bin", b"")
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        self.assertFalse(result.passed)
        self.assertIn("empty", result.to_markdown().lower())

    def test_executable_extension_is_refused(self):
        rel = self._bios_file("bios/Sony/PS/payload.exe")
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        self.assertFalse(result.passed)
        self.assertIn("Blocked file extension", result.to_markdown())

    def test_an_executable_a_profile_pins_by_sha1_passes(self):
        """PICO-8's pico8.exe and SDL2.dll come from the official archive and
        the lexaloffle profile pins their sha1: known bytes, not a payload."""
        import hashlib
        data = b"MZ pinned"
        rel = self._bios_file("bios/Lexaloffle/PICO-8/pico8.exe", data)
        pins = {"sha1": {hashlib.sha1(data).hexdigest(): {"lexaloffle"}}}
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES, pins)
        self.assertNotIn("Blocked file extension", result.to_markdown())
        self.assertIn("pins by sha1: lexaloffle", result.to_markdown())

    def test_an_executable_known_only_by_md5_stays_refused(self):
        import hashlib
        data = b"MZ weak"
        rel = self._bios_file("bios/Sony/PS/tool.exe", data)
        pins = {"md5": {hashlib.md5(data).hexdigest(): {"someemu"}}}
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES, pins)
        self.assertFalse(result.passed)
        self.assertIn("Blocked file extension", result.to_markdown())

    def test_oversized_file_is_refused(self):
        rel = self._bios_file("bios/Sony/PS/big.bin")
        original = validate_pr.MAX_FILE_SIZE
        validate_pr.MAX_FILE_SIZE = 2
        try:
            result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        finally:
            validate_pr.MAX_FILE_SIZE = original
        self.assertFalse(result.passed)
        self.assertIn("too large", result.to_markdown())

    def test_ordinary_file_passes(self):
        rel = self._bios_file("bios/Sony/PlayStation/scph.bin")
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        self.assertTrue(result.passed, result.to_markdown())
        self.assertEqual(len(result.sha1), 40)


class AFileOnlyACoreReadsIsKnown(_Fixture):
    """A file only an emulator profile declares (a standalone firmware, a
    game engine's data) was reported "not referenced in any platform
    config - needs manual review"."""

    def test_the_profiles_that_declare_the_hash_are_named(self):
        import hashlib  # noqa: PLC0415

        emulators = self.tmp / "emulators"
        emulators.mkdir()
        data = b"engine data"
        (emulators / "engine.yml").write_text(
            "emulator: Engine\ntype: standalone\nsystems: [x]\nfiles:\n"
            f"  - name: \"data.bin\"\n    sha1: \"{hashlib.sha1(data).hexdigest()}\"\n"
        )
        known = validate_pr.load_profile_hashes(str(emulators))
        result = validate_pr.validate_file(
            self._bios_file("bios/Maker/Engine/data.bin", data), None, EMPTY_HASHES, known,
        )
        self.assertIn(("PASS", "Hash matches a file the emulator profile declares: engine"),
                      result.checks)
        self.assertFalse(any("not referenced" in message for _s, message in result.checks))

    def test_a_missing_file_is_told_the_folder_of_its_system(self):
        """The folder came from platform lists only: a file only a profile
        declares, absent from the collection, got the generic advice."""
        import hashlib  # noqa: PLC0415

        held, missing = b"held rom", b"missing rom"
        emulators = self.tmp / "emulators"
        emulators.mkdir()
        (emulators / "engine.yml").write_text(
            "emulator: Engine\ntype: standalone\nsystems: [x, y]\nfiles:\n"
            f"  - name: \"a.bin\"\n    system: x\n    sha1: \"{hashlib.sha1(held).hexdigest()}\"\n"
            f"  - name: \"b.bin\"\n    system: x\n    md5: \"{hashlib.md5(missing).hexdigest()}\"\n"
        )
        db = {"files": {hashlib.sha1(held).hexdigest(): {"path": "bios/Maker/Console/a.bin"}},
              "indexes": {"by_md5": {}, "by_sha256": {}}}
        known = validate_pr.load_profile_hashes(str(emulators), db)
        result = validate_pr.validate_file(
            self._bios_file("Downloads/b.bin", missing), db, EMPTY_HASHES, known,
        )
        self.assertIn(
            ("WARN", "File is not under bios/ yet. Its system's files are in "
                     "`bios/Maker/Console/`. --place copies it to `bios/Maker/Console/b.bin`"),
            result.checks,
        )
        self.assertEqual(result.destination, "bios/Maker/Console/b.bin")
        # A file of that name already there: the copy is a variant.
        self._bios_file("bios/Maker/Console/b.bin", b"another")
        self.assertEqual(
            validate_pr.validate_file("Downloads/b.bin", db, EMPTY_HASHES, known).destination,
            f"bios/Maker/Console/.variants/b.bin.{result.sha1[:8]}",
        )
        # Copied under the declared name, never over a file, and only once.
        card = self._bios_file("card/B.BIN", missing)
        named = validate_pr.validate_file(card, db, EMPTY_HASHES, known)
        self.assertEqual(validate_pr.place([named]), [named.destination])
        self.assertEqual((self.tmp / named.destination).read_bytes(), missing)
        self.assertTrue((self.tmp / card).is_file())
        self.assertEqual(validate_pr.place([named]), [])
        unknown = validate_pr.validate_file(self._bios_file("card/x.bin"), db, EMPTY_HASHES, known)
        self.assertEqual((unknown.outcome, unknown.destination), ("unknown", ""))
        placed = validate_pr.validate_file(
            self._bios_file("bios/Other/Place/b.bin", missing), db, EMPTY_HASHES, known,
        )
        self.assertTrue(any("Placed under bios/Other/Place/" in m for _s, m in placed.checks))


class ADeclaredFileBesideItsHeldNameIsAVariant(_Fixture):
    """A file a profile declares, of a system the collection files nowhere
    yet, whose name the collection holds: the review named the folder and
    left the copy to land on the held file of that name."""

    def test_place_copies_it_beside_the_held_name(self):
        import hashlib  # noqa: PLC0415

        data = b"declared revision"
        emulators = self.tmp / "emulators"
        emulators.mkdir()
        (emulators / "engine.yml").write_text(
            "emulator: Engine\ntype: standalone\nsystems: [x, y]\nfiles:\n"
            f"  - name: \"v.bin\"\n    sha1: \"{hashlib.sha1(data).hexdigest()}\"\n"
        )
        db = {"files": {"a" * 40: {"path": "bios/Maker/Console/v.bin"}},
              "indexes": {"by_md5": {}, "by_sha256": {}, "by_name": {"v.bin": ["a" * 40]}}}
        known = validate_pr.load_profile_hashes(str(emulators), db)
        result = validate_pr.validate_file(
            self._bios_file("card/v.bin", data), db, EMPTY_HASHES, known)
        slot = f"bios/Maker/Console/.variants/v.bin.{result.sha1[:8]}"
        self.assertEqual(result.destination, slot)
        self.assertIn(("WARN", "File is not under bios/ yet. The collection keeps this name in "
                               f"`bios/Maker/Console/`. --place copies it to `{slot}`"),
                      result.checks)


class ASizeEveryDeclarationRulesOutIsNotAVariant(_Fixture):
    """1024 random bytes named scph5501.bin, a name every declaration sizes
    at 524288, were told "File size OK" and offered a .variants slot at the
    repository root."""

    DB = {
        "files": {"a" * 40: {"path": "bios/Sony/PlayStation/scph5501.bin"}},
        "indexes": {"by_name": {"scph5501.bin": ["a" * 40]}},
    }
    PLATFORM = {"sha1": set(), "md5": set(), "names": {"scph5501.bin"},
                "folders": {}, "sizes": {"scph5501.bin": [(524288, 524288)]}}

    def test_a_truncated_file_is_warned_and_not_offered_a_slot(self):
        rel = self._bios_file("scph5501.bin", b"x" * 1024)
        text = validate_pr.validate_file(rel, self.DB, self.PLATFORM).to_markdown()
        self.assertIn("expects 524,288 bytes", text)
        self.assertNotIn(".variants/", text)
        self.assertNotIn("File size OK", text)

    def test_a_right_sized_variant_goes_beside_its_name(self):
        rel = self._bios_file("scph5501.bin", b"y" * 524288)
        text = validate_pr.validate_file(rel, self.DB, self.PLATFORM).to_markdown()
        self.assertIn("bios/Sony/PlayStation/.variants/scph5501.bin.", text)
        self.assertNotIn("expects", text)


class SymlinksAreRefusedBeforeReading(_Fixture):
    """A symlink must be rejected without its target being read.

    The check used to run after compute_hashes, so a link to an endless
    device would be read until the CI job timed out, and a link outside the
    checkout would be hashed and reported as though it were contributed.
    """

    def test_symlink_is_refused(self):
        self._bios_file("bios/Sony/PS/real.bin")
        link = self.tmp / "bios" / "Sony" / "PS" / "link.bin"
        link.symlink_to(self.tmp / "bios" / "Sony" / "PS" / "real.bin")
        result = validate_pr.validate_file(
            "bios/Sony/PS/link.bin", None, EMPTY_HASHES
        )
        self.assertFalse(result.passed)
        self.assertIn("Symlink", result.to_markdown())

    def test_symlink_target_is_never_hashed(self):
        self._bios_file("bios/Sony/PS/real.bin")
        link = self.tmp / "bios" / "Sony" / "PS" / "link.bin"
        link.symlink_to(self.tmp / "bios" / "Sony" / "PS" / "real.bin")
        calls = []
        real = validate_pr.compute_hashes
        validate_pr.compute_hashes = lambda p, *a, **k: (
            calls.append(p) or real(p, *a, **k)
        )
        try:
            validate_pr.validate_file("bios/Sony/PS/link.bin", None, EMPTY_HASHES)
        finally:
            validate_pr.compute_hashes = real
        self.assertEqual(calls, [], "a symlink target must not be read")

    @unittest.skipUnless(os.path.exists("/dev/zero"), "needs /dev/zero")
    def test_a_link_to_an_endless_device_does_not_hang(self):
        link = self.tmp / "bios" / "Sony" / "PS" / "zero.bin"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("/dev/zero")
        result = validate_pr.validate_file(
            "bios/Sony/PS/zero.bin", None, EMPTY_HASHES
        )
        self.assertFalse(result.passed)


class HashRecognition(_Fixture):
    def test_a_declared_sha1_is_recognised(self):
        rel = self._bios_file("bios/Sony/PS/known.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        known = {"sha1": {probe.sha1}, "md5": set(), "names": set()}
        result = validate_pr.validate_file(rel, None, known)
        self.assertIn("SHA1 matches known platform requirement", result.to_markdown())

    def test_a_declared_md5_is_recognised(self):
        rel = self._bios_file("bios/Sony/PS/known.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        known = {"sha1": set(), "md5": {probe.md5}, "names": set()}
        self.assertIn(
            "MD5 matches known platform requirement",
            validate_pr.validate_file(rel, None, known).to_markdown(),
        )

    def test_a_known_name_with_another_hash_is_flagged_as_a_variant(self):
        rel = self._bios_file("bios/Sony/PS/known.bin")
        known = {"sha1": set(), "md5": set(), "names": {"known.bin"}}
        markdown = validate_pr.validate_file(rel, None, known).to_markdown()
        self.assertIn("may be a variant", markdown)
        self.assertIn(".variants/known.bin.", markdown)

    def test_an_unreferenced_file_asks_for_review(self):
        """Random bytes read "PASS" and "all checks passed", and the warning
        named the platform configs alone though the profiles were searched."""
        rel = self._bios_file("bios/Sony/PS/mystery.bin")
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        markdown = result.to_markdown()
        self.assertEqual(result.outcome, "unknown")
        self.assertIn("### REVIEW", markdown)
        self.assertIn("no platform list or emulator profile declares this file", markdown)
        self.assertIn("which emulator reads it", markdown)

    def test_a_zip_of_bios_files_is_read_member_by_member(self):
        """A card's BIOS folder zipped to upload it was hashed as one file,
        and its contributor was asked where that dump came from."""
        import hashlib  # noqa: PLC0415
        import zipfile  # noqa: PLC0415

        held, declared = b"HELD BIOS", b"DECLARED BIOS"
        with zipfile.ZipFile(self.tmp / "mybios.zip", "w") as archive:
            archive.writestr("scph5501.bin", held)
            archive.writestr("sub/declared.bin", declared)
            archive.writestr("other.bin", b"noise")
        db = {"files": {hashlib.sha1(held).hexdigest(): {"path": "bios/Sony/PS/scph5501.bin"}}}
        known = {**EMPTY_HASHES, "md5": {hashlib.md5(declared).hexdigest()}}
        result = validate_pr.validate_file("mybios.zip", db, known)
        markdown = result.to_markdown()
        self.assertEqual(result.outcome, "unknown")
        self.assertIn("unzipped, not the archive", markdown)
        self.assertIn("`scph5501.bin` already held at `bios/Sony/PS/scph5501.bin`", markdown)
        self.assertIn("`sub/declared.bin` declared and not held", markdown)
        self.assertIn("`other.bin` not recognised", markdown)
        self.assertNotIn("where the dump comes from", markdown)
        self.assertNotIn("Place it in", markdown)

    def test_a_duplicate_of_a_known_file_is_reported(self):
        """A copy of a held file passed, and was sent to the folder that
        already holds it."""
        rel = self._bios_file("elsewhere/dupe.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        db = {"files": {probe.sha1: {"path": "bios/Sony/PS/original.bin"}}}
        known = {**EMPTY_HASHES, "sha1": {probe.sha1},
                 "folders": {probe.sha1: {"bios/Sony/PS/"}}}
        result = validate_pr.validate_file(rel, db, known)
        markdown = result.to_markdown()
        self.assertEqual(result.outcome, "held")
        self.assertIn("### REVIEW", markdown)
        self.assertIn("Already held at `bios/Sony/PS/original.bin`: nothing to add", markdown)
        self.assertNotIn("not under bios/", markdown)
        # A duplicate is worth saying out loud but must not block the PR.
        self.assertTrue(result.passed)

    def test_a_copy_in_a_tree_read_by_path_is_kept(self):
        rel = self._bios_file("bios/ScummVM/a/dupe.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        db = {"files": {probe.sha1: {"path": "bios/ScummVM/b/dupe.bin"}}}
        self.assertNotEqual(validate_pr.validate_file(rel, db, EMPTY_HASHES).outcome, "held")

    def test_the_file_the_database_holds_is_not_its_own_duplicate(self):
        """The documented example on a tracked file warned "Duplicate:
        identical file already exists at" the very path being validated."""
        rel = self._bios_file("bios/Sony/PS/held.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        db = {"files": {probe.sha1: {"path": rel}}}
        markdown = validate_pr.validate_file(rel, db, EMPTY_HASHES).to_markdown()
        self.assertNotIn("Duplicate", markdown)
        self.assertIn("Already in the database at this path", markdown)


class PlacementBySystem(_Fixture):
    """Depth alone passed a PS1 BIOS filed under bios/Nintendo/Game Boy/:
    a declared hash names its system, and the files of that system already
    held name its folder."""

    def _known(self, sha1: str) -> dict:
        return {"sha1": {sha1}, "md5": set(), "names": set(),
                "folders": {sha1: {"bios/Sony/PlayStation/"}}}

    def test_a_file_under_another_maker_is_told_where_its_system_lives(self):
        rel = self._bios_file("bios/Nintendo/Game Boy/scph.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        markdown = validate_pr.validate_file(rel, None, self._known(probe.sha1)).to_markdown()
        self.assertIn("bios/Sony/PlayStation/", markdown)
        self.assertNotIn("Correct placement", markdown)

    def test_the_folder_of_its_system_passes(self):
        rel = self._bios_file("bios/Sony/PlayStation/scph.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        markdown = validate_pr.validate_file(rel, None, self._known(probe.sha1)).to_markdown()
        self.assertIn("Correct placement: bios/Sony/PlayStation/", markdown)

    def test_systems_spread_over_makers_name_no_home(self):
        platforms = self.tmp / "platforms"
        platforms.mkdir()
        (platforms / "_registry.yml").write_text(
            "platforms:\n  p:\n    config: p.yml\n", encoding="utf-8")
        (platforms / "p.yml").write_text(
            "platform: P\nsystems:\n  arcade:\n    files:\n"
            "      - {name: a.zip, sha1: aaaa}\n      - {name: b.zip, sha1: bbbb}\n",
            encoding="utf-8",
        )
        db = {"files": {"aaaa": {"path": "bios/Arcade/MAME/a.zip"},
                        "bbbb": {"path": "bios/Apple/Apple II/b.zip"}},
              "indexes": {"by_md5": {}}}
        known = validate_pr.load_platform_hashes(str(platforms), db)
        self.assertEqual(known["folders"], {})


class Placement(_Fixture):
    def test_manufacturer_and_console_directories_are_accepted(self):
        rel = self._bios_file("bios/Sega/Saturn/sega_101.bin")
        self.assertIn(
            "Correct placement: bios/Sega/Saturn/",
            validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown(),
        )

    def test_a_file_at_the_bios_root_is_flagged(self):
        rel = self._bios_file("bios/loose.bin")
        self.assertIn(
            "bios/Manufacturer/Console/",
            validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown(),
        )

    def test_a_file_outside_bios_is_flagged(self):
        rel = self._bios_file("elsewhere/loose.bin")
        self.assertIn(
            "not under bios/",
            validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown(),
        )


class Reporting(_Fixture):
    def test_markdown_carries_every_digest_and_the_verdict(self):
        rel = self._bios_file("bios/Sega/Saturn/sega.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        result = validate_pr.validate_file(rel, None, {**EMPTY_HASHES, "sha1": {probe.sha1}})
        markdown = result.to_markdown()
        for value in (result.sha1, result.md5, result.crc32):
            self.assertIn(value, markdown)
        self.assertIn("### PASS", markdown)

    def test_a_failure_is_marked_in_the_heading(self):
        rel = self._bios_file("bios/Sega/Saturn/bad.exe")
        self.assertIn("### FAIL", validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown())

    @unittest.skipUnless((REPO_ROOT / "database.json").is_file(), "database.json is not built")
    def test_the_status_line_names_what_is_left_to_review(self):
        import shutil
        import subprocess

        held = REPO_ROOT / "bios" / "Sony" / "PlayStation Portable" / "ppge_atlas.zim"
        if not held.is_file():
            self.skipTest(f"{held} is not here")
        shutil.copy(held, self.tmp / "ppge_atlas.zim")
        (self.tmp / "mystery.bin").write_bytes(os.urandom(4096))
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "validate_pr.py"), "--markdown",
             str(self.tmp / "mystery.bin"), str(self.tmp / "ppge_atlas.zim")],
            capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("**Status**: no check failed, to review: 1 already held, "
                      "1 not recognised", proc.stdout)
        self.assertNotIn("all checks passed", proc.stdout)


class PlatformHashLoading(_Fixture):
    def test_missing_directory_yields_empty_sets(self):
        known = validate_pr.load_platform_hashes(str(self.tmp / "absent"))
        self.assertEqual(known, {"sha1": set(), "md5": set(), "sha256": set(), "crc32": set(),
                                 "names": set(), "folders": {}, "sizes": {}, "entries": {},
                                 "named": {}, "name_systems": {}, "system_dirs": {},
                                 "system_folders": {}})

    def test_declared_hashes_and_names_are_collected(self):
        platforms = self.tmp / "platforms"
        platforms.mkdir()
        (platforms / "_registry.yml").write_text(
            "platforms:\n  demo:\n    config: demo.yml\n"
        )
        (platforms / "demo.yml").write_text(
            "platform: Demo\n"
            "systems:\n"
            "  test-sys:\n"
            "    files:\n"
            "      - name: boot.bin\n"
            f"        sha1: {'a' * 40}\n"
            f"        md5: {'b' * 32}\n"
        )
        known = validate_pr.load_platform_hashes(str(platforms))
        self.assertIn("a" * 40, known["sha1"])
        self.assertIn("b" * 32, known["md5"])
        self.assertIn("boot.bin", known["names"])


class ThePlatformsOwnCheckDecides(_Fixture):
    """Batocera pins a ROM inside adam_fdc.zip, Recalbox hashes a ZIP's
    members, RetroDECK declares a sha256: the container's sha1 and md5 are
    in none of those lists, and a file verify counts OK was reported as an
    unknown variant to be filed under .variants/."""

    def _platforms(self, registry: str, systems: str) -> dict:
        platforms = self.tmp / "platforms"
        platforms.mkdir()
        (platforms / "_registry.yml").write_text(
            f"platforms:\n  p:\n    config: p.yml\n{registry}",
            encoding="utf-8")
        (platforms / "p.yml").write_text(f"platform: P\nsystems:\n  s:\n    files:\n{systems}",
                                         encoding="utf-8")
        return validate_pr.load_platform_hashes(str(platforms))

    def _zip(self) -> str:
        import zipfile  # noqa: PLC0415

        path = self.tmp / "contrib" / "set.zip"
        path.parent.mkdir()
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("rom.u10", b"ROM")
        return "contrib/set.zip"

    def _verdict(self, path: str, known: dict) -> str:
        return validate_pr.validate_file(path, None, known).to_markdown()

    def test_a_member_pinned_by_zipped_file(self):
        import hashlib  # noqa: PLC0415

        md5 = hashlib.md5(b"ROM").hexdigest()
        known = self._platforms(
            "    verification_mode: md5\n",
            f"      - {{name: set.zip, md5: {md5}, zipped_file: rom.u10}}\n")
        markdown = self._verdict(self._zip(), known)
        self.assertIn("Accepted by the platform's own check: p", markdown)
        self.assertNotIn(".variants/", markdown)

    def test_a_member_digest(self):
        from hashing import md5_composite  # noqa: PLC0415

        path = self._zip()
        known = self._platforms(
            "    verification_mode: md5\n    zip_digest: composite\n",
            f"      - {{name: set.zip, md5: {md5_composite(path)}}}\n")
        self.assertIn("Accepted by the platform's own check: p", self._verdict(path, known))

    def test_a_sha256(self):
        import hashlib  # noqa: PLC0415

        path = self._zip()
        digest = hashlib.sha256((self.tmp / path).read_bytes()).hexdigest()
        known = self._platforms("    verification_mode: md5\n",
                                f"      - {{name: set.zip, sha256: {digest}}}\n")
        self.assertIn("Hash matches known platform requirement", self._verdict(path, known))

    def test_an_identical_copy_names_the_folder(self):
        db = {"files": {"m" * 40: {"path": "bios/Arcade/MAME/set.zip"},
                        "c" * 40: {"path": "bios/Coleco/Adam/set.zip"}},
              "indexes": {"by_name": {"set.zip": ["m" * 40, "c" * 40]}}}
        self.assertEqual(validate_pr._variant_home(db, "set.zip", "c" * 40), "bios/Coleco/Adam/")
        self.assertEqual(validate_pr._variant_home(db, "set.zip"), "bios/Arcade/MAME/")

    def test_another_member_is_still_a_variant(self):
        known = self._platforms(
            "    verification_mode: md5\n",
            f"      - {{name: set.zip, md5: {'0' * 32}, zipped_file: rom.u10}}\n")
        self.assertIn("may be a variant", self._verdict(self._zip(), known))


class FlagsAreAppliedOrRefused(unittest.TestCase):
    """Files named beside --changed were dropped for the git diff and the run
    said "No changed BIOS files detected" about files it never read; --json
    beside --markdown printed JSON and dropped the markdown."""

    def _run(self, *argv: str):
        import subprocess  # noqa: PLC0415

        return subprocess.run(
            [sys.executable, "scripts/validate_pr.py", *argv], cwd=REPO_ROOT,
            capture_output=True, text=True, timeout=300, check=False,
        )

    def test_files_beside_changed_are_refused(self):
        result = self._run("--changed", "bios/Sony/PlayStation/scph5501.bin", "--json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--changed", result.stderr)

    def test_two_output_formats_are_refused(self):
        result = self._run("--json", "--markdown", "bios/Sony/PlayStation/scph5501.bin")
        self.assertEqual(result.returncode, 2)
        self.assertIn("not allowed with", result.stderr)

    def test_a_failed_file_is_not_reported_new(self):
        """A path that does not exist came out as "outcome": "new", and a
        reader listing new contributions announced a BIOS nobody sent."""
        import json  # noqa: PLC0415

        result = self._run("--json", "bios/nope.bin")
        report = json.loads(result.stdout)
        self.assertEqual([(r["passed"], r["outcome"]) for r in report], [(False, "failed")])



class AFileOutsideBiosIsToldWhereToGo(unittest.TestCase):
    """validate_pr knew bios/Sony/PlayStation/ for scph5501.bin and only said
    "not under bios/". Given an absolute path, a placed file was reported a
    duplicate of itself."""

    def test_both(self):
        import os as _os
        import tempfile as _tempfile

        from validate_pr import validate_file

        content = b"bios bytes"
        import hashlib as _hashlib
        sha1 = _hashlib.sha1(content).hexdigest()
        md5 = _hashlib.md5(content).hexdigest()
        hashes = {"sha1": {sha1}, "md5": {md5}, "names": set(),
                  "folders": {sha1: {"bios/Sony/PlayStation/"}}}
        with _tempfile.TemporaryDirectory() as directory:
            loose = _os.path.join(directory, "scph5501.bin")
            with open(loose, "wb") as handle:
                handle.write(content)
            result = validate_file(loose, None, hashes)
        self.assertTrue(any("bios/Sony/PlayStation/" in m for _s, m in result.checks))

        previous = _os.getcwd()
        with _tempfile.TemporaryDirectory() as root:
            placed = _os.path.join(root, "bios", "Sony", "PlayStation", "scph5501.bin")
            _os.makedirs(_os.path.dirname(placed))
            with open(placed, "wb") as handle:
                handle.write(content)
            db = {"files": {sha1: {"path": "bios/Sony/PlayStation/scph5501.bin"}}}
            _os.chdir(root)
            try:
                result = validate_file(placed, db, hashes)
            finally:
                _os.chdir(previous)
        self.assertFalse(any("Duplicate" in m for _s, m in result.checks))


class ProfileHashesReadAsTheResolverDoes(unittest.TestCase):
    """A file a profile names by crc32 alone (clk's Electron os.rom, 626
    entries) or by a comma list of sha256 (mesence's BS-X.bin) was reported
    as referenced nowhere, needing manual review."""

    def test_crc32_only_and_comma_lists_are_indexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "core.yml").write_text(
                "emulator: Core\ntype: libretro\nsystems: [x]\nfiles:\n"
                "  - name: os.rom\n    crc32: BF63FB1F\n    size: 16384\n"
                "  - name: bsx.bin\n    sha256: \"aa,bb\"\n",
                encoding="utf-8",
            )
            known = validate_pr.load_profile_hashes(tmp)
        self.assertEqual(known["crc32"][("bf63fb1f", 16384)], {"core"})
        self.assertIn("bb", known["sha256"])


if __name__ == "__main__":
    unittest.main()
