"""Audit regressions on file resolution, hashing, caches and archive safety."""

from __future__ import annotations

import tests
from tests.sources import script_source
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock
from packs import verdicts
from scripts.resolve.localfile import resolve_local_file
from scripts.core.ziptools import safe_extract_zip
from tests import REPO_ROOT


class AutoFetchReadsListsAndPlacesWithoutClobbering(unittest.TestCase):
    """A profile hash list (daedalusx64's n64.psh) stopped auto_fetch with
    an unhashable-type error, and a fetched file went to the first folder
    sharing one word of the system slug (nintendo-64 into Nintendo/SNES),
    overwriting a same-named file there."""

    def test_a_hash_list_is_every_accepted_revision(self):
        import hashlib

        from scripts.acquire import fetch as acquire_fetch

        data = b"second revision"
        entry = {"sha1": ["0" * 40, hashlib.sha1(data).hexdigest()]}
        self.assertTrue(acquire_fetch.verify_content(data, entry))
        db = {"files": {hashlib.sha1(data).hexdigest(): {"path": "bios/x/n64.psh"}},
              "indexes": {"by_md5": {}}}
        self.assertEqual(acquire_fetch.step1_crossref_db(entry, db), "bios/x/n64.psh")

    @staticmethod
    def _tables(system: str, folder: str) -> tuple[dict, dict]:
        """Hash tables where the collection files *system* under *folder*."""
        return {"system_folders": {system: {folder}}}, {}

    def test_the_review_folder_is_used_and_nothing_is_overwritten(self):
        from scripts.acquire import placement as acquire_placement

        with tempfile.TemporaryDirectory() as directory:
            bios = Path(directory)
            for folder in ("Nintendo/SNES", "Nintendo/N64", "Nintendo/Nintendo 64DD"):
                (bios / folder).mkdir(parents=True)
            held = bios / "Nintendo" / "N64" / "n64.psh"
            held.write_bytes(b"other revision")
            placed = Path(acquire_placement.place_file(
                b"fetched", {"name": "n64.psh", "system": "nintendo-64"}, str(bios), {},
                *self._tables("nintendo-64", "bios/Nintendo/N64/"),
            ).path)
            self.assertEqual(placed.parent.parent, bios / "Nintendo" / "N64")
            self.assertEqual(placed.parent.name, ".variants")
            self.assertEqual(held.read_bytes(), b"other revision")

    def test_a_slug_inside_another_folder_name_is_no_folder(self):
        """'ds' is in '3DS': the DS firmware went to Nintendo/3DS."""
        from scripts.acquire import placement as acquire_placement

        with tempfile.TemporaryDirectory() as directory:
            bios = Path(directory)
            for folder in ("Nintendo/3DS", "Nintendo/Nintendo DS"):
                (bios / folder).mkdir(parents=True)
            placed = Path(acquire_placement.place_file(
                b"fw", {"name": "firmware.bin", "system": "nintendo-ds"}, str(bios), {},
                *self._tables("nintendo-ds", "bios/Nintendo/Nintendo DS/"),
            ).path)
            self.assertEqual(placed, bios / "Nintendo" / "Nintendo DS" / "firmware.bin")

    def test_an_unsettled_folder_stays_out_of_bios(self):
        """snk-neogeo went to a new bios/Unknown/snk-neogeo/."""
        import hashlib

        from scripts.acquire import placement as acquire_placement

        with tempfile.TemporaryDirectory() as directory:
            bios, acquired = Path(directory, "bios"), Path(directory, "acquire")
            bios.mkdir()
            placed = acquire_placement.place_file(
                b"set", {"name": "neogeo.zip", "system": "snk-neogeo"}, str(bios), {},
                {}, {}, acquire_dir=acquired,
            )
            self.assertTrue(placed.kept_out)
            self.assertEqual(Path(placed.path), acquired / hashlib.sha1(b"set").hexdigest())
            self.assertEqual(list(bios.iterdir()), [])


class ResolverRegressions(unittest.TestCase):
    def _database(self, entries: dict[str, Path], suffix: str | None = None) -> dict:
        files = {}
        by_name: dict[str, list[str]] = {}
        by_suffix: dict[str, list[str]] = {}
        for name, path in entries.items():
            payload = path.read_bytes()
            sha1 = hashlib.sha1(payload).hexdigest()
            md5 = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()
            files[sha1] = {
                "path": str(path),
                "name": name,
                "size": len(payload),
                "md5": md5,
                "sha256": sha256,
                "crc32": "00000000",
            }
            by_name.setdefault(name, []).append(sha1)
            if suffix and name == "firmware.bin":
                by_suffix.setdefault(suffix, []).append(sha1)
        return {
            "files": files,
            "indexes": {
                "by_name": by_name,
                "by_md5": {entry["md5"]: sha1 for sha1, entry in files.items()},
                "by_sha256": {
                    entry["sha256"]: sha1 for sha1, entry in files.items()
                },
                "by_crc32": {},
                "by_path_suffix": by_suffix,
            },
        }

    def test_hash_identity_wins_over_wrong_destination_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong = root / "wrong" / "firmware.bin"
            correct = root / "correct" / "firmware.bin"
            wrong.parent.mkdir()
            correct.parent.mkdir()
            wrong.write_bytes(b"wrong")
            correct.write_bytes(b"correct")
            db = self._database(
                {"firmware.bin": wrong, "correct-name.bin": correct},
                suffix="Console/USA/firmware.bin",
            )
            expected = hashlib.sha1(b"correct").hexdigest()
            path, status = resolve_local_file(
                {"name": "firmware.bin", "sha1": expected},
                db,
                dest_hint="Console/USA/firmware.bin",
            )
            self.assertEqual(path, str(correct))
            self.assertEqual(status, "sha1_exact")

    def test_name_cannot_mask_a_declared_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.bin"
            path.write_bytes(b"wrong")
            db = self._database({"firmware.bin": path})
            resolved, status = resolve_local_file(
                {"name": "firmware.bin", "sha1": "f" * 40}, db
            )
            self.assertEqual(resolved, str(path))
            self.assertEqual(status, "hash_mismatch")


class ArchiveSecurityRegressions(unittest.TestCase):
    def _zip_path(self, directory: Path, name: str = "archive.zip") -> Path:
        return directory / name

    def test_member_count_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("one.bin", b"1")
                handle.writestr("two.bin", b"2")
            with self.assertRaisesRegex(ValueError, "members"):
                safe_extract_zip(str(archive), str(root / "out"), max_members=1)

    def test_member_modes_follow_the_archive_and_the_umask(self):
        """Every member came out 0600, the mode of its temporary file: the
        pico8 and vox launchers the RetroDECK pack keeps 0755 lost their
        execute bit once download.py extracted them."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            program = zipfile.ZipInfo("pico8")
            program.create_system = 3
            program.external_attr = (stat.S_IFREG | 0o755) << 16
            plain = zipfile.ZipInfo("bios.bin")
            plain.create_system = 0
            plain.external_attr = 0x20  # MS-DOS archive bit, no Unix mode
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(program, b"\x7fELF")
                handle.writestr(plain, b"data")
            umask = os.umask(0o022)
            try:
                safe_extract_zip(str(archive), str(root / "out"))
            finally:
                os.umask(umask)
            self.assertEqual((root / "out" / "pico8").stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / "out" / "bios.bin").stat().st_mode & 0o777, 0o644)

    def test_symlink_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            link = zipfile.ZipInfo("link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(link, "target")
            with self.assertRaisesRegex(ValueError, "link or special"):
                safe_extract_zip(str(archive), str(root / "out"))

    def test_windows_separator_is_a_path_not_a_rejection(self):
        """Archives written on Windows store a backslash separator.

        download.py feeds third-party archives to this function, so a legal
        Windows path must extract into a subdirectory instead of failing.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("sub\\rom.bin", b"payload")
            out = root / "out"
            safe_extract_zip(str(archive), str(out))
            self.assertEqual((out / "sub" / "rom.bin").read_bytes(), b"payload")

    def test_windows_separator_cannot_smuggle_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("..\\escaped.bin", b"payload")
            with self.assertRaisesRegex(ValueError, "traversal"):
                safe_extract_zip(str(archive), str(root / "out"))

    def test_high_ratio_method_is_bounded_by_size_not_ratio(self):
        """bzip2 legitimately exceeds the DEFLATE ceiling."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_BZIP2) as handle:
                handle.writestr("zeros.bin", bytes(4_000_000))
            out = root / "out"
            safe_extract_zip(str(archive), str(out))
            self.assertEqual((out / "zeros.bin").stat().st_size, 4_000_000)

    def test_compression_ratio_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("zeros.bin", bytes(16_384))
            with self.assertRaisesRegex(ValueError, "compression ratio"):
                safe_extract_zip(
                    str(archive), str(root / "out"), max_compression_ratio=2
                )


class NoMd5IsNotNothingChecked(unittest.TestCase):
    """A declared hash that is not an md5 still contradicts.

    verify_entry_md5 returned OK the moment the entry declared no md5, so an
    entry whose sha256 the local file contradicts read as covered while the
    builder was already excluding it. RetroDECK's dsifirmware.bin declares a
    sha256 and no md5.
    """

    def _entry(self):
        return {"name": "dsifirmware.bin", "sha256": "b" * 64}

    def test_a_contradicted_sha256_is_not_reported_ok(self):
        result = verdicts.verify_entry_md5(
            self._entry(), "bios/whatever.bin", "hash_mismatch"
        )
        self.assertNotEqual(result["status"], verdicts.Status.OK)
        self.assertIn("contradicted", result.get("reason", ""))

    def test_a_clean_resolution_is_still_ok(self):
        result = verdicts.verify_entry_md5(
            self._entry(), "bios/whatever.bin", "sha256_exact"
        )
        self.assertEqual(result["status"], verdicts.Status.OK)


class AnotherEmulatorsTreeProvesNothing(unittest.TestCase):
    """lrps2 names no hash for pcsx2/resources/GameIndex.yaml, and the only
    full-tail copy was ARMSX2's, which counted as path proof and replaced
    the GameIndex RetroArch pins on desktop targets, where ARMSX2 does not
    exist. Upstream PCSX2 took ARMSX2's patches.zip by name the same way."""

    def _db(self, root, files):
        import hashlib

        db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}, "by_crc32": {},
                                       "by_path_suffix": {}}}
        for relative, payload in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            db["files"][sha1] = {"path": relative, "name": path.name, "sha1": sha1,
                                 "size": len(payload)}
            db["indexes"]["by_name"].setdefault(path.name, []).append(sha1)
            parts = relative.split("/")
            for start in range(1, len(parts) - 1):
                db["indexes"]["by_path_suffix"].setdefault(
                    "/".join(parts[start:]), []).append(sha1)
        return db

    def test_neither_the_full_tail_nor_the_name_lands_in_a_foreign_tree(self):
        from scripts.resolve.localfile import resolve_local_file

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # The collection's layout, read relative to its root.
            previous = os.getcwd()
            os.chdir(root)
            self.addCleanup(os.chdir, previous)
            db = self._db(root, {
                "bios/Other/armsx2/pcsx2/resources/GameIndex.yaml": b"fork",
                "bios/Other/armsx2/pcsx2/resources/patches.zip": b"fork patches",
                "bios/Sony/PlayStation 2/patches.zip": b"upstream patches",
            })
            index, status = resolve_local_file(
                {"name": "GameIndex.yaml", "path": "pcsx2/resources/GameIndex.yaml",
                 "source_profile": "lrps2"},
                db, dest_hint="pcsx2/resources/GameIndex.yaml",
            )
            # Held only in the fork's tree, the file answers by name and
            # proves nothing about this entry.
            self.assertEqual(status, "name_exact")
            patches, _status = resolve_local_file(
                {"name": "patches.zip", "path": "resources/patches.zip",
                 "source_profile": "pcsx2"},
                db, dest_hint="resources/patches.zip",
            )
            self.assertTrue(patches.endswith("PlayStation 2/patches.zip"))

    def test_no_desktop_retroarch_pack_serves_armsx2s_tree(self):
        from scripts.packs import slots
        from scripts.model.registry import load_data_dir_registry
        from scripts.model.database import load_database
        from scripts.model.profiles import load_emulator_profiles
        from scripts.model.platforms import load_platform_config
        from scripts.model.targets import load_target_config

        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        db = load_database(str(REPO_ROOT / "database.json"))
        config = load_platform_config("retroarch", str(REPO_ROOT / "platforms"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cores = set(load_target_config("retroarch", "x86_64", str(REPO_ROOT / "platforms")))
        overrides = slots.pack_overrides(
            config, profiles, db, None, load_data_dir_registry(str(REPO_ROOT / "platforms")),
            target_cores=cores,
        )
        self.assertFalse([d for d, p in overrides.items() if "/armsx2/" in p])


class APinnedCoreFileTakesTheSlotFirst(unittest.TestCase):
    """hypseus-singe asks for gamecontrollerdb.txt by name and took the BIOS
    root of Batocera, RetroBat and RetroPie with C-Dogs' 26 KB table, where
    Solarus pins its own by sha1."""

    def test_the_content_naming_claim_is_placed_first(self):
        from unittest import mock

        from scripts.packs import extras as packextras

        undeclared = [
            {"profile": "hypseus", "emulator": "hypseus", "name": "db.txt",
             "path": "db.txt", "in_repo": True, "systems": ["a"]},
            {"profile": "solarus", "emulator": "solarus", "name": "db.txt",
             "path": "db.txt", "in_repo": True, "systems": ["b"], "sha1": "a" * 40},
        ]
        config = {"systems": {}, "base_destination": "bios"}
        with mock.patch("packs.gaps.find_undeclared_files", return_value=undeclared), \
                mock.patch.object(packextras, "resolve_platform_cores",
                                  return_value=set()) as cores:
            extras = packextras.collect_emulator_extras(
                config, "emulators", {"files": {}, "indexes": {}}, set(), "bios", {}
            )
        self.assertEqual([e["source_profile"] for e in extras][:1], ["solarus"])
        # The stub is what ran: patched with create=True on a name the module
        # imported inside the function, it was never read and the real
        # resolve_platform_cores walked the repository's profiles.
        cores.assert_called_once()


class ANameWithItsDirectoryIsTheDestination(unittest.TestCase):
    """gam4980 declares gam4980/E.BIN with no path: resolved by its basename,
    verify --emulator and the emulator pack took the A4980's OS while the
    platform pack served the GAM4980's."""

    def test_the_directory_in_the_name_picks_the_copy(self):
        import hashlib

        from scripts.resolve.localfile import resolve_local_file

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = os.getcwd()
            os.chdir(root)
            self.addCleanup(os.chdir, previous)
            files, by_name, by_suffix = {}, {}, {}
            for relative, payload in (("bios/BBK/A4980/A4980/E.BIN", b"a4980"),
                                      ("bios/BBK/GAM4980/gam4980/E.BIN", b"gam4980")):
                Path(relative).parent.mkdir(parents=True, exist_ok=True)
                Path(relative).write_bytes(payload)
                sha1 = hashlib.sha1(payload).hexdigest()
                files[sha1] = {"path": relative, "name": "E.BIN", "sha1": sha1}
                by_name.setdefault("E.BIN", []).append(sha1)
                parent = relative.split("/")[-2]
                by_suffix.setdefault(f"{parent}/E.BIN", []).append(sha1)
            db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                              "by_crc32": {}, "by_path_suffix": by_suffix}}
            path, status = resolve_local_file(
                {"name": "gam4980/E.BIN", "source_profile": "gam4980"}, db
            )
            self.assertEqual((path, status), ("bios/BBK/GAM4980/gam4980/E.BIN", "path_exact"))


class AnUnreadableDatabaseStopsTheScan(unittest.TestCase):
    """A database.json left with merge markers read as an absent one: every
    release-asset entry silently left the rewritten database, then the
    manifests."""

    def test_a_corrupt_database_is_not_an_empty_one(self):
        from collection import releaseassets

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "database.json"
            path.write_text("<<<<<<< HEAD\n{}\n")
            with self.assertRaises(releaseassets.DatabaseUnreadable) as caught:
                releaseassets.read_database(str(path))
            self.assertIn("is not valid JSON", str(caught.exception))
            self.assertIsNone(
                releaseassets.read_database(str(Path(directory) / "absent.json"))
            )

    def test_the_build_exits_1_on_it(self):
        import argparse
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest import mock

        from collection import run

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bios").mkdir()
            output = root / "database.json"
            output.write_text("<<<<<<< HEAD\n{}\n")
            args = argparse.Namespace(
                bios_dir=str(root / "bios"), force=True, output=str(output),
                offline=True, platforms_dir=str(root), emulators_dir=str(root),
                provenance_dir=str(root),
            )
            err = io.StringIO()
            with mock.patch.object(run, "load_gitignored_large_files",
                                   return_value={"bios/big.bin"}), \
                    redirect_stdout(io.StringIO()), redirect_stderr(err):
                self.assertEqual(run.generate(args), 1)
            self.assertIn("is not valid JSON", err.getvalue())
            self.assertFalse((root / ".cache").exists())
            self.assertTrue(output.read_text().startswith("<<<<<<<"))


class TheDigestCacheBelongsToTheScannedTree(unittest.TestCase):
    """The cache path was fixed on the working directory: scanning a copy
    (tmp/wt/bios) replaced the repository's cache with the copy's entries,
    keyed bios/... like the real ones, and the next run rehashed everything."""

    def test_a_scan_writes_its_cache_beside_its_tree(self):
        import argparse
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from collection import hashcache, run

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bios" / "Sony").mkdir(parents=True)
            (root / "bios" / "Sony" / "a.bin").write_bytes(b"a")
            (root / "_registry.yml").write_text("platforms: {}\n")
            args = argparse.Namespace(
                bios_dir=str(root / "bios"), force=False,
                output=str(root / "database.json"), offline=True,
                platforms_dir=str(root), emulators_dir=str(root),
                provenance_dir=str(root),
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(run.generate(args), 0)
            cache = root / ".cache" / "db_cache.json"
            self.assertEqual(hashcache.cache_path(root / "bios"), str(cache))
            self.assertEqual(list(hashcache.load_cache(str(cache))), ["bios/Sony/a.bin"])
            self.assertEqual(hashcache.cache_path(Path("bios")), ".cache/db_cache.json")


class TheZipIndexCacheKnowsItsInputs(unittest.TestCase):
    """build_zip_contents_index cached on (path, mtime) alone: a smaller
    max_entry_size, or a database giving the same archive another sha1,
    got the first call's index back."""

    def test_the_bound_and_the_sha1_are_part_of_the_key(self):
        from scripts.core import ziptools

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("big.bin", b"x" * 4096)
            ziptools._zip_contents_cache = None
            db = {"files": {"a" * 40: {"path": str(path)}}}
            self.assertEqual(len(ziptools.build_zip_contents_index(db, Path(directory))), 1)
            self.assertEqual(ziptools.build_zip_contents_index(db, Path(directory), max_entry_size=10), {})
            other = {"files": {"b" * 40: {"path": str(path)}}}
            self.assertEqual(
                set(ziptools.build_zip_contents_index(other, Path(directory)).values()), {"b" * 40}
            )
            ziptools._zip_contents_cache = None


class GeneratedModelsAreWrittenWhole(unittest.TestCase):
    """The truth model and the cumulative MAME clone map were written by
    truncate-then-write, and a corrupt clone map also read as empty and was
    then overwritten, losing what earlier runs recorded."""

    def test_both_writers_replace_their_file_atomically(self):
        for module in ("generate_truth.py", "dedup.py"):
            source = script_source(module)
            with self.subTest(module=module):
                self.assertIn("write_text_atomic(", source)
                self.assertNotIn('open(out_path, "w")', source)
                self.assertNotIn('open(clone_path, "w")', source)

    def test_an_unreadable_clone_map_stops_the_run(self):
        from collection import dedup

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bios = root / "bios"
            # A device clone: two archive names, the same ROMs, in MAME's tree.
            (bios / "Arcade" / "MAME").mkdir(parents=True)
            for name in ("set.zip", "setclone.zip"):
                with zipfile.ZipFile(bios / "Arcade" / "MAME" / name, "w") as archive:
                    archive.writestr("rom.bin", b"rom")
            data = (bios / "Arcade" / "MAME" / "set.zip").read_bytes()
            (bios / "Arcade" / "MAME" / "setclone.zip").write_bytes(data)
            (root / "_mame_clones.json").write_text("<<<<<<< HEAD")
            from model.database import CloneMapUnreadable

            with self.assertRaises(CloneMapUnreadable):
                dedup.deduplicate(str(bios), dry_run=False)
            # Stopped before removing anything.
            self.assertTrue((bios / "Arcade" / "MAME" / "setclone.zip").exists())

    def test_the_pack_side_reads_the_same_bad_map_the_same_way(self):
        from model import database

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bios").mkdir()
            (root / "_mame_clones.json").write_text("<<<<<<< HEAD")
            with self.assertRaises(database.CloneMapUnreadable) as caught:
                database.get_mame_clone_map(str(root / "bios"))
            self.assertIn("Restore it from git", str(caught.exception))
            (root / "_mame_clones.json").write_text("[]")
            with self.assertRaises(database.CloneMapUnreadable):
                database.get_mame_clone_map(str(root / "bios"))


class TheDatabaseCacheIsWrittenWhole(unittest.TestCase):
    """A crash while serializing left a truncated db_cache.json behind, and
    the next run rehashed the whole collection from scratch."""

    def test_a_failed_save_keeps_the_previous_cache(self):
        import json
        from unittest import mock

        from collection import hashcache

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache", "db_cache.json")
            hashcache.save_cache(path, {"a": 1})
            with mock.patch.object(json, "dumps", side_effect=TypeError("miscomputed")), \
                    self.assertRaises(TypeError):
                hashcache.save_cache(path, {"a": 2})
            self.assertEqual(hashcache.load_cache(path), {"a": 1})
            self.assertEqual(os.listdir(os.path.dirname(path)), ["db_cache.json"])


class HashMergeBackupsAreNotSources(unittest.TestCase):
    """The hash merge copies a profile to <name>.old.yml before rewriting it.

    Every loader skipped the copy except validate_schemas, which then failed
    on a stale MAME profile nobody would ever ship.
    """

    def test_the_validator_skips_a_backup(self):
        try:
            from schemas.sourcetree import validate_yaml_directory
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")

        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "mame.old.yml").write_text("emulator: [\n")
            self.assertEqual(
                validate_yaml_directory(Path(directory), "emulator.schema.json"), []
            )

    def test_the_backup_suffix_is_written_once(self):
        offenders = [
            str(path.relative_to(REPO_ROOT))
            for path in sorted(REPO_ROOT.glob("scripts/**/*.py"))
            if path.relative_to(REPO_ROOT).as_posix() != "scripts/model/profiles.py"
            and '".old.yml"' in path.read_text()
        ]
        self.assertEqual(offenders, [])


class AnUnreadableArchiveIsSaidOutLoud(unittest.TestCase):
    """resolve_local_file skipped a ZIP it could not open without a word: a
    truncated archive read as a missing dump (not_found) or a wrong one."""

    def test_the_resolver_names_the_archive(self):
        from resolve import localfile

        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "neogeo.zip"
            broken.write_bytes(b"PK\x03\x04 truncated")
            sha1 = hashlib.sha1(broken.read_bytes()).hexdigest()
            db = {"files": {sha1: {"path": str(broken), "name": "neogeo.zip", "sha1": sha1,
                                   "md5": "0" * 32, "size": broken.stat().st_size}},
                  "indexes": {"by_name": {"neogeo.zip": [sha1]}, "by_md5": {},
                              "by_crc32": {}, "by_path_suffix": {}}}
            entry = {"name": "neogeo.zip", "md5": "1" * 32, "zipped_file": "sp-s2.sp1"}
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                localfile.resolve_local_file(entry, db)
        self.assertIn(f"unreadable archive {broken}", stderr.getvalue())


class ADataDirectoryIsWalkedOnce(unittest.TestCase):
    """Each unresolved name walked every data-directory cache again: the
    resolution cost names x tree on every pack build."""

    def test_two_lookups_share_one_walk_and_keep_its_order(self):
        from resolve.datadirs import forget_data_dir_index, resolve_in_data_dirs

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            (cache / "a").mkdir(parents=True)
            (cache / "b").mkdir()
            (cache / "a" / "Font.bin").write_bytes(b"1")
            (cache / "b" / "font.bin").write_bytes(b"2")
            (cache / "b" / "other.bin").write_bytes(b"3")
            registry = {"x": {"local_cache": str(cache)}}
            forget_data_dir_index()
            walks = []
            real_walk = os.walk

            def counting_walk(top, *a, **k):
                walks.append(top)
                return real_walk(top, *a, **k)

            with mock.patch.object(os, "walk", counting_walk):
                first, _ = resolve_in_data_dirs(["font.bin"], registry,
                                                        lambda _p: "name_exact")
                second, _ = resolve_in_data_dirs(["other.bin"], registry,
                                                         lambda _p: "name_exact")
            forget_data_dir_index()
        self.assertEqual(len(walks), 1)
        expected = sorted(str(p) for p in (cache / "a" / "Font.bin", cache / "b" / "font.bin"))
        self.assertIn(first[0], expected)
        self.assertEqual(second[0], str(cache / "b" / "other.bin"))


class AnAcceptedVersionIsNoCoreDiscrepancy(unittest.TestCase):
    """eduke32 lists the retail and demo NWINTER.GRP under one name: the extra
    carries the first, and a held demo copy is a version the code takes."""

    PROFILE = {"files": [
        {"name": "NWINTER.GRP", "size": 9, "crc32": "00000000",
         "validation": ["size", "crc32"]},
        {"name": "NWINTER.GRP", "size": 4, "crc32": "",
         "validation": ["size", "crc32"]},
    ]}

    def _extra(self) -> dict:
        # The shape find_undeclared_files gives a core extra: source_path
        # defaults to the name when the profile declares no path.
        return {"name": "NWINTER.GRP", "source_name": "NWINTER.GRP",
                "source_path": "NWINTER.GRP", "source_profile": "eduke32"}

    def test_a_sibling_version_matches(self):
        from scripts.packs.platformzip import _matches_an_alternative

        with tempfile.TemporaryDirectory() as tmp:
            held = Path(tmp) / "NWINTER.GRP"
            held.write_bytes(b"demo")
            profile = json.loads(json.dumps(self.PROFILE))
            profile["files"][1]["crc32"] = f"{zlib.crc32(b'demo'):08x}"
            self.assertTrue(_matches_an_alternative(
                self._extra(), str(held), {"eduke32": profile}))

    def test_a_copy_no_entry_declares_still_disagrees(self):
        from scripts.packs.platformzip import _matches_an_alternative

        with tempfile.TemporaryDirectory() as tmp:
            held = Path(tmp) / "NWINTER.GRP"
            held.write_bytes(b"other")
            profile = json.loads(json.dumps(self.PROFILE))
            profile["files"][1]["crc32"] = f"{zlib.crc32(b'demo'):08x}"
            self.assertFalse(_matches_an_alternative(
                self._extra(), str(held), {"eduke32": profile}))

    def test_the_pack_consults_the_alternatives(self):
        source = script_source("generate_pack.py")
        self.assertRegex(source, r'status == "hash_mismatch" and not _matches_an_alternative\(')


class ADataDirectoryCopyPassesTheNameChecks(unittest.TestCase):
    """The name steps over bios/ refuse a candidate outside the size or the
    Adler-32 the entry's code checks, but a cache copy found by the same name
    was returned without either check."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, True))
        cache = self.tmp / "cache"
        cache.mkdir()
        (cache / "wiitdb-pt.txt").write_bytes(b"12345")
        self.registry = {"dolphin-sys": {"local_cache": str(cache)}}
        self.db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {},
                                            "by_path_suffix": {}, "by_crc32": {}}}

    def resolve(self, **fields):
        entry = {"name": "wiitdb-pt.txt", **fields}
        return resolve_local_file(entry, self.db, data_dir_registry=self.registry)

    def test_a_size_the_code_accepts_resolves(self):
        self.assertEqual(self.resolve(size=5, validation=["size"])[1], "data_dir")

    def test_another_size_is_a_contradiction(self):
        self.assertEqual(self.resolve(size=1, validation=["size"])[1], "hash_mismatch")

    def test_another_adler32_is_a_contradiction(self):
        status = self.resolve(validation=["adler32"], known_hash_adler32="0xdeadbeef")[1]
        self.assertEqual(status, "hash_mismatch")


class AMameCloneNameIsANameStep(unittest.TestCase):
    """The clone fallback relaunched resolution on the bare canonical name:
    an unsourceable entry and a size the code checks were both served the
    parent set."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, True))
        bios = self.tmp / "bios" / "Arcade"
        bios.mkdir(parents=True)
        parent = bios / "parent.zip"
        parent.write_bytes(b"PARENTSET")
        (self.tmp / "_mame_clones.json").write_text(
            json.dumps({"parent.zip": {"clones": ["clone.zip"]}})
        )
        sha1 = hashlib.sha1(parent.read_bytes()).hexdigest()
        self.db = {
            "bios_dir": str(self.tmp / "bios"),
            "files": {sha1: {"path": str(parent), "name": "parent.zip",
                             "sha1": sha1, "size": 9}},
            "indexes": {"by_name": {"parent.zip": [sha1]}, "by_md5": {},
                        "by_path_suffix": {}, "by_crc32": {}},
        }

    def resolve(self, **fields):
        return resolve_local_file({"name": "clone.zip", **fields}, self.db)

    def test_a_clone_resolves_to_its_parent(self):
        self.assertEqual(self.resolve()[1], "mame_clone")

    def test_an_unsourceable_entry_is_not_served_the_parent(self):
        self.assertEqual(self.resolve(unsourceable="not held"), (None, "not_found"))

    def test_a_size_the_parent_contradicts_is_not_served(self):
        self.assertEqual(
            self.resolve(size=5, validation=["size"]), (None, "not_found")
        )


class ASameNamedMemberIsNotTheFile(unittest.TestCase):
    """The gap report counted touchhle's LiberationMono-Regular.ttf as held
    because idtech4a++'s extras.zip has a member of that name, another font,
    while verify --emulator said missing."""

    def test_a_declared_hash_decides_a_member_or_data_hit(self):
        from scripts.packs import supplemental

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, True))
        (tmp / "data").mkdir()
        (tmp / "data" / "font.ttf").write_bytes(b"DATA FONT")
        (tmp / "bios").mkdir()
        with zipfile.ZipFile(tmp / "bios" / "extras.zip", "w") as zf:
            zf.writestr("files/other.ttf", b"MEMBER FONT")
        names = supplemental.build_supplemental_index(str(tmp / "data"), str(tmp / "bios"))
        for fname, data in (("font.ttf", b"DATA FONT"), ("other.ttf", b"MEMBER FONT")):
            with self.subTest(name=fname):
                held = {"name": fname, "sha1": hashlib.sha1(data).hexdigest()}
                other = {"name": fname, "sha1": "0" * 40}
                self.assertTrue(supplemental.data_hit(fname, None, held, names))
                self.assertFalse(supplemental.data_hit(fname, None, other, names))
                self.assertTrue(supplemental.data_hit(fname, None, {"name": fname}, names))


class AutoFetchAsksVerifyWhatIsMissing(unittest.TestCase):
    """auto_fetch judged presence by sha1 or md5 in the database: Batocera's
    pc6001.zip, checked inside the zip and held, was a target, and no core
    file was ever one. 721 announced where verify saw none critical."""

    def test_the_targets_are_verify_verdicts(self):
        from scripts.acquire import fetch as acquire_fetch
        from packs import coverage as packs_coverage
        from packs import verdicts

        config = {"verification_mode": "md5", "systems": {"s": {"files": [
            {"name": "ok.bin", "md5": "1" * 32},
            {"name": "gone.bin", "md5": "2" * 32},
            {"name": "bad.bin", "md5": "3" * 32},
        ]}}}
        result = {
            "details": [
                {"system": "s", "name": "ok.bin", "status": verdicts.Status.OK},
                {"system": "s", "name": "gone.bin", "status": verdicts.Status.MISSING},
                {"system": "s", "name": "bad.bin", "status": verdicts.Status.UNTESTED},
            ],
            "undeclared_files": [
                {"name": "diabdat.mpq", "in_repo": False, "required": True,
                 "system": "diablo", "emulator": "DevilutionX"},
                {"name": "held.bin", "in_repo": True, "required": True},
                {"name": "extra.bin", "in_repo": False, "required": False},
                # zesarux installs 128s.rom with the emulator: not a target,
                # and a copy placed in bios/ fails pipeline step 4d.
                {"name": "128s.rom", "in_repo": False, "required": True,
                 "bundled": True, "emulator": "ZEsarUX"},
            ],
        }
        with mock.patch.object(packs_coverage, "verify_platform", lambda c, d: result):
            names = [m["name"] for m in acquire_fetch.find_missing(config, {})]
        self.assertEqual(names, ["gone.bin", "bad.bin", "diabdat.mpq"])


class AZipMemberIsHashedOnce(unittest.TestCase):
    """check_inside_zip decompressed a member for every md5 candidate and
    every step: 4 788 times for 355 members in verify --all."""

    def test_repeated_questions_read_the_archive_once(self):
        from scripts.core import ziptools

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp, "set.zip")
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("ROM.bin", b"abc")
            good = hashlib.md5(b"abc").hexdigest()
            opened = []
            real = ziptools.zipfile.ZipFile

            def counting(*args, **kwargs):
                opened.append(args[0])
                return real(*args, **kwargs)

            with mock.patch.object(ziptools.zipfile, "ZipFile", counting):
                answers = [ziptools.check_inside_zip(str(archive), "rom.bin", md5)
                           for md5 in (good, "0" * 32, good)]
        self.assertEqual(answers, ["ok", "untested", "ok"])
        self.assertEqual(len(opened), 1)


class CompanionsComeFromADirectoryIndex(unittest.TestCase):
    """_companions walked the whole database per scanned image."""

    def test_same_answer_one_walk(self):
        from scripts.packs import extrascan

        files_db = {
            "a": {"path": "bios/Sony/PS2/ps2.bin", "name": "ps2.bin"},
            "b": {"path": "bios/Sony/PS2/ps2.bin.rom1", "name": "ps2.bin.rom1"},
            "c": {"path": "bios/Sony/PS2/ps2.nvm", "name": "ps2.nvm"},
            "d": {"path": "bios/Other/ps2.nvm", "name": "ps2.nvm"},
        }
        found = extrascan._companions("bios/Sony/PS2/ps2.bin", "ps2.bin", {"rom1", "nvm"}, files_db)
        self.assertEqual([sha1 for sha1, _ in found], ["b", "c"])
        index = extrascan._files_by_directory(files_db)
        self.assertIs(extrascan._files_by_directory(files_db), index)


class ZippedFileMd5IsParsedOnce(unittest.TestCase):
    """verify lowercased a comma md5 list, the builder and packverify did
    not: an uppercase Recalbox-style md5 on a zipped_file entry was OK for
    verify and a mismatch for the pack and the manifest."""

    def test_an_uppercase_member_md5_is_accepted_everywhere(self):
        import hashlib
        import zipfile as zf_mod

        from scripts.resolve.acceptance import inner_rom_check
        from scripts.packs.verdicts import verify_entry_md5

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory, "x.zip")
            with zf_mod.ZipFile(archive, "w") as zf:
                zf.writestr("rom.bin", b"rom")
            member = hashlib.md5(b"rom").hexdigest().upper()
            for md5 in (member, f"{member},{'0' * 32}"):
                with self.subTest(md5=md5):
                    entry = {"name": "x.zip", "zipped_file": "rom.bin", "md5": md5}
                    self.assertEqual(inner_rom_check(entry, str(archive)), "ok")
                    self.assertEqual(
                        verify_entry_md5(entry, str(archive))["status"], "ok"
                    )

    def test_the_three_sites_share_the_parser(self):
        for module in ("resolve/acceptance.py", "verify.py"):
            source = script_source(module)
            self.assertIn("parse_hash_list(", source, module)
        self.assertIn("inner_rom_data_check(", script_source("packs/packhashes.py"))


class AHashListIsReadOneWay(unittest.TestCase):
    """mesence declares four sha256 for BS-X.bin as one comma-joined string.
    The resolver split it and shipped the file, but the gap report and
    profile_sync looked the whole string up and called it missing."""

    def test_every_reader_splits_the_list(self):
        from scripts.packs.supplemental import declared_content
        from scripts.core.hashing import parse_hash_list
        from scripts.profiling.citations import entry_hashes

        a, b = "a" * 64, "B" * 64
        entry = {"name": "BS-X.bin", "sha256": f"{a}, {b}", "crc32": "0xDEADBEEF"}
        self.assertEqual(parse_hash_list(entry["sha256"]), [a, b.lower()])
        self.assertEqual(declared_content(entry)["sha256"], {a, b.lower()})
        self.assertEqual(declared_content(entry)["crc32"], {"deadbeef"})
        self.assertEqual(set(entry_hashes(entry)), {a, b.lower(), "deadbeef"})


@tests.ONLINE
class AnUnansweredSearchIsNotANotFound(unittest.TestCase):
    """auto_fetch caught every network error and reported the file as
    needing a community contribution: offline, each file became an issue
    asking the public for something the tool never looked for."""

    def _fetch(self, error):
        from unittest import mock

        from scripts.acquire import fetch as acquire_fetch

        def refuse(*_args, **_kwargs):
            raise error

        entry = {"name": "nowhere.bin", "system": "test-system", "sha1": "0" * 40}
        db = {"files": {}, "indexes": {"by_md5": {}, "by_name": {}}}
        with mock.patch("urllib.request.urlopen", refuse), \
                mock.patch.object(acquire_fetch.forgehttp, "_sleep", lambda _s: None), \
                mock.patch.object(acquire_fetch, "step2_scan_branches", lambda e: None):
            return acquire_fetch.fetch_missing([entry], db, "bios")

    def test_offline_is_not_searched(self):
        import urllib.error

        result = self._fetch(urllib.error.URLError("offline"))
        self.assertEqual(result["still_missing"], [])
        self.assertEqual(result["stats"]["errors"], 1)

    def test_a_404_everywhere_is_not_found(self):
        import urllib.error

        result = self._fetch(urllib.error.HTTPError("u", 404, "missing", {}, None))
        self.assertEqual(len(result["still_missing"]), 1)
        self.assertEqual(result["stats"]["errors"], 0)


class AutoFetchProvesEveryHashItIsGiven(unittest.TestCase):
    """auto_fetch checked a download by sha1 or md5 only: RetroDECK's
    dsifirmware.bin, pinned by sha256 alone, was announced as searched and
    could never be accepted."""

    DATA = b"firmware bytes"

    def test_a_sha256_proves_a_download(self):
        import hashlib

        from scripts.acquire import fetch as acquire_fetch

        sha256 = {"sha256": hashlib.sha256(self.DATA).hexdigest()}
        self.assertTrue(acquire_fetch.verify_content(self.DATA, sha256))
        self.assertFalse(acquire_fetch.verify_content(b"other", sha256))

    def test_every_declared_cryptographic_hash_must_match(self):
        import hashlib

        from scripts.acquire import fetch as acquire_fetch

        both = {"sha256": hashlib.sha256(self.DATA).hexdigest(), "md5": "0" * 32}
        self.assertFalse(acquire_fetch.verify_content(self.DATA, both))
        both["md5"] = hashlib.md5(self.DATA).hexdigest()
        self.assertTrue(acquire_fetch.verify_content(self.DATA, both))

    def test_crc32_and_size_never_accept_a_download(self):
        """A crc32 can be forged: bytes a source crafts to it would land in
        bios/."""
        import urllib.request
        import zlib
        from unittest import mock

        from scripts.acquire import fetch as acquire_fetch

        crc = {"name": "forged.bin", "system": "test-system",
               "crc32": f"{zlib.crc32(self.DATA):08X}", "size": len(self.DATA)}
        self.assertFalse(acquire_fetch.verify_content(self.DATA, crc))
        self.assertFalse(acquire_fetch.verifiable(crc))

        served = io.BytesIO(self.DATA)
        with tempfile.TemporaryDirectory() as bios, \
                mock.patch.object(urllib.request, "urlopen", lambda *a, **k: served), \
                mock.patch.object(acquire_fetch, "step2_scan_branches",
                                  lambda e: self.DATA):
            result = acquire_fetch.fetch_missing([crc], {"files": {}}, bios)
            self.assertEqual(list(Path(bios).rglob("*")), [])
        self.assertEqual(result["stats"]["found"], 0)
        self.assertEqual(result["stats"]["unverifiable"], 1)
        self.assertEqual([r.outcome for r in result["records"]], ["unverifiable"])

    def test_a_held_sha256_is_found_in_the_database(self):
        from scripts.acquire import fetch as acquire_fetch

        db = {"files": {"s": {"path": "bios/x/dsi.bin", "size": 3, "sha256": "f" * 64}},
              "indexes": {"by_sha256": {"f" * 64: "s"}}}
        self.assertEqual(
            acquire_fetch.step1_crossref_db({"sha256": "F" * 64}, db), "bios/x/dsi.bin"
        )

    def test_a_held_file_a_declared_hash_contradicts_is_still_searched(self):
        """auto_fetch printed "Found in database" for a crc32 or md5 hit whose
        sha1 the entry contradicts, a file verify calls missing."""
        from scripts.acquire import fetch as acquire_fetch

        held = {"path": "bios/x/a.bin", "sha1": "c" * 40, "md5": "d" * 32,
                "crc32": "deadbeef", "size": 4}
        db = {"files": {"c" * 40: held},
              "indexes": {"by_crc32": {"deadbeef": "c" * 40}, "by_md5": {"d" * 32: "c" * 40}}}
        find = acquire_fetch.step1_crossref_db
        self.assertIsNone(find({"sha1": "a" * 40, "crc32": "deadbeef", "size": 4}, db))
        self.assertIsNone(find({"sha1": "a" * 40, "md5": "d" * 32}, db))
        self.assertIsNone(find({"crc32": "deadbeef", "size": 5}, db))
        self.assertEqual(find({"crc32": "deadbeef", "size": 4}, db), "bios/x/a.bin")
        self.assertEqual(find({"md5": "d" * 29}, db), "bios/x/a.bin")

    def test_an_entry_without_a_hash_is_not_searched(self):
        from unittest import mock

        from acquire import fetch as acquire_fetch
        from acquire import fetchtext

        entry = {"name": "DICROM.ROM", "system": "fujitsu-fm7"}
        out = io.StringIO()
        with mock.patch.object(acquire_fetch, "step2_scan_branches") as branches, \
                contextlib.redirect_stdout(out):
            result = fetchtext.report_fetch([entry], {"files": {}}, "bios", dry_run=True)
        branches.assert_not_called()
        self.assertEqual(result["stats"]["unverifiable"], 1)
        self.assertNotIn("Would search", out.getvalue())
        self.assertIn("Not searched", out.getvalue())


class AutoFetchIssueBodyReadsAsWritten(unittest.TestCase):
    """The --create-issues body was a template: Title Case headings, "The
    following...", an exclamation mark, numbered orders to the reader, a
    spaced dash, and hashes cut to 12 characters a contributor cannot
    match a file against."""

    ENTRY = {"name": "scph5501.bin", "system": "sony-playstation",
             "sha1": "b056ee5a4d65937e1a3a17e1e78f3258ea49c38e",
             "md5": "490f666e1afb15b7362b406ed1cea246"}

    def test_full_hashes_and_no_template_phrasing(self):
        from scripts.acquire import fetch as acquire_fetch

        body = acquire_fetch.generate_issue_body([self.ENTRY], "RetroArch")
        self.assertIn(f"`{self.ENTRY['sha1']}`", body)
        self.assertIn(f"`{self.ENTRY['md5']}`", body)
        self.assertNotIn("...", body)
        self.assertNotIn("!", body)
        self.assertNotRegex(body, r"(?i)the following|please| - |\bfork\b")
        self.assertNotRegex(body, r"(?m)^\d+\. ")
        for heading in re.findall(r"(?m)^#+ (.*)$", body):
            later = [w for w in heading.split()[1:] if w != "RetroArch"]
            self.assertEqual(later, [w.lower() for w in later], heading)

    def test_the_docstring_says_nothing_is_posted(self):
        from scripts import auto_fetch

        self.assertNotIn("Create GitHub Issue", auto_fetch.__doc__)
        self.assertIn("posts nothing", auto_fetch.__doc__)


class VerifySha1ReadsTheBuilderDigest(unittest.TestCase):
    """verify_entry_sha1 accepts what the builder's sha1 comparison accepts:
    a list of revisions and a padded value, which it crashed on or refused."""

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / "tmp")
        self.addCleanup(scratch.cleanup)
        self.path = str(Path(scratch.name) / "fw.bin")
        Path(self.path).write_bytes(b"bizhawk firmware")
        self.sha1 = hashlib.sha1(b"bizhawk firmware").hexdigest()

    def _status(self, sha1: object) -> str:
        from resolve.acceptance import frontend_digest_matches

        entry = {"name": "fw.bin", "sha1": sha1}
        builder = frontend_digest_matches(entry, self.path, "sha1")
        status = verdicts.verify_entry_sha1(entry, self.path)["status"]
        self.assertEqual(status == verdicts.Status.OK, builder)
        return status

    def test_a_list_of_revisions(self):
        self.assertEqual(self._status(["0" * 40, self.sha1]), verdicts.Status.OK)

    def test_a_padded_value(self):
        self.assertEqual(self._status(self.sha1.upper() + " "), verdicts.Status.OK)

    def test_another_dump(self):
        self.assertEqual(self._status("0" * 40), verdicts.Status.UNTESTED)


if __name__ == "__main__":
    unittest.main()
