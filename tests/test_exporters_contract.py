"""Native exporter contract: registry, pinned revision, cached originals, written exports."""

from __future__ import annotations

import tests

import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from model.registry import list_registered_platforms
from model.platforms import load_platform_config, native_layer
from exporter import discover_exporters
from exporter.base_exporter import BaseExporter
from exporter.originals import SOURCES_INDEX, collect_originals, fetch, pinned_base, source_key
from resolve.reconcile import build_native_model
from tests.exporterssupport import REPO_ROOT, UPSTREAM_CACHE


def _without_native_list() -> set[str]:
    """Registered platforms whose code names no BIOS file to hand back."""
    import yaml

    registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
    return {
        name for name, entry in registry["platforms"].items()
        if entry.get("native_list") == "none"
    }


class ExporterRegistry(unittest.TestCase):
    """Every registered platform has an exporter, and it declares itself."""

    def test_every_exporter_declares_a_platform_and_a_filename(self):
        for name, cls in discover_exporters().items():
            with self.subTest(platform=name):
                self.assertTrue(cls.platform_name())
                self.assertTrue(cls.native_filename())
                self.assertTrue(issubclass(cls, BaseExporter))

    def test_every_registered_platform_can_be_exported(self):
        """A platform with no exporter is a platform we cannot hand back.

        The export is a correction we offer, not a release artefact: a
        platform without a release pack is exported all the same.
        """
        exporters = discover_exporters()
        registered = set(
            list_registered_platforms(
                str(REPO_ROOT / "platforms")
            )
        )
        self.assertEqual(registered - set(exporters) - _without_native_list(), set())

    def test_a_run_over_a_platform_without_a_native_list_passes(self):
        """export_native --all ran over MinUI, NextUI and MyMinUI and failed
        the pipeline step for three platforms the registry says have nothing
        to export. A platform with no exporter and no such mark still fails."""
        import contextlib

        from exporter import runner

        with tempfile.TemporaryDirectory() as directory:
            platforms = Path(directory)
            (platforms / "_registry.yml").write_text(
                "platforms:\n  cardonly:\n    native_list: none\n  unwritten: {}\n",
                encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(runner.run(
                    ["cardonly"], directory, directory, str(platforms), directory, False), 0)
                self.assertEqual(runner.run(
                    ["unwritten"], directory, directory, str(platforms), directory, False), 1)
            self.assertIn("SKIP cardonly: names no BIOS file of its own", out.getvalue())

    def test_a_platform_without_a_native_list_declares_no_file(self):
        """`native_list: none` says the platform's code names no BIOS file
        (MinUI hands each core a folder and opens nothing in it). A platform
        whose file declares one has a list to hand back."""
        for name in _without_native_list():
            config = load_platform_config(name, str(REPO_ROOT / "platforms"))
            with self.subTest(platform=name):
                self.assertNotIn(name, discover_exporters())
                self.assertFalse(any(
                    system.get("files") for system in (config.get("systems") or {}).values()
                ))

    def test_no_exporter_is_registered_for_an_unregistered_platform(self):
        """A dead exporter is one nobody will notice has stopped working."""
        exporters = set(discover_exporters())
        registered = set(
            list_registered_platforms(
                str(REPO_ROOT / "platforms")
            )
        )
        self.assertEqual(exporters - registered, set())

    def test_every_exporter_says_what_its_format_can_state(self):
        """A correction to a field the file has no place for is not delivered."""
        for name, cls in discover_exporters().items():
            with self.subTest(platform=name):
                carried = cls.carries()
                self.assertTrue(carried)
                self.assertTrue(
                    carried
                    <= {"size", "crc32", "md5", "sha1", "sha256", "required", "name"},
                    f"{name} claims a field that is not one of ours: {carried}",
                )

    def test_only_a_format_with_the_field_claims_to_carry_it(self):
        """Recalbox writes mandatory, while RetroBat's entries are md5 and file."""
        exporters = discover_exporters()
        self.assertIn("required", exporters["recalbox"].carries())
        self.assertNotIn("required", exporters["retrobat"].carries())
        self.assertNotIn("required", exporters["retroarch"].carries())

    def test_an_exporter_that_patches_code_says_it_needs_the_original(self):
        """Regenerating a script from data alone drops the code around it."""
        for name in ("batocera", "rocknix", "emudeck", "retrodeck", "bizhawk",
                     "misterfpga", "knulli", "amberelec", "emuelec"):
            with self.subTest(platform=name):
                self.assertTrue(discover_exporters()[name].needs_original())

    def test_every_exporter_with_an_original_needs_it(self):
        """System.dat, RomM, Recalbox and RetroBat were rebuilt from our data
        when their file was not cached: libretro's quoted names, Recalbox's
        comments and its second zxspectrum block were lost, and the run
        said OK."""
        for name, exporter in discover_exporters().items():
            if exporter.native_sources():
                with self.subTest(platform=name):
                    self.assertTrue(exporter.needs_original())

    def test_an_export_without_its_original_writes_nothing(self):
        from exporter.native import export_platform

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            ok, messages = export_platform(
                "retroarch", discover_exporters()["retroarch"],
                REPO_ROOT / "dist" / "truth", output,
                str(REPO_ROOT / "platforms"), Path(tmp) / "no-cache", False,
            )
            if not (REPO_ROOT / "dist" / "truth" / "retroarch.yml").exists():
                self.skipTest("dist/truth not generated")
            self.assertFalse(ok, messages)
            self.assertFalse(output.exists())


class PinnedRevision(unittest.TestCase):
    """The file we patch is the revision our transcription came from."""

    def test_the_tag_the_scraper_pinned_wins_over_the_branch_tip(self):
        wanted = {"batocera-systems": "https://example.invalid/master/batocera-systems"}
        scraped = {
            "source": "https://raw.githubusercontent.com/batocera-linux"
            "/batocera.linux/batocera-43.1/package/batocera-systems"
        }
        self.assertEqual(
            pinned_base(wanted, scraped),
            "https://raw.githubusercontent.com/batocera-linux/batocera.linux"
            "/batocera-43.1/package/",
        )

    def test_a_blob_page_is_read_as_raw(self):
        """github.com/.../blob/... names a revision but serves HTML."""
        wanted = {"System.dat": "https://example.invalid/System.dat"}
        scraped = {
            "source": "https://github.com/libretro/libretro-database"
            "/blob/master/dat/System.dat"
        }
        self.assertEqual(
            pinned_base(wanted, scraped),
            "https://raw.githubusercontent.com/libretro/libretro-database"
            "/master/dat/",
        )

    def test_a_source_that_names_no_wanted_file_changes_nothing(self):
        wanted = {"component_manifest.json": "https://example.invalid/x.json"}
        scraped = {"source": "https://github.com/RetroDECK/components"}
        self.assertEqual(pinned_base(wanted, scraped), "")

    def test_every_platform_that_records_its_source_pins_the_export(self):
        """A scraped platform states the revision, and the export follows it."""
        exporters = discover_exporters()
        for name in ("batocera", "recalbox", "bizhawk", "romm", "retroarch"):
            with self.subTest(platform=name):
                config = load_platform_config(name, str(REPO_ROOT / "platforms"))
                base = pinned_base(dict(exporters[name].native_sources()), config)
                self.assertTrue(base.startswith("https://"), base)

    def test_every_file_of_every_platform_is_read_at_the_pinned_revision(self):
        """Checked on five platforms by their base only: ROCKNIX's second
        file, RetroDECK's manifests and RetroPie's tarball were never
        looked at, and a URL that fell back to a branch passed."""
        from exporter.originals import unpinned, wanted_sources

        for name, exporter_class in discover_exporters().items():
            with self.subTest(platform=name):
                config = native_layer(load_platform_config(name, str(REPO_ROOT / "platforms")))
                systems, _ = build_native_model({}, config)
                wanted = wanted_sources(exporter_class(), systems, config)
                self.assertTrue(wanted)
                self.assertEqual(unpinned(wanted, config), [])

    def test_a_file_read_off_the_pinned_revision_is_named(self):
        from exporter.originals import unpinned

        pinned = {"source": "https://raw.githubusercontent.com/o/r/v1.0/list.txt"}
        self.assertEqual(unpinned(
            {"list.txt": "https://raw.githubusercontent.com/o/r/v1.0/list.txt"}, pinned), [])
        moved = unpinned(
            {"list.txt": "https://raw.githubusercontent.com/o/r/master/list.txt"}, pinned)
        self.assertEqual(len(moved), 1)
        self.assertIn("v1.0", moved[0])
        bare = unpinned(
            {"x.json": "https://raw.githubusercontent.com/o/r/main/x.json"},
            {"source": "https://github.com/RetroDECK/components"})
        self.assertIn("names no revision", bare[0])


class _OneFileExporter:
    """An exporter reduced to what collect_originals reads."""

    def __init__(self, url: str):
        self._url = url

    def platform_name(self) -> str:
        return "plat"

    def native_sources(self) -> dict[str, str]:
        return {"list.txt": self._url}


class _ArchiveExporter(_OneFileExporter):
    """One whose original is an archive it unpacks, as MiSTer's is."""

    def native_sources(self) -> dict[str, str]:
        return {"db.zip": self._url}

    @staticmethod
    def unpack(raw: bytes) -> dict[str, str]:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return {"db.json": archive.read("db.json").decode("utf-8")}


class CachedOriginal(unittest.TestCase):
    """The cached original is the file the platform data was read from."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.cache = self.root / "cache"
        self.index = self.cache / SOURCES_INDEX

    def _upstream(self, name: str, text: str) -> str:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path.as_uri()

    def test_the_same_url_is_served_from_the_cache(self):
        url = self._upstream("v1.txt", "one")
        target = self.cache / "plat" / "list.txt"
        self.assertEqual(fetch(url, target, self.index), b"one")
        self._upstream("v1.txt", "moved")
        self.assertEqual(fetch(url, target, self.index), b"one")

    def test_an_unreadable_index_serves_nothing(self):
        """A truncated index read as empty: the cached batocera-41 file was
        served for a 43.1 URL, and the next download erased every other
        platform's recorded URL."""
        from exporter.originals import SourcesIndexUnreadable

        old = self._upstream("batocera-41.txt", "old")
        target = self.cache / "plat" / "list.txt"
        fetch(old, target, self.index)
        self.index.write_text('{"plat/list.txt": "' + old + '",', encoding="utf-8")
        new = self._upstream("batocera-43.txt", "new")
        with self.assertRaises(SourcesIndexUnreadable) as caught:
            fetch(new, target, self.index)
        self.assertIn("--refresh-cache", str(caught.exception))
        self.assertTrue(self.index.read_text(encoding="utf-8").endswith(","))

    def test_refresh_reads_a_branch_url_again(self):
        """A branch URL keeps its name while the platform moves."""
        url = self._upstream("branch.txt", "one")
        target = self.cache / "plat" / "list.txt"
        fetch(url, target, self.index)
        self._upstream("branch.txt", "two")
        self.assertEqual(fetch(url, target, self.index, refresh=True), b"two")
        self.assertEqual(target.read_bytes(), b"two")

    def test_a_new_pin_refetches_an_existing_file(self):
        """Reading the file straight from disk served the old pin forever."""
        old = self._upstream("tag-1.txt", "one")
        new = self._upstream("tag-2.txt", "two")
        originals, missing = collect_originals(
            _OneFileExporter(old), {}, self.cache, True
        )
        self.assertEqual((originals, missing), ({"list.txt": "one"}, []))
        originals, missing = collect_originals(
            _OneFileExporter(new), {}, self.cache, True
        )
        self.assertEqual((originals, missing), ({"list.txt": "two"}, []))

    def test_an_empty_or_html_original_fails_the_platform(self):
        """A System.dat served as an HTML page with 200, or a 0-byte cache,
        was parsed as a file with no entries: four exporters rebuilt it from
        our data and reported OK."""
        for body in ("", "  \n", "<html><body>Too Many Requests</body></html>",
                     "<!DOCTYPE html>\n<html></html>"):
            with self.subTest(body=body):
                url = self._upstream("served.txt", body)
                originals, missing = collect_originals(
                    _OneFileExporter(url), {}, self.cache, True, refresh=True
                )
                self.assertEqual(originals, {})
                self.assertEqual(len(missing), 1)
                cached = self.cache / "plat" / "list.txt"
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_text(body, encoding="utf-8")
                _, missing = collect_originals(
                    _OneFileExporter(url), {}, self.cache, False
                )
                self.assertEqual(len(missing), 1)
                cached.unlink()

    def test_offline_serves_what_is_cached_and_names_what_is_not(self):
        url = self._upstream("v1.txt", "one")
        _, missing = collect_originals(_OneFileExporter(url), {}, self.cache, False)
        self.assertEqual(missing, [
            f"list.txt: not in {self.cache / 'plat'}; rerun with --fetch to download it"
        ])
        collect_originals(_OneFileExporter(url), {}, self.cache, True)
        originals, missing = collect_originals(
            _OneFileExporter("file:///nowhere/else.txt"), {}, self.cache, False
        )
        self.assertEqual((originals, missing), ({"list.txt": "one"}, []))

    def test_the_bytes_are_written_under_the_index_lock(self):
        """Written under two locks, two runs wanting two URLs for one path
        could leave one's bytes beside the other's index entry."""
        import fcntl
        from unittest import mock

        from exporter import originals

        url = self._upstream("v1.txt", "one")
        target = self.cache / "plat" / "list.txt"
        lock = self.index.with_name(f".{self.index.name}.lock")
        held: list[bool] = []
        write = originals.write_bytes_atomic

        def probing(path, data):
            with open(lock, "a") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    held.append(True)
                else:
                    fcntl.flock(handle, fcntl.LOCK_UN)
                    held.append(False)
            write(path, data)

        with mock.patch.object(originals, "write_bytes_atomic", probing):
            fetch(url, target, self.index)
        self.assertEqual(held, [True])

    def test_an_unreadable_cached_archive_fails_its_platform_only(self):
        """A cached bios_db.json.zip that was not a zip raised BadZipFile
        out of run(): --all stopped and the next platforms were never
        exported."""
        target = self.cache / "plat" / "db.zip"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"<html>not a zip</html>")
        originals, missing = collect_originals(
            _ArchiveExporter("file:///nowhere/db.zip"), {}, self.cache, False
        )
        self.assertEqual(originals, {})
        self.assertEqual(len(missing), 1)
        self.assertIn("--refresh-cache", missing[0])

    def test_a_download_that_is_not_the_archive_keeps_the_cache(self):
        """fetch() cached any 200 reply, so an error page replaced a good
        archive and was served on every later run."""
        good = self.root / "db.zip"
        with zipfile.ZipFile(good, "w") as archive:
            archive.writestr("db.json", "{}")
        url = good.as_uri()
        exporter = _ArchiveExporter(url)
        collect_originals(exporter, {}, self.cache, True)
        cached = (self.cache / "plat" / "db.zip").read_bytes()
        good.write_bytes(b"<html>error</html>")
        originals, missing = collect_originals(exporter, {}, self.cache, True, refresh=True)
        self.assertEqual(originals, {})
        self.assertIn("--refresh-cache", missing[0])
        self.assertEqual((self.cache / "plat" / "db.zip").read_bytes(), cached)

    def test_an_incomplete_read_is_reported(self):
        import http.client
        from unittest import mock

        from exporter import originals as exporter_originals

        def cut(*_args, **_kwargs):
            raise http.client.IncompleteRead(b"par")

        with mock.patch.object(exporter_originals, "fetch", cut):
            originals, missing = collect_originals(
                _OneFileExporter("https://example.invalid/list.txt"), {}, self.cache, True
            )
        self.assertEqual((originals, len(missing)), ({}, 1))

    def test_the_index_names_a_file_the_same_from_any_directory(self):
        target = self.cache / "plat" / "list.txt"
        self.assertEqual(source_key(target, self.index), "plat/list.txt")
        relative = Path(os.path.relpath(target, Path.cwd()))
        self.assertEqual(source_key(relative, self.index), "plat/list.txt")


class AnExportLeavesNoStaleFile(unittest.TestCase):
    """RetroPie writes one scriptmodule per corrected package. A second run on
    a fresher truth printed "2 packages corrected" over a directory still
    holding the six files of the first run."""

    def test_files_this_run_does_not_write_are_removed(self):
        from exporter.native import _remove_stale

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "retropie"
            (root / "scriptmodules" / "libretrocores").mkdir(parents=True)
            kept = root / "scriptmodules" / "libretrocores" / "lr-mgba.sh"
            stale = root / "scriptmodules" / "libretrocores" / "lr-pcsx-rearmed.sh"
            gone_dir = root / "scriptmodules" / "emulators"
            gone_dir.mkdir()
            for path in (kept, stale, gone_dir / "pcsx-rearmed.sh"):
                path.write_text("old", encoding="utf-8")
            _remove_stale(root, {"scriptmodules/libretrocores/lr-mgba.sh"})
            self.assertTrue(kept.exists())
            self.assertFalse(stale.exists())
            self.assertFalse(gone_dir.exists())

    def test_the_export_clears_before_it_writes(self):
        source = (REPO_ROOT / "scripts" / "exporter" / "native.py").read_text()
        body = source[source.index("def write_export("):]
        self.assertLess(body.index("_remove_stale("), body.index("_write_produced("))


class AnExportIsWrittenAsItsBytes(unittest.TestCase):
    """write_text translated line ends on Windows (FirmwareDatabase.cs is
    CRLF, it would have become CR CR LF), replaced the published file in
    place, and dropped the mode: rocknix-systems is 100755 upstream."""

    def test_bytes_mode_and_atomicity(self):
        import stat

        from exporter.native import _write_produced

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_produced(root, {
                "FirmwareDatabase.cs": "a\r\nb\r\n",
                "rocknix-systems": "#!/usr/bin/python\n",
            }, {"rocknix-systems": 0o755})
            self.assertEqual((root / "FirmwareDatabase.cs").read_bytes(), b"a\r\nb\r\n")
            def mode(name: str) -> int:
                return stat.S_IMODE((root / name).stat().st_mode)

            self.assertEqual(mode("rocknix-systems"), 0o755)
            self.assertEqual(mode("FirmwareDatabase.cs"), 0o644)
            self.assertEqual(sorted(p.name for p in root.iterdir()),
                             ["FirmwareDatabase.cs", "rocknix-systems"])

    def test_rocknix_says_its_script_is_executable(self):
        self.assertEqual(discover_exporters()["rocknix"].file_modes(),
                         {"rocknix-systems": 0o755})


class AnExportWithoutTruthIsRefused(unittest.TestCase):
    """dist/ is not committed and exports/ is. On a fresh clone, or with a
    mistyped --truth-dir, the export copied each platform's file back
    uncorrected, said OK, and replaced the corrected export in exports/."""

    def test_nothing_is_written_and_the_run_fails(self):
        from exporter.native import export_platform

        exporter = discover_exporters()["batocera"]
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            published = output / "batocera" / "batocera-systems"
            published.parent.mkdir(parents=True)
            published.write_text("corrected", encoding="utf-8")
            ok, messages = export_platform(
                "batocera", exporter, Path(tmp) / "no-truth", output,
                str(REPO_ROOT / "platforms"), Path(tmp) / "no-cache", False,
            )
            self.assertFalse(ok)
            self.assertIn("generate_truth.py", messages[0])
            self.assertEqual(published.read_text(encoding="utf-8"), "corrected")
            self.assertEqual(sorted(p.name for p in output.rglob("*")),
                             ["batocera", "batocera-systems"])


class AnInvalidExportIsNotWritten(unittest.TestCase):
    """validate() ran after the files were written: an export its own
    validator refused still replaced the published one, and only the exit
    code said so."""

    def test_the_published_file_stays(self):
        from unittest import mock

        from exporter import native as exporter_native
        from exporter.native import export_platform

        if not (UPSTREAM_CACHE / "romm").exists():
            self.skipTest("upstream cache not populated")
        exporter = discover_exporters()["romm"]
        config = native_layer(load_platform_config("romm", str(REPO_ROOT / "platforms")))
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            published = output / "romm" / "known_bios_files.json"
            published.parent.mkdir(parents=True)
            published.write_text("published", encoding="utf-8")
            with mock.patch.object(exporter_native, "load_inputs",
                                   return_value=({"systems": {}}, config)), \
                 mock.patch.object(exporter, "validate", return_value=["bad entry"]):
                ok, messages = export_platform(
                    "romm", exporter, Path(tmp), output,
                    str(REPO_ROOT / "platforms"), UPSTREAM_CACHE, False,
                )
            self.assertFalse(ok)
            self.assertIn("INVALID: bad entry", messages)
            self.assertEqual(published.read_text(encoding="utf-8"), "published")


class TheWikiNamesWhatCountsAnExport(unittest.TestCase):
    """adding-a-platform listed the methods that say what a format can hold
    and none of those that count what render wrote, which seven exporters
    override so the report matches the diff."""

    def test_every_overridden_contract_method_is_documented(self):
        documented = ("carries", "requires", "can_add", "keys_by_system",
                      "lands", "states", "fills", "clears", "names_anew", "withheld")
        overridden = {
            name
            for cls in discover_exporters().values()
            for name in documented
            if name in vars(cls)
        }
        wiki = (REPO_ROOT / "wiki" / "adding-a-platform.md").read_text(encoding="utf-8")
        for name in sorted(overridden):
            with self.subTest(method=name):
                self.assertIn(f"`{name}(", wiki)


if __name__ == "__main__":
    unittest.main()
