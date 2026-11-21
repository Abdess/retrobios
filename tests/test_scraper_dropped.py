"""An upstream entry a scraper leaves out reaches the freshness check.

The RomM scraper skipped an unmapped IGDB slug and the RetroDECK scraper a
second component's conflicting MD5 with a stderr warning only: the rescrape
exited 0, the rewritten file showed no diff, and check_freshness said OK.
"""

from __future__ import annotations

import tests

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from freshness import platforms, rescrape
from freshness.findings import OK, STALE, UNKNOWN
from scraper.base_scraper import DROPPED_PREFIX, BiosRequirement, scraper_cli
from scripts.scraper import retrodeck_scraper, romm_scraper


def _manifest(md5: str) -> dict:
    return {"bios": [{"filename": "font.rom", "system": "pc98", "md5": md5}]}


class RetrodeckConflicts(unittest.TestCase):
    def test_a_second_components_md5_is_kept_not_dropped(self) -> None:
        """RetroDECK checks each manifest entry against its own md5 list
        (api_data_processing.sh:350-361): both are transcribed."""
        with tempfile.TemporaryDirectory() as tmp:
            for name, md5 in (("np2kai", "a" * 32), ("xm6", "b" * 32)):
                folder = Path(tmp) / name
                folder.mkdir()
                (folder / "component_manifest.json").write_text(json.dumps({name: _manifest(md5)}))
            scraper = retrodeck_scraper.Scraper(manifests_dir=tmp)
            reqs = scraper.fetch_requirements()
        self.assertEqual([(r.md5, r.native["component"]) for r in reqs],
                         [("a" * 32, "np2kai"), ("b" * 32, "xm6")])
        self.assertEqual(scraper.dropped, [])

    def test_a_plain_repeat_is_not_a_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("np2kai", "xm6"):
                folder = Path(tmp) / name
                folder.mkdir()
                (folder / "component_manifest.json").write_text(json.dumps({name: _manifest("a" * 32)}))
            scraper = retrodeck_scraper.Scraper(manifests_dir=tmp)
            scraper.fetch_requirements()
        self.assertEqual(scraper.dropped, [])

    def test_an_unreadable_local_manifest_stops_the_scrape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "np2kai"
            folder.mkdir()
            (folder / "component_manifest.json").write_text("{")
            with self.assertRaises(ValueError):
                retrodeck_scraper.Scraper(manifests_dir=tmp).fetch_requirements()


class RommUnmappedSlug(unittest.TestCase):
    def test_an_unmapped_slug_fails_the_scrape(self) -> None:
        data = {"nosuchconsole:bios.bin": {"size": "4", "md5": "c" * 32}}
        with mock.patch.object(romm_scraper, "fetch_github_latest_version", return_value="9.9.9"):
            scraper = romm_scraper.Scraper()
        scraper._raw_data = json.dumps(data)
        with self.assertRaisesRegex(ValueError, "nosuchconsole"):
            scraper.fetch_requirements()


class _Dropping:
    lists_files = True

    def __init__(self) -> None:
        self.dropped = ["x.bin (s): MD5 conflict"]

    def fetch_requirements(self) -> list[BiosRequirement]:
        return [BiosRequirement(name="a.bin", system="s", md5="d" * 32)]


class CliPrintsDrops(unittest.TestCase):
    def test_each_drop_is_one_marked_line(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["scraper", "--json"]), \
                mock.patch("sys.stderr", stderr), mock.patch("sys.stdout", io.StringIO()):
            scraper_cli(_Dropping)
        self.assertEqual(stderr.getvalue(), f"{DROPPED_PREFIX}x.bin (s): MD5 conflict\n")


class FreshnessReadsDrops(unittest.TestCase):
    def _scrape(self, stderr: str) -> tuple[Path, str | None, list[str]]:
        done = subprocess.CompletedProcess([], 0, stdout="", stderr=stderr)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src" / "p.yml"
            source.parent.mkdir()
            source.write_text("systems: {}\n")
            with mock.patch.object(rescrape, "rescrape_command", return_value=["true"]), \
                    mock.patch.object(rescrape.subprocess, "run", return_value=done):
                return rescrape.scrape_into_copy("platforms", "p", source, Path(tmp))

    def test_marked_lines_are_returned(self) -> None:
        _target, error, dropped = self._scrape(f"progress\n{DROPPED_PREFIX}x.bin (s): why\n")
        self.assertIsNone(error)
        self.assertEqual(dropped, ["x.bin (s): why"])

    def test_an_unchanged_file_with_drops_is_unknown(self) -> None:
        def status(dropped: list[str], new_text: str) -> str:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "p.yml"
                path.write_text("systems: {}\n")
                fresh = Path(tmp) / "fresh.yml"
                fresh.write_text(new_text)
                with mock.patch.object(platforms, "_scrapable_platforms", return_value=[("p", "m", path)]), \
                        mock.patch.object(platforms, "load_platform_registry", return_value={}), \
                        mock.patch.object(platforms, "scrape_into_copy", return_value=(fresh, None, dropped)):
                    return platforms.check_platforms(Path(tmp), Path(tmp), 1)[0].status
        self.assertEqual(status([], "systems: {}\n"), OK)
        self.assertEqual(status(["x.bin (s): why"], "systems: {}\n"), UNKNOWN)
        self.assertEqual(status(["x.bin (s): why"], "version: '2'\nsystems: {}\n"), STALE)


if __name__ == "__main__":
    unittest.main()
