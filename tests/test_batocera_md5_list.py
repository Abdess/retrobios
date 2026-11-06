"""An md5 written as a list of strings in batocera-systems.

batocera.linux 6b08b873 lets an item's md5 be one string or a list, and
checkBios accepts a file whose md5 is any listed value (`md5Matches`, and
`checkInsideZip` for a zippedFile). The scrapers keep the values
comma-joined with the list form recorded, the export writes a list back as
a list, and verify accepts any listed md5.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import resolve_local_file  # noqa: E402
from exporter import discover_exporters  # noqa: E402
from export_native import landed_changes  # noqa: E402
from exporter.baseline import NativeFile, build_native_model  # noqa: E402
from exporter.batocera_exporter import md5_list_support  # noqa: E402
from scraper import rocknix_scraper  # noqa: E402
from scraper.base_scraper import md5_field, requirement_entry  # noqa: E402
from scraper.batocera_scraper import (  # noqa: E402
    SYSTEM_SLUG_MAP,
    extract_systems_dict,
    platform_systems,
    requirements_from_systems,
)
from siteexports import describe_change  # noqa: E402
from verify import Status, verify_entry_md5  # noqa: E402

A = "dc2b9bf8da62ec93e868cfd29f0d067d"
B = "924e392ed05558ffdb115408c263dccf"
C = "8dd7d5296a650fac7319bce665a6a53c"

# The psx entry as 6b08b873 writes it, one string item beside one list item.
SCRIPT = (
    "#!/usr/bin/env python\n"
    "systems = {\n"
    '    "psx": { "name": "PSX", "biosFiles": [  '
    '{ "md5": "' + C + '", "file": "bios/scph5500.bin"    },\n'
    '                                            '
    '{ "md5": [ "' + A + '", "' + B + '" ], "file": "bios/scph1001.bin"    } ] },\n'
    "}\n"
    "def checkBios(systems, prefix, filterROMs):\n"
    "    return {}\n"
)


def _scraped(script: str = SCRIPT) -> dict:
    systems = extract_systems_dict(script)
    requirements = requirements_from_systems(systems, SYSTEM_SLUG_MAP)
    return {"cores": [], "systems": platform_systems(requirements, systems, SYSTEM_SLUG_MAP)}


def _files(scraped: dict) -> dict[str, dict]:
    return {fe["name"]: fe for system in scraped["systems"].values() for fe in system["files"]}


class Md5Field(unittest.TestCase):
    def test_string_and_list(self):
        self.assertEqual(md5_field(A), ([A], False))
        self.assertEqual(md5_field(""), ([], False))
        self.assertEqual(md5_field(None), ([], False))
        self.assertEqual(md5_field([A, B]), ([A, B], True))
        self.assertEqual(md5_field([A]), ([A], True))
        self.assertEqual(md5_field([]), ([], True))

    def test_anything_else_is_refused(self):
        with self.assertRaises(ValueError):
            md5_field(32)
        with self.assertRaises(ValueError):
            md5_field([A, 1])


class BatoceraScraper(unittest.TestCase):
    def test_a_string_stays_one_value(self):
        entry = _files(_scraped())["scph5500.bin"]
        self.assertEqual(entry["md5"], C)
        self.assertNotIn("md5_list", entry)

    def test_a_list_is_joined_and_marked(self):
        entry = _files(_scraped())["scph1001.bin"]
        self.assertEqual(entry["md5"], f"{A},{B}")
        self.assertIs(entry["md5_list"], True)

    def test_a_one_item_list_keeps_its_form(self):
        script = SCRIPT.replace(f'[ "{A}", "{B}" ]', f'[ "{A}" ]')
        entry = _files(_scraped(script))["scph1001.bin"]
        self.assertEqual(entry["md5"], A)
        self.assertIs(entry["md5_list"], True)

    def test_an_empty_list_checks_by_existence(self):
        script = SCRIPT.replace(f'[ "{A}", "{B}" ]', "[]")
        entry = _files(_scraped(script))["scph1001.bin"]
        self.assertNotIn("md5", entry)
        self.assertIs(entry["md5_list"], True)

    def test_the_schema_accepts_the_entry(self):
        import json

        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")

        schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text())
        entry = _files(_scraped())["scph1001.bin"]
        jsonschema.validate(entry, schema["$defs"]["bios_file"])


class RocknixScraper(unittest.TestCase):
    def _requirements(self, script: str):
        scraper = rocknix_scraper.Scraper(url="https://example.invalid/rocknix-systems")
        scraper._fetch_raw = lambda: script  # type: ignore[method-assign]
        return {req.name: requirement_entry(req) for req in scraper.fetch_requirements()}

    def test_string_and_list(self):
        entries = self._requirements(SCRIPT)
        self.assertEqual(entries["scph5500.bin"]["md5"], C)
        self.assertNotIn("md5_list", entries["scph5500.bin"])
        self.assertEqual(entries["scph1001.bin"]["md5"], f"{A},{B}")
        self.assertIs(entries["scph1001.bin"]["md5_list"], True)


class BatoceraExportRoundTrip(unittest.TestCase):
    def _render(self, truth_files: list[dict], script: str = SCRIPT) -> str:
        scraped = _scraped(script)
        systems, report = build_native_model(
            {"systems": {"sony-playstation": {"files": truth_files}}}, scraped
        )
        exporter = discover_exporters()["batocera"]()
        return exporter.render(systems, report, {"batocera-systems": script}, scraped)[
            "batocera-systems"]

    def test_nothing_to_correct_leaves_the_script_unchanged(self):
        self.assertEqual(self._render([]), SCRIPT)

    def test_a_one_item_list_is_written_back_as_a_list(self):
        script = SCRIPT.replace(f'[ "{A}", "{B}" ]', f'[ "{A}" ]')
        self.assertEqual(self._render([], script), script)

    def test_a_corrected_list_stays_a_list(self):
        produced = self._render([{
            "name": "scph1001.bin", "path": "scph1001.bin", "md5": [A, B, "f" * 32],
            "_cores": ["pcsx_rearmed"],
        }])
        self.assertEqual(
            produced,
            SCRIPT.replace(f'[ "{A}", "{B}" ]', f'[ "{A}", "{B}", "{"f" * 32}" ]'),
        )

    def test_a_string_item_stays_a_string(self):
        produced = self._render([{
            "name": "scph5500.bin", "path": "scph5500.bin", "md5": "e" * 32,
            "_cores": ["pcsx_rearmed"],
        }])
        self.assertEqual(produced, SCRIPT.replace(C, "e" * 32))


class VerifyAcceptsAnyListedMd5(unittest.TestCase):
    def setUp(self) -> None:
        scratch = REPO_ROOT / "tmp"
        self.tmp = tempfile.TemporaryDirectory(dir=scratch if scratch.is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _file(self, payload: bytes) -> str:
        path = self.root / "scph1001.bin"
        path.write_bytes(payload)
        return str(path)

    def test_each_listed_md5_matches(self):
        first, second, other = b"first", b"second", b"other"
        entry = _files(_scraped(SCRIPT.replace(A, hashlib.md5(first).hexdigest())
                                .replace(B, hashlib.md5(second).hexdigest())))["scph1001.bin"]
        for payload in (first, second):
            self.assertEqual(verify_entry_md5(entry, self._file(payload))["status"], Status.OK)
        self.assertEqual(verify_entry_md5(entry, self._file(other))["status"], Status.UNTESTED)

    def test_the_resolver_finds_the_second_listed_dump(self):
        """The pack builder and the manifest resolve through this function."""
        payload = b"second"
        md5 = hashlib.md5(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        path = self._file(payload)
        db = {
            "files": {sha1: {"path": path, "md5": md5, "sha1": sha1, "name": "scph1001.bin"}},
            "indexes": {"by_md5": {md5: sha1}, "by_name": {"scph1001.bin": [sha1]}},
        }
        entry = {"name": "scph1001.bin", "md5": f"{A},{md5}", "md5_list": True}
        self.assertEqual(resolve_local_file(entry, db), (path, "md5_exact"))

    def test_inside_a_zip(self):
        member = b"member"
        entry = {"name": "pack.zip", "zipped_file": "rom.bin",
                 "md5": f"{A},{hashlib.md5(member).hexdigest()}", "md5_list": True}
        archive = self.root / "pack.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("rom.bin", member)
        self.assertEqual(verify_entry_md5(entry, str(archive))["status"], Status.OK)


# checkBios as batocera.linux 6b08b873 writes it: a plain file's md5 goes
# through md5Matches, a member's through checkInsideZip, both reading lists.
LIST_CHECKER = """def md5Matches(computed, expected):
    if isinstance(expected, list):
        expectedList = expected
    else:
        expectedList = [expected]
    return computed in expectedList

def checkInsideZip(container, fileName, md5sums):
    if not isinstance(md5sums, list):
        md5sums = [md5sums]
    import zipfile
    from hashlib import md5
    with zipfile.ZipFile(container) as archive:
        for fname in archive.namelist():
            if fname.casefold() == fileName.casefold():
                if md5sums == [""] or md5sums == []:
                    return True
                return md5(archive.read(fname)).hexdigest() in md5sums
    return False

def checkBios(systems, prefix, filterROMs):
    from hashlib import md5
    from os.path import isfile
    missingBios = {}
    for system in systems.keys():
        for file in systems[system]["biosFiles"]:
            filepath = prefix + "/" + file["file"]
            if not isfile(filepath):
                missingBios.setdefault(system, {})[file["file"]] = "MISSING"
            elif not "zippedFile" in file:
                with open(filepath, "rb") as handle:
                    digest = md5(handle.read()).hexdigest()
                if not md5Matches(digest, file["md5"]) and file["md5"] != "" and file["md5"] != []:
                    missingBios.setdefault(system, {})[file["file"]] = "UNTESTED"
            elif 'altmd5' in file:
                if not checkInsideZip(filepath, file["zippedFile"], [file["md5"], file["altmd5"]]):
                    missingBios.setdefault(system, {})[file["file"]] = "UNTESTED"
            elif not checkInsideZip(filepath, file["zippedFile"], file["md5"]):
                missingBios.setdefault(system, {})[file["file"]] = "UNTESTED"
    return missingBios
"""

# batocera-43.1's checker: one md5, compared with `!=`.
STRING_CHECKER = """def checkInsideZip(container, fileName, md5sum):
    return md5sum == ""

def checkBios(systems, prefix, filterROMs):
    missingBios = {}
    for system in systems.keys():
        for file in systems[system]["biosFiles"]:
            if "zippedFile" in file:
                checkInsideZip(prefix, file["zippedFile"], file["md5"])
            elif "" != file["md5"]:
                missingBios[system] = file["file"]
    return missingBios
"""

DATA = SCRIPT.split("def checkBios")[0]
LISTING = DATA + LIST_CHECKER
STRINGS = DATA + STRING_CHECKER
D = "e" * 32
F = "f" * 32
SECOND = hashlib.md5(b"second").hexdigest()


class ListSupportIsReadFromTheChecker(unittest.TestCase):
    def test_the_list_checker_reads_lists_for_both_kinds(self):
        self.assertEqual(md5_list_support(LISTING), {"file", "zippedFile"})

    def test_the_string_checker_reads_none(self):
        self.assertEqual(md5_list_support(STRINGS), frozenset())
        self.assertEqual(md5_list_support(SCRIPT), frozenset())

    def test_a_list_test_on_another_parameter_is_not_support(self):
        checker = LIST_CHECKER.replace(
            "isinstance(expected, list)", "isinstance(computed, list)"
        )
        self.assertEqual(md5_list_support(DATA + checker), {"zippedFile"})

    def test_a_script_that_does_not_parse_reads_none(self):
        self.assertEqual(md5_list_support(LISTING + "\ndef (\n"), frozenset())

    def test_the_cached_originals(self):
        """The pins cached today (batocera-43.1 and the forks) read one md5."""
        root = REPO_ROOT / ".cache" / "upstream-native"
        scripts = [
            root / name / filename
            for name, filename in (
                ("batocera", "batocera-systems"), ("rocknix", "rocknix-systems"),
                ("amberelec", "batocera-systems"), ("emuelec", "batocera-systems"),
                ("knulli", "knulli-systems"),
            )
            if (root / name / filename).is_file()
        ]
        if not scripts:
            self.skipTest(".cache/upstream-native/ is not filled")
        for path in scripts:
            text = path.read_text(encoding="utf-8", errors="replace")
            expected = frozenset() if "md5Matches" not in text else {"file"}
            with self.subTest(path.parent.name):
                self.assertLessEqual(expected, md5_list_support(text))


class SeveralAcceptedMd5BecomeAList(unittest.TestCase):
    """Every md5 the truth accepts, once the pinned checker reads a list."""

    CORRECTED = {
        "name": "scph5500.bin", "path": "scph5500.bin", "md5": [C, D],
        "_cores": ["pcsx_rearmed"],
    }
    ADDED = {
        "name": "scph7001.bin", "path": "scph7001.bin", "md5": [D, F],
        "_cores": ["pcsx_rearmed"],
    }

    @staticmethod
    def _export(truth_files: list[dict], script: str):
        scraped = _scraped(script)
        scraped["cores"] = ["pcsx_rearmed"]
        systems, report = build_native_model(
            {"systems": {"sony-playstation": {"files": truth_files}}}, scraped
        )
        exporter = discover_exporters()["batocera"]()
        produced = exporter.render(
            systems, report, {"batocera-systems": script}, scraped
        )["batocera-systems"]
        files = {fe.name: fe for system in systems.values() for fe in system.files}
        return produced, landed_changes(exporter, systems), exporter, files

    def test_a_string_item_with_several_accepted_becomes_a_list(self):
        produced, changes, _, _ = self._export([self.CORRECTED], LISTING)
        self.assertEqual(
            produced, LISTING.replace(f'"md5": "{C}"', f'"md5": [ "{C}", "{D}" ]')
        )
        record = next(r for r in changes.records if r["kind"] == "hash_updated")
        self.assertEqual((record["old"], record["new"]), (C, [C, D]))
        self.assertEqual(changes.lists, 1)

    def test_an_addition_with_several_accepted_is_written_as_a_list(self):
        produced, changes, exporter, files = self._export([self.ADDED], LISTING)
        self.assertTrue(exporter.lands(files["scph7001.bin"]))
        self.assertIn(
            f'{{ "md5": [ "{D}", "{F}" ], "file": "bios/scph7001.bin", '
            '"emulator": "libretro", "core": "pcsx_rearmed" }',
            produced,
        )
        record = next(r for r in changes.records if r["kind"] == "added")
        self.assertEqual(record["new"]["md5"], [D, F])
        self.assertEqual(changes.lists, 1)

    def test_an_empty_md5_is_filled_with_the_list(self):
        """Left empty while one value was all the item could hold."""
        produced, changes, _, _ = self._export([self.CORRECTED], LISTING.replace(C, ""))
        self.assertEqual(
            produced, LISTING.replace(f'"md5": "{C}"', f'"md5": [ "{C}", "{D}" ]')
        )
        record = next(r for r in changes.records if r["kind"] == "hash_filled")
        self.assertEqual(record["new"], [C, D])
        strings = STRINGS.replace(C, "")
        self.assertEqual(self._export([self.CORRECTED], strings)[0], strings)

    def test_one_accepted_md5_stays_a_string(self):
        produced, changes, _, _ = self._export([dict(self.CORRECTED, md5=D)], LISTING)
        self.assertEqual(produced, LISTING.replace(C, D))
        self.assertEqual(changes.lists, 0)

    def test_without_the_checker_the_export_is_unchanged(self):
        """The string checker keeps the first md5 and refuses the addition,
        as every export did before the checker read lists."""
        produced, changes, exporter, files = self._export(
            [self.CORRECTED, self.ADDED], STRINGS
        )
        self.assertEqual(produced, STRINGS)
        self.assertFalse(exporter.lands(files["scph7001.bin"]))
        self.assertEqual(changes.lists, 0)

    def test_the_written_list_passes_the_checker(self):
        """Run the produced script: either listed md5 passes, another fails."""
        produced, _, _, _ = self._export([dict(self.CORRECTED, md5=[C, SECOND])], LISTING)
        namespace: dict = {"__name__": "batocera_systems"}
        exec(compile(produced, "batocera-systems", "exec"), namespace)  # noqa: S102
        item = namespace["systems"]["psx"]["biosFiles"][0]
        self.assertEqual(item["md5"], [C, SECOND])
        scratch = REPO_ROOT / "tmp"
        with tempfile.TemporaryDirectory(dir=scratch if scratch.is_dir() else None) as tmp:
            (Path(tmp) / "bios").mkdir()
            systems = {"psx": {"name": "PSX", "biosFiles": [item]}}
            for payload, missing in (
                (b"second", {}),
                (b"other", {"psx": {"bios/scph5500.bin": "UNTESTED"}}),
            ):
                (Path(tmp) / "bios" / "scph5500.bin").write_bytes(payload)
                with self.subTest(payload):
                    self.assertEqual(namespace["checkBios"](systems, tmp, False), missing)

    def test_an_item_with_altmd5_stays_a_string(self):
        """checkBios nests [md5, altmd5]: a list there matches no digest."""
        exporter = discover_exporters()["batocera"]()
        exporter._md5_lists = md5_list_support(LISTING)
        platform = {"name": "pack.zip", "md5": A, "alt_md5": B, "zipped_file": "rom.bin"}
        fe = NativeFile("pack.zip", "pack.zip", "psx", platform=platform,
                        truth={"md5": [A, B, D]})
        self.assertFalse(exporter.md5_list(fe))
        self.assertTrue(exporter.md5_list(
            NativeFile("rom.zip", "rom.zip", "psx", truth={"md5": [A, B]},
                       platform={"name": "rom.zip", "md5": A, "zipped_file": "rom.bin"})
        ))

    def test_the_formats_that_share_the_script_read_the_same_checker(self):
        for name in ("rocknix", "amberelec", "emuelec", "knulli"):
            fe = NativeFile("boot.bin", "boot.bin", "dc", truth={"md5": [A, B]})
            with self.subTest(name):
                exporter = discover_exporters()[name]()
                self.assertFalse(exporter.md5_list(fe))
                exporter._md5_lists = md5_list_support(LISTING)
                self.assertTrue(exporter.md5_list(fe))
                self.assertEqual(exporter.written_list(fe, "md5"), [A, B])


class SitePageShowsAList(unittest.TestCase):
    def test_a_list_reads_as_any_of_its_values(self):
        line = describe_change({
            "kind": "hash_updated", "system": "psx", "name": "scph5500.bin",
            "field": "md5", "old": C, "new": [C, D],
        })
        self.assertEqual(line, f"`psx/scph5500.bin` md5 `{C}` becomes `{C}` or `{D}`")


if __name__ == "__main__":
    unittest.main()
