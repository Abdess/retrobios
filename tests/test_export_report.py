"""The corrected platform files are published with every change named.

export_native printed five examples per kind of change and nothing else
recorded the rest: a platform maintainer had no page to fetch the corrected
file from and no list to check the diff against.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import export_native  # noqa: E402
from siteexports import generate_exports_page, load_export_reports  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _report(platform: str, files: list[str], **changes: object) -> dict:
    report = {
        "platform": platform,
        "originals": {f: f"https://example.org/{platform}/{f}" for f in files},
        "files": files,
        "summary": "3 kept, 1 file added, 7 hashes updated to the emulator source",
        "hashes_updated": [], "hashes_filled": [], "sizes_updated": [],
        "sizes_removed": [], "hashes_cleared": [], "required_aligned": 0,
        "withheld": [], "invalid": [],
    }
    report.update(changes)
    return report


class ExportReportIsWrittenAndRead(unittest.TestCase):
    def test_report_round_trips_through_the_page_loader(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as scratch:
            report = _report("recalbox", ["es_bios.xml"])
            export_native.write_report(Path(scratch) / "recalbox.json", report)
            (Path(scratch) / "recalbox").mkdir()
            self.assertEqual(load_export_reports(scratch), [report])

    def test_a_report_goes_into_a_directory_not_yet_made(self):
        """RetroPie with nothing left to correct writes no file, so its
        output directory was never made and the report crashed --all."""
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as scratch:
            target = Path(scratch) / "fresh" / "retropie.json"
            export_native.write_report(target, _report("retropie", []))
            self.assertTrue(target.exists())

    def test_export_keeps_every_change_not_the_printed_five(self):
        source = (ROOT / "scripts" / "export_native.py").read_text(encoding="utf-8")
        body = source[source.index("def export_platform("):source.index("def write_report(")]
        call = body[body.index("write_report("):]
        for key, value in (
            ("hashes_updated", "applied"), ("hashes_filled", "filled"),
            ("sizes_updated", "resized"), ("sizes_removed", "unsized"),
            ("hashes_cleared", "cleared"), ("invalid", "issues"),
        ):
            self.assertIn(f'"{key}": {value},', call)

    def test_default_output_is_the_published_directory(self):
        source = (ROOT / "scripts" / "export_native.py").read_text(encoding="utf-8")
        self.assertIn('"--output-dir", default="exports"', source)


class CorrectedFilesPage(unittest.TestCase):
    def setUp(self):
        corrected = [f"sys/file{i}.bin md5" for i in range(12)]
        self.reports = [
            _report("recalbox", ["es_bios.xml"], hashes_updated=corrected),
            _report("retropie", ["scriptmodules/a.sh", "scriptmodules/b.sh"],
                    invalid=["bash -n failed on a.sh"],
                    withheld=["a size the format has no field for"]),
        ]
        self.page = generate_exports_page(self.reports, {"recalbox": "Recalbox"})

    def test_every_platform_has_a_row_and_a_section(self):
        self.assertIn("| [Recalbox](#recalbox) | [`es_bios.xml`]", self.page)
        self.assertIn("## Recalbox { #recalbox }", self.page)
        self.assertIn("## retropie { #retropie }", self.page)

    def test_single_file_is_downloadable_raw(self):
        self.assertIn(
            'href="https://raw.githubusercontent.com/Abdess/retrobios/main/exports/recalbox/es_bios.xml"',
            self.page,
        )

    def test_every_section_links_its_changes_as_json(self):
        """exports/batocera.json listed 141 changes and no page or catalog
        entry named it: a maintainer had to scrape the HTML."""
        for platform in ("recalbox", "retropie"):
            self.assertIn(f'href="api/v1/exports/{platform}.json"', self.page)
        source = (ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        publish = source[source.index("def _publish_manifests("):]
        publish = publish[:publish.index("\ndef ")]
        self.assertIn('(_REPO_ROOT / "exports").glob("*.json")', publish)
        self.assertIn('exports = api / "exports"', publish)

    def test_several_files_link_to_their_directory(self):
        self.assertIn("tree/main/exports/retropie", self.page)
        self.assertIn("<summary>The 2 original files it is based on</summary>", self.page)

    def test_every_change_is_listed(self):
        self.assertIn("<summary>Hashes updated to the emulator source (12)</summary>", self.page)
        for i in range(12):
            self.assertIn(f"\n- `sys/file{i}.bin md5`", self.page)

    def test_a_failing_file_is_said_to_fail(self):
        self.assertIn("\n- bash -n failed on a.sh", self.page)
        self.assertIn("\n- a size the format has no field for", self.page)

    def test_nothing_published_says_how_to_build(self):
        self.assertIn("export_native.py --all --fetch", generate_exports_page([], {}))

    def test_site_has_the_page_in_its_nav(self):
        source = (ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        self.assertIn('{"Updated platform files": "exports.md"}', source)
        workflow = (ROOT / ".github" / "workflows" / "deploy-site.yml").read_text(encoding="utf-8")
        self.assertIn('"exports/**"', workflow)


class SummariesReadAsSentences(unittest.TestCase):
    """The page shows each run's summary. RetroPie's joined its parts with
    semicolons and read fs-uae's "(e.g, kick13.rom)" as two file names."""

    def test_an_abbreviation_is_not_a_file_name(self):
        from exporter.retropie_exporter import Exporter as RetroPieExporter

        names = RetroPieExporter._listed("BIOS files (e.g, kick13.rom) i.e. Kickstart")
        self.assertEqual(names, {"kick13.rom"})

    def test_retropie_outcome_has_no_semicolon(self):
        from exporter.retropie_exporter import Exporter as RetroPieExporter

        exporter = RetroPieExporter()
        exporter._skipped = {"whose help text lists no files to add to": ["fs-uae", "amiberry"]}
        text = exporter.outcome({}, {"a.sh": ""})
        self.assertNotIn(";", text)
        self.assertIn("Left as is: amiberry, fs-uae, whose help text lists no files to add to", text)


class ThePageAddressesMaintainersAsPeers(unittest.TestCase):
    """The page offers the platforms' own maintainers a file to take or
    leave. "Their file", "corrected" and "of theirs" read as a verdict on
    their work, which the page is not."""

    def test_the_change_sentence_is_built_from_the_numbers(self):
        from siteexports import change_text

        report = _report("batocera", ["batocera-systems"],
                         hashes_updated=["a md5", "b md5"], required_aligned=3)
        report["counts"] = {"kept": 692, "added": 253, "not_added": 10, "not_kept": 0}
        self.assertEqual(
            change_text(report),
            "692 entries kept, 253 files added, 2 hashes updated, "
            "3 required flags aligned with the code",
        )

    def test_no_wording_that_judges_the_original(self):
        report = _report("batocera", ["batocera-systems"], hashes_updated=["a md5"])
        report["counts"] = {"kept": 1, "added": 0, "not_added": 4, "not_kept": 1}
        page = generate_exports_page([report], {}).lower()
        for word in ("their file", "theirs", "corrected", "wrong", "drift", "left out"):
            self.assertNotIn(word, page)


class TheRunReportStatesWhatTheFileCarries(unittest.TestCase):
    """exports/<platform>.json, the report beside the file offered to a
    maintainer, said "82 hashes corrected" and "854 additions left out":
    the words the exports page avoids, and counts of things not in the file
    mixed into the summary of what is."""

    JUDGING = ("their", "corrected", "wrong", "drift", "left out", "never seen")

    def test_summary_and_messages(self):
        import json  # noqa: PLC0415
        from unittest import mock  # noqa: PLC0415

        from exporter.base_exporter import BaseExporter  # noqa: PLC0415

        class Plain(BaseExporter):
            @staticmethod
            def platform_name() -> str:
                return "plat"

            @staticmethod
            def native_filename() -> str:
                return "list.json"

            @staticmethod
            def requires() -> str:
                return "md5"

            def render(self, systems, report, originals, scraped=None):
                return {"list.json": json.dumps(sorted(
                    fe.name for system in systems.values()
                    for fe in system.files if self.writable(fe)
                ))}

            def validate(self, systems, produced):
                return []

        truth = {"systems": {"psx": {"files": [
            {"name": "a.bin", "md5": "b" * 32, "validation": ["md5"]},
            {"name": "new.bin", "md5": "c" * 32},
            {"name": "nohash.bin", "size": 16},
        ]}}}
        scraped = {"systems": {"psx": {"native_id": "psx", "files": [
            {"name": "a.bin", "destination": "a.bin", "native_system": "psx",
             "md5": "a" * 32},
        ]}}}
        doubled = {"destination": "a.bin", "declarations": []}
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as scratch, \
                mock.patch.object(export_native, "load_inputs",
                                  return_value=(truth, scraped)), \
                mock.patch.object(export_native, "unpinned", return_value=[]), \
                mock.patch.object(export_native, "removal_candidates", return_value=[]), \
                mock.patch.object(export_native, "doubled_in", return_value=[doubled]):
            ok, messages = export_native.export_platform(
                "plat", Plain, Path(scratch), Path(scratch) / "out",
                str(ROOT / "platforms"), Path(scratch) / "cache", False,
            )
            self.assertTrue(ok, messages)
            report = json.loads((Path(scratch) / "out" / "plat.json").read_text())
        self.assertEqual(report["doubled"], [doubled])
        self.assertIn(
            "1 destination declared twice for two files, listed in the report", messages
        )
        self.assertEqual(
            report["summary"],
            "1 kept, 1 file added, 1 hash updated to the emulator source",
        )
        self.assertIn(
            "not in the file: 1 file the format or its checker cannot carry", messages
        )
        self.assertIn("hash updated: psx/a.bin md5", messages)
        for text in [report["summary"], *messages]:
            for word in self.JUDGING:
                self.assertNotIn(word, text.lower())
        # The report is served as api/v1/exports/<platform>.json, keys and
        # change kinds included: "hash_corrected" sat on 130 Recalbox lines.
        names = [*report, *(c["kind"] for c in report["changes"])]
        self.assertIn("hash_updated", names)
        for name in names:
            for word in self.JUDGING:
                self.assertNotIn(word, name)

    def test_the_committed_reports_use_the_same_names(self):
        import json  # noqa: PLC0415

        for path in sorted((ROOT / "exports").glob("*.json")):
            report = json.loads(path.read_text(encoding="utf-8"))
            names = [*report, *(c["kind"] for c in report.get("changes") or [])]
            with self.subTest(report=path.name):
                self.assertFalse([n for n in names if "corrected" in n])


UPSTREAM_CACHE = ROOT / ".cache" / "upstream-native"
_DAT_ROM = re.compile(r"^\trom \( name (\"[^\"]+\"|\S+) (.*) \)$")
_DAT_FIELDS = {"size": "size", "crc": "crc32", "md5": "md5", "sha1": "sha1"}
_HASH_KINDS = {
    "hash_updated", "hash_filled", "hash_cleared", "size_updated", "size_removed",
}


def _norm(value: object) -> str | None:
    """A value as the frontend reads it: a list split on commas, each value
    stripped, so the layout of a wrapped attribute is not a change."""
    if value in (None, ""):
        return None
    return ",".join(v.strip() for v in str(value).casefold().split(","))


def _parse_dat(text: str) -> dict[tuple[str, str], dict[str, str]]:
    """Each rom line of a System.dat, keyed by its section and rom name."""
    roms: dict[tuple[str, str], dict[str, str]] = {}
    section = ""
    for line in text.splitlines():
        if line.startswith('\tcomment "'):
            section = line.split('"')[1]
            continue
        match = _DAT_ROM.match(line)
        if not match:
            continue
        tokens = match.group(2).split()
        fields = {
            _DAT_FIELDS[tokens[i]]: tokens[i + 1]
            for i in range(0, len(tokens) - 1, 2) if tokens[i] in _DAT_FIELDS
        }
        roms.setdefault((section, match.group(1).strip('"')), fields)
    return roms


def _parse_es_bios(text: str) -> dict[tuple[str, str], dict[str, str]]:
    """Each bios element of an es_bios.xml, keyed by system and path."""
    from common import parse_untrusted_xml

    root = parse_untrusted_xml(text)
    elements: dict[tuple[str, str], dict[str, str]] = {}
    for system in root.iter("system"):
        for bios in system.iter("bios"):
            elements.setdefault((system.get("platform", ""), bios.get("path", "")), {
                "md5": bios.get("md5", ""),
                "required": "false" if bios.get("mandatory") == "false" else "true",
            })
    return elements


class ReportedChangesAreTheDiff(unittest.TestCase):
    """The report gives each change its value before and after. Read back
    from the original and the updated file, the two must agree entry by
    entry, or a maintainer checks the diff against a list that differs."""

    def _run(self, platform: str, filename: str) -> tuple[list[dict], str, str, dict]:
        from common import load_platform_config, native_layer
        from exporter import discover_exporters
        from exporter.baseline import build_native_model

        original_path = UPSTREAM_CACHE / platform / filename
        if not original_path.is_file():
            self.skipTest(f"no cached original for {platform}")
        config = load_platform_config(platform, str(ROOT / "platforms"))
        truth = export_native.current_truth(platform, config, str(ROOT / "platforms"))
        scraped = native_layer(config)
        systems, report = build_native_model(truth, scraped)
        exporter = discover_exporters()[platform]()
        original = original_path.read_text(encoding="utf-8")
        originals = {
            p.name: p.read_text(encoding="utf-8")
            for p in (UPSTREAM_CACHE / platform).iterdir() if p.is_file()
        }
        produced = exporter.render(systems, report, originals, scraped)[filename]
        changes = export_native.landed_changes(exporter, systems).records
        return changes, original, produced, {"exporter": exporter, "systems": systems}

    @staticmethod
    def _diff(before: dict, after: dict) -> tuple[set, set]:
        changed = {
            (key, name, _norm(before[key].get(name)), _norm(after[key].get(name)))
            for key in before.keys() & after.keys()
            for name in before[key].keys() | after[key].keys()
            if _norm(before[key].get(name)) != _norm(after[key].get(name))
        }
        return changed, set(after) - set(before)

    def test_system_dat(self):
        changes, original, produced, ctx = self._run("retroarch", "System.dat")
        exporter = ctx["exporter"]
        rom_name = {
            (fe.native_system, fe.name, fe.destination): exporter._rom_name(fe)
            for system in ctx["systems"].values() for fe in system.files
        }
        changed, added = self._diff(_parse_dat(original), _parse_dat(produced))
        reported = {
            ((c["system"], rom_name[(c["system"], c["name"], c["destination"])]),
             c["field"], _norm(c["old"]), _norm(c["new"]))
            for c in changes if c["kind"] in _HASH_KINDS
        }
        self.assertTrue(changed, "nothing changed, the comparison proves nothing")
        self.assertEqual(reported, changed)
        reported_added = {
            (c["system"], rom_name[(c["system"], c["name"], c["destination"])])
            for c in changes if c["kind"] == "added"
        }
        self.assertEqual(reported_added, added)

    def test_recalbox(self):
        changes, original, produced, ctx = self._run("recalbox", "es_bios.xml")
        exporter = ctx["exporter"]
        path_of = {
            (fe.native_system, fe.name, fe.destination): exporter._path(fe)
            for system in ctx["systems"].values() for fe in system.files
        }
        changed, added = self._diff(_parse_es_bios(original), _parse_es_bios(produced))
        reported = {
            ((c["system"], path_of[(c["system"], c["name"], c["destination"])]),
             c["field"], _norm(c["old"]), _norm(c["new"]))
            for c in changes
            if c["kind"] in _HASH_KINDS or c["kind"] == "required_aligned"
        }
        self.assertTrue(changed, "nothing changed, the comparison proves nothing")
        self.assertEqual(reported, changed)
        reported_added = {
            (c["system"], path_of[(c["system"], c["name"], c["destination"])])
            for c in changes if c["kind"] == "added"
        }
        self.assertEqual(reported_added, added)

    def test_retropie(self):
        """Each addition is a name a help sentence gains, and no other: the
        report counted every file a profiled core reads as added."""
        from common import load_platform_config, native_layer
        from exporter import discover_exporters
        from exporter.baseline import build_native_model

        archive = UPSTREAM_CACHE / "retropie" / "RetroPie-Setup.tar.gz"
        if not archive.is_file():
            self.skipTest("no cached original for retropie")
        config = load_platform_config("retropie", str(ROOT / "platforms"))
        truth = export_native.current_truth("retropie", config, str(ROOT / "platforms"))
        scraped = native_layer(config)
        systems, report = build_native_model(truth, scraped)
        exporter = discover_exporters()["retropie"]()
        originals = exporter.unpack(archive.read_bytes())
        produced = exporter.render(systems, report, originals, scraped)
        self.assertTrue(produced, "nothing changed, the comparison proves nothing")
        gained: set[str] = set()
        for relative, text in produced.items():
            before = exporter.modules({relative: originals[relative]})[relative][1]
            after = exporter.modules({relative: text})[relative][1]
            gained |= exporter._listed(after) - exporter._listed(before)
        changes = export_native.landed_changes(exporter, systems).records
        reported = {c["name"].lower() for c in changes if c["kind"] == "added"}
        self.assertEqual(reported, gained)
        self.assertEqual(
            sum(c["kind"] == "added" for c in changes), len(gained),
            "one name counted under several entries",
        )


class ThePageShowsEachValueBeforeAndAfter(unittest.TestCase):
    """A list of names gave a maintainer nothing to check a correction
    against: each line now says what the value was and what it becomes."""

    def setUp(self):
        def change(kind: str, field: str | None, old: object, new: object) -> dict:
            return {"kind": kind, "system": "psx", "name": "scph5501.bin",
                    "destination": "scph5501.bin", "field": field,
                    "old": old, "new": new}

        self.report = _report(
            "recalbox", ["es_bios.xml"],
            hashes_updated=["psx/scph5501.bin md5"], required_aligned=1,
            changes=[
                change("hash_updated", "md5", "5626" + "0" * 28, "c523" + "1" * 28),
                change("required_aligned", "required", True, False),
                change("hash_filled", "sha1", None, "f" * 40),
            ],
        )
        self.page = generate_exports_page([self.report], {})

    def test_a_corrected_hash_shows_both_values(self):
        self.assertIn(
            f"\n- `psx/scph5501.bin` md5 `5626{'0' * 28}` becomes `c523{'1' * 28}`",
            self.page,
        )

    def test_a_requirement_names_the_entry_and_its_value(self):
        self.assertIn("<summary>Required flags aligned with the code (1)</summary>", self.page)
        self.assertIn("\n- `psx/scph5501.bin` becomes optional", self.page)

    def test_a_filled_hash_shows_its_value(self):
        self.assertIn(f"\n- `psx/scph5501.bin` sha1 `{'f' * 40}` added", self.page)

    def test_no_arrow_glyph(self):
        for glyph in (chr(0x2192), "->", "=>"):
            self.assertNotIn(glyph, self.page)

    def test_the_report_carries_every_change(self):
        source = (ROOT / "scripts" / "export_native.py").read_text(encoding="utf-8")
        body = source[source.index("def export_platform("):source.index("def write_report(")]
        self.assertIn('"changes": changes.records,', body)


class RemovalCandidatesNeedAReadingNoCoreAnswers(unittest.TestCase):
    """An entry the truth does not pair can still be read: by an alias, by its
    content, under a directory a core walks. Of 2776 such entries, 1189
    were read that way. Only what no core answers is listed, and nothing is
    removed."""

    PROFILES = {
        "corea": {
            "type": "libretro",
            "systems": ["sys-one"],
            "files": [
                {"name": "main.rom", "aliases": ["Alt.ROM"]},
                {"name": "other.bin", "md5": "0123456789abcdef0123456789abcdef"},
                {"name": "rtp/2000/", "path": "rtp/2000/", "type": "directory"},
                {"name": "set.zip", "category": "bios_zip"},
            ],
        },
    }

    def _scraped(self, names: list[dict], cores: list[str]) -> dict:
        return {
            "_key": "fake",
            "cores": cores,
            "systems": {"sys-one": {"files": names}},
        }

    def _candidates(self, files: list[dict], cores: list[str] | None = None) -> list[dict]:
        from exporter.baseline import build_native_model
        from exporter.candidates import removal_candidates

        scraped = self._scraped(files, cores or ["corea"])
        systems, _ = build_native_model({"systems": {}}, scraped)
        found = removal_candidates(systems, scraped, self.PROFILES)
        kept = [f.name for s in systems.values() for f in s.files]
        self.assertEqual(kept, [f["name"] for f in files])
        return found

    def test_a_name_the_platform_launcher_opens_is_a_reading(self):
        """Batocera's DuckStation generator walks 22 names (bios_lists,
        duckstationGenerator.py:501-515): a name it opens is read on
        Batocera whatever the profiles call it."""
        from exporter.baseline import build_native_model
        from exporter.candidates import removal_candidates

        scraped = self._scraped([{"name": "scph7502.bin"}], ["corea"])
        scraped["launchers"] = [{
            "emulator": "corea", "build": "libretro", "kind": "names_searched",
            "names": ["scph1001.bin", "scph7502.bin"], "source_ref": "gen.py:1-2",
        }]
        systems, _ = build_native_model({"systems": {}}, scraped)
        self.assertEqual(removal_candidates(systems, scraped, self.PROFILES), [])

    def test_an_alias_is_a_reading(self):
        self.assertEqual(self._candidates([{"name": "alt.rom"}]), [])

    def test_a_hash_is_a_reading(self):
        found = self._candidates([
            {"name": "renamed.bin", "md5": "0123456789ABCDEF0123456789ABCDEF"},
        ])
        self.assertEqual(found, [])

    def test_a_directory_entry_covers_its_members(self):
        found = self._candidates([
            {"name": "x.png", "destination": "easyrpg/rtp/2000/x.png"},
        ])
        self.assertEqual(found, [])

    def test_an_entry_nothing_answers_is_a_candidate(self):
        found = self._candidates([{"name": "nobody.rom"}])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["verdict"], "candidate")
        self.assertEqual(found[0]["cores_examined"], ["corea"])
        self.assertEqual(found[0]["unresolved_cores"], [])

    def test_an_unprofiled_core_leaves_it_undetermined(self):
        found = self._candidates([{"name": "nobody.rom"}], ["corea", "mystery-sa"])
        self.assertEqual(found[0]["verdict"], "undetermined")
        self.assertEqual(found[0]["unresolved_cores"], ["mystery-sa"])

    def test_a_romset_under_a_romset_core_is_undetermined(self):
        found = self._candidates([{"name": "device.zip"}])
        self.assertEqual(found[0]["verdict"], "undetermined")
        self.assertIn("corea", found[0]["reason"])

    def test_unresolved_names_skip_the_all_libretro_markers(self):
        from common import unresolved_platform_cores

        config = {"cores": ["retroarch", "all_libretro", "corea", "nope"]}
        self.assertEqual(unresolved_platform_cores(config, self.PROFILES), {"nope"})
        self.assertEqual(unresolved_platform_cores({"cores": "all_libretro"}, {}), set())

    def test_the_page_gives_the_count_and_each_entry(self):
        report = _report("retroarch", ["System.dat"], removal_candidates=[
            {"system": "Enterprise", "name": "zt18hfnt.rom",
             "destination": "zt18hfnt.rom", "verdict": "candidate",
             "reason": "no core the platform runs opens it",
             "cores_examined": [], "unresolved_cores": []},
        ])
        page = generate_exports_page([report], {})
        self.assertIn("1 entry of the original is not named, by name, path or hash", page)
        self.assertIn("- `Enterprise` `zt18hfnt.rom`", page)
        self.assertNotIn("no entry the platform declares is removed", page)

    def test_the_report_carries_the_list(self):
        source = (ROOT / "scripts" / "export_native.py").read_text(encoding="utf-8")
        body = source[source.index("def export_platform("):source.index("def write_report(")]
        self.assertIn('"removal_candidates": candidates,', body)


class ADestinationDeclaredTwiceIsNamed(unittest.TestCase):
    """RetroDECK aims a PC-88 disk ROM and a CoCo disk ROM at one
    bios/disk.rom, each with its own md5. One path holds one file, so one
    check fails on every install. The export keeps both entries and names
    the contradiction, with the emulators that read each file."""

    PC88 = b"\x01" * 2048
    COCO = b"\x02" * 8194

    def setUp(self):
        import hashlib  # noqa: PLC0415

        self._tmp = tempfile.TemporaryDirectory(dir=ROOT / "tmp")
        root = Path(self._tmp.name)
        files, by_md5, by_name = {}, {}, {}
        self.md5 = {}
        for label, data, rel in (
            ("pc88", self.PC88, "bios/NEC/PC-88/N88SUB.ROM"),
            ("coco", self.COCO, "bios/Tandy/CoCo/disk.rom"),
        ):
            path = root / rel
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            self.md5[label] = md5
            files[sha1] = {"path": str(path), "name": path.name, "md5": md5,
                           "sha1": sha1, "crc32": "", "size": len(data)}
            by_md5[md5] = sha1
            by_name.setdefault(path.name, []).append(sha1)
        self.db = {"files": files, "indexes": {
            "by_md5": by_md5, "by_name": by_name, "by_crc32": {}, "by_path_suffix": {},
        }}
        self.scraped = {"cores": ["pcemu", "cocoemu"], "systems": {
            "nec-pc-88": {"files": [
                {"name": "disk.rom", "destination": "bios/disk.rom",
                 "md5": self.md5["pc88"], "native_system": "pc88",
                 "component": "retroarch"},
            ]},
            "coco": {"files": [
                {"name": "disk.rom", "destination": "bios/disk.rom",
                 "md5": self.md5["coco"], "native_system": "coco",
                 "component": "xroar"},
            ]},
        }}
        self.profiles = {
            "pcemu": {"emulator": "PC Emu", "type": "libretro", "systems": ["nec-pc-88"],
                      "files": [{"name": "n88sub.rom", "aliases": ["disk.rom"],
                                 "size": 2048, "source_ref": "libretro.c:120"}]},
            "cocoemu": {"emulator": "CoCo Emu", "type": "libretro", "systems": ["coco"],
                        "files": [{"name": "disk11.rom", "source_ref": "xroar.c:714"}]},
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _doubled(self) -> list[dict]:
        from exporter.doubled import doubled_destinations  # noqa: PLC0415

        return doubled_destinations(self.scraped, self.profiles, self.db)

    def test_each_declaration_is_named_with_its_reader(self):
        doubled = self._doubled()
        self.assertEqual([d["destination"] for d in doubled], ["bios/disk.rom"])
        pc88, coco = doubled[0]["declarations"]
        self.assertEqual((pc88["system"], pc88["component"]), ("pc88", "retroarch"))
        self.assertEqual(pc88["hashes"], {"md5": [self.md5["pc88"]]})
        self.assertTrue(pc88["file"].endswith("bios/NEC/PC-88/N88SUB.ROM"))
        self.assertEqual(pc88["readers"], [{
            "emulator": "PC Emu", "profile": "pcemu", "entry": "n88sub.rom",
            "source_ref": "libretro.c:120",
        }])
        # A size the profile states rules out the CoCo ROM, and XRoar's own
        # profile never opens disk.rom.
        self.assertEqual((coco["system"], coco["component"]), ("coco", "xroar"))
        self.assertEqual(coco["hashes"], {"md5": [self.md5["coco"]]})
        self.assertEqual(coco["readers"], [])

    def test_the_platform_entries_are_left_as_written(self):
        import copy  # noqa: PLC0415

        before = copy.deepcopy(self.scraped)
        self._doubled()
        self.assertEqual(self.scraped, before)

    def test_a_destination_both_hashes_accept_is_not_doubled(self):
        self.scraped["systems"]["coco"]["files"][0]["md5"] = (
            f"{self.md5['coco']},{self.md5['pc88']}"
        )
        self.assertEqual(self._doubled(), [])

    def test_the_run_counts_it_and_the_report_carries_it(self):
        source = (ROOT / "scripts" / "export_native.py").read_text(encoding="utf-8")
        body = source[source.index("def export_platform("):source.index("def write_report(")]
        self.assertIn('"doubled": doubled,', body)
        self.assertIn("declared twice for two files", body)

    def test_the_page_names_each_declaration(self):
        page = generate_exports_page(
            [_report("retrodeck", ["a.json"], doubled=self._doubled())], {})
        self.assertIn("1 destination of the original is declared twice", page)
        self.assertIn("- `bios/disk.rom`", page)
        self.assertIn(
            f"  - `pc88` (`retroarch`) md5 `{self.md5['pc88']}`: read by PC Emu "
            "(`libretro.c:120`)", page)
        self.assertIn(
            f"  - `coco` (`xroar`) md5 `{self.md5['coco']}`: no emulator this "
            "platform runs is known to read this file", page)


if __name__ == "__main__":
    unittest.main()
