"""Audit regressions on the generated site: cards, gap pages, structured data and exports."""

from __future__ import annotations

import tests
from tests.sources import script_source
import contextlib
import io
import re
import sys
import unittest
from pathlib import Path
from unittest import mock
from tests import REPO_ROOT


class TheSiteCountsSlotsNotVersions(unittest.TestCase):
    """raze lists every GRP its code accepts under one name: the site said
    59 files, 46 missing, where verify --emulator said 23 slots, 12 missing."""

    def test_one_held_version_fills_the_slot(self):
        from scripts.sitegen.emulatorintro import emulator_file_summary, emulator_held_line

        files = [
            {"name": "DUKE3D.GRP", "crc32": "1"},
            {"name": "DUKE3D.GRP", "crc32": "2"},
            {"name": "BLOOD.RFF", "crc32": "3"},
        ]
        line = emulator_file_summary(files)[0]
        self.assertIn("**2 files** (3 accepted versions)", line)
        held = emulator_held_line(files, lambda f: f.get("crc32") == "2")[0]
        self.assertIn("1 in repo and 1 missing", held)


class TheWantedPageCountsRomsetMembers(unittest.TestCase):
    """The site called build_report without archive_members: the public
    Wanted page asked for dumps the collection holds inside romsets."""

    def test_members_are_read_unless_given(self):
        from scripts.acquire import provenance

        calls = []

        def members(db, root):
            calls.append(db)
            return {}

        with mock.patch.object(provenance, "archive_members", members):
            provenance.build_report({"files": {}}, {})
            provenance.build_report({"files": {}}, {}, {})
        self.assertEqual(len(calls), 1)


class TheGapReportKeepsItsShape(unittest.TestCase):
    """Multi-line notes fell to column 0 and read as emulator headings, a
    profile without systems printed `Abuse ()`, `*` had no legend, and
    --platform totals said "across all emulators"."""

    def test_layout(self):
        from scripts.packs.crossreftext import print_report

        report = {"abuse": {
            "emulator": "Abuse", "systems": [], "gaps": 1, "total_files": 1,
            "platform_covered": 0, "gap_missing": 1,
            "gap_details": [{"name": "a.spe", "required": True, "source": "missing",
                             "note": "first line\nsecond line"}],
        }}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_report(report, "the emulators batocera runs")
        text = out.getvalue()
        self.assertIn("* marks a file the emulator requires", text)
        self.assertIn("\nAbuse\n", text)
        self.assertIn("a.spe [MISSING]: first line second line", text)
        self.assertIn("across the emulators batocera runs", text)


class AFileToSourceIsAFileNotAName(unittest.TestCase):
    """The gaps page keyed acquisition targets by name: Fallout 2's
    master.dat disappeared behind Fallout 1's."""

    def test_rows_are_keyed_by_name_and_hash(self):
        source = script_source("generate_site.py")
        self.assertIn('key = (g["name"], g.get("identity") or f"emulator:{emu_name}")', source)
        from scripts.packs.crossrefsource import first_hash

        self.assertEqual(first_hash({"md5": ["AB", "cd"]}), "md5:ab")
        self.assertEqual(first_hash({"crc32": "1", "sha1": "F" * 40}), "sha1:" + "f" * 40)
        self.assertEqual(first_hash({}), "")


class AFileCardSaysAllItKnows(unittest.TestCase):
    """Emulator pages cut a set at 10 members without their hashes, never
    showed standalone_path, and gave no file an anchor to link to."""

    def test_members_standalone_path_and_anchor(self):
        from scripts.sitegen.emulatorcards import render_emulator_file

        entry = {
            "name": "neogeo.zip", "path": "neogeo.zip", "category": "bios_zip",
            "standalone_path": "Firmware/neogeo.zip",
            "contents": [{"name": f"m{i}.bin", "size": 1024, "crc32": f"{i:08x}"}
                         for i in range(12)],
        }
        text = "\n".join(render_emulator_file(
            entry, {"files": [entry]}, None, [entry], lambda f: True, "file-neogeo-zip",
        ))
        # The card is a heading with this id, linked by the heading's own
        # permalink.
        self.assertIn('<h3 id="file-neogeo-zip" class="rb-file-title"', text)
        self.assertIn("Standalone path: `Firmware/neogeo.zip`", text)
        self.assertIn("`m11.bin`", text)
        self.assertIn("CRC32 `0000000b`", text)
        self.assertNotIn("more", text)


class EmulatorPagesStateTheirDataForMachines(unittest.TestCase):
    """Every emulator page's JSON-LD differed only by name and url."""

    def test_source_pin_date_and_files(self):
        from scripts.sitegen.structured import emulator_structured_data

        data = emulator_structured_data({
            "emulator": "DuckStation", "source": "https://github.com/stenzek/duckstation",
            "source_commit": "4122fed9", "core_version": "v0.1-12070",
            "profiled_date": "2026-03-23",
            "files": [{"name": "scph5501.bin", "md5": "490F666E", "sha1": ["a" * 40]},
                      {"name": "free.bin"}],
        })
        self.assertEqual(data["about"]["codeRepository"], "https://github.com/stenzek/duckstation")
        # The release the profile describes, never the pin.
        self.assertEqual(data["about"]["version"], "v0.1-12070")
        self.assertNotIn("description", data["about"])
        self.assertEqual(data["dateModified"], "2026-03-23")
        self.assertEqual(data["hasPart"][0]["identifier"], ["sha1:" + "a" * 40, "md5:490f666e"])
        self.assertNotIn("identifier", data["hasPart"][1])

    def test_every_repository_with_its_own_release(self):
        """xemu's libretro build lives in another repository. Each source
        repository states the release of its build, a version holding a
        commit id states none, and a port's upstream is another code base."""
        from scripts.sitegen.structured import emulator_structured_data

        data = emulator_structured_data({
            "emulator": "MesenCE",
            "source": {"standalone": "https://github.com/nesdev-org/MesenCE",
                       "libretro": "https://github.com/libretro/MesenCE"},
            "source_commit": {"standalone": "f9b14039", "libretro": "d9804db7"},
            "core_version": {"standalone": "2.2.1", "libretro": "2.0.0"},
            "upstream": "https://github.com/SourMesen/Mesen2", "upstream_commit": "aa11",
        })
        self.assertEqual(
            [(a["codeRepository"].rsplit("/", 1)[1], a.get("version")) for a in data["about"]],
            [("MesenCE", "2.2.1"), ("MesenCE", "2.0.0"), ("Mesen2", None)])
        xemu = emulator_structured_data({
            "emulator": "xemu",
            "source": {"standalone": "https://github.com/xemu-project/xemu",
                       "libretro": "https://github.com/LibretroAdmin/xemu-libretro"},
            "core_version": {"standalone": "0.8.139-2-g25e1ee2fd5",
                             "libretro": "libretro-experimental"},
        })
        self.assertEqual([a.get("version") for a in xemu["about"]], [None, None])


class AdlerValuesReadLikeTheDownloads(unittest.TestCase):
    """The Dolphin card read Adler32: `['0x66f334fe', '0xe789b5a5']`, a list
    repr no download spells, and never said the values are taken over the
    byte-swapped ROM, so the raw ea3734fe in files.csv matched neither."""

    def test_values_and_the_swap_are_stated(self):
        from scripts.sitegen.emulatorcards import render_emulator_file

        entry = {"name": "dsp_rom.bin", "path": "dsp_rom.bin",
                 "known_hash_adler32": ["0x66f334fe", "0xE789B5A5"],
                 "adler32_byteswap": True}
        text = "\n".join(render_emulator_file(
            entry, {"files": [entry]}, None, [entry], lambda f: True, "file-dsp",
        ))
        self.assertIn("`66f334fe`, `e789b5a5`", text)
        self.assertIn("byte-swapped", text)
        self.assertNotIn("['", text)


class GapsPageCountsOneWay(unittest.TestCase):
    """The stats block said 1 untested (by destination) while Problem Files
    listed 4 untested entries, three of them at paths another declaration
    of the same platform already holds."""

    def test_settled_declarations_are_listed_apart(self):
        from scripts.sitegen.gapproblems import render_problem_files

        problems = [{"platform": "RetroDECK", "name": "dsifirmware.bin", "status": "untested",
                     "required": True, "reason": "x", "discrepancy": ""}]
        settled = [{"platform": "RetroDECK", "name": "cdibios.zip", "status": "untested",
                    "held_by": "arcade"}]
        text = "\n".join(render_problem_files(problems, settled))
        self.assertIn("0 missing, 1 untested", text)
        self.assertIn("Other revisions of a held destination", text)
        self.assertIn("`cdibios.zip`", text)

    def test_missing_says_the_destination_count_of_the_opening_sentence(self):
        # The page opened on "48 are missing" (by destination) above a
        # heading that said "10 files": one row per name.
        from scripts.sitegen.gapproblems import render_problem_files

        problems = [{"platform": "AmberELEC", "name": "hardwareconfig.xml",
                     "status": "missing", "required": True, "reason": "",
                     "discrepancy": "", "category": "unread"}] * 3
        text = "\n".join(render_problem_files(problems, missing_total=3))
        self.assertIn("3 missing under 1 name,", text)
        self.assertIn('rb-badge-danger">1 name</span>', text)
        self.assertNotIn("1 missing", text)

    def test_a_missing_row_links_each_entry_and_names_its_folder(self):
        """The row said `N88_KNJ1.ROM | unread | yes | AmberELEC` in plain text:
        neither where the list puts it nor which cores were examined."""
        from scripts.sitegen.gapproblems import render_problem_files

        problems = [{"platform": "AmberELEC", "platform_key": "amberelec", "name": "N88_KNJ1.ROM",
                     "status": "missing", "required": True, "reason": "", "discrepancy": "",
                     "category": "unread", "system": "nec-pc-88",
                     "destination": "bios/quasi88/N88_KNJ1.ROM"}]
        text = "\n".join(render_problem_files(problems))
        self.assertIn("| [AmberELEC](platforms/amberelec.md#nec-pc-88) "
                      "`bios/quasi88/N88_KNJ1.ROM` |", text)

    def test_the_destination_is_the_list_entrys(self):
        """AmberELEC declares hardwareconfig.xml under eighteen MSX folders:
        each missing one is shown under its own, not under the first."""
        from scripts.sitegen.gaps import _verify_tally
        from model.platforms import load_platform_config

        config = load_platform_config("amberelec", str(REPO_ROOT / "platforms"))
        details, wanted = [], []
        for system, data in (config.get("systems") or {}).items():
            for entry in data.get("files") or []:
                missing = entry["name"] in ("hardwareconfig.xml", "N88_KNJ1.ROM")
                details.append({"name": entry["name"], "system": system,
                                "status": "missing" if missing else "ok"})
                if missing:
                    wanted.append(str(entry.get("destination") or entry["name"]))
        coverage = {"platform": "AmberELEC", "config": config, "details": details,
                    "verified": 0, "untested": 0, "missing": len(wanted), "total": len(details)}
        tally = _verify_tally({"amberelec": coverage})
        shown = [p["destination"] for p in tally.problems]
        self.assertEqual(shown, wanted)
        self.assertGreater(len(set(shown)), 2)
        self.assertIn("bios/quasi88/N88_KNJ1.ROM", shown)

    def test_verify_marks_the_settled_entry(self):
        from packs import platformtally
        from packs import verdicts

        result = {"name": "cdibios.zip", "status": verdicts.Status.UNTESTED}
        self.assertTrue(platformtally._twin_unmet(result, "arcade"))
        self.assertEqual(result["settled_by"], "arcade")


class UnsourceableCardSaysWhy(unittest.TestCase):
    """DraStic's nds_firmware_modified.bin carried an 'unsourceable' badge
    and nothing else. The reason was only on the gaps page."""

    def test_reason_and_link(self):
        from scripts.sitegen.emulatorcards import render_emulator_file

        entry = {"name": "nds_firmware_modified.bin", "path": "x.bin",
                 "unsourceable": "written by the firmware editor, so no dump of it exists"}
        text = "\n".join(render_emulator_file(
            entry, {"files": [entry]}, None, [entry], lambda f: False, "file-x",
        ))
        self.assertIn("Not collected yet: written by the firmware editor", text)
        self.assertIn("../gaps-not-collected.md", text)
        self.assertNotIn("collectable", text)

    def test_the_gaps_page_names_where_a_wanted_file_is_listed(self):
        """The section read "Acknowledged gaps ... (verified from source
        code)" while No-Intro lists XM7's KANJI2.ROM and MAME's fm7740sx.zip
        carries it: the flag only keeps a homonym out, the file is wanted."""
        from scripts.sitegen.gaps import generate_gap_analysis

        unsourced = {"name": "KANJI2.ROM", "reason": "no dump distributed", "source_ref": ""}
        report = {"xm7": {"emulator": "XM7", "gaps": 0, "gap_missing": 0, "gap_bios": 0,
                          "unsourceable": [unsourced], "gap_details": []}}
        catalogued = {"no-intro": {"missing": [{
            "name": "KANJI2.rom",
            "romsets": [{"source": "mame", "archive": "fm7740sx.zip"}],
            "needed_by": [{"emulator": "xm7", "name": "KANJI2.ROM", "required": True}],
        }]}}
        page = generate_gap_analysis(
            {"xm7": {"emulator": "XM7", "files": [{"name": "KANJI2.ROM",
                                                   "unsourceable": "no dump distributed"}]}},
            {}, {"files": {}, "indexes": {}}, gap_report=report, catalogued=catalogued)
        self.assertIn("## Not collected yet", page)
        self.assertIn('<span id="acknowledged-gaps"></span>', page)
        self.assertIn("| No-Intro `KANJI2.rom`, mame `fm7740sx.zip` | yes |", page)
        self.assertNotIn("Acknowledged", page)
        self.assertNotIn("verified from source code", page)


class CollectionCardsSayWhereToGetTheFile(unittest.TestCase):
    """A system page card gave the hashes, readers and provenance of
    scph5501.bin and no path or link to the bytes."""

    def test_raw_and_release_asset_urls(self):
        from scripts.sitegen import cards

        cards._RELEASE_ASSET_NAMES = None
        self.addCleanup(setattr, cards, "_RELEASE_ASSET_NAMES", None)
        self.assertEqual(
            cards.fetch_url("bios/Sony/PlayStation/scph5501.bin"),
            "https://raw.githubusercontent.com/Abdess/retrobios/main/bios/Sony/PlayStation/scph5501.bin",
        )
        self.assertTrue(cards.fetch_url("bios/Arcade/MAME/MAME 0.174 Arcade XML.dat").endswith(
            "/releases/download/large-files/MAME.0.174.Arcade.XML.dat"
        ))


class CollectionCardsCarryFullHashes(unittest.TestCase):
    """A pasted md5 or crc32 found nothing: cards showed 12 characters of
    SHA1 and MD5 (the rest in a title the search does not index) and no
    CRC32 or SHA256."""

    def test_every_hash_in_full(self):
        from scripts.packs.consumers import FileConsumers
        from scripts.sitegen.cards import system_file_card

        entry = {"name": "DUKE.RTS", "path": "bios/x/DUKE.RTS", "size": 10,
                 "sha1": "a" * 40, "md5": "9d29f9673bbdb56068acf7645c13749c",
                 "crc32": "504086c1", "sha256": "b" * 64}
        text = "\n".join(system_file_card(entry, FileConsumers({}, {})))
        for value in (entry["sha1"], entry["md5"], entry["crc32"], entry["sha256"]):
            self.assertIn(f'<dd class="rb-hash">{value}</dd>', text)


class AHeldRevisionLinksItsBuildFile(unittest.TestCase):
    """advanced_drastic's page printed the KNULLI build file that holds its
    revision as plain text, while pin_build carries the repository, the tag
    and the path a pinned link needs. 36 profiles carry one."""

    def test_the_build_file_row(self):
        from scripts.sitegen.emulatorcards import build_rows

        rows = build_rows({"pin_frozen": "KNULLI builds this revision.", "pin_build": [{
            "platform": "knulli", "repo": "https://github.com/knulli-cfw/knulli-linux",
            "revision": "20260511", "path": "package/emulators/advanced_drastic/advanced_drastic.mk",
            "variable": "ADVANCED_DRASTIC_VERSION", "value": "eaf41ab9"}]})
        # A tag can move: named, never linked.
        self.assertIn(
            "| Build file | KNULLI `package/emulators/advanced_drastic/advanced_drastic.mk` "
            "at `20260511` sets `ADVANCED_DRASTIC_VERSION` |", rows)

    def test_a_build_read_at_a_recorded_commit_links(self):
        from scripts.sitegen.emulatorcards import build_rows

        pin = "46128cd252cdecae852a4d0bafa2aaf9d03ab563"
        rows = build_rows({"pin_build": [{
            "platform": "retropie", "repo": "https://github.com/RetroPie/RetroPie-Setup",
            "revision": pin, "path": "scriptmodules/emulators/advmame-1.4.sh",
            "variable": "rp_module_repo", "value": "x"}]})
        self.assertIn(
            f"[RetroPie `scriptmodules/emulators/advmame-1.4.sh`](https://github.com/RetroPie/"
            f"RetroPie-Setup/blob/{pin}/scriptmodules/emulators/advmame-1.4.sh)", rows[0])

    def test_the_record_holds_the_build_files(self):
        from sitegen import sources as sitegen_sources

        files = sitegen_sources.build_files({"pin_build": [
            {"repo": "https://github.com/o/r", "revision": "a" * 40, "path": "p.mk"},
            {"repo": "https://github.com/o/r", "revision": "v1", "path": "q.mk"}]})
        self.assertEqual([(f[1], f[2]) for f in files], [("a" * 40, "p.mk")])


class AVariantCardSaysWhatToSaveItAs(unittest.TestCase):
    """The Download button of a .variants/ card saved advision.zip.1c086064,
    the storage name, and nothing said RetroBat looks for advision.zip."""

    def test_the_name_to_save_it_under(self):
        from scripts.packs.consumers import FileConsumers
        from scripts.sitegen.cards import system_file_card

        entry = {"name": "advision.zip", "size": 10, "sha1": "a" * 40,
                 "path": "bios/Entex/Adventure Vision/.variants/advision.zip.1c086064"}
        text = "\n".join(system_file_card(entry, FileConsumers({}, {})))
        self.assertIn("Save as", text)
        self.assertIn("advision.zip.1c086064", text)
        plain = "\n".join(system_file_card(
            {**entry, "path": "bios/Entex/Adventure Vision/advision.zip"}, FileConsumers({}, {})))
        self.assertNotIn("Save as", plain)


class NullReadsAsNone(unittest.TestCase):
    """`upstream: ~` printed `| Upstream | None |` and `bios_filename: null`
    printed `bios_filename: None`: a stated "there is none" read as a gap."""

    def test_page_and_values(self):
        from scripts.sitegen.fields import _plain_value
        from scripts.sitegen.emulatorpage import generate_emulator_page

        self.assertEqual(_plain_value(None), "none")
        page = generate_emulator_page(
            "own", {"emulator": "Own", "type": "standalone", "source": "https://x/own",
                    "upstream": None, "core_version": None, "files": []},
            {"files": {}, "indexes": {}},
        )
        self.assertNotIn("None", page)
        self.assertIn("none: the source is the project itself", page)

    def test_the_rendered_site_has_no_python_none(self):
        from tests import sitepages

        pattern = re.compile(r"\| None \||: None$|: None \|", re.M)
        found = [sitepages.name(p) for p in sitepages.pages()
                 if pattern.search(p.read_text(encoding="utf-8"))]
        self.assertEqual(found, [])


class EmulatorCardsLinkTheCopyAndTheSection(unittest.TestCase):
    """Dolphin's IPL.bin (GC/USA) read "in repo" without naming the copy,
    did not link its collection card, and its platform links landed on the
    page top instead of the GameCube section."""

    def test_copy_and_sections(self):
        from types import SimpleNamespace

        from scripts.sitegen.emulatorcards import CardSources, render_emulator_file

        sha1 = "ef9194ab4804aa0aa8540d846caf291b28331165"
        consumers = SimpleNamespace(
            sha1_of=lambda entry, dest="", owner="": sha1,
            path_of=lambda value: "bios/Nintendo/GameCube/GC/USA/IPL.bin",
            platforms={sha1: {"batocera"}},
            platform_systems={sha1: {"batocera": {"nintendo-gamecube"}}},
        )
        entry = {"name": "IPL.bin", "path": "GC/USA/IPL.bin"}
        text = "\n".join(render_emulator_file(
            entry, {"files": [entry]}, CardSources(consumers), [entry], lambda f: True, "file-ipl", "dolphin",
        ))
        self.assertIn("../systems/nintendo.md#sha1-ef9194ab4804", text)
        self.assertIn("../platforms/batocera.md#nintendo-gamecube", text)


class VersionAnchorsFollowContent(unittest.TestCase):
    """raze's nine DUKE3D.GRP were anchored -1 to -9 by declaration rank: a
    version declared before another moved every later link to another
    edition."""

    @staticmethod
    def _anchors(files):
        from scripts.sitegen.emulatorpage import generate_emulator_page

        page = generate_emulator_page(
            "raze", {"emulator": "Raze", "type": "standalone", "files": files},
            {"files": {}, "indexes": {}},
        )
        return re.findall(r'<h3 id="(file-[^"]+)" class="rb-file-title"', page)

    def test_inserting_a_version_keeps_the_others(self):
        a = {"name": "DUKE3D.GRP", "path": "DUKE3D.GRP", "crc32": "bbc9ce44"}
        b = {"name": "DUKE3D.GRP", "path": "DUKE3D.GRP", "crc32": "aa4f6a40"}
        c = {"name": "DUKE3D.GRP", "path": "DUKE3D.GRP", "crc32": "982afe4a"}
        before = self._anchors([a, b])
        after = self._anchors([c, a, b])
        self.assertTrue(set(before) <= set(after))

    def test_same_size_versions_are_told_by_description(self):
        v1 = {"name": "AUDIO.ABS", "path": "AUDIO.ABS", "size": 6904, "description": "v1.12"}
        v2 = {"name": "AUDIO.ABS", "path": "AUDIO.ABS", "size": 6904, "description": "v1.13"}
        self.assertEqual(self._anchors([v1, v2]),
                         ["file-audio-abs-6904b-v1-12", "file-audio-abs-6904b-v1-13"])


class SitemapDatesComeFromThePage(unittest.TestCase):
    """All 664 sitemap URLs carried the build date: eduke32, re-read on
    2026-10-04, was announced as changed on the day of every build."""

    def test_the_page_date_or_none_reaches_the_sitemap(self):
        import tempfile

        from sitegen import decorate
        from sitegen.pageregistry import PageRegistry

        pages = PageRegistry(page_data={"emulators/dated.md": {"dateModified": "2026-10-04"}})
        with tempfile.TemporaryDirectory() as tmp:
            docs = Path(tmp)
            (docs / "emulators").mkdir()
            (docs / "emulators" / "dated.md").write_text("# Dated\n\nA page with its own date.\n")
            (docs / "emulators" / "undated.md").write_text("# Undated\n\nA page with no date.\n")
            lastmod = decorate.decorate_markdown_pages(docs, pages)
        self.assertEqual(lastmod, {"/retrobios/emulators/dated/": "2026-10-04"})
        # The sitemap reads that map, and leaves every other page undated.
        config = (REPO_ROOT / "website" / "astro.config.mjs").read_text(encoding="utf-8")
        self.assertIn("lastmod.json", config)
        self.assertIn("serialize(item)", config)


class SiteCodeSpansHoldTheirValue(unittest.TestCase):
    """Values from profiles, platform files and file names went into code
    spans as they were: a backtick in one closed the span and what followed
    was read as markup."""

    def test_a_backtick_cannot_close_the_span(self):
        from scripts.sitegen.render import code_span

        span = code_span("a`<img src=x onerror=alert(1)>`")
        self.assertEqual(span.count("`"), 2)
        self.assertTrue(span.startswith("`") and span.endswith("`"))


class TheDatasetDescribesItsDownloads(unittest.TestCase):
    """data.md was a Dataset named "Data & API" with no distribution,
    licence, date or creator: nothing a dataset harvester could index."""

    def test_distribution_licence_and_date(self):
        from scripts.sitegen.structured import dataset_structured_data

        exports = [{"title": "Content database", "url": "api/v1/database.json",
                    "media_type": "application/json", "bytes": 10, "sha256": "ab" * 32}]
        data = dataset_structured_data(exports, {"generated_at": "2026-10-18T07:00:00Z"})
        self.assertEqual(data["dateModified"], "2026-10-18")
        self.assertIn("MIT", data["license"])
        (download,) = data["distribution"]
        self.assertEqual(download["@type"], "DataDownload")
        self.assertTrue(download["contentUrl"].endswith("/api/v1/database.json"))
        self.assertEqual(download["sha256"], "ab" * 32)
        self.assertNotEqual(data["name"], "Data & API")


class SystemPagesDescribeTheirFiles(unittest.TestCase):
    """systems/* published a generic TechArticle: no file, hash or
    provenance for the pages that carry a card per file."""

    def test_parts_carry_hashes_anchor_and_provenance(self):
        from scripts.sitegen.structured import system_structured_data

        entry = {"name": "scph5501.bin", "sha1": "0555c6fae8906f3f09baf5988f00e55f88e9f30b",
                 "md5": "490f666e1afb15b7362b406ed1cea246", "crc32": "8d8cb7e4", "size": 524288,
                 "provenance": {"redump": {"dat": "Sony - PlayStation - BIOS Images",
                                           "name": "ps-30a.bin"}}}
        (part,) = system_structured_data("sony", {"PlayStation": [entry]})["hasPart"]
        self.assertTrue(part["url"].endswith("systems/sony/#sha1-0555c6fae890"))
        self.assertIn("md5:490f666e1afb15b7362b406ed1cea246", part["identifier"])
        self.assertIn("redump: Sony - PlayStation - BIOS Images (ps-30a.bin)", part["citation"])

    def test_a_huge_page_lists_its_verified_files_and_points_at_the_table(self):
        from scripts.sitegen.structured import SYSTEM_PARTS_IN_FULL, system_structured_data

        plain = [{"name": f"f{i}", "sha1": f"{i:040x}"} for i in range(SYSTEM_PARTS_IN_FULL)]
        cited = {"name": "v", "sha1": "f" * 40,
                 "provenance": {"tosec": {"dat": "d", "name": "n"}}}
        data = system_structured_data("engines", {"x": [*plain, cited]})
        self.assertEqual([p["name"] for p in data["hasPart"]], ["v"])
        self.assertTrue(data["isBasedOn"].endswith("downloads/files.csv"))


class TheCollectionShipsADat(unittest.TestCase):
    """The exports had JSON, CSV and SQLite and no DAT, the one format
    clrmamepro and RomVault read: auditing a BIOS tree meant writing a
    converter from files.csv."""

    def test_round_trip_through_the_logiqx_parser(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts" / "scraper"))
        from logiqx_parser import parse_logiqx
        from scripts.sitegen.structured import collection_dat

        db = {"files": {
            "a" * 40: {"path": "bios/Sony/PlayStation/scph5501.bin", "size": 4,
                       "crc32": "8D8CB7E4", "md5": "1" * 32, "sha1": "a" * 40},
            "b" * 40: {"path": "bios/Nintendo/GameCube/GC/USA/IPL.bin", "size": 8,
                       "crc32": "00000001", "md5": "2" * 32, "sha1": "b" * 40},
        }}
        dat = parse_logiqx(collection_dat(db, "2026-10-18T07:00:00Z"))
        self.assertEqual(dat.version, "20261018")
        roms = {(r.game, r.name): r for r in dat.roms}
        # The set name is the subfolder a copy of bios/ holds: named
        # "Sony - PlayStation", clrmamepro looked beside Sony/ for it.
        self.assertIn(("Sony\\PlayStation", "scph5501.bin"), roms)
        self.assertIn(("Nintendo\\GameCube", "GC\\USA\\IPL.bin"), roms)
        self.assertEqual(roms[("Sony\\PlayStation", "scph5501.bin")].crc32, "8d8cb7e4")

    def test_each_setup_has_a_dat_of_its_installed_folder(self):
        """A Batocera user auditing share/bios against the collection DAT met
        thousands of sets laid out by manufacturer, and nothing of the folder
        Batocera reads."""
        sys.path.insert(0, str(REPO_ROOT / "scripts" / "scraper"))
        from logiqx_parser import parse_logiqx
        from scripts.sitegen.platformfiles import platform_data_links
        from scripts.sitegen.structured import platform_dat

        db = {"files": {"a" * 40: {"size": 4, "crc32": "8D8CB7E4", "md5": "1" * 32,
                                   "sha1": "a" * 40}}}
        manifest = {
            "platform": "batocera", "display_name": "Batocera", "base_destination": "bios",
            "files": [{"dest": "dc/naomi2.zip", "sha1": "a" * 40, "size": 4},
                      {"dest": "saves/x.bin", "sha1": "a" * 40, "size": 4, "root": "save"}],
            "data_directories": [{"dest": "dolphin-emu/Sys",
                                  "files": {"GC/font.bin": {"sha1": "c" * 40, "size": 2}}}],
        }
        dat = parse_logiqx(platform_dat(manifest, db, {"c" * 40: {"md5": "3" * 32}},
                                        "2026-11-05T00:00:00Z"))
        roms = {(r.game, r.name): r for r in dat.roms}
        self.assertEqual(set(roms), {("bios", "dc\\naomi2.zip"),
                                     ("bios", "dolphin-emu\\Sys\\GC\\font.bin")})
        self.assertEqual(roms[("bios", "dc\\naomi2.zip")].md5, "1" * 32)
        self.assertEqual(roms[("bios", "dolphin-emu\\Sys\\GC\\font.bin")].md5, "3" * 32)
        self.assertIn("[DAT](../downloads/dat/batocera.dat)", platform_data_links("batocera"))


if __name__ == "__main__":
    unittest.main()
