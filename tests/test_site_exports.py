"""Regression tests for the public website data and citation contracts."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from generate_site import (  # noqa: E402
    _admonition_body,
    _browser_title,
    _forge_sources,
    _source_ref_markdown,
    decorate_markdown_pages,
    generate_data_exports,
)


class SiteReferenceContracts(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.docs = Path(self.temp.name) / "docs"
        self.docs.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _fixtures() -> tuple[dict, dict, dict, dict]:
        payload = b"firmware"
        sha1 = hashlib.sha1(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()
        db = {
            "schema_version": 1,
            "generated_at": "2026-08-09T00:00:00Z",
            "total_files": 1,
            "total_size": len(payload),
            "files": {
                sha1: {
                    "path": "bios/Test/fw.bin",
                    "name": "fw.bin",
                    "size": len(payload),
                    "sha1": sha1,
                    "md5": md5,
                    "sha256": sha256,
                    "crc32": "0f00ba11",
                    "adler32": "0f00ba11",
                }
            },
            "indexes": {
                "by_md5": {md5: sha1},
                "by_name": {"fw.bin": [sha1]},
                "by_crc32": {"0f00ba11": sha1},
                "by_sha256": {sha256: sha1},
                "by_path_suffix": {"fw.bin": [sha1]},
            },
        }
        coverages = {
            "test": {
                "platform": "Test Platform",
                "config": {
                    "platform": "Test Platform",
                    "cores": ["testemu"],
                    "systems": {
                        "test-system": {
                            "files": [
                                {
                                    "name": "fw.bin",
                                    "destination": "fw.bin",
                                    "required": True,
                                    "sha1": sha1,
                                    "md5": "C87A52C277F7952B41C639FC7BF0A43B,"
                                           "d0ed892a5e8d47e0cb5f8aa5f4dd7c5a",
                                    "crc32": "3F9F95A4",
                                    "size": len(payload),
                                }
                            ]
                        }
                    },
                },
                "total": 1,
                "present": 1,
                "verified": 1,
                "untested": 0,
                "missing": 0,
                "core_present": 1,
                "core_missing": 0,
                "core_unsourceable": 0,
                "details": [],
            }
        }
        profiles = {
            "testemu": {
                "emulator": "Test Emulator",
                "type": "libretro",
                "source": "https://github.com/example/emulator",
                "source_commit": "a" * 40,
                "cores": ["testemu"],
                "systems": ["test-system"],
                "files": [
                    {
                        "name": "fw.bin",
                        "system": "test-system",
                        "required": True,
                        "md5": ["5c124e7948ada85da603a522782940d0",
                                "4921d5f2165dee6e2496f4388c4c81b2"],
                        "source_ref": "src/firmware.cpp:10-12",
                    }
                ],
            }
        }
        stats = {
            "schema_version": 1,
            "generated_at": "2026-08-09T00:00:00Z",
            "files": 1,
            "size_bytes": len(payload),
            "platforms": 1,
            "emulators": 1,
            "systems": 1,
            "catalog_matched": 0,
            "source": "https://github.com/Abdess/retrobios",
            "downloads": "https://github.com/Abdess/retrobios/releases/tag/v2026.08.06",
            "composition": {
                "systems": {"files": 1, "size_bytes": len(payload)},
                "arcade": {"files": 0, "size_bytes": 0},
                "game_data": {"files": 0, "size_bytes": 0},
            },
        }
        return db, coverages, profiles, stats

    @mock.patch("sitesources.tree_holds", lambda *_args: True)  # a path the record confirms
    def test_source_references_are_revision_pinned_links(self):
        _, _, profiles, _ = self._fixtures()
        rendered = _source_ref_markdown(
            profiles["testemu"], "src/firmware.cpp:10-12"
        )
        self.assertIn("/blob/" + "a" * 40 + "/src/firmware.cpp#L10-L12", rendered)

    def test_ambiguous_two_repository_path_is_never_linked(self):
        """A path that could live in either declared repository stays plain.

        The libretro port and the original emulator are two different trees.
        Linking an unattributable path to whichever came first publishes a
        citation that resolves to nothing.
        """
        profile = {
            "source": "https://github.com/libretro/example-libretro",
            "source_commit": "a" * 40,
            "upstream": "https://gitlab.com/vendor/example",
            "upstream_commit": "b" * 40,
        }
        rendered = _source_ref_markdown(profile, "jg.c:213-214")
        self.assertEqual(rendered, "`jg.c:213-214`")
        self.assertNotIn("http", rendered)

        # A first segment equal to a repository's name proves nothing: PCSX2
        # keeps its sources in pcsx2/, hatariB vendors Hatari in hatari/.
        # Stripped, 470 links pointed at nothing or at another file.
        prefixed = _source_ref_markdown(profile, "example/jg.c:213-214")
        self.assertEqual(prefixed, "`example/jg.c:213-214`")

    @mock.patch("sitesources.tree_holds", lambda *_args: True)  # a path the record confirms
    def test_a_single_repository_links_the_path_as_written(self):
        profile = {"source": "https://github.com/PCSX2/pcsx2", "source_commit": "c" * 40}
        rendered = _source_ref_markdown(profile, "pcsx2/ImGui/FullscreenUI.cpp:755-759")
        self.assertIn("/blob/" + "c" * 40 + "/pcsx2/ImGui/FullscreenUI.cpp#L755-L759", rendered)

    def test_preprocessor_tokens_cannot_become_page_headings(self):
        rendered = _admonition_body("First paragraph.\n\n#if FEATURE\nEnabled")
        self.assertIn("\\#if FEATURE", rendered)
        self.assertNotIn("\n    #if FEATURE", rendered)

    def test_browser_titles_distinguish_emulators_from_system_pages(self):
        from unittest import mock  # noqa: PLC0415

        import generate_site  # noqa: PLC0415

        pages = {"systems/qemu.md": {}, "emulators/qemu.md": {"hasPart": [{"name": "a"}]}}
        with mock.patch.dict(generate_site.PAGE_DATA, pages, clear=True):
            self.assertEqual(_browser_title(Path("emulators/qemu.md"), "QEMU"),
                             "QEMU emulator BIOS files")
            self.assertEqual(_browser_title(Path("systems/qemu.md"), "QEMU"), "QEMU BIOS files")

    ACCEPTED = (
        ("md5", "c87a52c277f7952b41c639fc7bf0a43b"),
        ("md5", "d0ed892a5e8d47e0cb5f8aa5f4dd7c5a"),
        ("crc32", "3f9f95a4"),
        ("md5", "4921d5f2165dee6e2496f4388c4c81b2"),
    )

    def test_exports_have_catalog_hashes_and_queryable_sqlite(self):
        db, coverages, profiles, stats = self._fixtures()
        exports = generate_data_exports(
            self.docs, db, coverages, profiles, stats
        )
        catalog = json.loads((self.docs / "api/v1/catalog.json").read_text())
        self.assertEqual(catalog["count"], len(exports))
        # Every reference resolves against the catalog's own URL, as an
        # RFC 3986 client resolves it: the url was relative to the site root
        # and the schema to api/v1/, so neither base resolved both.
        import urllib.parse  # noqa: PLC0415

        site = "https://example.org/site/"
        base = site + "api/v1/catalog.json"
        for item in catalog["items"]:
            for key in ("url", "schema"):
                if key in item:
                    target = urllib.parse.urljoin(base, item[key]).removeprefix(site)
                    self.assertTrue((self.docs / target).is_file(), (key, item[key]))
            path = self.docs / urllib.parse.urljoin(base, item["url"]).removeprefix(site)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])

        with sqlite3.connect(self.docs / "downloads/retrobios.sqlite") as connection:
            # One lowercase row per accepted value: a comma-joined Recalbox
            # md5, a JSON array of accepted revisions and an uppercase crc32
            # each missed an exact lookup.
            for algorithm, value in self.ACCEPTED:
                with self.subTest(algorithm=algorithm, value=value):
                    self.assertTrue(connection.execute(
                        "SELECT count(*) FROM accepted_hashes WHERE algorithm = ? AND value = ?",
                        (algorithm, value)).fetchone()[0])
            self.assertEqual(connection.execute("SELECT count(*) FROM files").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM platforms").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM emulators").fetchone()[0], 1)

    def test_page_metadata_is_specific_and_idempotent(self):
        page = self.docs / "gaps.md"
        page.write_text("# Gap Analysis - RetroBIOS\n\nCurrent unresolved entries.\n")
        decorate_markdown_pages(self.docs)
        decorate_markdown_pages(self.docs)
        content = page.read_text()
        self.assertEqual(content.count("type: application/ld+json"), 1)
        self.assertIn("Current RetroBIOS verification gaps", content)
        self.assertIn('"@type":"TechArticle"', content)


class PerModeSourcePins(unittest.TestCase):
    """A profile whose builds live in separate repositories.

    `source`, `upstream` and `source_commit` may each be keyed by build mode.
    Reading the URL from one mode and the revision from another produces a
    permalink into a tree that never held that line, and binding the object
    form straight into SQLite fails outright.
    """

    PROFILE = {
        "emulator": "twobuilds",
        "source": {
            "standalone": "https://github.com/vendor/emu",
            "libretro": "https://github.com/porter/emu-libretro",
        },
        "upstream": "https://github.com/vendor/emu",
        "source_commit": {"standalone": "a" * 40, "libretro": "b" * 40},
    }

    def test_each_repository_keeps_its_own_revision(self):
        pairs = {
            (repo.slug, pin) for repo, pin in _forge_sources(self.PROFILE)
        }
        self.assertIn(("vendor/emu", "a" * 40), pairs)
        self.assertIn(("porter/emu-libretro", "b" * 40), pairs)
        # The libretro fork must never be pinned to the standalone revision.
        self.assertNotIn(("porter/emu-libretro", "a" * 40), pairs)
        self.assertNotIn(("vendor/emu", "b" * 40), pairs)

    def test_a_build_mode_label_is_resolved_first(self):
        repo, pin = _forge_sources(self.PROFILE, "libretro")[0]
        self.assertEqual((repo.slug, pin), ("porter/emu-libretro", "b" * 40))

    def test_the_plain_string_form_is_unchanged(self):
        profile = {
            "source": "https://github.com/vendor/emu",
            "source_commit": "c" * 40,
        }
        self.assertEqual(
            [(repo.slug, pin) for repo, pin in _forge_sources(profile)],
            [("vendor/emu", "c" * 40)],
        )

    def test_sqlite_export_accepts_a_per_mode_commit(self):
        from generate_site import _json_text

        self.assertEqual(
            _json_text(self.PROFILE["source_commit"]),
            '{"libretro": "' + "b" * 40 + '", "standalone": "' + "a" * 40 + '"}',
        )
        self.assertEqual(_json_text("c" * 40), "c" * 40)



class AnEmulatorPageNamesItsRevision(unittest.TestCase):
    """The page linked the repositories unpinned. The commit every citation
    refers to sat in the YAML alone, for 178 profiles."""

    def test_each_repository_links_its_pinned_commit(self):
        import generate_site  # noqa: PLC0415

        profile = {
            "emulator": "Caprice32", "type": "libretro",
            "source": "https://github.com/libretro/libretro-cap32",
            "upstream": "https://github.com/ColinPitrat/caprice32",
            "source_commit": "c" * 40, "upstream_commit": "6" * 40,
            "source_branch": "main", "systems": ["amstrad-cpc"], "files": [],
        }
        page = generate_site.generate_emulator_page("cap32", profile, {"files": {}})
        self.assertIn(
            "| Revision | [libretro/libretro-cap32@cccccccccccc]"
            "(https://github.com/libretro/libretro-cap32/commit/" + "c" * 40 + "), "
            "[ColinPitrat/caprice32@666666666666]"
            "(https://github.com/ColinPitrat/caprice32/commit/" + "6" * 40 + "), "
            "branch `main` |",
            page,
        )


class APlatformPageSaysWhereEachFileGoes(unittest.TestCase):
    """Three GameCube IPL.bin were listed by name alone: nothing told which
    goes to GC/USA, GC/EUR or GC/JAP."""

    def test_same_named_files_show_their_destinations(self):
        import generate_site  # noqa: PLC0415

        regions = ("USA", "EUR", "JAP")
        declared = [{"name": "IPL.bin", "destination": f"dolphin-emu/Sys/GC/{r}/IPL.bin",
                     "sha1": str(i) * 40} for i, r in enumerate(regions)]
        files = [{"name": "IPL.bin", "status": "ok"} for _ in regions]
        lines = generate_site._render_platform_systems(
            {"nintendo-gamecube": files}, {("nintendo-gamecube", "IPL.bin"): declared}, {})
        for region in regions:
            # The folder: the name is before it in the row.
            self.assertIn(f"<summary>IPL.bin <code>dolphin-emu/Sys/GC/{region}/</code> "
                          '<span class="rb-badge rb-badge-success">OK</span></summary>',
                          "\n".join(lines))


class AVariantShowsWhoPinsIt(unittest.TestCase):
    """A .variants/ file showed a name and a truncated MD5: the advision.zip
    Batocera and RetroBat pin named no platform."""

    def test_the_variant_card_names_its_readers(self):
        import types  # noqa: PLC0415

        import generate_site  # noqa: PLC0415

        primary = {"name": "advision.zip", "path": "bios/Entex/Adventure Vision/advision.zip",
                   "sha1": "a" * 40, "md5": "b" * 32, "size": 3000}
        variant = {"name": "advision.zip",
                   "path": "bios/Entex/Adventure Vision/.variants/advision.zip.1c086064",
                   "sha1": "c" * 40, "md5": "1c086064" + "0" * 24, "size": 3000,
                   "provenance": {"tosec": {"name": "x"}}}
        consumers = types.SimpleNamespace(
            platforms={"c" * 40: {"batocera", "retrobat"}}, emulators={"a" * 40: {"mame"}})
        page = generate_site.generate_system_page(
            "Entex", {"Adventure Vision": [primary, variant]}, consumers)
        # Another revision of a set sits open beside it.
        block = page[page.index('id="sha1-' + "c" * 12 + '"'):]
        self.assertIn("<dt>Collection path</dt><dd><code>bios/Entex/Adventure Vision/"
                      ".variants/advision.zip.1c086064</code>", block)
        self.assertIn('<a href="../platforms/batocera.md">Batocera</a>', block)
        self.assertIn('<a href="../platforms/retrobat.md">RetroBat</a>', block)
        self.assertIn('<dd class="rb-hash">' + "c" * 40 + "</dd>", block)
        self.assertIn("Catalogued", block)


class AFlaggedDumpIsNotVerified(unittest.TestCase):
    """scph5000.bin, which TOSEC names "...(JP)[b].bin", wore a green
    "Verified dump: TOSEC" badge. The catalog name lived only in a title
    attribute, outside the search and invisible on a touch screen."""

    def test_flags_and_name(self):
        from generate_site import _provenance_lines

        lines = _provenance_lines({
            "tosec": {"name": "Sony PlayStation BIOS (v2.2)(Sony)(JP)[b].bin"},
            "redump": {"name": "SCPH-5000 BIOS v2.2"},
        }, "../")
        tosec = next(l for l in lines if "TOSEC" in l)
        redump = next(l for l in lines if "Redump" in l)
        self.assertIn("rb-badge-warning", tosec)
        self.assertIn("bad dump", tosec)
        self.assertIn("(JP)[b].bin", tosec)
        self.assertIn("rb-badge-success", redump)
        self.assertIn("SCPH-5000 BIOS v2.2", redump)

    def test_an_alternate_is_not_a_flag(self):
        from generate_site import _dump_flags

        self.assertEqual(_dump_flags("tosec", {"name": "x (JP)[a].bin"}), [])
        self.assertEqual(_dump_flags("tosec", {"name": "x [o][b].bin"}), ["overdump", "bad dump"])



class EmulatorPagesPrintWholeHashes(unittest.TestCase):
    """Emulator pages cut every hash to 12 characters, the rest in a title
    attribute the search does not index: bstone's AUDIOHED.BS1 sha1 pasted
    whole found nothing."""

    def test_full_and_split(self):
        from generate_site import _hash_spans

        sha1 = "0c3de403b524107809fa9308b730d60e8e41ba93"
        self.assertIn(f">{sha1}</code>", _hash_spans(sha1))
        both = _hash_spans(f"{'a' * 64}, {'b' * 64}")
        self.assertIn(">" + "a" * 64 + "</code>", both)
        self.assertIn(">" + "b" * 64 + "</code>", both)
        self.assertNotIn("...", both)



class TheGapsSayWhatToSupplyAndWhere(unittest.TestCase):
    """The Files to Source table, gaps.csv and gaps.json gave neither the
    expected hash nor the destination: EANIM.BS6's sha1 af5af59a... was on
    the emulator page only, and Data.rsdk's three rows looked identical."""

    def test_export_rows(self):
        from generate_site import _gap_export_rows

        report = {"bstone": {"emulator": "BStone", "systems": ["blake-stone"], "gap_details": [
            {"name": "EANIM.BS6", "path": "AOG/EANIM.BS6", "source": "missing",
             "required": False, "identity": "sha1:" + "a" * 40}]}}
        row = next(r for r in _gap_export_rows({}, report) if r["name"] == "EANIM.BS6")
        self.assertEqual(row["destination"], "AOG/EANIM.BS6")
        self.assertEqual(row["expected"], "sha1:" + "a" * 40)



class AGoneSourceIsSaid(unittest.TestCase):
    """citron, yuzu and suyu linked sources answering 451 or a domain now
    owned by someone else, and the page said nothing."""

    def test_the_status_row(self):
        import generate_site

        profile = {"emulator": "Citron", "type": "standalone", "systems": [],
                   "source": "https://git.citron-emu.org/citron-emu/Citron",
                   "upstream_gone": "git.citron-emu.org no longer resolves. Observed 2026-09-04.",
                   "source_mirror": "https://example.org/mirror/Citron", "files": []}
        page = generate_site.generate_emulator_page(
            "citron", profile, {"files": {}, "indexes": {}}, {})
        self.assertIn("| Source status | gone: git.citron-emu.org no longer resolves", page)
        self.assertIn("| Mirror | [https://example.org/mirror/Citron]", page)



class ASystemCardLandsOnThePlatformsSection(unittest.TestCase):
    """From scph5000.bin's card, [retrodeck] opened the top of a 2,000-file
    page, while the emulator card already landed on #sony-playstation."""

    def test_section_and_destination(self):
        import types

        from generate_site import _platform_links

        consumers = types.SimpleNamespace(
            platforms={"s": {"retrodeck"}},
            platform_systems={"s": {"retrodeck": {"sony-playstation"}}},
            platform_destinations={"s": {"retrodeck": {"bios/scph5000.bin"}}},
        )
        self.assertEqual(
            _platform_links("s", consumers),
            ["[RetroDECK](../platforms/retrodeck.md#sony-playstation): `bios/scph5000.bin`"],
        )



class ArchiveMembersAreAcceptedHashes(unittest.TestCase):
    """accepted_hashes read only an entry's own hashes: 4,673 member crc32
    values of MAME and FBNeo sets were absent from the table the Data page
    calls the one to ask."""

    def test_member_rows(self):
        from generate_site import _accepted_hash_rows

        item = {"id": "fbalpha2019", "profile": {"files": [
            {"name": "nmk004.zip", "system": "arcade",
             "contents": [{"name": "nmk004.bin", "crc32": "83b6f611"}]}]}}
        rows = _accepted_hash_rows([], [item])
        self.assertIn(
            ("nmk004.bin", "nmk004.zip/nmk004.bin", "crc32", "83b6f611"),
            {(r["name"], r["path"], r["algorithm"], r["value"]) for r in rows},
        )



class PlatformPagesCarryTheirDeclarations(unittest.TestCase):
    """Platform pages were the only content pages without structured data:
    5,640 md5 and 2,047 sha1 the platforms declare lived in the prose only."""

    def test_parts_and_version(self):
        from generate_site import platform_structured_data

        data = platform_structured_data("batocera", {"platform": "Batocera", "config": {
            "version": "43.1", "systems": {"sony-playstation": {"files": [
                {"name": "scph5501.bin", "destination": "scph5501.bin", "md5": "490f666e"}]}}}})
        self.assertEqual(data["about"]["softwareVersion"], "43.1")
        part = data["hasPart"][0]
        self.assertEqual(part["identifier"], ["md5:490f666e"])
        self.assertTrue(part["url"].endswith("platforms/batocera/#sony-playstation"))

    def test_a_declared_sha256_is_published(self):
        """RetroDECK's dsifirmware.bin sha256 lived in the CSV exports only."""
        from generate_site import platform_structured_data

        data = platform_structured_data("retrodeck", {"platform": "RetroDECK", "config": {
            "systems": {"nds": {"files": [
                {"name": "dsifirmware.bin", "sha256": "11A150E3"}]}}}})
        self.assertEqual(data["hasPart"][0]["identifier"], ["sha256:11a150e3"])



class AnEmulatorPageLinksItsProfile(unittest.TestCase):
    """A page rendered a profile without linking it: reusing raze.yml meant
    guessing its path or filtering the 5.9 MB emulators.json."""

    def test_links(self):
        import generate_site

        page = generate_site.generate_emulator_page(
            "raze", {"emulator": "Raze", "type": "standalone", "systems": [], "files": []},
            {"files": {}, "indexes": {}}, {})
        self.assertIn("/blob/main/emulators/raze.yml", page)
        self.assertIn("(../api/v1/emulators/raze.json)", page)


class AVersionPerBuildReadsAsVersions(unittest.TestCase):
    """MesenCE's page showed {'standalone': '2.2.1', 'libretro': '2.0.0'}."""

    def test_each_build_is_named(self):
        from generate_site import generate_emulator_page  # noqa: PLC0415

        page = generate_emulator_page(
            "mesence",
            {"emulator": "MesenCE", "type": "standalone + libretro", "systems": [],
             "core_version": {"standalone": "2.2.1", "libretro": "2.0.0"}, "files": []},
            {"files": {}, "indexes": {}},
        )
        self.assertIn("2.2.1 (standalone), 2.0.0 (libretro)", page)
        self.assertNotIn("{'standalone'", page)


class EmulatorPartsCarryTheirIdentity(unittest.TestCase):
    """The emulator JSON-LD published 'sha256:a,b,c,d' as one identifier,
    gave archives none though their members carry crc32 and sha1, and gave
    no part the url of its card."""

    def test_identifiers_members_and_url(self):
        from generate_site import emulator_file_anchors, emulator_structured_data  # noqa: PLC0415

        files = [
            {"name": "BS-X.bin", "sha256": "aa,bb"},
            {"name": "neogeo.zip", "contents": [
                {"name": "sp-s2.sp1", "crc32": "9036D879", "sha1": "ff" * 20}]},
        ]
        data = emulator_structured_data({"files": files})
        bsx, neogeo = data["hasPart"]
        self.assertEqual(bsx["identifier"], ["sha256:aa", "sha256:bb"])
        self.assertEqual(
            neogeo["hasPart"][0]["identifier"], ["sha1:" + "ff" * 20, "crc32:9036d879"]
        )
        self.assertEqual(
            [bsx["url"], neogeo["url"]], [f"#{a}" for a in emulator_file_anchors(files)]
        )


class OnlyAPinnedProfileClaimsAPin(unittest.TestCase):
    """Redream, with no revision at all, was described as source-pinned."""

    def test_the_description_follows_the_pin(self):
        from unittest import mock  # noqa: PLC0415

        import generate_site  # noqa: PLC0415

        pages = {
            "emulators/pinned.md": {"about": {"version": "a" * 40}},
            "emulators/redream.md": {},
        }
        with mock.patch.dict(generate_site.PAGE_DATA, pages, clear=True):
            pinned = generate_site._page_description("", Path("emulators/pinned.md"), "P")
            loose = generate_site._page_description("", Path("emulators/redream.md"), "R")
        # A search snippet is level 0: the pin is on the page, not in it.
        self.assertNotIn("source-pinned", pinned)
        self.assertNotIn("source-pinned", loose)


class ADataDirectorySaysWhatItIs(unittest.TestCase):
    """The page said `dolphin-sys` > `Sys` and nothing of the tree it packs."""

    @mock.patch("sitesources.tree_holds", lambda *_args: True)  # a path the record confirms
    def test_description_origin_mode_and_source(self):
        from generate_site import generate_emulator_page  # noqa: PLC0415

        profile = {
            "emulator": "Cemu", "type": "standalone + libretro", "systems": [],
            "source": "https://github.com/cemu-project/Cemu", "source_commit": "c" * 40,
            "files": [{"name": "keys.txt"}],
            "data_directories": [{"ref": "packs", "destination": "graphicPacks",
                                  "mode": "standalone", "source_ref": "src/main.cpp:10"}],
        }
        registry = {"packs": {"description": "Community graphic packs",
                              "source_url": "https://example.test/packs.zip"}}
        page = generate_emulator_page("cemu", profile, {"files": {}, "indexes": {}},
                                      None, set(), registry)
        self.assertIn("`packs` > `graphicPacks`: Community graphic packs", page)
        self.assertIn("<https://example.test/packs.zip>", page)
        self.assertIn("standalone build only", page)
        self.assertIn("src/main.cpp#L10", page)


class APlatformPageNamesTheFileItTranscribes(unittest.TestCase):
    """Batocera's page gave 'Version 43.1' and a homepage, never the
    batocera-systems revision every md5 on it comes from."""

    def test_pinned_and_moving_sources(self):
        import generate_site  # noqa: PLC0415

        def page(source: str) -> str:
            cov = {"platform": "P", "config": {"source": source, "systems": {}},
                   "details": [], "total": 0, "verified": 0, "present": 0,
                   "missing": 0, "untested": 0, "mode": "md5"}
            return generate_site.generate_platform_page("p", cov)

        tag = "https://raw.githubusercontent.com/o/r/batocera-43.1/x/batocera-systems"
        self.assertIn(
            "| Transcribed from | [batocera-systems at tag batocera-43.1]"
            "(https://github.com/o/r/blob/batocera-43.1/x/batocera-systems) |", page(tag))
        branch = "https://raw.githubusercontent.com/o/r/master/x.json"
        self.assertIn("revision read is not recorded", page(branch))
        self.assertIn("revision read is not recorded", page("https://github.com/RetroDECK/components"))


class APerCoreDocumentValidates(unittest.TestCase):
    """api/v1/emulators/<id>.json had no schema_version, and its "id" beside
    the profile's fields failed the schema published next to it."""

    def test_shape(self):
        try:
            import jsonschema  # noqa: PLC0415
        except ImportError:
            self.skipTest("jsonschema is not installed")
        import yaml  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        self.assertNotIn('json.dumps({"id": name, **profile}', source)
        envelope = json.loads((root / "schemas" / "site-api-envelope.schema.json").read_text())
        schema = json.loads((root / "schemas" / "emulator.schema.json").read_text())
        profile = yaml.safe_load((root / "emulators" / "handy.yml").read_text())
        document = {"schema_version": 1, "generated_at": "2026-10-19T00:00:00Z",
                    "kind": "emulators", "count": 1,
                    "items": [{"id": "handy", "profile": profile}]}
        jsonschema.validate(document, envelope)
        jsonschema.validate(document["items"][0]["profile"], schema)


class AHashFindsEveryPageThatNamesIt(unittest.TestCase):
    """Hashes left the site search, 4 MB of the index every visitor
    downloaded. files/?hash= reads one shard instead, and it must answer at
    least what the search answered: the card, the platforms, the profiles."""

    def test_an_archive_answers_for_the_rom_a_list_pins_inside_it(self):
        """Batocera checks naomi2.zip by the md5 of 315-6146.bin inside it:
        dropped on the lookup, the archive listed every setup but Batocera,
        and 335 of its 337 zipped_file entries were unreachable that way."""
        import json as _json

        import generate_site  # noqa: PLC0415
        from common import load_platform_config  # noqa: PLC0415
        from cross_reference import FileConsumers  # noqa: PLC0415
        from ziptools import build_zip_contents_index  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        db = _json.loads((root / "database.json").read_text(encoding="utf-8"))
        config = load_platform_config("batocera", str(root / "platforms"))
        entry = next(e for system in config["systems"].values() for e in system.get("files") or []
                     if e.get("name") == "naomi2.zip" and e.get("zipped_file"))
        cwd = Path.cwd()
        try:
            os.chdir(root)
            consumers = FileConsumers(db, build_zip_contents_index(db))
            archive = consumers.sha1_of(entry)
        finally:
            os.chdir(cwd)
        if archive is None:
            self.skipTest("no copy of naomi2.zip holding the pinned ROM")
        coverages = {"batocera": {"config": {"systems": {"sega-naomi2": {"files": [entry]}}}}}
        records = generate_site.file_lookup_records(db, coverages, {}, [], None, consumers)
        found = {(r["owner"], r["value"]) for r in records if r["layer"] == "platform"}
        self.assertIn(("batocera", archive), found)
        pinned = next(r for r in records if r["layer"] == "platform" and r["algorithm"] == "md5")
        self.assertEqual(pinned["sha1"], archive)

    def test_a_data_directory_member_answers_every_hash(self):
        """Dolphin's ApprovedInis.json was found by its SHA1 only: its MD5
        and CRC32 answered no match although the pack ships it."""
        import hashlib
        import tempfile
        import zlib

        import generate_site  # noqa: PLC0415

        body = b"approved inis\n"
        sha1 = hashlib.sha1(body).hexdigest()
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / "tmp") as tmp:
            member = Path(tmp, "data", "dolphin-sys", "ApprovedInis.json")
            member.parent.mkdir(parents=True)
            member.write_bytes(body)
            stale = Path(tmp, "data", "dolphin-sys", "Stale.json")
            stale.write_bytes(b"other bytes")
            members = {"dolphin-sys": {"ApprovedInis.json": {"sha1": sha1},
                                       "Stale.json": {"sha1": "ef" * 20}}}
            registry = {"dolphin-sys": {"local_cache": "data/dolphin-sys"}}
            digests = generate_site._data_member_digests(members, registry, Path(tmp))
        self.assertEqual(digests, {sha1: {
            "sha1": sha1, "md5": hashlib.md5(body).hexdigest(),
            "sha256": hashlib.sha256(body).hexdigest(),
            "crc32": f"{zlib.crc32(body):08x}"}})
        with mock.patch.object(generate_site, "_data_member_digests", return_value=digests):
            records = generate_site.file_lookup_records(
                {"files": {}}, {}, {}, [{"sha1": sha1, "url": "u"}],
                {"dolphin-sys": {"ApprovedInis.json": {"sha1": sha1}}})
        self.assertEqual({r["algorithm"]: r["value"] for r in records}, digests[sha1])

    def test_records_cover_every_layer_and_shard_by_prefix(self):
        import json as _json
        import tempfile

        import generate_site  # noqa: PLC0415

        sha1 = "ab" * 20
        md5 = "490f666e1afb15b7362b406ed1cea246"
        db = {"files": {sha1: {"name": "scph5501.bin", "md5": md5, "crc32": "8D8CB7E4",
                               "path": "bios/Sony/PlayStation/scph5501.bin"}}}
        coverages = {"batocera": {"config": {"systems": {"sony-playstation": {"files": [
            {"name": "scph5501.bin", "md5": f"{md5}, 0123456789abcdef0123456789abcdef"},
            {"name": "typo.bin", "md5": "not-a-hash"},
        ]}}}}}
        profiles = {
            "duckstation": {"files": [{"name": "scph5501.bin", "md5": md5},
                                      {"name": "set.zip", "contents": [
                                          {"name": "m.rom", "crc32": "11223344"}]}]},
            "an-alias": {"type": "alias", "files": [{"name": "x", "md5": md5}]},
        }
        locations = generate_site.file_location_items(db) + [
            {"sha1": "cd" * 20, "url": "emulators/dolphin/#sha1-" + "cd" * 6}]
        members = {"dolphin-sys": {"Sys/GC/font.bin": {"sha1": "cd" * 20}}}
        records = generate_site.file_lookup_records(db, coverages, profiles, locations, members)
        found = {(r["layer"], r.get("owner", ""), r["algorithm"], r["value"]): r for r in records}
        self.assertEqual(found[("collection", "", "md5", md5)]["url"],
                         "/retrobios/systems/sony/#sha1-" + "ab" * 6)
        self.assertIn(("collection", "", "crc32", "8d8cb7e4"), found)
        self.assertEqual(found[("data-directory", "", "sha1", "cd" * 20)]["name"], "font.bin")
        self.assertEqual(found[("platform", "batocera", "md5", md5)]["url"],
                         "/retrobios/platforms/batocera/#sony-playstation")
        self.assertIn(("platform", "batocera", "md5", "0123456789abcdef0123456789abcdef"), found)
        self.assertEqual(found[("emulator", "duckstation", "md5", md5)]["url"],
                         "/retrobios/emulators/duckstation/#file-scph5501-bin-490f666e")
        self.assertEqual(found[("emulator", "duckstation", "crc32", "11223344")]["name"], "m.rom")
        self.assertNotIn(("emulator", "an-alias", "md5", md5), found)

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / "tmp") as tmp:
            shards = generate_site.write_lookup_shards(Path(tmp), records, "2026-01-01T00:00:00Z")
            folder = Path(tmp) / "lookup"
            names = sorted(path.name for path in folder.glob("*.json"))
            self.assertEqual(len(names), shards)
            for path in folder.glob("*.json"):
                document = _json.loads(path.read_text())
                self.assertEqual(document["kind"], "file-lookup")
                self.assertEqual(document["count"], len(document["items"]))
                for item in document["items"]:
                    self.assertTrue(item["value"].startswith(path.stem))
            self.assertNotIn("no.json", names)


class AnArchiveMemberIsFoundByItsCrc(unittest.TestCase):
    """A pasted CRC of logica2.u2 (8484f426), which the collection holds
    inside a500.zip, answered that no file the site knows has it: the
    lookup held the members a profile's `contents:` declares, 7,389 of
    33,403."""

    def test_each_member_is_a_record_leading_to_its_archive(self):
        import zipfile  # noqa: PLC0415

        import generate_site  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / "tmp") as tmp:
            root = Path(tmp)
            archive = root / "bios" / "Arcade" / "Arcade" / "a500.zip"
            archive.parent.mkdir(parents=True)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("logica2.u2", b"rom")
                handle.writestr("sub/kick.rom", b"kick")
            entry = {"name": "a500.zip", "path": "bios/Arcade/Arcade/a500.zip"}
            records = generate_site._archive_member_records(entry, "ab" * 20, "/retrobios/x/", root)
            plain = generate_site._archive_member_records(
                {"name": "a.bin", "path": "bios/a.bin"}, "cd" * 20, "/retrobios/y/", root)
        self.assertEqual(plain, [])
        import zlib  # noqa: PLC0415

        self.assertEqual(records, [
            {"value": f"{zlib.crc32(b'rom'):08x}", "algorithm": "crc32", "layer": "archive-member",
             "name": "logica2.u2", "archive": "a500.zip", "sha1": "ab" * 20, "url": "/retrobios/x/"},
            {"value": f"{zlib.crc32(b'kick'):08x}", "algorithm": "crc32", "layer": "archive-member",
             "name": "kick.rom", "archive": "a500.zip", "sha1": "ab" * 20, "url": "/retrobios/x/"},
        ])

    def test_the_lookup_and_the_schema_carry_the_layer(self):
        import json as _json  # noqa: PLC0415

        import generate_site  # noqa: PLC0415

        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn("records += _archive_member_records(entry, sha1, item[\"url\"])", source)
        schema = _json.loads((Path(__file__).resolve().parents[1] / "schemas"
                              / "site-api-envelope.schema.json").read_text())
        self.assertIn('"archive-member"', _json.dumps(schema))
        script = (Path(__file__).resolve().parents[1] / "website" / "src" / "scripts"
                  / "site.ts").read_text(encoding="utf-8")
        self.assertIn("byLayer('archive-member')", script)


class AWantedDumpIsFoundByItsHash(unittest.TestCase):
    """The SHA1 of a PS2 SCPH-30005R BIOS, which Redump lists as
    ps2-dvd-212k.bin and the Wanted page asks for, answered that no file
    the site knows has it."""

    def test_each_hash_of_a_wanted_row_is_a_record(self):
        import generate_site  # noqa: PLC0415

        row = {"catalog": "redump", "dat": "Sony - PlayStation 2 - BIOS Images",
               "name": "ps2-dvd-212k.bin", "description": "", "size": "4194304",
               "crc32": "1A2B3C4D", "md5": "", "sha1": "5b346eb9258d710609a9855befd35cab8f3a334a"}
        records = generate_site.file_lookup_records(
            {"files": {}, "indexes": {}}, {}, {}, [], wanted=[row, {**row, "dat": "other"}])
        self.assertEqual(records, [
            {"value": "1a2b3c4d", "algorithm": "crc32", "layer": "wanted", "owner": "Redump",
             "name": "ps2-dvd-212k.bin", "url": "/retrobios/provenance/#redump"},
            {"value": "5b346eb9258d710609a9855befd35cab8f3a334a", "algorithm": "sha1",
             "layer": "wanted", "owner": "Redump", "name": "ps2-dvd-212k.bin",
             "url": "/retrobios/provenance/#redump"},
        ])

    def test_the_schema_and_the_page_carry_the_layer(self):
        import json as _json  # noqa: PLC0415

        import generate_site  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        schema = _json.loads((root / "schemas" / "site-api-envelope.schema.json").read_text())
        self.assertIn('"wanted"', _json.dumps(schema))
        self.assertIn("byLayer('wanted')", (root / "website" / "src" / "scripts" / "site.ts").read_text())
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('retired_files.load(_REPO_ROOT / "retired.json"), wanted)', source)


class AMovedPartCardReachesItsPage(unittest.TestCase):
    """One entry added to mame.yml moved 938 of its 1,585 cards from one
    part page to another, and emulators/mame-files-1/#file-mackbd-m0110a-zip
    led to a page without the card: part pages have no card index, and
    site.js redirected only sha1- ids."""

    def test_a_part_page_sends_a_missing_card_to_the_emulator_page(self):
        import re as _re  # noqa: PLC0415

        import generate_site  # noqa: PLC0415

        script = (Path(__file__).resolve().parents[1] / "website" / "src" / "scripts"
                  / "site.ts").read_text(encoding="utf-8")
        body = script.split("const followMovedCard = () => {", 1)[1].split("\n};", 1)[0]
        pattern = _re.search(r"const part = /(.+?)/\.exec\(location\.pathname\)", body).group(1)
        files = [{"name": f"f{i}.bin", "path": f"f{i}.bin", "required": True} for i in range(600)]
        stem = generate_site.emulator_parts("mame", files)[1][0]
        found = _re.search(pattern.replace("\\/", "/"), f"/retrobios/emulators/{stem}/")
        self.assertEqual(found.group(1), "mame")
        self.assertIn("emulators/${part[1]}/#", body)
        self.assertIn("id.startsWith('file-')", body)
        # The emulator page holds the index whose row leads to the card.
        self.assertIn("closest('.rb-card-index tr')", body)


class AFileHasAnAddressByContent(unittest.TestCase):
    """mt32_control.rom moved from the Commodore page to the Roland page and
    every link to its card broke: the anchor was content-based, the page
    was not."""

    def test_index_page_and_resolver(self):
        import generate_site  # noqa: PLC0415

        db = {"files": {
            "ab" * 20: {"path": "bios/Roland/mt32-roms/mt32_control.rom"},
            "cd" * 20: {"path": "data/elsewhere.bin"},
        }}
        self.assertEqual(
            generate_site.file_location_items(db),
            [{"sha1": "ab" * 20, "url": "/retrobios/systems/roland/#sha1-" + "ab" * 6}],
        )
        self.assertIn('id="rb-file-lookup-status"', generate_site.generate_files_page())
        script = (Path(__file__).resolve().parents[1] / "website" / "src" / "scripts"
                  / "site.ts").read_text()
        self.assertIn("api/v1/lookup/", script)
        self.assertIn("params.has('sha1')", script)
        from cross_reference import FileConsumers  # noqa: PLC0415

        card = "\n".join(generate_site._system_file_card(
            {"name": "x.rom", "sha1": "ab" * 20, "size": 1}, FileConsumers({"files": {}}),
        ))
        self.assertIn("/retrobios/files/?sha1=" + "ab" * 20, card)


class ACardNamesThePacksThatInstallIt(unittest.TestCase):
    """A file card named only the platforms whose own list declares the
    file: a RetroBat user found no RetroBat on scph5501.bin, which its pack
    installs for six cores."""

    def test_a_manifest_destination_reaches_the_card(self):
        import json as _json

        from cross_reference import FileConsumers
        from generate_site import _installed_places

        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as tmp:
            Path(tmp, "retrobat.json").write_text(_json.dumps({
                "platform": "retrobat",
                "files": [{"dest": "scph5501.bin", "sha1": "b" * 40,
                           "alternatives": [{"sha1": "a" * 40}]}],
            }))
            consumers = FileConsumers({"files": {}})
            consumers.add_manifests(tmp)
        places = _installed_places("a" * 40, consumers, set())
        self.assertEqual(places, [("RetroBat", "../platforms/retrobat.md", ["scph5501.bin"])])
        self.assertEqual(_installed_places("a" * 40, consumers, {"retrobat"}), [])


class ProseCitationsLinkToThePin(unittest.TestCase):
    """4,328 file:line citations in notes and platform details were plain
    text, while profile_sync keeps each one on the profile's pin."""

    PROFILE = {"source": "https://github.com/libretro/FreeChaF",
               "source_commit": "76c7a84f1f7e80f3e6f2bba96fe100cb24e99124",
               "files": [{"name": "x", "source_ref": "libretro.c:10"}]}

    @mock.patch("sitesources.tree_holds", lambda *_args: True)  # a path the record confirms
    def test_a_rooted_or_structured_path_is_linked(self):
        from sitesources import link_prose_citations

        text = link_prose_citations(
            self.PROFILE, "BIOS loading is in src/libretro.c:186-208 and libretro.c:12.")
        self.assertIn("[`src/libretro.c:186-208`](https://github.com/libretro/FreeChaF/blob/"
                      "76c7a84f1f7e80f3e6f2bba96fe100cb24e99124/src/libretro.c#L186-L208)", text)
        self.assertIn("[`libretro.c:12`](", text)

    def test_what_cannot_be_placed_stays_text(self):
        from sitesources import link_prose_citations

        self.assertEqual(link_prose_citations(self.PROFILE, "see memory.c:5"), "see memory.c:5")
        self.assertEqual(link_prose_citations(self.PROFILE, "in `src/a.c:5`"), "in `src/a.c:5`")
        two = {**self.PROFILE, "upstream": "https://github.com/x/y", "upstream_commit": "a" * 40}
        self.assertEqual(link_prose_citations(two, "src/a.c:5"), "src/a.c:5")

    def test_two_repositories_link_into_the_one_holding_the_path(self):
        """1,044 citations in 86 profiles that read two repositories stayed
        text, the swanstation note on FindBIOSImageInDirectory among them."""
        from sitesources import link_prose_citations

        two = {**self.PROFILE, "upstream": "https://github.com/x/y", "upstream_commit": "a" * 40}

        def holds(repo, _pin, path):
            return path == "src/both.c" or (path == "src/port.c") == (repo.owner == "libretro")

        with mock.patch("sitesources.tree_holds", holds):
            text = link_prose_citations(two, "src/port.c:5, src/emu.c:7 and src/both.c:9")
            upstream_only = link_prose_citations(two, "upstream src/port.c:5")
            named = link_prose_citations(two, "upstream src/both.c:9")
        self.assertIn("[`src/both.c:9`](https://github.com/x/y/blob/", named)
        self.assertIn("[`src/port.c:5`](https://github.com/libretro/FreeChaF/blob/", text)
        self.assertIn("[`src/emu.c:7`](https://github.com/x/y/blob/" + "a" * 40, text)
        # Held by both: the citation does not say which it means.
        self.assertIn(" src/both.c:9", text)
        # The role word names a repository that does not hold it.
        self.assertNotIn("](", upstream_only)


class ACitationSaysWhoseCodeItIs(unittest.TestCase):
    """Readers could not tell whether the libretro core or the emulator asked
    for a file: both trees were cited alike, and left unlinked."""

    PROFILE = {"type": "libretro", "source": "https://github.com/libretro/a5200",
               "upstream": "https://github.com/alekmaul/a5200",
               "source_commit": "a" * 40, "upstream_commit": "b" * 40}

    @mock.patch("sitesources.tree_holds", lambda *_args: True)  # a path the record confirms
    def test_each_part_links_to_its_repository_with_its_label(self):
        from sitesources import _source_ref_markdown, requested_by

        ref = "source libretro.c:5, upstream emu/memory.c:46, 50-52"
        text = _source_ref_markdown(self.PROFILE, ref)
        self.assertIn("libretro/a5200/blob/" + "a" * 40 + "/libretro.c#L5) (libretro glue)", text)
        self.assertIn("alekmaul/a5200/blob/" + "b" * 40 + "/emu/memory.c#L50-L52) (upstream emulator)",
                      text)
        self.assertEqual(requested_by(self.PROFILE, ref), "libretro glue and upstream emulator")
        self.assertEqual(requested_by(self.PROFILE, "source src/mem.c:107"),
                         "emulator code, libretro port")
        self.assertEqual(requested_by(self.PROFILE, "upstream emu/memory.c:46"),
                         "upstream emulator")

    def test_a_role_without_a_pin_links_nowhere_else(self):
        from sitesources import _source_ref_markdown

        profile = {**self.PROFILE, "upstream_commit": ""}
        self.assertEqual(_source_ref_markdown(profile, "upstream emu/memory.c:46"),
                         "`emu/memory.c:46` (upstream emulator)")


class EveryAcceptedHashIsItsOwnWord(unittest.TestCase):
    """Recalbox md5 lists rendered as one comma-joined code span: the site
    search made one token of it and found none but the first."""

    def test_a_list_is_split(self):
        from generate_site import _hash_spans

        md5s = ["96cf" + "0" * 28, "d5af" + "0" * 28]
        text = _hash_spans(",".join(md5s))
        for md5 in md5s:
            self.assertIn(f'<code class="rb-hash">{md5}</code>', text)


class AMismatchNamesTheDumpTheCollectionHolds(unittest.TestCase):
    """The gaps table printed the hash an emulator accepts and stopped, while
    the collection held that exact dump for every row."""

    def test_the_held_copy_is_named(self):
        from generate_site import _held_accepted

        db = {"files": {"s1": {"path": "bios/Microsoft/MSX/CLK/msx-japanese.rom"}},
              "indexes": {"by_sha256": {"ab" * 32: "s1"}, "by_crc32": {"84f68bf9": "s1"}}}
        text = ("RetroBat says OK but ares says sha256 mismatch: got " + "cd" * 32
                + ", accepted [" + "ab" * 32 + "]")
        self.assertEqual(_held_accepted(text, db), "bios/Microsoft/MSX/CLK/msx-japanese.rom")
        self.assertEqual(_held_accepted("xroar says crc32 mismatch: got 1, accepted [84f68bf9]", db),
                         "bios/Microsoft/MSX/CLK/msx-japanese.rom")
        self.assertEqual(_held_accepted("size mismatch: got 1, accepted [256]", db), "")


class ADataDirectoryFileCanBeLookedUp(unittest.TestCase):
    """2,534 hashes the packs ship from data directories were on no page:
    the emulator page gave only a URL whose content moves."""

    def test_a_member_resolves_to_its_emulator_page(self):
        import json as _json

        from generate_site import data_directory_members, file_location_items

        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as tmp:
            Path(tmp, "retroarch.json").write_text(_json.dumps({"data_directories": [
                {"ref": "dolphin-sys", "files": {"GC/font.bin": {"sha1": "c" * 40, "size": 3}}},
            ]}))
            members = data_directory_members(Path(tmp))
        items = file_location_items(
            {"files": {}}, {"dolphin": {"data_directories": [{"ref": "dolphin-sys"}]}}, members)
        self.assertEqual(items, [{"sha1": "c" * 40,
                                  "url": "/retrobios/emulators/dolphin/#sha1-cccccccccccc"}])


class ACardSaysWhyAFileIsLeftOut(unittest.TestCase):
    """The badge said "bundled" and nothing about which build, so a reader
    could not tell why a RetroArch pack carried PPSSPP's assets."""

    def test_the_build_and_the_platforms_are_named(self):
        from generate_site import _file_badges

        badges = " ".join(_file_badges({"name": "a", "bundled": True, "mode": "standalone"}, True))
        self.assertIn("installed with the standalone emulator", badges)


class AnEmulatorPageOffersItsInstall(unittest.TestCase):
    """An emulator page linked each file one by one and offered no way to
    install them together."""

    def test_the_command_names_the_emulator(self):
        from generate_site import _install_block

        profile = yaml.safe_load((ROOT / "emulators" / "pcem.yml").read_text(encoding="utf-8"))
        text = "\n".join(_install_block("pcem", profile))
        self.assertIn("/i | sh -s -- --emulator pcem", text)
        self.assertIn("/i.ps1))) --emulator pcem", text)
        self.assertEqual(_install_block("x", {"type": "alias"}), [])

    def test_the_installer_takes_the_option(self):
        source = (ROOT / "install.py").read_text(encoding="utf-8")
        self.assertIn('"--emulator"', source)


class NestedProfileBlocksRenderAsLists(unittest.TestCase):
    """The clownmdemu page showed "- **external_required:** False" in a code
    block: a key written as a paragraph left its children indented eight
    spaces inside the admonition, which Markdown reads as code."""

    def _html(self, value: object) -> str:
        try:
            import markdown
        except ImportError:
            self.skipTest("markdown is not installed")
        from siterender import _render_yaml_value

        # The page opens the block with ???+ (pymdownx.details). An admonition
        # nests its body by the same four spaces, and needs nothing CI lacks.
        lines = ['!!! abstract "Analysis"', ""]
        _render_yaml_value(lines, value, 4)
        return markdown.markdown("\n".join(lines), extensions=["admonition"])

    def test_a_nested_mapping_is_a_nested_list(self):
        html = self._html({"megacd_bios": {"external_required": False, "source_ref": "a.c:1"},
                           "tmss": {"supported": True}})
        self.assertNotIn("<pre>", html)
        self.assertNotIn("**", html)
        self.assertIn("<strong>external required:</strong> no", html)
        self.assertIn("<code>a.c:1</code>", html)

    def test_platform_details_are_a_list(self):
        import generate_site

        lines = generate_site._render_platform_details(
            {"platform_details": {"megacd": {"root": "x"}, "note": "y"}}
        )
        try:
            import markdown
        except ImportError:
            self.skipTest("markdown is not installed")
        # The block's body, read as the engine reads Markdown inside HTML.
        body = lines[lines.index("<summary>Platform details</summary>") + 1:
                     lines.index("</details>")]
        html = markdown.markdown("\n".join(body))
        self.assertIn("<li>root: x</li>", html)
        self.assertNotIn("**", html)

    def test_a_list_under_a_key_is_a_sublist(self):
        html = self._html({"roms": [{"name": "a.bin", "size": 2}, "b.bin"]})
        self.assertNotIn("<pre>", html)
        self.assertIn("name: a.bin, size: 2", html)


class TheOneLinerIsWhereUsersLand(unittest.TestCase):
    """The download page had no Android line and no Windows form with
    options, and the platform and system pages offered only ZIP parts."""

    def test_download_page(self):
        import generate_site  # noqa: PLC0415

        page = generate_site.generate_which_pack()
        self.assertIn("Android (Termux", page)
        self.assertIn("/i.ps1))) --check", page)
        self.assertIn("--platform retroarch --dest", page)

    def test_platform_and_system_pages(self):
        import generate_site  # noqa: PLC0415
        from cross_reference import FileConsumers  # noqa: PLC0415

        cov = {"platform": "Batocera", "mode": "md5", "present": 0, "total": 0,
               "verified": 0, "missing": 0, "details": [], "config": {"systems": {}}}
        page = generate_site.generate_platform_page("batocera", cov)
        self.assertIn("/i | sh -s -- --platform batocera", page)
        # Batocera runs the command on the device itself, so its page opens on
        # the computer route. A platform detected on Windows gets the
        # PowerShell form, and its command comes before the ZIP.
        cov = dict(cov, platform="RetroArch", mode="existence")
        page = generate_site.generate_platform_page("retroarch", cov)
        self.assertIn("/i.ps1))) --platform retroarch", page)
        self.assertIn("/i | sh -s -- --platform retroarch", page)
        self.assertLess(page.index("--platform retroarch"), page.index("rb-button"))

        entry = {"name": "a.bin", "sha1": "a" * 40, "md5": "b" * 32, "size": 3,
                 "path": "bios/Recalbox/MSX/a.bin"}
        page = generate_site.generate_system_page(
            "Microsoft", {"MSX": [entry]}, FileConsumers({"files": {}}),
            {"MSX": [("recalbox", "msx1,msx2,msxturbor"), ("batocera", "msx1")]})
        # The whole system id, up to the end of the command.
        self.assertRegex(page, r"--platform recalbox --system msx1,msx2,msxturbor(\n|</code>)")
        self.assertIn("--platform batocera --system msx1", page)

    def test_a_system_is_offered_only_where_the_manifest_records_it(self):
        import generate_site  # noqa: PLC0415
        import siterender  # noqa: PLC0415

        saved = dict(siterender._system_page_map)
        self.addCleanup(siterender.set_system_page_map, saved)
        siterender.set_system_page_map({"sony-playstation": ("sony", "PlayStation"),
                                        "nowhere": ("sony", "PlayStation")})
        cov = {"retroarch": {"config": {"systems": {"sony-playstation": {}, "nowhere": {}}}}}
        choices = generate_site.system_install_choices(cov)
        self.assertEqual(choices["sony"]["PlayStation"], [("retroarch", "sony-playstation")])


class TheGapPageOpensOnCounts(unittest.TestCase):
    """The page opened on a slogan and on tiles reading "Verified (100%)"
    for 5,437 of 5,438 files and "Missing 0", above a table of red cells."""

    def test_every_count_is_said(self):
        import generate_site  # noqa: PLC0415

        text = generate_site._platform_lists_sentence(5438, 5437, 1, 0)
        self.assertIn("Of the 5,438 files", text)
        self.assertIn("5,437 are held", text)
        self.assertIn("1 is held but not verified", text)
        self.assertIn("0 are missing", text)
        self.assertNotIn("%", text)
        source = (Path(__file__).resolve().parents[1] / "scripts" / "generate_site.py").read_text()
        self.assertNotIn("Unified view of BIOS verification", source)


class WhichPackDescribesNoPlatformByOpinion(unittest.TestCase):
    """The page called RetroPie the largest community with the most guides,
    Batocera an easy setup and Recalbox good for a first build: claims
    nothing in the repository measures, ranking platforms against each
    other."""

    def test_no_ranking_words(self):
        import re

        import generate_site  # noqa: PLC0415

        page = generate_site.generate_which_pack()
        rows = [line for line in page.splitlines() if line.startswith("| ")]
        found = [
            row for row in rows
            if re.search(r"\b(largest|most|popular|easy|best|classic|lightweight|"
                         r"one-click|plug-and-play|first build|accuracy-focused)\b",
                         row, re.IGNORECASE)
        ]
        self.assertEqual(found, [])


class EveryPageLinksItsOwnData(unittest.TestCase):
    """An emulator page linked its YAML and JSON. A platform page linked
    nothing, and a tool had to download platforms.json (2.8 MB) and filter
    it. A system page linked nothing either."""

    def test_platform_and_system_documents(self):
        import generate_site  # noqa: PLC0415
        from cross_reference import FileConsumers  # noqa: PLC0415

        cov = {"platform": "Batocera", "mode": "md5", "present": 0, "total": 0,
               "verified": 0, "missing": 0, "details": [], "config": {"systems": {}}}
        page = generate_site.generate_platform_page("batocera", cov)
        self.assertIn("[JSON](../api/v1/platforms/batocera.json)", page)
        self.assertIn("/blob/main/platforms/batocera.yml)", page)

        entry = {"name": "a.bin", "sha1": "a" * 40, "md5": "b" * 32, "size": 3,
                 "path": "bios/Sony/PlayStation/a.bin"}
        page = generate_site.generate_system_page(
            "Sony", {"PlayStation": [entry]}, FileConsumers({"files": {}}))
        self.assertIn(" as JSON](../api/v1/systems/sony.json)", page)

        item = generate_site.system_export_item("sony", "Sony", {"PlayStation": [entry]})
        self.assertEqual(item["consoles"]["PlayStation"][0]["sha1"], "a" * 40)
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / "tmp") as tmp:
            path = Path(tmp) / "sony.json"
            generate_site.write_single_item(path, "systems", item, "2026-10-21T00:00:00Z")
            document = json.loads(path.read_text())
        self.assertEqual(document["count"], 1)
        try:
            import jsonschema  # noqa: PLC0415
        except ImportError:
            return
        root = Path(__file__).resolve().parents[1]
        envelope = json.loads((root / "schemas" / "site-api-envelope.schema.json").read_text())
        jsonschema.validate(document, envelope)


if __name__ == "__main__":
    unittest.main()
