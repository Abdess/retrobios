"""Reference data: exports, contracts, API documents and manifests.

The exports carry what the pages show, every served document validates
against its contract and carries the commit, and the Data page lists what
is served.

The API said Lakka and RetroPie had a release pack while their pages said
none, 50 nested manifest fields and the nine omission codes had no
description, the lookup named 9 emulators where the card named 11, four
served schemas and the target lists appeared nowhere on the Data page, the
folder check exited 0 on a folder missing every file, and a system id did
not lead to its JSON document. Tests reading the generated site skip when
it has not been generated.
"""

from __future__ import annotations

import tests
from tests.sources import script_source

import csv
import io
import json
import unittest
from pathlib import Path
from unittest import mock
import hashlib
import sqlite3
import tempfile

from model import siteinputs
from sitegen import apiitems
from sitegen import config as sitegen_config
from sitegen import dataexports
from sitegen import exportrows
from sitegen import datapage
from sitegen import lookup
from sitegen import platformfiles
from sitegen import provenance
from sitegen import publish
from sitegen import render
from sitegen import runlinks
from model.registry import list_release_pack_platforms
from model import releaserecord
from acquire.provenance import build_report
from model.dumpcatalog import load_provenance_snapshots
from tests.sitepages import API, DIST, PUBLIC, REPO_ROOT, SITE, built


class ExportsComplete(unittest.TestCase):
    def test_gap_rows_once_with_their_outcome(self):
        path = next(iter(platformfiles._collection_db(str(siteinputs.current().db))["files"].values()))["path"]
        detail = {"name": "x.bin", "system": "s", "status": "untested", "path": path,
                  "category": "bios"}
        coverages = {"p": {"platform": "P", "details": [
            {"name": "h.xml", "system": "s", "status": "missing"},
            {"name": "h.xml", "system": "s", "status": "missing"}, detail]}}
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        rows = exportrows.gap_export_rows(coverages, {}, db)
        self.assertEqual([r["name"] for r in rows], ["h.xml", "x.bin"])
        held = rows[1]
        self.assertEqual(held["collection_path"], path)
        self.assertEqual(held["resolved_sha1"], platformfiles._collection_sha1(path))
        self.assertEqual(held["category"], "bios")

    def test_a_path_spelled_another_way_keeps_its_sha1(self):
        """The export matched the raw string: bios/./x lost its sha1."""
        db = {"files": {"a" * 40: {"path": "bios/X/x.bin"}}}
        coverages = {"p": {"platform": "P", "details": [
            {"name": "x.bin", "system": "s", "status": "untested", "path": "bios/./X/x.bin"}]}}
        rows = exportrows.gap_export_rows(coverages, {}, db)
        self.assertEqual(rows[0]["resolved_sha1"], "a" * 40)

    def test_platform_rows_carry_status_and_file(self):
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        sha1, entry = next(iter(db["files"].items()))
        coverages = {"p": {"platform": "P", "config": {"systems": {"s": {"files": [
            {"name": "a.bin"}, {"name": "b.bin"}]}}}, "details": [
            {"name": "a.bin", "system": "s", "status": "ok", "path": entry["path"],
             "category": "bios"},
            {"name": "b.bin", "system": "s", "status": "missing", "category": "game_data"}]}}
        _items, rows = exportrows.platform_export_rows(coverages, db)
        self.assertEqual((rows[0]["status"], rows[0]["resolved_sha1"]), ("ok", sha1))
        self.assertEqual(rows[0]["collection_path"], entry["path"])
        self.assertEqual((rows[1]["status"], rows[1]["category"], rows[1]["collection_path"]),
                         ("missing", "game_data", ""))

    def test_commit_and_wanted_list(self):
        commit = exportrows.source_commit()
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        schema = json.loads((REPO_ROOT / "schemas" / "site-api-envelope.schema.json")
                            .read_text(encoding="utf-8"))
        self.assertIn("commit", schema["properties"])
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        rows = exportrows.provenance_wanted_rows(provenance.wanted_dumps(
            build_report(db, load_provenance_snapshots()), provenance.load_derivable()))
        self.assertTrue(rows)
        self.assertTrue(all(r["catalog"] and r["name"] for r in rows))
        text = dataexports._csv_document(list(exportrows.WANTED_FIELDS), rows)
        self.assertEqual(next(csv.reader(io.StringIO(text))), list(exportrows.WANTED_FIELDS))


class TheExportsKeepWhatACheckNeeds(unittest.TestCase):
    """8.1: zipped_file and the Recalbox flags reach the CSV and SQLite."""

    COVERAGE = {"batocera": {
        "platform": "Batocera", "details": [],
        "config": {"platform": "Batocera", "verification_mode": "md5",
                   "install": {"detect": []}, "logo": "x.svg", "_key": "batocera",
                   "systems": {"bbc": {"files": [
                       {"name": "bbcb.zip", "destination": "bbcb.zip",
                        "md5": "521a197d", "zipped_file": "basic1.rom"},
                       {"name": "n.rom", "destination": "n.rom", "md5": "ab",
                        "hash_match_mandatory": True, "mandatory_declared": False,
                        "shared_group": "group-x"},
                   ]}}},
    }}

    def test_rows_carry_the_member_and_the_flags(self):
        _items, rows = exportrows.platform_export_rows(self.COVERAGE)
        zipped, flagged = rows
        self.assertEqual(zipped["zipped_file"], "basic1.rom")
        self.assertIs(flagged["hash_match_mandatory"], True)
        self.assertIs(flagged["mandatory_declared"], False)
        self.assertEqual(flagged["shared_group"], "group-x")
        self.assertEqual(flagged["zipped_file"], "")

    def test_the_csv_header_and_the_table_name_them(self):
        source = script_source("generate_site.py")
        self.assertIn('"collection_path", "resolved_sha1", *ENTRY_EXPORT_FIELDS,', source)
        for field in exportrows.ENTRY_EXPORT_FIELDS:
            self.assertIn(f":{field}", source)
        for field in ("zipped_file", "hash_match_mandatory", "mandatory_declared", "curated"):
            self.assertIn(field, exportrows.ENTRY_EXPORT_FIELDS)

    def test_the_built_csv_has_the_column(self):
        text = built(PUBLIC / "downloads" / "platform-files.csv").read_text(encoding="utf-8")
        rows = list(csv.DictReader(io.StringIO(text)))
        batocera = [row for row in rows if row["platform_id"] == "batocera"]
        self.assertGreater(sum(1 for row in batocera if row["zipped_file"]), 300)
        with sqlite3.connect(built(PUBLIC / "downloads" / "retrobios.sqlite")) as db:
            count = db.execute("SELECT count(*) FROM platform_files "
                               "WHERE platform_id = 'batocera' AND zipped_file != ''").fetchone()[0]
            license_row = db.execute("SELECT value FROM metadata WHERE key = 'license'").fetchone()
        self.assertGreater(count, 300)
        self.assertEqual(license_row[0], sitegen_config.DATA_LICENSE)


class TheContractsValidate(unittest.TestCase):
    """8.4: registry keys leave the contract, every $id is its served URL."""

    def test_every_contract_validates_against_the_platform_schema(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")

        from model.registry import list_registered_platforms
        from model.platforms import PLATFORMS_DIR_KEY, load_platform_config, registry_fields

        schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text())
        validator = Draft202012Validator(schema)
        platforms = str(REPO_ROOT / "platforms")
        for name in list_registered_platforms(platforms):
            config = load_platform_config(name, platforms)
            contract, registry = exportrows._split_contract(config)
            with self.subTest(platform=name):
                errors = [error.message for error in validator.iter_errors(contract)]
                self.assertEqual(errors, [])
                self.assertIn("install", registry)
                self.assertNotIn("_key", registry)
                # The directory a run loaded the config from is no published field.
                self.assertNotIn(PLATFORMS_DIR_KEY, registry)
                # The registry is what the loader merged from _registry.yml,
                # never a key it adds for its own readers (_roms_root).
                self.assertEqual(set(registry), set(registry_fields(config)) - set(contract))
                self.assertEqual([key for key in registry if key.startswith("_")], [])
                self.assertLessEqual(set(contract) | set(registry), set(config))

    def test_every_schema_id_is_the_address_it_is_served_at(self):
        for path in sorted((REPO_ROOT / "schemas").glob("*.schema.json")):
            schema = json.loads(path.read_text())
            with self.subTest(schema=path.name):
                self.assertEqual(schema.get("$id"), f"{SITE}api/v1/schemas/{path.name}")

    def test_every_schema_is_published(self):
        published = {p.name for p in built(API / "schemas").glob("*.json")}
        self.assertEqual(published, {p.name for p in (REPO_ROOT / "schemas").glob("*.schema.json")})

    def test_the_built_api_validates(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")

        schemas = {p.name: json.loads(p.read_text()) for p in (REPO_ROOT / "schemas").glob("*.json")}
        envelope = Draft202012Validator(schemas["site-api-envelope.schema.json"])
        platform = Draft202012Validator(schemas["platform.schema.json"])
        document = json.loads(built(API / "platforms.json").read_text())
        self.assertEqual(list(envelope.iter_errors(document)), [])
        for item in document["items"]:
            with self.subTest(platform=item["id"]):
                self.assertEqual([e.message for e in platform.iter_errors(item["contract"])], [])
        for name in ("systems.json", "cores.json", "index.json", "catalog.json"):
            with self.subTest(document=name):
                self.assertEqual(
                    [e.message for e in envelope.iter_errors(json.loads((API / name).read_text()))], [])


class TheIndexSaysWhatTheCatalogLists(unittest.TestCase):
    """index.json called catalog.json every published file, while the 990
    one-item documents of emulators/, platforms/, systems/ and lookup/ are
    in none of its 80 items."""

    def test_the_description_matches_the_items(self):
        index = json.loads(built(API / "index.json").read_text())
        catalog = json.loads(built(API / "catalog.json").read_text())
        described = next(i["description"] for i in index["items"] if i["url"] == "catalog.json")
        self.assertNotIn("Every published file", described)
        listed = {item["url"].split("/", 1)[0] for item in catalog["items"]}
        for folder in ("emulators", "platforms", "systems", "lookup"):
            with self.subTest(folder=folder):
                self.assertIn(f"{folder}/", described)
                self.assertNotIn(folder, listed)
                self.assertTrue(any((API / folder).glob("*.json")))


class EveryEnvelopeCarriesTheCommit(unittest.TestCase):
    """8.5: emulators/ and systems/ lacked `commit` (716 documents)."""

    def test_the_writers_pass_it(self):
        source = script_source("generate_site.py")
        self.assertIn('build_timestamp(db), source_commit(),\n        )\n'
                      "    clash", source)
        block = source[source.index("public_profiles = {"):source.index("pages = emulator_pages(")]
        self.assertIn("write_single_item(", block)
        self.assertIn("source_commit()", block)

    def test_every_built_envelope_has_it(self):
        built(API / "catalog.json")
        if not exportrows.source_commit():
            raise unittest.SkipTest("not a git checkout")
        lacking = [
            path.relative_to(API).as_posix() for path in sorted(API.rglob("*.json"))
            if path.parent.name not in ("schemas", "manifests", "targets", "exports")
            and path.name not in ("database.json", "stats.json", "release.json")
            and "commit" not in json.loads(path.read_text())
        ]
        self.assertEqual(lacking, [])


class ManifestsArePublished(unittest.TestCase):
    """8.2: the manifest a pack installs, byte for byte, in the catalog."""

    def test_each_manifest_is_the_repository_file(self):
        catalog = json.loads(built(API / "catalog.json").read_text())
        listed = {item["url"]: item for item in catalog["items"]}
        for source in sorted((REPO_ROOT / "install").glob("*.json")):
            with self.subTest(manifest=source.name):
                item = listed[f"manifests/{source.name}"]
                self.assertEqual(item["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
                self.assertEqual(item["schema"], "schemas/install-manifest.schema.json")
        self.assertIn("release.json", listed)
        self.assertEqual(catalog["license"], sitegen_config.DATA_LICENSE)

    def test_the_data_page_explains_the_fields_from_the_schema(self):
        page = datapage.generate_data_page([])
        schema = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())
        for field in ("dest", "repo_path", "release_asset", "cores"):
            description = schema["$defs"]["file"]["properties"][field]["description"]
            self.assertIn(f"| `{field}` | {render.escape_tags(description)} |", page)
        self.assertIn("## Platform manifests", page)
        self.assertIn("**Licence:**", page)
        self.assertIn("## Hosting, rate limits and caching", page)
        # The endpoints first, the DAT below them.
        self.assertLess(page.index("## Stable JSON endpoints"), page.index("The DAT is Logiqx XML"))


class AnIdLeadsToItsData(unittest.TestCase):
    """8.6: a system by its id, a core by the name the buildbot gives it."""

    def test_a_buildbot_name_designates_its_profile(self):
        profiles = {
            "beetle_psx": {"type": "libretro", "cores": ["mednafen_psx", "mednafen_psx_hw"]},
            "pcsx2": {"type": "standalone"},
            "lrps2": {"type": "libretro", "cores": ["pcsx2"]},
            "mednafen_psx_alias": {"type": "alias", "alias_of": "beetle_psx"},
            "probe": {"type": "libretro", "role": "test", "cores": ["probe_core"]},
        }
        items = apiitems.core_index_items(profiles)
        by_name: dict[str, list[tuple[str, bool]]] = {}
        for item in items:
            by_name.setdefault(item["name"], []).append((item["profile"], item["preferred"]))
        self.assertEqual(by_name["mednafen_psx"], [("beetle_psx", True)])
        self.assertEqual(by_name["pcsx2"], [("pcsx2", True), ("lrps2", False)])
        self.assertEqual(by_name["mednafen_psx_alias"], [("beetle_psx", True)])
        self.assertNotIn("probe_core", by_name)

    def test_the_built_index_resolves_ids_to_sections(self):
        items = {item["id"]: item for item in
                 json.loads(built(API / "systems.json").read_text())["items"]}
        color = items["wonderswan-color"]
        self.assertEqual(color["name"], "Bandai WonderSwan Color")
        self.assertTrue(color["url"].startswith("/retrobios/systems/bandai/"), color["url"])
        self.assertTrue(items["sony-playstation"]["sha1"])
        cores = json.loads((API / "cores.json").read_text())["items"]
        self.assertIn({"name": "mednafen_psx", "profile": "beetle_psx", "preferred": True}, cores)


class ManifestFieldsAreComplete(unittest.TestCase):
    """8.3 and 8.4."""

    SCHEMA = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())

    def test_a_url_template_is_code(self):
        rows = datapage._schema_field_rows(self.SCHEMA["$defs"]["file"], ("repo_path",))
        self.assertIn("`https://raw.githubusercontent.com/Abdess/retrobios/<ref>/<repo_path>`",
                      rows[0])
        rows = datapage._schema_field_rows(
            {"properties": {"a": {"description": "From https://x.test/<asset>, then."}}}, ("a",))
        self.assertEqual(rows, ["| `a` | From `https://x.test/<asset>`, then. |"])

    def test_every_field_is_described_and_shown(self):
        page = datapage.generate_data_page([])
        for schema in (self.SCHEMA, self.SCHEMA["$defs"]["file"]):
            for key, spec in schema["properties"].items():
                self.assertTrue(spec.get("description"), key)
                self.assertIn(f"| `{key}` |", page)

    def test_no_link_carries_an_escaped_bracket(self):
        html = built(DIST / "data" / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(html, r'href="[^"]*&amp;lt;')
        self.assertNotRegex(html, r'href="[^"]*&lt;')


class EverySystemIdWithFilesHasAPage(unittest.TestCase):
    """8.5: tyrian, scummvm, dos and 25 more had files and a null url."""

    def test_built_index(self):
        items = json.loads(built(API / "systems.json").read_text())["items"]
        orphans = [item["id"] for item in items if item["sha1"] and not item["url"]]
        self.assertEqual(orphans, [])

    def test_first_file_then_emulator(self):
        files = {"f" * 40: {"path": "bios/DOS/DOS/a.bin"}}
        with mock.patch.object(runlinks.current(), "card_pages", {}):
            place = apiitems._first_file_place(
                "dos", ["f" * 40], files, {}, lambda path, sha1: "dos")
        self.assertEqual(place, ("DOS", "/retrobios/systems/dos/#sha1-ffffffffffff"))
        place = apiitems._first_file_place(
            "tyrian", [], files, {"opentyrian": {"systems": ["tyrian"]}}, None)
        self.assertEqual(place, ("", "/retrobios/emulators/opentyrian/"))


class TheReleaseRecordHasAVersion(unittest.TestCase):
    """8.9."""

    def test_the_writer_and_the_committed_record(self):
        self.assertEqual(releaserecord.SCHEMA_VERSION, 1)
        source = script_source("release_record.py")
        self.assertIn('{"schema_version": SCHEMA_VERSION, "tag": tag, "packs": packs}', source)
        schema = json.loads((REPO_ROOT / "schemas" / "release.schema.json").read_text())
        self.assertIn("schema_version", schema["required"])
        record = json.loads((REPO_ROOT / "release.json").read_text())
        self.assertEqual(record["schema_version"], 1)


GENERATED = REPO_ROOT / "website" / "src" / "generated"

SCHEMA = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())


def _released() -> set[str]:
    return set(list_release_pack_platforms(str(REPO_ROOT / "platforms")))


class OneAnswerOnReleasePacks(unittest.TestCase):
    """8.1: the API, the picker's data and the pages read the registry."""

    def test_a_child_does_not_inherit_its_parents_pack(self):
        _contract, registry = exportrows._split_contract(
            {"_key": "lakka", "inherits": "retroarch", "release_pack": True})
        self.assertIs(registry["release_pack"], "lakka" in _released())
        _contract, registry = exportrows._split_contract({"_key": "minui"})
        self.assertNotIn("release_pack", registry)
        _contract, registry = exportrows._split_contract({"_key": "retroarch"})
        self.assertIs(registry["release_pack"], "retroarch" in _released())

    def test_api_release_pack_set_equals_the_registry(self):
        found = set()
        for path in built(API / "platforms").glob("*.json"):
            item = json.loads(path.read_text())["items"][0]
            if item["registry"].get("release_pack"):
                found.add(item["id"])
        self.assertEqual(found, _released())

    def test_the_picker_file_is_the_advertised_record(self):
        with tempfile.TemporaryDirectory() as folder:
            publish.write_release_advertised(Path(folder))
            written = json.loads((Path(folder) / "release-advertised.json").read_text())
        self.assertEqual(written, releaserecord.load_advertised())
        served = {p for pack in written.get("packs", {}).values() for p in pack["platforms"]}
        self.assertLessEqual(served, _released())

    def test_the_built_picker_file(self):
        written = json.loads(built(GENERATED / "release-advertised.json").read_text())
        self.assertEqual(written, releaserecord.load_advertised())


def _properties(node: object, path: str = ""):
    """(path, spec) of every property at any depth, $defs included."""
    if not isinstance(node, dict):
        return
    for key, spec in (node.get("properties") or {}).items():
        yield f"{path}{key}", spec
        yield from _properties(spec, f"{path}{key}.")
    for key in ("items", "additionalProperties"):
        yield from _properties(node.get(key), path)
    for name, spec in (node.get("$defs") or {}).items():
        yield from _properties(spec, f"#{name}.")
    for key in ("oneOf", "anyOf", "allOf"):
        for spec in node.get(key) or []:
            yield from _properties(spec, path)


class EveryManifestFieldIsDescribed(unittest.TestCase):
    """8.2: every property at any depth, and each omission code."""

    def test_every_property_has_a_description(self):
        missing = [path for path, spec in _properties(SCHEMA)
                   if isinstance(spec, dict) and not spec.get("description")]
        self.assertEqual(missing, [])

    def test_each_reason_code_has_a_line(self):
        page = datapage.generate_data_page([])
        for path, spec in _properties(SCHEMA):
            if path.endswith(".reason"):
                self.assertEqual(len(spec["enumDescriptions"]), len(spec["enum"]), path)
                for code in spec["enum"]:
                    self.assertRegex(page, rf"\n- `{code}`: \S")

    def test_nested_tables_are_on_the_page(self):
        page = datapage.generate_data_page([])
        for label in ("Each entry of `omitted_files`:", "Each entry of `data_directories`:",
                      "Each value of `data_directories[].files`:", "Fields of `save_directory`:",
                      "Each entry of `files[].alternatives`:",
                      "Each entry of `files[].slot_choices`:",
                      "Each entry of `files[].declared_choices`:",
                      "Each entry of `files[].absent_claims`:"):
            self.assertIn(label, page)
        for key in ("below_platform_folder", "strip_components", "by_core"):
            self.assertIn(f"`{key}`", page)


class TheDataPageListsWhatIsServed(unittest.TestCase):
    """8.4 and 8.6."""

    def test_every_schema_is_listed(self):
        page = datapage.generate_data_page([])
        for path in (REPO_ROOT / "schemas").glob("*.schema.json"):
            self.assertIn(f"- [`{path.name}`](api/v1/schemas/{path.name}): ", page)

    def test_target_lists_are_published_and_catalogued(self):
        catalog = json.loads(built(API / "catalog.json").read_text())
        listed = {item["url"] for item in catalog["items"]}
        for source in (REPO_ROOT / "install" / "targets").glob("*.json"):
            self.assertIn(f"targets/{source.name}", listed)
            self.assertEqual((API / "targets" / source.name).read_bytes(), source.read_bytes())

    def test_declared_only_and_search_words(self):
        page = datapage.generate_data_page([])
        self.assertIn("With `--declared-only`, or from the `declared` event, "
                      "`install.py --check` answers it too.", page)
        terms = page.split("\n", 2)[1]
        for word in ("json schema", "license", "check bios folder script"):
            self.assertIn(word, terms)
        files_terms = lookup.generate_files_page().split("---\n", 2)[1]
        for word in ("is my bios correct", "is my bios right"):
            self.assertIn(word, files_terms)


class SystemItemsCarryTheirApi(unittest.TestCase):
    """8.7."""

    def test_each_api_address_is_served(self):
        items = json.loads(built(API / "systems.json").read_text())["items"]
        playstation = next(i for i in items if i["id"] == "sony-playstation")
        self.assertEqual(playstation["api"], "/retrobios/api/v1/systems/sony.json")
        for item in items:
            if item["url"] is not None:
                self.assertIsNotNone(item["api"], item["id"])
            if item["api"]:
                self.assertTrue((PUBLIC / item["api"].removeprefix("/retrobios/")).is_file(),
                                item["api"])


if __name__ == "__main__":
    unittest.main()
