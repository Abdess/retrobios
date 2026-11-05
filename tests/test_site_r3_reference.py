"""Reference pages and data.

The CSV and SQLite dropped zipped_file, so a check built from them judged
106 good Batocera files wrong. The manifest a pack installs was nowhere on
the site. Contracts failed their own schema, 716 documents lacked `commit`,
no endpoint answered a system id or a buildbot core name, lookup URLs
resolved to 404s, the data's licence went unstated, platform overviews
named emulators as unlinked ids, gaps tables overflowed with full hashes
and a source link went into a repository that does not hold the file.
Tests that read the built site skip when it has not been generated.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
import urllib.parse
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_platform_folder  # noqa: E402
import generate_site  # noqa: E402
import sitesources  # noqa: E402

PUBLIC = REPO_ROOT / "website" / "public"
API = PUBLIC / "api" / "v1"
SITE = "https://abdess.github.io/retrobios/"
TMP = REPO_ROOT / "tmp"


def _built(path: Path) -> Path:
    if not path.exists():
        raise unittest.SkipTest(f"{path.relative_to(REPO_ROOT)} not generated")
    return path


def _verify_status(entry: dict, path: Path, mode: str) -> str:
    """What verify.py says of one entry, the platform's native logic."""
    from verify import verify_entry_existence, verify_entry_md5, verify_entry_sha1

    local = str(path) if path.is_file() else None
    if mode == "existence":
        return verify_entry_existence(entry, local)["status"]
    if mode == "sha1":
        return verify_entry_sha1(entry, local)["status"]
    return verify_entry_md5(entry, local)["status"]


def _as_snippet(status: str) -> str:
    return {"ok": "ok", "untested": "wrong", "missing": "missing"}[status]


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
        _items, rows = generate_site._platform_export_rows(self.COVERAGE)
        zipped, flagged = rows
        self.assertEqual(zipped["zipped_file"], "basic1.rom")
        self.assertIs(flagged["hash_match_mandatory"], True)
        self.assertIs(flagged["mandatory_declared"], False)
        self.assertEqual(flagged["shared_group"], "group-x")
        self.assertEqual(flagged["zipped_file"], "")

    def test_the_csv_header_and_the_table_name_them(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('"collection_path", "resolved_sha1", *ENTRY_EXPORT_FIELDS,', source)
        for field in generate_site.ENTRY_EXPORT_FIELDS:
            self.assertIn(f":{field}", source)
        for field in ("zipped_file", "hash_match_mandatory", "mandatory_declared", "curated"):
            self.assertIn(field, generate_site.ENTRY_EXPORT_FIELDS)

    def test_the_built_csv_has_the_column(self):
        text = _built(PUBLIC / "downloads" / "platform-files.csv").read_text(encoding="utf-8")
        rows = list(csv.DictReader(io.StringIO(text)))
        batocera = [row for row in rows if row["platform_id"] == "batocera"]
        self.assertGreater(sum(1 for row in batocera if row["zipped_file"]), 300)
        with sqlite3.connect(_built(PUBLIC / "downloads" / "retrobios.sqlite")) as db:
            count = db.execute("SELECT count(*) FROM platform_files "
                               "WHERE platform_id = 'batocera' AND zipped_file != ''").fetchone()[0]
            license_row = db.execute("SELECT value FROM metadata WHERE key = 'license'").fetchone()
        self.assertGreater(count, 300)
        self.assertEqual(license_row[0], generate_site.DATA_LICENSE)


class AFolderCheckAgreesWithTheVerifier(unittest.TestCase):
    """8.1 and 8.3: the published example gives verify.py's verdicts."""

    def _folder(self, tmp: Path) -> tuple[dict, Path]:
        member = b"basic rom bytes"
        root = tmp / "bios"
        root.mkdir()
        with zipfile.ZipFile(root / "bbcb.zip", "w") as archive:
            archive.writestr("BASIC1.ROM", member)
        (root / "plain.bin").write_bytes(b"plain")
        (root / "wrong.bin").write_bytes(b"not it")
        (root / "nohash.bin").write_bytes(b"x")
        md5 = lambda data: hashlib.md5(data).hexdigest()  # noqa: E731
        contract = {"verification_mode": "md5", "systems": {"s": {"files": [
            {"name": "bbcb.zip", "destination": "bbcb.zip", "md5": md5(member),
             "zipped_file": "basic1.rom"},
            {"name": "bbcb.zip", "destination": "bbcb.zip", "md5": "0" * 32,
             "zipped_file": "basic1.rom"},
            {"name": "plain.bin", "destination": "plain.bin", "md5": md5(b"plain")[:29]},
            {"name": "wrong.bin", "destination": "wrong.bin", "md5": md5(b"plain")},
            {"name": "nohash.bin", "destination": "nohash.bin"},
            {"name": "gone.bin", "destination": "gone.bin", "md5": "1" * 32},
        ]}}}
        return contract, root

    def test_each_rule_on_a_sample_folder(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            contract, root = self._folder(Path(tmp))
            platforms = Path(tmp) / "platforms"
            platforms.mkdir()
            (platforms / "sample.json").write_text(
                json.dumps({"items": [{"contract": contract}]}), encoding="utf-8")
            found = check_platform_folder.check("sample", root, platforms.as_uri() + "/")
            expected = [
                (entry["destination"], _as_snippet(_verify_status(entry, root / entry["destination"], "md5")))
                for entry in contract["systems"]["s"]["files"]
            ]
        self.assertEqual(found, expected)
        self.assertEqual([v for _d, v in found], ["ok", "wrong", "ok", "wrong", "ok", "missing"])

    def test_batocera_from_the_csv_matches_the_verifier(self):
        """A check driven by platform-files.csv, with zipped_file, gives the
        verifier's verdict on every Batocera entry of a folder filled from
        the collection."""
        text = _built(PUBLIC / "downloads" / "platform-files.csv").read_text(encoding="utf-8")
        rows = [row for row in csv.DictReader(io.StringIO(text)) if row["platform_id"] == "batocera"]
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            root = Path(tmp)
            for row in rows:
                source = REPO_ROOT / row["collection_path"] if row["collection_path"] else None
                target = root / row["destination"]
                if source and source.is_file() and not target.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        os.link(source, target)
                    except OSError:
                        shutil.copyfile(source, target)
            held = [row for row in rows if (root / row["destination"]).is_file()]
            if len(held) < 100:
                raise unittest.SkipTest("the collection files are not in this checkout")
            # The verifier reads the platform's own entries, the check the CSV.
            contract = json.loads(_built(API / "platforms" / "batocera.json").read_text())[
                "items"][0]["contract"]
            declared = [entry for _sys, system in sorted(contract["systems"].items())
                        for entry in system.get("files") or []]
            self.assertEqual([e["name"] for e in declared], [row["name"] for row in rows])
            mismatched = []
            zipped_ok = 0
            for row, platform_entry in zip(rows, declared):
                entry = {key: value for key, value in row.items() if value}
                path = root / row["destination"]
                ours = "ok" if check_platform_folder.accepts(entry, path, "md5") else (
                    "wrong" if path.is_file() else "missing")
                theirs = _as_snippet(_verify_status(platform_entry, path, "md5"))
                if ours != theirs:
                    mismatched.append((row["destination"], row.get("zipped_file"), ours, theirs))
                zipped_ok += ours == "ok" and bool(row["zipped_file"])
        self.assertEqual(mismatched, [])
        self.assertGreater(zipped_ok, 100)

    def test_the_data_page_shows_the_script_itself(self):
        script = (REPO_ROOT / "scripts" / "check_platform_folder.py").read_text(encoding="utf-8")
        page = generate_site.generate_data_page([])
        self.assertIn("```python\n" + script.rstrip("\n") + "\n```", page)
        self.assertLess(len(script.splitlines()), 70)
        self.assertIn("## Check a folder for one platform", page)


class TheContractsValidate(unittest.TestCase):
    """8.4: registry keys leave the contract, every $id is its served URL."""

    def test_every_contract_validates_against_the_platform_schema(self):
        try:
            from jsonschema import Draft202012Validator  # noqa: PLC0415
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")

        from common import list_registered_platforms, load_platform_config  # noqa: PLC0415

        schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text())
        validator = Draft202012Validator(schema)
        platforms = str(REPO_ROOT / "platforms")
        for name in list_registered_platforms(platforms, include_archived=True):
            config = load_platform_config(name, platforms)
            contract, registry = generate_site._split_contract(config)
            with self.subTest(platform=name):
                errors = [error.message for error in validator.iter_errors(contract)]
                self.assertEqual(errors, [])
                self.assertIn("install", registry)
                self.assertNotIn("_key", registry)
                self.assertEqual(set(contract) | set(registry) | {"_key"}, set(config) | {"_key"})

    def test_every_schema_id_is_the_address_it_is_served_at(self):
        for path in sorted((REPO_ROOT / "schemas").glob("*.schema.json")):
            schema = json.loads(path.read_text())
            with self.subTest(schema=path.name):
                self.assertEqual(schema.get("$id"), f"{SITE}api/v1/schemas/{path.name}")

    def test_every_schema_is_published(self):
        published = {p.name for p in _built(API / "schemas").glob("*.json")}
        self.assertEqual(published, {p.name for p in (REPO_ROOT / "schemas").glob("*.schema.json")})

    def test_the_built_api_validates(self):
        try:
            from jsonschema import Draft202012Validator  # noqa: PLC0415
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")

        schemas = {p.name: json.loads(p.read_text()) for p in (REPO_ROOT / "schemas").glob("*.json")}
        envelope = Draft202012Validator(schemas["site-api-envelope.schema.json"])
        platform = Draft202012Validator(schemas["platform.schema.json"])
        document = json.loads(_built(API / "platforms.json").read_text())
        self.assertEqual(list(envelope.iter_errors(document)), [])
        for item in document["items"]:
            with self.subTest(platform=item["id"]):
                self.assertEqual([e.message for e in platform.iter_errors(item["contract"])], [])
        for name in ("systems.json", "cores.json", "index.json", "catalog.json"):
            with self.subTest(document=name):
                self.assertEqual(
                    [e.message for e in envelope.iter_errors(json.loads((API / name).read_text()))], [])


class EveryEnvelopeCarriesTheCommit(unittest.TestCase):
    """8.5: emulators/ and systems/ lacked `commit` (716 documents)."""

    def test_the_writers_pass_it(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('str(db.get("generated_at") or _timestamp()), _source_commit(),\n        )\n'
                      "    clash", source)
        block = source[source.index("public_profiles = {"):source.index("pages = emulator_pages(")]
        self.assertIn("write_single_item(", block)
        self.assertIn("_source_commit()", block)

    def test_every_built_envelope_has_it(self):
        _built(API / "catalog.json")
        if not generate_site._source_commit():
            raise unittest.SkipTest("not a git checkout")
        lacking = [
            path.relative_to(API).as_posix() for path in sorted(API.rglob("*.json"))
            if path.parent.name not in ("schemas", "manifests", "targets")
            and path.name not in ("database.json", "stats.json", "release.json")
            and "commit" not in json.loads(path.read_text())
        ]
        self.assertEqual(lacking, [])


class ManifestsArePublished(unittest.TestCase):
    """8.2: the manifest a pack installs, byte for byte, in the catalog."""

    def test_each_manifest_is_the_repository_file(self):
        catalog = json.loads(_built(API / "catalog.json").read_text())
        listed = {item["url"]: item for item in catalog["items"]}
        for source in sorted((REPO_ROOT / "install").glob("*.json")):
            with self.subTest(manifest=source.name):
                item = listed[f"manifests/{source.name}"]
                self.assertEqual(item["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
                self.assertEqual(item["schema"], "schemas/install-manifest.schema.json")
        self.assertIn("release.json", listed)
        self.assertEqual(catalog["license"], generate_site.DATA_LICENSE)

    def test_the_data_page_explains_the_fields_from_the_schema(self):
        page = generate_site.generate_data_page([])
        schema = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())
        for field in ("dest", "repo_path", "release_asset", "cores"):
            description = schema["$defs"]["file"]["properties"][field]["description"]
            self.assertIn(f"| `{field}` | {generate_site._escape_tags(description)} |", page)
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
            "probe": {"type": "test", "cores": ["probe_core"]},
        }
        items = generate_site.core_index_items(profiles)
        by_name: dict[str, list[tuple[str, bool]]] = {}
        for item in items:
            by_name.setdefault(item["name"], []).append((item["profile"], item["preferred"]))
        self.assertEqual(by_name["mednafen_psx"], [("beetle_psx", True)])
        self.assertEqual(by_name["pcsx2"], [("pcsx2", True), ("lrps2", False)])
        self.assertEqual(by_name["mednafen_psx_alias"], [("beetle_psx", True)])
        self.assertNotIn("probe_core", by_name)

    def test_the_built_index_resolves_ids_to_sections(self):
        items = {item["id"]: item for item in
                 json.loads(_built(API / "systems.json").read_text())["items"]}
        color = items["wonderswan-color"]
        self.assertEqual(color["name"], "Bandai WonderSwan Color")
        self.assertTrue(color["url"].startswith("/retrobios/systems/bandai/"), color["url"])
        self.assertTrue(items["sony-playstation"]["sha1"])
        cores = json.loads((API / "cores.json").read_text())["items"]
        self.assertIn({"name": "mednafen_psx", "profile": "beetle_psx", "preferred": True}, cores)


class LookupUrlsResolve(unittest.TestCase):
    """8.7: a record's url, joined to the shard holding it, is a page."""

    def test_site_absolute(self):
        db = {"files": {"ab" * 20: {"path": "bios/Sony/PlayStation/scph5501.bin"}}}
        [item] = generate_site.file_location_items(db)
        self.assertTrue(item["url"].startswith("/retrobios/systems/"), item["url"])
        shard = SITE + "api/v1/lookup/ab.json"
        self.assertTrue(urllib.parse.urljoin(shard, item["url"]).startswith(SITE + "systems/"))

    def test_each_record_names_its_system_as_the_pages_do(self):
        """Find a file opens on "a BIOS file for Sony PlayStation": the name
        comes from system_name, never built in the browser."""
        from siterender import system_name  # noqa: PLC0415

        db = {"files": {"ab" * 20: {"path": "bios/Sony/PlayStation/scph5501.bin",
                                    "name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}}}
        coverages = {"batocera": {"platform": "Batocera", "config": {"systems": {
            "sony-playstation": {"files": [{"name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}]}}}}}
        profiles = {"duckstation": {"systems": ["sony-playstation"], "files": [
            {"name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}]}}
        records = generate_site.file_lookup_records(
            db, coverages, profiles, generate_site.file_location_items(db))
        expected = system_name("sony-playstation")
        by_layer = {r["layer"]: r for r in records if r["algorithm"] == "md5"}
        for layer in ("collection", "platform", "emulator"):
            with self.subTest(layer=layer):
                self.assertEqual(by_layer[layer]["system_name"], expected)

    def test_built_shards_carry_the_name(self):
        shard = json.loads(_built(API / "lookup" / "05.json").read_text())
        record = next(r for r in shard["items"] if r["value"].startswith("0555c6fae890"))
        self.assertEqual(record["system_name"], "Sony PlayStation")

    def test_built_records_land_on_built_pages(self):
        shard = json.loads(_built(API / "lookup" / "05.json").read_text())
        dist = REPO_ROOT / "website" / "dist"
        for record in shard["items"][:200]:
            with self.subTest(url=record["url"]):
                self.assertTrue(record["url"].startswith("/retrobios/"))
                if dist.is_dir():
                    page = urllib.parse.unquote(record["url"].split("#")[0].removeprefix("/retrobios/"))
                    self.assertTrue((dist / page / "index.html").is_file(), page)


class PlatformPagesLinkTheirSystemsAndEmulators(unittest.TestCase):
    """8.9: the overview named emulators as ids, none of 1,463 linked."""

    def test_an_emulator_is_named_and_linked(self):
        link = generate_site._emulator_named_link("beetle_psx", "../")
        self.assertRegex(link, r"^\[[^\]]+\]\(\.\./emulators/beetle_psx\.md\)$")
        self.assertNotEqual(link, "[beetle_psx](../emulators/beetle_psx.md)")

    def test_the_overview_column_uses_it(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        block = source[source.index("### Systems overview"):source.index("_render_platform_systems(by_system")]
        self.assertIn("_emulator_named_link(e, \"../\")", block)
        self.assertNotIn('", ".join(sys_emus[:3])', block)

    def test_a_moved_list_opens_on_its_console_and_names_its_parent(self):
        # Past PLATFORM_SECTION_BUDGET, so the list leaves for a page of its own.
        files = [{"name": f"{'f' * 200}{i}.bin", "status": "ok"} for i in range(2000)]
        moved: dict[str, str] = {}
        generate_site._render_platform_systems(
            {"sony-playstation": files}, {}, {}, ("retroarch", "RetroArch"), moved, {})
        self.assertTrue(moved)
        page = next(iter(moved.values()))
        self.assertTrue(page.startswith('---\nparent:\n  label: "RetroArch"\n'
                                        '  link: "/platforms/retroarch/"\n---\n'), page[:120])
        self.assertRegex(page, r"RetroArch's list for \[Sony PlayStation\]\(\.\./systems/")

    def test_part_pages_of_gaps_and_cross_reference_name_their_parent(self):
        moved: dict[str, str] = {}
        generate_site._list_pages("gaps-x", "T", "intro", [], [["| a |"]], moved,
                                  parent=("What the packs do not hold", "/gaps/"))
        self.assertIn('parent:\n  label: "What the packs do not hold"\n  link: "/gaps/"', moved["gaps-x"])
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('_parent_front_matter(("Cores by platform", "/cross-reference/"))', source)
        self.assertIn('parent=("Dump provenance", "/provenance/")', source)


class TablesFitTheirColumn(unittest.TestCase):
    """8.12 and 8.13: a hash in a cell is 12 characters, the rest in its title."""

    def test_the_downloads_table(self):
        item = {"title": "SQLite snapshot", "url": "downloads/retrobios.sqlite",
                "media_type": "application/vnd.sqlite3", "bytes": 10, "sha256": "a" * 64}
        page = generate_site.generate_data_page([item])
        row = next(line for line in page.splitlines() if "SQLite snapshot" in line and "|" in line)
        self.assertIn(f'<code title="{"a" * 64}">{"a" * 12}</code>', row)
        self.assertNotIn("a" * 13, row.replace(f'title="{"a" * 64}"', ""))

    def test_the_gaps_tables(self):
        problem = {"platform": "Batocera", "name": "x.bin", "status": "untested", "required": True,
                   "reason": "expected md5 differs", "declared": {"md5": ["b" * 32]}, "path": ""}
        table = "\n".join(generate_site._render_problem_files([problem], db={"files": {}}))
        row = next(line for line in table.splitlines() if "x.bin" in line)
        self.assertIn(f'<code title="{"b" * 32}">{"b" * 12}</code>', row)
        self.assertIn('<span class="rb-reason">expected md5 differs</span>', row)
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('expected = f"{algorithm} {short_hash(value)}"', source)
        self.assertIn("{_reason_cell(u['reason'])}", source)


class SourceLinksGoWhereTheFileIs(unittest.TestCase):
    """8.14: trident cited a Panda3DS path and linked it into 3dsTrident."""

    PROFILE = {
        "emulator": "trident", "type": "libretro",
        "source": "https://github.com/DanAlexMorton/3dsTrident",
        "upstream": "https://github.com/wheremyfoodat/Panda3DS",
        "source_commit": "b" * 40,
    }

    def tearDown(self):
        sitesources._tree_paths.cache_clear()

    def _render(self, tree: frozenset[str]) -> str:
        original = sitesources._tree_paths
        sitesources._tree_paths = lambda repo, pin: tree  # type: ignore[assignment]
        try:
            return sitesources._source_ref_markdown(
                self.PROFILE, "src/emulator.cpp:234; src/core/loader/ncch.cpp:151-164")
        finally:
            sitesources._tree_paths = original

    def test_a_path_the_tree_lacks_is_not_linked(self):
        text = self._render(frozenset({"src/emulator.cpp"}))
        self.assertIn("[`src/emulator.cpp:234`](https://github.com/DanAlexMorton/3dsTrident/", text)
        self.assertIn("`src/core/loader/ncch.cpp:151-164`", text)
        self.assertNotIn("3dsTrident/blob/" + "b" * 40 + "/src/core/loader", text)

    def test_a_path_no_tree_confirmed_is_not_linked(self):
        """Round 4: without a tree the declared repository took the path,
        and the deploy, which has no tree cache, linked 30 paths to a 404."""
        text = self._render(frozenset())
        self.assertNotIn("](https://", text)
        self.assertIn("`src/core/loader/ncch.cpp:151-164`", text)

    def test_every_rendered_link_is_in_its_cached_tree(self):
        """Offline: each link the pages render points at a path the cached
        tree of its repository holds."""
        if not sitesources.TREE_CACHE.is_dir():
            raise unittest.SkipTest("no cached tree listings")
        from common import load_emulator_profiles  # noqa: PLC0415

        link = re.compile(r"\(https://github\.com/([^/]+/[^/]+)/blob/([0-9a-f]{40})/([^#)]+)")
        checked, wrong = 0, []
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"), skip_aliases=False)
        for key, profile in sorted(profiles.items()):
            for entry in profile.get("files") or []:
                if not isinstance(entry, dict) or not entry.get("source_ref"):
                    continue
                for slug, pin, path in link.findall(
                        sitesources._source_ref_markdown(profile, entry["source_ref"])):
                    import upstream  # noqa: PLC0415

                    repo = upstream.parse_repo(f"https://github.com/{slug}")
                    held = sitesources.tree_holds(repo, pin, urllib.parse.unquote(path))
                    if held is None:
                        continue
                    checked += 1
                    if not held:
                        wrong.append((key, slug, path))
        if not checked:
            raise unittest.SkipTest("no rendered link has a cached tree")
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
