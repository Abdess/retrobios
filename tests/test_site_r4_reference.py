"""Reference pages and data.

The lookup answered a SHA1 without the setups that list the same file by
MD5, the published folder check failed 134 EmuDeck entries a folder EmuDeck
accepts, the manifest table printed `&lt;ref>` behind a dead link and showed
17 of 48 fields, 28 system ids held files and no page, and source links went
to 404s on the deploy, which has no tree cache. Tests that read the built
site skip when it has not been generated.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_platform_folder  # noqa: E402
import generate_site  # noqa: E402
import release_record  # noqa: E402
import sitesources  # noqa: E402
import upstream  # noqa: E402

PUBLIC = REPO_ROOT / "website" / "public"
API = PUBLIC / "api" / "v1"
DOCS = REPO_ROOT / "website" / "src" / "content" / "docs"
DIST = REPO_ROOT / "website" / "dist"
TMP = REPO_ROOT / "tmp"


def _built(path: Path) -> Path:
    if not path.exists():
        raise unittest.SkipTest(f"{path.relative_to(REPO_ROOT)} not generated")
    return path


def _page(stem: str) -> str:
    for suffix in (".md", ".mdx"):
        path = DOCS / f"{stem}{suffix}"
        if path.is_file():
            return path.read_text(encoding="utf-8")
    raise unittest.SkipTest(f"{stem} not generated")


class LookupRecordsUnderEveryHash(unittest.TestCase):
    """8.1: a platform listing a file by MD5 is found by its SHA1 too."""

    SHA1 = "a" * 40
    FILE = {"name": "bios.bin", "path": "bios/Sony/PlayStation/bios.bin", "sha1": SHA1,
            "md5": "b" * 32, "crc32": "c" * 8, "sha256": "d" * 64}

    def records(self) -> list[dict]:
        db = {"files": {self.SHA1: self.FILE}, "indexes": {
            "by_md5": {"b" * 32: self.SHA1}, "by_crc32": {"c" * 8: self.SHA1},
            "by_sha256": {"d" * 64: self.SHA1}}}
        coverages = {"setup": {"config": {"systems": {"sony-playstation": {"files": [
            {"name": "bios.bin", "md5": "b" * 32}]}}}}}
        profiles = {"core": {"type": "libretro", "systems": ["sony-playstation"],
                             "files": [{"name": "bios.bin", "crc32": "c" * 8}]}}
        with mock.patch.object(generate_site, "_console_system_names", return_value={}), \
                mock.patch.object(generate_site, "_lookup_system_name", return_value=None), \
                mock.patch.object(generate_site, "emulator_card_page", side_effect=lambda k, a: k):
            return generate_site.file_lookup_records(
                db, coverages, profiles, [{"sha1": self.SHA1, "url": "/x"}])

    def test_each_hash_names_the_setup_and_the_emulator(self):
        records = self.records()
        for value in (self.SHA1, "b" * 32, "c" * 8, "d" * 64):
            owners = {(r["layer"], r.get("owner")) for r in records if r["value"] == value}
            self.assertIn(("platform", "setup"), owners, value)
            self.assertIn(("emulator", "core"), owners, value)

    def test_records_carry_the_sha1_and_say_what_was_declared(self):
        for record in self.records():
            if record["layer"] in ("platform", "emulator"):
                self.assertEqual(record["sha1"], self.SHA1)
        copy = next(r for r in self.records()
                    if r["layer"] == "platform" and r["value"] == self.SHA1)
        self.assertEqual(copy["declared"], "md5")

    def test_scph5501_gives_one_answer_for_its_four_hashes(self):
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        sha1 = "0555c6fae8906f3f09baf5988f00e55f88e9f30b"
        entry = db["files"][sha1]
        _built(API / "lookup")
        answers = []
        for algorithm in ("sha1", "md5", "crc32", "sha256"):
            value = str(entry[algorithm]).lower()
            shard = json.loads((API / "lookup" / f"{value[:2]}.json").read_text())
            found = [r for r in shard["items"] if r["value"] == value]
            answers.append(tuple(sorted({(r["layer"], r.get("owner", "")) for r in found})))
        self.assertEqual(len(set(answers)), 1, answers)
        setups = {owner for layer, owner in answers[0] if layer == "platform"}
        emulators = {owner for layer, owner in answers[0] if layer == "emulator"}
        self.assertGreaterEqual(len(setups), 10)
        self.assertGreaterEqual(len(emulators), 8)


class TheFolderCheckReadsEmuDecksWhitelist(unittest.TestCase):
    """8.2: an entry with no destination names no file. EmuDeck's check
    passes the system when any top-level file of the folder has its md5."""

    def check(self, files: dict[str, bytes]) -> list[tuple[str, str]]:
        good = b"ps1 bios bytes"
        contract = {"verification_mode": "md5", "systems": {"sony-playstation": {"files": [
            {"name": f"sony-playstation:{hashlib.md5(good).hexdigest()}", "destination": "",
             "md5": hashlib.md5(good).hexdigest()},
            {"name": "sony-playstation:" + "0" * 32, "destination": "", "md5": "0" * 32},
        ]}}}
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            root = Path(tmp) / "bios"
            (root / "sub").mkdir(parents=True)
            for name, data in files.items():
                (root / name).write_bytes(data)
            api = Path(tmp) / "api"
            api.mkdir()
            (api / "emudeck.json").write_text(json.dumps({"items": [{"contract": contract}]}))
            found = check_platform_folder.check("emudeck", root, api.as_uri() + "/")
            # The verifier's verdict on the matching entry, file by file.
            from verify import verify_entry_md5  # noqa: PLC0415

            verdicts = {name: verify_entry_md5(contract["systems"]["sony-playstation"]["files"][0],
                                               str(root / name))["status"]
                        for name in files if (root / name).is_file()}
        return found, verdicts

    def test_any_name_passes(self):
        found, verdicts = self.check({"my-ps1-dump.bin": b"ps1 bios bytes"})
        self.assertEqual(found, [("sony-playstation: any file", "ok")])
        self.assertEqual(verdicts, {"my-ps1-dump.bin": "ok"})

    def test_a_folder_without_it_is_missing(self):
        found, _verdicts = self.check({"other.bin": b"x", "sub/deep.bin": b"ps1 bios bytes"})
        self.assertEqual(found, [("sony-playstation: any file", "missing")])

    def test_the_data_page_states_the_rule(self):
        page = generate_site.generate_data_page([])
        self.assertIn("An entry with no `destination` (EmuDeck) names no file", page)
        self.assertLess(len((REPO_ROOT / "scripts" / "check_platform_folder.py")
                            .read_text().splitlines()), 70)


class ManifestFieldsAreComplete(unittest.TestCase):
    """8.3 and 8.4."""

    SCHEMA = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())

    def test_a_url_template_is_code(self):
        rows = generate_site._schema_field_rows(self.SCHEMA["$defs"]["file"], ("repo_path",))
        self.assertIn("`https://raw.githubusercontent.com/Abdess/retrobios/<ref>/<repo_path>`",
                      rows[0])
        rows = generate_site._schema_field_rows(
            {"properties": {"a": {"description": "From https://x.test/<asset>, then."}}}, ("a",))
        self.assertEqual(rows, ["| `a` | From `https://x.test/<asset>`, then. |"])

    def test_every_field_is_described_and_shown(self):
        page = generate_site.generate_data_page([])
        for schema in (self.SCHEMA, self.SCHEMA["$defs"]["file"]):
            for key, spec in schema["properties"].items():
                self.assertTrue(spec.get("description"), key)
                self.assertIn(f"| `{key}` |", page)

    def test_no_link_carries_an_escaped_bracket(self):
        html = _built(DIST / "data" / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(html, r'href="[^"]*&amp;lt;')
        self.assertNotRegex(html, r'href="[^"]*&lt;')


class EverySystemIdWithFilesHasAPage(unittest.TestCase):
    """8.5: tyrian, scummvm, dos and 25 more had files and a null url."""

    def test_built_index(self):
        items = json.loads(_built(API / "systems.json").read_text())["items"]
        orphans = [item["id"] for item in items if item["sha1"] and not item["url"]]
        self.assertEqual(orphans, [])

    def test_first_file_then_emulator(self):
        files = {"f" * 40: {"path": "bios/DOS/DOS/a.bin"}}
        with mock.patch("siterender._card_pages", {}):
            place = generate_site._first_file_place(
                "dos", ["f" * 40], files, {}, lambda path, sha1: "dos")
        self.assertEqual(place, ("DOS", "/retrobios/systems/dos/#sha1-ffffffffffff"))
        place = generate_site._first_file_place(
            "tyrian", [], files, {"opentyrian": {"systems": ["tyrian"]}}, None)
        self.assertEqual(place, ("", "/retrobios/emulators/opentyrian/"))


# A source permalink of each forge family the pages write.
_PERMALINK = re.compile(
    r"\]\(https://(?P<host>[^/]+)/(?P<slug>[^/]+/[^/]+)/"
    r"(?:blob/|-/blob/|src/commit/)(?P<pin>[0-9a-f]{40})/(?P<path>[^#)]+)")


class SourceLinksOnlyWhereTheFileIs(unittest.TestCase):
    """8.6: the deploy reads the committed record, never a tree cache."""

    def test_an_address_in_a_binary_reads_as_one(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40}
        text = sitesources._source_ref_markdown(
            profile, "Nesoid 2.5.0 libnes.so 0x455a4-0x45694 (setter), 0x8094-0x80ac")
        self.assertEqual(text, "offset `0x455a4-0x45694` in `Nesoid 2.5.0 libnes.so`, "
                               "offset `0x8094-0x80ac` in `Nesoid 2.5.0 libnes.so`")

    def test_only_a_recorded_path_links(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40}
        repo = upstream.parse_repo("https://github.com/o/r")
        record = {sitesources.tree_key(repo, "e" * 40): frozenset({"src/a.c"})}
        with mock.patch.object(sitesources, "_verified", return_value=record):
            sitesources._tree_paths.cache_clear()
            try:
                text = sitesources._source_ref_markdown(profile, "src/a.c:5, src/b.c:7")
            finally:
                sitesources._tree_paths.cache_clear()
        self.assertIn("[`src/a.c:5`](https://github.com/o/r/blob/" + "e" * 40 + "/src/a.c#L5)", text)
        self.assertIn("`src/b.c:7`", text)
        self.assertNotIn("src/b.c#", text)

    def test_the_writer_keeps_held_paths_only(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40,
                   "notes": "see src/c.c:3", "files": [{"source_ref": "src/a.c:5, gone.c:1"}]}
        with mock.patch.object(sitesources, "_cached_tree",
                               return_value=frozenset({"src/a.c", "src/c.c", "x.c"})):
            held, unread = sitesources.build_source_paths({"p": profile}, [TMP])
        self.assertEqual(held, {"github.com/o/r@" + "e" * 40: ["src/a.c", "src/c.c"]})
        self.assertEqual(unread, [])

    def test_a_tree_no_directory_answers_for_stays_unread(self):
        # TeknoParrotUI answers 404: listed folder by folder, every listing
        # failed and the tree read as holding nothing, so a fetch without its
        # cached tree dropped its four recorded paths.
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40,
                   "files": [{"source_ref": "src/a.c:5"}]}
        with mock.patch.object(sitesources, "_cached_tree", return_value=None), \
                mock.patch.object(sitesources.upstream, "list_directory",
                                  side_effect=upstream.UpstreamError("HTTP 404")):
            held, unread = sitesources.build_source_paths({"p": profile}, [TMP])
        self.assertEqual(held, {})
        self.assertEqual(unread, ["github.com/o/r@" + "e" * 40])

    def test_every_rendered_link_is_recorded(self):
        record = json.loads(sitesources.SOURCE_PATHS.read_text(encoding="utf-8"))
        pages = sorted(_built(DOCS / "emulators").rglob("*.md*")) + sorted(DOCS.glob("gaps*.md*"))
        import measurement_records  # noqa: PLC0415

        # A Tested block links a record line and its data file in this
        # repository. The records are append-only, so a file a permalink
        # names is still in the tree.
        records = set(measurement_records.tree_files(REPO_ROOT))
        checked, stray = 0, []
        for page in pages:
            for found in _PERMALINK.finditer(page.read_text(encoding="utf-8")):
                key = f"{found['host']}/{found['slug']}@{found['pin']}"
                path = urllib.parse.unquote(found["path"])
                if "/Abdess/retrobios/" in found[0]:
                    if path.startswith(f"{measurement_records.RECORDS_DIR}/") and path not in records:
                        stray.append((page.name, key, path))
                    continue
                checked += 1
                if path not in record.get(key, ()):
                    stray.append((page.name, key, path))
        self.assertGreater(checked, 1000)
        self.assertEqual(stray[:20], [])

    def test_the_record_is_read_by_the_deploy(self):
        """The record is committed where the build reads it, sorted."""
        record = json.loads(sitesources.SOURCE_PATHS.read_text(encoding="utf-8"))
        self.assertGreater(len(record), 300)
        for key, paths in record.items():
            self.assertRegex(key, r"^[a-z0-9.-]+/.+@[0-9a-f]{40}$")
            self.assertEqual(paths, sorted(set(paths)), key)


class TheReferencePagesAnswerTheirWords(unittest.TestCase):
    """8.7, 8.8, 8.10 and 8.13."""

    def test_find_or_check_a_file(self):
        page = generate_site.generate_files_page()
        self.assertTrue(page.startswith(
            "---\nterms: check my dump, md5 check, verify bios file, check hash, "
            "is my bios correct, is my bios right\n---\n"))
        self.assertIn("\n# Find or check a file\n\nCheck a BIOS dump: paste its hash "
                      "or choose the file.\n", page)

    def test_the_data_page(self):
        page = generate_site.generate_data_page([])
        self.assertTrue(page.startswith(
            "---\nterms: manifest, schema, json schema, license, check a folder, "
            "check bios folder script, rate limit, api\n---\n"))
        self.assertIn("## Hosting, rate limits and caching", page)
        self.assertIn("HTTP 429", page)
        self.assertIn("crypto.subtle.digest(\"SHA-1\"", page)
        self.assertIn("api/v1/lookup/", page)
        self.assertIn("`preferred: true`", page)
        self.assertIn("`database.json`, `stats.json`, `release.json` and the manifests are not "
                      "envelopes", page)
        self.assertIn("- MinUI, MyMinUI and NextUI have no list of their own "
                      "(`native_list: none`). An empty list does not mean nothing is needed.", page)

    def test_overview_ids_and_counts_are_not_indexed(self):
        html = _built(DIST / "platforms" / "batocera" / "index.html").read_text(encoding="utf-8")
        self.assertRegex(html, r"<small data-pagefind-ignore(=\"true\")?>sony-playstation</small>")
        self.assertRegex(html, r"<span data-pagefind-ignore(=\"true\")?>\d+/\d+</span>")


class TheReleaseRecordHasAVersion(unittest.TestCase):
    """8.9."""

    def test_the_writer_and_the_committed_record(self):
        self.assertEqual(release_record.SCHEMA_VERSION, 1)
        source = (REPO_ROOT / "scripts" / "release_record.py").read_text(encoding="utf-8")
        self.assertIn('{"schema_version": SCHEMA_VERSION, "tag": tag, "packs": packs}', source)
        schema = json.loads((REPO_ROOT / "schemas" / "release.schema.json").read_text())
        self.assertIn("schema_version", schema["required"])
        record = json.loads((REPO_ROOT / "release.json").read_text())
        self.assertEqual(record["schema_version"], 1)


class NoEmptyCoreTable(unittest.TestCase):
    """8.11: MiSTer and BizHawk declare cores: [] and had a page of nothing."""

    def test_own_list_platforms_get_a_sentence(self):
        coverages = {"misterfpga": {"platform": "MiSTer FPGA", "config": {"cores": [], "systems": {}}}}
        moved: dict[str, str] = {}
        page = generate_site.generate_cross_reference(coverages, {}, moved)
        self.assertEqual(moved, {})
        self.assertIn(generate_site.OWN_LIST_ONLY, page)

    def test_built_pages(self):
        _built(DOCS / "cross-reference.md")
        for name in ("misterfpga", "bizhawk"):
            self.assertFalse((DOCS / f"cross-reference-{name}.md").exists())
            self.assertIn(generate_site.OWN_LIST_ONLY, _page(f"platforms/{name}"))
        redirects = json.loads((REPO_ROOT / "website" / "src" / "generated" /
                                "redirects.json").read_text())
        self.assertEqual(redirects.get("/cross-reference-misterfpga/"), "/platforms/misterfpga/")


class FilesToSourceOnAPhone(unittest.TestCase):
    """8.12: 601 rows on one page, no way to give a file."""

    def test_parts_of_a_hundred_rows_each_with_an_upload(self):
        _built(DOCS / "gaps-files-to-source.md")
        parts = sorted(DOCS.glob("gaps-files-to-source*.md"))
        self.assertGreater(len(parts), 1)
        for part in parts:
            rows = [line for line in part.read_text(encoding="utf-8").splitlines()
                    if line.startswith("| `")]
            self.assertLessEqual(len(rows), generate_site.FILES_TO_SOURCE_PART, part.name)
            for row in rows:
                self.assertIn(f"[Have it? Upload]({generate_site.UPLOAD_URL}", row)

    def test_the_upload_lands_in_the_console_folder(self):
        with mock.patch("siterender._own_section", return_value=("Sony", "PlayStation")):
            self.assertEqual(generate_site._upload_folder({"systems": ["sony-playstation"]}),
                             "Sony/PlayStation")


if __name__ == "__main__":
    unittest.main()
