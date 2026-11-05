"""Reference pages and data.

The API said Lakka and RetroPie had a release pack while their pages said
none, 50 nested manifest fields and the nine omission codes had no
description, the lookup named 9 emulators where the card named 11, four
served schemas and the target lists appeared nowhere on the Data page, the
folder check exited 0 on a folder missing every file, and a system id did
not lead to its JSON document. Tests reading the generated site skip when
it has not been generated.
"""

from __future__ import annotations

import io
import json
import runpy
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import release_record  # noqa: E402
from common import list_release_pack_platforms  # noqa: E402

PUBLIC = REPO_ROOT / "website" / "public"
API = PUBLIC / "api" / "v1"
GENERATED = REPO_ROOT / "website" / "src" / "generated"
SCHEMA = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())


def _built(path: Path) -> Path:
    if not path.exists():
        raise unittest.SkipTest(f"{path.relative_to(REPO_ROOT)} not generated")
    return path


def _released() -> set[str]:
    return set(list_release_pack_platforms(str(REPO_ROOT / "platforms"), include_archived=True))


class OneAnswerOnReleasePacks(unittest.TestCase):
    """8.1: the API, the picker's data and the pages read the registry."""

    def test_a_child_does_not_inherit_its_parents_pack(self):
        _contract, registry = generate_site._split_contract(
            {"_key": "lakka", "inherits": "retroarch", "release_pack": True})
        self.assertIs(registry["release_pack"], "lakka" in _released())
        _contract, registry = generate_site._split_contract({"_key": "minui"})
        self.assertNotIn("release_pack", registry)
        _contract, registry = generate_site._split_contract({"_key": "retroarch"})
        self.assertIs(registry["release_pack"], "retroarch" in _released())

    def test_api_release_pack_set_equals_the_registry(self):
        found = set()
        for path in _built(API / "platforms").glob("*.json"):
            item = json.loads(path.read_text())["items"][0]
            if item["registry"].get("release_pack"):
                found.add(item["id"])
        self.assertEqual(found, _released())

    def test_the_picker_file_is_the_advertised_record(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir()
                                         else None) as folder:
            generate_site.write_release_advertised(Path(folder))
            written = json.loads((Path(folder) / "release-advertised.json").read_text())
        self.assertEqual(written, release_record.load_advertised())
        served = {p for pack in written.get("packs", {}).values() for p in pack["platforms"]}
        self.assertLessEqual(served, _released())

    def test_the_built_picker_file(self):
        written = json.loads(_built(GENERATED / "release-advertised.json").read_text())
        self.assertEqual(written, release_record.load_advertised())


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
        page = generate_site.generate_data_page([])
        for path, spec in _properties(SCHEMA):
            if path.endswith(".reason"):
                self.assertEqual(len(spec["enumDescriptions"]), len(spec["enum"]), path)
                for code in spec["enum"]:
                    self.assertRegex(page, rf"\n- `{code}`: \S")

    def test_nested_tables_are_on_the_page(self):
        page = generate_site.generate_data_page([])
        for label in ("Each entry of `omitted_files`:", "Each entry of `data_directories`:",
                      "Each value of `data_directories[].files`:", "Fields of `save_directory`:",
                      "Each entry of `files[].alternatives`:",
                      "Each entry of `files[].slot_choices`:",
                      "Each entry of `files[].declared_choices`:",
                      "Each entry of `files[].absent_claims`:"):
            self.assertIn(label, page)
        for key in ("below_platform_folder", "strip_components", "by_core"):
            self.assertIn(f"`{key}`", page)


class FakeConsumers:
    def __init__(self, sha1: str) -> None:
        self.emulators = {sha1: {"byname"}}
        self.emulator_entries = {sha1: {"byname": 0}}
        self.emulator_files = {"byname": [{"name": "bios.bin"}]}


class LookupCountsEmulatorsLikeTheCard(unittest.TestCase):
    """8.3: an emulator reading the file by name is in the verdict."""

    SHA1 = "a" * 40

    def records(self) -> list[dict]:
        db = {"files": {self.SHA1: {"name": "bios.bin", "path": "bios/Sony/PlayStation/bios.bin",
                                    "sha1": self.SHA1, "md5": "b" * 32}},
              "indexes": {"by_md5": {"b" * 32: self.SHA1}}}
        coverages = {"setup": {"config": {"systems": {"sony-playstation": {"files": [
            {"name": "bios.bin", "md5": "b" * 32}]}}}}}
        with mock.patch.object(generate_site, "_console_system_names", return_value={}), \
                mock.patch.object(generate_site, "_lookup_system_name", return_value=None), \
                mock.patch.object(generate_site, "emulator_card_page", side_effect=lambda k, a: k):
            return generate_site.file_lookup_records(
                db, coverages, {}, [{"sha1": self.SHA1, "url": "/x"}], None,
                FakeConsumers(self.SHA1))

    def test_by_name_under_every_hash(self):
        records = self.records()
        for value in (self.SHA1, "b" * 32):
            named = [r for r in records if r["value"] == value and r.get("owner") == "byname"]
            self.assertEqual(len(named), 1, value)
            self.assertEqual(named[0]["declared"], "name")

    def test_every_setup_and_emulator_record_says_what_was_declared(self):
        for record in self.records():
            if record["layer"] in ("platform", "emulator"):
                self.assertIn("declared", record)
        own = next(r for r in self.records()
                   if r["layer"] == "platform" and r["value"] == "b" * 32)
        self.assertEqual(own["declared"], "md5")

    def test_scph5501_names_the_cards_eleven(self):
        sha1 = "0555c6fae8906f3f09baf5988f00e55f88e9f30b"
        shard = json.loads(_built(API / "lookup" / f"{sha1[:2]}.json").read_text())
        owners = {r["owner"] for r in shard["items"]
                  if r["value"] == sha1 and r["layer"] == "emulator"}
        self.assertGreaterEqual(len(owners), 11)
        self.assertLessEqual({"pcsx_rearmed", "pcsx1"}, owners)


class TheDataPageListsWhatIsServed(unittest.TestCase):
    """8.4 and 8.6."""

    def test_every_schema_is_listed(self):
        page = generate_site.generate_data_page([])
        for path in (REPO_ROOT / "schemas").glob("*.schema.json"):
            self.assertIn(f"- [`{path.name}`](api/v1/schemas/{path.name}): ", page)

    def test_target_lists_are_published_and_catalogued(self):
        catalog = json.loads(_built(API / "catalog.json").read_text())
        listed = {item["url"] for item in catalog["items"]}
        for source in (REPO_ROOT / "install" / "targets").glob("*.json"):
            self.assertIn(f"targets/{source.name}", listed)
            self.assertEqual((API / "targets" / source.name).read_bytes(), source.read_bytes())

    def test_declared_only_and_search_words(self):
        page = generate_site.generate_data_page([])
        self.assertIn("With `--declared-only`, or from the `declared` event, "
                      "`install.py --check` answers it too.", page)
        terms = page.split("\n", 2)[1]
        for word in ("json schema", "license", "check bios folder script"):
            self.assertIn(word, terms)
        files_terms = generate_site.generate_files_page().split("---\n", 2)[1]
        for word in ("is my bios correct", "is my bios right"):
            self.assertIn(word, files_terms)


def _respond(routes: dict):
    def urlopen(url: str, *args, **kwargs):
        for suffix, body in routes.items():
            if url.endswith(suffix):
                if body is None:
                    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
                return io.BytesIO(json.dumps(body).encode())
        raise AssertionError(url)
    return urlopen


class TheFolderCheckExitCode(unittest.TestCase):
    """8.5: exit 1 on a file wrong or missing, a word for an unknown platform."""

    SCRIPT = str(REPO_ROOT / "scripts" / "check_platform_folder.py")
    CONTRACT = {"items": [{"contract": {"verification_mode": "existence", "systems": {
        "x": {"files": [{"name": "a.bin", "destination": "a.bin"}]}}}}]}

    def run_script(self, platform: str, folder: Path, routes: dict) -> tuple[object, str]:
        err = io.StringIO()
        with mock.patch("urllib.request.urlopen", _respond(routes)), \
                mock.patch.object(sys, "argv", ["check", platform, str(folder)]), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", err), \
                self.assertRaises(SystemExit) as raised:
            runpy.run_path(self.SCRIPT, run_name="__main__")
        return raised.exception.code, err.getvalue()

    def test_missing_exits_one_and_complete_exits_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            code, _err = self.run_script("p", Path(folder), {"/p.json": self.CONTRACT})
            self.assertEqual(code, 1)
            (Path(folder) / "a.bin").write_bytes(b"x")
            code, _err = self.run_script("p", Path(folder), {"/p.json": self.CONTRACT})
            self.assertEqual(code, 0)

    def test_an_unknown_platform_names_the_known_ones(self):
        catalog = {"items": [{"url": "manifests/batocera.json"}, {"url": "stats.json"}]}
        with tempfile.TemporaryDirectory() as folder:
            code, _err = self.run_script(
                "nosuch", Path(folder), {"/nosuch.json": None, "/catalog.json": catalog})
        self.assertEqual(code, "unknown platform: nosuch. Known: batocera")

    def test_the_page_shows_the_script(self):
        script = Path(self.SCRIPT).read_text(encoding="utf-8")
        self.assertIn("```python\n" + script.rstrip("\n") + "\n```",
                      generate_site.generate_data_page([]))


class SystemItemsCarryTheirApi(unittest.TestCase):
    """8.7."""

    def test_each_api_address_is_served(self):
        items = json.loads(_built(API / "systems.json").read_text())["items"]
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
