"""A file RetroDECK declares in several manifest entries, through scrape,
verify and export.

RetroDECK checks each entry of each component manifest on its own: one
result row per entry, the md5 of the file found under that exact basename
tested against that entry's list only (functions/api_data_processing.sh
304-313, 322-339 and 350-361 at 0.10.10b). The scraper kept the first
entry per system and case-folded name, so 22 entries left the platform
file: decocass.zip for FBNeo beside MAME's, the second and third
64DD_IPL.bin revisions, and MSX.rom, a second file beside MSX.ROM on
RetroDECK's Linux filesystem whose md5 list is a prefix of MSX.ROM's.
"""

from __future__ import annotations

import tests

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from collections import OrderedDict
from pathlib import Path

from exporter import discover_exporters
from packs.coverage import verify_platform
from resolve.reconcile import build_native_model
from scraper.base_scraper import systems_from_requirements
from scripts.scraper import retrodeck_scraper

MAME_DECO = b"mame decocass" * 4
FBNEO_DECO = b"fbneo decocass" * 4
IPL = [b"64dd retail", b"64dd dev", b"64dd other"]


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


MANIFESTS: dict[str, dict] = {
    "mame": {"mame": {"name": "MAME", "system": "mame", "bios": [
        {"filename": "decocass.zip", "system": "mame", "md5": md5(MAME_DECO),
         "required": "Required"},
    ]}},
    "retroarch": {"retroarch": {"name": "RetroArch", "cores": {"bios": [
        {"filename": "decocass.zip", "system": "fbneo", "md5": md5(FBNEO_DECO),
         "required": "Required"},
        *({"filename": "64DD_IPL.bin", "system": "n64dd", "md5": md5(data),
           "required": "At least one"} for data in IPL),
        {"filename": "MSX.ROM", "system": "msx", "md5": ["a" * 32, "b" * 32],
         "required": "Required"},
        {"filename": "MSX.rom", "system": "msx", "md5": "a" * 32},
        {"filename": "scph5501.bin", "system": "psx", "md5": "c" * 32,
         "required": "Required"},
    ]}}},
    "duckstation": {"duckstation": {"name": "DuckStation", "system": "psx", "bios": [
        {"filename": "scph5501.bin", "system": "psx", "md5": "c" * 32,
         "required": "Required"},
    ]}},
}


def _scrape(root: Path) -> retrodeck_scraper.Scraper:
    for component, manifest in MANIFESTS.items():
        folder = root / "manifests" / component
        folder.mkdir(parents=True)
        (folder / "component_manifest.json").write_text(json.dumps(manifest))
    return retrodeck_scraper.Scraper(manifests_dir=str(root / "manifests"))


class ScrapeKeepsEveryDeclaration(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.scraper = _scrape(self.root)
        self.reqs = self.scraper.fetch_requirements()

    def _md5s(self, name: str) -> list[str]:
        return [r.md5 or "" for r in self.reqs if r.name == name]

    def test_nothing_is_dropped(self) -> None:
        self.assertEqual(self.scraper.dropped, [])

    def test_each_component_keeps_its_own_md5(self) -> None:
        deco = [(r.native["component"], r.native_id, r.md5)
                for r in self.reqs if r.name == "decocass.zip"]
        self.assertEqual(deco, [("mame", "mame", md5(MAME_DECO)),
                                ("retroarch", "fbneo", md5(FBNEO_DECO))])

    def test_revisions_under_one_name_are_each_kept(self) -> None:
        self.assertEqual(self._md5s("64DD_IPL.bin"), [md5(data) for data in IPL])

    def test_two_spellings_are_two_files(self) -> None:
        """MSX.rom's single md5 is the first of MSX.ROM's two: the dry run
        printed "847cc025ffae... vs 847cc025ffae..." for a list against its
        first item."""
        self.assertEqual(self._md5s("MSX.ROM"), [f"{'a' * 32},{'b' * 32}"])
        self.assertEqual(self._md5s("MSX.rom"), ["a" * 32])
        self.assertEqual(
            {r.destination for r in self.reqs if r.name.lower() == "msx.rom"},
            {"bios/MSX.ROM", "bios/MSX.rom"},
        )

    def test_a_plain_repeat_is_one_entry(self) -> None:
        self.assertEqual(self._md5s("scph5501.bin"), ["c" * 32])


class VerifyJudgesEachDeclaration(unittest.TestCase):
    """The pack holds one file at bios/decocass.zip: MAME's declaration is
    met, FBNeo's is reported against the file that holds the path."""

    def setUp(self) -> None:
        from model.profiles import emulator_profiles_cache

        emulator_profiles_cache.clear()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        reqs = _scrape(self.root).fetch_requirements()
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.db: dict = {"files": {}, "indexes": {
            "by_md5": {}, "by_name": {}, "by_crc32": {}, "by_path_suffix": {}}}
        for rel, data in (("bios/Arcade/MAME/decocass.zip", MAME_DECO),
                          ("bios/Nintendo/Nintendo 64DD/64DD_IPL.bin", IPL[0])):
            Path(rel).parent.mkdir(parents=True, exist_ok=True)
            Path(rel).write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            name = rel.rsplit("/", 1)[1]
            self.db["files"][sha1] = {"path": rel, "name": name, "size": len(data),
                                      "md5": md5(data), "crc32": ""}
            self.db["indexes"]["by_md5"][md5(data)] = sha1
            self.db["indexes"]["by_name"][name] = [sha1]
        Path("emulators").mkdir()
        self.config = {
            "platform": "RetroDECK", "verification_mode": "md5", "hash_type": "md5",
            "base_destination": "",
            "systems": systems_from_requirements(
                [r for r in reqs if r.name in ("decocass.zip", "64DD_IPL.bin")]
            ),
        }

    def _details(self, name: str) -> list[dict]:
        result = verify_platform(self.config, self.db, "emulators", emu_profiles={})
        return [d for d in result["details"] if d.get("name") == name]

    def test_the_held_declaration_is_met_and_the_other_reported(self) -> None:
        details = self._details("decocass.zip")
        self.assertEqual(len(details), 2)
        met = [d for d in details if d["status"] == "ok"]
        unmet = [d for d in details if d.get("settled_by")]
        self.assertEqual(len(met), 1)
        self.assertEqual(len(unmet), 1)
        message = unmet[0]["discrepancy"]
        self.assertIn("arcade (fbneo)", message)
        self.assertIn("arcade (mame)", message)
        self.assertIn(md5(FBNEO_DECO), message)

    def test_revisions_name_the_hash_the_path_holds(self) -> None:
        details = self._details("64DD_IPL.bin")
        self.assertEqual(len(details), 3)
        unmet = [d for d in details if d.get("settled_by")]
        self.assertEqual(len(unmet), 2)
        for detail in unmet:
            self.assertIn(f"file (md5 {md5(IPL[0])})", detail["discrepancy"])


class ExportWritesEachComponentsOwnMd5(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        reqs = _scrape(self.root).fetch_requirements()
        self.scraped = {"systems": systems_from_requirements(reqs)}
        self.originals = {
            f"{component}/component_manifest.json": json.dumps(manifest, indent=2)
            for component, manifest in MANIFESTS.items()
        }
        self.exporter = discover_exporters()["retrodeck"]()

    @staticmethod
    def _bios(produced: dict[str, str], component: str) -> list[dict]:
        manifest = json.loads(produced[f"{component}/component_manifest.json"])
        value = manifest[component]
        return value["bios"] if "bios" in value else value["cores"]["bios"]

    def test_every_declaration_reads_back_as_written(self) -> None:
        """Each entry of the platform file renders to the manifest entry it
        came from: name, native system and md5 list."""
        systems, _report = build_native_model({"systems": {}}, self.scraped)

        def key(entry: dict) -> tuple[str, str, tuple[str, ...]]:
            listed = entry["md5"]
            return (entry["filename"], entry["system"],
                    tuple(listed if isinstance(listed, list) else [listed]))

        rendered: dict[str, set] = {}
        for system in systems.values():
            for fe in system.files:
                component = str(fe.native("component"))
                rendered.setdefault(component, set()).add(key(self.exporter._entry(fe)))
        for component, manifest in MANIFESTS.items():
            value = manifest[component]
            declared = value["bios"] if "bios" in value else value["cores"]["bios"]
            expected = {key(e) for e in declared}
            if component == "retroarch":
                # A repeat of duckstation's scph5501.bin, the same name, path
                # and md5: transcribed once, under the first component read.
                expected.discard(("scph5501.bin", "psx", ("c" * 32,)))
            with self.subTest(component=component):
                self.assertEqual(rendered[component], expected)

    def test_a_correction_lands_on_its_own_revision(self) -> None:
        """The truth accepts a second dump for the dev 64DD IPL: that entry
        alone takes it, the two other revisions keep their own md5. Keyed by
        name and system, the first entry of ours answered for all three and
        the dev entry's correction was written nowhere."""
        dev, extra = md5(IPL[1]), "d" * 32
        truth = {"systems": {"nintendo-64dd": {"files": [
            {"name": "64DD_IPL.bin", "path": "64DD_IPL.bin", "md5": f"{dev},{extra}",
             "required": True, "_cores": ["parallel_n64"]},
        ]}}}
        systems, report = build_native_model(truth, self.scraped)
        produced = self.exporter.render(systems, report, self.originals, self.scraped)
        ipl = [e for e in self._bios(produced, "retroarch") if e["filename"] == "64DD_IPL.bin"]
        self.assertEqual([e["md5"] for e in ipl],
                         [md5(IPL[0]), [dev, extra], md5(IPL[2])])
        self.assertEqual(self.exporter._appended, set())

    def test_an_unchanged_model_writes_the_manifests_back(self) -> None:
        systems, report = build_native_model({"systems": {}}, self.scraped)
        produced = self.exporter.render(systems, report, self.originals, self.scraped)
        for path, text in produced.items():
            with self.subTest(manifest=path):
                self.assertEqual(text, self.originals[path])

    def test_merge_pairs_each_revision_by_hash(self) -> None:
        a, b, c = "a" * 32, "b" * 32, "c" * 32
        existing = [{"filename": "64DD_IPL.bin", "system": "n64dd", "md5": m} for m in (a, b)]
        ours = [OrderedDict(filename="64DD_IPL.bin", system="n64dd", md5=m, required=r)
                for m, r in ((b, "Optional"), (a, "Required"), (c, "Required"))]
        appended: set = set()
        merged = self.exporter._merge(existing, ours, None, appended)
        self.assertEqual([(e["md5"], e.get("required")) for e in merged],
                         [(a, "Required"), (b, "Optional"), (c, "Required")])
        self.assertEqual(appended, {("64DD_IPL.bin", "n64dd")})


class PlatformFileCarriesTheDeclarations(unittest.TestCase):
    """The committed transcription holds each md5 the dry run used to drop."""

    def test_retrodeck_yml_keeps_both_sides(self) -> None:
        from model.platforms import load_platform_config

        root = Path(__file__).resolve().parents[1]
        config = load_platform_config("retrodeck", str(root / "platforms"))
        files = [f for s in config["systems"].values() for f in s.get("files", [])]

        def md5s(name: str) -> set[str]:
            return {f.get("md5", "") for f in files if f["name"] == name}

        self.assertEqual(
            md5s("decocass.zip"),
            {"2b268f2f8960e5124f9a8cc6cfe86773", "b7e1189b341bf6a8e270017c096d21b0"},
        )
        self.assertEqual(len(md5s("64DD_IPL.bin")), 3)
        self.assertEqual(md5s("MSX.rom"),
                         {"364a1a579fe5cb8dba54519bcfcdac0d,aa95aea2563cd5ec0a0919b44cc17d47"})


if __name__ == "__main__":
    unittest.main()
