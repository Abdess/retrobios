"""Native exporters against the platforms' real files.

export_native.py rewrites each platform's own file, corrected: Recalbox's
es_bios.xml, Batocera's systems list, RetroDECK's manifests. The point is
that a maintainer can take the output and use it, so what matters is
whether the platform would still read it, and whether anything it already
declared went missing on the way through.

The fidelity cases read the platforms' real files from the upstream cache
and skip when it has not been populated (python scripts/export_native.py
--all --fetch), because a test that needs the network is not a test.
"""

from __future__ import annotations

import tests

import json
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.safeparse import parse_untrusted_xml
from exporter import discover_exporters
from resolve.reconcile import build_native_model
from tests.exporterssupport import REPO_ROOT, UPSTREAM_CACHE


class UpstreamFidelity(unittest.TestCase):
    """The real files, compared against what we hand back.

    Nothing a platform declares today may be missing from the export: an
    export that loses systems is one no maintainer can apply.
    """

    @classmethod
    def setUpClass(cls):
        if not UPSTREAM_CACHE.is_dir():
            raise unittest.SkipTest(
                "no upstream cache, run scripts/export_native.py --all --fetch"
            )

    def _export(self, platform: str, truth: dict | None = None) -> tuple[dict, dict[str, str]]:
        cache = UPSTREAM_CACHE / platform
        if not cache.is_dir():
            self.skipTest(f"no cached original for {platform}")
        scraped = load_platform_config(platform, str(REPO_ROOT / "platforms"))
        systems, report = build_native_model(truth or {"systems": {}}, scraped)
        # The profiles the export pipeline hands every exporter.
        exporter = discover_exporters()[platform](
            load_emulator_profiles(str(REPO_ROOT / "emulators"))
        )
        originals: dict[str, str] = {}
        for path in cache.rglob("*"):
            if not path.is_file():
                continue
            relative = str(path.relative_to(cache))
            if relative.endswith((".zip", ".tar.gz")) and hasattr(exporter, "unpack"):
                originals.update(exporter.unpack(path.read_bytes()))
            else:
                originals[relative] = path.read_text(
                    encoding="utf-8", errors="replace"
                )
        produced = exporter.render(systems, report, originals, scraped)
        self.assertEqual(exporter.validate(systems, produced), [])
        return produced, originals

    def test_retrodeck_keeps_every_bios_entry_it_declares(self):
        """The component list is corrected in place, never replaced.

        Assigning our entries wholesale dropped 114 distinct filenames that
        RetroDECK's own manifests declare.
        """
        produced, originals = self._export("retrodeck")

        def names(text: str) -> set[str]:
            manifest = json.loads(text)
            for value in manifest.values():
                if not isinstance(value, dict):
                    continue
                listing = value.get("bios")
                if listing is None:
                    for key in ("preset_actions", "cores"):
                        nested = value.get(key)
                        if isinstance(nested, dict) and "bios" in nested:
                            listing = nested["bios"]
                            break
                if listing is None:
                    continue
                return {
                    str(e.get("filename", ""))
                    for e in listing
                    if isinstance(e, dict)
                }
            return set()

        lost: set[str] = set()
        compared = 0
        for path, text in produced.items():
            if path not in originals:
                continue
            compared += 1
            lost |= names(originals[path]) - names(text)
        self.assertGreater(compared, 0, "no component manifest was compared")
        self.assertEqual(
            lost, set(), "the export dropped entries RetroDECK declares"
        )

    def test_recalbox_keeps_every_system_and_every_path(self):
        produced, originals = self._export("recalbox")
        before = parse_untrusted_xml(originals["es_bios.xml"], "es_bios.xml")
        after = ET.fromstring(produced["es_bios.xml"])
        self.assertEqual(
            {s.get("platform") for s in before.iter("system")}
            - {s.get("platform") for s in after.iter("system")},
            set(),
        )
        self.assertEqual(
            {b.get("path") for b in before.iter("bios")}
            - {b.get("path") for b in after.iter("bios")},
            set(),
        )

    def test_the_recalbox_export_satisfies_the_schema_recalbox_ships(self):
        schema_path = UPSTREAM_CACHE / "recalbox" / "es_bios.xsd"
        if not schema_path.exists():
            self.skipTest("es_bios.xsd not cached")
        required = self._required_attributes(schema_path.read_text())
        produced, _ = self._export("recalbox")
        root = ET.fromstring(produced["es_bios.xml"])
        for tag, attributes in required.items():
            for element in root.iter(tag):
                for attribute in attributes:
                    with self.subTest(tag=tag, attribute=attribute):
                        self.assertTrue(element.get(attribute))

    @staticmethod
    def _required_attributes(schema: str) -> dict[str, set[str]]:
        """Read the required attributes straight out of the platform's XSD.

        Scoped to each element's own type: a nested declaration belongs to
        the child, and folding it into the parent would demand md5 on
        <system>.
        """
        namespace = "{http://www.w3.org/2001/XMLSchema}"
        root = parse_untrusted_xml(schema, "es_bios.xsd")
        required: dict[str, set[str]] = {}

        def own_attributes(node: ET.Element) -> set[str]:
            found: set[str] = set()
            for child in node:
                if child.tag == f"{namespace}element":
                    continue
                if child.tag == f"{namespace}attribute":
                    name = child.get("name")
                    if child.get("use") == "required" and name:
                        found.add(name)
                    continue
                found |= own_attributes(child)
            return found

        for element in root.iter(f"{namespace}element"):
            name = element.get("name")
            if not name:
                continue
            names = own_attributes(element)
            if names:
                required[name] = names
        return required

    def test_batocera_keeps_every_system_and_still_runs(self):
        produced, originals = self._export("batocera")
        before = set(
            re.findall(r'^\s{4}"([^"]+)":\s*\{\s*"name"', originals["batocera-systems"],
                       re.M)
        )
        after = set(
            re.findall(r'^\s{4}"([^"]+)":\s*\{\s*"name"',
                       produced["batocera-systems"], re.M)
        )
        self.assertEqual(before - after, set())

        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "batocera-systems"
            script.write_text(produced["batocera-systems"], encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "--createReadme"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip())

    def test_batocera_keeps_the_zip_member_checks(self):
        """checkInsideZip verifies a ROM inside the archive, not the archive."""
        produced, originals = self._export("batocera")
        self.assertEqual(
            produced["batocera-systems"].count("zippedFile"),
            originals["batocera-systems"].count("zippedFile"),
        )

    def test_rocknix_still_runs(self):
        produced, _ = self._export("rocknix")
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "rocknix-systems"
            script.write_text(produced["rocknix-systems"], encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "--createReadme"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_emudeck_keeps_every_check_and_still_parses(self):
        produced, originals = self._export("emudeck")
        pattern = re.compile(r"^(\w+)\(\)\{", re.M)
        before = set(pattern.findall(originals["checkBIOS.sh"]))
        after = set(pattern.findall(produced["checkBIOS.sh"]))
        self.assertEqual(before - after, set())

        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "checkBIOS.sh"
            script.write_text(produced["checkBIOS.sh"], encoding="utf-8")
            result = subprocess.run(
                ["bash", "-n", str(script)], capture_output=True, text=True, timeout=60,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_emudeck_keeps_every_md5_it_declares(self):
        """An md5 the platform holds is never withdrawn from its array.

        The array was assigned wholesale, so any value our model did not
        carry disappeared and a user whose dump matched it stopped passing
        EmuDeck's own check.
        """
        produced, originals = self._export("emudeck")
        pattern = re.compile(r"local\s+hashes=\(([^)]*)\)")
        before = pattern.findall(originals["checkBIOS.sh"])
        after = pattern.findall(produced["checkBIOS.sh"])
        self.assertEqual(len(before), len(after), "an md5 array vanished")
        for index, (was, now) in enumerate(zip(before, after)):
            with self.subTest(array=index):
                self.assertEqual(
                    set(was.split()) - set(now.split()),
                    set(),
                    "the export withdrew an md5 EmuDeck declares",
                )

    def test_retrobat_keeps_every_system_and_every_file(self):
        produced, originals = self._export("retrobat")
        before = json.loads(originals["batocera-systems.json"])
        after = json.loads(produced["batocera-systems.json"])
        self.assertEqual(set(before) - set(after), set())
        self.assertEqual(
            {(s, f["file"]) for s, d in before.items() for f in d["biosFiles"]}
            - {(s, f["file"]) for s, d in after.items() for f in d["biosFiles"]},
            set(),
        )

    def test_retroarch_keeps_every_rom_name_the_dat_declares(self):
        produced, originals = self._export("retroarch")
        pattern = re.compile(r"^\trom \( name (\"[^\"]+\"|\S+)", re.M)
        before = {n.strip('"') for n in pattern.findall(originals["System.dat"])}
        after = {n.strip('"') for n in pattern.findall(produced["System.dat"])}
        self.assertEqual(before - after, set())

    def test_the_dat_keeps_the_system_names_libretro_writes(self):
        """The comment is the name the DAT spells, separator included."""
        produced, originals = self._export("retroarch")
        comments = re.compile(r'^\tcomment "([^"]+)"', re.M)
        before = set(comments.findall(originals["System.dat"]))
        after = set(comments.findall(produced["System.dat"]))
        self.assertEqual(before - after, set())

    def test_the_dat_never_states_a_rom_it_cannot_hash(self):
        produced, _ = self._export("retroarch")
        for line in re.findall(r"^\trom \( (.*) \)$", produced["System.dat"], re.M):
            with self.subTest(line=line[:60]):
                self.assertTrue(
                    any(f" {h} " in line for h in ("crc", "md5", "sha1"))
                )

    def test_misterfpga_keeps_the_download_urls_it_installs_from(self):
        produced, _ = self._export("misterfpga")
        database = json.loads(produced["bios_db.json"])
        self.assertTrue(database.get("db_id"))
        for path, entry in database["files"].items():
            with self.subTest(path=path):
                self.assertTrue(entry.get("url"))

    def test_bizhawk_stays_compilable(self):
        produced, originals = self._export("bizhawk")
        source = produced["FirmwareDatabase.cs"]
        self.assertEqual(source.count("{"), source.count("}"))
        self.assertEqual(
            source.count("FirmwareAndOption("),
            originals["FirmwareDatabase.cs"].count("FirmwareAndOption("),
        )

    # A core RetroPie packages, with a file its help does not yet name.
    RETROPIE_TRUTH = {
        "systems": {
            "magnavox-odyssey2": {
                "files": [
                    {
                        "name": "c52.bin",
                        "required": True,
                        "md5": "f1071cdb0b6b10dde94d3bc8a6146387",
                        "_cores": ["o2em"],
                    }
                ]
            }
        }
    }

    def test_retropie_keeps_every_name_its_packages_already_list(self):
        """RetroPie's BIOS list is prose, and a name it writes is never removed."""
        produced, originals = self._export("retropie", self.RETROPIE_TRUTH)
        exporter = discover_exporters()["retropie"]()
        help_of = re.compile(r'rp_module_help="((?:[^"\\]|\\.)*)"')
        for relative, text in produced.items():
            with self.subTest(module=relative):
                before = help_of.search(originals[relative])
                after = help_of.search(text)
                self.assertIsNotNone(after, "the help string is not closed")
                self.assertEqual(
                    exporter._listed(before.group(1))
                    - exporter._listed(after.group(1)),
                    set(),
                )
                self.assertIn("BIOS", after.group(1))

    def test_a_patched_scriptmodule_still_parses_as_bash(self):
        produced, _ = self._export("retropie", self.RETROPIE_TRUTH)
        self.assertTrue(produced)
        with tempfile.TemporaryDirectory() as tmp:
            for relative, text in produced.items():
                script = Path(tmp) / Path(relative).name
                script.write_text(text, encoding="utf-8")
                result = subprocess.run(
                    ["bash", "-n", str(script)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                with self.subTest(module=relative):
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_retropie_never_drafts_a_sentence_nobody_wrote(self):
        """A package with no BIOS list is a docs change, not a correction."""
        produced, originals = self._export("retropie", self.RETROPIE_TRUTH)
        for relative in produced:
            with self.subTest(module=relative):
                self.assertIn("BIOS", originals[relative])

    def test_retrodeck_writes_a_manifest_per_component(self):
        produced, _ = self._export("retrodeck")
        self.assertTrue(produced)
        for path, content in produced.items():
            with self.subTest(path=path):
                self.assertTrue(path.endswith("component_manifest.json"))
                manifest = json.loads(content)
                component = next(iter(manifest.values()))
                self.assertTrue(
                    component.get("name") or component.get("system"),
                    "the component lost its identity",
                )


if __name__ == "__main__":
    unittest.main()
