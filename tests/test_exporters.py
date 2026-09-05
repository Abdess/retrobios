#!/usr/bin/env python3
"""Native-format exporters.

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

import json
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import (  # noqa: E402
    list_registered_platforms,
    load_platform_config,
    parse_untrusted_xml,
)
from exporter import discover_exporters  # noqa: E402
from exporter.base_exporter import BaseExporter  # noqa: E402
from export_native import pinned_base  # noqa: E402
from exporter.baseline import (  # noqa: E402
    NativeFile,
    build_native_model,
)

UPSTREAM_CACHE = REPO_ROOT / ".cache" / "upstream-native"

TRUTH = {
    "systems": {
        "sony-playstation": {
            "files": [
                {
                    "name": "scph5501.bin",
                    "path": "psx/scph5501.bin",
                    "md5": "490f666e1afb15b7362b406ed1cea246",
                    "size": 524288,
                    "required": True,
                    "_cores": ["duckstation"],
                },
                {
                    "name": "scph7001.bin",
                    "path": "psx/scph7001.bin",
                    "md5": "1e68c231d0896b7eadcad1d7d8e76129",
                    "size": 524288,
                    "required": False,
                    "_cores": ["duckstation"],
                },
                # Carries an md5 on purpose: without one it would be dropped
                # for being incomplete, and the placeholder guard would never
                # be the reason it stayed out.
                {
                    "name": "<user-selected>.bin",
                    "path": "psx/PLACEHOLDER-MUST-NOT-SHIP.bin",
                    "md5": "00000000000000000000000000000000",
                    "size": 1,
                    "required": False,
                    "_cores": ["duckstation"],
                },
            ],
        },
    },
}

SCRAPED = {
    "systems": {
        "sony-playstation": {
            "native_id": "psx",
            "files": [
                {
                    "name": "scph5501.bin",
                    "destination": "psx/scph5501.bin",
                    "native_system": "psx",
                    "native_name": "Sony PlayStation",
                    "md5": "deadbeefdeadbeefdeadbeefdeadbeef",
                    "core": "libretro/duckstation",
                    "required": True,
                },
                {
                    "name": "unknown-to-truth.bin",
                    "destination": "psx/unknown-to-truth.bin",
                    "native_system": "psx",
                    "native_name": "Sony PlayStation",
                    "md5": "11111111111111111111111111111111",
                    "core": "libretro/duckstation",
                    "required": True,
                },
            ],
        },
    },
}


def model(truth: dict = TRUTH, scraped: dict | None = SCRAPED):
    return build_native_model(truth, scraped)


class Reconciliation(unittest.TestCase):
    """The platform's file corrected, not replaced by ours."""

    def test_a_file_the_truth_says_nothing_about_is_kept(self):
        systems, _ = model()
        names = {fe.name for fe in systems["psx"].files}
        self.assertIn("unknown-to-truth.bin", names)

    def test_the_truth_overrides_a_hash_the_platform_got_wrong(self):
        systems, report = model()
        entry = next(fe for fe in systems["psx"].files if fe.name == "scph5501.bin")
        self.assertEqual(entry.hash("md5"), "490f666e1afb15b7362b406ed1cea246")
        self.assertTrue(any("scph5501" in c for c in report.hashes_corrected))

    def test_a_file_only_the_truth_knows_is_added(self):
        systems, report = model()
        names = {fe.name for fe in systems["psx"].files}
        self.assertIn("scph7001.bin", names)
        self.assertEqual(report.files_added, 1)

    def test_a_placeholder_is_never_added(self):
        systems, _ = model()
        names = {fe.name for fe in systems["psx"].files}
        self.assertNotIn("<user-selected>.bin", names)

    def test_systems_are_keyed_by_the_name_the_platform_uses(self):
        systems, _ = model()
        self.assertEqual(sorted(systems), ["psx"])

    def test_the_platform_own_grouping_survives_a_collapsed_slug(self):
        """Several native systems can share one of our slugs.

        Recalbox files pcengine, pcenginecd and supergrafx under one slug.
        Grouping on the slug would publish one of the three and drop the
        rest, which is how eleven Recalbox platforms went missing.
        """
        scraped = {
            "systems": {
                "nec-pc-engine": {
                    "native_id": "pcengine",
                    "files": [
                        {
                            "name": "syscard3.pce",
                            "destination": "pcengine/syscard3.pce",
                            "native_system": "pcengine",
                            "md5": "38179df8f4ac870017db21ebcbf53114",
                        },
                        {
                            "name": "syscard3.pce",
                            "destination": "supergrafx/syscard3.pce",
                            "native_system": "supergrafx",
                            "md5": "38179df8f4ac870017db21ebcbf53114",
                        },
                    ],
                },
            },
        }
        systems, _ = build_native_model({"systems": {}}, scraped)
        self.assertEqual(sorted(systems), ["pcengine", "supergrafx"])

    def test_an_entry_the_platform_declares_without_a_hash_is_still_written(self):
        """Batocera and RetroBat both ship entries with an empty md5."""
        scraped = {
            "systems": {
                "nintendo-ds": {
                    "native_id": "nds",
                    "files": [
                        {
                            "name": "firmware.bin",
                            "destination": "firmware.bin",
                            "native_system": "nds",
                        }
                    ],
                }
            }
        }
        systems, _ = build_native_model({"systems": {}}, scraped)
        entry = systems["nds"].files[0]
        self.assertTrue(BaseExporter.writable(entry, require="md5"))

    def test_no_format_drops_what_the_platform_already_declares(self):
        """An export poorer than the file it corrects is not usable."""
        systems, _ = model()
        for name, cls in discover_exporters().items():
            for system in systems.values():
                for entry in system.files:
                    if entry.platform is None:
                        continue
                    with self.subTest(platform=name, file=entry.name):
                        self.assertTrue(cls.writable(entry))

    def test_an_addition_the_format_cannot_express_is_refused(self):
        truth = {
            "systems": {
                "nintendo-ds": {"files": [{"name": "no-hash.bin", "required": True}]}
            }
        }
        systems, _ = build_native_model(truth, None)
        entry = systems["nintendo-ds"].files[0]
        self.assertFalse(BaseExporter.writable(entry, require="md5"))


class ExporterRegistry(unittest.TestCase):
    """Every registered platform has an exporter, and it declares itself."""

    def test_every_exporter_declares_a_platform_and_a_filename(self):
        for name, cls in discover_exporters().items():
            with self.subTest(platform=name):
                self.assertTrue(cls.platform_name())
                self.assertTrue(cls.native_filename())
                self.assertTrue(issubclass(cls, BaseExporter))

    def test_every_registered_platform_can_be_exported(self):
        """A platform with no exporter is a platform we cannot hand back.

        Archived included: the export is a correction we offer, not a
        release artefact, and RetroPie's users are not fewer for it.
        """
        exporters = discover_exporters()
        registered = set(
            list_registered_platforms(
                str(REPO_ROOT / "platforms"), include_archived=True
            )
        )
        self.assertEqual(registered - set(exporters), set())

    def test_no_exporter_is_registered_for_an_unregistered_platform(self):
        """A dead exporter is one nobody will notice has stopped working."""
        exporters = set(discover_exporters())
        registered = set(
            list_registered_platforms(
                str(REPO_ROOT / "platforms"), include_archived=True
            )
        )
        self.assertEqual(exporters - registered, set())

    def test_every_exporter_says_what_its_format_can_state(self):
        """A correction to a field the file has no place for is not delivered."""
        for name, cls in discover_exporters().items():
            with self.subTest(platform=name):
                carried = cls.carries()
                self.assertTrue(carried)
                self.assertTrue(
                    carried
                    <= {"size", "crc32", "md5", "sha1", "sha256", "required", "name"},
                    f"{name} claims a field that is not one of ours: {carried}",
                )

    def test_only_a_format_with_the_field_claims_to_carry_it(self):
        """Recalbox writes mandatory; RetroBat's entries are md5 and file."""
        exporters = discover_exporters()
        self.assertIn("required", exporters["recalbox"].carries())
        self.assertNotIn("required", exporters["retrobat"].carries())
        self.assertNotIn("required", exporters["retroarch"].carries())

    def test_an_exporter_that_patches_code_says_it_needs_the_original(self):
        """Regenerating a script from data alone drops the code around it."""
        for name in ("batocera", "rocknix", "emudeck", "retrodeck", "bizhawk",
                     "misterfpga"):
            with self.subTest(platform=name):
                self.assertTrue(discover_exporters()[name].needs_original())


class SearchOrder(unittest.TestCase):
    """A list is read in the order the code looks, best first."""

    @staticmethod
    def _entry(name, priority=None, position=0):
        truth = {"name": name, "required": True, "md5": f"{position:032x}"}
        if priority is not None:
            truth["priority"] = priority
        return NativeFile(
            name=name, destination=name, native_system="psx", truth=truth
        )

    def test_the_declared_rank_orders_the_names(self):
        exporter = discover_exporters()["retropie"]()
        candidates = [
            self._entry("scph5502.bin", 5, 0),
            self._entry("scph5501.bin", 2, 1),
            self._entry("scph7001.bin", 10, 2),
        ]
        self.assertEqual(
            exporter._in_search_order(candidates),
            ["scph5501.bin", "scph5502.bin", "scph7001.bin"],
        )

    def test_without_a_rank_the_order_the_code_walks_is_kept(self):
        """An undeclared order is the profile's own, not the alphabet."""
        exporter = discover_exporters()["retropie"]()
        candidates = [
            self._entry("zzz.bin", None, 0),
            self._entry("aaa.bin", None, 1),
        ]
        self.assertEqual(
            exporter._in_search_order(candidates), ["zzz.bin", "aaa.bin"]
        )

    def test_a_ranked_file_is_read_before_an_unranked_one(self):
        exporter = discover_exporters()["retropie"]()
        candidates = [
            self._entry("unranked.bin", None, 0),
            self._entry("ranked.bin", 9, 1),
        ]
        self.assertEqual(
            exporter._in_search_order(candidates), ["ranked.bin", "unranked.bin"]
        )

    def test_cores_that_disagree_keep_the_best_rank(self):
        """Nothing is dropped on the rank here, so the best one wins.

        slot.py voids the choice when cores disagree because it keeps one
        file; ordering keeps them all, and a file that is some core's first
        choice belongs early.
        """
        merged = {"name": "scph5501.bin", "priority": 2, "priority_conflict": True}
        entry = NativeFile(
            name="scph5501.bin",
            destination="scph5501.bin",
            native_system="psx",
            truth=merged,
        )
        self.assertEqual(entry.priority, 2)


class AdditionOrder(unittest.TestCase):
    """What we add is listed the way the code looks for it."""

    TRUTH = {
        "systems": {
            "sony-playstation": {
                "files": [
                    {
                        "name": "third.bin",
                        "md5": "c" * 32,
                        "required": True,
                        "priority": 10,
                    },
                    {
                        "name": "first.bin",
                        "md5": "a" * 32,
                        "required": True,
                        "priority": 1,
                    },
                    {"name": "unranked.bin", "md5": "b" * 32, "required": True},
                ]
            }
        }
    }

    def test_a_ranked_addition_is_named_before_a_later_one(self):
        systems, _ = build_native_model(self.TRUTH, None)
        names = [fe.name for fe in systems["sony-playstation"].files]
        self.assertEqual(names, ["first.bin", "third.bin", "unranked.bin"])

    def test_what_the_platform_wrote_keeps_its_place(self):
        """Reordering their own entries would be churn, not a correction."""
        scraped = {
            "systems": {
                "sony-playstation": {
                    "native_id": "psx",
                    "files": [
                        {
                            "name": "theirs-b.bin",
                            "destination": "theirs-b.bin",
                            "native_system": "psx",
                            "md5": "d" * 32,
                        },
                        {
                            "name": "theirs-a.bin",
                            "destination": "theirs-a.bin",
                            "native_system": "psx",
                            "md5": "e" * 32,
                        },
                    ],
                }
            }
        }
        systems, _ = build_native_model(self.TRUTH, scraped)
        names = [fe.name for fe in systems["psx"].files]
        self.assertEqual(names[:2], ["theirs-b.bin", "theirs-a.bin"])
        self.assertEqual(names[2], "first.bin")


class PinnedRevision(unittest.TestCase):
    """The file we patch is the revision our transcription came from."""

    def test_the_tag_the_scraper_pinned_wins_over_the_branch_tip(self):
        wanted = {"batocera-systems": "https://example.invalid/master/batocera-systems"}
        scraped = {
            "source": "https://raw.githubusercontent.com/batocera-linux"
            "/batocera.linux/batocera-43.1/package/batocera-systems"
        }
        self.assertEqual(
            pinned_base(wanted, scraped),
            "https://raw.githubusercontent.com/batocera-linux/batocera.linux"
            "/batocera-43.1/package/",
        )

    def test_a_blob_page_is_read_as_raw(self):
        """github.com/.../blob/... names a revision but serves HTML."""
        wanted = {"System.dat": "https://example.invalid/System.dat"}
        scraped = {
            "source": "https://github.com/libretro/libretro-database"
            "/blob/master/dat/System.dat"
        }
        self.assertEqual(
            pinned_base(wanted, scraped),
            "https://raw.githubusercontent.com/libretro/libretro-database"
            "/master/dat/",
        )

    def test_a_source_that_names_no_wanted_file_changes_nothing(self):
        wanted = {"component_manifest.json": "https://example.invalid/x.json"}
        scraped = {"source": "https://github.com/RetroDECK/components"}
        self.assertEqual(pinned_base(wanted, scraped), "")

    def test_every_platform_that_records_its_source_pins_the_export(self):
        """A scraped platform states the revision; the export follows it."""
        exporters = discover_exporters()
        for name in ("batocera", "recalbox", "bizhawk", "romm", "retroarch"):
            with self.subTest(platform=name):
                config = load_platform_config(name, str(REPO_ROOT / "platforms"))
                base = pinned_base(dict(exporters[name].native_sources()), config)
                self.assertTrue(base.startswith("https://"), base)


class RecalboxExport(unittest.TestCase):
    def _render(self):
        systems, report = model()
        exporter = discover_exporters()["recalbox"]()
        return exporter, systems, exporter.render(systems, report, {}, None)

    def test_output_is_well_formed_xml_in_recalbox_shape(self):
        _, _, produced = self._render()
        root = ET.fromstring(produced["es_bios.xml"])
        self.assertEqual(root.tag, "biosList")
        self.assertTrue(list(root.iter("system")))

    def test_every_element_carries_what_the_schema_requires(self):
        """es_bios.xsd makes path, md5 and core required on every bios."""
        _, _, produced = self._render()
        root = ET.fromstring(produced["es_bios.xml"])
        for element in root.iter("bios"):
            for attribute in ("path", "md5", "core"):
                self.assertTrue(element.get(attribute), attribute)

    def test_mandatory_is_only_stated_when_it_is_false(self):
        _, _, produced = self._render()
        root = ET.fromstring(produced["es_bios.xml"])
        by_path = {e.get("path"): e for e in root.iter("bios")}
        self.assertIsNone(by_path["psx/scph5501.bin"].get("mandatory"))
        self.assertEqual(by_path["psx/scph7001.bin"].get("mandatory"), "false")

    def test_hash_match_mandatory_does_not_follow_mandatory(self):
        """They are separate axes: Recalbox uses all four combinations."""
        _, _, produced = self._render()
        root = ET.fromstring(produced["es_bios.xml"])
        optional = next(
            e for e in root.iter("bios") if e.get("mandatory") == "false"
        )
        self.assertIsNone(optional.get("hashMatchMandatory"))

    def test_the_export_passes_its_own_validator(self):
        exporter, systems, produced = self._render()
        self.assertEqual(exporter.validate(systems, produced), [])

    def test_a_truncated_export_is_reported(self):
        exporter, systems, _ = self._render()
        empty = {
            "es_bios.xml": '<?xml version="1.0"?>\n<biosList></biosList>\n',
        }
        self.assertTrue(exporter.validate(systems, empty))


class RommExport(unittest.TestCase):
    def _render(self):
        systems, report = model()
        exporter = discover_exporters()["romm"]()
        return exporter, systems, exporter.render(systems, report, {}, None)

    def test_every_entry_can_actually_verify(self):
        """RomM matches on size and then on one hash; without both, never."""
        _, _, produced = self._render()
        data = json.loads(produced["known_bios_files.json"])
        self.assertTrue(data)
        for key, entry in data.items():
            with self.subTest(key=key):
                self.assertTrue(entry.get("size"))
                self.assertTrue(
                    any(entry.get(h) for h in ("md5", "sha1", "crc"))
                )

    def test_size_is_written_as_the_fixture_writes_it(self):
        _, _, produced = self._render()
        data = json.loads(produced["known_bios_files.json"])
        self.assertIsInstance(next(iter(data.values()))["size"], str)

    def test_keys_are_the_platform_slug_the_file_belongs_to(self):
        _, _, produced = self._render()
        data = json.loads(produced["known_bios_files.json"])
        self.assertTrue(all(k.startswith("psx:") for k in data))


class BatoceraExport(unittest.TestCase):
    def _render(self, originals):
        systems, report = model()
        exporter = discover_exporters()["batocera"]()
        return exporter, systems, exporter.render(systems, report, originals, None)

    SKELETON = (
        "#!/usr/bin/env python\n"
        "systems = {\n"
        "}\n"
        "def checkBios(systems, prefix, filterROMs):\n"
        "    return {}\n"
    )

    def test_an_unhashed_entry_is_written_with_an_empty_md5(self):
        scraped = {
            "systems": {
                "nintendo-ds": {
                    "native_id": "nds",
                    "files": [
                        {
                            "name": "firmware.bin",
                            "destination": "firmware.bin",
                            "native_system": "nds",
                        }
                    ],
                }
            }
        }
        systems, report = build_native_model({"systems": {}}, scraped)
        exporter = discover_exporters()["batocera"]()
        produced = exporter.render(
            systems, report, {"batocera-systems": self.SKELETON}, None
        )
        self.assertIn('"md5": ""', produced["batocera-systems"])

    def test_writing_without_the_platform_file_is_refused(self):
        """A systems dict alone is not the script Batocera runs."""
        systems, report = model()
        exporter = discover_exporters()["batocera"]()
        with self.assertRaises(ValueError):
            exporter.render(systems, report, {}, None)

    def test_the_code_around_the_data_survives(self):
        original = (
            "#!/usr/bin/env python\n"
            "systems = {\n"
            '    "psx": { "name": "PS1", "biosFiles": [ '
            '{ "md5": "deadbeefdeadbeefdeadbeefdeadbeef", '
            '"file": "bios/psx/scph5501.bin" } ] },\n'
            "}\n"
            "def checkBios(systems, prefix, filterROMs):\n"
            "    return {}\n"
        )
        _, _, produced = self._render({"batocera-systems": original})
        output = produced["batocera-systems"]
        self.assertIn("def checkBios(", output)
        self.assertIn("#!/usr/bin/env python", output)

    def test_a_note_beside_a_file_is_not_lost_when_the_entry_changes(self):
        original = (
            "systems = {\n"
            '    "psx": { "name": "PS1", "biosFiles": [\n'
            '        # ideally the other revision\n'
            '        { "md5": "deadbeefdeadbeefdeadbeefdeadbeef", '
            '"file": "bios/psx/scph5501.bin" } ] },\n'
            "}\n"
            "def checkBios(systems, prefix, filterROMs):\n"
            "    return {}\n"
        )
        _, _, produced = self._render({"batocera-systems": original})
        self.assertIn("# ideally the other revision", produced["batocera-systems"])


class UpstreamFidelity(unittest.TestCase):
    """The real files, compared against what we hand back.

    Nothing a platform declares today may be missing from the export: an
    export that loses systems is one no maintainer can apply.
    """

    @classmethod
    def setUpClass(cls):
        if not UPSTREAM_CACHE.is_dir():
            raise unittest.SkipTest(
                "no upstream cache; run scripts/export_native.py --all --fetch"
            )

    def _export(self, platform: str, truth: dict | None = None) -> dict[str, str]:
        cache = UPSTREAM_CACHE / platform
        if not cache.is_dir():
            self.skipTest(f"no cached original for {platform}")
        scraped = load_platform_config(platform, str(REPO_ROOT / "platforms"))
        systems, report = build_native_model(truth or {"systems": {}}, scraped)
        exporter = discover_exporters()[platform]()
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
                    if child.get("use") == "required" and child.get("name"):
                        found.add(child.get("name"))
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
                ["bash", "-n", str(script)], capture_output=True, text=True, timeout=60
            )
        self.assertEqual(result.returncode, 0, result.stderr)

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
        """RetroPie's BIOS list is prose; a name it writes is never removed."""
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
