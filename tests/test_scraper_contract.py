#!/usr/bin/env python3
"""The BaseScraper contract the wiki asks contributors to implement.

wiki/adding-a-scraper.md and wiki/adding-a-platform.md document
compare_with_config, ChangeSet.has_changes and test_connection as the
interface a new scraper plugs into. No scraper in the repository calls them,
so nothing proved they still worked. A documented contract that is never
exercised is a promise to contributors backed by nothing.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import importlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper import emudeck_scraper, libretro_scraper  # noqa: E402
from scraper.base_scraper import (  # noqa: E402
    BaseScraper,
    BiosRequirement,
    ChangeSet,
    fetch_github_latest_version,
    github_headers,
)


class _StubScraper(BaseScraper):
    """Minimal scraper: returns what it was handed, or raises."""

    def __init__(self, requirements=None, error: Exception | None = None):
        super().__init__(url="https://example.test/bios.xml")
        self._requirements = requirements or []
        self._error = error

    def fetch_requirements(self) -> list[BiosRequirement]:
        if self._error is not None:
            raise self._error
        return self._requirements

    def validate_format(self, raw_data: str) -> bool:
        return True


def _config(*files: dict) -> dict:
    return {"systems": {"test-sys": {"files": list(files)}}}


class ChangeSetSummary(unittest.TestCase):
    def test_empty_changeset_has_no_changes(self):
        changes = ChangeSet()
        self.assertFalse(changes.has_changes)
        self.assertEqual(changes.summary(), "no changes")

    def test_summary_counts_each_kind(self):
        req = BiosRequirement(name="a.bin", system="test-sys")
        changes = ChangeSet(added=[req], removed=[req], modified=[(req, req)])
        self.assertTrue(changes.has_changes)
        self.assertEqual(changes.summary(), "+1 added, -1 removed, ~1 modified")


class CompareWithConfig(unittest.TestCase):
    def test_new_upstream_file_is_reported_as_added(self):
        scraper = _StubScraper([BiosRequirement(name="new.bin", system="test-sys")])
        changes = scraper.compare_with_config(_config())
        self.assertEqual([r.name for r in changes.added], ["new.bin"])
        self.assertTrue(changes.has_changes)

    def test_file_dropped_upstream_is_reported_as_removed(self):
        scraper = _StubScraper([])
        changes = scraper.compare_with_config(_config({"name": "old.bin"}))
        self.assertEqual([r.name for r in changes.removed], ["old.bin"])

    def test_changed_sha1_is_reported_as_modified(self):
        scraper = _StubScraper(
            [BiosRequirement(name="a.bin", system="test-sys", sha1="b" * 40)]
        )
        changes = scraper.compare_with_config(_config({"name": "a.bin", "sha1": "a" * 40}))
        self.assertEqual(len(changes.modified), 1)
        before, after = changes.modified[0]
        self.assertEqual((before.sha1, after.sha1), ("a" * 40, "b" * 40))

    def test_changed_md5_is_reported_when_no_sha1_is_declared(self):
        scraper = _StubScraper(
            [BiosRequirement(name="a.bin", system="test-sys", md5="b" * 32)]
        )
        changes = scraper.compare_with_config(_config({"name": "a.bin", "md5": "a" * 32}))
        self.assertEqual(len(changes.modified), 1)

    def test_identical_hashes_are_not_a_change(self):
        scraper = _StubScraper(
            [BiosRequirement(name="a.bin", system="test-sys", sha1="a" * 40)]
        )
        changes = scraper.compare_with_config(_config({"name": "a.bin", "sha1": "a" * 40}))
        self.assertFalse(changes.has_changes)

    def test_a_file_in_another_system_is_not_the_same_file(self):
        scraper = _StubScraper([BiosRequirement(name="a.bin", system="other-sys")])
        changes = scraper.compare_with_config(_config({"name": "a.bin"}))
        self.assertEqual([r.name for r in changes.added], ["a.bin"])
        self.assertEqual([r.name for r in changes.removed], ["a.bin"])


class TestConnection(unittest.TestCase):
    def test_reachable_source_reports_true(self):
        self.assertTrue(_StubScraper([]).test_connection())

    def test_network_failure_reports_false(self):
        self.assertFalse(_StubScraper(error=OSError("unreachable")).test_connection())

    def test_bad_payload_reports_false(self):
        self.assertFalse(_StubScraper(error=ValueError("bad format")).test_connection())

    def test_an_unexpected_error_is_not_swallowed(self):
        """Only reachability failures are absorbed. A bug must surface."""
        with self.assertRaises(KeyError):
            _StubScraper(error=KeyError("bug")).test_connection()


class RateLimitedForge(unittest.TestCase):
    """GitLab answered 429 midway through Recalbox's system.ini files and
    the whole scrape stopped."""

    @staticmethod
    def _limited(retry_after: str | None):
        import email.message  # noqa: PLC0415
        import io  # noqa: PLC0415

        headers = email.message.Message()
        if retry_after is not None:
            headers["Retry-After"] = retry_after
        return urllib.error.HTTPError("u", 429, "Too Many Requests", headers, io.BytesIO())

    def test_a_rate_limit_is_waited_out(self):
        import io  # noqa: PLC0415

        from scraper.base_scraper import fetch_bytes  # noqa: PLC0415

        waits: list[float] = []
        answers = [self._limited("7"), self._limited(None), io.BytesIO(b"ok")]

        def urlopen(_request, timeout):
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        with mock.patch("urllib.request.urlopen", urlopen):
            self.assertEqual(fetch_bytes("https://x", sleep=waits.append), b"ok")
        self.assertEqual(waits, [7.0, 4.0])

    def test_a_lasting_limit_or_a_missing_file_fails(self):
        from scraper.base_scraper import fetch_bytes  # noqa: PLC0415

        def limited(_request, timeout):
            raise self._limited(None)

        with mock.patch("urllib.request.urlopen", limited):
            with self.assertRaises(ConnectionError):
                fetch_bytes("https://x", attempts=3, sleep=lambda _s: None)

        def gone(_request, timeout):
            raise urllib.error.HTTPError("u", 404, "Not Found", None, None)

        waits: list[float] = []
        with mock.patch("urllib.request.urlopen", gone):
            with self.assertRaises(ConnectionError):
                fetch_bytes("https://x", sleep=waits.append)
        self.assertEqual(waits, [])


class RecalboxReadsItsSystemsInBatches(unittest.TestCase):
    """One raw read per system.ini, about 150, kept GitLab throttling the
    scrape past its half-hour timeout."""

    def test_one_query_per_fifty_systems(self):
        import json as _json  # noqa: PLC0415

        from scraper import recalbox_scraper  # noqa: PLC0415

        systems = [f"sys{i:03}" for i in range(120)]
        queries: list[list[str]] = []

        def fetch(url, data=None, headers=None):
            if "repository/tree" in url:
                page = int(url.rsplit("page=", 1)[1])
                names = systems[(page - 1) * 100:page * 100]
                return _json.dumps([{"name": n, "type": "tree"} for n in names]).encode()
            paths = _json.loads(data)["variables"]["paths"]
            queries.append(paths)
            nodes = [{"path": p, "rawBlob": "[core.0]\nemulator = libretro\ncore = "
                      + p.split("/")[-2] + "\n"} for p in paths]
            return _json.dumps({"data": {"project": {"repository": {
                "blobs": {"nodes": nodes}}}}}).encode()

        scraper = recalbox_scraper.Scraper.__new__(recalbox_scraper.Scraper)
        scraper.tag = "10.1.1"
        with mock.patch.object(recalbox_scraper, "fetch_bytes", fetch):
            cores, _standalone, _dual = scraper._fetch_cores()
        self.assertEqual([len(q) for q in queries], [50, 50, 20])
        self.assertEqual(len(cores), 120)


class EveryNamedScraperExists(unittest.TestCase):
    """The registry named lakka_targets, a scraper no file defines: a refresh
    of stale targets would have failed on its import."""

    def test_registry_scrapers_are_modules(self):
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        scraper_dir = REPO_ROOT / "scripts" / "scraper"
        for name, meta in registry["platforms"].items():
            with self.subTest(platform=name):
                if meta.get("scraper"):
                    self.assertTrue((scraper_dir / f"{meta['scraper']}_scraper.py").is_file())
                if meta.get("target_scraper"):
                    self.assertTrue((scraper_dir / "targets"
                                     / f"{meta['target_scraper']}_scraper.py").is_file())


class RetroPiePackageList(unittest.TestCase):
    """RetroPie states its packages, and nothing else states them for it."""

    @staticmethod
    def _archive(modules: dict[str, str]) -> bytes:
        import io
        import tarfile

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for path, body in modules.items():
                payload = body.encode()
                info = tarfile.TarInfo(f"RetroPie-Setup-master/{path}")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        return buffer.getvalue()

    def _scraper(self, modules: dict[str, str]):
        from scraper.retropie_scraper import Scraper

        # An explicit archive URL: the tests read a local archive, never the
        # branch head.
        scraper = Scraper(url="https://codeload.github.com/RetroPie/RetroPie-Setup/tar.gz/" + "0" * 40)
        scraper.module_ids(self._archive(modules))
        return scraper

    def test_a_package_is_read_from_the_id_its_script_declares(self):
        scraper = self._scraper(
            {
                "scriptmodules/libretrocores/lr-mgba.sh": 'rp_module_id="lr-mgba"\n',
                "scriptmodules/emulators/openmsx.sh": 'rp_module_id="openmsx"\n',
            }
        )
        self.assertEqual(scraper.module_ids(), ["lr-mgba", "openmsx"])

    def test_a_script_outside_the_package_directories_is_not_a_package(self):
        """Setup helpers, themes and drivers carry no core."""
        scraper = self._scraper(
            {
                "scriptmodules/libretrocores/lr-mgba.sh": 'rp_module_id="lr-mgba"\n',
                "scriptmodules/supplementary/autostart.sh": (
                    'rp_module_id="autostart"\n'
                ),
                "scriptmodules/admin/setup.sh": 'rp_module_id="setup"\n',
            }
        )
        self.assertEqual(scraper.module_ids(), ["lr-mgba"])

    def test_the_core_list_drops_the_libretro_prefix(self):
        scraper = self._scraper(
            {
                "retropie_packages.sh": '__version="4.8.12"\n',
                "scriptmodules/libretrocores/lr-mgba.sh": 'rp_module_id="lr-mgba"\n',
                "scriptmodules/emulators/openmsx.sh": 'rp_module_id="openmsx"\n',
            }
        )
        config = scraper.generate_platform_yaml()
        self.assertEqual(config["cores"], ["mgba", "openmsx"])
        self.assertEqual(config["inherits"], "retroarch")
        self.assertEqual(config["base_destination"], "BIOS")

    def test_a_libretro_package_takes_the_buildbot_core_name(self):
        """lr-dosbox-pure builds dosbox_pure. Kept hyphenated, it matched
        DOSBox Pure Unleashed, a standalone build RetroPie does not ship,
        while the target scraper wrote dosbox_pure."""
        from scraper.targets.retropie_targets_scraper import core_name as target_name

        scraper = self._scraper(
            {
                "retropie_packages.sh": '__version="4.8.12"\n',
                "scriptmodules/libretrocores/lr-dosbox-pure.sh": (
                    'rp_module_id="lr-dosbox-pure"\n'
                ),
                "scriptmodules/emulators/dosbox-staging.sh": (
                    'rp_module_id="dosbox-staging"\n'
                ),
            }
        )
        cores = scraper.generate_platform_yaml()["cores"]
        self.assertEqual(cores, ["dosbox-staging", "dosbox_pure"])
        self.assertEqual(
            sorted(target_name(m) for m in scraper.module_ids()), cores
        )

    def test_a_package_built_outside_libretro_runs_standalone(self):
        """hatari ships as lr-hatari and as hatari: both layouts are read."""
        scraper = self._scraper(
            {
                "retropie_packages.sh": '__version="4.8.12"\n',
                "scriptmodules/libretrocores/lr-hatari.sh": 'rp_module_id="lr-hatari"\n',
                "scriptmodules/libretrocores/lr-mgba.sh": 'rp_module_id="lr-mgba"\n',
                "scriptmodules/emulators/hatari.sh": 'rp_module_id="hatari"\n',
                "scriptmodules/emulators/openmsx.sh": 'rp_module_id="openmsx"\n',
                "scriptmodules/emulators/retroarch.sh": 'rp_module_id="retroarch"\n',
            }
        )
        config = scraper.generate_platform_yaml()
        self.assertEqual(config["standalone_cores"], ["hatari", "openmsx"])
        self.assertEqual(config["dual_mode_cores"], ["hatari"])

    def test_the_version_is_the_one_the_setup_script_declares(self):
        scraper = self._scraper(
            {
                "retropie_packages.sh": '#!/bin/bash\n__version="4.8.12"\n',
                "scriptmodules/libretrocores/lr-mgba.sh": 'rp_module_id="lr-mgba"\n',
            }
        )
        self.assertEqual(scraper.generate_platform_yaml()["version"], "4.8.12")

    def test_a_version_assigned_elsewhere_is_not_the_setup_version(self):
        """Only the top-level retropie_packages.sh speaks for the release."""
        scraper = self._scraper(
            {
                "scriptmodules/emulators/openmsx.sh": (
                    'rp_module_id="openmsx"\n__version="1.0"\n'
                ),
            }
        )
        with self.assertRaises(ValueError):
            scraper.generate_platform_yaml()

    def test_no_requirement_is_invented_from_prose(self):
        """RetroPie names BIOS in prose, without a hash to transcribe."""
        scraper = self._scraper(
            {
                "scriptmodules/libretrocores/lr-mgba.sh": (
                    'rp_module_id="lr-mgba"\n'
                    'rp_module_help="Copy the required BIOS file gba_bios.bin'
                    ' to $biosdir"\n'
                ),
            }
        )
        self.assertEqual(scraper.fetch_requirements(), [])


class RecalboxBuildMode(unittest.TestCase):
    """Recalbox's cores come from each system.ini of recalbox-romfs2: a
    `[core.N]` section names `emulator = "libretro"` with the core, or a
    standalone emulator. es_bios.xml only names the cores that need a BIOS,
    so read alone it left most of Recalbox's cores, mame0258 and mame0278
    among them, outside the pack."""

    SYSTEM_INI = """\
[system]
name = "mame"
fullname = "MAME"
  extra line the parser must survive.

[core.0]
package = BR2_PACKAGE_LIBRETRO_MAME0278
emulator = "libretro"
core = "mame0278"

[core.1]
emulator = "advancemame"
core = "advancemame"

[core.2.rpi4]
emulator = "libretro"
core = "mame2003_plus"
"""

    def test_libretro_cores_and_standalone_emulators(self):
        from scraper.recalbox_scraper import system_ini_cores

        cores, standalone = system_ini_cores(self.SYSTEM_INI)
        self.assertEqual(cores, {"mame0278", "advancemame", "mame2003_plus"})
        self.assertEqual(standalone, {"advancemame"})

    def test_the_registry_leaves_the_list_to_the_scraper(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        registry = yaml.safe_load((root / "platforms" / "_registry.yml").read_text())
        self.assertNotIn("cores", registry["platforms"]["recalbox"])


class RetroBatCoresFromItsES(unittest.TestCase):
    """RetroBat's YAML carried no core list: batocera-systems.json names
    BIOS files only, and a registry list copied from Batocera stood in,
    with abuse, clk or etlegacy that RetroBat never runs."""

    ES_SYSTEMS = """\
<?xml version="1.0"?>
<systemList>
  <system><name>snes</name><emulators>
    <emulator name="libretro"><cores><core>snes9x</core><core>bsnes</core></cores></emulator>
    <emulator name="bsnes" />
  </emulators></system>
  <system><name>samcoupe</name><emulators>
    <emulator name="simcoupe"><cores><core>simcoupe</core></cores></emulator>
  </emulators></system>
</systemList>
"""

    def test_libretro_cores_and_standalone_emulators(self):
        from scraper.retrobat_scraper import es_systems_cores

        cores, standalone = es_systems_cores(self.ES_SYSTEMS)
        self.assertEqual(cores, {"snes9x", "bsnes", "simcoupe"})
        self.assertEqual(standalone, {"bsnes", "simcoupe"})

    def test_the_registry_leaves_the_list_to_the_scraper(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        registry = yaml.safe_load((root / "platforms" / "_registry.yml").read_text())
        self.assertNotIn("cores", registry["platforms"]["retrobat"])
        platform = yaml.safe_load((root / "platforms" / "retrobat.yml").read_text())
        self.assertIn("snes9x", platform["cores"])


class RocknixRunsItsStandaloneEmulators(unittest.TestCase):
    """ROCKNIX declared all_libretro while it packages duckstation, dolphin,
    ppsspp and 33 other emulators standalone, and read rocknix-systems on
    the next branch under the release's version."""

    def test_package_names_reach_the_profiles(self):
        from scraper.rocknix_scraper import standalone_emulators

        self.assertEqual(
            standalone_emulators(["duckstation-sa", "hatarisa", "openbor"]),
            ["duckstation", "duckstation-sa", "hatari", "hatarisa", "openbor"],
        )

    def test_only_an_emulator_retroarch_also_runs_is_dual(self):
        """Every standalone package was declared launched both ways, so
        ARMSX2's libretro layout reached ROCKNIX, whose package.mk adds it
        as armsx2-sa only (add_emu_core ps2 armsx2 armsx2-sa true)."""
        from scraper.rocknix_scraper import dual_mode_emulators

        package_mk = (
            "  add_emu_core psx retroarch duckstation false\n"
            "  add_emu_core psx duckstation duckstation-sa true\n"
            "  add_emu_core ps2 armsx2 armsx2-sa true\n"
            "      add_emu_core atarist retroarch hatari false\n"
        )
        standalone = ["armsx2", "armsx2-sa", "duckstation", "duckstation-sa",
                      "hatari", "hatarisa"]
        self.assertEqual(
            dual_mode_emulators(standalone, package_mk),
            ["duckstation", "duckstation-sa", "hatari", "hatarisa"],
        )

    def test_the_platform_file_is_read_at_its_release(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        platform = yaml.safe_load((root / "platforms" / "rocknix.yml").read_text())
        self.assertIn(f"/distribution/{platform['version']}/", platform["source"])
        # RetroArch runs the libretro cores some device image installs, not
        # every libretro profile.
        self.assertNotIn("retroarch", platform["cores"])
        self.assertIn("beetle_psx", platform["cores"])
        registry = yaml.safe_load((root / "platforms" / "_registry.yml").read_text())
        self.assertNotIn("cores", registry["platforms"]["rocknix"])


class RetroDeckCoresAreItsComponents(unittest.TestCase):
    """The registry added clk and gsplus to RetroDECK, which ships neither
    as a component, current or archived."""

    def test_the_registry_leaves_the_list_to_the_scraper(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        registry = yaml.safe_load((root / "platforms" / "_registry.yml").read_text())
        self.assertNotIn("cores", registry["platforms"]["retrodeck"])


class RetroDeckComponentModes(unittest.TestCase):
    """Every RetroDECK component was written standalone only: Azahar, whose
    ES-DE system also loads azahar_libretro.so, never got its libretro
    files, which the core reads below its save folder."""

    # Commands as RetroDECK/ES-DE 15e1b236 writes them in
    # resources/systems/linux/es_systems.xml (n3ds at 1379-1383, psx at
    # 1843 and 1847). The commented-out DuckStation core is the fixture's own.
    ES_SYSTEMS = """\
<?xml version="1.0"?>
<systemList>
  <system><name>n3ds</name><path>%ROMPATH%/n3ds</path>
    <command label="Azahar (Standalone)">%EMULATOR_AZAHAR% %ROM%</command>
    <command label="Azahar">%EMULATOR_RETROARCH% -L %CORE_RETROARCH%/azahar_libretro.so %ROM%</command>
    <command label="Citra">%EMULATOR_RETROARCH% -L %CORE_RETROARCH%/citra_libretro.so %ROM%</command>
  </system>
  <system><name>psx</name><path>%ROMPATH%/psx</path>
    <command label="SwanStation">%EMULATOR_RETROARCH% -L %CORE_RETROARCH%/swanstation_libretro.so %ROM%</command>
    <!-- <command label="DuckStation">%EMULATOR_RETROARCH% -L %CORE_RETROARCH%/duckstation_libretro.so %ROM%</command> -->
    <command label="DuckStation (Legacy) (Standalone)">%EMULATOR_DUCKSTATION% -batch %ROM%</command>
  </system>
</systemList>
"""

    def _config(self) -> dict:
        from scraper import retrodeck_scraper as rd

        with tempfile.TemporaryDirectory() as tmp:
            for component in ("azahar", "duckstation", "es-de", "retroarch"):
                (Path(tmp) / component).mkdir()
                (Path(tmp) / component / "component_manifest.json").write_text(
                    json.dumps({component: {"system": component}})
                )
            scraper = rd.Scraper(manifests_dir=tmp)
            systems = rd.es_systems_libretro_systems(self.ES_SYSTEMS)
            with mock.patch.object(rd, "fetch_github_latest_version", return_value="0.10.10b"), \
                    mock.patch.object(rd, "extract_launchers", return_value=[]), \
                    mock.patch.object(rd.Scraper, "_fetch_libretro_systems", return_value=systems):
                return scraper.generate_platform_yaml()

    def test_a_component_es_de_also_runs_as_a_core_is_dual_mode(self):
        config = self._config()
        self.assertEqual(config["cores"], ["azahar", "duckstation", "retroarch"])
        self.assertEqual(config["standalone_cores"], ["azahar", "duckstation"])
        self.assertEqual(config["dual_mode_cores"], ["azahar"])

    def test_a_commented_out_core_command_offers_nothing(self):
        """duckstation_libretro.so sits in a comment: DuckStation runs standalone only."""
        config = self._config()
        self.assertNotIn("duckstation", config["dual_mode_cores"])
        self.assertNotIn("duckstation", config["libretro_systems"])

    def test_a_core_without_a_component_is_not_a_component(self):
        """citra_libretro.so runs through RetroArch, and RetroDECK ships no citra build."""
        from scraper.retrodeck_scraper import component_modes

        standalone, dual = component_modes(
            ["azahar", "retroarch"], {"azahar": ["n3ds"], "citra": ["n3ds"]}
        )
        self.assertEqual((standalone, dual), (["azahar"], ["azahar"]))

    def test_the_platform_file_carries_the_modes(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        platform = yaml.safe_load((root / "platforms" / "retrodeck.yml").read_text())
        dual = set(platform.get("dual_mode_cores") or [])
        self.assertIn("azahar", dual)
        self.assertLessEqual(dual, set(platform["standalone_cores"]))
        self.assertLessEqual(dual, set(platform["libretro_systems"]))


class BizHawkRunsAresForN64Only(unittest.TestCase):
    """BizHawk embeds ares as Ares64, its N64 core. Mapping it to the ares
    profile claimed thirty systems and accused FirmwareDatabase.cs of a
    wrong MSX.rom it never declared for ares."""

    def test_ares_is_not_a_bizhawk_core(self):
        import yaml

        root = Path(__file__).resolve().parents[1]
        platform = yaml.safe_load((root / "platforms" / "bizhawk.yml").read_text())
        registry = yaml.safe_load((root / "platforms" / "_registry.yml").read_text())
        self.assertNotIn("ares", platform["cores"])
        self.assertNotIn("ares", registry["platforms"]["bizhawk"]["cores"])

    def test_no_profile_speaks_for_emuhawk(self):
        """EmuHawk finds firmware by SHA1 in its own database. Cores listed
        for overlapping systems shipped 400 files it never reads (Clock
        Signal, O2EM, FBNeo, VICE)."""
        import yaml

        root = Path(__file__).resolve().parents[1]
        platform = yaml.safe_load((root / "platforms" / "bizhawk.yml").read_text())
        registry = yaml.safe_load((root / "platforms" / "_registry.yml").read_text())
        self.assertEqual(platform["cores"], [])
        self.assertEqual(registry["platforms"]["bizhawk"]["cores"], [])


class EveryTargetCoreReachesAProfile(unittest.TestCase):
    """A target lists cores by their buildbot or package name. A name no
    profile's cores: claims makes --target drop that core and its systems
    without a word. Only check_freshness compared them, on a fresh scrape."""

    # RetroPie's packages that no profile describes yet, counted down, never up.
    RETROPIE_UNPROFILED = 53

    def test_the_committed_targets_resolve(self):
        import glob
        import os

        import yaml

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        import check_freshness
        from common import load_emulator_profiles

        root = Path(__file__).resolve().parents[1]
        index = check_freshness.profile_name_index(
            load_emulator_profiles(str(root / "emulators"))
        )
        overrides = yaml.safe_load((root / "platforms/targets/_overrides.yml").read_text()) or {}
        for path in sorted(glob.glob(str(root / "platforms/targets/*.yml"))):
            platform = os.path.basename(path)[:-4]
            if platform.startswith("_"):
                continue
            unresolved = check_freshness.unresolved_target_cores(
                yaml.safe_load(Path(path).read_text()), index,
                check_freshness._platform_overrides(overrides, platform),
            )
            with self.subTest(platform=platform):
                if platform == "retropie":
                    self.assertLessEqual(len(unresolved), self.RETROPIE_UNPROFILED)
                else:
                    self.assertEqual(unresolved, {})


class UnreadableReleaseStopsTheScrape(unittest.TestCase):
    """A failed tag lookup fell back to master, or to an empty or invented
    version. BizHawk, RomM, Batocera and Recalbox then wrote a YAML read from
    master under the previous release's version (Recalbox under "10.0"), and
    the exporter patched a revision the data never described."""

    @staticmethod
    def _refuse(*_args, **_kwargs):
        raise urllib.error.HTTPError("https://api.github.com/x", 403, "rate limited", {}, None)

    # Read at a release tag: the pin is the tag, not a branch commit.
    TAG_PINNED = {"amberelec", "batocera", "bizhawk", "emuelec", "knulli", "recalbox",
                  "rocknix", "romm"}

    @staticmethod
    def _registry_scrapers() -> list[str]:
        """Every platform scraper the registry names: a hand-written list
        left rocknix, retrodeck, minui, nextui and myminui unchecked."""
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        return sorted({entry["scraper"] for entry in registry["platforms"].values()
                       if entry.get("scraper")})

    def test_the_tag_pinned_scrapers_are_registered(self):
        self.assertLessEqual(self.TAG_PINNED, set(self._registry_scrapers()))

    def test_every_pinned_scraper_raises(self):
        for scraper in self._registry_scrapers():
            name = f"scraper.{scraper}_scraper"
            module = importlib.import_module(name)
            with self.subTest(scraper=name), mock.patch(
                "urllib.request.urlopen", self._refuse
            ), self.assertRaises(RuntimeError):
                module.Scraper()

    def test_a_branch_read_records_its_commit(self):
        """System.dat, batocera-systems.json, checkBIOS.sh, the BiosDB and the
        RetroPie scriptmodules are read from a branch. The YAML named the
        branch, so the exporter patched whatever it had become since."""
        sha = "0123456789abcdef0123456789abcdef01234567"

        class Answer(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

        def answer(request, timeout=None):
            return Answer(json.dumps({"sha": sha}).encode())

        branch_read = [s for s in self._registry_scrapers() if s not in self.TAG_PINNED]
        self.assertGreater(len(branch_read), 8)
        for scraper in branch_read:
            name = f"scraper.{scraper}_scraper"
            module = importlib.import_module(name)
            with self.subTest(scraper=name), mock.patch("urllib.request.urlopen", answer):
                instance = module.Scraper()
                # RetroDECK reads a tree of manifests and keeps the commit apart.
                recorded = getattr(instance, "revision", "") or instance.url
                self.assertRegex(recorded, f"(^|/){sha}(/|$)")

    def test_the_export_reads_the_recorded_tarball(self):
        from export_native import _tarball_at

        branch = "https://codeload.github.com/RetroPie/RetroPie-Setup/tar.gz/refs/heads/master"
        pinned = "https://codeload.github.com/RetroPie/RetroPie-Setup/tar.gz/" + "a" * 40
        self.assertEqual(_tarball_at(branch, pinned), pinned)
        other = "https://codeload.github.com/Other/Repo/tar.gz/" + "b" * 40
        self.assertEqual(_tarball_at(branch, other), "")

    def test_the_export_reads_every_component_at_the_recorded_tree(self):
        from export_native import pinned_base

        sha = "c" * 40
        base = pinned_base(
            {"pcsx2/component_manifest.json": "unused"},
            {"source": f"https://github.com/RetroDECK/components/tree/{sha}"},
        )
        self.assertEqual(base, f"https://raw.githubusercontent.com/RetroDECK/components/{sha}/")

    def test_a_release_lookup_raises(self):
        with mock.patch("urllib.request.urlopen", self._refuse), self.assertRaises(
            RuntimeError
        ):
            fetch_github_latest_version("libretro/RetroArch")

    def test_the_token_is_sent(self):
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "t0k"}):
            self.assertEqual(github_headers()["Authorization"], "Bearer t0k")

    def test_emudeck_cores_raise(self):
        """EmuDeck wrote cores: [] when the GitHub listing was refused."""
        with mock.patch("urllib.request.urlopen", self._refuse), self.assertRaises(
            RuntimeError
        ):
            emudeck_scraper.Scraper(checkbios_url="pinned")._fetch_installed_emulators("0" * 40)

    def test_libretro_core_metadata_raises(self):
        """libretro dropped every system name and manufacturer when the
        core-info listing was refused."""
        with mock.patch("urllib.request.urlopen", self._refuse), self.assertRaises(
            RuntimeError
        ):
            libretro_scraper.Scraper()._fetch_core_metadata()

    def test_a_core_info_file_the_forge_refuses_raises(self):
        """Read as empty, the core left the result and --compare-db counted
        none of its firmware missing."""
        from scraper import coreinfo_scraper  # noqa: PLC0415

        scraper = coreinfo_scraper.Scraper()
        with mock.patch.object(
            scraper, "_fetch_info_list", return_value=["mednafen_psx_libretro.info"]
        ), mock.patch("urllib.request.urlopen", self._refuse), self.assertRaises(
            ConnectionError
        ):
            scraper.fetch_requirements()



class EveryGitHubApiCallerSendsTheToken(unittest.TestCase):
    """romset_dat_importer and coreinfo_scraper called api.github.com with no
    token: past the anonymous quota, --fetch failed with 403 while
    refresh_stale had put a token in their environment."""

    def test_each_module_naming_the_api_reads_the_token(self):
        # download.sh is download.py's twin and called the API bare.
        scripts = Path(__file__).resolve().parent.parent / "scripts"
        silent = sorted(
            str(path.relative_to(scripts))
            for path in [*scripts.rglob("*.py"), *scripts.rglob("*.sh")]
            if "api.github.com" in (source := path.read_text(encoding="utf-8"))
            # arcade_parent_importer names API URLs and sends them through
            # romset_dat_importer._api_json, which holds the token.
            and ("Request(" in source or "urlopen(" in source or path.suffix == ".sh")
            and "GITHUB_TOKEN" not in source
            and "github_headers(" not in source
            and "github_token(" not in source
        )
        self.assertEqual(silent, [])

    def test_each_function_building_an_api_request_reads_the_token(self):
        """Per module, one call of github_headers anywhere covered them all:
        fetch_github_latest_tag sent no token beside a helper that did."""
        import ast  # noqa: PLC0415

        scripts = Path(__file__).resolve().parent.parent / "scripts"
        silent = []
        for path in sorted(scripts.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            for node in ast.walk(ast.parse(source)):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                body = ast.get_source_segment(source, node) or ""
                requests = any(
                    isinstance(call, ast.Call)
                    and getattr(call.func, "attr", getattr(call.func, "id", ""))
                    in ("Request", "urlopen")
                    for call in ast.walk(node)
                )
                if (
                    requests
                    and "api.github.com" in body
                    and "github_headers(" not in body
                    and "github_token(" not in body
                    and "GITHUB_TOKEN" not in body
                ):
                    silent.append(f"{path.relative_to(scripts)}:{node.name}")
        self.assertEqual(silent, [])

    def test_the_tag_helper_sends_the_token_and_raises(self):
        from scraper import base_scraper  # noqa: PLC0415

        seen = {}

        def answer(request, timeout=None):
            seen.update(request.headers)
            raise urllib.error.HTTPError(request.full_url, 403, "rate limited", {}, None)

        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "t0k"}), mock.patch(
            "urllib.request.urlopen", answer
        ), self.assertRaises(RuntimeError):
            base_scraper.fetch_github_latest_tag("o/r")
        self.assertEqual(seen.get("Authorization"), "Bearer t0k")


_IMPORT_WITHOUT_NETWORK = """
import importlib, socket, sys
from pathlib import Path
root, package = Path(sys.argv[1]), sys.argv[2]
sys.path[:0] = [str(root), str(root / "scripts")]
attempts = []
def refuse(*_args, **_kwargs):
    attempts.append(1)
    raise OSError("network refused at import")
socket.socket.connect = refuse
socket.create_connection = refuse
socket.getaddrinfo = refuse
for path in sorted((root / package.replace(".", "/")).rglob("*.py")):
    if path.name == "__init__.py":
        continue
    name = ".".join(path.relative_to(root).with_suffix("").parts)
    before = len(attempts)
    try:
        importlib.import_module(name)
    except Exception as exc:
        print(f"{name}: {type(exc).__name__}: {exc}")
        continue
    # A fetch whose error the module swallows ("or 'master'") still tried.
    if len(attempts) > before:
        print(f"{name}: reached for the network")
"""


class ImportingAScraperFetchesNothing(unittest.TestCase):
    """A tag resolved at module load made a refused API call fall back to
    master before any scraper ran. The rule since is no network at import.
    Each module is imported in a fresh interpreter with sockets refused, so
    nothing already cached hides an import-time fetch."""

    @staticmethod
    def _offenders(root: Path, package: str) -> str:
        return subprocess.run(
            [sys.executable, "-I", "-c", _IMPORT_WITHOUT_NETWORK, str(root), package],
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        ).stdout.strip()

    def test_every_scraper_imports_offline(self):
        self.assertEqual(self._offenders(REPO_ROOT, "scripts.scraper"), "")

    def test_a_swallowed_import_time_fetch_is_caught(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as directory:
            package = Path(directory) / "planted"
            package.mkdir()
            (package / "__init__.py").write_text("")
            (package / "quiet_scraper.py").write_text(
                "import urllib.request\n"
                "def _tag():\n"
                "    try:\n"
                "        return urllib.request.urlopen('https://api.github.com/x').read()\n"
                "    except OSError:\n"
                "        return None\n"
                "TAG = _tag() or 'master'\n"
            )
            self.assertIn(
                "planted.quiet_scraper: reached for the network",
                self._offenders(Path(directory), "planted"),
            )

    def test_an_import_time_fetch_is_caught(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as directory:
            package = Path(directory) / "planted"
            package.mkdir()
            (package / "__init__.py").write_text("")
            (package / "eager_scraper.py").write_text(
                "import urllib.request\n"
                "urllib.request.urlopen('https://api.github.com/repos/o/r/tags')\n"
            )
            self.assertIn(
                "planted.eager_scraper", self._offenders(Path(directory), "planted")
            )


class OneNativeIdOneSystem(unittest.TestCase):
    """RetroDECK filed coco as tandy-coco and Batocera as coco: xroar's 28
    CoCo and Dragon ROMs reached no RetroDECK system, and --system left
    them out of the pack and the installer alike."""

    # A folder each platform fills with something else, not a system name:
    # EmuDeck checks the Neo Geo BIOS there, RetroDECK keeps arcade sets.
    # Several platforms file the PC Engine CD under the HuCard system, the
    # native_system of each entry keeping the platform's own grouping.
    FOLDS = {"fbneo", "pcenginecd"}

    def test_scrapers_agree_on_every_shared_native_id(self):
        from common import _norm_system_id  # noqa: PLC0415

        seen: dict[str, dict[str, str]] = {}
        for path in sorted((REPO_ROOT / "scripts" / "scraper").glob("*_scraper.py")):
            if "SYSTEM_SLUG_MAP" not in path.read_text():
                continue
            module = importlib.import_module(f"scraper.{path.stem}")
            for native, slug in getattr(module, "SYSTEM_SLUG_MAP", {}).items():
                slug = slug[0] if isinstance(slug, tuple) else slug
                if isinstance(slug, str):
                    seen.setdefault(native.lower(), {})[path.stem] = slug
        split = {
            native: by for native, by in seen.items()
            if native not in self.FOLDS and len({_norm_system_id(s) for s in by.values()}) > 1
        }
        self.assertEqual(split, {})

    def test_retrobat_files_its_systems_as_batocera_does(self):
        """RetroBat kept psx, nds and atari800: no profile system met them,
        so no core extra joined them and --system found nothing."""
        import yaml  # noqa: PLC0415

        from scraper import batocera_scraper, retrobat_scraper  # noqa: PLC0415

        for native, slug in batocera_scraper.SYSTEM_SLUG_MAP.items():
            self.assertEqual(retrobat_scraper.SYSTEM_SLUG_MAP[native], slug)
        data = yaml.safe_load((REPO_ROOT / "platforms" / "retrobat.yml").read_text())
        self.assertTrue({"sony-playstation", "nintendo-ds"} <= set(data["systems"]))
        self.assertFalse({"psx", "nds", "atari800"} & set(data["systems"]))

    # A platform system no profile names gets no core extra and answers no
    # --system. Named here: Batocera's family folds Naomi and Atomiswave into
    # one system the profiles keep apart, and MiSTer cores nothing profiles.
    # EmuELEC lists Duke Nukem 2's data for RigelEngine, which no profile
    # describes yet.
    UNMATCHED = {
        "*": {"sega-dreamcast-arcade"},
        "emuelec": {"RigelEngine"},
        "misterfpga": {"gameking", "interact", "marty", "studio-ii", "superacan",
                       "videobrain"},
    }

    def test_every_platform_system_meets_a_profile_system(self):
        import yaml  # noqa: PLC0415

        from common import (  # noqa: PLC0415
            _norm_system_id,
            load_emulator_profiles,
            load_platform_config,
        )

        known = set()
        for profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).values():
            known |= {_norm_system_id(s) for s in profile.get("systems") or []}
            known |= {_norm_system_id(f["system"]) for f in profile.get("files") or []
                      if isinstance(f, dict) and f.get("system")}
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        for name in registry["platforms"]:
            with self.subTest(platform=name):
                config = load_platform_config(name, str(REPO_ROOT / "platforms"))
                allowed = self.UNMATCHED["*"] | self.UNMATCHED.get(name, set())
                stray = {s for s in config.get("systems", {})
                         if _norm_system_id(s) not in known} - allowed
                self.assertEqual(stray, set())

    def test_xroar_machines_reach_the_platforms_that_run_it(self):
        import yaml  # noqa: PLC0415

        from common import _norm_system_id  # noqa: PLC0415

        xroar = yaml.safe_load((REPO_ROOT / "emulators" / "xroar.yml").read_text())
        machines = {_norm_system_id(s) for s in xroar["systems"]}
        for platform, wanted in (("retrodeck", {"coco", "dragon64"}),
                                 ("recalbox", {"coco", "dragon64"}),
                                 ("misterfpga", {"coco3"})):
            with self.subTest(platform=platform):
                data = yaml.safe_load((REPO_ROOT / "platforms" / f"{platform}.yml").read_text())
                ids = {_norm_system_id(s) for s in data["systems"]}
                self.assertEqual(wanted & ids & machines, wanted)


class HashScraperRefusesAnEmptyRead(unittest.TestCase):
    """A source tree that yields no BIOS set is never cached as a result.

    Cached, it was served for a day: every profile entry came out "out of
    scope", nothing was refreshed and pipeline steps 2a and 2a2 said OK.
    """

    def _fresh(self, sets: dict) -> dict:
        from datetime import datetime, timezone  # noqa: PLC0415

        return {"fetched_at": datetime.now(timezone.utc).isoformat(),
                "commit": "abc", "bios_sets": sets}

    def test_mame_raises_and_writes_no_cache(self):
        from scraper import mame_hash_scraper as m  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "mame-hashes.json"
            with mock.patch.object(m, "_CACHE_PATH", cache), \
                    mock.patch.object(m, "_get_release_tag", return_value="mame0289"), \
                    mock.patch.object(m, "_sparse_clone"), \
                    mock.patch.object(m, "_cleanup"), \
                    mock.patch.object(m, "_get_commit", return_value="abc"), \
                    mock.patch.object(m, "parse_mame_source_tree", return_value={}):
                with self.assertRaises(RuntimeError):
                    m._fetch_hashes(force=True)
            self.assertFalse(cache.exists())

    def test_mame_does_not_serve_an_empty_cache(self):
        from scraper import mame_hash_scraper as m  # noqa: PLC0415

        self.assertTrue(m._is_stale(self._fresh({})))
        self.assertFalse(m._is_stale(self._fresh({"neogeo": {}})))

    def test_fbneo_raises_and_writes_no_cache(self):
        from scraper import fbneo_hash_scraper as f  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "fbneo-hashes.json"
            with mock.patch.object(f, "CACHE_PATH", cache), \
                    mock.patch.object(f, "_sparse_clone"), \
                    mock.patch.object(f, "_cleanup"), \
                    mock.patch.object(f, "_extract_version", return_value=("v1.0.0.03", "abc")), \
                    mock.patch.object(f, "parse_fbneo_source_tree", return_value={}):
                with self.assertRaises(RuntimeError):
                    f.fetch_and_cache(force=True)
            self.assertFalse(cache.exists())

    def test_fbneo_does_not_serve_an_empty_cache(self):
        from scraper import fbneo_hash_scraper as f  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "fbneo-hashes.json"
            with mock.patch.object(f, "CACHE_PATH", cache):
                cache.write_text(json.dumps(self._fresh({})))
                self.assertFalse(f._is_cache_fresh())
                cache.write_text(json.dumps(self._fresh({"neogeo": {}})))
                self.assertTrue(f._is_cache_fresh())



class EmptyScrapeWritesNothing(unittest.TestCase):
    """An upstream that changed shape parses to nothing: the run fails and
    the committed platform file stays as it was."""

    def _run(self, scraper_class, output: Path) -> int:
        from scraper.base_scraper import scraper_cli  # noqa: PLC0415

        argv = ["scraper", "-o", str(output)]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            try:
                scraper_cli(scraper_class)
            except SystemExit as exc:
                return int(exc.code or 0)
        return 0

    def test_no_requirement_exits_non_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "platform.yml"
            output.write_text("systems:\n  a:\n    files:\n    - name: x\n")
            self.assertEqual(self._run(_StubScraper, output), 1)
            self.assertIn("name: x", output.read_text())

    def test_a_generated_file_without_files_exits_non_zero(self):
        class NoSystems(_StubScraper):
            def __init__(self):
                super().__init__([BiosRequirement(name="a.bin", system="s")])

            def generate_platform_yaml(self) -> dict:
                return {"platform": "x", "systems": {}}

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "platform.yml"
            self.assertEqual(self._run(NoSystems, output), 1)
            self.assertFalse(output.exists())

    def test_a_platform_that_inherits_its_files_may_list_none(self):
        class CoresOnly(_StubScraper):
            lists_files = False

            def generate_platform_yaml(self) -> dict:
                return {"inherits": "retroarch", "cores": ["mgba"]}

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "platform.yml"
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(self._run(CoresOnly, output), 0)
            self.assertIn("mgba", output.read_text())

    def test_retropie_without_a_package_raises(self):
        archive = RetroPiePackageList._archive(
            {"scriptmodules/supplementary/autostart.sh": 'rp_module_id="autostart"\n'}
        )
        from scraper.retropie_scraper import Scraper  # noqa: PLC0415

        scraper = Scraper(url="https://codeload.github.com/RetroPie/RetroPie-Setup/tar.gz/" + "0" * 40)
        with self.assertRaises(ValueError):
            scraper.module_ids(archive)


if __name__ == "__main__":
    unittest.main()
