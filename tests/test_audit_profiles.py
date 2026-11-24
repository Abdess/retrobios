"""Audit regressions on emulator profiles: citations, pins, found-by-content cores and bundled files."""

from __future__ import annotations

import tests
from tests.sources import script_source
import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import yaml
from tests import HAS_JSONSCHEMA, REPO_ROOT


class UnreachableCitationRegressions(unittest.TestCase):
    """A citation must name a place a declared repository can hold.

    kenji-nx carried tmp/es-de/ANDROID.md:470-474, a path from the machine
    of whoever profiled it. No revision of any declared repository holds it,
    so profile_sync could only report it missing, every pass, forever. The
    check is offline and runs on every push.
    """

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def _hits(self, text: str) -> bool:
        from schemas import citations

        return bool(citations.UNREACHABLE_REF.search(" " + text))

    def test_a_scratch_directory_is_rejected(self):
        self.assertTrue(self._hits("tmp/es-de/ANDROID.md:470-474"))

    def test_an_absolute_path_is_rejected(self):
        self.assertTrue(self._hits("/home/someone/src/a.c:12"))
        self.assertTrue(self._hits(r"C:\work\src\a.c:12"))

    def test_a_path_climbing_out_of_the_tree_is_rejected(self):
        self.assertTrue(self._hits("../outside/src/a.c:12"))

    def test_ordinary_citations_pass(self):
        for good in (
            "src/core/main.cpp:210",
            "libretro.c:5293-5337",
            "PCE.emu/src/main/Main.cc:80-91",
            "es-de ANDROID.md:470-474",
            "see tmp files for details",
        ):
            with self.subTest(citation=good):
                self.assertFalse(self._hits(good))

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_the_corpus_carries_none(self):
        from schemas import citations

        errors = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            with path.open(encoding="utf-8") as handle:
                errors.extend(
                    citations.unreachable_citations(path, yaml.safe_load(handle))
                )
        self.assertEqual(errors, [])


@unittest.skipUnless(HAS_JSONSCHEMA, "validate_schemas needs jsonschema")
class DoubledCitationPaths(unittest.TestCase):
    """primehack cited Source/Core/Core/IOS/USB/Bluetooth/ twice in a row in a
    comment: no revision holds that path, and the parsed document never
    showed it to the citation checks."""

    def _hits(self, text: str) -> bool:
        from schemas import citations

        return bool(citations.DOUBLED_PATH.search(text))

    def test_a_repeated_directory_is_rejected(self):
        self.assertTrue(self._hits(
            "# ref: Source/Core/Core/IOS/USB/Bluetooth/Source/Core/Core/IOS/USB/"
            "Bluetooth/RealtekFirmwareLoader.cpp:373-416"
        ))

    def test_a_directory_named_once_passes(self):
        for good in (
            "Source/Core/Core/IOS/USB/Bluetooth/RealtekFirmwareLoader.cpp:383",
            "src/src/main.c:10",
            "a/b/c/a/b.c:1",
        ):
            with self.subTest(citation=good):
                self.assertFalse(self._hits(good))

    def test_the_corpus_carries_none(self):
        from schemas import citations

        errors = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            errors.extend(citations.doubled_paths(path))
        self.assertEqual(errors, [])


class KidVidTapesStayWithTheContent(unittest.TestCase):
    """Stella opens its KidVid tapes by bare name (stella2014, from the
    working directory) or from its base directory (stella2023, the content
    folder, and stella, a folder under the save directory): never the system
    directory. Without load_from every Linux pack put about 68 MB of WAVs at
    the BIOS root, in two cases. The save directory is a place a pack
    reaches: stella's tapes go there, never to the BIOS tree."""

    def test_no_pack_places_them_in_the_system_directory(self):
        from scripts.model.profiles import load_emulator_profiles
        from scripts.resolve.entryscope import (
            outside_gap_scope,
            read_from_save_dir,
            read_from_system_dir,
        )

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        for name in ("stella", "stella2014", "stella2023"):
            tapes = [f for f in profiles[name]["files"]
                     if f["name"].lower().endswith(".wav")]
            with self.subTest(profile=name):
                self.assertEqual(len(tapes), 7)
                self.assertFalse(any(read_from_system_dir(f, False) for f in tapes))
                for f in tapes:
                    self.assertTrue(
                        outside_gap_scope(f, False) or read_from_save_dir(f, False)
                    )


class GeneralUserGSReachesEveryCoreThatNamesIt(unittest.TestCase):
    """The SoundFont was held as dosbox_pure's DOSBOX.SF2 alone: dosbox-staging
    and dosbox-x, which name it GeneralUser-GS.sf2 and GeneralUser_GS.sf2,
    shipped no General MIDI bank."""

    def test_each_name_resolves_to_the_one_file(self):
        from model import profiles as model_profiles
        from resolve import localfile

        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        db = json.loads((REPO_ROOT / "database.json").read_text())
        profiles = model_profiles.load_emulator_profiles(str(REPO_ROOT / "emulators"))
        held = "bios/Other/GeneralUser GS/GeneralUser-GS.sf2"
        for emulator, name in (("dosbox_pure", "DOSBOX.SF2"),
                               ("dosbox-staging", "GeneralUser-GS.sf2"),
                               ("dosbox-x", "GeneralUser_GS.sf2")):
            with self.subTest(emulator=emulator):
                entry = next(f for f in profiles[emulator]["files"] if f["name"] == name)
                path, _status = localfile.resolve_local_file(
                    {**entry, "source_profile": emulator}, db, dest_hint=entry.get("path", ""))
                self.assertEqual(path, held)


class APlatformPinDoesNotReplaceTheCoresRevision(unittest.TestCase):
    """RetroArch pins ScummVM's kyra.dat and FBNeo's hiscore.dat at older
    revisions. Collected as variants with profiles that claimed no content,
    the platform's md5 became the only proof and the pack shipped the old
    files to cores built against newer ones."""

    def test_the_profile_revision_serves_the_core(self):
        from model import profiles as model_profiles
        from resolve import localfile

        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        db = json.loads((REPO_ROOT / "database.json").read_text())
        profiles = model_profiles.load_emulator_profiles(str(REPO_ROOT / "emulators"))
        for emulator, name, pinned in (("scummvm", "kyra.dat", "21a57f79886e46f410cfb50186ed8d77"),
                                       ("fbneo", "hiscore.dat", "37fc4e050b53a1ef2c2e7f3042553025")):
            with self.subTest(emulator=emulator):
                entry = next(f for f in profiles[emulator]["files"] if f["name"] == name)
                self.assertTrue(entry.get("sha1"), "the profile claims its revision")
                self.assertIn(pinned, db["indexes"]["by_md5"], "the platform's pin is held")
                path, status = localfile.resolve_local_file(
                    {**entry, "source_profile": emulator}, db, dest_hint=entry["path"])
                self.assertEqual(status, "sha1_exact")
                self.assertEqual(db["files"][entry["sha1"]]["path"], path)


class ProseCitationsUseTheTrackedForm(unittest.TestCase):
    """profile_sync tracks `path:line` citations only. `libretro.c
    I_FindFile, line 1742` escaped it, and sixteen such citations in six
    profiles stayed behind when their pins moved, four already pointing at
    other code."""

    UNTRACKED = re.compile(
        r"[\w./+-]+\.(?:c|cc|cpp|cxx|h|hh|hpp|inc|cs|py|rs|go|java|kt|js|ts"
        r"|m|mm|s|asm|lua|sh)\b[^\n:]{0,80}?\blines? \d+"
    )

    def test_the_pattern_reads_the_old_forms(self):
        for text in ("libretro.c I_FindFile, line 1742",
                     "memory.c LoadBios() line 1353",
                     "libretro_core_options.h lines 52-64"):
            self.assertRegex(text, self.UNTRACKED)
        self.assertNotRegex("I_FindFile, libretro/libretro.c:4176-4252", self.UNTRACKED)

    def test_no_profile_writes_a_line_number_profile_sync_cannot_see(self):
        found = [
            f"{path.name}:{number}: {match.group(0)}"
            for path in sorted((REPO_ROOT / "emulators").glob("*.yml"))
            for number, line in enumerate(path.read_text().splitlines(), 1)
            for match in self.UNTRACKED.finditer(line)
        ]
        self.assertEqual(found, [])


class ACitationInsideASourceRefIsTracked(unittest.TestCase):
    """split_source_ref reads each chunk's located head and drops the rest.
    zesarux cited src/cpu.h:545 inside an annotation, four lines off at its
    pin, and pce-emu joined two citations with ` + `: neither was anchored."""

    def citations(self, ref: str) -> list[tuple[str, str]]:
        from scripts.profiling.citations import collect_citations

        document = {"files": [{"name": "x.rom", "source_ref": ref}]}
        return [(c.kind, c.ref) for c in collect_citations(document)]

    def test_an_annotation_citation_is_read_as_prose(self):
        found = self.citations(
            "src/cpu.c:3381-3383, src/utils.c:4100 "
            "(MACHINE_IS_SPECTRUM_128_P2 covers Pentagon, src/cpu.h:549)"
        )
        self.assertIn(("prose", "src/cpu.h:549"), found)
        self.assertNotIn(("prose", "src/cpu.c:3381-3383"), found)

    def test_a_joined_citation_is_read_as_prose(self):
        found = self.citations(
            "src/pce_fast/pce.cpp:477-483 + src/pce_fast/huc.cpp:284-304"
        )
        self.assertIn(("prose", "src/pce_fast/huc.cpp:284-304"), found)
        self.assertEqual([c for c in found if c[0] == "prose"],
                         [("prose", "src/pce_fast/huc.cpp:284-304")])

    def test_offsets_match_the_scalar(self):
        from scripts.model.sourceref import ref_prose_text

        ref = "a.c:1-2, 5 (see b.c:7)"
        masked = ref_prose_text(ref)
        self.assertEqual(len(masked), len(ref))
        self.assertEqual(masked.index("b.c:7"), ref.index("b.c:7"))
        self.assertNotIn("a.c", masked)


class OpenMsxRomsSitInItsSystemroms(unittest.TestCase):
    """openMSX entries had no path and landed at the BIOS root, where no
    frontend points FilePool. The profile writes share/systemroms below
    openMSX's user folder, the pool's first place (src/file/FilePool.cc,
    FileOperations.cc), and RetroBat, which sets OPENMSX_HOME to
    bios/openmsx and declares its ROMs under openMSX/share/systemroms, gets
    them there."""

    def test_every_entry_is_under_share_systemroms(self):
        from scripts.model.profiles import load_emulator_profiles
        from scripts.model.platforms import load_platform_config
        from scripts.resolve.standalone import platform_layouts, platform_launches

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        profile = profiles["openmsx"]
        retrobat = yaml.safe_load((REPO_ROOT / "platforms" / "retrobat.yml").read_text())
        declared_dirs = {
            fe["destination"].rsplit("/", 1)[0].lower()
            for system in retrobat["systems"].values()
            for fe in system.get("files", [])
            if "systemroms" in fe.get("destination", "")
        }
        self.assertEqual(declared_dirs, {"openmsx/share/systemroms"})
        config = load_platform_config("retrobat", str(REPO_ROOT / "platforms"))
        ((view, _standalone),) = platform_layouts("openmsx", profile, platform_launches(config, profiles))
        placed = {f["name"]: f for f in view["files"]}
        for entry in profile["files"]:
            with self.subTest(name=entry["name"]):
                self.assertEqual(entry.get("path", "").lower(),
                                 f"share/systemroms/{entry['name']}".lower())
                self.assertEqual(placed[entry["name"]].get("standalone_path", "").lower(),
                                 f"openmsx/share/systemroms/{entry['name']}".lower())


class EmuDeckRunsItsEmulatorsStandalone(unittest.TestCase):
    """EmuDeck declared no standalone_cores: Dolphin, Cemu, xemu, ARMSX2 and
    Supermodel, installed as apps by EmuScripts, got the libretro layout and
    lost their standalone-only files."""

    def test_every_emuscripts_emulator_is_standalone(self):
        from scripts.model.platforms import load_platform_config
        from scripts.resolve.launches import PlatformLaunches
        from scripts.model.profiles import load_emulator_profiles

        config = load_platform_config("emudeck", str(REPO_ROOT / "platforms"))
        self.assertEqual(
            sorted(config["standalone_cores"]),
            sorted(c for c in config["cores"] if c != "retroarch"),
        )
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        standalone = PlatformLaunches(standalone=frozenset(config["standalone_cores"]))
        for name in ("dolphin", "cemu", "armsx2", "supermodel"):
            with self.subTest(emulator=name):
                self.assertTrue(standalone.runs_standalone(name, profiles[name]))

    def test_retroarch_brings_its_libretro_cores(self):
        """The scraper dropped RetroArch's own script: np2kai, neocd and
        every core EmuDeck installs through RetroArch got no file that
        checkBIOS.sh does not name."""
        from scripts.model.profiles import load_emulator_profiles
        from scripts.model.platforms import load_platform_config
        from scripts.resolve.cores import resolve_platform_cores

        config = load_platform_config("emudeck", str(REPO_ROOT / "platforms"))
        self.assertIn("retroarch", config["cores"])
        cores = resolve_platform_cores(config, load_emulator_profiles(str(REPO_ROOT / "emulators")))
        for name in ("np2kai", "neocd", "dolphin"):
            with self.subTest(core=name):
                self.assertIn(name, cores)


class BundledFilesAreNotToSource(unittest.TestCase):
    """DaedalusX64's n64.psh, the shader library its renderer installs
    beside the binary, was reported as a required core file missing and
    listed among the files to source, with 19 more like it."""

    def test_verify_does_not_count_it_missing(self):
        from packs import verifysummary
        from packs import shares as packs_shares

        entry = {"name": "n64.psh", "required": True, "in_repo": False,
                 "category": "bios", "in_pack": True, "bundled": True}
        self.assertEqual(packs_shares.core_required_missing([entry]), [])
        summary = verifysummary.overall_summary(
            [({"severity_counts": {}, "undeclared_files": [entry]}, ["ROCKNIX"])]
        )
        self.assertNotIn("n64.psh", summary)

    def test_the_site_gives_it_its_own_status(self):
        from sitegen import exportrows

        rows = exportrows.gap_export_rows({}, {"daedalusx64": {
            "emulator": "DaedalusX64", "systems": ["nintendo-64"],
            "gap_details": [{"name": "n64.psh", "source": "missing", "required": True,
                             "in_repo": False, "bundled": True}],
        }})
        self.assertEqual([row["status"] for row in rows], ["bundled"])

    def test_a_held_bundled_file_is_not_packed(self):
        """A file installed with the emulator is already on the user's
        machine, so the pack leaves it out even when the collection holds it."""
        from packs import coverage as packs_coverage

        entry = {"name": "n64.psh", "required": True, "in_repo": True,
                 "emulator": "daedalusx64", "category": "bios", "bundled": True}
        with mock.patch("packs.extraresolver.unplaceable_extras", return_value={}):
            packs_coverage._mark_unplaced({}, [entry], {})
        self.assertFalse(entry["in_pack"])
        self.assertIn("installed with its emulator", entry["omitted"])

    def test_a_build_scope_keeps_it_for_the_other_build(self):
        """PPSSPP's standalone release ships assets/, its libretro core does
        not: bundled for one build, the entry still reaches a core's pack."""
        from resolve.entryscope import deliverable

        entries = [{"ref": "ppsspp-assets", "mode": "libretro"},
                   {"name": "a.bin", "bundled": True, "mode": "standalone"},
                   {"name": "b.bin", "bundled": True}]
        self.assertEqual([e.get("ref") or e["name"] for e in deliverable(entries, False)],
                         ["ppsspp-assets"])
        self.assertEqual(deliverable(entries, True), [])

    def test_a_platform_package_can_differ_both_ways(self):
        """Batocera's hcl package installs the binary alone, its blueMSX core
        package copies the machines beside the core."""
        from resolve.entryscope import installed_with_emulator

        hcl = {"name": "data.pak", "bundled": True, "not_bundled_on": ["batocera"]}
        machines = {"name": "Machines/MSX/config.ini", "installed_on": ["batocera", "retropie"]}
        self.assertTrue(installed_with_emulator(hcl, "retrobat"))
        self.assertFalse(installed_with_emulator(hcl, "batocera"))
        self.assertTrue(installed_with_emulator(machines, "retropie"))
        self.assertFalse(installed_with_emulator(machines, "retroarch"))
        self.assertTrue(installed_with_emulator(hcl))

    def test_a_view_naming_no_setup_keeps_what_one_package_leaves_out(self):
        """touchHLE panics without its fonts on ROCKNIX: the emulator page,
        the global gap report and the wanted list all still ask for them."""
        from acquire.provenance import profile_needs
        from packs.crossref import cross_reference
        from resolve.entryscope import installed_everywhere
        from sitegen.install import comes_with_app

        font = {"name": "LiberationMono-Regular.ttf", "bundled": True,
                "not_bundled_on": ["rocknix"]}
        self.assertFalse(installed_everywhere(font))
        self.assertFalse(comes_with_app(font))
        self.assertTrue(installed_everywhere({"name": "a.bin", "bundled": True}))
        profiles = {"touchhle": {"emulator": "touchHLE", "type": "standalone",
                                 "systems": ["apple-ios"], "files": [font]}}
        report = cross_reference(profiles, {}, {"files": {}, "indexes": {}})
        self.assertFalse(report["touchhle"]["gap_details"][0]["bundled"])
        sized = {**font, "size": 312132}
        needs = profile_needs({"touchhle": {"files": [sized]}}, {"files": {}, "indexes": {}})
        self.assertIn("liberationmono-regular.ttf", needs["by_name"])
        everywhere = {**sized, "not_bundled_on": []}
        needs = profile_needs({"touchhle": {"files": [everywhere]}}, {"files": {}, "indexes": {}})
        self.assertEqual(needs["by_name"], {})

    def test_every_platform_named_is_registered(self):
        from model.registry import list_registered_platforms
        from model.profiles import load_emulator_profiles

        known = set(list_registered_platforms(str(REPO_ROOT / "platforms")))
        unknown = sorted({
            (name, platform)
            for name, profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).items()
            for entry in (profile.get("files") or []) + (profile.get("data_directories") or [])
            if isinstance(entry, dict)
            for field in ("installed_on", "not_bundled_on")
            for platform in entry.get(field) or []
            if platform not in known
        })
        self.assertEqual(unknown, [])

    def test_a_tree_the_platform_installs_leaves_its_pack(self):
        """retroarch.yml names dolphin-sys and ppsspp-assets and Lakka
        inherits them, while Lakka's core packages install both trees."""
        from model.profiles import installed_data_refs_in

        profiles = {"dolphin": {
            "emulator": "Dolphin", "type": "libretro", "files": [],
            "data_directories": [{"ref": "dolphin-sys", "installed_on": ["lakka"]}]}}
        self.assertEqual(installed_data_refs_in("lakka", profiles), frozenset({"dolphin-sys"}))
        self.assertEqual(installed_data_refs_in("retroarch", profiles), frozenset())
        source = script_source("generate_pack.py")
        self.assertIn("if ref_key in installed:", source)
        self.assertIn("installed=installed_data_refs_in(plan.platform_name", source)

    def test_the_pack_builder_skips_it(self):
        source = (REPO_ROOT / "scripts" / "packs" / "extras.py").read_text(encoding="utf-8")
        self.assertIn('if u.get("bundled"):', source)


class RommRunsTheCoresItsPlayerNames(unittest.TestCase):
    """RomM's player merges a nightly core map into the stable one when netplay
    is on. Inheriting EmulatorJS's list left azahar, bsnes and
    genesis_plus_gx_wide out of the RomM pack, though RomM launches them."""

    SOURCE = """
const _EJS_CORES_MAP: Record<string, string[]> = {
  "3do": ["opera"],
  arcade: [
    "mame2003_plus",
    "fbneo",
  ],
} as const;

const _EJS_NIGHTLY_CORES_MAP: Record<string, string[]> = {
  "3ds": ["azahar"],
  snes: ["snes9x", "bsnes"],
};
"""

    def test_both_maps_are_read(self):
        from scripts.scraper.romm_scraper import parse_player_cores

        self.assertEqual(
            parse_player_cores(self.SOURCE),
            ["azahar", "bsnes", "fbneo", "mame2003_plus", "opera", "snes9x"],
        )

    def test_a_missing_map_raises(self):
        from scripts.scraper.romm_scraper import parse_player_cores

        source = self.SOURCE.replace("_EJS_NIGHTLY_CORES_MAP", "_RENAMED")
        with self.assertRaises(RuntimeError):
            parse_player_cores(source)

    def test_the_platform_file_carries_the_nightly_cores(self):
        from model.platforms import load_platform_config

        cores = set(load_platform_config("romm", str(REPO_ROOT / "platforms"))["cores"])
        self.assertTrue({"azahar", "bsnes", "genesis_plus_gx_wide"} <= cores)


class RommNeoGeoFoldersGetTheirBios(unittest.TestCase):
    """RomM runs fbneo for neogeoaes and neogeomvs as for arcade and reads
    firmware per platform folder, but the fixture gives neogeo.zip to arcade
    alone, so a Neo Geo game in its own folder started without it."""

    def test_the_mirror_is_per_file(self):
        from scripts.scraper.romm_scraper import FIRMWARE_MIRRORS, SLUG_MAP

        arcade = FIRMWARE_MIRRORS["arcade"]
        self.assertEqual(arcade["neogeoaes"], ("neogeo.zip",))
        self.assertEqual(arcade["neogeomvs"], ("neogeo.zip",))
        self.assertIn("neogeoaes", SLUG_MAP)

    def test_a_file_files_under_its_own_system_only(self):
        # Adding the Neo Geo slugs sent MAME 2003's ZN-1 BIOS and data files
        # into neogeoaes/, and FBNeo's CPS3 sets already sat in colecovision/:
        # a system the platform lacks has no folder, and a mirror-only
        # folder attracts no system-less file.
        from scripts.packs.extraplace import _slug_for

        config_systems = {"arcade", "snk-neogeo-aes", "nintendo-ds"}
        sys_to_slug = {"arcade": "arcade", "snk-neogeo-aes": "neogeoaes",
                       "nintendo-ds": "nds"}
        profiles = {"mame2003": {"systems": ["snk-neogeo-aes", "zn1-acclaim"]},
                    "melonds": {"systems": ["nintendo-ds", "nintendo-dsi"]}}
        args = (profiles, config_systems, {}, sys_to_slug, {"arcade", "nintendo-ds"})
        self.assertEqual(_slug_for({"profile": "mame2003", "system": "zn1-acclaim"}, *args), "")
        self.assertEqual(_slug_for({"profile": "mame2003"}, *args), "")
        self.assertEqual(_slug_for({"profile": "melonds", "system": "nintendo-dsi"}, *args), "")
        self.assertEqual(_slug_for({"profile": "melonds"}, *args), "nds")

    def test_the_platform_file_carries_it(self):
        text = (REPO_ROOT / "platforms" / "romm.yml").read_text(encoding="utf-8")
        self.assertIn("destination: neogeoaes/neogeo.zip", text)
        self.assertIn("destination: neogeomvs/neogeo.zip", text)
        self.assertNotIn("neogeoaes/pgm.zip", text)


class AProfilePathIsTheEmulatorsNotOurs(unittest.TestCase):
    """No guard stopped a profile `path:` naming .variants/, our storage:
    the pack would write the file where no emulator reads."""

    def test_a_variants_path_is_refused(self):
        from unittest import mock

        try:
            from schemas import sourcetree
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")

        with tempfile.TemporaryDirectory() as directory:
            emulators = Path(directory) / "emulators"
            emulators.mkdir()
            (emulators / "x.yml").write_text(
                "emulator: X\nfiles:\n  - name: scph1001.bin\n"
                "    path: .variants/scph1001.bin.abc12345\n"
            )
            with mock.patch("core.paths.REPO_ROOT", Path(directory)):
                errors = sourcetree.repository_layout_in_profiles()
        self.assertEqual(len(errors), 1)
        self.assertIn(".variants/", errors[0])


class AHashScanningCoreContradictsNoPlatform(unittest.TestCase):
    """ares finds its firmware by sha256 in a folder and opens no file by
    name, so its entries' names are labels. Labels reused from other dumps
    (MSX2.ROM, bios_CD_U.bin) put ares's revision on a path where RetroBat
    pins another: slots called RetroBat's declaration wrong, and the pack
    dropped ares's own dump behind the platform's."""

    def test_no_conflict_names_ares(self):
        import json

        from scripts.packs import slotscan
        from scripts.model.registry import list_registered_platforms
        from scripts.model.profiles import load_emulator_profiles

        root = REPO_ROOT
        if not (root / "database.json").exists():
            self.skipTest("database.json is not built")
        profiles = load_emulator_profiles(str(root / "emulators"))
        db = json.loads((root / "database.json").read_text(encoding="utf-8"))
        claimed = [
            (platform, conflict.destination)
            for platform in list_registered_platforms(str(root / "platforms"))
            for conflict in slotscan.scan_platform(platform, profiles, db, str(root / "platforms"))
            if any(claim.emulator == "ares" for claim in conflict.profile_claims)
        ]
        self.assertEqual(claimed, [])


class FsUaeKickstartIsFoundByContent(unittest.TestCase):
    """FS-UAE scans its Kickstarts directory and names a ROM by checksum
    (src/fs-uae/config.c:121-140, main.c:431-470), and with no ROM loads the
    AROS replacement (memory.cpp:2374-2379). kick13.rom and its required
    flag came from the RetroPie launcher, which the platform layer records."""

    def test_the_kickstart_is_an_optional_label(self):
        from scripts.resolve.entryscope import opens_by_name

        profile = yaml.safe_load((REPO_ROOT / "emulators" / "fs-uae.yml").read_text(encoding="utf-8"))
        entry = next(f for f in profile["files"] if f.get("sha1") == "891e9a547772fe0c6c19b610baf8bc4ea7fcb785")
        self.assertFalse(opens_by_name(entry, profile, standalone=True))
        self.assertFalse(entry.get("required"))
        self.assertNotIn("RetroPie launcher", entry.get("note", ""))


class NoProfileHashFromASecondarySource(unittest.TestCase):
    """ecwolf.yml pinned ecwolf.pk3 to an md5 its note said came from the
    .info. The code checks none, and no file shipped at the pin carries it:
    a source without a hash gives the profile none."""

    PATTERN = re.compile(
        r"(md5|sha1|crc32|hash)[^.]{0,40}\bfrom (the )?(\.info|core-?info|docs?|documentation)",
        re.IGNORECASE,
    )

    def test_no_hashed_entry_names_a_secondary_source(self):
        found = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in profile.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                if any(entry.get(k) for k in ("md5", "sha1", "crc32", "sha256")) and (
                    self.PATTERN.search(str(entry.get("note", "")))
                ):
                    found.append(f"{path.name}: {entry.get('name')}")
        self.assertEqual(found, [])


class XeniosFollowsItsReleaseBranch(unittest.TestCase):
    """The xenios pin 87b176a0 sat on `preview`, which diverged from the
    default `xenios` branch, and without source_branch profile_sync read the
    pin as orphaned. Since November 2026 the releases (2.2 to 2.3.1) come from
    `xenios` and `preview` stopped in June: the pin is release 2.3.1 on the
    default branch, so the profile names no other branch."""

    def test_the_profile_follows_the_branch_its_pin_is_on(self):
        profile = yaml.safe_load((REPO_ROOT / "emulators" / "xenios.yml").read_text(encoding="utf-8"))
        self.assertIn(profile.get("source_branch"), (None, "xenios"))
        self.assertEqual(profile["source_commit"][:7], "cf7c7ee")


class PcemUpstreamPinIsTheLastSync(unittest.TestCase):
    """The pcem bump set upstream_commit to dev's HEAD 25b54e3f, and dev was
    rewritten: the pin left every branch (compare: diverged 109/114). The
    port shares no history with upstream and took mainline patches by hand
    until 2016-04-13, whose last upstream commit is 10739b96. Held there, a
    bump cannot move it to a HEAD the port never contained."""

    def test_the_upstream_pin_is_held_at_the_last_sync(self):
        profile = yaml.safe_load((REPO_ROOT / "emulators" / "pcem.yml").read_text(encoding="utf-8"))
        self.assertEqual(profile["upstream_commit"], "10739b9618e388a5bf8c21e752f12b3952fa83e1")
        self.assertTrue(profile.get("upstream_frozen"))


class AHashScanLabelNamesNoOtherDump(unittest.TestCase):
    """A core that finds its firmware by content names no file, so each
    entry name is a label. ares labelled its Famicom Disk System revision
    (RP2C33-01, crc32 1c7ae5d5) disksys.rom, the name six NES cores read for
    the RP2C33A-01A dump: on ROCKNIX the manifest put ares's revision at
    disksys.rom for all of them. A label that another profile gives a
    different dump is refused, the two dumps compared through the
    collection's hash indexes."""

    # Names the core's own code gives the image, not labels.
    CODE_NAMED = {
        ("bizhawk", "MSX.rom"):
            "FirmwareDatabase.cs:362 names the image MSX.rom",
        ("swanstation", "ps1_rom.bin"):
            "the whole PS3 image is the file the PS3 itself names ps1_rom.bin, "
            "beetle_psx reads its first 512 KB under the same name",
        ("duckstation-legacy", "ps1_rom.bin"):
            "the same whole PS3 image, whose first 512 KB src/core/bios.cpp:89 hashes",
        ("openmsx", "COLECO.ROM"):
            "share/machines/ColecoVision_SGM.xml:56 names it, tried beside the machine XML",
        ("openmsx", "fmpac.rom"):
            "share/machines/Boosted_MSX2_EN.xml:83 names it, tried beside the machine XML",
        ("openmsx-libretro", "rs232.rom"):
            "share/extensions/rs232.xml:18-22 names it, tried beside the extension XML",
    }

    @staticmethod
    def _identity(entry: dict, db: dict) -> tuple[set, set]:
        raw: set = set()
        sha1s: set = set()
        indexes = db["indexes"]
        for field, index in (("sha1", None), ("md5", "by_md5"),
                             ("crc32", "by_crc32"), ("sha256", "by_sha256")):
            value = entry.get(field)
            values = value if isinstance(value, list) else [value] if value else []
            for item in values:
                for digest in str(item).lower().split(","):
                    digest = digest.strip()
                    if not digest:
                        continue
                    raw.add((field, digest))
                    sha1 = digest if index is None else indexes[index].get(digest)
                    if sha1 in db["files"]:
                        sha1s.add(sha1)
        return raw, sha1s

    def test_labels_are_not_other_dumps_names(self):
        import json

        from scripts.model.profiles import load_emulator_profiles

        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        by_name: dict[str, list[tuple[str, dict]]] = {}
        for emulator, profile in profiles.items():
            for entry in profile.get("files") or []:
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if name:
                        by_name.setdefault(str(name).casefold(), []).append((emulator, entry))
        clashes = []
        for emulator, profile in profiles.items():
            if profile.get("found_by") != "content":
                continue
            for entry in profile.get("files") or []:
                raw, sha1s = self._identity(entry, db)
                if not sha1s:
                    continue
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if (emulator, name) in self.CODE_NAMED:
                        continue
                    for other, other_entry in by_name.get(str(name).casefold(), []):
                        if other == emulator:
                            continue
                        other_raw, other_sha1s = self._identity(other_entry, db)
                        if other_sha1s and not raw & other_raw and not sha1s & other_sha1s:
                            clashes.append(f"{emulator} {name} is {other}'s name for another dump")
        self.assertEqual(sorted(set(clashes)), [])


class ANoteOutsideTheSystemDirCarriesLoadFrom(unittest.TestCase):
    """mame2000 opens hiscore.dat, history.dat and mameinfo.dat from the
    directory of the loaded content (src/libretro/fileio.c:1002-1014), and
    mame2014 and mame2015 open hiscore.dat from the working directory
    (src/emu/hiscore.c:330-337). Their notes said so, but no load_from did:
    the entries claimed system/hiscore.dat and the RetroArch pack shipped a
    file neither core opens there. A libretro entry whose note places the
    read outside the system directory declares where."""

    ELSEWHERE = re.compile(
        r"\b(?:opened|read|loaded)\b[^.]*?\bfrom (?:the )?(?:working directory|"
        r"ROM directory|content directory|directory of the loaded content)"
        r"|IMAMEBASEPATH",
        re.IGNORECASE,
    )

    def test_prose_and_load_from_agree(self):
        offenders = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if profile.get("type") != "libretro":
                continue
            for entry in profile.get("files") or []:
                if entry.get("path") or entry.get("load_from") or entry.get("mode") == "standalone":
                    continue
                if self.ELSEWHERE.search(str(entry.get("note") or "")):
                    offenders.append(f"{path.name}: {entry.get('name')}")
        self.assertEqual(offenders, [])


class TheTreeKeepsStandaloneEntries(unittest.TestCase):
    """With no platform named, the gap report laid every dual profile out as
    libretro only: eka2l1, dolphin and xenia-edge lost 133 files that
    Batocera and RetroBat run standalone and no platform declares."""

    def test_a_standalone_only_entry_is_reported(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        out = subprocess.run(
            [sys.executable, "scripts/cross_reference.py", "--emulator", "eka2l1"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=True,
        ).stdout
        undeclared = re.search(r"(\d+) undeclared", out)
        self.assertIsNotNone(undeclared, out[-500:])
        self.assertGreater(int(undeclared.group(1)), 0)


class TheCliSetsBundledFilesApart(unittest.TestCase):
    """cross_reference counted daedalusx64's n64.psh and touchHLE's runtime
    libraries as missing, to be sourced, though the project leaves them out
    by design and verify and the gaps page already say so."""

    def test_a_bundled_gap_is_not_missing(self):
        from scripts.packs.crossreftext import print_report

        gap = {"name": "n64.psh", "required": True, "bundled": True, "note": "",
               "source": "missing"}
        report = {"emu": {
            "emulator": "Emu", "systems": [], "total_files": 1, "platform_covered": 0,
            "gaps": 1, "gap_missing": 1, "gap_details": [gap],
        }}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_report(report)
        text = out.getvalue()
        self.assertIn("0 missing (need to be sourced)", text)
        self.assertIn("1 bundled with their emulator", text)
        self.assertIn("n64.psh [BUNDLED]", text)


class WhatOnlyAnInstallProvidesIsListed(unittest.TestCase):
    """A file installed with its emulator is already on the user's machine.
    A copy nothing else asks for is dead weight in the collection."""

    def test_only_the_bundled_only_copy_is_listed(self):
        import tempfile

        from packs import bundledonly

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(bundledonly, "list_registered_platforms", return_value=[]):
            def entry(sha1, name):
                path = Path(tmp, name)
                path.write_bytes(name.encode())
                return {"path": str(path), "name": name, "sha1": sha1,
                        "md5": sha1[:32], "size": path.stat().st_size}

            db = {"bios_dir": tmp,
                  "files": {"a" * 40: entry("a" * 40, "icon.png"),
                            "b" * 40: entry("b" * 40, "bios.rom")},
                  "indexes": {"by_name": {"icon.png": ["a" * 40], "bios.rom": ["b" * 40]},
                              "by_md5": {}, "by_crc32": {}, "by_sha256": {},
                              "by_path_suffix": {}}}
            profiles = {
                "app": {"files": [{"name": "icon.png", "sha1": "a" * 40, "bundled": True},
                                  {"name": "bios.rom", "sha1": "b" * 40, "bundled": True}]},
                "core": {"files": [{"name": "bios.rom", "sha1": "b" * 40}]},
            }
            rows = bundledonly.bundled_only(db, profiles, tmp, Path(tmp))
            self.assertEqual([row["path"] for row in rows], [str(Path(tmp, "icon.png"))])
            # A platform whose package leaves the file out brings it from the
            # collection: the copy stays.
            profiles["app"]["files"][0]["not_bundled_on"] = ["someplatform"]
            self.assertEqual(bundledonly.bundled_only(db, profiles, tmp, Path(tmp)), [])

    def test_every_copy_of_the_listed_bytes_is_listed(self):
        """The database keeps one path per content: splitwolf's sprite
        folders hold one file several times and took five passes to empty."""
        import hashlib
        import tempfile

        from packs import bundledonly

        with tempfile.TemporaryDirectory() as tmp:
            for name in ("dir1/a.bmp", "dir2/a.bmp", "dir2/b.bmp"):
                Path(tmp, name).parent.mkdir(exist_ok=True)
                Path(tmp, name).write_bytes(b"same" if "a.bmp" in name else b"diff")
            sha1 = hashlib.sha1(b"same").hexdigest()
            row = {"sha1": sha1, "path": Path(tmp, "dir1/a.bmp").as_posix(), "size": 4,
                   "emulators": ["splitwolf"]}
            copies = bundledonly.other_copies([row], Path(tmp))
            self.assertEqual([c["path"] for c in copies], [Path(tmp, "dir2/a.bmp").as_posix()])

    def test_the_collection_holds_no_copy_only_an_install_provides(self):
        """The pull request checks run this suite, not the pipeline: without
        this, a copy only a bundled entry reaches merges green."""
        from packs import bundledonly
        from model.database import load_database
        from model.profiles import load_emulator_profiles

        rows = bundledonly.bundled_only(
            load_database(str(REPO_ROOT / "database.json")),
            load_emulator_profiles(str(REPO_ROOT / "emulators")),
            str(REPO_ROOT / "platforms"), REPO_ROOT / "install",
        )
        self.assertEqual([f"{r['path']} ({', '.join(r['emulators'])})" for r in rows], [],
                         "remove the copy: the emulator's own install provides it")


class AFileTheLauncherNeverOpens(unittest.TestCase):
    """RetroBat hands standalone BlastEm absolute paths to its own BIOS
    names, so the defaults the emulator would read (cdbios.bin) were listed
    as required and missing on RetroBat although nothing there opens them."""

    def test_unread_on_drops_the_entry_for_that_platform_only(self):
        from resolve.entryscope import deliverable, unread_on

        entry = {"name": "cdbios.bin", "unread_on": ["retrobat"]}
        self.assertTrue(unread_on(entry, "retrobat"))
        self.assertFalse(unread_on(entry, "batocera"))
        self.assertFalse(unread_on(entry, ""))
        self.assertEqual(deliverable([entry], True, "retrobat"), [])
        self.assertEqual(deliverable([entry], True, "batocera"), [entry])

    def test_the_gap_report_reads_it(self):
        source = script_source("verify.py")
        self.assertIn('unread_on(f, config.get("_key", ""))', source)


class AmigaCdDriversLiveInTheExtendedRom(unittest.TestCase):
    """WinUAE starts without the CD32 or CDTV extended ROM, but cd.device,
    cdtv.device, cdfs.library and cdstrap are resident modules of those ROMs
    and the Kickstarts carry none. Its AROS replacement stands in only for a
    missing Kickstart (memory.cpp:3055-3063), so the CDTV ROM has no
    fallback to downgrade its absence."""

    def test_both_extended_roms_are_required_without_fallback(self):
        profile = yaml.safe_load(
            (REPO_ROOT / "emulators" / "winuae.yml").read_text(encoding="utf-8")
        )
        entries = {f["name"]: f for f in profile["files"]}
        for name in ("amiga-ext-310-cd32.rom", "amiga-ext-130-cdtv.rom"):
            with self.subTest(name=name):
                self.assertIs(entries[name]["required"], True)
                self.assertNotIn("hle_fallback", entries[name])


class BizHawkListsEveryDsiNandSlot(unittest.TestCase):
    """FirmwareDatabase.cs:405-410 declares six DSi NAND slots, each a
    placeholder hash and 251658240 + 64 bytes, and DecideNAND
    (MelonDS.cs:684-706) stops a DSi load when none is set. The profile
    listed DSi_Firmware.bin, a placeholder slot of the same kind, and left
    the NANDs out."""

    def test_the_six_regional_nands_are_declared(self):
        profile = yaml.safe_load(
            (REPO_ROOT / "emulators" / "bizhawk.yml").read_text(encoding="utf-8")
        )
        entries = {f["name"]: f for f in profile["files"]}
        for region_code in ("JPN", "EUR", "USA", "AUS", "CHN", "KOR"):
            with self.subTest(region=region_code):
                entry = entries[f"DSi_Nand_{region_code}.bin"]
                self.assertEqual(entry["size"], 251658240 + 64)
                self.assertIs(entry["required"], False)
                self.assertNotIn("sha1", entry)


class HiganSuperGameBoyFolderIsFree(unittest.TestCase):
    """higan reads program.rom in the option's folder, SGB.sfc/, then Super
    GameBoy.sfc/. bsnes, Mesen-S and ares read SGB1.sfc and SGB2.sfc as files
    in the same system directory, and SuperSnes9x sgb.sfc, so a pack that only
    had the first two folders never gave the higan cores a Super Game Boy."""

    def test_each_higan_core_has_a_folder_no_core_reads_as_a_file(self):
        import yaml

        file_names: set[str] = set()
        for path in (REPO_ROOT / "emulators").glob("*.yml"):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in document.get("files") or []:
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if name:
                        file_names.add(str(name).casefold())
                if entry.get("path"):
                    file_names.add(str(entry["path"]).casefold())
        for profile in ("higan_sfc", "higan_sfc_balanced"):
            document = yaml.safe_load(
                (REPO_ROOT / "emulators" / f"{profile}.yml").read_text(encoding="utf-8")
            )
            folders = {
                str(entry["path"]).split("/", 1)[0]
                for entry in document["files"]
                if str(entry.get("path") or "").endswith("/program.rom")
                and entry.get("system") == "nintendo-sgb"
            }
            with self.subTest(profile=profile):
                self.assertTrue(
                    [f for f in folders if f.casefold() not in file_names], folders
                )


class ProfileNotesDescribeTheCoreAlone(unittest.TestCase):
    """mednafen_pce_fast, sdlpop and x64sdl described the core by what
    another profile of this directory does ("unlike beetle_pce", "unlike the
    other engines in this directory"), which means nothing once the profile
    is read on its own, and 21 lines shouted NOT, ALL or MUST."""

    SHOUT = re.compile(r"\b(NOT|NEVER|ONLY|MUST|ALL|DIFFERENT)\b(?! FOUND)")

    def test_no_profile_shouts_or_compares_with_another_profile(self):
        names = {path.stem.casefold() for path in (REPO_ROOT / "emulators").glob("*.yml")}
        names |= {name.replace("_", "-") for name in names}
        found = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), 1):
                if self.SHOUT.search(line):
                    found.append(f"{path.stem}:{number}")
                found.extend(
                    f"{path.stem}:{number}"
                    for match in re.finditer(r"\bunlike (?:the )?([\w+-]+)", line, re.I)
                    if match.group(1).casefold() in names
                )
        self.assertEqual(found, [])


class Ps2BiosImagesAreFoundByContent(unittest.TestCase):
    """PCSX2 and its forks scan the BIOS folder and keep the first 4 to 8 MB
    image with a romdir (pcsx2/ps2/BiosTools.cpp:258-282 at f0523f8a). With
    no found_by the label ps2-0230a-20080220.bin read as a name the core
    opens, and the RetroDECK export added it as a required file."""

    def test_every_ps2_image_scan_is_marked(self):
        """ARMSX2's arcade scan takes 2 to 8 MB COH-H images by their EXTINFO
        serial (BiosTools.cpp:366-419 at 7f914418): r27v1602f.8g read as a
        name armsx2 opens on six platforms."""
        import yaml

        from resolve.entryscope import opens_by_name

        named = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            # Whatever the profile's own flags: TeknoParrot documents its
            # pcsx2x6 component, whose scan is the same (BiosTools.cpp:268-291
            # at 583f0e90), and carries no agnostic flag.
            named.extend(
                f"{path.stem}: {entry['name']}"
                for entry in profile.get("files") or []
                if (
                    entry.get("min_size") in (2097152, 4194304)
                    and entry.get("max_size") == 8388608
                    and opens_by_name(entry, profile)
                )
            )
        self.assertEqual(named, [])


class SynthRomsAreFoundByContent(unittest.TestCase):
    """dosbox-staging's libmt32emu scan identifies each file of the ROM
    folder with identifyROMFile (src/midi/mt32_lasynth_model.cpp:68-91 at
    fa1856c0), and the Sound Canvas plugin hashes its model folder
    (Nuked-SC55-CLAP, RomLoader::Hashing). The truth read the labels as
    names dosbox-staging opens, and MT32_CONTROL.ROM did not count."""

    def test_every_synth_rom_is_marked(self):
        import yaml

        from resolve.entryscope import opens_by_name

        profile = yaml.safe_load(
            (REPO_ROOT / "emulators" / "dosbox-staging.yml").read_text(encoding="utf-8")
        )
        named = [
            entry["name"]
            for entry in profile["files"]
            if str(entry.get("path", "")).startswith(("mt32-roms/", "soundcanvas-roms/"))
            and opens_by_name(entry, profile)
        ]
        self.assertEqual(named, [])


class Dev9FilesAreReadFromTheWorkingDirectory(unittest.TestCase):
    """DEV9 opens eeprom.dat and flash.dat by bare name (PCSX2
    pcsx2/DEV9/DEV9.cpp:144, AetherSX2 DEV9/flash.cpp:89): the working
    directory, never the BIOS folder. Eight profiles left load_from unset,
    so the file was packed into the BIOS folder, where nothing reads it."""

    def test_every_dev9_file_names_the_working_directory(self):
        import yaml

        unset = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            unset.extend(
                f"{path.stem}: {entry['name']}"
                for entry in profile.get("files") or []
                if (
                    entry.get("name") in ("eeprom.dat", "flash.dat")
                    and "DEV9" in str(entry.get("source_ref"))
                    and entry.get("load_from") != "working_directory"
                )
            )
        self.assertEqual(unset, [])


class OpenMsxSystemRomsAreFoundBySha1(unittest.TestCase):
    """openMSX reaches a ROM in share/systemroms through the file pool by
    SHA1 alone, a filename being looked up only beside the machine's XML
    (src/memory/Rom.cc:121-170). Read as names the core opens, the labels
    were added to the KNULLI and Batocera exports."""

    def test_no_systemrom_label_reads_as_a_name(self):
        import yaml

        from resolve.entryscope import opens_by_name

        profile = yaml.safe_load((REPO_ROOT / "emulators" / "openmsx.yml").read_text())
        named = [
            entry["name"] for entry in profile["files"]
            if "share/systemroms/" in str(entry.get("path"))
            and opens_by_name(entry, profile)
        ]
        self.assertEqual(named, [])


class PrboomPlusCitesFullPaths(unittest.TestCase):
    """prboom-plus cited gl_hires.c, e6y.c, d_client.c and g_game.c bare:
    none resolves against the repository, so the page showed them as plain
    code with no link, and "behind GL_DOOM and PRBOOM_DEBUG" was read as a
    seventeenth citation. Each name has one path in the tree at the pin."""

    def test_every_cited_file_has_its_directory(self):
        import yaml

        from scripts.model.sourceref import source_ref_values, split_source_ref

        profile = yaml.safe_load((REPO_ROOT / "emulators" / "prboom-plus.yml").read_text(encoding="utf-8"))
        refs: list[str] = []

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "source_ref":
                        refs.extend(r for _, r in source_ref_values(value))
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(profile)
        parts = [p for ref in refs for p in split_source_ref(ref)]
        self.assertGreater(len(parts), 40)
        for part in parts:
            with self.subTest(path=part.path):
                self.assertIsNotNone(part.start)
                self.assertTrue(part.path.startswith("prboom2/"), part.path)


class EveryReaderOfACoreFileIsNamed(unittest.TestCase):
    """A requirement two cores read is reported once, the first profile
    hosting the others' claims. Whatever drops the host must not drop the
    claims with it."""

    def test_a_host_its_emulator_installs_leaves_the_others_in_the_pack(self):
        from packs.gaps import _split_bundled_claims

        dsperate = {"profile": "dsperate", "name": "usrcheat.dat", "in_repo": True}
        drastic = {"profile": "drastic", "name": "usrcheat.dat", "bundled": True,
                   "in_repo": True, "other_claims": [dsperate]}
        out = _split_bundled_claims([drastic])
        self.assertEqual([(u["profile"], u.get("other_claims")) for u in out],
                         [("drastic", None), ("dsperate", None)])
        alone = {"profile": "drastic", "bundled": True, "other_claims": [
            {"profile": "drastic-legacy", "bundled": True}]}
        self.assertEqual(_split_bundled_claims([alone]), [alone])

    def test_a_held_file_out_of_reach_names_every_core_reading_it(self):
        """harm1.wad is a release asset: a checkout without it omits the file,
        and the omission named gzdoom alone where lzdoom reads it too."""
        from packs.manifestentry import claim_cores

        extra = {"source_profile": "gzdoom", "other_claims": [
            {"source_profile": "uzdoom"}, {"source_profile": "lzdoom"}]}
        self.assertEqual(claim_cores(extra), ["gzdoom", "lzdoom", "uzdoom"])

    def test_a_missing_file_names_every_core_reading_it(self):
        from packs.manifestentry import record_absent

        omitted: dict[str, dict] = {}

        def record(full_dest, entry, system, reason, cores):
            omitted[full_dest] = {"dest": full_dest, "reason": reason, "cores": cores}

        absent = [
            {"name": "NAPALM.GRP", "destination": "NAPALM.GRP", "source_profile": profile,
             "source_system": system}
            for profile, system in (("raze", "nam"), ("eduke32", "napalm"))
        ]
        platform = {"dest": "SHARED.BIN", "reason": "not_found", "cores": None}
        omitted["SHARED.BIN"] = platform
        absent.append({"name": "SHARED.BIN", "destination": "SHARED.BIN",
                       "source_profile": "raze"})
        record_absent(absent, {}, "", set(), False, set(), omitted, record)
        self.assertEqual(omitted["NAPALM.GRP"]["cores"], ["eduke32", "raze"])
        # A platform's own omission stays the platform's.
        self.assertIsNone(omitted["SHARED.BIN"]["cores"])


if __name__ == "__main__":
    unittest.main()
