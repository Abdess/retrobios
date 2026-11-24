"""The installer replays the pack builder: a narrowed install holds what the narrowed pack holds."""
from __future__ import annotations

import tests

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from packs import archive, coverage, platformpack
from packs import manifest as packs_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)


class InstallMatchesThePack(unittest.TestCase):
    """Narrowing the full manifest gives what the narrowed build carries."""

    PLATFORM = "recalbox"

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        from model.profiles import load_emulator_profiles
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cls.full = cls._manifest(None)

    @classmethod
    def _manifest(cls, regions):
        return packs_manifest.generate_manifest(
            cls.PLATFORM, str(REPO_ROOT / "platforms"), cls.db,
            str(REPO_ROOT / "bios"), str(REPO_ROOT / "platforms" / "_registry.yml"),
            emulators_dir=str(REPO_ROOT / "emulators"), emu_profiles=cls.profiles,
            regions=regions, offline=True,
        )

    def _narrowed(self, systems, regions):
        files, omitted = install.narrow(
            self.full["files"], self.full["omitted_files"], systems, [], regions
        )
        return {f["dest"] for f in files}, {o["dest"] for o in omitted}

    def test_regions(self):
        for regions in (["north-america"], ["japan", "europe"]):
            with self.subTest(regions=regions):
                built = self._manifest(regions)
                files, omitted = self._narrowed([], regions)
                self.assertEqual(files, {f["dest"] for f in built["files"]})
                self.assertEqual(omitted, {o["dest"] for o in built["omitted_files"]})


class InstallMatchesASystemPack(unittest.TestCase):
    """`install.py --system X --region R` against a real `generate_pack.py
    --system X --region R` build. The cases are the ones a review reproduced:
    ColecoVision's extras filed at destinations another system declares, and
    PicoDrive's Mega CD variant group spread over two systems. The last pick
    holds MAME device sets filed under several systems (systems:), under one,
    and under none."""

    PLATFORM = "retroarch"
    CASES = (
        (["coleco-colecovision"], []),
        (["sega-mega-cd"], ["north-america"]),
        (["sony-playstation"], ["japan"]),
        (["elektronika-bk"], []),
    )

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        from packs import manifest as packs_manifest
        from model.profiles import load_emulator_profiles
        from model.platforms import load_platform_config
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cls.base = load_platform_config(
            cls.PLATFORM, str(REPO_ROOT / "platforms")
        ).get("base_destination", "")
        cls.full = packs_manifest.generate_manifest(
            cls.PLATFORM, str(REPO_ROOT / "platforms"), cls.db,
            str(REPO_ROOT / "bios"), str(REPO_ROOT / "platforms" / "_registry.yml"),
            emulators_dir=str(REPO_ROOT / "emulators"), emu_profiles=cls.profiles,
            offline=True,
        )

    def _packed(self, systems, regions) -> set[str]:
        import zipfile

        with tempfile.TemporaryDirectory() as out:
            zip_path = platformpack.generate_pack(
                self.PLATFORM, str(REPO_ROOT / "platforms"), self.db,
                str(REPO_ROOT / "bios"), out,
                emulators_dir=str(REPO_ROOT / "emulators"),
                emu_profiles=self.profiles, system_filter=systems,
                regions=regions or None, offline=True,
            )
            with zipfile.ZipFile(zip_path) as zf:
                names = set(zf.namelist())
        prefix = f"{self.base}/" if self.base else ""
        return {n[len(prefix):] if prefix and n.startswith(prefix) else n for n in names}

    def test_each_case(self):
        known = {f["dest"] for f in self.full["files"]}
        for systems, regions in self.CASES:
            with self.subTest(systems=systems, regions=regions):
                files, _omitted = install.narrow(
                    self.full["files"], self.full["omitted_files"],
                    systems, [], regions,
                )
                self.assertEqual(
                    {f["dest"] for f in files}, self._packed(systems, regions) & known
                )


class DataTreesFollowTheSystemsTheyServe(InstallMatchesASystemPack):
    """The data trees a system choice keeps, installer against pack. GBA
    alone took FBNeo's cheats and samples, 3,472 files, because the trees
    listed every FBNeo system. The Mega Drive took no cheat: the tree said
    sega-megadrive where RetroArch's list says sega-mega-drive."""

    CASES = ((["nintendo-gba"], []), (["sega-mega-drive"], []), (["arcade"], []))

    def _packed(self, systems, regions) -> set[str]:
        import zipfile

        from model.registry import load_data_dir_registry

        # The trees come from the registry the manifest reads by itself.
        with tempfile.TemporaryDirectory() as out:
            zip_path = platformpack.generate_pack(
                self.PLATFORM, str(REPO_ROOT / "platforms"), self.db,
                str(REPO_ROOT / "bios"), out,
                emulators_dir=str(REPO_ROOT / "emulators"),
                emu_profiles=self.profiles, system_filter=systems,
                regions=regions or None, offline=True,
                data_registry=load_data_dir_registry(str(REPO_ROOT / "platforms")),
            )
            with zipfile.ZipFile(zip_path) as zf:
                names = set(zf.namelist())
        prefix = f"{self.base}/" if self.base else ""
        return {n[len(prefix):] if prefix and n.startswith(prefix) else n for n in names}

    def _members(self, trees) -> set[str]:
        return {f"{tree['dest']}/{rel}" if tree["dest"] else rel
                for tree in trees for rel in tree["files"]}

    def test_each_case(self):
        everything = self._members(self.full.get("data_directories") or [])
        for systems, regions in self.CASES:
            with self.subTest(systems=systems):
                files, _omitted = install.narrow(
                    self.full["files"], self.full["omitted_files"], systems, [], regions)
                trees = install.select_data_directories(self.full, files, True, systems=systems)
                refs = {tree["ref"] for tree in trees}
                if systems == ["nintendo-gba"]:
                    self.assertFalse({"fbneo-cheats", "fbneo-samples"} & refs)
                if systems == ["sega-mega-drive"]:
                    self.assertIn("fbneo-cheats", refs)
                    self.assertNotIn("fbneo-samples", refs)
                if systems == ["arcade"]:
                    self.assertTrue({"fbneo-cheats", "fbneo-samples"} <= refs)
                self.assertEqual(self._members(trees),
                                 self._packed(systems, regions) & everything)


class InstallMatchesATargetManifest(unittest.TestCase):
    """`install.py --target T` against the manifest the builder writes for T.

    A target list names cores the way the buildbot does (`mednafen_psx`)
    while a file names the profile that reads it (`beetle_psx`), and the
    builder drops a platform system no available core reads. The installer
    did neither: on RetroArch desktop it kept every system and lost the
    extras of five cores. A destination two cores read was also filed under
    the first alone, so a target without that core lost it, or got the
    first core's copy where the other core wants different bytes
    (megaplay.zip for mame and mame2003 on Switch).
    """

    CASES = (
        ("retroarch", "desktop"),
        ("retroarch", "switch"),
        ("batocera", "x86_64"),
        ("batocera", "bcm2711"),
        ("retropie", "rpi4"),
        ("emudeck", "steamos"),
        # A core only Batocera's x86_64 downloader brings, a missing file two
        # cores read, a file another emulator installs itself, and a name a
        # launcher opens that another core's copy used to fill.
        ("batocera", "jh7110"),
        ("knulli", "h700"),
        ("rocknix", "sdm845"),
        ("retropie", "x86"),
        ("retropie", "rpi1"),
    )

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        from model.profiles import load_emulator_profiles
        from model.targets import load_target_config
        cls.load_target_config = staticmethod(load_target_config)
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

    def _manifest(self, platform, target_cores=None, target=None):
        return packs_manifest.generate_manifest(
            platform, str(REPO_ROOT / "platforms"), self.db,
            str(REPO_ROOT / "bios"), str(REPO_ROOT / "platforms" / "_registry.yml"),
            emulators_dir=str(REPO_ROOT / "emulators"), emu_profiles=self.profiles,
            target_cores=target_cores, target_name=target, offline=True,
        )

    def test_each_target(self):
        for platform, target in self.CASES:
            with self.subTest(platform=platform, target=target):
                cores = sorted(self.load_target_config(
                    platform, target, str(REPO_ROOT / "platforms")
                ))
                full = self._manifest(platform)
                built = self._manifest(platform, set(cores), target)
                files, omitted = install.narrow_to_cores(full, cores, target=target)
                # A case-insensitive platform reads one file under both
                # spellings (BlastEm's 32X_M_BIOS.bin, PicoDrive's .BIN).
                from model.platforms import load_platform_config

                config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
                fold = str.lower if config.get("case_insensitive_fs") else str
                self.assertEqual(
                    {(fold(f["dest"]), f["sha1"]) for f in files},
                    {(fold(f["dest"]), f["sha1"]) for f in built["files"]},
                )
                self.assertEqual(
                    {o["dest"] for o in omitted},
                    {o["dest"] for o in built["omitted_files"]},
                )


class AHeldFileTheInstallerCannotFetch(unittest.TestCase):
    """The builder holds a release asset this offline run has no copy of.

    jp.bin is registered in .gitignore and indexed by the database, as every
    file of the large-files release is, but neither the checkout nor
    .cache/large/ holds it. The builder counts it held, so it displaces the
    American fallback for --region japan, while the manifest can only list
    it as omitted. Counted unheld there, the installer kept the fallback the
    pack drops."""

    def setUp(self):
        from model import profiles
        from model.platforms import _platform_config_cache
        from model.profiles import emulator_profiles_cache
        from collection.indexes import build_indexes
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        previous = os.getcwd()
        os.chdir(tmp.name)
        self.addCleanup(os.chdir, previous)
        Path("bios/Sys").mkdir(parents=True)
        Path("bios/Sys/us.bin").write_bytes(b"us")
        files = {}
        for name, payload in (("us.bin", b"us"), ("jp.bin", b"jp")):
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {"path": f"bios/Sys/{name}", "name": name,
                           "size": len(payload), "sha1": sha1,
                           "md5": hashlib.md5(payload).hexdigest(),
                           "sha256": hashlib.sha256(payload).hexdigest(),
                           "crc32": "00000001"}
        # The registry of release assets: listed there, so a checkout has
        # no copy, and this offline run fetches none.
        Path(".gitignore").write_text("bios/Sys/jp.bin\n")
        registered = mock.patch(
            "model.largefiles.load_registered_paths", return_value=["bios/Sys/jp.bin"]
        )
        registered.start()
        self.addCleanup(registered.stop)
        self.db = {"files": files, "indexes": build_indexes(files, {})}
        Path("platforms").mkdir()
        Path("platforms/p.yml").write_text(json.dumps({
            "platform": "P", "version": "2.1", "verification_mode": "existence", "cores": ["core"],
            "systems": {"sys": {"files": []}},
        }))
        Path("platforms/_registry.yml").write_text(
            json.dumps({"platforms": {"p": {"config": "p.yml"}}})
        )
        Path("emulators").mkdir()
        Path("emulators/core.yml").write_text(json.dumps({
            "emulator": "core", "type": "libretro", "systems": ["sys"], "files": [
                {"name": "jp.bin", "system": "sys", "region": ["japan"],
                 "required": True},
                {"name": "us.bin", "system": "sys", "region": ["north-america"],
                 "required": True},
            ]}))
        _platform_config_cache.clear()
        emulator_profiles_cache.clear()
        self.addCleanup(_platform_config_cache.clear)
        self.addCleanup(emulator_profiles_cache.clear)
        self.profiles = profiles.load_emulator_profiles("emulators")

    def _manifest(self, regions):
        return packs_manifest.generate_manifest(
            "p", "platforms", self.db, "bios", "platforms/_registry.yml",
            emulators_dir="emulators", emu_profiles=self.profiles,
            regions=regions, offline=True,
        )

    def test_the_installer_drops_the_fallback_the_pack_drops(self):
        full = self._manifest(None)
        omitted = {o["dest"]: o for o in full["omitted_files"]}
        self.assertTrue(omitted["jp.bin"].get("held"))
        built = self._manifest(["japan"])
        self.assertNotIn("us.bin", {f["dest"] for f in built["files"]})
        files, still = install.narrow(
            full["files"], full["omitted_files"], [], [], ["japan"]
        )
        self.assertEqual({f["dest"] for f in files}, {f["dest"] for f in built["files"]})
        self.assertEqual(
            {o["dest"] for o in still}, {o["dest"] for o in built["omitted_files"]}
        )


class AStandaloneLayoutBelowTheBiosFolder(unittest.TestCase):
    """DuckStation reads `bios/<name>` standalone, which a platform whose
    base destination is `bios` places in that folder itself. The collector
    deduplicated the path at `bios/bios/<name>` while the builder wrote it
    at `bios/<name>`, so another core's claim on the same file took the
    path under a second key: `--region north-america` withdrew one key and
    the pack kept the European BIOS the installer drops."""

    def setUp(self):
        from model import profiles
        from model.platforms import _platform_config_cache
        from model.profiles import emulator_profiles_cache
        from collection.indexes import build_indexes
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        previous = os.getcwd()
        os.chdir(tmp.name)
        self.addCleanup(os.chdir, previous)
        Path("bios/Sys").mkdir(parents=True)
        files = {}
        for name in ("us.bin", "eu.bin", "jp.bin"):
            payload = name.encode()
            Path(f"bios/Sys/{name}").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {"path": f"bios/Sys/{name}", "name": name,
                           "size": len(payload), "sha1": sha1,
                           "md5": hashlib.md5(payload).hexdigest(),
                           "sha256": hashlib.sha256(payload).hexdigest(),
                           "crc32": "00000001"}
        self.db = {"files": files, "indexes": build_indexes(files, {})}
        Path("platforms").mkdir()
        Path("platforms/p.yml").write_text(json.dumps({
            "platform": "P", "version": "2.1", "verification_mode": "existence",
            "base_destination": "bios", "cores": ["dsa", "other"],
            "standalone_cores": ["dsa"], "systems": {"sys": {"files": []}},
        }))
        Path("platforms/_registry.yml").write_text(
            json.dumps({"platforms": {"p": {"config": "p.yml"}}})
        )
        Path("emulators").mkdir()
        Path("emulators/dsa.yml").write_text(json.dumps({
            "emulator": "dsa", "type": "standalone + libretro", "systems": ["sys"],
            "files": [
                {"name": name, "standalone_path": f"bios/{name}", "system": "sys",
                 "region": [region_name], "required": False}
                for name, region_name in (
                    ("us.bin", "north-america"), ("eu.bin", "europe"),
                    ("jp.bin", "japan"),
                )
            ]}))
        Path("emulators/other.yml").write_text(json.dumps({
            "emulator": "other", "type": "libretro", "systems": ["sys"], "files": [
                {"name": name, "system": "sys", "required": False}
                for name in ("eu.bin", "jp.bin")
            ]}))
        _platform_config_cache.clear()
        emulator_profiles_cache.clear()
        self.addCleanup(_platform_config_cache.clear)
        self.addCleanup(emulator_profiles_cache.clear)
        self.profiles = profiles.load_emulator_profiles("emulators")

    def _manifest(self, regions):
        return packs_manifest.generate_manifest(
            "p", "platforms", self.db, "bios", "platforms/_registry.yml",
            emulators_dir="emulators", emu_profiles=self.profiles,
            regions=regions, offline=True,
        )

    def test_one_path_one_entry(self):
        full = self._manifest(None)
        dests = [f["dest"] for f in full["files"]]
        self.assertEqual(sorted(dests), ["eu.bin", "jp.bin", "us.bin"])

    def test_the_installer_keeps_what_the_pack_keeps(self):
        full = self._manifest(None)
        built = self._manifest(["north-america"])
        self.assertEqual({f["dest"] for f in built["files"]}, {"us.bin"})
        files, _omitted = install.narrow(
            full["files"], full["omitted_files"], [], [], ["north-america"]
        )
        self.assertEqual({f["dest"] for f in files}, {f["dest"] for f in built["files"]})


class AnExtraBesideItsDeclarationBelowTheBiosFolder(unittest.TestCase):
    """RetroDECK declares bios/scph5501.bin and writes core files below bios/.
    Beetle PSX's scph5501.bin was grouped bare, a key whose region lookup
    another core leaves untagged, while the declaration's key resolved to
    DuckStation's American tag: `--region japan` dropped the declaration and
    the pack kept the file through the core's claim, while the installer,
    which records the path once, dropped it."""

    def setUp(self):
        from model import profiles
        from model.platforms import _platform_config_cache
        from model.profiles import emulator_profiles_cache
        from collection.indexes import build_indexes
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        previous = os.getcwd()
        os.chdir(tmp.name)
        self.addCleanup(os.chdir, previous)
        Path("bios/Sys").mkdir(parents=True)
        files = {}
        for name in ("us.bin", "jp.bin"):
            payload = name.encode()
            Path(f"bios/Sys/{name}").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {"path": f"bios/Sys/{name}", "name": name,
                           "size": len(payload), "sha1": sha1,
                           "md5": hashlib.md5(payload).hexdigest(),
                           "sha256": hashlib.sha256(payload).hexdigest(),
                           "crc32": "00000001"}
        self.db = {"files": files, "indexes": build_indexes(files, {})}
        Path("platforms").mkdir()
        Path("platforms/p.yml").write_text(json.dumps({
            "platform": "P", "version": "2.1", "verification_mode": "existence",
            "base_destination": "", "cores": ["beetle", "dsa", "other"],
            "standalone_cores": ["dsa"], "systems": {"sys": {"files": [
                {"name": name, "destination": f"bios/{name}", "required": False}
                for name in ("us.bin", "jp.bin")
            ]}},
        }))
        Path("platforms/_registry.yml").write_text(
            json.dumps({"platforms": {"p": {"config": "p.yml"}}})
        )
        Path("emulators").mkdir()
        Path("emulators/dsa.yml").write_text(json.dumps({
            "emulator": "dsa", "type": "standalone + libretro", "systems": ["sys"],
            "files": [
                {"name": name, "standalone_path": f"bios/{name}", "system": "sys",
                 "region": [region_name], "required": False}
                for name, region_name in (("us.bin", "north-america"), ("jp.bin", "japan"))
            ]}))
        # Read before dsa, as beetle_psx is before duckstation, and untagged
        # by name through a second reader, as pcsx1 leaves scph5501.bin.
        Path("emulators/beetle.yml").write_text(json.dumps({
            "emulator": "beetle", "type": "libretro", "systems": ["sys"], "files": [
                {"name": "us.bin", "system": "sys", "region": ["north-america"],
                 "required": False},
            ]}))
        Path("emulators/other.yml").write_text(json.dumps({
            "emulator": "other", "type": "libretro", "systems": ["sys"], "files": [
                {"name": "us.bin", "path": "alt/us.bin", "system": "sys", "required": False},
            ]}))
        _platform_config_cache.clear()
        emulator_profiles_cache.clear()
        self.addCleanup(_platform_config_cache.clear)
        self.addCleanup(emulator_profiles_cache.clear)
        self.profiles = profiles.load_emulator_profiles("emulators")

    def _manifest(self, regions):
        return packs_manifest.generate_manifest(
            "p", "platforms", self.db, "bios", "platforms/_registry.yml",
            emulators_dir="emulators", emu_profiles=self.profiles,
            regions=regions, offline=True,
        )

    def _pack(self, regions):
        record = archive.PackRecord()
        platformpack.generate_pack(
            "p", "platforms", self.db, "bios", "", emulators_dir="emulators",
            emu_profiles=self.profiles, regions=regions, offline=True, record=record,
        )
        return {m for m in record.members if m.startswith("bios/")}

    def test_the_slot_choices_are_computed_once(self):
        """pack_overrides recomputed the choices the manifest had just
        computed with the same arguments: 8% of a manifest run."""
        from packs import slots

        real = slots.slot_choices
        with mock.patch.object(slots, "slot_choices", side_effect=real) as counted:
            self._manifest(None)
        self.assertEqual(counted.call_count, 1)

    def test_the_pack_and_the_installer_drop_the_same_files(self):
        full = self._manifest(None)
        files, _omitted = install.narrow(
            full["files"], full["omitted_files"], [], [], ["japan"]
        )
        installed = {f["dest"] for f in files if f["dest"].startswith("bios/")}
        self.assertIn("bios/jp.bin", installed)
        self.assertEqual(self._pack(["japan"]), installed)


class ACoreWithNothingHeldIsAnOmission(unittest.TestCase):
    """DOSBox serves SC-55/WAVEROM3.BIN, DOSBox Pure wants it and nothing is
    held for it. A pack built for a target without DOSBox lists it as left
    out. Narrowed from the full manifest, it had vanished."""

    MANIFEST = {"files": [{
        "dest": "SC-55/WAVEROM3.BIN", "cores": ["dosbox"], "sha1": "1" * 40,
        "absent_claims": [{"name": "WAVEROM3.BIN", "system": "dos", "required": False,
                           "reason": "not_found", "cores": ["dosbox_pure"]}],
    }], "omitted_files": []}

    def test_narrowing_away_the_holder_leaves_the_omission(self):
        files, omitted = install.narrow_to_cores(self.MANIFEST, ["dosbox_pure"])
        self.assertEqual(files, [])
        self.assertEqual([o["dest"] for o in omitted], ["SC-55/WAVEROM3.BIN"])
        files, omitted = install.narrow_to_cores(self.MANIFEST, ["dosbox", "dosbox_pure"])
        self.assertEqual(len(files), 1)
        self.assertEqual(omitted, [])


class ANativeNameSelectsOneSetEverywhere(unittest.TestCase):
    """`--system psx` was accepted by the installer and refused by
    generate_pack and verify. The platform's own name now resolves through
    common.resolve_system_arg in both tools, from the mapping the manifest's
    system_names is built from, and selects what the system id selects:
    the same pack, the same verify report, the same installed files."""

    CASES = (
        ("batocera", "psx", "sony-playstation"),
        ("recalbox", "msx1,msx2", "microsoft-msx"),
        ("romm", "acpc", "amstrad-cpc"),
    )

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        from model.profiles import load_emulator_profiles

        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

    def _packed(self, platform: str, systems: list[str]) -> tuple[set[str], set[str]]:
        """The pack's members and those the build took from data directories."""
        import zipfile

        from packs.packcounts import PackCounts

        counts: list[PackCounts] = []
        with tempfile.TemporaryDirectory() as out:
            zip_path = platformpack.build_platform_pack(
                platform, str(REPO_ROOT / "platforms"), self.db,
                str(REPO_ROOT / "bios"), out,
                emulators_dir=str(REPO_ROOT / "emulators"),
                emu_profiles=self.profiles, system_filter=systems, offline=True,
                counts=counts,
            ).zip_path
            with zipfile.ZipFile(zip_path) as zf:
                names = {i.filename for i in zf.infolist() if not i.is_dir()}
        return names, set(counts[0].trees)

    def test_pack_verify_and_installer_agree(self):
        from model.platforms import load_platform_config
        from model.systems import resolve_system_arg
        from packs.archive import is_pack_note

        for platform, native, system_id in self.CASES:
            with self.subTest(platform=platform, name=native):
                config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
                systems = list(config["systems"])
                chosen = resolve_system_arg(native, systems, config)
                self.assertEqual(chosen, resolve_system_arg(system_id, systems, config))
                self.assertEqual(chosen, [system_id])

                report = coverage.verify_platform(
                    config, self.db, str(REPO_ROOT / "emulators"), self.profiles,
                    system_filter=chosen,
                )
                self.assertEqual(report["systems"], [system_id])
                credited = set(report["pack_destinations"])
                members, trees = self._packed(platform, chosen)
                written = {
                    name for name in members
                    if not is_pack_note(name) and name not in trees - credited
                }
                self.assertTrue(written)
                self.assertEqual(credited, written)

                manifest = packs_manifest.generate_manifest(
                    platform, str(REPO_ROOT / "platforms"), self.db,
                    str(REPO_ROOT / "bios"),
                    str(REPO_ROOT / "platforms" / "_registry.yml"),
                    emulators_dir=str(REPO_ROOT / "emulators"),
                    emu_profiles=self.profiles, offline=True,
                )
                picked = install.resolve_choices(
                    [native],
                    install.available_choices(
                        manifest["files"], manifest["omitted_files"]
                    )["systems"],
                    "system", install.system_aliases(manifest),
                )
                self.assertEqual(picked, [system_id])
                files, _omitted = install.narrow(
                    manifest["files"], manifest["omitted_files"], picked, [], [],
                )
                base = config.get("base_destination", "")
                prefix = f"{base}/" if base else ""
                packed = {
                    n[len(prefix):] if prefix and n.startswith(prefix) else n
                    for n in members
                }
                known = {f["dest"] for f in manifest["files"]}
                self.assertEqual({f["dest"] for f in files}, packed & known)


if __name__ == "__main__":
    unittest.main()
