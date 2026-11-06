"""MinUI, NextUI and MyMinUI hand each core a system directory of its own.

minarch sets ``core.bios_dir`` to SDCARD_PATH "/Bios/<TAG>", the tag being
the pak's folder name and the one in parentheses of the Roms folder, and
returns it for RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY. A core run from
GB.pak reads gb_bios.bin from Bios/GB/, the same core run from GBC.pak from
Bios/GBC/. The frontends name no BIOS file, so the platform file maps each
folder to the cores its paks start, and the files come from the core
profiles, placed below that folder.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

from common import load_emulator_profiles, load_platform_config  # noqa: E402
from scraper import minui_scraper  # noqa: E402

MINARCH = (
    "void Core_open(const char* core_path, const char* tag_name) {\n"
    '\tsprintf((char*)core.saves_dir, SDCARD_PATH "/Saves/%s", core.tag);\n'
    '\tsprintf((char*)core.bios_dir, SDCARD_PATH "/Bios/%s", core.tag);\n'
    "}\n"
)
BASE_PAK = (
    "#!/bin/sh\n\n"
    "EMU_EXE=gambatte\n\n"
    "###############################\n\n"
    'EMU_TAG=$(basename "$(dirname "$0")" .pak)\n'
    'mkdir -p "$BIOS_PATH/$EMU_TAG"\n'
    'nice -20 minarch.elf "$CORES_PATH/${EMU_EXE}_libretro.so" "$ROM" &> "$LOGS_PATH/$EMU_TAG.txt"\n'
)
# MyMinUI's shape: the pak hands its folder to launch_rom.sh.
EXTRA_PAK = (
    "#!/bin/sh\n\n"
    "EMU_EXE=dosbox\n\n"
    "RUN=minarch\nRUN2=minarch\n"
    'CURDIR="$(dirname "$0")"\n'
    'launch_rom.sh  "$1" "$2" "$3" "$4" ${RUN} ${RUN2} "$CURDIR" "$EMU_EXE" $CPU_OC\n'
)
STANDALONE_PAK = (
    "#!/bin/sh\n"
    'if [ -f /mnt/SDCARD/Bios/NDS/drastic ]; then\n'
    '    /mnt/SDCARD/Bios/NDS/drastic "$1"\n'
    "fi\n"
)
RECIPE = (
    "CORES = gambatte dosbox # mesen\n"
    "dosbox_REPO = https://github.com/libretro/dosbox-pure.git\n"
    "dosbox_CORE = dosbox_libretro.so\n"
)
FIXTURE = {
    "workspace/all/minarch/minarch.c": MINARCH,
    "skeleton/SYSTEM/miyoomini/paks/Emus/GB.pak/launch.sh": BASE_PAK,
    "skeleton/SYSTEM/tg5040/paks/Emus/GB.pak/launch.sh": BASE_PAK,
    "skeleton/EXTRAS/Emus/tg5040/DOS.pak/launch.sh": EXTRA_PAK,
    "skeleton/EXTRAS/Emus/miyoomini/NDS.pak/launch.sh": STANDALONE_PAK,
    "workspace/tg5040/cores/makefile": RECIPE,
}


class ScraperReadsThePaks(unittest.TestCase):
    """Two paks, one per bundle, and a standalone one left out."""

    def config(self, files: dict[str, str] | None = None) -> dict:
        return minui_scraper.platform_config(
            minui_scraper.VARIANTS["minui"], "f" * 40, "2026-01-01", files or FIXTURE
        )

    def test_each_tag_is_a_folder_below_bios(self):
        dirs = self.config()["core_system_dirs"]
        self.assertEqual(sorted(dirs), ["Bios/DOS", "Bios/GB"])
        self.assertEqual(dirs["Bios/GB"]["cores"], ["gambatte"])
        self.assertEqual(dirs["Bios/GB"]["devices"], ["miyoomini", "tg5040"])
        self.assertEqual(
            dirs["Bios/GB"]["source_ref"],
            "skeleton/SYSTEM/miyoomini/paks/Emus/GB.pak/launch.sh:3",
        )

    def test_the_core_is_the_project_the_library_is_built_from(self):
        """MyMinUI builds dosbox-pure into dosbox_libretro.so: the pak's
        EMU_EXE=dosbox is DOSBox Pure, whose profile reads other files than
        the dosbox core's."""
        config = self.config()
        self.assertEqual(config["core_system_dirs"]["Bios/DOS"]["cores"], ["dosbox_pure"])
        self.assertEqual(
            config["core_repositories"]["dosbox_pure"],
            ["https://github.com/libretro/dosbox-pure"],
        )
        self.assertEqual(config["cores"], ["dosbox_pure", "gambatte"])

    def test_the_folder_rule_is_read_from_minarch(self):
        config = self.config()
        self.assertEqual(config["system_directory_ref"], "workspace/all/minarch/minarch.c:3")
        self.assertEqual(config["base_destination"], "")
        self.assertEqual(config["verification_mode"], "existence")

    def test_a_standalone_pak_is_not_a_core(self):
        dirs = self.config()["core_system_dirs"]
        self.assertNotIn("Bios/NDS", dirs)

    def test_a_named_core_started_another_way_raises(self):
        files = {**FIXTURE, "skeleton/SYSTEM/miyoomini/paks/Emus/GB.pak/launch.sh":
                 "EMU_EXE=gambatte\nretroarch -L core.so\n"}
        with self.assertRaises(ValueError):
            self.config(files)

    def test_a_moved_system_directory_raises(self):
        files = {**FIXTURE, "workspace/all/minarch/minarch.c":
                 'sprintf((char*)core.bios_dir, SDCARD_PATH "/BIOS");\n'}
        with self.assertRaises(ValueError):
            self.config(files)

    def test_the_scraper_reads_the_pinned_revision(self):
        """Tree, commit and file reads all name the same commit."""
        revision = "a" * 40
        asked: list[str] = []

        def fetch(url: str, _headers: dict[str, str] | None = None) -> bytes:
            asked.append(url)
            if url.endswith(f"git/trees/{revision}?recursive=1"):
                tree = [{"path": p, "type": "blob"} for p in FIXTURE]
                tree.append({"path": "skeleton/BASE/README.txt", "type": "blob"})
                return json.dumps({"tree": tree, "truncated": False}).encode()
            if url.endswith(f"commits/{revision}"):
                return json.dumps(
                    {"commit": {"committer": {"date": "2026-02-03T04:05:06Z"}}}
                ).encode()
            prefix = f"https://raw.githubusercontent.com/shauninman/MinUI/{revision}/"
            self.assertTrue(url.startswith(prefix), url)
            return FIXTURE[url[len(prefix):]].encode()

        scraper = minui_scraper.Scraper(
            url=f"https://github.com/shauninman/MinUI/tree/{revision}", fetch=fetch
        )
        config = scraper.generate_platform_yaml()
        self.assertEqual(config["version"], "2026-02-03")
        self.assertEqual(config["source"], f"https://github.com/shauninman/MinUI/tree/{revision}")
        self.assertNotIn(
            f"https://raw.githubusercontent.com/shauninman/MinUI/{revision}/skeleton/BASE/README.txt",
            asked,
        )


def _crc(data: bytes) -> str:
    return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")


class PackPlacesCoreFilesUnderTheTag(unittest.TestCase):
    """The pack, the report and the manifest put a core's files in each
    folder the platform hands it, and nowhere else."""

    def setUp(self):
        from common import _emulator_profiles_cache

        _emulator_profiles_cache.clear()
        self.root = tempfile.mkdtemp(dir=REPO_ROOT / "tmp" / "tests")
        self.bios = os.path.join(self.root, "bios")
        self.platforms = os.path.join(self.root, "platforms")
        self.emulators = os.path.join(self.root, "emulators")
        for folder in (self.bios, self.platforms, self.emulators):
            os.makedirs(folder)
        self.records: dict[str, dict] = {}
        self._file("Nintendo/Game Boy/gb_bios.bin", b"DMG BOOT ROM")
        # Two palettes of one name: the core's path, below its folder,
        # must still choose its own.
        self._file("Other/gambatte/palettes/default.pal", b"GAMBATTE PALETTE")
        self._file("Other/elsewhere/default.pal", b"ANOTHER PALETTE")
        self.member = b"ARCADE BIOS ROM"
        buffer = os.path.join(self.root, "arc.zip")
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("rom_a.bin", self.member)
        self._file("Arcade/arc.zip", Path(buffer).read_bytes())
        self._file("Other/unlisted/unlisted.bin", b"NOT HANDED")
        self.db = self._database()

        platform = {
            "platform": "MinUI Test",
            "version": "2025-11-27",
            "base_destination": "",
            "verification_mode": "existence",
            "cores": ["gambatte", "arcadecore", "unlisted"],
            "core_system_dirs": {
                "Bios/GB": {"cores": ["gambatte"], "source_ref": "GB.pak/launch.sh:3"},
                "Bios/GBC": {"cores": ["gambatte"], "source_ref": "GBC.pak/launch.sh:3"},
                "Bios/ARC": {"cores": ["arcade_lib"], "source_ref": "ARC.pak/launch.sh:3"},
            },
            "systems": {},
        }
        Path(self.platforms, "test_minui.yml").write_text(yaml.safe_dump(platform))
        profiles = {
            "gambatte": {
                "emulator": "Gambatte", "type": "libretro", "systems": ["nintendo-gb"],
                "files": [
                    {"name": "gb_bios.bin", "required": False},
                    {"name": "default.pal", "path": "palettes/default.pal", "required": False},
                ],
            },
            "arcadecore": {
                "emulator": "Arcade", "type": "libretro", "systems": ["arcade"],
                "cores": ["arcade_lib"], "archive_prefix": "arcadecore",
                "files": [
                    {"name": "rom_a.bin", "archive": "arc.zip", "required": True,
                     "crc32": _crc(self.member)},
                ],
            },
            "unlisted": {
                "emulator": "Unlisted", "type": "libretro", "systems": ["other"],
                "files": [{"name": "unlisted.bin", "required": True}],
            },
        }
        for key, profile in profiles.items():
            Path(self.emulators, f"{key}.yml").write_text(yaml.safe_dump(profile))

    def tearDown(self):
        shutil.rmtree(self.root)

    def _file(self, relative: str, data: bytes) -> None:
        path = os.path.join(self.bios, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_bytes(data)
        self.records[relative] = {
            "path": path,
            "name": os.path.basename(relative),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "crc32": _crc(data),
            "size": len(data),
        }

    def _database(self) -> dict:
        files, by_name, by_md5, by_crc32, by_suffix = {}, {}, {}, {}, {}
        for relative, record in self.records.items():
            sha1 = record["sha1"]
            files[sha1] = {k: v for k, v in record.items() if k != "sha1"}
            by_name.setdefault(record["name"], []).append(sha1)
            by_md5[record["md5"]] = sha1
            by_crc32[record["crc32"]] = sha1
            parts = relative.split("/")
            for start in range(len(parts) - 1):
                by_suffix.setdefault("/".join(parts[start:]), []).append(sha1)
        return {"files": files, "indexes": {
            "by_name": by_name, "by_md5": by_md5, "by_crc32": by_crc32,
            "by_path_suffix": by_suffix,
        }}

    def _pack(self) -> dict[str, bytes]:
        from generate_pack import generate_pack

        output = os.path.join(self.root, "dist")
        os.makedirs(output)
        zip_path = generate_pack(
            "test_minui", self.platforms, self.db, self.bios, output,
            emulators_dir=self.emulators, offline=True,
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as archive:
            return {
                name: archive.read(name) for name in archive.namelist()
                if name not in ("README.txt", "manifest.json")
            }

    def test_a_core_file_lands_in_every_folder_of_the_core(self):
        packed = self._pack()
        self.assertEqual(packed["Bios/GB/gb_bios.bin"], b"DMG BOOT ROM")
        self.assertEqual(packed["Bios/GBC/gb_bios.bin"], b"DMG BOOT ROM")

    def test_the_core_path_still_chooses_the_copy(self):
        packed = self._pack()
        self.assertEqual(packed["Bios/GB/palettes/default.pal"], b"GAMBATTE PALETTE")

    def test_an_archive_and_its_core_subfolder_move_with_the_folder(self):
        packed = self._pack()
        self.assertIn("Bios/ARC/arc.zip", packed)
        self.assertIn("Bios/ARC/arcadecore/arc.zip", packed)

    def test_nothing_outside_a_handed_folder(self):
        """A core no pak starts gets no folder, so none of its files."""
        packed = self._pack()
        outside = [
            name for name in packed
            if "/".join(name.split("/")[:2]) not in ("Bios/GB", "Bios/GBC", "Bios/ARC")
        ]
        self.assertEqual(outside, [])

    def test_the_same_cores_in_other_folders_make_another_pack(self):
        from common import group_identical_platforms

        twin = yaml.safe_load(Path(self.platforms, "test_minui.yml").read_text())
        twin["core_system_dirs"]["Bios/GB"]["cores"] = ["arcade_lib"]
        Path(self.platforms, "test_twin.yml").write_text(yaml.safe_dump(twin))
        groups = group_identical_platforms(["test_minui", "test_twin"], self.platforms)
        self.assertEqual(len(groups), 2)

    def test_the_report_and_the_manifest_agree_with_the_pack(self):
        from generate_pack import generate_manifest
        from verify import verify_platform

        packed = set(self._pack())
        config = load_platform_config("test_minui", self.platforms)
        profiles = load_emulator_profiles(self.emulators)
        report = verify_platform(config, self.db, self.emulators, profiles)
        self.assertEqual(set(report["pack_destinations"]), packed)
        manifest = generate_manifest(
            "test_minui", self.platforms, self.db, self.bios,
            os.path.join(self.platforms, "_registry.yml"), emulators_dir=self.emulators,
            emu_profiles=profiles, offline=True,
        )
        self.assertEqual({entry["dest"] for entry in manifest["files"]}, packed)


class PublishedPlatformsHoldTheRule(unittest.TestCase):
    """The committed files of the family, read as the tools read them."""

    FAMILY = ("minui", "nextui", "myminui")

    def test_every_core_resolves_to_a_profile_of_its_project(self):
        """A core named in core_system_dirs is the profile built from the
        repository the platform's recipe names: a library renamed from
        another project (dosbox-pure as dosbox) would hand the wrong
        profile's files to the folder."""
        from common import resolve_platform_cores

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

        def norm(url: str) -> str:
            url = str(url).strip().rstrip("/").lower()
            url = url.split("/tree/", 1)[0]
            return url[: -len(".git")] if url.endswith(".git") else url

        for platform in self.FAMILY:
            config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
            resolved = resolve_platform_cores(config, profiles)
            for core, repositories in config["core_repositories"].items():
                matches = [
                    key for key in resolved
                    if (key == core or core in [str(c) for c in profiles[key].get("cores") or []])
                    and profiles[key].get("type") not in ("alias", "launcher")
                ]
                with self.subTest(platform=platform, core=core):
                    self.assertTrue(matches, f"{core} resolves to no profile")
                    for key in matches:
                        declared = []
                        for field in ("source", "upstream"):
                            value = profiles[key].get(field)
                            declared += list(value.values()) if isinstance(value, dict) else [value]
                        self.assertTrue(
                            {norm(r) for r in repositories} & {norm(d) for d in declared if d},
                            f"{key} documents {declared}, {platform} builds {repositories}",
                        )

    def test_the_registry_detects_the_card_the_installer_reads(self):
        import install

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        rules = {
            (name, rule["file"], rule["first_line_prefix"])
            for name, entry in registry["platforms"].items()
            for rule in (entry.get("install") or {}).get("detect", [])
            if rule["method"] == "card_marker"
        }
        self.assertEqual(set(install._CARD_RULES), rules)
        self.assertEqual({name for name, _f, _p in rules}, set(self.FAMILY))


class InstallerReadsTheCard(unittest.TestCase):
    """install.py runs on the computer the card is mounted on."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" / "tests"))
        (self.root / ".system").mkdir()

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_the_release_name_names_the_frontend(self):
        import install

        for first_line, expected in (
            ("MinUI-20251127-0", "minui"),
            ("MyMinUI-20260809b-0", "myminui"),
            ("NextUI-20261020-1", "nextui"),
            ("Onion-4.3", None),
        ):
            (self.root / ".system" / "version.txt").write_text(f"{first_line}\nabc123\n")
            with self.subTest(first_line=first_line):
                self.assertEqual(install.card_platform(self.root), expected)

    def test_a_folder_inside_the_card_is_refused(self):
        """Bios/ given for the card would install into Bios/Bios/<TAG>/."""
        import install

        (self.root / ".system" / "version.txt").write_text("MinUI-20251127-0\n")
        (self.root / "Bios").mkdir()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            install.card_dest("minui", "minui", self.root / "Bios")
        self.assertEqual(install.card_dest("minui", "minui", self.root),
                         ("minui", self.root))


class TheSitePageOfACardPlatform(unittest.TestCase):
    """A platform that names no file showed "0/0 Coverage (0%)" and an empty
    systems table, which read as "not supported". Its page lists the folders
    the frontend hands its cores and the files the pack puts in each."""

    def test_folders_replace_the_empty_coverage(self):
        import generate_site
        from common import load_database, load_platform_registry
        from generate_readme import compute_coverage

        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("database.json absent")
        registry = load_platform_registry(str(REPO_ROOT / "platforms"))
        db = load_database(str(REPO_ROOT / "database.json"))
        cov = compute_coverage("minui", str(REPO_ROOT / "platforms"), db)
        page = generate_site.generate_platform_page("minui", cov, registry, {})
        self.assertNotIn("0/0", page)
        self.assertNotIn("## Systems overview", page)
        self.assertIn("| `Bios/PS/` | [pcsx_rearmed](../emulators/pcsx_rearmed.md) |", page)
        # MinUI has no release pack: no unzip row, the command instead.
        self.assertNotIn("| Unzip the pack into |", page)
        self.assertIn("No ZIP for MinUI. The command installs every file and checks it.", page)


class TheWholeTreeKeepsCoresMinUILeavesOut(unittest.TestCase):
    """Without --platform, cross_reference and the site's gap report merge
    every platform's standalone set. MinUI's per-core folders came along and
    left every core MinUI does not list with no layout: px68k showed 0 files
    and the global report lost 238 profiles."""

    def test_a_core_minui_does_not_list_keeps_its_files(self):
        from common import merged_standalone_set, platform_layouts

        minui = {"core_system_dirs": {"Bios/FC": {"cores": ["fceumm"]}}}
        retroarch = {}
        merged = merged_standalone_set([minui, retroarch])
        profile = {"type": "libretro", "files": [{"name": "cgrom.tmp"}]}
        layouts = platform_layouts("px68k", profile, merged)
        self.assertEqual(layouts, [(profile, False)])

    def test_both_readers_build_the_set_the_same_way(self):
        for script in ("cross_reference.py", "generate_site.py"):
            source = (REPO_ROOT / "scripts" / script).read_text(encoding="utf-8")
            with self.subTest(script=script):
                self.assertIn("merged_standalone_set(", source)
                self.assertNotIn("set().union(*(\n            standalone_set(", source)
                self.assertNotIn("*(standalone_set(cov", source)


if __name__ == "__main__":
    unittest.main()
