"""install/games/: what the games-on-card mode reads, built from fixtures.

Profiles and platform files are the repository's own (read only). The rom
folders, the install list, the catalogs and the arcade index are fixtures,
so a test pins the join and not the state of the data.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import generate_games_index as gi  # noqa: E402
from romfolders import SystemResolver, load_setups  # noqa: E402

SETUP = """\
setup: fixture
name: Fixture OS
platform: fixtureplat
sources:
  os: {repo: https://github.com/example/os, commit: 0123456789abcdef0123456789abcdef01234567}
roms_root: {path: /storage/roms, from_bios: ../roms, source_ref: os main.c:12}
case_sensitive: true
skip:
- {name: bios, source_ref: os main.c:20}
folders:
- {folder: psx, extensions: [.cue, .chd], core: mednafen_psx_hw, source_ref: os es_systems.cfg:10,
   board_defaults: {rpi1: {core: pcsx_rearmed}}}
- {folder: mame, extensions: [.zip], core: mame, arcade: true, source_ref: os es_systems.cfg:30}
- {folder: zzunknownzz, extensions: [.bin], core: nosuchcore, source_ref: os es_systems.cfg:40}
"""

MANIFEST = {
    "platform": "fixtureplat",
    "core_names": {"beetle_psx": ["mednafen_psx_hw"]},
    "files": [
        {"dest": "scph5501.bin", "size": 524288, "cores": None, "systems": ["sony-playstation"]},
        {"dest": "psxonpsp660.bin", "size": 524288, "cores": ["beetle_psx"]},
        {"dest": "neogeo.zip", "size": 1000, "cores": ["mame"]},
        {"dest": "other.bin", "size": 7, "cores": ["snes9x"]},
    ],
    "omitted_files": [],
}

CATALOG = {
    "source": "no-intro",
    "system": "sony-playstation",
    "dat": "Fixture",
    "version": "1",
    "fetched_from": "https://example.org/x.zip",
    "licence": {"quote": "free"},
    "fields": ["crc32", "size", "sha1", "region", "title", "serials"],
    "regions": [["japan"], ["north-america"]],
    "games": [
        ["ffffffff", 10, "aa", 1, "B (USA)", ["SLUS-00001"]],
        ["00000001", 20, "bb", 0, "A (Japan)", ["SLPS-00001"]],
    ],
}

ARCADE = {"profile": "mame", "bios": {"neogeo": ["mslug"]}}


class GamesIndexFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        (self.tmp / "romfolders").mkdir()
        (self.tmp / "romfolders" / "fixture.yml").write_text(SETUP, encoding="utf-8")
        (self.tmp / "install").mkdir()
        (self.tmp / "install" / "fixtureplat.json").write_text(json.dumps(MANIFEST), encoding="utf-8")
        catalogs = self.tmp / "games" / "catalogs" / "no-intro"
        catalogs.mkdir(parents=True)
        (catalogs / "sony-playstation.json").write_text(json.dumps(CATALOG), encoding="utf-8")
        (self.tmp / "games" / "arcade").mkdir()
        (self.tmp / "games" / "arcade" / "mame.json").write_text(json.dumps(ARCADE), encoding="utf-8")
        self.inputs = gi.Inputs(
            games=self.tmp / "games",
            romfolders=self.tmp / "romfolders",
            install=self.tmp / "install",
            emulators=str(ROOT / "emulators"),
            platforms=str(ROOT / "platforms"),
        )
        # The fixture platform has no YAML of its own.
        original = gi._platform_required
        gi._platform_required = lambda platform, platforms_dir: {}
        self.addCleanup(setattr, gi, "_platform_required", original)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def render(self) -> tuple[dict[Path, str], dict]:
        return gi.render(self.tmp / "out", self.inputs)

    def doc(self, files: dict[Path, str], rel: str) -> dict:
        return json.loads(files[self.tmp / "out" / rel])

    def test_two_runs_write_the_same_bytes(self) -> None:
        first, _ = self.render()
        second, _ = self.render()
        self.assertEqual(first, second)

    def test_folders_resolve_to_systems_and_profiles(self) -> None:
        files, coverage = self.render()
        folders = {f["folder"]: f for f in self.doc(files, "setups/fixture.json")["folders"]}
        self.assertEqual(folders["psx"]["systems"], ["sony-playstation"])
        self.assertEqual(folders["psx"]["profile"], "beetle_psx")
        self.assertEqual(folders["mame"]["arcade"], "mame")
        self.assertEqual(folders["zzunknownzz"]["systems"], [])
        self.assertEqual(folders["zzunknownzz"]["basis"], "unresolved")
        self.assertEqual(coverage["setups"]["fixture"]["resolved"], 2)

    def test_fallback_keeps_platform_and_default_core_files_of_the_system(self) -> None:
        files, _ = self.render()
        table = self.doc(files, "fallback/fixtureplat.json")
        chosen = table["sets"]["sony-playstation|beetle_psx"]
        kept = [table["files"][i][0] for i in chosen["files"]]
        self.assertEqual(kept, ["psxonpsp660.bin", "scph5501.bin"])
        self.assertEqual(chosen["bytes"], 2 * 524288)

    def test_a_board_default_core_has_its_own_fallback_set(self) -> None:
        files, _ = self.render()
        folders = {f["folder"]: f for f in self.doc(files, "setups/fixture.json")["folders"]}
        board = folders["psx"]["board_defaults"]["rpi1"]
        self.assertEqual(board["profile"], "pcsx_rearmed")
        self.assertEqual(board["fallback"], ["sony-playstation|pcsx_rearmed"])
        table = self.doc(files, "fallback/fixtureplat.json")
        self.assertIn("sony-playstation|pcsx_rearmed", table["sets"])

    def test_index_names_the_systems_of_every_folder_name(self) -> None:
        files, _ = self.render()
        folders = self.doc(files, "index.json")["folders"]
        self.assertEqual(folders["psx"], ["sony-playstation"])
        self.assertEqual(folders["sony-playstation"], ["sony-playstation"])
        self.assertNotIn("zzunknownzz", folders)

    def test_catalog_rows_are_published_sorted_with_serials(self) -> None:
        files, _ = self.render()
        system = self.doc(files, "systems/sony-playstation.json")
        games = system["identify"]["games"]
        self.assertEqual([g[0] for g in games], ["00000001", "ffffffff"])
        regions = system["identify"]["regions"]
        self.assertEqual(regions[games[0][2]], ["japan"])
        self.assertEqual(
            [regions[i] for i in system["identify"]["serials"]["SLUS-00001"]], [["north-america"]]
        )
        self.assertEqual(system["identify"]["sources"][0]["licence"], {"quote": "free"})

    def test_index_lists_every_file_with_size_and_digest(self) -> None:
        files, _ = self.render()
        index = self.doc(files, "index.json")
        listed = {
            entry["file"] for kind in ("setups", "fallback", "systems", "arcade")
            for entry in index[kind].values()
        }
        written = {p.relative_to(self.tmp / "out").as_posix() for p in files} - {"index.json"}
        self.assertEqual(listed, written)
        for kind in ("setups", "systems"):
            for entry in index[kind].values():
                text = files[self.tmp / "out" / entry["file"]].encode()
                self.assertEqual(entry["size"], len(text))
                self.assertLess(entry["gzip_size"], entry["size"] + 64)
        self.assertEqual(len(index["data_version"]), 16)

    def test_floor_names_what_fell_short(self) -> None:
        _, coverage = self.render()
        failures = gi.floor_failures(coverage)
        self.assertTrue(any("catalog" in f for f in failures))


class CheckSaysWhatDiffers(unittest.TestCase):
    """--check printed STALE and a path after 120 lines of coverage: the
    reader had to diff single-line JSON of 550 KB by hand to find that a
    manifest had gained one file."""

    def test_an_added_file_is_named(self) -> None:
        old = json.dumps({"files": [["a.bin", 1, "bios"]], "version": 1})
        new = json.dumps({"files": [["a.bin", 1, "bios"], ["ide12.rom", 16384, "bios"]],
                          "version": 1})
        lines = gi.describe_change(old, new)
        self.assertEqual(len(lines), 1)
        self.assertIn("1 added", lines[0])
        self.assertIn("ide12.rom", lines[0])

    def test_new_and_unreadable_documents(self) -> None:
        self.assertEqual(gi.describe_change(None, "{}"), ["not written yet"])
        self.assertIn("not valid JSON", gi.describe_change("{", "{}")[0])

    def test_check_names_the_command_and_skips_coverage(self) -> None:
        import contextlib
        import io
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = out / "index.json"
            target.write_text(json.dumps({"files": []}), encoding="utf-8")
            files = {target: json.dumps({"files": [["x.rom", 2, "bios"]]})}
            coverage = {"setups": {}, "systems": {}, "arcade": []}
            stdout, stderr = io.StringIO(), io.StringIO()
            argv = ["generate_games_index.py", "--check", "--output-dir", tmp]
            with mock.patch.object(gi, "render", return_value=(files, coverage)), \
                    mock.patch.object(sys, "argv", argv), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = gi.main()
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("files: 1 added", stderr.getvalue())
        self.assertIn("python scripts/generate_games_index.py", stderr.getvalue())


class CommittedData(unittest.TestCase):
    """The data the repository publishes."""

    def test_published_files_are_current(self) -> None:
        if not (ROOT / "install" / "games" / "index.json").exists():
            self.skipTest("install/games/ not generated")
        import subprocess

        result = subprocess.run(
            [sys.executable, "scripts/generate_games_index.py", "--check", "--quiet"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])

    def test_every_folder_name_resolves_or_is_counted(self) -> None:
        setups = load_setups(ROOT / "platforms" / "romfolders")
        if not setups:
            self.skipTest("no setup scraped")
        from common import load_emulator_profiles
        from romfolders import ProfileResolver

        resolver = SystemResolver.from_repo(str(ROOT / "emulators"), str(ROOT / "platforms"))
        cores = ProfileResolver.from_repo(str(ROOT / "emulators"))
        profiles = gi.Profiles(load_emulator_profiles(str(ROOT / "emulators")), resolver)
        total = unresolved = 0
        for doc in setups.values():
            for row in doc["folders"]:
                total += 1
                profile = cores.resolve(row.get("core"))
                if not gi.resolve_folder(row, doc["platform"], profile, resolver, profiles).systems:
                    unresolved += 1
        self.assertGreaterEqual((total - unresolved) / total, gi.FLOORS["folders_resolved_share"])

    def test_a_folder_holds_a_machine_its_core_runs(self) -> None:
        """muOS names its GBA folder gameboyadvance first: it resolved to
        ares's game-boy-advance, which mgba does not list, and an
        unrecognised GBA game got none of the nintendo-gba files. A CD
        folder run by mednafen_pce_fast, which lists nec-pc-engine, got no
        System Card."""
        from common import load_emulator_profiles
        from romfolders import ProfileResolver, folder_names

        setups = load_setups(ROOT / "platforms" / "romfolders")
        if not setups:
            self.skipTest("no setup scraped")
        resolver = SystemResolver.from_repo(str(ROOT / "emulators"), str(ROOT / "platforms"))
        cores = ProfileResolver.from_repo(str(ROOT / "emulators"))
        loaded = load_emulator_profiles(str(ROOT / "emulators"))
        profiles = gi.Profiles(loaded, resolver)
        arcade = gi._arcade_profiles(ROOT / "games" / "arcade")
        apart = []
        for key, doc in sorted(setups.items()):
            for row in doc["folders"]:
                profile = cores.resolve(row.get("core"))
                if not profile or profile in arcade:
                    continue
                runs = {sid for s in loaded[profile].get("systems") or []
                        for sid in resolver.equivalents(str(s))}
                systems = gi.resolve_folder(row, doc["platform"], profile, resolver,
                                            profiles, arcade).systems
                if runs and systems and not runs & set(systems):
                    apart.append(f"{key}/{row['folder']} {systems} by {profile}")
        self.assertEqual(apart, [])
        muos = next(row for row in setups["muos"]["folders"]
                    if row["folder"] == "nintendogameboyadvance")
        self.assertIn("gameboyadvance", folder_names(muos))
        self.assertEqual(
            gi.resolve_folder(muos, "retroarch", "mgba", resolver, profiles, arcade).systems,
            ["nintendo-gba"])

    def test_an_unrecognised_gba_game_on_muos_gets_the_gba_bios(self) -> None:
        index = ROOT / "install" / "games"
        if not (index / "index.json").exists():
            self.skipTest("install/games/ not generated")
        setup = json.loads((index / "setups" / "muos.json").read_text())
        row = next(r for r in setup["folders"] if r["folder"] == "nintendogameboyadvance")
        self.assertEqual(row["systems"], ["nintendo-gba"])
        table = json.loads((index / "fallback" / "retroarch.json").read_text())
        dests = {table["files"][i][0] for key in row["fallback"]
                 for i in table["sets"][key]["files"]}
        self.assertIn("gba_bios.bin", dests)

    def test_a_folder_of_a_several_machine_core_holds_its_machines(self) -> None:
        from common import load_emulator_profiles

        resolver = SystemResolver.from_repo(str(ROOT / "emulators"), str(ROOT / "platforms"))
        profiles = gi.Profiles(load_emulator_profiles(str(ROOT / "emulators")), resolver)
        thomson = gi.resolve_folder({"folder": "thomson"}, "recalbox", "theodore", resolver, profiles)
        self.assertIn("thomson-to8", thomson.systems)
        self.assertEqual(thomson.basis, "systems of theodore")
        lcd = gi.resolve_folder({"folder": "lcdgames"}, "batocera", "mame", resolver, profiles, {"mame"})
        self.assertEqual(lcd.systems, [])


# The cores the setups name that resolve to no profile, each with why. A
# folder of one of these keeps the files of every core of its systems. ArkOS
# ran the GBA with gpsp_ezode_mod, which resolved to nothing: the card got
# the files of every GBA core, FBNeo's 3,472 data files among them.
KNOWN_UNRESOLVED = {
    # Not an emulator: a frontend, a shell, a player, a launcher, a store.
    **dict.fromkeys(["crisp game lib", "exodos", "external", "ffplay", "flatpak", "gmloader",
                     "heroic", "idtech", "libretro", "mplayer", "mreader landscape", "mugen",
                     "native", "odcommander", "os-shell", "port", "portmaster", "ports",
                     "powerbomberman", "quiverlauncher", "sh", "steam", "vaixterm", "wasabi",
                     "windows", "wine", "wine-tkg"], "not an emulator"),
    # A launcher mode or an argument: the program depends on the folder.
    **dict.fromkeys(["standalone", "standalone-2021", "standalone-nobios",
                     "standalone-pirry-nobios", "standalone-r7", "standalone-vulkan", "Normal",
                     "coco3", "dragon32"], "launcher mode, the program depends on the folder"),
    # An emulator no profile documents yet.
    **dict.fromkeys(["exa", "gloopy", "gp32emu", "km_ludicrousn64_2k22_xtreme_amped",
                     "libgametank", "ludicrousn64_xtreme32", "mametiger", "memu", "onscripter-sa",
                     "ryubing", "zc250x"], "no profile yet"),
    # The program's profile declares no system of the folder, or the folder
    # has none: MAME documents no GameKing ROM.
    **dict.fromkeys(["gameking", "gamekin3", "ctvboy", "gaelco", "namco3xx"],
                    "the program's profile lacks the system"),
    # Not settled: two builds by host, a binary the OS tree lacks, a fork
    # whose required files differ, a shell variable the scraper kept.
    **dict.fromkeys(["pcsx2-nogui", "zx81", "reicast-audio-${backend}"],
                    "not proven"),
}


class EveryCoreResolvesOrIsExplained(unittest.TestCase):
    def setUp(self) -> None:
        from common import load_emulator_profiles
        from romfolders import ProfileResolver

        self.resolver = SystemResolver.from_repo(str(ROOT / "emulators"), str(ROOT / "platforms"))
        self.cores = ProfileResolver.from_repo(str(ROOT / "emulators"))
        self.profiles = gi.Profiles(load_emulator_profiles(str(ROOT / "emulators")), self.resolver)

    def profile(self, row: dict, platform: str) -> str | None:
        return (self.cores.resolve(row.get("core"))
                or gi.emulator_profile(row, platform, self.cores, self.resolver, self.profiles))

    def test_either_separator_resolves(self) -> None:
        self.assertEqual(self.cores.resolve("flycast_xtreme"), "flycast2021")

    def test_a_mode_resolves_by_its_program_when_it_runs_the_system(self) -> None:
        hikaru = {"folder": "hikaru", "core": "hikaru", "emulator": "demul", "systems": ["sega-hikaru"]}
        self.assertEqual(self.profile(hikaru, "retrobat"), "demul")
        # MAME runs the GameKing, but its profile documents no GameKing ROM:
        # answering MAME would leave the ROM out.
        gameking = {"folder": "gameking", "core": "gameking", "emulator": "mame"}
        self.assertIsNone(self.profile(gameking, "amberelec"))
        launcher = {"folder": "doom", "core": "standalone", "emulator": "standalone"}
        self.assertIsNone(self.profile(launcher, "arkos"))

    def test_no_core_is_left_unexplained(self) -> None:
        setups = load_setups(ROOT / "platforms" / "romfolders")
        if not setups:
            self.skipTest("no setup scraped")
        unexplained = sorted({
            str(row["core"]) for doc in setups.values() for row in doc["folders"]
            if row.get("core") and not self.profile(row, doc["platform"])
            and str(row["core"]) not in KNOWN_UNRESOLVED
        })
        self.assertEqual(unexplained, [], "map each to its profile (cores:) or record why it has none")
        # And no reason outlives its row: a core mapped since leaves the list.
        still = {str(row["core"]) for doc in setups.values() for row in doc["folders"]
                 if row.get("core") and not self.profile(row, doc["platform"])}
        self.assertEqual(sorted(set(KNOWN_UNRESOLVED) - still), [])


class OneNarrowingPerCoreList(unittest.TestCase):
    """Each (platform, system, core) key narrowed the whole install list:
    2,357 narrowings for 1,289 distinct core lists."""

    def test_the_systems_of_one_core_share_it(self) -> None:
        from unittest import mock

        manifest = {"files": [{"dest": "dir/SCPH5501.BIN"}, {"dest": "b.rom"}]}
        cache: dict = {}
        with mock.patch.object(gi.install, "narrow",
                               return_value=(manifest["files"], [])) as narrow:
            for _system in ("sony-playstation", "sony-playstation-2"):
                rows = gi._narrowed(manifest, ["core"], cache)
            gi._narrowed(manifest, ["other"], cache)
        self.assertEqual(narrow.call_count, 2)
        self.assertEqual([base for _entry, base in rows], ["scph5501.bin", "b.rom"])


if __name__ == "__main__":
    unittest.main()
