"""The installer narrows a platform the way the pack builder does.

The one-liner can install a chosen set of systems, cores and regions. It runs
without the profiles or the database, from the manifest alone, so the
manifest records each file's systems and regional competition and the
installer replays the builder's region rule. These tests hold the two ends
to one answer.
"""

from __future__ import annotations

import functools
import hashlib
import http.server
import importlib.util
import json
import os
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import region  # noqa: E402

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)


class OneRegionVocabulary(unittest.TestCase):
    """install.py cannot import region.py, so it carries a copy."""

    def test_the_copy_matches(self):
        self.assertEqual(install.REGION_TREE, dict(region.REGION_TREE))
        self.assertEqual(install.REGION_ALIASES, region.ALIASES)
        self.assertEqual(install.WORLD_REGION, region.WORLD)
        self.assertEqual(install.REGIONS, region.REGIONS)


class TheRegionRuleIsTheBuilders(unittest.TestCase):
    """Random groups, both implementations, one answer."""

    POOL = ["north-america", "europe", "japan", "uk", "canada", "brazil",
            "south-korea", "world", "asia", "oceania"]

    def _case(self, rng: random.Random):
        groups: dict[str, list[tuple[str, str]]] = {}
        index: dict[str, dict] = {}
        entries: dict[str, dict] = {}
        for g in range(rng.randint(1, 4)):
            for m in range(rng.randint(1, 5)):
                dest = f"d{g}_{m}" if rng.random() < 0.8 else f"shared{m}"
                if dest not in entries:
                    regions = (
                        set()
                        if rng.random() < 0.2
                        else set(rng.sample(self.POOL, rng.randint(1, 2)))
                    )
                    priority = rng.choice([None, None, 5, 10, 100, 200])
                    entries[dest] = {"dest": dest, "regions": sorted(regions),
                                     "region_groups": []}
                    if priority is not None:
                        entries[dest]["priority"] = priority
                    index[dest] = {"regions": regions,
                                   "has_untagged": not regions, "emulators": [],
                                   "priorities": {priority}}
                groups.setdefault(f"g{g}", []).append((dest, dest))
                if f"g{g}" not in entries[dest]["region_groups"]:
                    entries[dest]["region_groups"].append(f"g{g}")
        for entry in entries.values():
            if not entry["regions"]:
                del entry["regions"], entry["region_groups"]
                entry.pop("priority", None)
        requested = rng.sample(["north-america", "europe", "japan", "uk", "canada"],
                               rng.randint(1, 3))
        return groups, index, list(entries.values()), requested

    def test_two_thousand_random_platforms(self):
        rng = random.Random(20261010)
        for trial in range(2000):
            groups, index, entries, requested = self._case(rng)
            with self.subTest(trial=trial):
                self.assertEqual(
                    install.region_drops(entries, requested),
                    region.resolve_region_drops(groups, index, requested),
                )


class Narrowing(unittest.TestCase):
    FILES = [
        {"dest": "scph5500.bin", "size": 1, "cores": None,
         "systems": ["sony-playstation"], "regions": ["japan"],
         "region_system_groups": ["sony-playstation"]},
        {"dest": "scph5501.bin", "size": 1, "cores": None,
         "systems": ["sony-playstation"], "regions": ["north-america"],
         "region_system_groups": ["sony-playstation"]},
        {"dest": "gba_bios.bin", "size": 1, "cores": None,
         "systems": ["nintendo-gba"]},
        {"dest": "pcsx/extra.bin", "size": 1, "cores": ["pcsx_rearmed"],
         "systems": ["sony-playstation"]},
        {"dest": "beetle/extra.bin", "size": 1, "cores": ["beetle_psx"],
         "systems": ["sony-playstation"]},
    ]
    OMITTED = [
        {"dest": "scph5502.bin", "name": "scph5502.bin", "system": "sony-playstation",
         "systems": ["sony-playstation"],
         "required": True, "reason": "not_found", "cores": None,
         "regions": ["europe"], "region_system_groups": ["sony-playstation"]},
    ]

    def _dests(self, *args):
        files, omitted = install.narrow(list(self.FILES), list(self.OMITTED), *args)
        return sorted(f["dest"] for f in files), sorted(o["dest"] for o in omitted)

    def test_nothing_chosen_keeps_everything(self):
        self.assertEqual(len(self._dests([], [], [])[0]), len(self.FILES))

    def test_a_system(self):
        files, omitted = self._dests(["nintendo-gba"], [], [])
        self.assertEqual(files, ["gba_bios.bin"])
        self.assertEqual(omitted, [])

    def test_a_core_keeps_the_platform_list(self):
        files, _ = self._dests(["sony-playstation"], ["pcsx_rearmed"], [])
        self.assertEqual(files, ["pcsx/extra.bin", "scph5500.bin", "scph5501.bin"])

    def test_a_region_keeps_one_bios(self):
        files, omitted = self._dests([], [], ["north-america"])
        self.assertNotIn("scph5500.bin", files)
        self.assertIn("scph5501.bin", files)
        self.assertEqual(omitted, [])

    def test_an_unavailable_match_still_wins_as_the_builder_counts_it(self):
        files, omitted = self._dests([], [], ["europe"])
        self.assertNotIn("scph5500.bin", files)
        self.assertNotIn("scph5501.bin", files)
        self.assertEqual(omitted, ["scph5502.bin"])

    def test_no_match_keeps_every_regional_file(self):
        files, _ = self._dests([], [], ["brazil"])
        self.assertIn("scph5500.bin", files)
        self.assertIn("scph5501.bin", files)

    def test_other_holds_what_no_platform_system_owns(self):
        files = [
            {"dest": "pak0.pak", "size": 1, "cores": ["tyrquake"]},
            {"dest": "gba_bios.bin", "size": 1, "cores": None,
             "systems": ["nintendo-gba"]},
        ]
        self.assertEqual(install.available_choices(files, [])["systems"],
                         ["nintendo-gba", "other"])
        kept, _ = install.narrow(files, [], ["nintendo-gba"], [], [])
        self.assertEqual([f["dest"] for f in kept], ["gba_bios.bin"])
        kept, _ = install.narrow(files, [], ["other"], [], [])
        self.assertEqual([f["dest"] for f in kept], ["pak0.pak"])

    def test_a_core_variant_competes_across_systems(self):
        """PicoDrive files its US Mega CD BIOS under sega-segacd and the EU
        one under sega-mega-cd, one variant group. The pack groups every core
        extra before keeping a system, so under --system sega-mega-cd
        --region us the US member still wins and the EU one is dropped."""
        files = [
            {"dest": "us_scd.bin", "size": 1, "cores": ["picodrive"],
             "systems": ["sega-segacd"], "regions": ["north-america"],
             "region_groups": ["picodrive:variant:mcd"]},
            {"dest": "eu_mcd.bin", "size": 1, "cores": ["picodrive"],
             "systems": ["sega-mega-cd"], "regions": ["europe"],
             "region_groups": ["picodrive:variant:mcd"]},
            {"dest": "bios_CD_U.bin", "size": 1, "cores": None,
             "systems": ["sega-mega-cd"]},
        ]
        kept, _ = install.narrow(files, [], ["sega-mega-cd"], [], ["north-america"])
        self.assertEqual([f["dest"] for f in kept], ["bios_CD_U.bin"])

    def test_an_unkept_systems_declaration_does_not_compete(self):
        """Group `a` holds system a's own US file and a core extra filed
        under a but owned by `shared`. Under --system shared the pack builds
        group a from the extra alone: nothing matches, so the extra stays.
        Counting a's own file would make it win and drop the extra."""
        files = [
            {"dest": "a/us.bin", "size": 1, "cores": None, "systems": ["a"],
             "regions": ["north-america"], "region_system_groups": ["a"]},
            {"dest": "core/jp.bin", "size": 1, "cores": ["core"],
             "systems": ["shared"], "regions": ["japan"], "region_groups": ["a"]},
        ]
        kept, _ = install.narrow(files, [], ["shared"], [], ["north-america"])
        self.assertEqual([f["dest"] for f in kept], ["core/jp.bin"])


class CommandLineChoices(unittest.TestCase):
    KNOWN = ["msx1,msx2,msxturbor", "nintendo-gba", "sony-playstation"]

    def test_comma_lists_and_repeats(self):
        self.assertEqual(
            install.resolve_choices(["Sony-PlayStation,nintendo-gba"], self.KNOWN, "system"),
            ["sony-playstation", "nintendo-gba"],
        )

    def test_a_name_with_commas_is_one_name(self):
        self.assertEqual(
            install.resolve_choices(["msx1,msx2,msxturbor"], self.KNOWN, "system"),
            ["msx1,msx2,msxturbor"],
        )

    def test_an_unknown_name_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            install.resolve_choices(["sega-saturn"], self.KNOWN, "system")
        self.assertIn("sega-saturn", str(ctx.exception))
        self.assertIn("nintendo-gba", str(ctx.exception))

    def test_an_empty_list_is_refused(self):
        with self.assertRaises(ValueError):
            install.resolve_regions([" , "])
        with self.assertRaises(ValueError):
            install.resolve_choices([","], self.KNOWN, "system")

    def test_region_aliases_keep_their_order(self):
        self.assertEqual(
            install.resolve_regions(["jp,us", "eu,jp"]),
            ["japan", "north-america", "europe"],
        )
        with self.assertRaises(ValueError):
            install.resolve_regions(["mars"])

    def test_prompt_numbers(self):
        self.assertEqual(install.parse_selection("3,1-2", 5), [1, 2, 3])
        self.assertEqual(install.parse_selection("3,1", 5, ordered=True), [3, 1])
        self.assertEqual(install.parse_selection("all", 3), [1, 2, 3])
        for bad in ("0", "6", "4-2", "x", "1-"):
            with self.subTest(text=bad), self.assertRaises(ValueError):
                install.parse_selection(bad, 5)


class TheBoundaryChecksTheNewFields(unittest.TestCase):
    def _manifest(self, **extra):
        entry = {"dest": "a.bin", "sha1": "a" * 40, "size": 1,
                 "repo_path": "bios/a.bin", **extra}
        return {"manifest_version": 2, "platform": "retroarch", "files": [entry]}

    def test_well_formed(self):
        install._validate_manifest(
            self._manifest(systems=["x"], regions=["japan"], region_groups=["x"]),
            "retroarch",
        )

    def test_malformed(self):
        for bad in ({"systems": "x"}, {"regions": [1]}, {"region_groups": [""]},
                    {"region_system_groups": "x"}):
            with self.subTest(field=bad), self.assertRaises(ValueError):
                install._validate_manifest(self._manifest(**bad), "retroarch")


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        return


class FakeRepository:
    """A loopback copy of the repository: one manifest and its payloads."""

    PAYLOADS = {
        "scph5500.bin": (b"jp bios", ["sony-playstation"], ["japan"], None),
        "scph5501.bin": (b"us bios", ["sony-playstation"], ["north-america"], None),
        "gba_bios.bin": (b"gba bios", ["nintendo-gba"], None, None),
        "pcsx/extra.bin": (b"pcsx", ["sony-playstation"], None, ["pcsx_rearmed"]),
        "mgba/extra.bin": (b"mgba", ["nintendo-gba"], None, ["mgba"]),
    }

    def __init__(self, selection: bool = True):
        self.selection = selection

    def __enter__(self) -> FakeRepository:
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        (self.root / "install").mkdir()
        (self.root / "bios").mkdir()
        files = []
        for name, (payload, systems, regions, cores) in self.PAYLOADS.items():
            stored = name.replace("/", "_")
            (self.root / "bios" / stored).write_bytes(payload)
            entry = {
                "dest": name,
                "sha1": hashlib.sha1(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "repo_path": f"bios/{stored}",
                "cores": cores,
            }
            if self.selection:
                entry["systems"] = systems
                if regions:
                    entry.update(regions=regions, region_system_groups=systems)
            files.append(entry)
        manifest = {"manifest_version": 2, "platform": "retroarch", "files": files}
        (self.root / "install" / "retroarch.json").write_text(json.dumps(manifest))
        handler = functools.partial(_QuietHandler, directory=str(self.root))
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.dest = self.root / "dest"
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.root, ignore_errors=True)

    def env(self) -> dict:
        env = dict(os.environ)
        env["RETROBIOS_BASE_URL"] = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return env

    def command(self, *options: str) -> list[str]:
        return [sys.executable, str(REPO_ROOT / "install.py"), "--platform",
                "retroarch", "--dest", str(self.dest), *options]

    def run(self, *options: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.command(*options), env=self.env(), capture_output=True,
            text=True, timeout=60, check=False, stdin=subprocess.DEVNULL,
        )

    def installed(self) -> list[str]:
        if not self.dest.exists():
            return []
        return sorted(
            p.relative_to(self.dest).as_posix()
            for p in self.dest.rglob("*") if p.is_file()
        )


class TheOneLinerNarrows(unittest.TestCase):
    def test_options_install_only_the_choice(self):
        with FakeRepository() as repo:
            proc = repo.run("--system", "sony-playstation", "--region", "us")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("Narrowed 5 -> 2 files", proc.stdout)
            self.assertEqual(repo.installed(), ["pcsx/extra.bin", "scph5501.bin"])

    def test_a_core_choice_keeps_the_platform_list(self):
        with FakeRepository() as repo:
            proc = repo.run("--core", "mgba")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(
                repo.installed(),
                ["gba_bios.bin", "mgba/extra.bin", "scph5500.bin", "scph5501.bin"],
            )

    def test_an_older_file_list_is_refused_not_ignored(self):
        """Without the fields, a region filter would match nothing and the
        run would install everything while the user asked for one region."""
        with FakeRepository(selection=False) as repo:
            proc = repo.run("--region", "us")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("records no systems or regions", proc.stderr)
            self.assertEqual(repo.installed(), [])

    def test_empty_names_are_a_usage_error(self):
        with FakeRepository() as repo:
            for option in (["--region", " , "], ["--system", ""], ["--core", ","]):
                with self.subTest(option=option):
                    proc = repo.run(*option)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertIn("needs at least one", proc.stderr)

    def test_listing_follows_the_narrowing(self):
        with FakeRepository() as repo:
            proc = repo.run("--list-cores", "--system", "nintendo-gba")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("mgba", proc.stdout)
            self.assertNotIn("pcsx_rearmed", proc.stdout)

    def test_an_unknown_system_is_refused_before_any_download(self):
        with FakeRepository() as repo:
            proc = repo.run("--system", "sega-saturn")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("unknown system: sega-saturn", proc.stderr)
            self.assertIn("nintendo-gba", proc.stderr)
            self.assertEqual(repo.installed(), [])

    def test_an_unknown_region_is_a_usage_error(self):
        with FakeRepository() as repo:
            proc = repo.run("--region", "mars")
            self.assertEqual(proc.returncode, 2)
            self.assertIn("unknown region: mars", proc.stderr)

    def test_listing_systems_installs_nothing(self):
        with FakeRepository() as repo:
            proc = repo.run("--list-systems")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("nintendo-gba", proc.stdout)
            self.assertIn("3 files", proc.stdout)
            self.assertEqual(repo.installed(), [])

    def test_no_terminal_asks_nothing_and_installs_everything(self):
        with FakeRepository() as repo:
            proc = repo.run()
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("choose systems", proc.stdout)
            self.assertEqual(len(repo.installed()), 5)

    @unittest.skipUnless(shutil.which("script"), "script(1) provides the terminal")
    def test_the_custom_mode_at_a_terminal(self):
        """Typed answers: customise, PlayStation only, no core, US first."""
        with FakeRepository() as repo:
            command = " ".join(shlex.quote(part) for part in repo.command())
            proc = subprocess.run(
                ["script", "-qec", command, "/dev/null"],
                input="c\n2\n\n2\n", env=repo.env(), capture_output=True,
                text=True, timeout=60, check=False,
            )
            out = proc.stdout
            self.assertEqual(proc.returncode, 0, out + proc.stderr)
            self.assertIn("choose systems, cores and regions", out)
            self.assertIn("pcsx_rearmed", out)
            self.assertIn("--system sony-playstation --region north-america", out)
            self.assertEqual(repo.installed(), ["pcsx/extra.bin", "scph5501.bin"])

    @unittest.skipUnless(shutil.which("script"), "script(1) provides the terminal")
    def test_enter_installs_everything_at_a_terminal(self):
        with FakeRepository() as repo:
            command = " ".join(shlex.quote(part) for part in repo.command())
            proc = subprocess.run(
                ["script", "-qec", command, "/dev/null"],
                input="\n", env=repo.env(), capture_output=True,
                text=True, timeout=60, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(len(repo.installed()), 5)

    @unittest.skipUnless(shutil.which("script"), "script(1) provides the terminal")
    def test_no_input_asks_nothing_at_a_terminal(self):
        with FakeRepository() as repo:
            command = " ".join(
                shlex.quote(part) for part in repo.command("--no-input")
            )
            proc = subprocess.run(
                ["script", "-qec", command, "/dev/null"],
                input="", env=repo.env(), capture_output=True,
                text=True, timeout=60, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("choose systems", proc.stdout)
            self.assertEqual(len(repo.installed()), 5)


class InstallMatchesThePack(unittest.TestCase):
    """Narrowing the full manifest gives what the narrowed build carries."""

    PLATFORM = "recalbox"

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        import generate_pack as gp
        from common import load_emulator_profiles

        cls.gp = gp
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cls.full = cls._manifest(None)

    @classmethod
    def _manifest(cls, regions):
        return cls.gp.generate_manifest(
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
    PicoDrive's Mega CD variant group spread over two systems."""

    PLATFORM = "retroarch"
    CASES = (
        (["coleco-colecovision"], []),
        (["sega-mega-cd"], ["north-america"]),
        (["sony-playstation"], ["japan"]),
    )

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        import generate_pack as gp
        from common import load_emulator_profiles, load_platform_config

        cls.gp = gp
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cls.base = load_platform_config(
            cls.PLATFORM, str(REPO_ROOT / "platforms")
        ).get("base_destination", "")
        cls.full = gp.generate_manifest(
            cls.PLATFORM, str(REPO_ROOT / "platforms"), cls.db,
            str(REPO_ROOT / "bios"), str(REPO_ROOT / "platforms" / "_registry.yml"),
            emulators_dir=str(REPO_ROOT / "emulators"), emu_profiles=cls.profiles,
            offline=True,
        )

    def _packed(self, systems, regions) -> set[str]:
        import zipfile

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as out:
            zip_path = self.gp.generate_pack(
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


if __name__ == "__main__":
    unittest.main()
