"""The installer narrows a platform the way the pack builder does.

The one-liner can install a chosen set of systems, cores and regions. It runs
without the profiles or the database, from the manifest alone, so the
manifest records each file's systems and regional competition and the
installer replays the builder's region rule. These tests hold the two ends
to one answer.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import functools
import hashlib
import http.server
import importlib.util
import io
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
from unittest import mock
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
        self.assertEqual(install.AREA_TERRITORIES, dict(region.AREA_TERRITORIES))
        self.assertEqual(install.REGION_ALIASES, region.ALIASES)
        self.assertEqual(install.WORLD_REGION, region.WORLD)
        self.assertEqual(install.REGIONS, region.REGIONS)
        self.assertEqual(install.FILE_GROUP, region.FILE_GROUP)


class TheRegionRuleIsTheBuilders(unittest.TestCase):
    """Random groups, both implementations, one answer."""

    POOL = ["north-america", "europe", "japan", "uk", "canada", "brazil",
            "south-korea", "world", "asia", "oceania", "taiwan", "asia-ntsc",
            "china", "asia-pal"]

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
                # A lone core file no system names gets a group of its own.
                group = f"g{g}" if rng.random() < 0.85 else f"e{region.FILE_GROUP}{dest}"
                groups.setdefault(group, []).append((dest, dest))
                if group not in entries[dest]["region_groups"]:
                    entries[dest]["region_groups"].append(group)
        for entry in entries.values():
            if not entry["regions"]:
                del entry["regions"], entry["region_groups"]
                entry.pop("priority", None)
        requested = rng.sample(["north-america", "europe", "japan", "uk", "canada",
                                "taiwan", "asia-ntsc", "china", "asia-pal"],
                               rng.randint(1, 3))
        held = {dest for dest in entries if rng.random() < 0.7}
        return groups, index, list(entries.values()), requested, held

    def test_two_thousand_random_platforms(self):
        rng = random.Random(20261010)
        for trial in range(2000):
            groups, index, entries, requested, held = self._case(rng)
            with self.subTest(trial=trial):
                self.assertEqual(
                    install.region_drops(entries, requested),
                    region.resolve_region_drops(groups, index, requested),
                )
                self.assertEqual(
                    install.region_drops(entries, requested, held=held),
                    region.resolve_region_drops(groups, index, requested, held),
                )

    def test_narrow_passes_the_installable_files_as_held(self):
        """The builder passes what the collection holds (generate_pack
        _select_variants). An omission is the installer's unheld file."""
        rng = random.Random(20261021)
        for trial in range(500):
            groups, index, entries, requested, held = self._case(rng)
            files = [dict(e, size=1, cores=None) for e in entries if e["dest"] in held]
            omitted = [dict(e, cores=None) for e in entries if e["dest"] not in held]
            kept, still_omitted = install.narrow(files, omitted, [], [], requested)
            drops = region.resolve_region_drops(groups, index, requested, held)
            with self.subTest(trial=trial):
                self.assertEqual(
                    {f["dest"] for f in kept},
                    {f["dest"] for f in files} - drops,
                )
                self.assertEqual(
                    {o["dest"] for o in still_omitted},
                    {o["dest"] for o in omitted} - drops,
                )

    def test_narrow_counts_what_the_builder_holds(self):
        """A file the builder holds and the installer cannot download sits in
        omitted_files. Counted unheld, it left the installer a fallback the
        pack drops. The manifest marks it held, and narrow replays the
        builder's held set: installable files plus held omissions."""
        rng = random.Random(20261021)
        replayed = 0
        for trial in range(500):
            groups, index, entries, requested, held = self._case(rng)
            pack_only = {dest for dest in held if rng.random() < 0.3}
            files = [dict(e, size=1, cores=None) for e in entries
                     if e["dest"] in held - pack_only]
            omitted = [dict(e, cores=None, **({"held": True} if e["dest"] in pack_only else {}))
                       for e in entries if e["dest"] not in held - pack_only]
            kept, still_omitted = install.narrow(files, omitted, [], [], requested)
            drops = region.resolve_region_drops(groups, index, requested, held)
            unheld = region.resolve_region_drops(
                groups, index, requested, held - pack_only
            )
            replayed += drops != unheld
            with self.subTest(trial=trial):
                self.assertEqual(
                    {f["dest"] for f in kept},
                    {f["dest"] for f in files} - drops,
                )
                self.assertEqual(
                    {o["dest"] for o in still_omitted},
                    {o["dest"] for o in omitted} - drops,
                )
        # The cases where counting them unheld answers otherwise exist.
        self.assertGreater(replayed, 0)

    def test_the_held_flag_is_checked_at_the_boundary(self):
        entry = {"name": "a.bin", "system": "s", "required": True,
                 "reason": "not_found", "cores": None}
        install._check_omission({**entry, "held": True}, "a.bin")
        with self.assertRaises(ValueError):
            install._check_omission({**entry, "held": "yes"}, "a.bin")

    def test_a_lone_core_file_leaves_its_systems_drop(self):
        """Dolphin's GC/EUR/IPL.bin is a core extra no system names, plus the
        GameCube's own declaration. The builder skips the one-file group, so
        --region us drops it."""
        entries = [
            {"dest": "GC/USA/IPL.bin", "regions": ["north-america"],
             "region_system_groups": ["nintendo-gamecube"]},
            {"dest": "GC/EUR/IPL.bin", "regions": ["europe"],
             "region_groups": [f"dolphin{region.FILE_GROUP}GC/EUR/IPL.bin"],
             "region_system_groups": ["nintendo-gamecube"]},
        ]
        self.assertEqual(
            install.region_drops(entries, ["north-america"]), {"GC/EUR/IPL.bin"}
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

    def test_an_unavailable_match_never_displaces_a_held_file(self):
        """The builder keeps the held BIOS when the requested one is missing
        (region.resolve_region_drops, held). The missing one stays reported."""
        files, omitted = self._dests([], [], ["europe"])
        self.assertIn("scph5500.bin", files)
        self.assertIn("scph5501.bin", files)
        self.assertEqual(omitted, ["scph5502.bin"])

    def test_a_missing_japanese_bios_keeps_the_american_one(self):
        files = [dict(self.FILES[1])]
        omitted = [dict(self.OMITTED[0], dest="scph5500.bin", regions=["japan"])]
        kept, still = install.narrow(files, omitted, [], [], ["japan"])
        self.assertEqual([f["dest"] for f in kept], ["scph5501.bin"])
        self.assertEqual([o["dest"] for o in still], ["scph5500.bin"])

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

    def test_a_short_name_is_suggested_never_taken(self):
        """`--system gba`, `psx` and `ps1` were refused on RetroArch with no
        suggestion, though nintendo-gba holds the very letters."""
        known = [f"system-{i}" for i in range(40)] + [
            "nintendo-gb", "nintendo-gba", "nintendo-gbc", "sony-playstation",
            "sony-playstation-2", "sega-mega-drive"]
        for typed, meant in (("gba", "nintendo-gba"), ("psx", "sony-playstation"),
                             ("ps1", "sony-playstation"), ("PS2", "sony-playstation-2"),
                             ("genesis", "sega-mega-drive"), ("gb", "nintendo-gb")):
            with self.subTest(typed=typed), self.assertRaises(ValueError) as ctx:
                install.resolve_choices([typed], known, "system")
            self.assertIn(f"Close matches: {meant}", str(ctx.exception))

    def test_a_short_name_for_a_system_the_list_lacks_is_not_suggested(self):
        with self.assertRaises(ValueError) as ctx:
            install.resolve_choices(["psx"], [f"system-{i}" for i in range(40)], "system")
        self.assertNotIn("sony-playstation", str(ctx.exception))

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


class DecliningTheSizePointsAtTheChoice(unittest.TestCase):
    """Saying no to `Download 8.4 GB?` printed "--system, --core and
    --region install less (see --help)": a 91-line help for someone who had
    just passed the c entry that does it."""

    def _run(self, answers: list[str], *options: str) -> str:
        replies = iter(answers)
        out = io.StringIO()
        # main() on a WSL host reads the Windows variables through cmd.exe
        # and sets them in os.environ: restored here, they leaked into every
        # later test (USERPROFILE added a Scoop folder to detection).
        with FakeRepository() as repo, mock.patch.dict(os.environ), \
                mock.patch.object(sys, "argv", ["install.py", "--platform", "retroarch",
                                                "--dest", str(repo.dest), *options]), \
                mock.patch.object(install, "MANIFEST_URL",
                                  repo.env()["RETROBIOS_BASE_URL"] + "/install/{platform}.json"), \
                mock.patch.object(install, "RAW_FILE_URL",
                                  repo.env()["RETROBIOS_BASE_URL"] + "/{path}"), \
                mock.patch.object(install, "CONFIRM_FROM_BYTES", 1), \
                mock.patch("sys.stdin", mock.Mock(isatty=lambda: True)), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch("builtins.input", lambda _prompt="": next(replies)), \
                contextlib.redirect_stdout(out):
            try:
                install.main()
            except SystemExit:
                pass
            self.assertEqual(repo.installed(), [])
        return out.getvalue()

    def test_install_everything_then_no_names_the_c_entry(self):
        out = self._run(["", "n"])
        self.assertIn("type c at the first question", out)
        self.assertNotIn("see --help", out)

    def test_options_given_keep_the_option_advice(self):
        # The menu is shown with --system too: Enter keeps it.
        out = self._run(["", "n"], "--system", "sony-playstation")
        self.assertIn("--system, --core and --region install less", out)


class ACoreWithNoFileOfItsOwn(unittest.TestCase):
    """pcsx_rearmed, swanstation and pcsx1 showed `0 files, 0 B` in the
    cores step and in --list-cores, which reads as "this core gets nothing":
    their files are the platform's own, which are always kept."""

    FILES = [
        {"dest": "scph5501.bin", "size": 5, "cores": None, "systems": ["sony-playstation"],
         "declared_choices": [], "slot_choices": [{"cores": ["pcsx_rearmed"]}]},
        {"dest": "ps2.bin", "size": 9, "cores": ["duckstation"],
         "systems": ["sony-playstation"]},
    ]

    def _line(self, out: str, core: str) -> str:
        return next(line for line in out.splitlines() if line.strip().startswith(core)
                    or f") {core}" in line)

    def test_the_listing_says_its_files_are_the_platforms(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            install._print_choices("retroarch", self.FILES, [], systems=False)
        line = self._line(out.getvalue(), "pcsx_rearmed")
        self.assertNotIn("0 files", line)
        self.assertIn("always kept", line)
        self.assertIn("1 file, 9 B", self._line(out.getvalue(), "duckstation"))

    def test_the_cores_step_says_so_too(self):
        answers = iter(["c", "", "", ""])
        out = io.StringIO()
        with mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            install._prompt_custom_selection("retroarch", self.FILES, [])
        line = self._line(out.getvalue(), "pcsx_rearmed")
        self.assertNotIn("0 files", line)
        self.assertIn("always kept", line)


class FilesSharedBySystemsAreCountedApart(unittest.TestCase):
    """`3do 1704 files, 349.0 MB`: 1689 of them are MAME's hash and plugin
    files, which six systems carry. Picking 3DO, one expects its BIOS."""

    FILES = [
        {"dest": "panafz10.bin", "size": 4, "cores": None, "systems": ["3do"]},
        {"dest": "mame/hash/a.xml", "size": 100, "cores": None,
         "systems": ["3do", "philips-cdi"]},
        {"dest": "mame/hash/b.xml", "size": 50, "cores": None,
         "systems": ["3do", "philips-cdi"]},
        {"dest": "gba_bios.bin", "size": 8, "cores": None, "systems": ["nintendo-gba"]},
    ]

    def _listing(self) -> str:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            install._print_choices("retroarch", self.FILES, [], systems=True)
        return out.getvalue()

    def test_the_listing(self):
        lines = {line.split()[0]: line for line in self._listing().splitlines()}
        self.assertIn("1 file, 4 B, and 2 files, 150 B shared with other systems",
                      lines["3do"])
        self.assertIn("2 files, 150 B, all shared with other systems", lines["philips-cdi"])
        self.assertTrue(lines["nintendo-gba"].endswith("1 file, 8 B"))

    def test_the_systems_step(self):
        answers = iter(["c", "", ""])
        out = io.StringIO()
        with mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            install._prompt_custom_selection("retroarch", self.FILES, [])
        self.assertIn("1 file, 4 B, and 2 files, 150 B shared with other systems",
                      out.getvalue())


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

    def test_the_core_maps(self):
        good = self._manifest()
        good.update(core_names={"beetle_psx": ["mednafen_psx"]},
                    system_cores={"sony-playstation": ["beetle_psx"]})
        install._validate_manifest(good, "retroarch")
        for field, bad in (("core_names", ["x"]), ("core_names", {"a": "b"}),
                           ("system_cores", {"s": None}), ("system_cores", {"": ["a"]}),
                           ("system_cores", {"s": [1]})):
            manifest = self._manifest()
            manifest[field] = bad
            with self.subTest(field=field, value=bad), self.assertRaises(ValueError):
                install._validate_manifest(manifest, "retroarch")

    def test_the_system_titles(self):
        """A title is read as text by --system and the interface: a list or
        a number there raised mid-run instead of at the boundary."""
        good = self._manifest()
        good["system_titles"] = {"sony-playstation": "Sony PlayStation"}
        install._validate_manifest(good, "retroarch")
        for bad in (["x"], {"s": ["Sony"]}, {"s": None}, {"s": 5}, {"s": ""},
                    {"": "Sony"}, {"s": "x" * 257}, {"s" * 257: "Sony"}):
            manifest = self._manifest()
            manifest["system_titles"] = bad
            with self.subTest(value=bad), self.assertRaises(ValueError):
                install._validate_manifest(manifest, "retroarch")


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
            self.assertIn("Narrowed 5 to 2 files", proc.stdout)
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
            self.assertIn("records no regions, so --region cannot narrow it", proc.stderr)
            self.assertIn("older release", proc.stderr)
            self.assertEqual(repo.installed(), [])

    def test_a_pinned_ref_is_named_as_the_way_out(self):
        """RETROBIOS_REF=<tag>, which the docs suggest for reproducibility,
        selects lists from before narrowing existed, and the error said only
        "narrowing needs a newer one"."""
        with FakeRepository(selection=False) as repo:
            proc = subprocess.run(
                repo.command("--region", "us"),
                env={**repo.env(), "RETROBIOS_REF": "v2026.10.10"},
                capture_output=True, text=True, timeout=60, check=False,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("unset RETROBIOS_REF", proc.stderr)

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
            self.assertEqual(proc.returncode, 2)
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
        """Typed answers: customise, PlayStation only, US first. Its one
        core is not asked about."""
        with FakeRepository() as repo:
            command = " ".join(shlex.quote(part) for part in repo.command())
            proc = subprocess.run(
                ["script", "-qec", command, "/dev/null"],
                input="c\n2\n2\n\n", env=repo.env(), capture_output=True,
                text=True, timeout=60, check=False,
            )
            out = proc.stdout
            self.assertEqual(proc.returncode, 0, out + proc.stderr)
            self.assertIn("choose systems, cores and regions", out)
            self.assertNotIn("Cores:", out)
            self.assertIn("--system sony-playstation --region north-america", out)
            self.assertEqual(repo.installed(), ["pcsx/extra.bin", "scph5501.bin"])

    @unittest.skipUnless(shutil.which("script"), "script(1) provides the terminal")
    def test_a_quoted_folder_typed_at_the_prompt(self):
        """The quotes "Copy as path" adds were kept: the files went into a
        folder named `"` under the current directory, created without the
        question --dest asks, and the run said Done."""
        with FakeRepository() as repo:
            home = repo.root / "home"
            home.mkdir()
            # Read for the standalone emulator folders, of which there are none.
            (repo.root / "install" / "emudeck.json").write_text(json.dumps(
                {"manifest_version": 2, "platform": "emudeck", "files": []}))
            card = repo.root / "My Card" / "bios"
            env = dict(repo.env(), HOME=str(home), USERPROFILE=str(home),
                       XDG_CONFIG_HOME=str(home), RETROBIOS_OS="linux")
            command = f"{shlex.quote(sys.executable)} {shlex.quote(str(REPO_ROOT / 'install.py'))}"
            # No to the folders asks the folder again, as the screen's
            # Choose another folder does: the input then ends, Ctrl+D.
            for answer, code in (("n", 130), ("y", 0)):
                with self.subTest(answer=answer):
                    proc = subprocess.run(
                        ["script", "-qec", command, "/dev/null"],
                        input=f'1\n"{card}"\n{answer}\n\n', env=env, cwd=repo.root,
                        capture_output=True, text=True, timeout=60, check=False,
                    )
                    self.assertEqual(proc.returncode, code, proc.stdout + proc.stderr)
                    self.assertIn(f"Create 2 folders under {repo.root}?", proc.stdout)
                    self.assertFalse((repo.root / '"').exists())
            self.assertEqual(len([p for p in card.rglob("*") if p.is_file()]), 5)

    def test_q_at_every_menu_stops_on_the_quit_code(self):
        """`install.sh && retroarch` started RetroArch after a q, which left
        with 0. A quit chosen ends on 2, nothing installed, where Ctrl+C and
        Ctrl+D leave with 130."""
        files = [{"dest": "a.bin", "size": 1, "systems": ["nintendo-gba"]}]
        menus = (
            lambda: install._choose_platform("Platform:"),
            lambda: install._pick("Systems:", [("nintendo-gba", files)]),
            lambda: install._prompt_custom_selection("retroarch", files, []),
        )
        for menu in menus:
            with self.subTest(menu=menu), \
                    mock.patch("builtins.input", lambda _prompt="": "q"), \
                    mock.patch("sys.stdout", new_callable=lambda: open(os.devnull, "w")), \
                    self.assertRaises(SystemExit) as stop:
                menu()
            self.assertEqual(stop.exception.code, install.QUIT_CODE)

    @unittest.skipIf(os.name == "nt", "a pseudo-terminal is a POSIX one")
    def test_ctrl_d_at_the_first_question_has_nothing_to_carry_on(self):
        import pty  # noqa: PLC0415

        with FakeRepository() as repo:
            home = repo.root / "home"
            home.mkdir()
            (repo.root / "install" / "emudeck.json").write_text(json.dumps(
                {"manifest_version": 2, "platform": "emudeck", "files": []}))
            env = dict(repo.env(), HOME=str(home), USERPROFILE=str(home),
                       XDG_CONFIG_HOME=str(home), RETROBIOS_OS="linux")
            leader, follower = pty.openpty()
            # The question needs the output on the terminal too: sent to a
            # pipe, the run asks nothing.
            proc = subprocess.Popen(
                [sys.executable, str(REPO_ROOT / "install.py")], stdin=follower,
                stdout=follower, stderr=subprocess.PIPE, env=env, text=True,
            )
            os.close(follower)
            os.write(leader, b"\x04")
            err = proc.communicate(timeout=60)[1]
            chunks = []
            while True:
                try:
                    chunk = os.read(leader, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            os.close(leader)
            out = b"".join(chunks).decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 130, out + err)
        self.assertIn("Stopped. Nothing was installed.", out)
        self.assertNotIn("carry on", out)

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


class DataTreesFollowTheSystemsTheyServe(InstallMatchesASystemPack):
    """The data trees a system choice keeps, installer against pack. GBA
    alone took FBNeo's cheats and samples, 3,472 files, because the trees
    listed every FBNeo system. The Mega Drive took no cheat: the tree said
    sega-megadrive where RetroArch's list says sega-mega-drive."""

    CASES = ((["nintendo-gba"], []), (["sega-mega-drive"], []), (["arcade"], []))

    def _packed(self, systems, regions) -> set[str]:
        import zipfile

        from common import load_data_dir_registry

        # The trees come from the registry the manifest reads by itself.
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as out:
            zip_path = self.gp.generate_pack(
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
    )

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        import generate_pack as gp
        from common import load_emulator_profiles, load_target_config

        cls.gp = gp
        cls.load_target_config = staticmethod(load_target_config)
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

    def _manifest(self, platform, target_cores=None, target=None):
        return self.gp.generate_manifest(
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
                files, omitted = install.narrow_to_cores(full, cores)
                # A case-insensitive platform reads one file under both
                # spellings (BlastEm's 32X_M_BIOS.bin, PicoDrive's .BIN).
                from common import load_platform_config

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
        import common
        import generate_db
        import generate_pack

        self.gp = generate_pack
        tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
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
            "largefiles.load_registered_paths", return_value=["bios/Sys/jp.bin"]
        )
        registered.start()
        self.addCleanup(registered.stop)
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
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
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.addCleanup(common._platform_config_cache.clear)
        self.addCleanup(common._emulator_profiles_cache.clear)
        self.profiles = common.load_emulator_profiles("emulators")

    def _manifest(self, regions):
        return self.gp.generate_manifest(
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
        import common
        import generate_db
        import generate_pack

        self.gp = generate_pack
        tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
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
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
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
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.addCleanup(common._platform_config_cache.clear)
        self.addCleanup(common._emulator_profiles_cache.clear)
        self.profiles = common.load_emulator_profiles("emulators")

    def _manifest(self, regions):
        return self.gp.generate_manifest(
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
        import common
        import generate_db
        import generate_pack

        self.gp = generate_pack
        tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
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
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
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
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.addCleanup(common._platform_config_cache.clear)
        self.addCleanup(common._emulator_profiles_cache.clear)
        self.profiles = common.load_emulator_profiles("emulators")

    def _manifest(self, regions):
        return self.gp.generate_manifest(
            "p", "platforms", self.db, "bios", "platforms/_registry.yml",
            emulators_dir="emulators", emu_profiles=self.profiles,
            regions=regions, offline=True,
        )

    def _pack(self, regions):
        record = self.gp.PackRecord()
        self.gp.generate_pack(
            "p", "platforms", self.db, "bios", "", emulators_dir="emulators",
            emu_profiles=self.profiles, regions=regions, offline=True, record=record,
        )
        return {m for m in record.members if m.startswith("bios/")}

    def test_the_slot_choices_are_computed_once(self):
        """pack_overrides recomputed the choices the manifest had just
        computed with the same arguments: 8% of a manifest run."""
        import slots

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


class AListingNeedsNoInstall(unittest.TestCase):
    """--list-systems with --platform bizhawk stopped on "not found, name it
    with --dest": a question asked before downloading BizHawk was refused."""

    def test_bizhawk_lists_without_a_folder(self):
        with FakeRepository() as repo:
            manifest = json.loads((repo.root / "install" / "retroarch.json").read_text())
            manifest["platform"] = "bizhawk"
            (repo.root / "install" / "bizhawk.json").write_text(json.dumps(manifest))
            env = {**repo.env(), "HOME": str(repo.root / "home"), "USERPROFILE": str(repo.root / "home")}
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "bizhawk",
                 "--list-systems"],
                env=env, capture_output=True, text=True, timeout=60, check=False,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("nintendo-gba", proc.stdout)


class ThePlatformsOwnSystemNamesAreAccepted(unittest.TestCase):
    """A Batocera user who typed `--system psx`, the folder under roms/,
    was told the name is unknown with no suggestion, while the platform
    file records psx as the native_system of sony-playstation."""

    def test_the_names_come_from_the_platform_file(self):
        from common import load_platform_config  # noqa: PLC0415
        from common import platform_system_names  # noqa: PLC0415

        config = load_platform_config("batocera", str(REPO_ROOT / "platforms"))
        names = platform_system_names(config, list(config["systems"]))
        self.assertEqual(names["sony-playstation"], ["psx"])
        self.assertEqual(names["nintendo-gba"], ["gba"])
        # A name spelled like the system id adds nothing.
        self.assertTrue(all(
            install._name_key(alias) != install._name_key(system)
            for system, aliases in names.items() for alias in aliases
        ))

    def test_the_builder_writes_them_into_the_manifest(self):
        source = (REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertIn('"system_names": platform_system_names(config, list(pack_systems))',
                      source)

    def test_every_listed_system_gets_the_title_the_site_prints(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from generate_pack import system_titles  # noqa: PLC0415

        files = [{"dest": "a.bin", "systems": ["sony-playstation", "nintendo-gba"]}]
        omitted = [{"dest": "b.bin", "systems": ["3do"]}]
        self.assertEqual(system_titles(files, omitted), {
            "3do": "3DO",
            "nintendo-gba": "Nintendo Game Boy Advance",
            "sony-playstation": "Sony PlayStation",
        })
        self.assertEqual(system_titles([{"dest": "c.bin", "systems": ["sys-a"]}]), {})

    def test_a_native_name_narrows_and_lists(self):
        with FakeRepository() as repo:
            path = repo.root / "install" / "retroarch.json"
            manifest = json.loads(path.read_text())
            manifest["system_names"] = {"sony-playstation": ["psx"],
                                        "nintendo-gba": ["gba"]}
            path.write_text(json.dumps(manifest))
            proc = repo.run("--system", "psx", "--no-input")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(repo.installed(),
                             ["pcsx/extra.bin", "scph5500.bin", "scph5501.bin"])
            listing = repo.run("--list-systems", "--no-input")
            self.assertIn("nintendo-gba (gba)", listing.stdout)
            typo = repo.run("--system", "psxx", "--no-input")
            self.assertEqual(typo.returncode, 2)
            self.assertIn("Close matches: sony-playstation", typo.stderr)



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
        import generate_pack as gp
        import pipeline
        import verify
        from common import load_emulator_profiles

        cls.gp, cls.pipeline, cls.verify = gp, pipeline, verify
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

    def _packed(self, platform: str, systems: list[str]) -> set[str]:
        import contextlib
        import io
        import zipfile

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as out, \
                contextlib.redirect_stdout(io.StringIO()):
            zip_path = self.gp.generate_pack(
                platform, str(REPO_ROOT / "platforms"), self.db,
                str(REPO_ROOT / "bios"), out,
                emulators_dir=str(REPO_ROOT / "emulators"),
                emu_profiles=self.profiles, system_filter=systems, offline=True,
            )
            with zipfile.ZipFile(zip_path) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
        return {i.filename: i.file_size for i in infos}

    def test_pack_verify_and_installer_agree(self):
        from common import load_platform_config, resolve_system_arg

        for platform, native, system_id in self.CASES:
            with self.subTest(platform=platform, name=native):
                config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
                systems = list(config["systems"])
                chosen = resolve_system_arg(native, systems, config)
                self.assertEqual(chosen, resolve_system_arg(system_id, systems, config))
                self.assertEqual(chosen, [system_id])

                report = self.verify.verify_platform(
                    config, self.db, str(REPO_ROOT / "emulators"), self.profiles,
                    system_filter=chosen,
                )
                self.assertEqual(report["systems"], [system_id])
                credited = set(report["pack_destinations"])
                trees = self.pipeline._tree_members(platform, str(REPO_ROOT / "platforms"))
                members = self._packed(platform, chosen)
                written = {
                    name for name, size in members.items()
                    if not self.pipeline._PACK_NOTES.search(name)
                    and not (trees.get(name) == size and name not in credited)
                }
                self.assertTrue(written)
                self.assertEqual(credited, written)

                manifest = self.gp.generate_manifest(
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


class SystemNamesResolveOneWay(unittest.TestCase):
    """common.resolve_system_arg, the one reading of --system."""

    CONFIG = {"systems": {
        "sony-playstation": {"files": [{"name": "a.bin", "native_system": "psx"}]},
        "microsoft-msx": {"files": [{"name": "b.rom", "native_system": "msx1,msx2"}]},
        "nintendo-gba": {"files": [{"name": "c.bin", "native_system": "gba"}]},
        "gb": {"files": [{"name": "d.bin", "native_system": "nintendo-gba"}]},
    }}

    def _resolve(self, value, config=CONFIG):
        from common import resolve_system_arg

        return resolve_system_arg(value, list(self.CONFIG["systems"]), config)

    def test_native_names_and_ids(self):
        self.assertEqual(self._resolve("psx"), ["sony-playstation"])
        self.assertEqual(self._resolve("PSX"), ["sony-playstation"])
        self.assertEqual(self._resolve("psx,gb"), ["sony-playstation", "gb"])
        self.assertEqual(self._resolve("Sony PlayStation"), ["sony-playstation"])
        self.assertEqual(self._resolve("playstation"), ["sony-playstation"])

    def test_a_name_with_commas_is_one_name(self):
        self.assertEqual(self._resolve("msx1,msx2"), ["microsoft-msx"])

    def test_an_id_wins_over_another_systems_native_name(self):
        self.assertEqual(self._resolve("nintendo-gba"), ["nintendo-gba"])

    def test_without_a_platform_only_ids_count(self):
        with self.assertRaises(ValueError):
            self._resolve("psx", config=None)

    def test_an_unknown_name_is_refused_with_a_suggestion(self):
        with self.assertRaises(ValueError) as caught:
            self._resolve("psx,psxx")
        self.assertIn("unknown system psxx", str(caught.exception))
        self.assertIn("Close matches: psx.", str(caught.exception))


class AnUnknownNativeNameIsRefusedBeforeAnyWork(unittest.TestCase):
    """Both tools answer a typo with the platform's names before reading the
    database: a missing --db would otherwise be the first error."""

    def test_both_tools(self):
        missing = str(REPO_ROOT / "tmp" / "no-such-database.json")
        for script, extra in (
            ("verify.py", []),
            ("generate_pack.py", ["--output-dir", str(REPO_ROOT / "tmp" / "never")]),
        ):
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--platform", "batocera",
                     "--system", "psxx", "--db", missing, *extra],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
                )
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn("unknown system psxx. Close matches: psx.", proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)
        self.assertFalse((REPO_ROOT / "tmp" / "never").exists())

    def test_verify_takes_a_native_name_beside_platform(self):
        proc = subprocess.run(
            [sys.executable, "scripts/verify.py", "--platform", "batocera",
             "--system", "psx", "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
        )
        if "database" in proc.stderr and proc.returncode:
            self.skipTest("database.json is not built")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["batocera"]["systems"], ["sony-playstation"])


class ThePlatformsOwnListAlone(unittest.TestCase):
    """A setup that checks its own list asked --check about 14,508 files on
    Batocera, 353 of them its own, and had no option to ask about those:
    --declared-only keeps the entries the platform declares (cores: null)."""

    FILES = [
        {"dest": "a.bin", "size": 1, "cores": None, "systems": ["sys-a"],
         "alternatives": [{"sha1": "2" * 40, "size": 2, "cores": ["core-b"]}]},
        {"dest": "b.bin", "size": 1, "cores": None, "systems": ["sys-a"],
         "sha1": "1" * 40,
         "slot_choices": [{"sha1": "3" * 40, "size": 3, "cores": ["core-b"]}],
         "declared_choices": [{"sha1": "1" * 40, "size": 1, "systems": ["sys-a"]}]},
        {"dest": "core/c.bin", "size": 1, "cores": ["core-b"], "systems": ["sys-a"]},
    ]
    OMITTED = [
        {"dest": "d.bin", "name": "d.bin", "system": "sys-a", "systems": ["sys-a"],
         "required": True, "reason": "not_found", "cores": None},
        {"dest": "core/e.bin", "name": "e.bin", "system": "sys-a", "systems": ["sys-a"],
         "required": True, "reason": "not_found", "cores": ["core-b"]},
    ]

    def test_the_cut(self):
        files, omitted = install.keep_declared(list(self.FILES), list(self.OMITTED))
        self.assertEqual([f["dest"] for f in files], ["a.bin", "b.bin"])
        self.assertEqual([o["dest"] for o in omitted], ["d.bin"])
        # The platform answers its own slot, and no core copy is left to
        # stand in for it when a later narrowing drops the system.
        self.assertEqual(files[1]["sha1"], "1" * 40)
        for entry in files:
            self.assertIsNone(entry["cores"])
            self.assertFalse({"alternatives", "slot_choices", "declared_choices"} & set(entry))
        self.assertEqual(install.available_choices(files, omitted)["cores"], [])

    def test_install_check_and_dry_run_apply_it(self):
        with FakeRepository() as repo:
            proc = repo.run("--declared-only")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("5 to 3 files", proc.stdout)
            self.assertEqual(repo.installed(),
                             ["gba_bios.bin", "scph5500.bin", "scph5501.bin"])
        for mode in ("--check", "--dry-run"):
            with self.subTest(mode=mode), FakeRepository() as repo:
                proc = repo.run("--declared-only", mode)
                self.assertIn("5 to 3 files", proc.stdout, proc.stderr)
                self.assertIn("0 in place, 3 missing", proc.stdout)
                self.assertEqual(repo.installed(), [])

    def test_it_composes_with_the_other_narrowings(self):
        with FakeRepository() as repo:
            proc = repo.run("--declared-only", "--system", "sony-playstation",
                            "--region", "us")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(repo.installed(), ["scph5501.bin"])
        with FakeRepository() as repo:
            listing = repo.run("--declared-only", "--list-systems")
            self.assertEqual(listing.returncode, 0, listing.stderr)
            row = next(line for line in listing.stdout.splitlines()
                       if "sony-playstation" in line)
            self.assertIn("2 files", row)

    def test_a_local_file_list_applies_it(self):
        with FakeRepository() as repo:
            proc = repo.run("--declared-only", "--dry-run", "--manifest",
                            str(repo.root / "install" / "retroarch.json"))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("5 to 3 files", proc.stdout)

    def test_every_mode_that_cannot_apply_it_refuses_it(self):
        """Applied or refused, never ignored: each of these would have run
        as if the option was not there."""
        refused = [
            ["--list-platforms"],
            ["--list-targets"],
            ["--list-cores"],
            ["--list-emulators"],
            ["--core", "mgba"],
            ["--standalone-copies"],
            ["--tui"],
        ]
        with FakeRepository() as repo:
            for extra in refused:
                with self.subTest(extra=extra):
                    proc = repo.run("--declared-only", *extra)
                    self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                    self.assertIn("--declared-only", proc.stderr)
                    self.assertEqual(repo.installed(), [])
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--restore",
             str(REPO_ROOT / "tmp"), "--declared-only"],
            capture_output=True, text=True, timeout=60, check=False,
            stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("takes no --declared-only", proc.stderr)

    def test_events_count_the_platforms_own_files(self):
        with FakeRepository() as repo:
            proc = repo.run("--check", "--events")
            events = [json.loads(line) for line in proc.stdout.splitlines()]
            declared = [e for e in events if e["event"] == "declared"]
            self.assertEqual(declared, [{
                "event": "declared", "platform": "retroarch", "files": 3, "present": 0,
                "missing": 3, "wrong_hash": 0, "bytes_needed": 22,
                "dests": ["scph5500.bin", "scph5501.bin", "gba_bios.bin"],
            }])
            kinds = [e["event"] for e in events]
            self.assertEqual(kinds.index("declared"), kinds.index("check") + 1)
            narrowed = [json.loads(line) for line in
                        repo.run("--check", "--events", "--declared-only").stdout.splitlines()]
            check = next(e for e in narrowed if e["event"] == "check")
            self.assertEqual(check["files"], 3)


class AnIdAnotherSetupUses(unittest.TestCase):
    """The Neo Geo card offers `--system snk-neogeo`, and RetroArch, which
    files neogeo.zip under arcade, answered "Close matches: snk-neogeo-cd."."""

    KNOWN = ["arcade", "snk-neogeo-cd", "sony-playstation"]
    HOLDERS = {"snk-neogeo": ["arcade"]}

    def _refusal(self, typed: str, holders=None) -> str:
        with self.assertRaises(ValueError) as ctx:
            install.resolve_choices([typed], self.KNOWN, "system",
                                    holders=self.HOLDERS if holders is None else holders)
        return str(ctx.exception)

    def test_the_system_holding_its_file_is_suggested_never_taken(self):
        for typed in ("snk-neogeo", "SNK-NeoGeo", "neogeo", "mvs", "aes"):
            with self.subTest(typed=typed):
                text = self._refusal(typed)
                self.assertIn("Close matches: arcade.", text)
                self.assertIn("neogeo.zip", text)
                self.assertNotIn("snk-neogeo-cd", text)

    def test_a_typo_still_gets_the_closest_names(self):
        self.assertIn("Close matches: snk-neogeo-cd", self._refusal("snk-neogeo-dc", {}))

    def test_holders_are_read_from_the_file_list(self):
        files = [
            {"dest": "neogeo.zip", "systems": ["arcade"]},
            {"dest": "fbneo/neogeo.zip", "systems": ["arcade"]},
            {"dest": "neocd/neocd.bin", "systems": ["snk-neogeo-cd"]},
            {"dest": "Other/neogeo.zip", "systems": []},
        ]
        self.assertEqual(install.key_file_holders(files, []), {"snk-neogeo": ["arcade"]})
        own = [{"dest": "neogeo.zip", "systems": ["snk-neogeo"]}]
        self.assertEqual(install.key_file_holders(own, []), {})

    def test_retroarch_suggests_arcade(self):
        never = REPO_ROOT / "tmp" / "never"
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--manifest", str(REPO_ROOT / "install" / "retroarch.json"),
             "--dest", str(never), "--system", "snk-neogeo", "--dry-run", "--no-input"],
            capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("Close matches: arcade.", proc.stderr)
        self.assertNotIn("snk-neogeo-cd", proc.stderr)
        self.assertFalse(never.exists())


class TheTitleASetupPrints(unittest.TestCase):
    """The installer and the site print "SNK Neo Geo CD": typed back, the
    title was refused."""

    MANIFEST = {
        "system_names": {"sony-playstation": ["psx"]},
        "system_titles": {"snk-neogeo-cd": "SNK Neo Geo CD", "arcade": "Arcade games",
                          "sony-playstation": "Sony PlayStation",
                          "twin-a": "Twin", "twin-b": "Twin"},
    }
    KNOWN = ["arcade", "snk-neogeo-cd", "sony-playstation", "twin-a", "twin-b"]

    def _resolve(self, typed: str) -> list[str]:
        return install.resolve_choices([typed], self.KNOWN, "system",
                                       install.system_aliases(self.MANIFEST))

    def test_a_title_is_taken_for_its_id(self):
        self.assertEqual(self._resolve("SNK Neo Geo CD"), ["snk-neogeo-cd"])
        self.assertEqual(self._resolve("arcade games"), ["arcade"])
        self.assertEqual(self._resolve("psx"), ["sony-playstation"])

    def test_a_title_two_systems_share_is_not_taken(self):
        with self.assertRaises(ValueError):
            self._resolve("Twin")

    def test_the_platforms_own_name_wins_over_a_title(self):
        manifest = {"system_names": {"arcade": ["Sony PlayStation"]},
                    "system_titles": {"sony-playstation": "Sony PlayStation"}}
        self.assertEqual(install.system_aliases(manifest)["Sony PlayStation"], "arcade")


class SomethingElseAtADestination(unittest.TestCase):
    """A folder, or a file this user cannot read, at a destination ended
    --check and the install on an IsADirectoryError traceback."""

    def prepare(self, repo: FakeRepository) -> None:
        (repo.dest / "scph5500.bin").mkdir(parents=True)
        unreadable = repo.dest / "scph5501.bin"
        unreadable.write_bytes(b"x")
        unreadable.chmod(0)

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                     "a mode of 0 stops no read on Windows or as root")
    def test_each_says_why_in_the_check_and_the_install(self):
        with FakeRepository() as repo:
            self.prepare(repo)
            proc = repo.run("--check")
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            self.assertIn("    wrong copy: scph5500.bin\n      a folder sits where this "
                          "file goes: move it away, then run again", proc.stdout)
            self.assertIn("    wrong copy: scph5501.bin\n      could not be read "
                          "(Permission denied)", proc.stdout)
            proc = repo.run("--yes")
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            # Each failure named once, on its FAILED line.
            self.assertIn("FAILED scph5500.bin (a folder sits where this file goes",
                          proc.stdout)
            self.assertIn("FAILED scph5501.bin (file in place could not be kept aside",
                          proc.stdout)
            self.assertEqual(proc.stdout.count("scph5500.bin ("), 1, proc.stdout)
            self.assertTrue((repo.dest / "scph5500.bin").is_dir())
            self.assertIn("gba_bios.bin", repo.installed())


if __name__ == "__main__":
    unittest.main()
