"""Audit regressions on the README, the wiki and the help texts the tools print."""

from __future__ import annotations

import tests
from tests.sources import script_source
import ast
import io
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock
import yaml
from tests import REPO_ROOT


class ReadmeRegressions(unittest.TestCase):
    """The README advertises commands, and these must stay executable.

    Wording is the maintainer's, so nothing here asserts prose. What is
    asserted is that every flag and URL the README hands a reader is one the
    shipped scripts actually accept.
    """

    def _quick_install(self) -> str:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        return readme.split("## Install in one line", 1)[1].split(
            "## Or download a ZIP", 1
        )[0]

    def test_advertised_bootstrap_urls_are_the_shipped_ones(self):
        from sitegen import bootstrap as sitebootstrap
        from sitegen.guidedata import install_base

        quick_install = self._quick_install()
        for name in sitebootstrap.SOURCES:
            url = f"{install_base()}/{name}"
            self.assertIn(f"{url} |", quick_install, f"{name} bootstrap URL missing")
        # The site serves each bootstrap with install.py read from the
        # commit it was built from, the raw form from main.
        commit = "0" * 40
        for name in sitebootstrap.SOURCES:
            self.assertIn(sitebootstrap.installer_url(commit),
                          sitebootstrap.served_text(name, REPO_ROOT, commit))
        self.assertIn(
            "https://raw.githubusercontent.com/Abdess/retrobios/main/install.py",
            (REPO_ROOT / "install.sh").read_text(encoding="utf-8"),
        )

    def test_advertised_installer_flags_exist(self):
        quick_install = self._quick_install()
        advertised = set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", quick_install))
        parser_source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        supported = set(re.findall(r'add_argument\(\s*"(--[a-z][a-z-]+)"', parser_source))
        unknown = advertised - supported
        self.assertEqual(unknown, set(), f"README advertises unknown flags: {unknown}")

    def test_the_build_version_is_the_one_the_pipeline_requires(self):
        """"Python 3 + pyyaml" sent a 3.8 user to a SyntaxError in
        generate_pack, and a 3.10 one through six steps to fail at step 7."""
        floor = re.search(
            r"sys\.version_info < \((\d+), (\d+)\)",
            (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8"),
        )
        self.assertIsNotNone(floor, "pipeline.py checks no interpreter version")
        version = f"Python {floor.group(1)}.{floor.group(2)}"
        for page in ("README.md", "wiki/tools.md", "wiki/testing-guide.md"):
            with self.subTest(page=page):
                self.assertIn(version, (REPO_ROOT / page).read_text(encoding="utf-8"))
        self.assertIn(
            version, script_source("generate_readme.py")
        )

    def test_an_older_interpreter_is_refused_before_the_first_step(self):
        import shutil

        python38 = shutil.which("python3.8")
        if python38 is None:
            if os.environ.get("CI"):
                self.fail("CI must provide python3.8")
            self.skipTest("no python3.8 on PATH")
        # --help: without the guard the run must stop at argparse, not
        # rebuild database.json under an interpreter missing pyyaml.
        proc = subprocess.run(
            [python38, "-I", "scripts/pipeline.py", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("needs Python 3.9", proc.stderr)

    def test_the_readme_build_command_names_the_floor(self):
        """The README's first command is generate_pack.py. Under 3.8 it
        stopped on a raw SyntaxError at a parenthesized `with`."""
        import shutil

        python38 = shutil.which("python3.8")
        if python38 is None:
            if os.environ.get("CI"):
                self.fail("CI must provide python3.8")
            self.skipTest("no python3.8 on PATH")
        proc = subprocess.run(
            [python38, "-I", "scripts/generate_pack.py", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("SyntaxError", proc.stderr)
        self.assertIn("generate_pack.py needs Python 3.9", proc.stderr)

    def test_every_script_names_the_floor_under_an_older_interpreter(self):
        """Only generate_pack.py and pipeline.py checked the version. verify.py,
        slots.py, validate_pr.py and cross_reference.py started under 3.8 and
        stopped halfway on a str.removeprefix AttributeError."""
        import shutil

        python38 = shutil.which("python3.8")
        if python38 is None:
            if os.environ.get("CI"):
                self.fail("CI must provide python3.8")
            self.skipTest("no python3.8 on PATH")
        commands = (
            ["verify.py", "--emulator", "handy"],
            ["verify.py", "--platform", "batocera"],
            ["validate_pr.py", "--json", "README.md"],
            ["cross_reference.py", "--emulator", "handy"],
            ["slots.py"],
            ["identity.py"],
            ["generate_site.py", "--help"],
            ["campaign.py", "--help"],
            ["region_check.py", "--help"],
        )
        for command in commands:
            with self.subTest(command=" ".join(command)):
                # -E -s rather than -I: -I drops the script's folder from
                # sys.path, so the imports would fail before any check.
                proc = subprocess.run(
                    [python38, "-E", "-s", f"scripts/{command[0]}", *command[1:]],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
                    check=False,
                )
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)
                self.assertIn(f"{command[0]} needs Python 3.9", proc.stderr)

    def test_the_floor_interpreter_imports_every_script(self):
        """Every module under scripts/ is loaded by a real interpreter of the
        floor version, as the installer's 3.8 floor is proven by running it.
        Compiling only checks the grammar: a module-level alias such as
        `tuple[int, int | None]` compiles under 3.9 and raises TypeError
        when the module loads."""
        import shutil

        floor = re.search(
            r"sys\.version_info < \((\d+), (\d+)\)",
            (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8"),
        )
        name = f"python{floor.group(1)}.{floor.group(2)}"
        interpreter = shutil.which(name)
        if interpreter is None:
            if os.environ.get("CI"):
                self.fail(f"CI must provide {name}")
            self.skipTest(f"no {name} on PATH")
        check = (
            "import importlib, json, pathlib, sys\n"
            "sys.path.insert(0, '.')\n"
            "failed = {}\n"
            "for p in sorted(pathlib.Path('scripts').rglob('*.py')):\n"
            "    if '__pycache__' in p.parts:\n"
            "        continue\n"
            "    parts = p.with_suffix('').parts\n"
            "    if parts[-1] == '__init__':\n"
            "        parts = parts[:-1]\n"
            "    try:\n"
            "        importlib.import_module('.'.join(parts))\n"
            "    except BaseException as e:\n"
            "        failed[str(p)] = [type(e).__name__, getattr(e, 'name', None), str(e)]\n"
            "print(json.dumps(failed))\n"
        )
        proc = subprocess.run(
            [interpreter, "-I", "-c", check], cwd=REPO_ROOT, capture_output=True,
            text=True, timeout=600, check=False,
            env={**os.environ, "RETROBIOS_OFFLINE": "1"},
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        failed = json.loads(proc.stdout.strip().splitlines()[-1])
        # pyyaml for every build script, jsonschema for validate_schemas:
        # without them the floor interpreter cannot load the modules, which
        # proves nothing either way.
        absent = sorted({
            err[1] for err in failed.values()
            if err[0] == "ModuleNotFoundError" and err[1] in ("yaml", "jsonschema")
        })
        if absent:
            message = f"{name} lacks {', '.join(absent)}"
            if os.environ.get("CI"):
                self.fail(message)
            self.skipTest(message)
        self.assertEqual(failed, {})


class PackReadmesSayWhatTheInstallerDoes(unittest.TestCase):
    """The EmuDeck README promised keys set up automatically (they need
    --standalone-copies) and gave a Citra path the installer never uses, and the
    RetroArch README offered only `| sh`, which Windows cannot run."""

    def _guide(self, platform: str) -> str:
        from packs.readme import build_readme

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        install = registry["platforms"][platform].get("install") or {}
        text = build_readme(platform, platform, "", 1, 1,
                             detect=install.get("detect", []),
                             standalone_copies=install.get("standalone_copies", []))
        return text[text.index("INSTALLATION"):text.index("TROUBLESHOOTING")]

    def test_retroarch_offers_the_windows_installer(self):
        from sitegen.guidedata import install_ps1, install_sh

        guide = self._guide("retroarch")
        self.assertIn(f"{install_sh()} | sh", guide)
        self.assertIn(f"{install_ps1()} | iex", guide)

    def test_emudeck_keys_match_the_registry_and_the_flag(self):
        import re

        guide = self._guide("emudeck")
        self.assertIn("--standalone-copies", guide)
        self.assertNotIn("emulator keys automatically", guide)
        self.assertNotIn("handles this for you", guide)
        with (REPO_ROOT / "platforms" / "_registry.yml").open(encoding="utf-8") as handle:
            registry = yaml.safe_load(handle)
        targets = {
            target.rstrip("/").replace("$HOME", "~")
            for copy in registry["_standalone_copies"]
            for target in copy.get("targets", {}).get("linux", [])
        }
        named = {
            path.rstrip("/") for path in re.findall(r"-> (~/\S+)", guide)
        }
        self.assertEqual(sorted(named - targets), [])

    def test_retropie_never_sends_a_pc_to_the_linux_partition(self):
        guide = self._guide("retropie")
        from sitegen.guidedata import install_sh

        self.assertNotIn("Put the SD card in your PC", guide)
        self.assertIn(f"{install_sh()} | sh", guide)


class FaqRegressions(unittest.TestCase):
    """The FAQ states facts the code owns, and these tie it back to the source.

    Three of its claims had drifted: a pinned MAME version, Adler-32
    attributed to Dolphin's IPL instead of its DSP ROMs, and a verbose
    per-emulator report described as the only way to catch a bad file on an
    existence platform. Readers act on all three.
    """

    @staticmethod
    def _faq() -> str:
        # The questions about hashes and checks moved to the technical FAQ.
        return "\n\n".join(
            (REPO_ROOT / "wiki" / name).read_text(encoding="utf-8")
            for name in ("faq.md", "technical-faq.md")
        )

    @staticmethod
    def _profile(key: str) -> dict:
        with (REPO_ROOT / "emulators" / f"{key}.yml").open(encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def test_the_romset_table_is_written_from_the_profiles(self):
        # Typed by hand, the table and the prose under it kept MAME 0.160
        # and FinalBurn Neo 1.0.0.2, versions no source at the pins states,
        # and the test holding them to the profiles kept the errors in step.
        from sitegen import emulatormetadata
        from model.profiles import load_emulator_profiles

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"), skip_aliases=False)
        page = (REPO_ROOT / "wiki" / "technical-faq.md").read_text(encoding="utf-8")
        self.assertEqual(
            page, emulatormetadata.with_romset_table(page, profiles),
            "wiki/technical-faq.md romset table is stale: run scripts/generate_site.py",
        )
        prose = page.split("### How this is known", 1)[1].split("\n## ", 1)[0]
        self.assertIsNone(re.search(r"\(0\.\d", prose),
                          "the prose under the table types a version again")

    def test_adler32_is_attributed_to_the_files_that_carry_it(self):
        dolphin = self._profile("dolphin")
        carriers = {
            f["name"] for f in dolphin["files"] if f.get("known_hash_adler32")
        }
        self.assertTrue(carriers, "dolphin.yml declares no Adler-32 hash")
        sentence = self._faq().split("Adler-32", 1)[1].split("\n\n", 1)[0]
        for name in carriers:
            self.assertIn(name, sentence, f"FAQ omits the Adler-32 file {name}")
        self.assertNotIn(
            "IPL.bin", carriers,
            "IPL.bin gained an Adler-32 hash, but the docs say it has none",
        )
        for page in ("faq.md", "profiling.md"):
            text = (REPO_ROOT / "wiki" / page).read_text(encoding="utf-8")
            for line in text.splitlines():
                if "Adler-32" in line or "adler32" in line:
                    self.assertNotIn(
                        "IPL", line,
                        f"wiki/{page} ties Adler-32 back to IPL: {line.strip()}",
                    )

    def test_existence_platforms_are_not_told_the_verbose_report_is_the_only_check(self):
        self.assertIn(
            "DISCREPANCY",
            self._faq(),
            "the FAQ must name the check the platform report performs itself",
        )
        self.assertIn(
            'result["discrepancy"]',
            script_source("verify.py"),
            "verify.py no longer raises the discrepancy the FAQ advertises",
        )


class CatalogRatioRegressions(unittest.TestCase):
    """The catalog-matched count must read the same on every surface.

    The home page, the provenance page, the README and the stats export each
    used to count matches on their own. Two of them dropped the systems
    scope, so the site published 566 and 553 for the same quantity, one click
    apart, and the export paired the wider number with composition.systems as
    its denominator.
    """

    _SURFACES = ("scripts/generate_site.py", "scripts/generate_readme.py")

    def test_no_surface_counts_matches_on_its_own(self):
        for relative in self._SURFACES:
            tree = ast.parse(script_source(relative.removeprefix("scripts/")))
            inline = [
                node.lineno
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "sum"
                and "provenance" in ast.dump(node)
            ]
            self.assertEqual(
                inline,
                [],
                f"{relative} counts provenance matches inline at {inline}; "
                "call common.count_catalog_matched instead",
            )

    def test_arcade_and_engine_data_stay_out_of_the_ratio(self):
        from scripts.model.composition import compute_composition, count_catalog_matched

        db = {
            "files": {
                "a": {"path": "bios/Sony/PlayStation/scph5501.bin", "size": 1,
                      "provenance": {"redump": {}}},
                "b": {"path": "bios/Arcade/Arcade/neogeo.zip", "size": 1,
                      "provenance": {"no-intro": {}}},
                "c": {"path": "bios/ScummVM/soundfonts/Roland.sf2", "size": 1,
                      "provenance": {"tosec": {}}},
                "d": {"path": "bios/Sega/Saturn/sega_101.bin", "size": 1},
            }
        }
        self.assertEqual(count_catalog_matched(db), 1)
        self.assertEqual(compute_composition(db)["systems"]["files"], 2)

    def test_engine_and_publisher_trees_are_game_data(self):
        """Engine data collected under `Game Engines/` and under a game
        publisher counted as console and computer system files: 7 697 of
        them made the README announce 13 564 system files."""
        from scripts.model.composition import composition_tier

        for path in (
            "bios/Game Engines/C-Dogs SDL/cdogs/data/guns.json",
            "bios/Id Software/Quake III Arena/baseq3/pak1.pk3",
            "bios/Epic MegaGames/Jazz Jackrabbit 2/jazz2/Source/share.j2e",
            "bios/RPG Maker/easyrpg/rtp/2000/Backdrop/Bridge.png",
        ):
            self.assertEqual(composition_tier(path), "game_data", path)
        self.assertEqual(composition_tier("bios/Sony/PlayStation/scph5501.bin"), "systems")
        self.assertEqual(composition_tier("bios/Microsoft/MSX/MSX2.ROM"), "systems")

    def test_readme_ratio_matches_the_database(self):
        from scripts.model.composition import compute_composition, count_catalog_matched
        from scripts.model.database import load_database

        database = REPO_ROOT / "database.json"
        if not database.exists():
            self.skipTest("database.json not generated")
        db = load_database(str(database))
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(
            r"\*\*([\d,]+) of ([\d,]+) system files\*\* matched to", readme
        )
        if match is None:
            # The README states no ratio since it leads to the site: a ratio
            # it states must still be the database's.
            return
        matched, total = (int(g.replace(",", "")) for g in match.groups())
        self.assertEqual(matched, count_catalog_matched(db))
        self.assertEqual(total, compute_composition(db)["systems"]["files"])


class ContributorsSurviveAFailedRequest(unittest.TestCase):
    """The one part of the README that comes from the network.

    A refused or rate-limited request left the list empty, which deleted the
    section from a published README. It happened during a pipeline run and
    the result was committed, after which the freshness check regenerated the
    section and failed on the difference. Losing the list is a worse answer
    than publishing a stale one.
    """

    def _block(self, text: str):
        import tempfile

        from sitegen.readme import _existing_contributor_block

        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as handle:
            handle.write(text)
            name = handle.name
        try:
            return _existing_contributor_block(name)
        finally:
            os.unlink(name)

    def test_a_published_list_is_read_back(self):
        text = (
            "# Title\n\n## Contributors\n\n"
            '<a href="https://github.com/a"><img src="x" alt="a"></a>\n'
            '<a href="https://github.com/b"><img src="y" alt="b"></a>\n\n'
            "## Community tools\n\nsomething else\n"
        )
        block = self._block(text)
        self.assertEqual(block[0], "## Contributors")
        self.assertIn('alt="a"', "\n".join(block))
        self.assertIn('alt="b"', "\n".join(block))
        self.assertNotIn("Community tools", "\n".join(block))
        self.assertNotIn("something else", "\n".join(block))

    def test_a_readme_without_the_section_yields_nothing(self):
        self.assertEqual(self._block("# Title\n\n## Other\n\ntext\n"), [])

    def test_an_unreadable_file_yields_nothing(self):
        from sitegen.readme import _existing_contributor_block

        self.assertEqual(_existing_contributor_block("/nonexistent/README.md"), [])

    def test_the_committed_readme_still_carries_its_contributors(self):
        """Regenerating offline must never be the reason this disappears."""
        text = (REPO_ROOT / "README.md").read_text()
        # Missing is the failure this guards, never a reason to skip.
        self.assertIn("## Contributors", text)
        self.assertGreater(
            text.count('<a href="https://github.com/'), 0,
            "the section is present but empty",
        )

    def test_a_failed_request_republishes_the_kept_block(self):
        from sitegen.readme import render_readme
        from tests.readmeinputs import readme_inputs

        kept = ["## Contributors", "", '<a href="https://github.com/a"><img src="x" alt="a"></a>']
        text = render_readme(readme_inputs(kept_contributors=kept))
        self.assertIn("\n".join(kept) + "\n\n\n## Community tools", text)

    def test_a_fetched_list_replaces_the_kept_block(self):
        from sitegen.readme import render_readme
        from tests.readmeinputs import readme_inputs

        text = render_readme(readme_inputs(
            contributors=[{"login": "someone", "avatar_url": "https://a/x"}],
            kept_contributors=["## Contributors", "", "stale"],
        ))
        self.assertIn(
            '## Contributors\n\n<a href="https://github.com/someone"><img src="https://a/x"'
            ' width="50" alt="someone" title="someone"></a>\n', text)
        self.assertNotIn("stale", text)

    def test_no_list_and_nothing_kept_leaves_the_section_out(self):
        from sitegen.readme import render_readme
        from tests.readmeinputs import readme_inputs

        self.assertNotIn("## Contributors", render_readme(readme_inputs()))

    def test_the_loader_keeps_the_published_block_when_the_request_fails(self):
        import tempfile

        from sitegen import readme

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "README.md"
            path.write_text("# T\n\n## Contributors\n\nkept line\n\n## Other\n", encoding="utf-8")
            with mock.patch.object(readme, "README_PATH", path), \
                    mock.patch.object(readme, "fetch_contributors", return_value=[]), \
                    mock.patch.object(readme, "list_registered_platforms", return_value=[]), \
                    mock.patch("model.registry.load_data_dir_registry", return_value={}), \
                    mock.patch.object(readme, "platform_coverages", return_value={}), \
                    mock.patch.object(readme, "load_emulator_profiles", return_value={}), \
                    mock.patch.object(readme.releaserecord, "load_advertised", return_value={}), \
                    mock.patch.object(readme, "_extract_cells", return_value={}), \
                    mock.patch.object(readme.ledger, "rebuild_counts",
                                      return_value={"total": 0, "exact": 0, "canonical": 0}), \
                    mock.patch.object(readme, "clone_line", return_value=""), \
                    mock.patch("sys.stdout", new_callable=io.StringIO):
                inputs = readme.load_readme_inputs({}, "platforms")
        self.assertEqual(inputs.kept_contributors, ["## Contributors", "", "kept line"])
        self.assertIn("## Contributors\n\nkept line\n", readme.render_readme(inputs))

    def test_the_contributor_list_is_not_asked_offline(self):
        from sitegen import readme

        with mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": "1"}), \
                mock.patch.object(readme.forgehttp, "fetch_body",
                                  side_effect=AssertionError("network")):
            self.assertEqual(readme.fetch_contributors(), [])

    def test_contributors_are_read_through_the_retrying_client(self):
        from sitegen import readme

        answer = json.dumps([
            {"login": "someone", "type": "User"},
            {"login": "dependabot[bot]", "type": "Bot"},
            {"login": readme.REPO.split("/")[0], "type": "User"},
        ]).encode()
        with mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                mock.patch.object(readme.forgehttp, "fetch_body", return_value=answer) as fetch:
            self.assertEqual([c["login"] for c in readme.fetch_contributors()], ["someone"])
        self.assertIn("/contributors", fetch.call_args.args[0])


class EveryReadmeNamesItsFolder(unittest.TestCase):
    """The Lakka pack's README reused RetroArch's guide and never named
    /storage/system, the folder the registry and the installer use."""

    def test_the_registry_folder_is_in_the_guide(self):
        from scripts.packs.readme import build_readme

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        for name, entry in registry["platforms"].items():
            folder = (entry.get("extract_to") or "").rstrip("/")
            if not folder:
                continue
            with self.subTest(platform=name):
                text = build_readme(name, name, "", 1, 1,
                                     detect=[{"os": "linux", "bios_path": folder}])
                self.assertIn(folder, text)
        lakka = build_readme("lakka", "Lakka", "", 1, 1)
        self.assertNotIn("retroarch/system", lakka)


class TheToolsPageSaysWhatDedupDoes(unittest.TestCase):
    """tools.md said duplicates move to .variants/ (they are deleted) and
    named 2 of the 11 directories dedup leaves alone."""

    def test_every_protected_tree_is_named(self):
        from scripts.model import nodedup

        line = next(
            row for row in (REPO_ROOT / "wiki" / "tools.md").read_text().splitlines()
            if row.startswith("| `dedup.py`")
        )
        self.assertNotIn(".variants", line)
        for name in nodedup.NODEDUP_DIRS:
            self.assertIn(name, line)


class ThePipelineTableNamesEveryStep(unittest.TestCase):
    """tools.md listed the steps without 1c, 2b2, 3a and 3b."""

    def test_every_labelled_step_is_documented(self):
        labels = set(re.findall(
            r'"(\d[a-z]?\d?)(?:/8)? [a-z]', script_source("pipeline.py")
        ))
        doc = (REPO_ROOT / "wiki" / "tools.md").read_text()
        documented = set(re.findall(r"^\| (\d[a-z]?\d?)(?:/8)? \|", doc, re.MULTILINE))
        self.assertEqual(labels - documented, set())


class DocumentedHashLookupsFindTheirFile(unittest.TestCase):
    """The --from-md5 example was a test fixture hash: copied from the docs,
    it answered NOT FOUND, which then exited 0."""

    def test_every_documented_lookup_is_in_the_database(self):
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        by_md5 = db["indexes"]["by_md5"]
        found = 0
        for page in sorted((REPO_ROOT / "wiki").glob("*.md")):
            text = page.read_text(encoding="utf-8")
            for md5 in re.findall(r"--from-md5 ([0-9a-f]{32})\b", text):
                found += 1
                with self.subTest(page=page.name, md5=md5):
                    self.assertIn(md5, by_md5)
        self.assertGreater(found, 0)


class ToolReferenceListsEveryModule(unittest.TestCase):
    """The exporter table described retropie_exporter as a System.dat writer
    and left out bizhawk, misterfpga and rocknix, and the target table missed
    recalbox and rocknix. A contributor reads these tables as the map."""

    def _rows(self, heading: str) -> set[str]:
        text = (REPO_ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")
        section = text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
        return set(re.findall(r"^\| `(\w+)` \|", section, re.M))

    def test_every_exporter_has_a_row(self):
        modules = {p.stem for p in (REPO_ROOT / "scripts" / "exporter").glob("*_exporter.py")}
        self.assertEqual(self._rows("Exporters"), modules - {"base_exporter"})

    def test_every_target_scraper_has_a_row(self):
        modules = {
            p.stem for p in (REPO_ROOT / "scripts" / "scraper" / "targets").glob("*_targets_scraper.py")
        }
        self.assertEqual(self._rows("Target scrapers"), modules)


class ToolReferenceCountsMatchTheirArtifacts(unittest.TestCase):
    """tools.md said 67 derivable entries for 79 and 1,113 identified
    archives for 1,181: counts written by hand drift from the tools."""

    def setUp(self):
        self.text = (REPO_ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")

    def test_recipe_store_counts(self):
        store = json.loads((REPO_ROOT / "recipes" / "mame.json").read_text(encoding="utf-8"))
        versions = {dat for entry in store["entries"] for dat in entry.get("dats") or [entry["dat"]]}
        listed = sum(len(entry.get("dats") or [entry["dat"]]) for entry in store["entries"])
        match = re.search(
            r"(\d+) MAME versions produce ([\d,]+) entries but only ([\d,]+)\s+distinct",
            self.text,
        )
        self.assertIsNotNone(match)
        stated = [int(group.replace(",", "")) for group in match.groups()]
        self.assertEqual(stated, [len(versions), listed, len(store["entries"])])

    def test_no_derivable_count(self):
        """The count now lives in derivable.json alone, which step 1b rewrites."""
        self.assertNotRegex(self.text, r"\d+ entries on the current snapshots")


class WikiProseHasNoTornSentence(unittest.TestCase):
    """tools.md read "replaces each destination atomically. The shell and /
    Both one-liners verify...": half of an old sentence left in front of
    its rewrite, on the page that explains the installer's trust boundary."""

    STARTERS = {"Both", "The", "This", "It", "A", "An", "Each", "Every", "When",
                "If", "They", "These", "That", "There"}

    def test_no_line_ends_on_a_function_word_before_a_new_sentence(self):
        for page in sorted((REPO_ROOT / "wiki").glob("*.md")):
            lines = page.read_text(encoding="utf-8").splitlines()
            in_code = False
            for number, (line, following) in enumerate(zip(lines, lines[1:]), 1):
                if line.startswith("```"):
                    in_code = not in_code
                if in_code:
                    continue
                if (re.search(r"\b(and|or|the|a|an|of|to)$", line.rstrip())
                        and following.split(" ")[0] in self.STARTERS):
                    self.fail(f"{page.name}:{number} ends mid-sentence: {line.strip()!r}")


class EveryOptionIsDocumented(unittest.TestCase):
    """profile_sync's --system, --stale-before and --ref, auto_fetch
    --create-issues, download.py --info and forty more were in no page: a
    maintainer ran --all and spent the API quota that --system would have
    saved. --help lists a flag, but only a page says when to reach for it."""

    def test_every_long_option_of_a_tracked_script_is_in_the_docs(self):
        tracked = subprocess.run(
            ["git", "ls-files", "scripts"], capture_output=True, text=True,
            cwd=str(REPO_ROOT), check=True,
        ).stdout.split()
        docs = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [*sorted((REPO_ROOT / "wiki").glob("*.md")),
                         REPO_ROOT / "README.md", REPO_ROOT / "CONTRIBUTING.md"]
        )
        option = re.compile(r'add_argument\(\s*(?:"-\w",\s*)?"(--[\w-]+)"')
        undocumented = sorted(
            f"{name}: {flag}"
            for name in tracked if name.endswith(".py")
            for flag in set(option.findall((REPO_ROOT / name).read_text(encoding="utf-8")))
            if not re.search(re.escape(flag) + r"(?![\w-])", docs)
        )
        self.assertEqual(undocumented, [])


class OfflineHelpSaysWhatItCuts(unittest.TestCase):
    """--offline read "Skip data directory freshness check" while it also
    stops release assets from downloading: on a fresh clone the gitignored
    files were missing from the pack and nothing had announced it."""

    def test_both_helps_name_the_release_assets(self):
        for script in ("generate_pack.py", "pipeline.py"):
            with self.subTest(script=script):
                out = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--help"],
                    capture_output=True, text=True, cwd=str(REPO_ROOT), check=True,
                ).stdout
                block = out.split("--offline", 2)[-1].split("\n  --", 1)[0]
                self.assertIn("release", " ".join(block.split()))


class PipelineDocstringNamesThePrintedSteps(unittest.TestCase):
    """The docstring numbered 1 to 9 while the run prints 1/8 to 8/8, and
    had no 2a, 2b, 3a, 3b or 6: a reader of a failed `6/8 pack integrity`
    found nothing under 6."""

    def test_the_two_lists_hold_the_same_steps(self):
        import ast

        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        doc = ast.get_docstring(ast.parse(source))
        listed = set(re.findall(r"^  (\d[a-z0-9]*)\s{2,}", doc, re.M))
        from orchestrate.labels import STEP_LABELS, step_number

        printed = {step_number(key) for key in STEP_LABELS}
        self.assertEqual(listed, printed)


class DocumentedExamplesHoldTogether(unittest.TestCase):
    """The verification block downloaded RetroArch_BIOS_Pack.zip*, a name
    no release ever published (packs are versioned and split), and the
    first-install example ended on "72 files installed" after announcing a
    download of 12,893."""

    def test_the_verification_pattern_matches_published_pack_names(self):
        import fnmatch
        import re

        page = (REPO_ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        patterns = re.findall(r"--pattern '([^']*Pack[^']*)'", page)
        self.assertTrue(patterns)
        for name in ("RetroArch_Lakka_v1.22.2_BIOS_Pack.part1of2.zip",
                     "RetroArch_v1.22.2_BIOS_Pack.zip"):
            with self.subTest(name=name):
                self.assertTrue(any(fnmatch.fnmatch(name, p) for p in patterns))

    def test_the_first_install_example_counts_one_number(self):
        import re

        # The annotated run moved from First install to the installer page.
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        downloading = re.search(r"Downloading (\d+) files", page).group(1)
        done = re.search(r"Done\. (\d+) files installed", page).group(1)
        # The data trees come after the download, counted in the index.
        index = page[page.index("Fetching file index for batocera"):]
        trees = re.search(r"^    .* and (\d+) data files", index, re.M)
        self.assertEqual(int(done), int(downloading) + (int(trees.group(1)) if trees else 0))


class TheReadmeCountsSystemsAsListSystemsDoes(unittest.TestCase):
    """The README counted every raw spelling (nes and nintendo-nes as two)
    and announced 550 systems while the tool it points to listed 513."""

    def test_one_count(self):
        import io
        import re
        from contextlib import redirect_stdout

        from scripts.model.cliargs import list_system_ids

        out = io.StringIO()
        with redirect_stdout(out):
            list_system_ids(str(REPO_ROOT / "emulators"))
        listed = len(out.getvalue().splitlines())
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        announced = int(re.search(r"\*\*(\d+) systems\*\*", readme).group(1))
        self.assertEqual(announced, listed)


class DocsDescribeTheRegistriesTheyName(unittest.TestCase):
    """The contributing guide said files over 50 MB are release assets and that
    RPG Maker and ScummVM were the trees kept out of dedup. `.gitignore`
    decides the first, four committed files exceed 50 MB, and NODEDUP_DIRS
    holds eleven trees."""

    SIZE_RULE = re.compile(r"(over|larger than|>)\s*50\s*MB[^\n]*(release|asset)", re.I)

    def _texts(self):
        paths = sorted((REPO_ROOT / "wiki").glob("*.md"))
        paths += [REPO_ROOT / "scripts" / "generate_readme.py", REPO_ROOT / "CONTRIBUTING.md"]
        return [(p, p.read_text(encoding="utf-8")) for p in paths]

    def test_no_page_says_size_decides_a_release_asset(self):
        offenders = [str(p.relative_to(REPO_ROOT)) for p, text in self._texts()
                     if self.SIZE_RULE.search(text)]
        self.assertEqual(offenders, [])

    def test_the_dedup_list_is_named_whole_or_by_its_constant(self):
        from model.nodedup import NODEDUP_DIRS
        tools = (REPO_ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")
        line = next(entry for entry in tools.splitlines() if "NODEDUP_DIRS" in entry)
        # Compared as list items: `mame` was missing while the substring
        # test found it in `mame_clones.json` on the same line.
        listed = line.split("`NODEDUP_DIRS`", 1)[1].split(":", 1)[1].rstrip(" |")
        self.assertEqual(
            sorted(item.strip() for item in listed.split(",")),
            sorted(NODEDUP_DIRS),
        )
        readme_gen = script_source("generate_readme.py")
        self.assertIn("NODEDUP_DIRS", readme_gen)


class SkipPacksHelpSaysWhatRuns(unittest.TestCase):
    """--help said "Only regenerate DB and verify" while the run went on to
    rewrite derivable.json, README.md and docs/."""

    def test_the_help_names_the_steps_that_still_run(self):
        proc = subprocess.run(
            [sys.executable, "scripts/pipeline.py", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=True,
        )
        text = " ".join(proc.stdout.split())
        self.assertNotIn("Only regenerate DB and verify", text)
        self.assertIn("step 4e still rewrites install/games/, and steps 7 to 8b rewrite README.md "
                      "and the site unless --skip-docs is given", text)
        self.assertNotIn("docs/", text)

    def test_every_step_it_names_is_one_it_skips(self):
        from orchestrate.labels import step_number

        source = script_source("pipeline.py")
        keys = re.findall(r'skip_notice\("(\w+)", "--skip-packs"\)', source)
        skipped = {step_number(key) for key in keys}
        self.assertEqual(skipped, {"4", "4b", "4c", "6"})


if __name__ == "__main__":
    unittest.main()
