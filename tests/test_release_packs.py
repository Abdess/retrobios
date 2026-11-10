"""Which platforms a release publishes a ZIP for, and how every surface says it.

The release carried a pack for every platform, 35 GB, while five of them
drew 83% of the downloads. `release_pack: true` in the registry is now the
list: the build, the pack checks, the release record and every download
table read it. The other platforms keep their install manifest, and each
page that would show a ZIP says there is none and gives the command.

Every release also deleted the previous tag, and with it each asset URL:
six of the eight links a community wiki had to our packs answered 404. Each
platform has a permanent page at get/<platform>/ instead.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import release_record  # noqa: E402

PLATFORMS = str(REPO_ROOT / "platforms")
TMP_ROOT = REPO_ROOT / "tmp"
SITE = "https://abdess.github.io/retrobios/"
# The owner's choice of 2026-10-23, from the download counts of v2026.10.10.
RELEASED = {"retroarch", "emudeck", "retrobat", "batocera", "romm", "misterfpga"}


def _write_registry(root: Path, platforms: dict) -> str:
    platforms_dir = root / "platforms"
    platforms_dir.mkdir()
    for name in platforms:
        (platforms_dir / f"{name}.yml").write_text(
            yaml.dump({"platform": name.title(), "systems": {}}), encoding="utf-8"
        )
    registry = {name: {"config": f"{name}.yml", **entry} for name, entry in platforms.items()}
    (platforms_dir / "_registry.yml").write_text(
        yaml.dump({"platforms": registry}), encoding="utf-8"
    )
    return str(platforms_dir)


def _which_pack() -> str:
    import generate_site

    with contextlib.chdir(REPO_ROOT):
        return generate_site.generate_which_pack()


class TheFieldIsTheList(unittest.TestCase):
    def test_the_registry_marks_the_most_downloaded_setups(self):
        self.assertEqual(
            set(common.list_release_pack_platforms(PLATFORMS)), RELEASED
        )

    def test_only_marked_platforms_are_listed(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            platforms_dir = _write_registry(Path(tmp), {
                "big": {"release_pack": True},
                "small": {},
                "off": {"release_pack": False},
            })
            self.assertEqual(common.list_release_pack_platforms(platforms_dir), ["big"])
            self.assertEqual(
                common.list_registered_platforms(platforms_dir), ["big", "off", "small"]
            )

    def test_the_schema_holds_the_field(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")

        schema = json.loads((REPO_ROOT / "schemas" / "registry.schema.json").read_text())
        validator = Draft202012Validator(schema)
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        self.assertEqual([e.message for e in validator.iter_errors(registry)], [])
        registry["platforms"]["knulli"]["release_pack"] = "yes"
        self.assertTrue(list(validator.iter_errors(registry)))


class NoPlatformIsSetApart(unittest.TestCase):
    """A registry `status: archived` kept RetroPie out of every full run
    unless --include-archived was typed, after release_pack had become the
    only thing that sets platforms apart. A platform is registered or not."""

    def test_the_registry_carries_no_status(self):
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        flagged = sorted(
            name for name, entry in registry["platforms"].items() if "status" in (entry or {})
        )
        self.assertEqual(flagged, [])

    def test_the_schema_declares_no_status(self):
        text = (REPO_ROOT / "schemas" / "registry.schema.json").read_text(encoding="utf-8")
        for word in ('"status"', "archived"):
            with self.subTest(word=word):
                self.assertNotIn(word, text)

    def test_no_script_knows_the_word(self):
        found = sorted(
            str(path.relative_to(REPO_ROOT))
            for path in (REPO_ROOT / "scripts").rglob("*.py")
            if any(
                word in path.read_text(encoding="utf-8").lower()
                for word in ("archived", "include_archived", "include-archived")
            )
        )
        self.assertEqual(found, [])


class TheBuildReadsTheField(unittest.TestCase):
    def _groups(self, *argv: str) -> list[str]:
        import generate_pack

        built: list[str] = []

        def capture(args, groups, *rest, **kw):
            built.extend(name for group, _rep in groups for name in group)

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as out, \
                contextlib.chdir(REPO_ROOT), \
                mock.patch.object(generate_pack, "_run_platform_packs", capture), \
                mock.patch.object(generate_pack, "_run_manifest_mode", capture), \
                mock.patch.object(sys, "argv", ["generate_pack.py", *argv, "--output-dir", out]), \
                contextlib.redirect_stdout(io.StringIO()):
            generate_pack.main()
        return built

    def test_all_builds_the_release_packs_only(self):
        self.assertEqual(set(self._groups("--all", "--offline")), RELEASED)

    def test_manifests_cover_every_platform(self):
        self.assertEqual(
            set(self._groups("--all", "--manifest", "--offline")),
            set(common.list_registered_platforms(PLATFORMS)),
        )

    def test_the_release_owners_are_the_marked_platforms(self):
        owners = release_record.release_owners(PLATFORMS)
        served = {p for platforms in owners.values() for p in platforms}
        self.assertEqual(served, RELEASED)

    def test_the_list_marks_installer_only_platforms(self):
        import subprocess

        proc = subprocess.run(
            [sys.executable, "scripts/generate_pack.py", "--list"],
            capture_output=True, text=True, cwd=REPO_ROOT, check=True, timeout=120,
        )
        lines = proc.stdout.splitlines()
        for name in RELEASED:
            self.assertIn(name, lines)
        self.assertIn("recalbox (installer only)", lines)


class APlatformWithoutAPackFailsNoCheck(unittest.TestCase):
    VERIFY = (
        "RetroArch: 10/10 OK [existence]\n"
        "KNULLI: 5/5 OK [md5]\n"
    )
    PACK = (
        "Generating pack for RetroArch...\n"
        "  dist/RetroArch_BIOS_Pack.zip: 10 files packed, 10/10 files OK [existence]\n"
    )

    def test_the_consistency_step_skips_a_setup_served_by_the_installer(self):
        import pipeline

        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertTrue(pipeline.check_consistency(
                self.VERIFY, self.PACK, pipeline.release_pack_keys(PLATFORMS)))
        self.assertIn("KNULLI: 5/5 (no release pack, served by the installer)", out.getvalue())

    def test_a_released_platform_without_its_pack_still_fails(self):
        import pipeline

        verify = self.VERIFY + "Batocera: 3/3 OK [md5]\n"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertFalse(pipeline.check_consistency(
                verify, self.PACK, pipeline.release_pack_keys(PLATFORMS)))
        # The failing line says it fails: "(no separate pack)" read like
        # the installer-only note above it.
        self.assertIn("Batocera: MISSING pack: verify judged 3/3 but the build wrote no pack for it",
                      out.getvalue())

    def test_the_pipeline_passes_the_release_platforms(self):
        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertIn("release_pack_keys()", source)

    def test_verify_packs_sweeps_the_release_packs_only(self):
        import subprocess

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            proc = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--all", "--verify-packs",
                 "--output-dir", directory],
                capture_output=True, text=True, cwd=REPO_ROOT, timeout=600,
            )
        swept = {line.split(":")[0].strip() for line in proc.stdout.splitlines()
                 if "SKIP (no pack in" in line}
        self.assertEqual(swept, RELEASED)


class TheReleaseCheckReadsTheField(unittest.TestCase):
    RECORD = {"tag": "v1", "packs": {
        "A_BIOS_Pack.zip": {"download_size": 1, "assets": ["A_BIOS_Pack.zip"],
                            "platforms": ["retroarch"]},
        "K_BIOS_Pack.zip": {"download_size": 1, "assets": ["K_BIOS_Pack.zip"],
                            "platforms": ["knulli"]},
    }}

    def test_a_missing_and_an_unlisted_pack_are_reported(self):
        from check_release import Asset, compare_release

        sums = {"A_BIOS_Pack.zip": "a" * 64, "K_BIOS_Pack.zip": "b" * 64}
        assets = {name: Asset(1, digest) for name, digest in sums.items()}
        assets["SHA256SUMS.txt"] = Asset(1, None)
        findings = compare_release(self.RECORD, sums, assets, "v1", None,
                                   {"retroarch", "batocera"})
        kinds = {(f.kind, f.name) for f in findings}
        self.assertIn(("no-pack", "batocera"), kinds)
        self.assertIn(("not-released", "K_BIOS_Pack.zip"), kinds)
        self.assertNotIn(("no-pack", "retroarch"), kinds)


class TheTablesFollowTheField(unittest.TestCase):
    def test_a_pack_of_a_platform_without_the_field_is_not_advertised(self):
        record = {"tag": "v1", "packs": {
            "RetroArch_Lakka_BIOS_Pack.zip": {"platforms": ["lakka", "retroarch"],
                                              "assets": ["x.zip"]},
            "Recalbox_BIOS_Pack.zip": {"platforms": ["recalbox"], "assets": ["y.zip"]},
        }}
        shown = release_record.advertised(record, PLATFORMS)
        self.assertEqual(list(shown["packs"]), ["RetroArch_Lakka_BIOS_Pack.zip"])
        self.assertEqual(shown["packs"]["RetroArch_Lakka_BIOS_Pack.zip"]["platforms"],
                         ["retroarch"])
        self.assertIsNone(release_record.pack_for("lakka", shown))
        self.assertEqual(release_record.advertised({}, PLATFORMS), {})


class EverySurfaceSaysWhy(unittest.TestCase):
    def test_a_setup_page_says_no_zip_with_the_command_beside_it(self):
        import generate_site

        line = generate_site.no_zip_line("KNULLI")
        self.assertEqual(line, "No ZIP for KNULLI. The command installs every file and checks it.")
        with contextlib.chdir(REPO_ROOT):
            block = generate_site._pack_buttons("knulli")
            guide = generate_site._guide_download(
                "knulli", "KNULLI", generate_site.GUIDES["knulli"], None, "## Download")
        self.assertIn(line, block)
        self.assertIn(generate_site.NO_ZIP_FAQ, block)
        self.assertIn(line, "\n".join(guide))
        self.assertNotIn("yet", block)

    def test_a_built_setup_page_has_the_line(self):
        page = REPO_ROOT / "website" / "src" / "content" / "docs" / "platforms" / "knulli.md"
        if not page.is_file():
            self.skipTest("the site is not generated")
        text = page.read_text(encoding="utf-8")
        self.assertIn("No ZIP for KNULLI. The command installs every file and checks it.", text)
        install = text.index("## Install")
        self.assertLess(install, text.index("No ZIP for KNULLI"))

    def test_get_your_files_explains_the_rows(self):
        page = _which_pack()
        self.assertIn("No ZIP. [Use the command](platforms/knulli.md#install).", page)
        self.assertIn("ZIPs are made for the setups most people download.", page)
        self.assertIn("wiki/faq.md#why-is-there-no-zip-for-my-setup", page)

    def test_the_readme_rows_read_use_the_command(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        line = next(text for text in readme.split("\n\n") if "ZIPs are made for the setups most people download." in text)
        self.assertIn(f"[KNULLI]({SITE}get/knulli/)", line)
        self.assertIn("install with the line above", line)

    def test_the_faq_answers_why(self):
        faq = (REPO_ROOT / "wiki" / "faq.md").read_text(encoding="utf-8")
        section = faq.split("## Why is there no ZIP for a setup?", 1)[1].split("\n## ", 1)[0]
        self.assertIn("most people download", section)
        self.assertIn("checks each one", section)
        self.assertIn("--dry-run", section)

    def test_the_release_process_documents_the_field_and_the_counts(self):
        page = (REPO_ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        self.assertIn("release_pack: true", page)
        self.assertIn("download_count", page)
        self.assertIn("part1of", page)


class TheReleaseNotesNameTheSetupsWithoutAZip(unittest.TestCase):
    RECORD = {"tag": "v2026.10.24", "packs": {
        "RomM_5_BIOS_Pack.zip": {
            "files": 1, "extracted_size": 1, "download_size": 1,
            "assets": ["RomM_5_BIOS_Pack.zip"], "platforms": ["romm"]},
    }}

    def test_the_paragraph_names_them_and_points_to_the_command(self):
        import release_notes

        text = release_notes.render(self.RECORD, PLATFORMS, "### What changed\n\n- x\n")
        paragraph = next(line for line in text.splitlines()
                         if line.startswith("Only the most used setups have a pack"))
        for name in ("KNULLI", "Recalbox", "RetroPie", "Lakka"):
            self.assertIn(name, paragraph)
        for name in ("RetroArch", "Batocera", "RomM"):
            self.assertNotIn(f" {name},", paragraph)
        self.assertTrue(paragraph.endswith("use the command above."))
        self.assertLess(text.index("| Platform"), text.index(paragraph))
        self.assertLess(text.index(paragraph), text.index("### What changed"))

    def test_the_rows_link_this_release_files(self):
        """The files sit right below the notes: a row sends nobody to the
        site to find them (owner, 2026-11-10)."""
        import release_notes

        text = release_notes.render(self.RECORD, PLATFORMS, "x")
        self.assertIn(
            "[Download](https://github.com/Abdess/retrobios/releases/download/"
            "v2026.10.24/RomM_5_BIOS_Pack.zip)", text)
        rows = [line for line in text.splitlines() if line.startswith("| ")]
        self.assertTrue(rows)
        for row in rows:
            self.assertNotIn(f"{SITE}get/", row)

    def test_the_command_comes_before_the_packs(self):
        """Most readers need a few files, not a pack of several GB (owner,
        2026-11-10): the command and the handheld app open the notes."""
        import release_notes

        text = release_notes.render(self.RECORD, PLATFORMS, "### What changed\n\n- x\n")
        command = text.index("```sh")
        # The installer's handheld section, which opens on every download.
        handheld = text.index(f"{SITE}wiki/installer/#on-a-handheld-the-retrobios-port")
        packs = text.index("### Full packs")
        self.assertLess(text.index("### Get your BIOS"), command)
        self.assertLess(command, handheld)
        self.assertLess(handheld, packs)
        self.assertLess(packs, text.index("| Platform"))
        self.assertLess(packs, text.index("### What changed"))
        self.assertNotIn("releases/download/", text[:packs])


class TheReleaseNotesThankPeople(unittest.TestCase):
    """The notes end with everyone who helped since the repository started
    and the full changelog, read from gh and git (owner, 2026-11-10).
    Fixtures stand in for both."""

    TAGS = {"c4": "v2026.11.10", "c3": "v2026.10.10", "c2": "v2026.10.10",
            "c1": "v2026.10.10", "c0": "v2026.09.04"}
    # `gh api --paginate --jq` prints one login per line, none for a
    # commit GitHub links to no account.
    COMMIT_AUTHORS = "Abdess\nhabib256\nAbdess76\ndependabot[bot]\nzed\nhabib256\n"
    PULLS = [
        {"number": 84, "author": {"login": "dajiaohuang", "is_bot": False}},
        {"number": 86, "author": {"login": "habib256", "is_bot": False}},
        {"number": 80, "author": {"login": "app/dependabot", "is_bot": True}},
        {"number": 67, "author": {"login": "prakashmagat50-byte", "is_bot": False}},
        {"number": 70, "author": {"login": "closedwithoutmerge", "is_bot": False}},
    ]
    ISSUES = [
        {"number": 87, "author": {"login": "paperweightorder", "is_bot": False}},
        {"number": 85, "author": {"login": "72374", "is_bot": False}},
        {"number": 83, "author": {"login": "72374", "is_bot": False}},
        {"number": 32, "author": {"login": "Bappo0", "is_bot": False}},
        {"number": 31, "author": {"login": "ghost", "is_bot": False}},
        {"number": 30, "author": {"login": "habib256", "is_bot": False}},
        {"number": 29, "author": {"login": "Abdess", "is_bot": False}},
    ]
    ISSUE_COMMENTS = "Abdess\nhelper\n72374\ngithub-actions[bot]\nAlpha\n"
    REVIEW_COMMENTS = "reviewer\nhabib256\n"

    def fake(self, argv):
        self.calls.append(argv)
        if argv[:2] == ["git", "log"]:
            return "\n".join(self.TAGS) + "\n"
        if argv[:2] == ["git", "show"]:
            return json.dumps({"tag": self.TAGS[argv[2].split(":")[0]]})
        if argv[:2] == ["gh", "api"]:
            path = argv[3]
            return {"repos/Abdess/retrobios/commits": self.COMMIT_AUTHORS,
                    "repos/Abdess/retrobios/issues/comments": self.ISSUE_COMMENTS,
                    "repos/Abdess/retrobios/pulls/comments": self.REVIEW_COMMENTS}[path]
        if argv[:3] == ["gh", "pr", "list"]:
            return json.dumps(self.PULLS)
        if argv[:3] == ["gh", "issue", "list"]:
            return json.dumps(self.ISSUES)
        raise AssertionError(argv)

    def setUp(self):
        self.calls = []

    def test_the_base_is_the_previous_release_record(self):
        import release_notes

        self.assertEqual(release_notes.previous_record_commit("v2026.11.10", self.fake), "c1")

    def test_everyone_since_the_start_is_thanked_once(self):
        import release_notes

        lines = release_notes.gather_thanks(self.fake)
        self.assertEqual(lines, [
            "- **Code and data**: @closedwithoutmerge, @dajiaohuang, @habib256 and @zed.",
            "- **Reports**: @72374 and @paperweightorder.",
            "- **Help in issues**: @Alpha, @helper and @reviewer.",
        ])
        text = "\n".join(lines)
        for left_out in ("Abdess", "bot", "dependabot", "ghost", "Bappo0", "prakashmagat50"):
            self.assertNotIn(left_out, text)
        # Every state: a pull request closed without merge still counts.
        pulls = next(argv for argv in self.calls if argv[:3] == ["gh", "pr", "list"])
        self.assertEqual(pulls[pulls.index("--state") + 1], "all")
        issues = next(argv for argv in self.calls if argv[:3] == ["gh", "issue", "list"])
        self.assertEqual(issues[issues.index("--state") + 1], "all")

    def test_the_notes_end_with_thanks_then_the_changelog(self):
        import release_notes

        closing = release_notes.closing_lines(
            ["- **Code and data**: @habib256."],
            release_notes.changelog_url("55eb95344" + "0" * 31, "v2026.11.10"))
        text = release_notes.render(TheReleaseNotesNameTheSetupsWithoutAZip.RECORD, PLATFORMS,
                                    "### What changed\n\n- x\n", closing)
        self.assertLess(text.index("### What changed"), text.index("### Thanks"))
        self.assertIn("### Thanks\n\n<details>\n"
                      "<summary>Everyone who helped since the start</summary>\n\n"
                      "- **Code and data**: @habib256.\n\n</details>\n\n**Full changelog**",
                      text)
        self.assertEqual(release_notes.refused_words(text), [])
        self.assertTrue(text.rstrip().endswith(
            "**Full changelog**: https://github.com/Abdess/retrobios/compare/"
            "55eb95344...v2026.11.10"))

    def test_a_checked_list_replaces_the_one_gh_gives(self):
        import release_notes

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            tmp = Path(tmp)
            (tmp / "whats-new.md").write_text("### What changed\n\n- x\n", encoding="utf-8")
            (tmp / "thanks.md").write_text("- **Code and data**: @habib256.\n",
                                           encoding="utf-8")
            (tmp / "release.json").write_text(
                json.dumps(TheReleaseNotesNameTheSetupsWithoutAZip.RECORD), encoding="utf-8")
            argv = ["release_notes.py", "--record", str(tmp / "release.json"),
                    "--whats-new", str(tmp / "whats-new.md"), "--thanks", str(tmp / "thanks.md"),
                    "--platforms-dir", PLATFORMS, "--output", str(tmp / "notes.md")]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(release_notes, "_run", self.fake), \
                    mock.patch.object(release_notes, "gather_thanks",
                                      side_effect=AssertionError("gh read")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(release_notes.main(), 0)
            text = (tmp / "notes.md").read_text(encoding="utf-8")
        self.assertIn("- **Code and data**: @habib256.\n", text)
        self.assertIn("/compare/c4...v2026.10.24", text)


class EveryPlatformHasAPermanentPage(unittest.TestCase):
    def test_a_page_for_every_registered_platform(self):
        import generate_site

        record = release_record.load_advertised()
        with contextlib.chdir(REPO_ROOT):
            for name in common.list_registered_platforms(PLATFORMS):
                page = generate_site.generate_get_page(name)
                pack = release_record.pack_for(name, record)
                with self.subTest(platform=name):
                    self.assertRegex(page, r"\n# (.+ )?BIOS (pack|files)( for .+)?\n")
                    if name in RELEASED and pack:
                        for asset in pack["assets"]:
                            self.assertIn(
                                f"/releases/download/{record['tag']}/{asset}", page)
                    elif name not in RELEASED:
                        self.assertNotIn("_BIOS_Pack", page)
                        self.assertIn(f"/i | sh -s -- --platform {name}", page)
                        self.assertIn("No ZIP for ", page)

    def test_the_generator_writes_and_sweeps_them(self):
        import generate_site

        self.assertIn(release_record.GET_DIR, generate_site.GENERATED_DIRS)
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('write_if_changed(str(get_dir / f"{name}.md"), generate_get_page(name))',
                      source)

    def test_built_pages_exist(self):
        docs = REPO_ROOT / "website" / "src" / "content" / "docs" / release_record.GET_DIR
        if not docs.is_dir():
            self.skipTest("the site is not generated")
        for name in common.list_registered_platforms(PLATFORMS):
            with self.subTest(platform=name):
                self.assertTrue(any(docs.glob(f"{name}.md*")))


class TheSiteCheckResolvesEveryGetPage(unittest.TestCase):
    def _site(self, root: Path, pages: dict[str, str]) -> Path:
        site = root / "dist"
        for rel, body in pages.items():
            path = site / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"<!doctype html><html lang=en><body>{body}</body></html>",
                            encoding="utf-8")
        return site

    def test_missing_and_wrong_pages_are_reported(self):
        import validate_site

        record = {"tag": "v1", "packs": {"RomM_BIOS_Pack.zip": {
            "platforms": ["romm"], "assets": ["RomM_BIOS_Pack.zip"],
            "files": 1, "extracted_size": 1, "download_size": 1}}}
        download = validate_site.RELEASE_DOWNLOAD
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            record_path = root / "release.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")
            pages = {
                f"get/{name}/index.html": "install.sh"
                for name in common.list_registered_platforms(PLATFORMS)
            }
            pages["get/romm/index.html"] = f'<a href="{download}v1/RomM_BIOS_Pack.zip">x</a>'
            pages["get/knulli/index.html"] = f'<a href="{download}v1/K_BIOS_Pack.zip">x</a>'
            del pages["get/lakka/index.html"]
            site = self._site(root, pages)
            parsed = {p.resolve(): validate_site._parse_page(p) for p in site.rglob("*.html")}
            issues = validate_site._check_get_pages(parsed, site.resolve(), Path(PLATFORMS),
                                                    record_path)
        joined = "\n".join(issues)
        self.assertIn("get/lakka/index.html: no download page", joined)
        self.assertIn("get/knulli/index.html: links a pack", joined)
        self.assertIn("get/knulli/index.html: gives no install command", joined)
        self.assertNotIn("get/romm/", joined)
        self.assertNotIn("get/retroarch/", joined)

    def test_the_cli_runs_the_check(self):
        source = (REPO_ROOT / "scripts" / "validate_site.py").read_text(encoding="utf-8")
        self.assertIn("validate_site(Path(args.site_dir), args.base, args.platforms_dir, args.record)",
                      source)


if __name__ == "__main__":
    unittest.main()
