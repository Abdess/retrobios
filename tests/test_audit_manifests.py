"""Audit regressions on install manifests, the installer boundary and release assets."""

from __future__ import annotations

import tests
from tests.sources import script_source
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock
import yaml
import install
from orchestrate import runner
from scripts.packs.targets import generate_target_manifests
from tests.auditsupport import HAS_JSONSCHEMA, ROOT


class InstallerBoundaryRegressions(unittest.TestCase):
    def _manifest(self, dest: str) -> dict:
        return {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [
                {
                    "dest": dest,
                    "size": 1,
                    "sha1": "a" * 40,
                    "sha256": "b" * 64,
                    "repo_path": "bios/test.bin",
                    "cores": None,
                }
            ],
            "standalone_copies": [],
        }

    def test_manifest_destination_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe"):
            install._validate_manifest(self._manifest("../escape"), "retroarch")

    def test_manifest_repo_source_is_confined_to_bios(self):
        manifest = self._manifest("safe.bin")
        manifest["files"][0]["repo_path"] = "scripts/pipeline.py"
        with self.assertRaisesRegex(ValueError, "outside bios"):
            install._validate_manifest(manifest, "retroarch")

    def test_omitted_destination_cannot_overlap_a_download(self):
        manifest = self._manifest("safe.bin")
        manifest["omitted_files"] = [
            {
                "dest": "safe.bin",
                "name": "safe.bin",
                "system": "console",
                "required": True,
                "reason": "hash_mismatch",
                "cores": None,
            }
        ]
        manifest["total_omitted"] = 1
        with self.assertRaisesRegex(ValueError, "conflicting omitted"):
            install._validate_manifest(manifest, "retroarch")

    def test_omitted_destination_traversal_is_rejected(self):
        manifest = self._manifest("safe.bin")
        manifest["omitted_files"] = [
            {
                "dest": "../unsafe.bin",
                "name": "unsafe.bin",
                "system": "console",
                "required": True,
                "reason": "hash_mismatch",
                "cores": None,
            }
        ]
        manifest["total_omitted"] = 1
        with self.assertRaisesRegex(ValueError, "unsafe"):
            install._validate_manifest(manifest, "retroarch")

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_target_schema_accepts_the_null_the_generator_emits(self):
        """The schema and generate_target_manifests must agree on null.

        A target with no core list is written as null, and a schema that rejects
        it turns a valid manifest into a CI failure.
        """
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (ROOT / "schemas" / "target-manifest.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        document = {"windows": None, "switch": ["a5200"]}
        self.assertEqual(list(validator.iter_errors(document)), [])

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_pack_manifests_are_read_from_inside_the_archive(self):
        """generate_pack writes manifest.json into the ZIP, not beside it.

        A filesystem glob over dist/ matches nothing and reports success
        without validating a single document.
        """
        from schemas import packmanifests

        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            broken = {
                "schema_version": 1,
                "version": 1,
                "generator": "retrobios generate_pack.py",
                "generated": "2026-08-10T00:00:00Z",
                "files": [{"path": "a.bin", "sha1": "nope", "md5": "nope",
                           "size": 1, "status": "verified", "name": "a.bin"}],
                "summary": {"total_files": 1, "verified": 1, "untracked": 0,
                            "errors": 0},
                "errors": [],
            }
            with zipfile.ZipFile(dist / "Pack.zip", "w") as archive:
                archive.writestr("manifest.json", json.dumps(broken))

            errors = packmanifests.validate_pack_manifests(dist)
            self.assertTrue(errors, "an invalid in-archive manifest must be reported")
            self.assertTrue(any("sha1" in message for message in errors), errors)

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_packs_being_written_are_a_skip_not_a_pass(self):
        """Under a build's lock the reader returned [], the value of packs
        that validated, and validate_schemas announced everything valid
        without reading one."""
        from core.artifacts import ArtifactLockBusy, artifact_lock
        from schemas import packmanifests, run

        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory) / "dist"
            dist.mkdir()
            (dist / "Bad_BIOS_Pack.zip").write_bytes(b"not a zip")
            self.assertTrue(packmanifests.validate_pack_manifests(dist))
            with artifact_lock(str(dist), exclusive=True):
                with self.assertRaises(ArtifactLockBusy):
                    packmanifests.validate_pack_manifests(dist)
                outcome = run.Validation()
                with mock.patch.object(run.core.paths, "REPO_ROOT", Path(directory)):
                    run.generated_errors(outcome)
        self.assertEqual(outcome.skipped, ["pack manifests skipped, dist in use"])

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_a_pack_carries_its_install_list_and_board_lists(self):
        """pack_systems puts the install list and the per-board core lists
        in the pack's manifest.json, which install.py reads with the pack
        alone. The pack schema refused both keys, and each is checked under
        its own contract."""
        from packs import scope
        from schemas import packmanifests

        install_list = json.loads((ROOT / "install" / "romm.json").read_text(encoding="utf-8"))
        targets = {"browser": None, "rpi4": {"cores": ["mgba"], "images": ["rpi4"]}}
        document = {
            "schema_version": 1, "version": 1,
            "generator": "retrobios generate_pack.py",
            "generated": "2026-08-10T00:00:00Z", "files": [],
            "summary": {"total_files": 0, "verified": 0, "untracked": 0, "errors": 0},
            "errors": [],
        }
        scope.annotate_pack_systems(
            document, scope.pack_systems(install_list, targets))
        self.assertIn("install_list", document)
        self.assertIn("targets", document)
        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            with zipfile.ZipFile(dist / "Pack.zip", "w") as archive:
                archive.writestr("manifest.json", json.dumps(document))
            self.assertEqual(packmanifests.validate_pack_manifests(dist), [])

            broken = {**document, "targets": {"rpi4": [1]},
                      "install_list": {**install_list, "files": "none"}}
            with zipfile.ZipFile(dist / "Pack.zip", "w") as archive:
                archive.writestr("manifest.json", json.dumps(broken))
            errors = packmanifests.validate_pack_manifests(dist)
            self.assertTrue(any(":targets:" in message for message in errors), errors)
            self.assertTrue(any(":install_list:" in message for message in errors), errors)

    def test_null_core_list_keeps_the_other_targets(self):
        """A target without a core inventory must not void the manifest.

        generate_target_manifests emits null for a target that publishes no
        core list. Rejecting the document would silently disable --target for
        every target on that platform.
        """
        normalized = install._validate_targets({"windows": None, "switch": ["a5200"]})
        self.assertIsNone(normalized["windows"]["cores"])
        self.assertEqual(normalized["switch"]["cores"], ["a5200"])

    def test_legacy_target_lists_are_normalized(self):
        self.assertEqual(
            install._validate_targets({"rpi4": ["core-a", "core-b"]}),
            {"rpi4": {"cores": ["core-a", "core-b"]}},
        )


class TargetManifestRegressions(unittest.TestCase):
    def test_yaml_scalar_core_is_rejected_instead_of_leaking_to_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "output"
            source.mkdir()
            (source / "platform.yml").write_text(
                "targets:\n  device:\n    cores: [81, valid-core]\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "non-empty strings"):
                generate_target_manifests(str(source), str(output))

    def test_a_missing_targets_directory_fails_the_command(self):
        """--manifest-targets printed the missing directory and exited 0
        with nothing written: the pipeline step read that as done."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(FileNotFoundError, "No targets directory"):
                generate_target_manifests(str(root / "absent"), str(root / "out"))
            (root / "plat").mkdir()
            run = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "generate_pack.py"),
                 "--manifest-targets", "--platforms-dir", str(root / "plat"),
                 "--output-dir", str(root / "out")],
                capture_output=True, text=True, cwd=ROOT, check=False,
            )
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertIn("No targets directory at", run.stderr)


def _git_paths(*args: str, stdin: list[str] | None = None) -> set[str] | None:
    """The NUL-separated paths a git command prints, or None outside a
    checkout. check-ignore exits 1 when it matches nothing, an answer."""
    try:
        result = subprocess.run(
            ["git", *args],
            input="".join(f"{p}\0" for p in stdin or []),
            capture_output=True, text=True, cwd=ROOT, check=False,
        )
    except FileNotFoundError:
        return None
    answered = (0, 1) if args[0] == "check-ignore" else (0,)
    if result.returncode not in answered:
        return None
    return {p for p in result.stdout.split("\0") if p}


class ManifestVersionIsThePlatformsOwn(unittest.TestCase):
    """Every install manifest named its list "1.0", and an inheriting YAML
    took its parent's version: Lakka was published as RetroArch v1.22.2.
    The installer compares the list's version with the one a machine runs,
    so each manifest states the version its own platform YAML records."""

    def setUp(self):
        from scripts.model.platforms import _platform_config_cache
        _platform_config_cache.clear()

    def test_committed_manifests_state_their_platform_version(self):
        from scripts.model.platforms import load_platform_config
        manifests = sorted((ROOT / "install").glob("*.json"))
        self.assertTrue(manifests)
        for path in manifests:
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                config = load_platform_config(data["platform"], str(ROOT / "platforms"))
                self.assertTrue(config.get("version"))
                self.assertEqual(data["version"], str(config["version"]))

    def test_no_child_shows_its_parents_version(self):
        from scripts.model.platforms import load_platform_config
        platforms = ROOT / "platforms"
        children = {}
        for path in sorted(platforms.glob("*.yml")):
            raw = yaml.safe_load(path.read_text()) or {}
            if isinstance(raw, dict) and raw.get("inherits"):
                children[path.stem] = raw
        self.assertIn("lakka", children)
        for name, raw in children.items():
            with self.subTest(platform=name):
                parent = yaml.safe_load(
                    (platforms / f"{raw['inherits']}.yml").read_text())
                version = load_platform_config(name, str(platforms)).get("version")
                self.assertEqual(version, raw.get("version"))
                self.assertNotEqual(version, parent.get("version"))

    def test_an_unversioned_child_has_no_version(self):
        from scripts.model.platforms import load_platform_config
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "parent.yml").write_text("platform: P\nversion: '2.0'\nsystems: {}\n")
            Path(tmp, "child.yml").write_text("inherits: parent\nplatform: C\n")
            self.assertNotIn("version", load_platform_config("child", tmp))

    def test_lakka_names_the_release_its_cores_are_read_at(self):
        platforms = ROOT / "platforms"
        lakka = yaml.safe_load((platforms / "lakka.yml").read_text())
        targets = yaml.safe_load((platforms / "targets" / "lakka.yml").read_text())
        tag = re.search(r"/blob/([^/]+)/", targets["source"]).group(1)
        self.assertEqual(lakka["version"], tag)


class EveryManifestEntryIsFetchable(unittest.TestCase):
    """An install manifest may not list a file the installer cannot get.

    install.py fetches a file either from its repo_path or from a release
    asset. An entry carrying neither is a line in the download list that can
    only ever fail. It happened when resolution landed on a file the database
    does not index, so the hash was computed but the repo lookup came back
    empty and the entry shipped anyway.
    """

    def test_committed_manifests_all_have_a_source(self):
        manifests = sorted((ROOT / "install").glob("*.json"))
        self.assertTrue(manifests, "no install manifests to check")
        for path in manifests:
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                orphans = [
                    entry["dest"]
                    for entry in data.get("files", []) + data.get("case_variants", [])
                    if not entry.get("repo_path") and not entry.get("release_asset")
                ]
                self.assertEqual(
                    orphans, [], f"{path.name} lists unfetchable files: {orphans[:3]}"
                )

    def test_an_unresolvable_file_is_recorded_as_omitted(self):
        """The reason must be one install.py knows how to report."""
        for path in sorted((ROOT / "install").glob("*.json")):
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                for entry in data.get("omitted_files", []):
                    self.assertIn(entry.get("reason"), install.OMISSION_REASONS)

    def test_the_installer_accepts_every_published_manifest(self):
        """A reason the schema allowed and the installer did not made the
        installer refuse the whole RomM manifest: no RomM install ran."""
        for path in sorted((ROOT / "install").glob("*.json")):
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                install._validate_manifest(data, data["platform"])

    def test_every_standalone_layout_goes_with_its_list(self):
        """install/standalone/<platform>.json, which only --standalone
        reads: the installer accepts it against its own list, each item
        written whole has a source, and a list naming builds has its file."""
        listed = {path.stem: json.loads(path.read_text())
                  for path in sorted((ROOT / "install").glob("*.json"))}
        layouts = sorted((ROOT / "install" / "standalone").glob("*.json"))
        self.assertEqual({path.stem for path in layouts},
                         {plat for plat, data in listed.items()
                          if data.get("standalone_builds")})
        for path in layouts:
            with self.subTest(layout=path.name):
                data = json.loads(path.read_text())
                kept = install._check_standalone_layouts(data, listed[path.stem], path.stem)
                orphans = [item["dest"] for items in kept.values() for item in items
                           if isinstance(item, dict)
                           and not item.get("repo_path") and not item.get("release_asset")]
                self.assertEqual(orphans, [])

    def test_schema_and_installer_name_the_same_reasons(self):
        schema = json.loads(
            (ROOT / "schemas" / "install-manifest.schema.json").read_text()
        )
        reasons = schema["properties"]["omitted_files"]["items"]["properties"][
            "reason"
        ]["enum"]
        self.assertEqual(set(reasons), set(install.OMISSION_REASONS))

    def _manifests(self) -> list[Path]:
        paths = sorted((ROOT / "install").glob("*.json"))
        paths += sorted((ROOT / "install" / "targets").glob("*.json"))
        self.assertTrue(paths, "no install manifests to check")
        return paths

    def test_repo_paths_name_the_file_the_database_holds(self):
        """A manifest written before a file moved sends the installer to 404.

        database.json is regenerated whenever a file is refiled, but the manifests
        are a separate artefact and were left behind once (the two DS
        firmware dumps of the 7 September refile). The installer fetches
        repo_path from raw.githubusercontent.com, so a stale one is a
        download that can never succeed.
        """
        database = ROOT / "database.json"
        if not database.is_file():
            self.skipTest("database.json not generated")
        files = json.loads(database.read_text(encoding="utf-8"))["files"]
        for path in self._manifests():
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text(encoding="utf-8"))
                stale = [
                    (entry["dest"], entry["repo_path"], files.get(entry["sha1"], {}).get("path"))
                    for entry in data.get("files", []) + data.get("case_variants", [])
                    if entry.get("repo_path")
                    and files.get(entry.get("sha1", ""), {}).get("path") != entry["repo_path"]
                ]
                self.assertEqual(stale, [], f"{path.name} names moved files: {stale[:3]}")

    def test_release_entries_are_exactly_the_files_git_does_not_hold(self):
        """The installer has two sources, and the manifest must pick the right one.

        A committed file is served by the repository, a gitignored one by
        the large-files release. Marking a committed file as a release asset
        sends the installer to an asset nobody uploaded (sdlpal/5.avi, 83 MB
        in git, was announced as release asset `5.avi`). Marking a gitignored
        file as a repo file sends it to a raw URL that has no content. A
        file neither committed nor ignored is a commit nobody made, and is
        named as such rather than as a release asset.
        """
        tracked = _git_paths("ls-files", "-z", "--", "bios")
        if tracked is None:
            self.skipTest("not a git checkout")
        manifests: dict[str, list[dict]] = {}
        for path in self._manifests():
            data = json.loads(path.read_text(encoding="utf-8"))
            manifests[path.name] = [
                entry
                for entry in data.get("files", []) + data.get("case_variants", [])
                if entry.get("repo_path")
            ]
        outside = sorted(
            {e["repo_path"] for group in manifests.values() for e in group} - tracked
        )
        ignored = _git_paths("check-ignore", "-z", "--no-index", "--stdin", stdin=outside)
        if ignored is None:
            self.skipTest("not a git checkout")
        for name, group in manifests.items():
            with self.subTest(manifest=name):
                wrong = []
                for entry in group:
                    repo_path = entry["repo_path"]
                    state = (
                        "committed" if repo_path in tracked
                        else "gitignored" if repo_path in ignored
                        else "untracked, never committed"
                    )
                    if state == "untracked, never committed" or (
                        bool(entry.get("release_asset")) != (state == "gitignored")
                    ):
                        wrong.append((entry["dest"], repo_path, state))
                self.assertEqual(wrong, [], f"{name} picks the wrong source: {wrong[:3]}")

    def test_no_collected_file_is_left_uncommitted(self):
        """157 files of the 17 September campaign sat in bios/ untracked:
        the database indexed them, the manifests gave them a repo_path and
        the installer got a 404. A file under bios/ is either committed or
        listed in .gitignore as a release asset, nothing in between."""
        untracked = _git_paths("ls-files", "-z", "--others", "--exclude-standard", "--", "bios")
        if untracked is None:
            self.skipTest("not a git checkout")
        self.assertEqual(sorted(untracked)[:20], [], f"{len(untracked)} untracked files under bios/")

    def test_every_database_path_is_committed_or_a_release_asset(self):
        """A git mv under bios/ committed without regenerating anything left
        database.json and the manifests agreeing on the old path: the tests
        above compare them with each other, so all passed, and the installer
        got a 404 (issue 78, with the database stale too)."""
        database = ROOT / "database.json"
        if not database.is_file():
            self.skipTest("database.json not generated")
        files = json.loads(database.read_text(encoding="utf-8"))["files"]
        paths = {
            path
            for entry in files.values()
            for path in [entry.get("path"), *(entry.get("paths") or [])]
            if path
        }
        tracked = _git_paths("ls-files", "-z")
        if tracked is None:
            self.skipTest("not a git checkout")
        outside = sorted(paths - tracked)
        ignored = _git_paths("check-ignore", "-z", "--no-index", "--stdin", stdin=outside)
        if ignored is None:
            self.skipTest("not a git checkout")
        stale = [path for path in outside if path not in ignored]
        self.assertEqual(
            stale[:20], [],
            f"{len(stale)} database paths git neither holds nor ignores: "
            "python scripts/generate_db.py --force --bios-dir bios --output database.json, "
            "then the manifests",
        )


class ReleaseAssetCriterion(unittest.TestCase):
    """What decides whether the installer fetches from the release is git, not size.

    Files over 50 MB are supposed to be gitignored and uploaded to the
    large-files release, but four committed files break that rule and one of
    them reached a manifest as a release asset that does not exist. The
    truthful question is whether the repository serves the bytes, and the
    ledger of what it does not serve is .gitignore.
    """

    def _repo(self, directory: str, ignored: str) -> str:
        Path(directory, ".gitignore").write_text(ignored + "\n", encoding="utf-8")
        return directory

    def test_a_large_committed_file_is_served_by_the_repository(self):
        from scripts.packs import manifestentry

        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory, "bios/elsewhere.bin")
            big = Path(root, "bios", "big.avi")
            big.parent.mkdir()
            with big.open("wb") as handle:
                handle.truncate(60_000_000)
            manifestentry._registered.cache_clear()
            try:
                self.assertFalse(manifestentry._is_release_asset(str(big), root))
            finally:
                manifestentry._registered.cache_clear()

    def test_the_manifest_names_the_asset_as_github_serves_it(self):
        # GitHub publishes a space as a dot. The site linked the dotted
        # name while the manifest gave install.py the spaced one, a 404.
        from scripts.packs import manifestentry

        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory, "bios/MAME/MAME 0.174 Arcade XML.dat")
            target = Path(root, "bios", "MAME", "MAME 0.174 Arcade XML.dat")
            target.parent.mkdir(parents=True)
            target.write_bytes(b"x")
            manifestentry._registered.cache_clear()
            try:
                self.assertEqual(
                    manifestentry._release_asset_name(str(target), root),
                    "MAME.0.174.Arcade.XML.dat",
                )
            finally:
                manifestentry._registered.cache_clear()

    def test_a_gitignored_file_is_served_by_the_release_whatever_its_size(self):
        from scripts.packs import manifestentry

        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory, "bios/small.zip")
            small = Path(root, "bios", "small.zip")
            small.parent.mkdir()
            small.write_bytes(b"PK")
            manifestentry._registered.cache_clear()
            try:
                self.assertTrue(manifestentry._is_release_asset(str(small), root))
            finally:
                manifestentry._registered.cache_clear()


class ReleaseAssetsMatchTheCollection(unittest.TestCase):
    """The bytes the release serves must be the bytes the manifests describe.

    install.py checks Content-Length against the manifest size before it
    downloads, and the manifest size is that of the local copy. Both FBNeo
    sample archives were rebuilt locally after their upload and never
    re-uploaded: same members, different container, every install of them
    failed. The comparison is offline here on a fixture, while the script runs it
    against the live release.
    """

    def test_missing_and_resized_assets_are_reported_and_nothing_else(self):
        from scripts.release import assets as release_assets

        expected = {
            "bios/Other/fbneo/fbneo/samples/twotiger.zip": 154985212,
            "bios/Arcade/MAME/MAME 0.174 Arcade XML.dat": 53677408,
            "bios/Other/sdlpal/sdlpal/5.avi": 82833972,
        }
        assets = {
            "twotiger.zip": 154888877,
            "MAME.0.174.Arcade.XML.dat": 53677408,
            "unrelated.zip": 1,
        }
        findings = release_assets.compare(expected, assets)
        self.assertEqual(
            findings,
            [
                ("missing", "bios/Other/sdlpal/sdlpal/5.avi", 82833972, None),
                ("size", "bios/Other/fbneo/fbneo/samples/twotiger.zip", 154985212, 154888877),
            ],
        )

    def test_expected_assets_are_the_gitignored_database_entries(self):
        from scripts.release import assets as release_assets

        db = {
            "files": {
                "a" * 40: {"path": "bios/Other/x/big.zip", "size": 10},
                "b" * 40: {"path": "bios/Other/x/small.bin", "size": 2},
            }
        }
        gitignore = "# large\nbios/Other/x/big.zip\ntmp/\n"
        self.assertEqual(
            release_assets.expected_assets(db, gitignore),
            {"bios/Other/x/big.zip": 10},
        )

    def test_release_notes_are_rendered_from_the_collection(self):
        """The release page is written by hand and drifts, so it is rendered instead.

        Three assets had no row, three rows carried the SHA1 of an asset
        that had since been replaced, and the footer counted 41 files for 44.
        Hand-written descriptions survive by name. A new row takes its
        description from the profile that declares the file, and an asset the
        collection does not index is listed apart, with its size only.
        """
        from scripts.release import assets as release_assets

        db = {"files": {
            "a" * 40: {"path": "bios/Nintendo/Wii/nand.bin", "size": 553649152},
            "b" * 40: {"path": "bios/Other/fbneo/fbneo/samples/twotiger.zip", "size": 154985212},
            "c" * 40: {"path": "bios/Other/x/small.bin", "size": 2},
        }}
        gitignore = "bios/Nintendo/Wii/nand.bin\nbios/Other/fbneo/fbneo/samples/twotiger.zip\n"
        assets = {"nand.bin": 553649152, "twotiger.zip": 154985212,
                  "sdlpal-data.zip": 140773720, "whoopee.zip": 222665810}
        previous = (
            "## Arcade\n\n| File | Description | Size | SHA1 |\n|---|---|---|---|\n"
            "| [twotiger.zip](u) | Two Tigers samples | 148 MB | `" + "0" * 40 + "` |\n"
            "| [whoopee.zip](u) | Toaplan Whoopee samples | 212 MB | `" + "9" * 40 + "` |\n"
        )
        descriptions = {"nand.bin": "BootMii NAND backup"}
        bundles = {"sdlpal-data.zip": "SDLPAL Chinese Paladin game data (.mkf archives)"}
        body = release_assets.render_notes(
            db, gitignore, assets, previous, descriptions, bundles, {"sdlpal-data.zip": "d" * 40}
        )
        self.assertIn("| [twotiger.zip](https://github.com/Abdess/retrobios/releases/download/large-files/twotiger.zip) | Two Tigers samples | 147.8 MB | `" + "b" * 40 + "` |", body)
        self.assertIn("| [nand.bin](https://github.com/Abdess/retrobios/releases/download/large-files/nand.bin) | BootMii NAND backup | 528.0 MB | `" + "a" * 40 + "` |", body)
        self.assertIn("| [sdlpal-data.zip](https://github.com/Abdess/retrobios/releases/download/large-files/sdlpal-data.zip) | SDLPAL Chinese Paladin game data (.mkf archives) | 134.3 MB | `" + "d" * 40 + "` |", body)
        self.assertIn("## Not indexed", body)
        self.assertIn("| [whoopee.zip](https://github.com/Abdess/retrobios/releases/download/large-files/whoopee.zip) | Toaplan Whoopee samples | 212.4 MB |", body)
        self.assertNotIn("9" * 40, body)
        self.assertNotIn("small.bin", body)
        # The total reads in the unit of the rows above it: 1022.4 MB, not 1.0 GB.
        self.assertIn("4 files, 1022.4 MB total", body)
        self.assertEqual(body.index("## Console firmware"), min(
            body.index(h) for h in ("## Console firmware", "## Arcade", "## Not indexed")
        ))

    def test_stale_notes_are_a_finding(self):
        from scripts.release import assets as release_assets

        findings = release_assets.compare({}, {}, notes_current=False)
        self.assertEqual(findings, [("notes", "release description", 0, None)])

    def test_pipeline_runs_the_check_online_and_marks_it_skipped_offline(self):
        """Run with each step recorded instead of executed: reading the
        source for two strings stayed green with the guard inverted."""
        import contextlib
        import io
        from unittest import mock

        from scripts import pipeline

        def steps(*flags: str) -> tuple[list[str], str]:
            ran: list[str] = []

            def record(cmd, label):
                ran.append(label)
                return True, ""

            argv = ["pipeline.py", "--skip-packs", "--skip-docs", *flags]
            with mock.patch.object(runner, "run", record), \
                    mock.patch.object(sys, "argv", argv), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit) as done:
                pipeline.main()
            self.assertEqual(done.exception.code, 0)
            return ran, out.getvalue()

        online, _ = steps()
        self.assertIn("2b2 check release assets", online)
        offline, printed = steps("--offline")
        self.assertNotIn("2b2 check release assets", offline)
        self.assertIn("check_release_assets.................... SKIPPED", printed)


class EachRootReadsItsOwnRegistry(unittest.TestCase):
    """The release-asset registry was cached once per process whatever root
    was asked: a second tree got the first tree's .gitignore."""

    def test_two_roots_in_one_process(self):
        from scripts.packs import manifestentry

        with tempfile.TemporaryDirectory() as a, \
                tempfile.TemporaryDirectory() as b:
            Path(a, ".gitignore").write_text("bios/one.bin\n")
            Path(b, ".gitignore").write_text("bios/two.bin\n")
            self.assertTrue(manifestentry._is_release_asset(str(Path(a, "bios/one.bin")), a))
            self.assertFalse(manifestentry._is_release_asset(str(Path(b, "bios/one.bin")), b))
            self.assertTrue(manifestentry._is_release_asset(str(Path(b, "bios/two.bin")), b))

    def test_one_parser_reads_the_registry(self):
        for module in ("generate_pack.py", "generate_db.py"):
            source = script_source(module)
            with self.subTest(module=module):
                self.assertIn("load_registered_paths", source)
                self.assertNotIn('startswith("bios/")\n    }', source)


class TheInstallerNamesWhatItSkipped(unittest.TestCase):
    def test_count_agrees_and_required_files_are_named(self):
        one = install._omission_lines(1, [{"name": "diabdat.mpq", "required": True}])
        self.assertTrue(one[0].startswith("1 file was not installed"))
        self.assertTrue(any("diabdat.mpq" in line for line in one[1:]))
        many = install._omission_lines(
            12,
            [{"name": f"f{i:02}", "required": True, "system": f"s{i:02}",
              "cores": ["core"]} for i in range(12)],
        )
        self.assertTrue(many[0].startswith("12 files were not installed"))
        self.assertIn("    s00 (core): f00", many)
        self.assertTrue(any("and 4 more systems" in line for line in many))


class AManifestHashesAFileOnce(unittest.TestCase):
    """Every manifest entry rehashed its file with five algorithms: 70 476
    calls for 15 011 files, 163 s of a 218 s step."""

    def test_verified_hashes_are_reused(self):
        from scripts.packs import manifestentry

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "a.bin")
            path.write_bytes(b"abc")
            sha1 = hashlib.sha1(b"abc").hexdigest()
            db = {"files": {sha1: {"path": str(path)}}}
            calls = []
            real = manifestentry.compute_hashes

            def counting(file_path, algorithms=None):
                calls.append(algorithms)
                return real(file_path, algorithms)

            with mock.patch.object(manifestentry, "compute_hashes", counting):
                first = manifestentry._stable_hashes(str(path), db)
                second = manifestentry._stable_hashes(str(path), db)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], frozenset({"sha1", "sha256"}))


class ATreeNobodyHoldsIsMissingNotAnAsset(unittest.TestCase):
    """julius's caesar3/ directory, unexpanded, went to the asset store,
    which answered with .cache/large/ itself: the emulator pack died on
    IsADirectoryError where verify said MISSING."""

    def test_directory_entries_never_reach_the_asset_store(self):
        from scripts.model import largefiles
        from scripts.resolve import packfiles as packresolve

        db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}, "by_crc32": {},
                                      "by_path_suffix": {}}}
        for entry in ({"name": "caesar3/", "type": "directory"}, {"name": "caesar3/"}):
            with self.subTest(entry=entry):
                self.assertEqual(
                    packresolve.resolve_file(entry, db, "bios", {}, offline=True),
                    (None, "not_found"),
                )
        self.assertIsNone(largefiles.fetch_large_file("caesar3/", offline=True))
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "sub").mkdir()
            self.assertIsNone(largefiles._fetch_asset("sub", tmp, "", "", offline=True))


class InstallerJsonKindsNeverOverwriteEachOther(unittest.TestCase):
    """Install manifests and target core lists are both <platform>.json.
    --manifest-targets aimed at install/ replaced install/retroarch.json, the
    file every installer downloads, with a target table, exit 0."""

    def _run(self, *flags: str, held: str) -> tuple:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp, "retroarch.json")
            before = (ROOT / held).read_text(encoding="utf-8")
            target.write_text(before, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", *flags,
                 "--offline", "--output-dir", tmp],
                cwd=ROOT, capture_output=True, text=True, timeout=600,
                check=False,
            )
            return proc, before, target.read_text(encoding="utf-8")

    def test_target_lists_refuse_a_manifest_directory(self):
        proc, before, after = self._run(
            "--manifest-targets", held="install/retroarch.json"
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("holds install manifests", proc.stderr)
        self.assertIn("--output-dir", proc.stderr)
        self.assertEqual(after, before)

    def test_manifests_refuse_a_target_list_directory(self):
        proc, before, after = self._run(
            "--manifest", "--platform", "retroarch",
            held="install/targets/retroarch.json",
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("holds per-target core lists", proc.stderr)
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
