"""Emulator pages.

61 profiles cite the folder their app reads its data from (data_root) and
no page printed it: AetherSX2's step said "inside the app's own data
folder", ten pages named the field itself, and every install block offered
Linux, Windows and Android commands, for MAME4droid an Android-only app.
215 pages printed `--emulator X` for a name no published manifest takes.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402

CONTENT = REPO_ROOT / "website" / "src" / "content" / "docs"
EMULATORS = CONTENT / "emulators"


def _profile(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / "emulators" / f"{name}.yml").read_text(encoding="utf-8"))


def _profiles_with_data_root() -> dict[str, dict]:
    found = {}
    for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
        profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(profile, dict) and isinstance(profile.get("data_root"), dict):
            found[path.stem] = profile
    return found


def _page(name: str) -> str:
    for suffix in (".mdx", ".md"):
        path = EMULATORS / f"{name}{suffix}"
        if path.exists():
            return path.read_text(encoding="utf-8")
    return ""


def _generated() -> bool:
    return EMULATORS.is_dir() and any(EMULATORS.iterdir())


def _install_section(page: str) -> str:
    match = re.search(r"<summary>Install this emulator's files</summary>(.*?)</details>",
                      page, re.S)
    return match[1] if match else ""


def _tab_labels(text: str) -> set[str]:
    return set(re.findall(r'<TabItem label="([^"]+)">', text))


def _entries(profile: dict) -> list[dict]:
    return [f for f in profile.get("files") or [] if isinstance(f, dict)]


def _alternatives(root: str) -> list[str]:
    return [part.strip().rstrip("/") for part in root.split(", else ")]


class FolderOnlyTable(unittest.TestCase):
    """The entries whose joined path is not the app's folder: one table in
    the generator, each row with its reason, and it cannot rot."""

    def test_every_row_names_a_profile_and_entries_that_exist(self) -> None:
        roots = _profiles_with_data_root()
        for profile_name, patterns, keys, reason in gs.FOLDER_ONLY:
            with self.subTest(profile=profile_name, patterns=patterns):
                self.assertIn(profile_name, roots, "no profile with data_root by that name")
                self.assertTrue(reason.strip())
                entries = _entries(roots[profile_name])
                for pattern in patterns:
                    self.assertTrue(
                        any(gs.folder_only_matches(pattern, f) for f in entries),
                        f"{pattern!r} names no entry of {profile_name}")
                self.assertLessEqual(set(keys), set(roots[profile_name]["data_root"]))

    def test_a_listed_entry_is_never_joined_to_the_root(self) -> None:
        roots = _profiles_with_data_root()
        for profile_name, patterns, keys, _reason in gs.FOLDER_ONLY:
            profile = roots[profile_name]
            for entry in _entries(profile):
                if not any(gs.folder_only_matches(p, entry) for p in patterns):
                    continue
                raw = {str(entry.get(k) or "") for k in ("path", "standalone_path")} - {""}
                for key in keys or tuple(profile["data_root"]):
                    with self.subTest(profile=profile_name, entry=entry.get("name"), key=key):
                        self.assertEqual(gs.standalone_place(profile_name, profile, entry, key), "")
                        self.assertEqual(gs.standalone_place(profile_name, profile, entry), "")
                        block = "\n".join(gs.data_folder_block(profile_name, profile))
                        for root in _alternatives(str(profile["data_root"][key]["path"])):
                            for place in raw:
                                self.assertNotIn(f"{root}/{place}", block)

    def test_built_pages_print_no_joined_path_for_a_listed_entry(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        roots = _profiles_with_data_root()
        for profile_name, patterns, keys, _reason in gs.FOLDER_ONLY:
            profile = roots[profile_name]
            pages = [p.read_text(encoding="utf-8")
                     for p in EMULATORS.glob(f"{profile_name}*.md*")]
            for entry in _entries(profile):
                if not any(gs.folder_only_matches(p, entry) for p in patterns):
                    continue
                for key in keys or tuple(profile["data_root"]):
                    for root in _alternatives(str(profile["data_root"][key]["path"])):
                        for place in {entry.get("path"), entry.get("standalone_path")} - {None, ""}:
                            joined = f"{root}/{place}"
                            for text in pages:
                                self.assertNotIn(joined, text, profile_name)


class DataFolderPrinted(unittest.TestCase):
    def test_every_profile_prints_each_of_its_folders(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        for name, profile in _profiles_with_data_root().items():
            if profile.get("type") in ("alias", "test"):
                continue
            page = _page(name)
            with self.subTest(profile=name):
                self.assertIn('id="data-folder"', page)
                for root in profile["data_root"].values():
                    for alternative in _alternatives(str(root["path"])):
                        self.assertIn(alternative, page)

    def test_ryujinx_keys_sit_in_system(self) -> None:
        block = "\n".join(gs.data_folder_block("ryujinx", _profile("ryujinx")))
        self.assertIn("`%APPDATA%/Ryujinx/system/`", block)
        self.assertIn("`~/Library/Application Support/Ryujinx/system/`", block)
        self.assertEqual(_tab_labels(block), {"Windows", "macOS", "Linux"})

    def test_aethersx2_step_names_the_android_folder(self) -> None:
        profile = _profile("aethersx2")
        steps = gs._any_name_steps("AetherSX2", profile, gs.any_name_bios(profile), "", "aethersx2")
        self.assertIn("2. Put it in this folder:", steps)
        self.assertIn("`Android/data/xyz.aethersx2.android/files/bios/`, on the internal storage.",
                      steps)
        self.assertNotIn("app's own data folder", steps)

    def test_one_system_is_a_line_not_a_tab(self) -> None:
        block = "\n".join(gs.data_folder_block("mame4droid", _profile("mame4droid")))
        self.assertTrue(block.startswith("On Android: `Android/data/com.seleuco.mame4droid/files/`"))
        self.assertNotIn("<Tabs", block)

    def test_an_entry_found_by_name_or_shipped_is_not_placed(self) -> None:
        profile = {"type": "standalone", "data_root": {"linux": {"path": "~/x", "source_ref": "a"}}}
        self.assertEqual(gs.standalone_place("x", profile, {"name": "a.bin"}), "")
        self.assertEqual(gs.standalone_place("x", profile, {"name": "a", "path": "a", "bundled": True}),
                         "")
        self.assertEqual(gs.standalone_place("x", profile, {"name": "a", "path": "b/a"}), "b/a")
        dual = {**profile, "type": "standalone + libretro"}
        self.assertEqual(gs.standalone_place("x", dual, {"name": "a", "path": "core/a"}), "")
        self.assertEqual(gs.standalone_place("x", dual, {"name": "a", "path": "c/a",
                                                         "standalone_path": "a"}), "a")

    def test_the_metadata_card_has_a_row_per_system(self) -> None:
        rows = gs._render_metadata_rows(_profile("cxbx-reloaded"))
        self.assertIn("| Data folder (Windows) | `%APPDATA%/Cxbx-Reloaded/` |", rows)
        self.assertFalse(any("Data folder (Linux)" in row for row in rows))

    def test_no_page_names_the_field(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        named = sorted(str(p.relative_to(CONTENT)) for p in CONTENT.rglob("*.md*")
                       if "data_root" in p.read_text(encoding="utf-8")
                       and not p.relative_to(CONTENT).as_posix().startswith("wiki/profiling"))
        self.assertEqual(named, [])


class InstallBlockWhereItWorks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
        cls.install = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.install)
        cls.accepted: dict[str, set[str]] = {}
        for path in sorted((REPO_ROOT / "install").glob("*.json")):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            names = cls.install.emulator_names(manifest, manifest.get("files") or [],
                                               manifest.get("omitted_files") or [])
            for alias, profile in names.items():
                cls.accepted.setdefault(alias, set()).add(profile)

    def test_every_printed_command_names_this_profile_in_a_manifest(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        for path in sorted(EMULATORS.glob("*.md*")):
            text = path.read_text(encoding="utf-8")
            for name in set(re.findall(r"--emulator ([\w.+-]+)", text)):
                with self.subTest(page=path.name, name=name):
                    self.assertIn(path.stem, self.accepted.get(name, set()))

    def test_no_os_tab_outside_the_data_root(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        labels = {key: gs.TERMINALS[key][0] for key in gs.TERMINALS}
        for name, profile in _profiles_with_data_root().items():
            allowed = {labels["device"]}
            for key in profile["data_root"]:
                allowed |= {labels[t] for t in gs._DATA_ROOT_TERMINALS[key]}
            with self.subTest(profile=name):
                self.assertLessEqual(_tab_labels(_install_section(_page(name))), allowed)

    def test_android_only_app_gets_no_desktop_command(self) -> None:
        self.assertEqual(gs._install_block("mame4droid", _profile("mame4droid")), [])
        command, setups, oses = gs.emulator_install_route("cxbx-reloaded", _profile("cxbx-reloaded"))
        self.assertEqual(oses, ("windows",))

    def test_a_lone_app_is_named_with_the_setup_that_launches_it(self) -> None:
        text = "\n".join(gs._install_block("ryujinx", _profile("ryujinx")))
        self.assertRegex(text, r"With [^:]*EmuDeck[^:]*: the installer finds")
        self.assertNotIn("Android (Termux)", text)
        self.assertNotIn("RetroArch", text)

    def test_a_dual_app_says_what_the_command_fills(self) -> None:
        text = "\n".join(gs._install_block("duckstation", _profile("duckstation")))
        self.assertIn("For DuckStation inside RetroArch, Batocera or another setup.", text)

    def test_no_files_no_command(self) -> None:
        self.assertEqual(gs._install_block("beetle_wswan", _profile("beetle_wswan")), [])

    def test_tabs_follow_the_keys_given(self) -> None:
        tabs = "\n".join(gs.install_commands("--emulator x", oses=("linux", "steamdeck")))
        self.assertEqual(_tab_labels(tabs), {"Linux", "Steam Deck"})
        self.assertIn('syncKey="os"', tabs)
        blocks = "\n".join(gs.install_commands("--emulator x"))
        self.assertIn("Windows (PowerShell):", blocks)


class SmallFixes(unittest.TestCase):
    def test_structured_blocks_closed_below_the_files(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        page = _page("cemu")
        self.assertLess(page.index("## Files"), page.index("<summary>Firmware titles</summary>"))
        self.assertNotRegex(page, r"<details[^>]*open>\s*<summary>Firmware titles")

    def test_region_choice_summary(self) -> None:
        lines = gs._emulator_file_summary(_profile("duckstation")["files"])
        self.assertIn("One of 3 is required, for your games' region.", lines[0])
        self.assertNotIn("3 required", lines[0])

    def test_no_emulator_part_says_where_it_sits(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        parts = sorted(EMULATORS.glob("*-files-*.md*"))
        if not parts:
            self.skipTest("no split emulator page")
        said = [p.name for p in parts if "\nPart of [" in p.read_text(encoding="utf-8")]
        self.assertEqual(said, [])


if __name__ == "__main__":
    unittest.main()
