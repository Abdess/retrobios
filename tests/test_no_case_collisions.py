from __future__ import annotations

import subprocess
import unittest
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BIOS_ROOT = REPO_ROOT / "bios"


def case_collisions(paths: list[str]) -> list[list[str]]:
    """Spellings one casefolded path takes among *paths* and their parents.

    A file and a directory are compared too: font.rom beside a FONT.ROM/
    tree is one name to Windows and macOS. Hash-suffixed .variants/ names
    are names like any other.
    """
    nodes: set[str] = set()
    for path in paths:
        parts = path.split("/")
        nodes.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    groups: dict[str, set[str]] = defaultdict(set)
    for node in nodes:
        groups[node.casefold()].add(node)
    return sorted(sorted(spellings) for spellings in groups.values() if len(spellings) > 1)


class TestNoCaseCollisions(unittest.TestCase):
    """Guard against case-colliding paths in bios/.

    On case-insensitive filesystems (Windows, macOS default), git can only
    check out one path per casefold-equivalence class, silently corrupting
    clones. Issue #33 and #49 both stemmed from this. Read from the git
    index, which is what a clone checks out, not from the disk.
    """

    def test_bios_has_no_case_colliding_paths(self) -> None:
        listed = subprocess.run(
            ["git", "ls-files", "-z", "--", "bios"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        if listed.returncode != 0 or not listed.stdout:
            self.skipTest("not a git checkout with bios/")
        collisions = case_collisions([p for p in listed.stdout.split("\0") if p])
        self.assertEqual(
            collisions,
            [],
            "Case-colliding paths in bios/ would break Windows/macOS clones:\n"
            + "\n".join(map(str, collisions)),
        )

    def test_a_file_and_a_directory_collide(self) -> None:
        self.assertEqual(
            case_collisions(["bios/NEC/font.rom", "bios/NEC/FONT.ROM/a.bin"]),
            [["bios/NEC/FONT.ROM", "bios/NEC/font.rom"]],
        )
        self.assertEqual(
            case_collisions(["bios/x/.variants/BIOS.ROM.910fae67",
                             "bios/x/.variants/bios.rom.910fae67"]),
            [["bios/x/.variants/BIOS.ROM.910fae67", "bios/x/.variants/bios.rom.910fae67"]],
        )


class SharedGroupsAddNoSecondSpelling(unittest.TestCase):
    """The np2kai group added np2kai/font.rom beside System.dat's
    np2kai/FONT.ROM. NP2kai reads font.rom only when FONT.ROM is absent: an
    alternative name, which belongs in the profile's aliases. On Lakka and
    RetroPie, whose filesystems keep both, the pack carried the font twice
    and verify counted one more required file."""

    def test_no_group_entry_respells_a_declared_destination(self) -> None:
        import sys

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from common import (
            list_registered_platforms,
            load_emulator_profiles,
            load_platform_config,
        )

        # A spelling some code opens as its own file stands: NP2kai's rhythm
        # engine reads 2608_bd.wav, its fmgen engine 2608_BD.WAV, and a
        # case-sensitive filesystem needs both. A spelling that is only ever
        # an alias is the same file asked for twice.
        read_as_named = {
            str(entry.get("path") or entry.get("name") or "")
            for profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).values()
            for entry in profile.get("files", [])
            if isinstance(entry, dict)
        }
        platforms_dir = str(REPO_ROOT / "platforms")
        respelled: list[str] = []
        for name in list_registered_platforms(platforms_dir):
            config = load_platform_config(name, platforms_dir)
            own: dict[str, str] = {}
            grouped: list[tuple[str, str]] = []
            for system in config.get("systems", {}).values():
                for entry in system.get("files", []):
                    dest = entry.get("destination") or entry.get("name") or ""
                    if entry.get("shared_group"):
                        grouped.append((dest, entry["shared_group"]))
                    else:
                        own.setdefault(dest.casefold(), dest)
            for dest, group in grouped:
                spelled = own.get(dest.casefold())
                named = dest in read_as_named
                if spelled and spelled != dest and not named:
                    respelled.append(f"{name}: {group} adds {dest} beside {spelled}")
        self.assertEqual(respelled, [])


class Np2kaiRhythmSamplesAreTwoSets(unittest.TestCase):
    """NP2kai's rhythm engine opens 2608_bd.wav, fmgen 2608_BD.WAV, and
    getbiospath folds no case. Filed as aliases of one entry, a pack built
    from the profile shipped one spelling and reported both OK."""

    def test_each_spelling_is_its_own_entry(self):
        import sys

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from common import load_emulator_profiles

        files = load_emulator_profiles(str(REPO_ROOT / "emulators"))["np2kai"]["files"]
        paths = {entry.get("path") for entry in files}
        aliases = {alias for entry in files for alias in entry.get("aliases", [])}
        for sample in ("BD", "SD", "TOP", "HH", "TOM", "RIM"):
            with self.subTest(sample=sample):
                self.assertIn(f"np2kai/2608_{sample.lower()}.wav", paths)
                self.assertIn(f"np2kai/2608_{sample}.WAV", paths)
                self.assertNotIn(f"2608_{sample}.WAV", aliases)
        self.assertNotIn("2608_RYM.WAV", aliases)


if __name__ == "__main__":
    unittest.main()
