"""The file picker on Get your files lists what the installer installs.

The picker reads a compacted copy of each install/<platform>.json and keeps
a file when one of its systems is chosen, or when it has none and "other"
is chosen, then prints `--system` with the choices. install.py --system
narrows with install.narrow(). The two must agree file for file, or the
list the page shows is not what the command it prints installs.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import importlib.util
import json
import random
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)

PICKER = REPO_ROOT / "website" / "src" / "components" / "FilePicker.astro"


def picked(data: dict, chosen: set[str]) -> list[str]:
    """The picker's rule, as FilePicker.astro applies it."""
    wanted = {index for index, system in enumerate(data["systems"]) if system["id"] in chosen}
    other = install.OTHER_SYSTEMS in chosen
    return [dest for dest, _size, systems in data["files"]
            if (any(s in wanted for s in systems) if systems else other)]


class PickerMatchesInstaller(unittest.TestCase):
    def setUp(self):
        import sitestarlight  # noqa: PLC0415

        self.folder = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir() else None)
        self.out = Path(self.folder.name)
        self.count = sitestarlight.picker_data(REPO_ROOT / "install", self.out,
                                                {"sony-playstation": "Sony PlayStation"})

    def tearDown(self):
        self.folder.cleanup()

    def test_every_manifest_has_its_list(self):
        index = json.loads((self.out / "index.json").read_text(encoding="utf-8"))
        manifests = [p for p in (REPO_ROOT / "install").glob("*.json")
                     if "files" in json.loads(p.read_text(encoding="utf-8"))]
        self.assertEqual(len(index), len(manifests))
        self.assertEqual(self.count, len(manifests))

    def test_random_selections_equal_install_narrow(self):
        rng = random.Random(20261022)
        checked = 0
        for entry in json.loads((self.out / "index.json").read_text(encoding="utf-8")):
            platform = entry["platform"]
            manifest = json.loads((REPO_ROOT / "install" / f"{platform}.json").read_text(encoding="utf-8"))
            data = json.loads((self.out / f"{platform}.json").read_text(encoding="utf-8"))
            choices = [s["id"] for s in data["systems"]] + ([install.OTHER_SYSTEMS] if data["other"] else [])
            for _round in range(10):
                chosen = set(rng.sample(choices, rng.randint(1, min(len(choices), 6))))
                files, _omitted = install.narrow(manifest["files"], [], sorted(chosen), [], [])
                with self.subTest(platform=platform, systems=sorted(chosen)):
                    self.assertEqual(sorted(picked(data, chosen)), sorted(f["dest"] for f in files))
                checked += 1
        self.assertGreater(checked, 0)

    def test_choices_are_what_the_installer_offers(self):
        for entry in json.loads((self.out / "index.json").read_text(encoding="utf-8")):
            manifest = json.loads((REPO_ROOT / "install" / f"{entry['platform']}.json").read_text(encoding="utf-8"))
            data = json.loads((self.out / f"{entry['platform']}.json").read_text(encoding="utf-8"))
            offered = install.available_choices(manifest["files"], [])["systems"]
            ours = [s["id"] for s in data["systems"]] + ([install.OTHER_SYSTEMS] if data["other"] else [])
            with self.subTest(platform=entry["platform"]):
                self.assertEqual(ours, offered)

    def test_component_applies_the_same_rule(self):
        """The rule above is the component's: a change to one fails here."""
        source = PICKER.read_text(encoding="utf-8")
        self.assertIn("systems.length ? systems.some((s) => wanted.has(s)) : other", source)
        self.assertIn("picked.includes('other')", source)
        self.assertRegex(source, re.escape("--system ${picked.join(',')}"))

    def test_systems_carry_their_page_title(self):
        """A beginner picks "Sony PlayStation". The id stays for the command."""
        data = json.loads((self.out / "batocera.json").read_text(encoding="utf-8"))
        psx = next(s for s in data["systems"] if s["id"] == "sony-playstation")
        self.assertEqual(psx["title"], "Sony PlayStation")
        self.assertIn("s.title || s.id", PICKER.read_text(encoding="utf-8"))

    def test_filter_hides_rows_and_survives_a_platform_change(self):
        """A display rule on the rows overrides the hidden attribute, and a new
        list must keep the query typed: otherwise None clears rows no one sees."""
        source = PICKER.read_text(encoding="utf-8")
        self.assertIn(".rb-pick-list label[hidden] { display: none; }", source)
        load = source[source.index("const load = async"):source.index("const applyFilter")]
        self.assertIn("applyFilter();", load)

    def test_sizes_use_the_installer_units(self):
        """The total the page shows is the one install.py prints for the same files."""
        source = PICKER.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"\b1e[369]\b")
        self.assertEqual(install.format_size(338_165_350), "322.5 MB")
        self.assertIn("(bytes / 1024 ** 2).toFixed(1)} MB", source)


if __name__ == "__main__":
    unittest.main()
