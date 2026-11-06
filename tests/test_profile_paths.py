"""A standalone app's paths are the folders its code opens below data_root.

The site prints data_root joined to each entry's standalone destination, so a
frontend's layout written there (Batocera's bios/switch/) sends the reader to a
folder the app never reads. A frontend folder name is allowed only where the
app's own code joins that folder to its data root.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

FRONTEND_FOLDERS = ("bios/", "switch/", "system/")

# Profiles whose code reads one of those folders below its data root.
CODE_READS = {
    # BIOS folder of the data directory, the PCSX2 layout it carries
    # (aethersx2 profile notes, AetherSX2-release MacOS/AetherSX2).
    "aethersx2": {"bios/"},
    # BIOS_FOLDER under gui_data_folder() (src/core/fds.c:305, src/core/cheat.c:105).
    "punes": {"bios/"},
    # KeysDir "system" under BaseDirPath
    # (src/Ryujinx.Common/Configuration/AppDataManager.cs:17, 229).
    "ryujinx": {"system/"},
    "kenji-nx": {"system/"},
    # PathSystem is the system folder beside DOSBoxPure.cfg (main.cpp:2032-2039).
    "dosbox-pure-unleashed": {"system/"},
}


def _standalone_profiles() -> dict[str, dict]:
    profiles = {}
    for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
        with path.open(encoding="utf-8") as fh:
            profile = yaml.safe_load(fh)
        if isinstance(profile, dict) and profile.get("data_root") \
                and profile.get("type") == "standalone":
            profiles[path.stem] = profile
    return profiles


def _destination(entry: dict) -> str:
    return str(entry.get("standalone_path") or entry.get("path") or "")


class StandaloneDestinations(unittest.TestCase):
    def test_no_frontend_folder_below_data_root(self):
        wrong = []
        for name, profile in _standalone_profiles().items():
            allowed = CODE_READS.get(name, set())
            for entry in profile.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                dest = _destination(entry)
                for folder in FRONTEND_FOLDERS:
                    if dest.startswith(folder) and folder not in allowed:
                        wrong.append(f"{name}: {entry.get('name')} at {dest}")
        self.assertEqual(wrong, [])

    def test_every_allowed_folder_is_read(self):
        profiles = _standalone_profiles()
        unused = []
        for name, folders in CODE_READS.items():
            dests = [_destination(e) for e in profiles.get(name, {}).get("files") or []
                     if isinstance(e, dict)]
            unused += [f"{name}: {folder}" for folder in sorted(folders)
                       if not any(d.startswith(folder) for d in dests)]
        self.assertEqual(unused, [])


if __name__ == "__main__":
    unittest.main()
