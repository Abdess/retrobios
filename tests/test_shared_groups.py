"""A shared group adds files, never a second name for a native one.

The quasi88 group declared N88SUB.ROM beside the disk.rom System.dat
already names for nec-pc-88, same bytes: the RetroArch pack carried the
2 KB ROM twice under quasi88/, and the group read as twelve required files
where four did the work. Alternative names are aliases in the profile.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import list_registered_platforms, load_platform_config  # noqa: E402

PLATFORMS = str(REPO_ROOT / "platforms")


def _md5s(entry: dict) -> set[str]:
    raw = entry.get("md5") or ""
    values = raw if isinstance(raw, list) else str(raw).split(",")
    return {v.strip().lower() for v in values if v and v.strip()}


class SharedGroupsAddOnly(unittest.TestCase):
    def test_no_shared_file_repeats_a_native_file_of_the_same_directory(self):
        shared = yaml.safe_load((REPO_ROOT / "platforms" / "_shared.yml").read_text())
        groups = shared.get("shared_groups") or {}
        repeated = []
        for platform in list_registered_platforms(PLATFORMS, include_archived=True):
            config = load_platform_config(platform, PLATFORMS)
            for system in config.get("systems", {}).values():
                included = [
                    fe for group in system.get("includes", []) for fe in groups.get(group, [])
                ]
                if not included:
                    continue
                group_keys = {
                    (fe.get("name"), fe.get("destination", fe.get("name"))) for fe in included
                }
                native: dict[tuple[str, str], str] = {}
                for fe in system.get("files", []):
                    if (fe.get("name"), fe.get("destination", fe.get("name"))) in group_keys:
                        continue
                    dest = fe.get("destination") or fe.get("name", "")
                    directory = dest.rsplit("/", 1)[0] if "/" in dest else ""
                    for md5 in _md5s(fe):
                        native.setdefault((directory, md5), fe.get("name", ""))
                for fe in included:
                    dest = fe.get("destination") or fe.get("name", "")
                    directory = dest.rsplit("/", 1)[0] if "/" in dest else ""
                    for md5 in _md5s(fe):
                        other = native.get((directory, md5))
                        if other and other.lower() != fe.get("name", "").lower():
                            repeated.append(f"{platform}:{fe['name']} = {other}")
        self.assertEqual(repeated, [])

if __name__ == "__main__":
    unittest.main()
