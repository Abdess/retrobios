"""A platform's coverage does not depend on which data caches are on disk.

EmuELEC declares 19 files of the Tyrian 2.1 distribution that bios/ did not
hold (setup.ini, netterm.int...). They resolved only through data/opentyrian,
the cache refresh_data_dirs.py fills from a release asset, so verify gave
544/572 in a checkout with that cache and 525/572 in a fresh worktree, for the
same commit. A file a platform declares is collected in bios/; a data
directory cache is not a collection.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class DeclaredFilesResolveWithoutDataCaches(unittest.TestCase):
    def test_no_platform_entry_rests_on_a_data_directory_cache(self):
        from common import (  # noqa: PLC0415
            build_zip_contents_index,
            list_registered_platforms,
            load_data_dir_registry,
            load_database,
            load_platform_config,
        )
        from packresolve import resolve_declaration  # noqa: PLC0415

        platforms_dir = REPO_ROOT / "platforms"
        registry = load_data_dir_registry(str(platforms_dir))
        caches = [
            entry["local_cache"] for entry in registry.values()
            if (REPO_ROOT / entry.get("local_cache", "")).is_dir()
        ]
        if not caches or not (REPO_ROOT / "database.json").is_file():
            self.skipTest("no data directory cache on disk (refresh_data_dirs.py fills them)")

        cwd = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            db = load_database("database.json")
            zip_contents = build_zip_contents_index(db)
            offenders = []
            for platform in list_registered_platforms(str(platforms_dir)):
                config = load_platform_config(platform, str(platforms_dir))
                for sys_id, system in config.get("systems", {}).items():
                    for entry in system.get("files", []) or []:
                        path, status = resolve_declaration(
                            entry, db, "bios", zip_contents, registry, None, offline=True,
                        )
                        if status.startswith("data_dir"):
                            offenders.append(f"{platform} {sys_id} {entry.get('name')}: {path}")
        finally:
            os.chdir(cwd)
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
