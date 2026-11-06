"""Each cited path is one a declared repository holds at its pin.

Seven profiles cited paths their repositories do not hold. trident wraps
the Panda3DS fork vendored as a submodule, so 3dsTrident holds none of the
emulator sources it cites. pce-emu, uqm and stonesoup wrote their paths from
a subdirectory of the repository (PCE.emu/, sc2/, crawl-ref/), and nesoid
named two Java files without their directory. future-pinball-fploader and
nesoid continue a binary citation with a bare address or library name,
which the pages took for a path of the source repository. The Ryujinx
mirror pages its tree, and read as one page it could not confirm a path.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sitesources  # noqa: E402
import upstream  # noqa: E402
from common import load_emulator_profiles  # noqa: E402
from sourceref import ref_role, source_ref_values, split_source_ref  # noqa: E402

PROFILES = ("trident", "future-pinball-fploader", "pce-emu", "uqm", "nesoid",
            "ryujinx", "stonesoup")


class BinaryContinuationsAreNotLinked(unittest.TestCase):
    PROFILE = {
        "emulator": "future-pinball-fploader", "type": "standalone",
        "source": "https://github.com/ravarcade/BAM_FPloader",
        "source_commit": "e" * 40,
    }

    def tearDown(self):
        sitesources._tree_paths.cache_clear()

    def _render(self, value: str) -> str:
        original = sitesources._tree_paths
        sitesources._tree_paths = lambda repo, pin: frozenset({"FPLoader.cpp"})  # type: ignore[assignment]
        try:
            return sitesources._source_ref_markdown(self.PROFILE, value)
        finally:
            sitesources._tree_paths = original

    def test_an_address_continuing_a_binary_range(self):
        text = self._render("BAM.dll 1.5-408 .text:0x100ae843-0x100ae8a7, 0x10037130-0x100371de")
        self.assertNotIn("](https://", text)
        self.assertIn("`0x10037130-0x100371de`", text)

    def test_a_bare_library_name(self):
        text = self._render("DesktopKinect.dll, Kinect.dll import directories")
        self.assertNotIn("](https://", text)

    def test_a_source_path_is_still_linked(self):
        text = self._render("FPLoader.cpp:259-305")
        self.assertIn("](https://github.com/ravarcade/BAM_FPloader/blob/", text)


class ForgejoTreesArePaged(unittest.TestCase):
    """git.ngram.ca returns 1000 entries a page and the total."""

    def test_every_page_is_read(self):
        repo = upstream.parse_repo("https://git.ngram.ca/mirrors/Ryujinx")
        pages = {
            1: [{"type": "blob", "path": f"a/{i}.cs"} for i in range(1000)],
            2: [{"type": "blob", "path": "src/Ryujinx.HLE/FileSystem/VirtualFileSystem.cs"},
                {"type": "tree", "path": "src"}],
        }

        def fake_api(url, cache_dir, offline, *args, **kwargs):
            page = int(url.rsplit("&page=", 1)[1]) if "&page=" in url else 1
            return {"tree": pages.get(page, []), "truncated": True, "total_count": 1002}

        with mock.patch.object(upstream, "_api", side_effect=fake_api):
            paths, truncated = upstream.list_tree(repo, "7" * 40, "unused")
        self.assertFalse(truncated)
        self.assertEqual(len(paths), 1001)
        self.assertIn("src/Ryujinx.HLE/FileSystem/VirtualFileSystem.cs", paths)

    def test_a_github_truncation_stays_final(self):
        repo = upstream.parse_repo("https://github.com/o/r")
        payload = {"tree": [{"type": "blob", "path": "x"}], "truncated": True}
        with mock.patch.object(upstream, "_api", return_value=payload) as api:
            paths, truncated = upstream.list_tree(repo, "7" * 40, "unused")
        self.assertTrue(truncated)
        self.assertEqual(api.call_count, 1)


class TheSevenProfilesCiteHeldPaths(unittest.TestCase):
    """Read against the cached tree listings, skipped where none is cached."""

    def test_every_cited_path_is_held(self):
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"), skip_aliases=False)
        missing, checked = [], 0
        for key in PROFILES:
            profile = profiles[key]
            candidates = sitesources._forge_sources(profile)
            values = [e["source_ref"] for e in profile.get("files") or []
                      if isinstance(e, dict) and e.get("source_ref")]
            values += [d["source_ref"] for d in profile.get("data_directories") or []
                       if isinstance(d, dict) and d.get("source_ref")]
            for value in values:
                for _label, refs in source_ref_values(value):
                    for part in split_source_ref(refs):
                        _role, path = ref_role(part.path)
                        if " " in path or sitesources.is_binary_citation(path):
                            continue
                        verdicts = [sitesources.tree_holds(r, p, path) for r, p in candidates]
                        if None in verdicts:
                            continue
                        checked += 1
                        if not any(verdicts):
                            missing.append((key, path))
        if not checked:
            raise unittest.SkipTest("no cached tree listings")
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
