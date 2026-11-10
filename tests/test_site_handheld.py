"""The handheld launchers the site serves.

The four archives build_port.py writes carry install.py pinned by SHA-256,
so they left the release (owner, 2026-11-10): the site builds them from its
own commit, serves them under get/handheld/, and the get/ page of each
system names the file, its size and hash, where it goes and which menu
starts it.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import hashlib
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_port  # noqa: E402
import common  # noqa: E402
import sitehandheld  # noqa: E402

PLATFORMS = str(REPO_ROOT / "platforms")


def _pages() -> dict[str, str]:
    """Every page that carries a launcher, by site path."""
    import generate_site  # noqa: PLC0415

    with contextlib.chdir(REPO_ROOT):
        pages = {f"get/{key}.md": generate_site.generate_get_page(key)
                 for key in sorted(set(sitehandheld.PLATFORM_OF.values()))}
    pages[f"get/{sitehandheld.GROUP_PAGE}.md"] = sitehandheld.group_page(REPO_ROOT)
    return pages


class TheSiteServesTheLaunchers(unittest.TestCase):
    def setUp(self):
        scratch = REPO_ROOT / "tmp"
        scratch.mkdir(exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(dir=scratch, prefix="site-handheld-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_the_written_archives_are_the_ones_build_port_writes(self):
        written = sitehandheld.write_launchers(self.tmp / "public", REPO_ROOT)
        self.assertEqual([path.name for path in written], list(build_port.ARCHIVES))
        for path in written:
            with self.subTest(archive=path.name):
                self.assertEqual(path.parent, self.tmp / "public" / "get" / "handheld")
                built = build_port.build_archive(path.name, self.tmp / "built" / path.name)
                self.assertEqual(path.read_bytes(), built.read_bytes())

    def test_an_unchanged_archive_is_not_rewritten(self):
        first = sitehandheld.write_launchers(self.tmp / "public", REPO_ROOT)
        stamps = {path: path.stat().st_mtime_ns for path in first}
        sitehandheld.write_launchers(self.tmp / "public", REPO_ROOT)
        self.assertEqual({path: path.stat().st_mtime_ns for path in first}, stamps)

    def test_a_stale_pin_stops_the_build(self):
        """build_port refuses an install.py the bootstraps do not pin: served,
        that launcher would refuse its own installer."""
        with mock.patch.dict(sitehandheld._built, clear=True), \
                mock.patch.object(build_port, "pinned_installer_sha256", return_value="0" * 64):
            with self.assertRaisesRegex(ValueError, "re-pin the bootstraps"):
                sitehandheld.write_launchers(self.tmp / "public", REPO_ROOT)
        self.assertFalse(list((self.tmp / "public").rglob("RetroBIOS*")))

    def test_every_archive_is_on_a_page_with_its_link_and_hash(self):
        public = self.tmp / "public"
        written = {path.name: path for path in sitehandheld.write_launchers(public, REPO_ROOT)}
        pages = _pages()
        for name in build_port.ARCHIVES:
            with self.subTest(archive=name):
                data = written[name].read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                holding = [page for page, text in pages.items()
                           if f'href="handheld/{name}"' in text]
                self.assertTrue(holding, f"no page links {name}")
                for page in holding:
                    text = pages[page]
                    # The link resolves to the file written under public/.
                    target = (Path(page).parent / "handheld" / name).as_posix()
                    self.assertTrue((public / target).is_file(), target)
                    block = text.split(f'href="handheld/{name}"', 1)[1].split("\n\n", 2)[1]
                    self.assertIn(f"SHA-256: `{digest}`", block)
                    self.assertIn(sitehandheld._size(len(data)), block)
                    self.assertRegex(block, r"- (Copy it to|Unzip it into) .+\.")
                    self.assertRegex(block, r"- Start it from .+\.")


class WhereEachSystemFindsItsFile(unittest.TestCase):
    def test_each_platform_page_is_a_registered_platform(self):
        registered = set(common.list_registered_platforms(PLATFORMS))
        self.assertLessEqual(set(sitehandheld.PLATFORM_OF.values()), registered)
        self.assertNotIn(sitehandheld.GROUP_PAGE, registered)

    def test_the_group_page_sits_with_the_handheld_guide(self):
        """It shares the guide's name, so the sidebar files it with it, and
        the guide a muOS or ArkOS owner lands on links it."""
        import generate_site  # noqa: PLC0415

        guide = generate_site.HANDHELD_GUIDE
        self.assertEqual(sitehandheld.GROUP_PAGE, guide.page)
        with contextlib.chdir(REPO_ROOT):
            self.assertIn(f"(../get/{sitehandheld.GROUP_PAGE}.md)",
                          generate_site.generate_handheld_guide(guide))
            self.assertIn(f"]({sitehandheld.GROUP_PAGE}.md)", generate_site.generate_get_index())

    def test_every_system_has_its_launchers_on_its_page(self):
        pages = _pages()
        for system in sitehandheld.systems():
            page = sitehandheld.page_of(system)
            with self.subTest(system=system):
                self.assertIn(page, pages)
                for launcher in sitehandheld.launchers_for(system):
                    self.assertIn(f'href="handheld/{launcher.archive}"', pages[page])
                    self.assertIn(launcher.folder_for(system), pages[page])
                    self.assertIn(launcher.start, pages[page])
        for system in sitehandheld.group_systems():
            self.assertIn(f"\n## {system}\n", pages[f"get/{sitehandheld.GROUP_PAGE}.md"])

    def test_the_installer_table_is_written_from_the_same_rows(self):
        text = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        block = re.search(r"<!-- generated: handheld -->\n(.*?)<!-- /generated: handheld -->",
                          text, re.S)
        self.assertIsNotNone(block)
        self.assertEqual(block.group(1).strip(), "\n".join(sitehandheld.table_rows()))
        self.assertNotIn("releases/latest", text.split("## On a handheld", 1)[1].split("\n## ")[0])

    def test_the_installer_section_opens_on_the_downloads(self):
        """The section was long, with no link to click (owner, 2026-11-10):
        it opens on one row per system, each file a link to its copy on the
        site, before the detail."""
        text = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        section = text.split("## On a handheld", 1)[1].split("\n## ")[0]
        block = re.search(r"<!-- generated: handheld-downloads -->\n(.*?)"
                          r"<!-- /generated: handheld-downloads -->", section, re.S)
        self.assertIsNotNone(block)
        self.assertEqual(block.group(1).strip(), "\n".join(sitehandheld.download_rows()))
        self.assertLess(block.start(), section.index("### Where each file goes"))
        self.assertLess(len(section[:block.start()].split()), 40)
        for system in sitehandheld.systems():
            with self.subTest(system=system):
                row = next(line for line in block.group(1).splitlines()
                           if line.startswith(f"| {system} |"))
                for launcher in sitehandheld.launchers_for(system):
                    self.assertIn(f"](../{sitehandheld.SERVED_DIR}/{launcher.archive})", row)
                self.assertIn(f"](../{sitehandheld.page_of(system)}#", row)
        for name in build_port.ARCHIVES:
            self.assertIn(f"](../{sitehandheld.SERVED_DIR}/{name})", block.group(1))

    def test_the_generator_writes_them(self):
        source = (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        self.assertIn("sitehandheld.write_launchers(public, _REPO_ROOT)", source)
        self.assertIn("sitehandheld.platform_block(platform_name, _REPO_ROOT)", source)
        self.assertIn("sitehandheld.group_page(_REPO_ROOT)", source)


if __name__ == "__main__":
    unittest.main()
