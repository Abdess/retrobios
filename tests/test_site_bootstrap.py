"""The one-line commands the site serves.

`curl -fsSL https://abdess.github.io/retrobios/i | sh` and the PowerShell
`i.ps1` replaced a raw.githubusercontent.com address of 70 characters. The
site deploys some eleven minutes after a push: a copy that pinned one
commit's installer and downloaded another's would refuse every install for
that long, so each copy reads install.py from the commit it was built from.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import install  # noqa: E402
import sitebootstrap  # noqa: E402
from siteguides import INSTALL_BASE, INSTALL_PS1, INSTALL_SH, install_command  # noqa: E402

WEBSITE = REPO_ROOT / "website"
DOCS = WEBSITE / "src" / "content" / "docs"
OLD_SH = "raw.githubusercontent.com/Abdess/retrobios/main/install.sh"
OLD_PS1 = "raw.githubusercontent.com/Abdess/retrobios/main/install.ps1"


def _head() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def _pin(text: str) -> str:
    match = re.search(r'(?:DEFAULT_INSTALL_SHA256="|\$defaultInstallSha256 = ")([0-9a-f]{64})"',
                      text)
    assert match, "no installer pin"
    return match.group(1)


class ServedCopies(unittest.TestCase):
    def setUp(self):
        self.commit = _head()

    def test_each_copy_is_its_bootstrap_but_for_the_installer_address(self):
        for name, (source, _line) in sitebootstrap.SOURCES.items():
            with self.subTest(name=name):
                original = (REPO_ROOT / source).read_text(encoding="utf-8").splitlines()
                served = sitebootstrap.served_text(name, REPO_ROOT, self.commit).splitlines()
                self.assertEqual(len(original), len(served))
                changed = [(a, b) for a, b in zip(original, served) if a != b]
                # The address, and the advice a refusal gives.
                self.assertEqual(len(changed), 2, changed)
                advice = [pair for pair in changed if sitebootstrap.SERVED_ADVICE in pair[1]]
                self.assertEqual(len(advice), 1, changed)
                before, after = next(pair for pair in changed if pair not in advice)
                self.assertIn("https://raw.githubusercontent.com/Abdess/retrobios/main/install.py",
                              before)
                self.assertEqual(after, before.replace(
                    "https://raw.githubusercontent.com/Abdess/retrobios/main/install.py",
                    sitebootstrap.installer_url(self.commit)))

    def test_the_address_names_the_commit_whose_installer_the_pin_holds(self):
        installer = hashlib.sha256((REPO_ROOT / "install.py").read_bytes()).hexdigest()
        url = f"https://raw.githubusercontent.com/Abdess/retrobios/{self.commit}/install.py"
        for name in sitebootstrap.SOURCES:
            with self.subTest(name=name):
                text = sitebootstrap.served_text(name, REPO_ROOT, self.commit)
                self.assertIn(f'"{url}"', text)
                self.assertEqual(_pin(text), installer)

    def test_ci_builds_from_the_pushed_commit(self):
        pushed = "a" * 40
        with mock.patch.dict(os.environ, {"GITHUB_SHA": pushed}):
            self.assertEqual(sitebootstrap.build_commit(REPO_ROOT), pushed)
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "main"}), \
                self.assertRaises(ValueError):
            sitebootstrap.build_commit(REPO_ROOT)
        with mock.patch.dict(os.environ, {"GITHUB_SHA": ""}):
            self.assertEqual(sitebootstrap.build_commit(REPO_ROOT), self.commit)

    def test_the_copies_land_at_the_root_of_the_public_folder(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir()
                                         else None) as scratch:
            public = Path(scratch) / "public"
            written = sitebootstrap.write_bootstraps(public, REPO_ROOT, self.commit)
            self.assertEqual(sorted(p.name for p in written), ["i", "i.ps1"])
            for path in written:
                self.assertEqual(path.read_text(encoding="utf-8"),
                                 sitebootstrap.served_text(path.name, REPO_ROOT, self.commit))

    def test_the_served_copy_never_blames_a_cut_download_or_caches(self):
        """The commit-pinned copy said "cut short, try
        again" and "waiting five minutes settles that", neither of which can
        happen to it."""
        for name in sitebootstrap.SOURCES:
            with self.subTest(name=name):
                text = sitebootstrap.served_text(name, REPO_ROOT, self.commit)
                self.assertNotIn("cut short", text)
                self.assertNotIn("five minutes", text)
                self.assertIn(sitebootstrap.SERVED_ADVICE, text)
        # The raw form keeps its advice: a branch's copy can be stale.
        self.assertIn("cut short", (REPO_ROOT / "install.sh").read_text(encoding="utf-8"))
        page = (REPO_ROOT / "wiki" / "first-install.md").read_text(encoding="utf-8")
        answer = page.split("does not match its expected fingerprint.", 1)[1].split("###", 1)[0]
        self.assertNotIn("cut short", answer)
        self.assertIn("something changed the file", answer)

    def test_a_stale_pin_stops_the_build(self):
        """A pin that is not the installer's was served,
        and refused every install until the next good deploy."""
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir()
                                         else None) as scratch:
            root = Path(scratch)
            for source in ("install.sh", "install.ps1"):
                (root / source).write_text((REPO_ROOT / source).read_text(encoding="utf-8"),
                                           encoding="utf-8")
            (root / "install.py").write_text('print("not the pinned installer")\n',
                                             encoding="utf-8")
            for name in sitebootstrap.SOURCES:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    sitebootstrap.served_text(name, root, self.commit)

    def test_deploy_site_checks_the_copies_before_it_publishes(self):
        import yaml  # noqa: PLC0415

        steps = yaml.safe_load((REPO_ROOT / ".github/workflows/deploy-site.yml").read_text(
            encoding="utf-8"))["jobs"]["build"]["steps"]
        runs = [str(step.get("run", "")) for step in steps]
        uses = [str(step.get("uses", "")) for step in steps]
        check = next(i for i, run in enumerate(runs) if "tests.test_site_bootstrap" in run)
        build = next(i for i, run in enumerate(runs) if "scripts/generate_site.py" in run)
        upload = next(i for i, use in enumerate(uses) if "upload-pages-artifact" in use)
        self.assertLess(build, check)
        self.assertLess(check, upload)

    def test_a_bootstrap_without_its_address_line_stops_the_build(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir()
                                         else None) as scratch:
            root = Path(scratch)
            (root / "install.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                sitebootstrap.served_text("i", root, self.commit)


class DocumentedCommands(unittest.TestCase):
    def test_the_addresses_are_the_served_paths(self):
        config = (WEBSITE / "astro.config.mjs").read_text(encoding="utf-8")
        site = re.search(r"const SITE = '([^']+)'", config).group(1)
        base = re.search(r"const BASE = '([^']+)'", config).group(1)
        self.assertEqual(f"{INSTALL_BASE}/", site + base)
        self.assertEqual(INSTALL_SH, f"{site}{base}{sitebootstrap.SH_NAME}")
        self.assertEqual(INSTALL_PS1, f"{site}{base}{sitebootstrap.PS1_NAME}")
        self.assertEqual(install.BOOTSTRAP_URL, INSTALL_SH)
        self.assertEqual(f"{install.BOOTSTRAP_URL}.ps1", INSTALL_PS1)

    def test_the_installer_hints_give_the_short_command(self):
        with mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
            self.assertEqual(install.Invocation().launcher(), f"curl -fsSL {INSTALL_SH} | sh -s --")
        with mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "ps1"}):
            self.assertEqual(install.Invocation().launcher(),
                             f"&([scriptblock]::Create((irm {INSTALL_PS1})))")

    def test_every_page_a_user_copies_from_gives_the_short_command(self):
        sources = {
            "wiki/installer.md": [install_command("sh"), install_command("powershell")],
            "wiki/first-install.md": [install_command("sh"), install_command("powershell")],
            "wiki/faq.md": [f"curl -fsSL {INSTALL_SH} | sh -s -- --dry-run"],
            "wiki/troubleshooting.md": [install_command("sh", "--check")],
            "wiki/tools.md": [install_command("sh"), install_command("powershell")],
            "website/src/components/FilePicker.astro": [f"'curl -fsSL {INSTALL_SH} | sh -s --'"],
            "scripts/download.sh": [f"curl -fsSL {INSTALL_SH} | sh -s -- --platform <name>"],
            "scripts/download.py": [f"curl -fsSL {INSTALL_SH} | sh -s -- --platform <name>"],
        }
        for rel, commands in sources.items():
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            for command in commands:
                with self.subTest(file=rel, command=command):
                    self.assertIn(command, text)

    def test_the_raw_form_is_written_once_as_the_fallback(self):
        """The long address stays on the installer page only, for the day
        the site is down."""
        surfaces = [*sorted((REPO_ROOT / "wiki").glob("*.md")), REPO_ROOT / "README.md",
                    REPO_ROOT / "CONTRIBUTING.md", REPO_ROOT / "install.py",
                    *sorted((REPO_ROOT / "scripts").rglob("*.py")),
                    REPO_ROOT / "scripts" / "download.sh",
                    *sorted((WEBSITE / "src" / "components").glob("*.astro"))]
        found = {
            str(path.relative_to(REPO_ROOT)): text.count(OLD_SH) + text.count(OLD_PS1)
            for path in surfaces
            for text in [path.read_text(encoding="utf-8")]
            if OLD_SH in text or OLD_PS1 in text
        }
        self.assertEqual(found, {"wiki/installer.md": 2})

    def test_no_command_drops_the_scheme(self):
        """A first request in clear text lets anyone on the way serve another
        script, which the installer's pin cannot catch: the pin is in it."""
        bare = INSTALL_BASE.removeprefix("https://")
        for page in sorted((REPO_ROOT / "wiki").glob("*.md")):
            text = page.read_text(encoding="utf-8")
            with self.subTest(page=page.name):
                self.assertNotRegex(text, rf"(?<![/\w]){re.escape(bare)}/")


class NothingElseAtTheseAddresses(unittest.TestCase):
    """A page or a folder named i would take the address, or turn it into a
    redirect to i/ that `curl | sh` reads as HTML."""

    NAMES = tuple(sitebootstrap.SOURCES)

    def test_no_source_page_takes_the_names(self):
        for folder in (REPO_ROOT / "wiki", WEBSITE / "src" / "pages"):
            taken = sorted(str(path.relative_to(REPO_ROOT)) for path in folder.glob("i*")
                           if path.name == "i" or path.name.split(".", 1)[0] == "i")
            with self.subTest(folder=str(folder.relative_to(REPO_ROOT))):
                self.assertEqual(taken, [])

    @unittest.skipUnless(DOCS.is_dir(), "site not generated")
    def test_no_generated_page_or_redirect_takes_the_names(self):
        for name in self.NAMES:
            stem = name.split(".", 1)[0]
            with self.subTest(name=name):
                self.assertFalse((DOCS / stem).exists())
                self.assertEqual(sorted(DOCS.glob(f"{stem}.md*")), [])
        redirects = WEBSITE / "src" / "generated" / "redirects.json"
        if redirects.is_file():
            sources = {key.strip("/").removeprefix("retrobios/")
                       for key in json.loads(redirects.read_text(encoding="utf-8"))}
            self.assertEqual(sources & set(self.NAMES), set())

    @unittest.skipUnless((WEBSITE / "dist" / "index.html").is_file(), "site not built")
    def test_the_built_site_serves_files_at_the_addresses(self):
        built = (WEBSITE / "dist" / "index.html").stat().st_mtime
        written = [WEBSITE / "public" / name for name in self.NAMES]
        if any(path.is_file() and path.stat().st_mtime > built for path in written):
            self.skipTest("website/dist was built before these copies were written")
        for name in self.NAMES:
            path = WEBSITE / "dist" / name
            with self.subTest(name=name):
                self.assertTrue(path.is_file())
                text = path.read_text(encoding="utf-8")
                self.assertRegex(text, r"raw\.githubusercontent\.com/Abdess/retrobios/[0-9a-f]{40}/"
                                       r"install\.py")


class GeneratedSurfaces(unittest.TestCase):
    def test_a_shorter_address_moves_no_section(self):
        """The install boxes weigh in the split of a manufacturer's page,
        fitted on the 66-character raw address: weighed at their new length,
        Nintendo DS fell back onto the Nintendo summary and lost its page."""
        import generate_site

        tail = " | sh -s -- --check"
        self.assertEqual(generate_site._install_box_weight([f"curl -fsSL {INSTALL_SH}{tail}"]),
                         len("curl -fsSL ") + 66 + len(tail) + 1)
        line = f"&([scriptblock]::Create((irm {INSTALL_PS1}))) --check"
        self.assertEqual(generate_site._install_box_weight([line]),
                         len(line) - len(INSTALL_PS1) + 67 + 1)

    def test_the_readme_shows_the_short_form(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        quick = readme.split("## Install in one line", 1)[1].split("\n## ", 1)[0]
        self.assertIn(f"\n{install_command('sh')}\n", quick)
        self.assertIn(f"\n{install_command('powershell')}\n", quick)
        self.assertNotIn("raw.githubusercontent.com", quick)

    @unittest.skipUnless(DOCS.is_dir(), "site not generated")
    def test_the_site_shows_the_short_form(self):
        pages = {path: path.read_text(encoding="utf-8") for path in DOCS.rglob("*.md*")}
        self.assertTrue(any(INSTALL_SH in text for text in pages.values()))
        long_form = sorted(str(path.relative_to(DOCS)) for path, text in pages.items()
                           if OLD_SH in text or OLD_PS1 in text)
        self.assertEqual(long_form, ["wiki/installer.md"])


if __name__ == "__main__":
    unittest.main()
