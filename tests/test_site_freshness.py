"""A copy an assistant read long ago can be told from the current one.

Each Markdown copy, llms.txt and llms-full.txt name the commit they were
built from, version.json names the current one, and the next deploy lists
the pages whose words changed for IndexNow."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

import tests  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import indexnow  # noqa: E402
import siteagents  # noqa: E402
import site_markdown  # noqa: E402

STAMP = {"commit": "0123456789abcdef0123456789abcdef01234567", "date": "2026-11-09T08:00:00+01:00"}
# The two parts a built Starlight page gives the copy: its title and its content.
PAGE = ('<html><body><h1 id="_top">Title</h1>'
        '<div class="sl-markdown-content"><p>Words of the page.</p></div></body></html>')


def _site(root: Path, words: str = "Words of the page.") -> Path:
    dist = root / "dist"
    for page in ("", "wiki/faq/"):
        (dist / page).mkdir(parents=True, exist_ok=True)
        (dist / page / "index.html").write_text(PAGE.replace("Words of the page.", words),
                                                encoding="utf-8")
    (dist / "llms.txt").write_text("# RetroBIOS\n\n> The summary.\n\n## Start\n", encoding="utf-8")
    return dist


class BuildStamp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / "tmp")
        self.dist = _site(Path(self.tmp.name))
        site_markdown.convert_site(self.dist, STAMP)

    def tearDown(self):
        self.tmp.cleanup()

    def test_each_copy_names_its_commit_under_its_title(self):
        lines = (self.dist / "wiki" / "faq" / "index.md").read_text(encoding="utf-8").splitlines()
        self.assertTrue(lines[0].startswith("# "))
        self.assertEqual(lines[2], "> Built from commit 0123456789ab on 2026-11-09. "
                                   "The current build: https://abdess.github.io/retrobios/version.json")

    def test_version_json_names_the_build(self):
        self.assertEqual(json.loads((self.dist / "version.json").read_text(encoding="utf-8")), STAMP)

    def test_llms_txt_keeps_its_summary_after_the_title(self):
        text = (self.dist / "llms.txt").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# RetroBIOS\n\n> The summary.\n\nBuilt from commit 0123456789ab"))

    def test_llms_full_says_the_build_once(self):
        text = (self.dist / "llms-full.txt").read_text(encoding="utf-8")
        self.assertEqual(text.count("Built from commit"), 1)

    def test_digests_ignore_the_build_line(self):
        first = json.loads((self.dist / "digests.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as other:
            dist = _site(Path(other))
            site_markdown.convert_site(dist, {"commit": "f" * 40, "date": "2026-11-10T00:00:00Z"})
            second = json.loads((dist / "digests.json").read_text(encoding="utf-8"))
        self.assertEqual(first, second)
        self.assertIn("https://abdess.github.io/retrobios/llms.txt", first)


class IndexNowList(unittest.TestCase):
    def test_added_changed_and_removed_pages_are_listed(self):
        old = {"a": "1", "b": "2", "gone": "3"}
        new = {"a": "1", "b": "9", "new": "4"}
        self.assertEqual(indexnow.changed_urls(new, old), ["b", "gone", "new"])

    def test_the_first_deploy_lists_every_page(self):
        self.assertEqual(indexnow.changed_urls({"a": "1", "b": "2"}, {}), ["a", "b"])

    def test_the_key_is_served_where_the_request_says(self):
        body = indexnow.payload(["https://abdess.github.io/retrobios/"])
        self.assertEqual(body["keyLocation"], "https://abdess.github.io/retrobios/indexnow.txt")
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as public:
            written: dict[str, str] = {}
            siteagents.write(Path(public), [], lambda path, text: written.__setitem__(path, text))
            self.assertEqual(written[str(Path(public) / "indexnow.txt")].strip(), body["key"])

    def test_the_deploy_posts_the_list_after_the_site_is_live(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy-site.yml").read_text(encoding="utf-8")
        listed = workflow.index("scripts/indexnow.py --dist website/dist")
        deployed = workflow.index("actions/deploy-pages@")
        posted = workflow.index("https://api.indexnow.org/indexnow")
        self.assertLess(listed, deployed)
        self.assertLess(deployed, posted)


class AnswerRule(unittest.TestCase):
    def test_assistants_are_told_to_compare_the_commit(self):
        self.assertTrue(any("version.json" in rule for rule in siteagents.ANSWER_RULES))


if __name__ == "__main__":
    unittest.main()
