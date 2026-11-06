"""What the site counts stays what wiki/privacy.md says it counts.

The counter is website/src/scripts/count.ts. These checks read its source:
the guarantees are in a few lines that a later edit could drop without any
page looking different.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COUNTER = REPO_ROOT / "website" / "src" / "scripts" / "count.ts"
FOOTER = REPO_ROOT / "website" / "src" / "components" / "Footer.astro"
PRIVACY = REPO_ROOT / "wiki" / "privacy.md"


class TheCounterAsksNothingOfTheDevice(unittest.TestCase):
    def setUp(self) -> None:
        self.source = COUNTER.read_text(encoding="utf-8")
        # Comments state the rules: only the code must keep them.
        self.code = re.sub(r"^\s*//.*$", "", self.source, flags=re.M)

    def test_no_storage_on_the_device(self) -> None:
        for api in ("document.cookie", "localStorage", "sessionStorage", "indexedDB"):
            with self.subTest(api=api):
                self.assertNotIn(api, self.code)

    def test_a_declined_browser_sends_nothing(self) -> None:
        self.assertIn("doNotTrack === '1'", self.code)
        self.assertIn("globalPrivacyControl === true", self.code)
        self.assertRegex(self.code, r"const send = .*\n\tif \(!enabled\) return;")

    def test_only_the_published_site_counts(self) -> None:
        self.assertIn("location.hostname === HOST", self.code)

    def test_no_query_anchor_or_device_detail_is_read(self) -> None:
        for read in ("location.search", "location.hash", "location.href,", "screen.", "navigator.language"):
            with self.subTest(read=read):
                self.assertNotIn(read, self.code)

    def test_the_referrer_is_reduced_to_its_domain(self) -> None:
        self.assertIn("from.origin", self.code)
        self.assertNotIn("from.pathname", self.code)

    def test_a_search_is_sent_only_as_a_file_name_or_a_hash(self) -> None:
        self.assertIn("isHash(query) || isFileName(query) || isFileStem(query) ? query : 'other'", self.code)
        self.assertIn("countEvent(`search-none/${searchWords(query)}`)", self.code)
        self.assertIn("message.startsWith('No results for')", self.code)

    def _shape(self, name: str):
        """A search-shape predicate of count.ts, its regexes run by Python
        (the counter's patterns use no syntax the two read differently)."""
        body = re.search(rf"const {name} = \(query: string\): boolean =>(.*?);\n", self.code, re.S).group(1)
        patterns = [re.compile(p) for p in re.findall(r"/(\^.*?\$|\[[^/]*?\]|\\d)/\.test\(query\)", body)]
        digits = "(query.match(/\\d/g) ?? []).length <= 4" in body
        return lambda q: all(p.search(q) for p in patterns) and (
            not digits or len(re.findall(r"\d", q)) <= 4)

    def test_a_number_alone_is_never_sent(self) -> None:
        """An 8-digit phone number is valid hex and went out as a hash."""
        shapes = [self._shape(n) for n in ("isHash", "isFileName", "isFileStem")]
        for query in ("55512345", "91234567", "0612345678", "+33612345678"):
            with self.subTest(query=query):
                self.assertFalse(any(shape(query) for shape in shapes))
        for query in ("b4430a3b", "scph5501", "scph5501.bin", "a" * 40):
            with self.subTest(query=query):
                self.assertTrue(any(shape(query) for shape in shapes))

    def test_one_endpoint(self) -> None:
        self.assertEqual(set(re.findall(r"https://[\w.-]+", self.code)),
                         {"https://retrobios.goatcounter.com"})


class ThePageSaysWhatIsCounted(unittest.TestCase):
    def test_every_page_loads_the_counter_and_links_the_page(self) -> None:
        footer = FOOTER.read_text(encoding="utf-8")
        self.assertIn("import '../scripts/count.ts';", footer)
        self.assertIn("wiki/privacy/", footer)
        # Hidden until the script shows it: a declined browser is not asked.
        self.assertRegex(footer, r"data-rb-helpful-box hidden")

    def test_the_page_names_each_thing_sent(self) -> None:
        page = PRIVACY.read_text(encoding="utf-8")
        for said in ("No cookies", "Do Not Track", "Global Privacy Control",
                     "copy button", "found nothing", "Did this page help?",
                     "The installer sends nothing back", "retrobios.goatcounter.com"):
            with self.subTest(said=said):
                self.assertIn(said, page)

    def test_the_page_names_what_the_counter_cannot_tell_apart(self) -> None:
        """The page left out outbound clicks, which count.ts sends, said the
        referrer went by domain when the origin goes, and promised a search
        word goes out only as a file name while a nickname with digits does."""
        page = PRIVACY.read_text(encoding="utf-8")
        code = COUNTER.read_text(encoding="utf-8")
        self.assertIn("`out/${url.hostname}`", code)
        self.assertIn("link to another site", page)
        self.assertIn("from.origin", code)
        self.assertIn("`https://www.google.com`", page)
        self.assertIn("`dupont1985`", page)
        self.assertIn("phone number, never is", page)

    def test_the_installer_has_no_counter(self) -> None:
        installer = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertNotIn("goatcounter", installer.lower())


if __name__ == "__main__":
    unittest.main()
