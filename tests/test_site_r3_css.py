"""Round 3 theme: the stylesheet fixes of package 1, read from its source.

Each test fails on the stylesheet as it was before the fix: commands allowed
to break inside any word on a phone, a sidebar whose top links outsize its
group labels, badge links cut to a few pixels by the
next row, 12 px hashes, Get your files tables each sizing their own columns.
"""
from __future__ import annotations

import unittest

from tests.test_site_r2_css import CSS_PATH, PAGE_BG, _blocks, _ratio, _rules, _strip_comments, _theme_tokens

# The Get your files tables: no class reaches them, the Markdown table is
# matched by the cells the generator labels.
PACKS = "table:has(td[data-label='Runs on']):has(td[data-label='ZIP'])"


class ThemeStylesheetRound3(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.css = _strip_comments(CSS_PATH.read_text(encoding="utf-8"))
        dark = _theme_tokens(cls.css, ":root")
        light = {**dark, **_theme_tokens(cls.css, ":root[data-theme='light']")}
        cls.tokens = {"dark": dark, "light": light}

    # 1.1
    def test_commands_never_break_inside_a_word(self):
        blocks = _rules(self.css, ".expressive-code pre > code")
        self.assertTrue(blocks)
        for body in blocks:
            self.assertIn("white-space: pre-wrap", body, "commands keep wrapping")
            self.assertNotIn("overflow-wrap: anywhere", body)
        for selector in (".rb-facts code", ".rb-hash code", ".rb-meta-card td code"):
            with self.subTest(selector=selector):
                self.assertIn("overflow-wrap: anywhere", _rules(self.css, selector)[0])

    # 1.2
    def test_sidebar_labels_above_links(self):
        label = _rules(self.css, ".top-level summary .large")[0]
        # 13 px grey semibold, no uppercase: the house style refuses small caps.
        for declaration in ("font-size: var(--sl-text-xs)", "font-weight: 600", "color: var(--rb-text-secondary)"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, label)
        links = next(b for s, b in _blocks(self.css) if s == "#starlight__sidebar .top-level a")
        self.assertIn("font-size: var(--sl-text-sm)", links)
        self.assertIn("font-weight: 400", links)

    # 1.4
    def test_badge_links_keep_a_24px_target(self):
        dd = next(b for s, b in _blocks(self.css) if s == ".sl-markdown-content .rb-facts dd")
        self.assertIn("line-height: 24px", dd)
        badge = _rules(self.css, ".rb-facts :is(.rb-badge:has(> a), a.rb-badge)")[0]
        for declaration in ("display: inline-flex", "align-items: center", "min-height: 24px", "margin-block: 2px"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, badge)

    # 1.5
    def test_hashes_are_13px_at_every_width(self):
        hashes = [b for s, b in _blocks(self.css) if ".rb-hash" in s and "font-size" in b]
        self.assertEqual(len(hashes), 1, "a second size for .rb-hash, on phones")
        self.assertIn("font-size: 0.8125rem", hashes[0])
        short = _rules(self.css, "td code[title]")[0]
        self.assertIn("white-space: nowrap", short)
        self.assertIn("underline dotted", short)
        self.assertIn("min-width: 12rem", _rules(self.css, "td.rb-reason")[0])

    # 1.6
    def test_pack_tables_share_their_columns(self):
        base = next(b for s, b in _blocks(self.css) if PACKS in s and "table-layout" in b)
        self.assertIn("table-layout: fixed", base)
        self.assertIn("width: 100%", base)
        widths = {s.rsplit("th:nth-child(", 1)[1].split(")")[0]: b for s, b in _blocks(self.css)
                  if PACKS in s and "th:nth-child(" in s}
        self.assertEqual({k: v.strip() for k, v in widths.items()},
                         {"1": "width: 18%;", "2": "width: 20%;", "3": "width: 40%;", "4": "width: 22%;"})
        parts = next(b for s, b in _blocks(self.css) if PACKS in s and s.endswith(":is(a, .rb-button)"))
        self.assertIn("white-space: nowrap", parts)

    def test_secondary_text_on_the_sidebar_meets_aa(self):
        for theme in ("light", "dark"):
            with self.subTest(theme=theme):
                fg = self.tokens[theme]["--rb-text-secondary"].strip()
                self.assertGreaterEqual(_ratio(fg, PAGE_BG[theme]), 4.5)


if __name__ == "__main__":
    unittest.main()
