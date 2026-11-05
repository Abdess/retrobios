"""The stylesheet, read from its source.

Each test fails on the stylesheet as it was before the fix: a red focus ring
and hover, Starlight's 35 px h2, tinted disclosure blocks, striped asides,
the search result file dump, lifting shadows, a sidebar without hierarchy,
two indigos, permalinks hidden on touch screens, OS tabs cut at 320 px, a
column that moves on pages without a TOC.

Each test fails on the stylesheet as it was before the fix: commands allowed
to break inside any word on a phone, a sidebar whose top links outsize its
group labels, badge links cut to a few pixels by the
next row, 12 px hashes, Get your files tables each sizing their own columns.

Each test fails on the stylesheet as it was before the fix: OS tabs on one
hidden scrolling row, stacked table cells 16 px apart with labels drawn over
the next row, short flags split across lines, lone card links 19 px high, a
card label column too narrow for its longest label.

Each test fails on the stylesheet as it was before the fix: detection tables
whose last column sat past the page at 1440 px, a header search box, title
and "On this page" that moved 12 px between a guide and a console page,
stacked rows 136 px tall for four short cells, a line 4 px under a button,
a heading touching its first line, the browser's own choice list, and a
crumb separator free to end a line alone.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CSS_PATH = ROOT / "website" / "src" / "styles" / "retrobios.css"

# Page backgrounds Starlight 0.42.6 draws under our tokens, read with
# getComputedStyle on a built page (light: white, dark: gray-7 hsl(224 10% 10%)).
PAGE_BG = {"light": "#ffffff", "dark": "#17181c"}
# Text Starlight draws on a filled button (--sl-color-black in each theme).
ON_FILL = {"light": "#ffffff", "dark": "#17181c"}


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _blocks(css: str) -> list[tuple[str, str]]:
    """Innermost (selector, body) pairs, media queries flattened."""
    return [(sel.strip(), body) for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css)]


def _theme_tokens(css: str, selector: str) -> dict[str, str]:
    for sel, body in _blocks(css):
        if sel == selector:
            return dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", body))
    raise AssertionError(f"no block {selector}")


def _rules(css: str, selector_part: str) -> list[str]:
    return [body for sel, body in _blocks(css) if selector_part in sel]


def _luminance(hex_colour: str) -> float:
    value = hex_colour.lstrip("#")
    channels = [int(value[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _ratio(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


class ThemeStylesheet(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.css = _strip_comments(CSS_PATH.read_text(encoding="utf-8"))
        dark = _theme_tokens(cls.css, ":root")
        light = {**dark, **_theme_tokens(cls.css, ":root[data-theme='light']")}
        cls.tokens = {"dark": dark, "light": light}

    def resolve(self, theme: str, token: str) -> str:
        value = self.tokens[theme][token].strip()
        while value.startswith("var("):
            value = self.tokens[theme][value[4:-1].strip()].strip()
        return value

    def test_focus_ring_is_the_link_colour_not_red(self):
        focus = _rules(self.css, ":focus-visible")
        self.assertTrue(focus)
        for body in focus:
            self.assertIn("2px solid var(--rb-link)", body)
            self.assertNotIn("accent", body.replace("--rb-link", ""))
        ring = next(b for s, b in _blocks(self.css) if s.startswith(":where(a, button"))
        self.assertIn("outline-offset: 2px", ring)
        self.assertNotIn("#b42318", self.css)
        self.assertNotIn("--rb-accent", self.css)

    def test_button_hover_stays_in_its_own_colour(self):
        self.assertNotRegex(self.css, r"\.rb-button:is\(:hover,\s*:focus\)")
        primary = _rules(self.css, ".rb-button-primary:hover")
        self.assertTrue(primary)
        self.assertIn("var(--rb-link-strong)", primary[0])
        self.assertEqual(self.resolve("light", "--rb-link-strong"), "#1d2f73")
        self.assertEqual(self.resolve("dark", "--rb-link-strong"), "#c9d2ff")
        outline = [b for s, b in _blocks(self.css) if s.endswith(".rb-button:hover")]
        self.assertIn("var(--sl-color-accent-low)", outline[0])

    def test_heading_scale(self):
        root = self.tokens["dark"]
        self.assertEqual(root["--sl-text-h1"], "2.25rem")
        self.assertEqual(root["--sl-text-h2"], "1.5rem")
        self.assertEqual(root["--sl-text-h3"], "1.2rem")
        self.assertEqual(root["--sl-text-h4"], "1rem")
        self.assertRegex(self.css, r"@media \(max-width: 50rem\) \{\s*:root \{ --sl-text-h1: 1\.875rem; \}")
        self.assertRegex(self.css, r"level-h2, h2\) \{ margin-top: 2\.75rem; \}")
        self.assertRegex(self.css, r"level-h3, h3:not\(\.rb-file-title\)\) \{ margin-top: 1\.75rem; \}")

    def test_asides_are_neutral_boxes(self):
        neutral = _rules(self.css, ".starlight-aside:is(.starlight-aside--note, .starlight-aside--tip)")
        joined = "".join(neutral)
        self.assertIn("--sl-color-asides-border: var(--rb-border)", joined)
        self.assertIn("background: var(--rb-surface)", joined)
        self.assertIn("display: none", joined)
        box = _rules(self.css, ".sl-markdown-content .starlight-aside")[0]
        self.assertIn("border: 1px solid", box)

    def test_disclosure_blocks_are_neutral(self):
        self.assertNotIn("rb-details-tip", self.css)
        self.assertNotIn("--sl-color-blue", self.css)
        base = next(b for s, b in _blocks(self.css) if s == ".sl-markdown-content details.rb-details")
        self.assertIn("background: transparent", base)
        self.assertIn("var(--rb-border)", base)
        self.assertIn("0.95rem", _rules(self.css, "details.rb-details > summary")[0])

    def test_search_hides_the_file_list(self):
        self.assertIn("display: none", _rules(self.css, "site-search .pagefind-ui__result-tags")[0])

    def test_no_lifting_shadow_on_pagination_or_menu(self):
        self.assertIn("box-shadow: none", _rules(self.css, ".pagination-links a")[0])
        self.assertIn("font-size: 1.05rem", _rules(self.css, ".pagination-links .link-title")[0])
        menu = next(b for s, b in _blocks(self.css) if s == ".sl-menu-button")
        self.assertIn("box-shadow: none", menu)
        self.assertIn("background: transparent", menu)
        self.assertIn("1px solid var(--rb-border)", menu)

    def test_sidebar_hierarchy(self):
        label = _rules(self.css, ".top-level summary .large")[0]
        self.assertIn("var(--sl-text-xs)", label)
        self.assertIn("var(--rb-text-secondary)", label)
        current = _rules(self.css, "a[aria-current='page']")[0]
        self.assertIn("background: var(--sl-color-accent-low)", current)
        self.assertIn("color: var(--sl-color-accent-high)", current)
        self.assertNotIn("border", current)

    def test_one_indigo(self):
        for theme in ("light", "dark"):
            with self.subTest(theme=theme):
                self.assertEqual(self.resolve(theme, "--sl-color-accent"), self.resolve(theme, "--rb-link"))
                self.assertEqual(self.resolve(theme, "--sl-color-text-accent"), self.resolve(theme, "--rb-link"))

    def test_permalinks_visible_without_hover(self):
        self.assertRegex(self.css, r"@media \(hover: none\) \{\s*\.rb-permalink \{ opacity: 1; \}")
        permalink = next(b for s, b in _blocks(self.css) if s == ".rb-permalink")
        self.assertIn("min-height: 24px", permalink)

    # The row wraps, every tab on screen
    def test_os_tabs_stay_reachable(self):
        tablist = _rules(self.css, "starlight-tabs [role='tablist']")[0]
        self.assertIn("flex-wrap: wrap", tablist)
        self.assertIn("overflow-x: visible", tablist)
        self.assertIn("white-space: nowrap", _rules(self.css, "starlight-tabs [role='tab']")[0])

    def test_page_without_toc_keeps_the_column(self):
        self.assertIn("--__toc-width: initial", _rules(self.css, ":root[data-has-sidebar]:not([data-has-toc])")[0])
        # One pane rule for every page with a sidebar, "On this page"
        # or not, placed from the grid width.
        pane = _rules(self.css, ":root[data-has-sidebar] .main-pane")[0]
        self.assertIn("--sl-content-margin-inline: max(0rem, 100% - var(--rb-grid-width)) auto", pane)

    def test_card_pages(self):
        cards = next(b for s, b in _blocks(self.css) if s == ".sl-markdown-content :is(.rb-sys-file, .rb-file-entry)")
        self.assertIn("content-visibility: auto", cards)
        self.assertIn("contain-intrinsic-size: auto 320px", cards)
        self.assertIn("--sl-content-width: var(--rb-grid-width)", _rules(self.css, "body:has(.rb-sys-file, .rb-file-entry)")[0])
        self.assertEqual(_theme_tokens(self.css, ":root")["--rb-grid-width"], "54rem")
        facts = _rules(self.css, "dl.rb-facts")[0]
        self.assertIn("grid-template-columns: 11rem minmax(0, 1fr)", facts)
        self.assertRegex(self.css, r"@media \(max-width: 30rem\) \{\s*\.sl-markdown-content dl\.rb-facts \{ grid-template-columns: minmax\(0, 1fr\)")

    def test_long_values_wrap_between_words(self):
        table = _rules(self.css, ".rb-meta-card table")[0]
        self.assertIn("table-layout: fixed", table)
        self.assertIn("display: table", table)
        self.assertNotRegex(self.css, r"\.rb-meta-card td \{ overflow-wrap: anywhere")
        self.assertIn("overflow-wrap: anywhere", _rules(self.css, ".rb-meta-card td code")[0])
        self.assertIn("width: 40%", "".join(_rules(self.css, ".rb-meta-card td:first-child")))
        upstream = _rules(self.css, "#by-upstream-emulator")[0]
        self.assertIn("max-width: 22rem", upstream)

    def test_two_column_tables_stack_label_over_value(self):
        self.assertIn("content: none", _rules(self.css, "table[data-rb-stack='kv'] td::before")[0])
        self.assertTrue(_rules(self.css, "table[data-rb-stack='kv'] td:first-child"))

    def test_contrast_meets_wcag_aa_in_both_themes(self):
        for theme in ("light", "dark"):
            bg = PAGE_BG[theme]
            pairs = [
                ("link", self.resolve(theme, "--rb-link"), bg, 4.5),
                ("focus ring", self.resolve(theme, "--rb-link"), bg, 3.0),
                ("primary button", ON_FILL[theme], self.resolve(theme, "--rb-link"), 4.5),
                ("primary hover", ON_FILL[theme], self.resolve(theme, "--rb-link-strong"), 4.5),
                ("outline hover", self.resolve(theme, "--rb-link"), self.resolve(theme, "--sl-color-accent-low"), 4.5),
                ("sidebar current", self.resolve(theme, "--sl-color-accent-high"), self.resolve(theme, "--sl-color-accent-low"), 4.5),
                ("secondary text", self.resolve(theme, "--rb-text-secondary"), bg, 4.5),
                ("link on surface", self.resolve(theme, "--rb-link"), self.resolve(theme, "--rb-surface"), 4.5),
            ]
            for label, fg, back, need in pairs:
                with self.subTest(theme=theme, pair=label):
                    self.assertGreaterEqual(_ratio(fg, back), need, f"{fg} on {back}")


class DeviceTilesAndHeaderLogo(unittest.TestCase):
    """The device tiles had no style once merged: every line underlined and one
    tall block per setup on a phone. The header logo was sized from the whole
    header, tab row included, and grew to 84 px."""

    def test_a_tile_is_one_compact_link(self):
        css = CSS_PATH.read_text(encoding="utf-8")
        self.assertRegex(css, r"a\.rb-tile \{[^}]*grid-template-columns: 40px 1fr")
        self.assertRegex(css, r"a\.rb-tile \{[^}]*text-decoration: none")

    def test_the_header_logo_follows_the_top_bar(self):
        css = CSS_PATH.read_text(encoding="utf-8")
        self.assertIn("header .site-title img { height: calc(4rem - 2 * var(--sl-nav-pad-y))", css)


# The Get your files tables: no class reaches them, the Markdown table is
# matched by the cells the generator labels.
PACKS = "table:has(td[data-label='Runs on']):has(td[data-label='ZIP'])"


class CommandsSidebarAndPackTables(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.css = _strip_comments(CSS_PATH.read_text(encoding="utf-8"))
        dark = _theme_tokens(cls.css, ":root")
        light = {**dark, **_theme_tokens(cls.css, ":root[data-theme='light']")}
        cls.tokens = {"dark": dark, "light": light}

    def test_commands_never_break_inside_a_word(self):
        blocks = _rules(self.css, ".expressive-code pre > code")
        self.assertTrue(blocks)
        for body in blocks:
            self.assertIn("white-space: pre-wrap", body, "commands keep wrapping")
            self.assertNotIn("overflow-wrap: anywhere", body)
        for selector in (".rb-facts code", ".rb-hash code", ".rb-meta-card td code"):
            with self.subTest(selector=selector):
                self.assertIn("overflow-wrap: anywhere", _rules(self.css, selector)[0])

    def test_sidebar_labels_above_links(self):
        label = _rules(self.css, ".top-level summary .large")[0]
        # 13 px grey semibold, no uppercase: the house style refuses small caps.
        for declaration in ("font-size: var(--sl-text-xs)", "font-weight: 600", "color: var(--rb-text-secondary)"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, label)
        links = next(b for s, b in _blocks(self.css) if s == "#starlight__sidebar .top-level a")
        self.assertIn("font-size: var(--sl-text-sm)", links)
        self.assertIn("font-weight: 400", links)

    def test_badge_links_keep_a_24px_target(self):
        dd = next(b for s, b in _blocks(self.css) if s == ".sl-markdown-content .rb-facts dd")
        self.assertIn("line-height: 24px", dd)
        badge = _rules(self.css, ".rb-facts :is(.rb-badge:has(> a), a.rb-badge)")[0]
        for declaration in ("display: inline-flex", "align-items: center", "min-height: 24px", "margin-block: 2px"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, badge)

    def test_hashes_are_13px_at_every_width(self):
        hashes = [b for s, b in _blocks(self.css) if ".rb-hash" in s and "font-size" in b]
        self.assertEqual(len(hashes), 1, "a second size for .rb-hash, on phones")
        self.assertIn("font-size: 0.8125rem", hashes[0])
        short = _rules(self.css, "td code[title]")[0]
        self.assertIn("white-space: nowrap", short)
        self.assertIn("underline dotted", short)
        self.assertIn("min-width: 12rem", _rules(self.css, "td.rb-reason")[0])

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


STACK = ".sl-markdown-content table[data-rb-stack] td"


def _block(css: str, selector: str) -> str:
    bodies = [b for s, b in _blocks(css) if s == selector]
    if not bodies:
        raise AssertionError(f"no block {selector}")
    return "".join(bodies)


class TabsCellsAndCardLinks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = CSS_PATH.read_text(encoding="utf-8")
        cls.css = _strip_comments(cls.raw)

    def test_os_tabs_wrap_and_never_hide(self):
        tablist = _block(self.css, "starlight-tabs [role='tablist']")
        for declaration in ("flex-wrap: wrap", "overflow-x: visible", "row-gap: 0.25rem"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, tablist)
        self.assertNotIn("scrollbar-width: none", self.css)
        self.assertNotIn("::-webkit-scrollbar", self.css)

    def test_stacked_cells_close_up_and_labels_push_rows(self):
        cell = _block(self.css, STACK)
        # A 7.1rem column and 1.35 lines.
        for declaration in ("margin-top: 0", "display: flow-root", "line-height: 1.35",
                            "padding: 0 0.6rem 0 7.1rem"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, cell)
        label = _block(self.css, STACK + "::before")
        self.assertIn("position: static", label)
        self.assertIn("float: left", label)
        self.assertNotIn("position: absolute", label)
        # The label sits in the cell's left padding.
        self.assertIn("margin: 0 0.6rem 0 -7.1rem", label)

    def test_short_inline_code_never_splits(self):
        self.assertIn("white-space: pre", _block(self.css, ".sl-markdown-content :not(pre) > code.rb-short"))
        self.assertIn("white-space: break-spaces", _block(self.css, ".sl-markdown-content :not(pre) > code"))
        self.assertIn("white-space: nowrap", _block(self.css, ".sl-markdown-content table.rb-options td:first-child"))
        # A stacked value column is narrow: short code there moves down whole
        # and splits only when wider than the column, never pushing the page.
        stacked = _block(self.css, STACK + " code.rb-short")
        for declaration in ("display: inline-block", "max-width: 100%", "overflow-wrap: anywhere"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, stacked)
        # Commands in code blocks keep wrapping on a phone.
        self.assertIn("white-space: pre-wrap", _block(self.css, ".sl-markdown-content .expressive-code pre > code"))

    def test_lone_card_links_are_24px_targets(self):
        dd = _block(self.css, ".sl-markdown-content .rb-facts dd")
        self.assertIn("min-height: 24px", dd)
        self.assertIn("line-height: 24px", dd)
        link = _block(self.css, ".sl-markdown-content .rb-facts dd > a")
        self.assertIn("display: inline-block", link)
        self.assertIn("min-height: 24px", link)

    def test_card_labels_fit_and_lookup_labels_match(self):
        facts = _rules(self.css, "dl.rb-facts")[0]
        self.assertIn("grid-template-columns: 11rem minmax(0, 1fr)", facts)
        self.assertIn("font-weight: 600", _block(self.css, ".sl-markdown-content .rb-file-lookup label"))


def _declarations(body: str) -> dict[str, str]:
    return {k.strip(): v.strip() for k, v in re.findall(r"([\w-]+)\s*:\s*([^;]+);", body)}


class TablesHeaderAndRowHeights(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.css = _strip_comments(CSS_PATH.read_text(encoding="utf-8"))

    def test_long_code_in_a_cell_breaks_to_fit_its_column(self):
        self.assertIn("overflow-wrap: anywhere",
                      _block(self.css, ".sl-markdown-content table td code:not(.rb-short)"))
        last = _block(self.css, ".sl-markdown-content table:not([data-rb-stack='kv']) "
                                "td:last-child:not(:first-child):has(code:not(.rb-short))")
        self.assertIn("min-width: 9rem", last)
        # A flag or a short name in a cell still never splits.
        self.assertIn("white-space: pre", _block(self.css, ".sl-markdown-content :not(pre) > code.rb-short"))

    def test_one_grid_for_every_page(self):
        self.assertEqual(_theme_tokens(self.css, ":root").get("--rb-grid-width"), "54rem")
        self.assertIn("--sl-content-width: var(--rb-grid-width)",
                      _block(self.css, "body:has(.rb-sys-file, .rb-file-entry)"))
        # The header places its search box from the grid, not the page's column.
        self.assertIn("--sl-content-width: var(--rb-grid-width)",
                      _block(self.css, ":root[data-has-sidebar] header.header"))
        toc = _block(self.css, ":root[data-has-sidebar] .right-sidebar-container")
        pane = _block(self.css, ":root[data-has-sidebar] .main-pane")
        for body in (toc, pane):
            self.assertIn("var(--rb-grid-width)", body)
            self.assertNotIn("var(--sl-content-width)", body)
        # Every column starts on the grid's edge, the narrow one included.
        self.assertIn("--sl-content-margin-inline: max(0rem, 100% - var(--rb-grid-width)) auto", pane)
        # The pane rule covers pages with and without "On this page" alike.
        self.assertFalse([s for s, _ in _blocks(self.css) if s.endswith(":not([data-has-toc]) .main-pane")])

    def test_stacked_rows_are_short(self):
        cell = _declarations(_block(self.css, STACK))
        self.assertEqual(cell["font-size"], "0.875rem")
        self.assertEqual(cell["line-height"], "1.35")
        label = _declarations(_block(self.css, STACK + "::before"))
        self.assertEqual(label["width"], "max-content")
        self.assertEqual(label["min-width"], "6.5rem")
        self.assertEqual(label["max-width"], "9rem")
        self.assertEqual(label["font-size"], "0.8125rem")
        # Values start in the column of the shortest label: the label's
        # negative margin is the cell's left padding.
        indent = cell["padding"].split()[3]
        self.assertEqual(label["margin"].split()[3], f"-{indent}")
        self.assertEqual(indent, "7.1rem")
        self.assertIn("padding: 0.3rem 0", _block(self.css, ".sl-markdown-content table[data-rb-stack] tr"))
        # A two-column list keeps body text.
        self.assertIn("font-size: 1rem", _block(self.css, ".sl-markdown-content table[data-rb-stack='kv'] td"))

    def test_spacing_after_a_button_and_a_search_marker(self):
        self.assertIn("margin-top: 1rem",
                      _block(self.css, ".sl-markdown-content :is(.rb-button, p:has(> .rb-button)) + p"))
        self.assertIn("margin-top: var(--sl-content-gap-y)",
                      _block(self.css, ".sl-markdown-content span[data-pagefind-meta]:empty + :is(p, ul, ol, table, div)"))

    def test_choice_list_matches_the_filter_box(self):
        select = _declarations(_block(self.css, ".sl-markdown-content :is(.rb-file-lookup, .rb-picker) select,\n"
                                                ".sl-markdown-content select"))
        box = _declarations(_block(self.css, ".rb-table-filter input"))
        for prop in ("border", "border-radius", "min-height"):
            with self.subTest(prop=prop):
                self.assertEqual(select[prop], box[prop])
        self.assertEqual(select["appearance"], "none")
        self.assertIn("var(--rb-select-arrow)", select["background"])
        dark = _theme_tokens(self.css, ":root")["--rb-select-arrow"]
        light = _theme_tokens(self.css, ":root[data-theme='light']")["--rb-select-arrow"]
        # The arrow is drawn in each theme's secondary text colour.
        for arrow, tokens in ((dark, _theme_tokens(self.css, ":root")),
                              (light, _theme_tokens(self.css, ":root[data-theme='light']"))):
            colour = tokens["--rb-text-secondary"].lstrip("#")
            self.assertIn(f"%23{colour}", arrow)

    def test_crumb_separator_stays_with_its_label(self):
        self.assertIn("white-space: nowrap", _block(self.css, ".rb-breadcrumbs li"))
        self.assertIn("white-space: normal", _block(self.css, ".rb-breadcrumbs li > :is(a, span)"))


if __name__ == "__main__":
    unittest.main()
