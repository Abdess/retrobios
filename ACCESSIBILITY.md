# Accessibility

## Commitment

The installer can be used without its full-screen interface, without colour and without a mouse, and the website is checked against Lighthouse's accessibility audits. An accessibility problem reported in an issue is treated like any other defect.

## Supported environments

**Installer** (`install.py`, Python 3.8 or later, on Linux, macOS, Windows, WSL, Android in Termux and the handheld launchers under `ports/`):

- Line-by-line questions: any terminal, a pipe or a log included. This is the mode for a screen reader.
- Full-screen interface: a terminal of at least 40 columns and 12 rows whose `TERM` is set, is not `dumb` and moves the cursor with ANSI sequences. On Windows, a console that draws escape sequences (Windows 10 or later).
- JSON events (`--events`): for a program or another front end that drives the installer.

**Website** (https://abdess.github.io/retrobios/): light and dark themes, phone and desktop widths. The audits below ran in Chrome. Other browsers have not been audited.

## What works

Installer:

- `--plain`, `RETROBIOS_PLAIN=1` or `ACCESSIBLE=1` keep the questions line by line instead of the full screen.
- The full screen falls back to line-by-line questions by itself, and says why, when the window is smaller than 40x12, when `TERM` is unset or `dumb`, or when the terminal cannot draw it. `--tui` asks for the full screen and exits with code 2 and the reason when it cannot open.
- Every action has a key (arrows, `j`/`k`, Enter, Space, Esc, Tab, `/` to filter a list), and `?` or F1 lists the keys of the screen. The bottom line names what Enter or A does on the row under the cursor.
- A controller drives it through a handheld launcher (`RETROBIOS_PAD`: gptokeyb, muxterm, evmapy, Miyoo). A mouse or a touch screen works where the terminal reports clicks, and `RETROBIOS_NO_MOUSE` leaves the mouse to the terminal.
- Colour is added to words, never put in their place, and only the 16 basic colours are used. `NO_COLOR` (any value but an empty one), `TERM=dumb`, an unset `TERM`, a terminal that names fewer than 8 colours or an output that is not a terminal turn colour off. The text stays the same.
- Without a UTF-8 terminal, or under the C locale, the screen is drawn in ASCII.
- However the screen ends (Enter, `q`, Ctrl+C, a signal), the terminal is given back with the cursor shown and echo on.

Website:

- Lighthouse accessibility, 2026-11-19 (Lighthouse 13.4.1, Chrome, mobile and desktop, median of 3 runs, on a production build served with gzip under `/retrobios/`): 100 on `/`, `/emulators/mgba/`, `/systems/sony-playstation-2/`, `/systems/other-project64/`, `/platforms/retroarch/`, `/get/retroarch/`, `/files/`, `/wanted/`, `/wiki/installer/`, `/gaps/`, `/provenance-redump/`, `/cross-reference/` and the not-found page. Best Practices is 100 on the same pages, and SEO is 100 on all but the not-found page (see Known limitations).
- Text, link, button and focus ring colours meet the WCAG AA contrast ratios in both themes. A test in `tests/test_site_css.py` checks each pair.
- Every link and control shows a focus ring. Form fields (file picker, wanted list filter, measurements filters) have labels, and results are announced in live regions.
- Glossary terms open with Enter or Space and close with Escape.
- The search button is named "Search", and its shortcut (Ctrl+K, or Cmd+K on a Mac) is announced through `aria-keyshortcuts`. The key hint beside it is drawn, so it does not change the button's name.
- Animations and transitions are cut when the system asks for reduced motion.

## Known limitations

- The full-screen installer is read badly by a screen reader. Use `--plain`.
- Mouse and touch input have not been checked in macOS Terminal or iTerm2.
- The not-found page scores below 100 in SEO because it carries `noindex`, so Lighthouse fails `is-crawlable`. A page that only says an address does not exist must stay out of search results, so this is kept. Lighthouse cannot audit the page at a missing address, since the server answers 404 there, so it was audited at `/404.html`.
- The website checks are automated. No review with a screen reader or with the keyboard alone has been recorded.

## Reporting

Open an issue at https://github.com/Abdess/retrobios/issues/new (the **Report a problem** link at the bottom of each page leads there). Include:

- the page address, or the installer command you ran and what `python3 install.py --version` prints,
- your system, browser or terminal, and any assistive technology (screen reader, magnifier, controller, voice control),
- what you expected and what happened.

A security problem goes through the private channel described in [SECURITY.md](SECURITY.md).
