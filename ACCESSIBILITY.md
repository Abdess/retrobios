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

- Lighthouse accessibility, 2026-11-19 (Lighthouse 13.4.1): 100 for `/`, `/emulators/mgba/` and `/files/` on desktop, 100 for `/` on mobile, 96 for `/systems/sony-playstation-2/` on desktop (see Known limitations).
- Text, link, button and focus ring colours meet the WCAG AA contrast ratios in both themes. A test in `tests/test_site_css.py` checks each pair.
- Every link and control shows a focus ring. Form fields (file picker, wanted list filter, measurements filters) have labels, and results are announced in live regions.
- Glossary terms open with Enter or Space and close with Escape.
- Animations and transitions are cut when the system asks for reduced motion.

## Known limitations

- The full-screen installer is read badly by a screen reader. Use `--plain`.
- Mouse and touch input have not been checked in macOS Terminal or iTerm2.
- On long system pages, Lighthouse flags `target-size` on links inside file cards. The cards use `content-visibility: auto`, so cards out of view are not laid out when the audit measures them. With every card drawn, the same audit passes. The score of `/systems/sony-playstation-2/` is 96 for this reason.
- Lighthouse flags `label-content-name-mismatch` on the search button: its accessible name is "Search" while the button also shows the Ctrl K shortcut, which is exposed through `aria-keyshortcuts`. This audit does not count toward the score.
- The website checks are automated. No review with a screen reader or with the keyboard alone has been recorded.

## Reporting

Open an issue at https://github.com/Abdess/retrobios/issues/new (the **Report a problem** link at the bottom of each page leads there). Include:

- the page address, or the installer command you ran and what `python3 install.py --version` prints,
- your system, browser or terminal, and any assistive technology (screen reader, magnifier, controller, voice control),
- what you expected and what happened.

A security problem goes through the private channel described in [SECURITY.md](SECURITY.md).
