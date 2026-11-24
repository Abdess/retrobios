"""Diagrams for the site, written as SVG from the repository's own data.

Each diagram is a function of the registry, the platform files, the
pipeline's step list or the install manifests, so it changes when the data
does and never needs redrawing by hand. Output is deterministic: sorted
inputs, fixed number formatting, ids derived from the diagram's name.

A page asks for a diagram with an HTML comment on a line of its own::

    <!-- image: install-flow -->

``resolve_images`` replaces the comment with the figure. Each drawing is
an SVG file shown through ``<img>``, so the page text holds its words once:
an inline SVG put every label of both layouts, its title and its desc into
what a screen reader, a copy, a text dump or a crawler reads, next to the
prose that already says them. A file reads no stylesheet of the page, so it
is written once per theme with the colours retrobios.css gives the
``rb-d-*`` classes (``THEMES``), and the stylesheet shows the one of the
current theme. Presentation attributes give the same drawing a readable
default when the SVG is opened on its own.

Every figure carries two layouts, wide and narrow, and ``<picture>`` picks
one: a 720-unit drawing scaled to a phone would print 9 px text. The
drawings are ``alt=""``: the figure says what they show once, in a
screen-reader line, and the caption under them.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sitegen.diagrams import write_svgs


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Write the site diagrams as SVG files.", allow_abbrev=False
    )
    parser.add_argument("--output-dir", default="tmp/diagrams", help="default: %(default)s")
    args = parser.parse_args()
    for path in write_svgs(Path(args.output_dir)):
        print(path)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
