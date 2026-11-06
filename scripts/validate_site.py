#!/usr/bin/env python3
"""Validate the built RetroBIOS site as a navigable, accessible data product.

This complements Starlight's own link check (starlight-links-validator,
which fails the build) with checks on the rendered HTML: metadata,
heading structure, image alternatives, duplicate IDs, structured data, local
resources, links and fragments, the budgets of what a visitor downloads, and
a get/ download page for every registered platform.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


@dataclass
class Page:
    path: Path
    title: str = ""
    h1: str = ""
    lang: str = ""
    descriptions: list[str] = field(default_factory=list)
    canonical: list[str] = field(default_factory=list)
    h1_count: int = 0
    main_count: int = 0
    ids: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    missing_alt: list[str] = field(default_factory=list)
    jsonld: list[str] = field(default_factory=list)
    unrendered: list[str] = field(default_factory=list)
    remote_images: list[str] = field(default_factory=list)
    remote_scripts: list[str] = field(default_factory=list)
    placeholders: list[str] = field(default_factory=list)
    headings: list[int] = field(default_factory=list)
    empty_headers: int = 0
    runtime_diagrams: int = 0
    size: int = 0
    elements: int = 0
    # A moved page's old address: a meta refresh to the new one, no content.
    redirect: str = ""


# Budgets the site was brought under on 2026-10-22, with room to grow. A
# change that passes one is a regression of what a visitor downloads, not a
# matter of taste: raise the number in the same change that explains why.
#
# The largest page was 10.5 MB (systems/game-engines/) and took 21 s of
# main-thread work on a throttled phone. Split pages now top out at 0.9 MB.
MAX_PAGE_BYTES = 1_000_000
# Elements outside scripts and styles: the browser lays out and styles each.
# emulators/mame held 13,300 and blocked the main thread for 235 ms. Its
# index now carries each card's id on the link itself.
MAX_PAGE_ELEMENTS = 10_000
# Pages allowed past it, each with the reason, removed when it comes under.
OVER_ELEMENT_BUDGET: dict[str, str] = {}
# Pagefind loads its index in pieces: the metadata, then the chunks the words
# typed fall in (stored compressed). 59 KB for the largest chunk and 7.5 KB of
# metadata on 2026-10-22, 5.2 MB for the whole index on disk.
MAX_PAGEFIND_CHUNK_BYTES = 150_000
MAX_PAGEFIND_META_BYTES = 50_000
MAX_PAGEFIND_TOTAL_BYTES = 12_000_000
# Pages whose description is one text once the page's own name is taken
# out. 707 pages shared five templates ("X: source-pinned emulator
# firmware profile with paths, hashes..."), and a search engine showed the
# same line under every result.
MAX_SHARED_DESCRIPTION = 10


# Text inside these is shown as written, so markup there is not a leftover.
_LITERAL_TAGS = frozenset({"pre", "code", "script", "style", "textarea"})


class _PageParser(HTMLParser):
    def __init__(self, path: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.page = Page(path)
        self._title_depth = 0
        self._title_parts: list[str] = []
        self._h1_depth = 0
        self._h1_parts: list[str] = []
        self._jsonld_depth = 0
        self._jsonld_parts: list[str] = []
        self._literal_depth = 0
        self._header_parts: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {key: value or "" for key, value in attrs}
        if tag not in ("script", "style"):
            self.page.elements += 1
        if tag in _LITERAL_TAGS:
            self._literal_depth += 1
        if re.fullmatch(r"h[1-6]", tag):
            self.page.headings.append(int(tag[1]))
        if tag == "th":
            self._header_parts = []
        if "mermaid" in data.get("class", "").split():
            # Material renders it in the browser with a script from a CDN.
            self.page.runtime_diagrams += 1
        if tag == "script" and re.match(r"\s*(?:https?:)?//", data.get("src", "")):
            self.page.remote_scripts.append(data["src"])
        if tag == "html":
            self.page.lang = data.get("lang", "")
        elif tag == "title":
            self._title_depth += 1
        elif tag == "meta" and data.get("http-equiv", "").lower() == "refresh":
            self.page.redirect = data.get("content", "").partition("url=")[2]
        elif tag == "meta" and data.get("name", "").lower() == "description":
            self.page.descriptions.append(data.get("content", "").strip())
        elif tag == "h1":
            self.page.h1_count += 1
            self._h1_depth += 1
        elif tag == "main":
            self.page.main_count += 1
        elif tag == "img" and "alt" not in data:
            self.page.missing_alt.append(data.get("src", "?"))
        elif tag == "script" and data.get("type") == "application/ld+json":
            self._jsonld_depth += 1
            self._jsonld_parts = []

        element_id = data.get("id")
        if element_id is not None:
            self.page.ids.append(element_id)

        if tag in ("a", "link") and data.get("href"):
            self.page.links.append(data["href"])
        if tag in ("img", "script", "source") and data.get("src"):
            self.page.links.append(data["src"])
        # An image from another host breaks when that host renames it, and
        # tells it about every visit: the site serves its own copies.
        sources = [data.get("src") or ""] + (data.get("srcset") or "").split(",")
        if tag in ("img", "source", "image") and any(
            re.match(r"\s*(?:https?:)?//", value) for value in sources if value
        ):
            self.page.remote_images.append(data.get("src") or data.get("srcset") or "?")
        if tag == "link" and "canonical" in data.get("rel", "").split():
            self.page.canonical.append(data.get("href", ""))

    def handle_comment(self, data: str) -> None:
        match = re.match(r"\s*image:\s*(\S+)", data)
        if match:
            self.page.placeholders.append(match.group(1))

    def handle_endtag(self, tag: str) -> None:
        if tag in _LITERAL_TAGS and self._literal_depth:
            self._literal_depth -= 1
        if tag == "th" and self._header_parts is not None:
            if not "".join(self._header_parts).strip():
                self.page.empty_headers += 1
            self._header_parts = None
        if tag == "title":
            self._title_depth -= 1
        elif tag == "h1" and self._h1_depth:
            self._h1_depth -= 1
        elif tag == "script" and self._jsonld_depth:
            self.page.jsonld.append("".join(self._jsonld_parts).strip())
            self._jsonld_depth -= 1
            self._jsonld_parts = []

    def handle_data(self, data: str) -> None:
        if self._header_parts is not None:
            self._header_parts.append(data)
        if self._title_depth:
            self._title_parts.append(data)
        if self._h1_depth:
            self._h1_parts.append(data)
        if self._jsonld_depth:
            self._jsonld_parts.append(data)
        if not self._literal_depth and "**" in data:
            self.page.unrendered.append(data.strip()[:60])

    def close(self) -> None:
        super().close()
        self.page.title = "".join(self._title_parts).strip()
        self.page.h1 = re.sub(r"\s+", " ", "".join(self._h1_parts)).strip()


def _parse_page(path: Path) -> Page:
    parser = _PageParser(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    parser.feed(text)
    parser.close()
    parser.page.size = len(text.encode("utf-8"))
    return parser.page


def _heading_jumps(levels: list[int]) -> list[str]:
    """Each heading more than one level below the one before it: a screen
    reader user moving by level finds nothing at the level skipped."""
    return [f"h{before} to h{after}" for before, after in zip(levels, levels[1:])
            if after > before + 1]


def _check_pagefind(site: Path) -> list[str]:
    """Pagefind's index pieces, each against its budget."""
    root = site / "pagefind"
    files = [path for path in root.rglob("*") if path.is_file()]
    issues = []
    for path in files:
        size = path.stat().st_size
        rel = path.relative_to(site).as_posix()
        if path.suffix == ".pf_index" and size > MAX_PAGEFIND_CHUNK_BYTES:
            issues.append(f"{rel}: {size:,} bytes, over the {MAX_PAGEFIND_CHUNK_BYTES:,} budget of a chunk")
        if path.suffix == ".pf_meta" and size > MAX_PAGEFIND_META_BYTES:
            issues.append(f"{rel}: {size:,} bytes, over the {MAX_PAGEFIND_META_BYTES:,} budget")
    total = sum(path.stat().st_size for path in files)
    if total > MAX_PAGEFIND_TOTAL_BYTES:
        issues.append(f"pagefind/: {total:,} bytes, over the {MAX_PAGEFIND_TOTAL_BYTES:,} budget")
    return issues


def _local_target(
    href: str, page_path: Path, site: Path, base_path: str
) -> tuple[list[Path], str] | None:
    parsed = urlsplit(href)
    if parsed.scheme or parsed.netloc or href.startswith(
        ("mailto:", "tel:", "data:", "javascript:")
    ):
        return None

    raw_path = unquote(parsed.path)
    if not raw_path:
        return [page_path], unquote(parsed.fragment)

    if base_path != "/" and (
        raw_path == base_path.rstrip("/") or raw_path.startswith(base_path)
    ):
        suffix = raw_path[len(base_path.rstrip("/")) :]
        raw_path = "/" + suffix.lstrip("/")

    target = (
        site / raw_path.lstrip("/")
        if raw_path.startswith("/")
        else page_path.parent / raw_path
    ).resolve()
    try:
        target.relative_to(site)
    except ValueError:
        return [], unquote(parsed.fragment)

    candidates = [target]
    if raw_path.endswith("/"):
        candidates = [target / "index.html"]
    elif not target.suffix:
        candidates.extend([target / "index.html", target.with_suffix(".html")])
    return candidates, unquote(parsed.fragment)


def _check_pages(
    pages: dict, site: Path, titles: dict, descriptions: dict
) -> list[str]:
    """Every per-page check: title, description, links, JSON-LD.

    Split out of validate_site, which reached complexity 43. The
    cross-page duplicate check stays with the caller, since it can only
    run once every page has been seen. *titles* and *descriptions* are
    filled here for it.
    """
    issues: list[str] = []

    def report(path: Path, message: str) -> None:
        issues.append(f"{path.relative_to(site)}: {message}")

    for path, page in pages.items():
        is_404 = path.relative_to(site) == Path("404.html")
        if not page.title:
            report(path, "missing document title")
        elif not is_404:
            titles[page.title].append(path)
        if page.lang != "en":
            report(path, f"expected lang='en', got {page.lang!r}")
        if len(page.descriptions) != 1 or not page.descriptions[0]:
            report(path, f"expected one non-empty description, got {len(page.descriptions)}")
        elif not is_404:
            descriptions[page.descriptions[0]].append(path)
        if not is_404 and page.h1_count != 1:
            report(path, f"expected one H1, got {page.h1_count}")
        if page.main_count != 1:
            report(path, f"expected one main landmark, got {page.main_count}")
        if not is_404 and (
            len(page.canonical) != 1
            or not page.canonical[0].startswith("https://")
        ):
            report(path, f"expected one HTTPS canonical URL, got {page.canonical!r}")
        duplicate_ids = [
            value
            for value, count in Counter(page.ids).items()
            if value and count > 1
        ]
        if duplicate_ids:
            report(path, f"duplicate IDs: {duplicate_ids[:5]}")
        if page.missing_alt:
            report(path, f"images missing alt: {page.missing_alt[:5]}")
        if page.remote_images:
            report(path, f"images loaded from another host: {page.remote_images[:3]}")
        if page.remote_scripts:
            report(path, f"scripts loaded from another host: {page.remote_scripts[:3]}")
        if page.runtime_diagrams:
            report(path, f"{page.runtime_diagrams} diagram(s) drawn by a script at runtime")
        if page.size > MAX_PAGE_BYTES:
            report(path, f"{page.size:,} bytes of HTML, over the {MAX_PAGE_BYTES:,} budget")
        if page.elements > MAX_PAGE_ELEMENTS \
                and path.relative_to(site).as_posix() not in OVER_ELEMENT_BUDGET:
            report(path, f"{page.elements:,} elements, over the {MAX_PAGE_ELEMENTS:,} budget")
        jumps = _heading_jumps(page.headings)
        if jumps:
            report(path, f"heading levels skipped: {sorted(set(jumps))}")
        if page.empty_headers:
            report(path, f"{page.empty_headers} table header cell(s) without text")
        if page.placeholders:
            # scripts/sitediagrams.py knows no diagram of this name.
            report(path, f"image placeholders left unresolved: {page.placeholders[:3]}")
        if page.unrendered:
            # Bold that reached the reader as asterisks: a block indented
            # one level too deep is read as code (the clownmdemu analysis).
            report(path, f"markdown left unrendered: {page.unrendered[:3]}")

        if not is_404 and len(page.jsonld) != 1:
            report(path, f"expected one JSON-LD block, got {len(page.jsonld)}")
        for document in page.jsonld:
            try:
                payload = json.loads(document)
            except json.JSONDecodeError as exc:
                report(path, f"invalid JSON-LD: {exc}")
                continue
            if not isinstance(payload, dict) or payload.get("@context") != "https://schema.org":
                report(path, "JSON-LD is not a schema.org object")

    return issues


def description_template(page: Page, site_name: str = "RetroBIOS") -> str:
    """A page's description with its own names taken out: its h1 and its
    window title. What is left is the text it shares with its template."""
    text = page.descriptions[0] if page.descriptions else ""
    names = {page.h1, page.title.removesuffix(f" - {site_name}").strip()}
    for name in sorted(filter(None, names), key=len, reverse=True):
        text = text.replace(name, "")
    return re.sub(r"\s+", " ", text).strip()


def _check_description_templates(pages: dict, site: Path) -> list[str]:
    """No more than MAX_SHARED_DESCRIPTION pages share one description
    once their names are taken out."""
    shared: dict[str, list[Path]] = defaultdict(list)
    for path, page in pages.items():
        if path.relative_to(site) != Path("404.html") and page.descriptions:
            shared[description_template(page)].append(path)
    return [
        f"{len(paths)} pages share the description {text!r} after their name: "
        + ", ".join(str(path.relative_to(site)) for path in paths[:3])
        for text, paths in shared.items()
        if len(paths) > MAX_SHARED_DESCRIPTION
    ]


def _check_links(pages: dict, site: Path, base_path: str) -> list[str]:
    """Every local link and fragment resolves to something on disk."""
    issues: list[str] = []

    def report(path: Path, message: str) -> None:
        issues.append(f"{path.relative_to(site)}: {message}")

    for path, page in pages.items():
        for href in page.links:
            resolved = _local_target(href, path, site, base_path)
            if resolved is None:
                continue
            candidates, fragment = resolved
            if not candidates:
                report(path, f"link escapes site root: {href}")
                continue
            existing = next((candidate for candidate in candidates if candidate.is_file()), None)
            if existing is None:
                report(path, f"broken local link or resource: {href}")
                continue
            if fragment and existing.suffix.lower() == ".html":
                target_page = pages.get(existing.resolve())
                if target_page is not None and fragment not in target_page.ids:
                    report(path, f"missing fragment in {href}")

    return issues


RELEASE_DOWNLOAD = "https://github.com/Abdess/retrobios/releases/download/"


def _check_get_pages(
    pages: dict, site: Path, platforms_dir: Path, record_path: Path,
) -> list[str]:
    """get/<platform>/ resolves for every registered platform, as a page.

    Links outside the site keep these addresses across releases, so a
    missing one is a dead download link for whoever followed it. A platform
    with a pack in the release record links every one of its assets at the
    recorded tag, and one without links none and gives the command.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import release_record  # noqa: PLC0415
    from siteguides import INSTALL_SH  # noqa: PLC0415
    from common import list_registered_platforms, list_release_pack_platforms  # noqa: PLC0415

    if not (platforms_dir / "_registry.yml").is_file():
        return [f"no platform registry in {platforms_dir}"]
    record = release_record.load_advertised(record_path, str(platforms_dir))
    released = set(list_release_pack_platforms(str(platforms_dir), include_archived=True))
    issues: list[str] = []
    for platform in list_registered_platforms(str(platforms_dir), include_archived=True):
        rel = f"{release_record.GET_DIR}/{platform}/index.html"
        page = pages.get((site / rel).resolve())
        if page is None or page.redirect:
            issues.append(f"{rel}: no download page for {platform}")
            continue
        assets = [link for link in page.links if link.startswith(RELEASE_DOWNLOAD)]
        pack = release_record.pack_for(platform, record)
        if platform in released and pack:
            expected = {f"{RELEASE_DOWNLOAD}{record['tag']}/{a}" for a in pack["assets"]}
            missing = sorted(expected - set(assets))
            if missing:
                issues.append(f"{rel}: does not link {', '.join(missing)}")
        elif platform not in released:
            packs = [a for a in assets if "_BIOS_Pack" in a]
            if packs:
                issues.append(f"{rel}: links a pack for a setup without one: {packs[0]}")
            if f"{INSTALL_SH} | sh" not in (site / rel).read_text(encoding="utf-8"):
                issues.append(f"{rel}: gives no install command")
    return issues


def validate_site(
    site: Path, base_path: str = "/retrobios/", platforms_dir: Path | None = None,
    record_path: Path | None = None,
) -> list[str]:
    site = site.resolve()
    if not site.is_dir():
        return [f"site directory does not exist: {site}"]

    html_paths = sorted(site.rglob("*.html"))
    if not html_paths:
        return [f"no HTML pages found in {site}"]

    pages = {path.resolve(): _parse_page(path) for path in html_paths}
    issues: list[str] = []
    titles: dict[str, list[Path]] = defaultdict(list)
    descriptions: dict[str, list[Path]] = defaultdict(list)

    # A redirect has no page to judge, only a target. The link check below
    # still follows its link, so a redirect to nowhere is reported.
    content = {path: page for path, page in pages.items() if not page.redirect}
    issues.extend(_check_pages(content, site, titles, descriptions))

    for label, values in (("title", titles), ("description", descriptions)):
        for value, paths in values.items():
            if len(paths) > 1:
                rendered = ", ".join(str(path.relative_to(site)) for path in paths[:5])
                issues.append(f"duplicate {label} {value!r}: {rendered}")

    issues.extend(_check_description_templates(content, site))
    issues.extend(_check_links(pages, site, base_path))
    issues.extend(_check_pagefind(site))
    if platforms_dir is not None:
        issues.extend(_check_get_pages(
            pages, site, platforms_dir, record_path or platforms_dir.parent / "release.json"))

    return issues


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=__doc__.replace("``", ""),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--site-dir", default="website/dist",
        help="the built site (default: %(default)s)",
    )
    parser.add_argument(
        "--base", default="/retrobios/",
        help="the path the site is served under (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms", type=Path,
        help="registry whose platforms each need a get/ page (default: %(default)s)",
    )
    parser.add_argument(
        "--record", default="release.json", type=Path,
        help="release record the get/ pages link (default: %(default)s)",
    )
    parser.add_argument(
        "--max-errors", type=int, default=100,
        help="stop listing after this many errors (default: %(default)s)",
    )
    args = parser.parse_args()
    from common import require_directory  # noqa: PLC0415

    require_directory(str(args.platforms_dir), "--platforms-dir")

    try:
        issues = validate_site(Path(args.site_dir), args.base, args.platforms_dir, args.record)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Site validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if issues:
        for issue in issues[: args.max_errors]:
            print(f"ERROR {issue}", file=sys.stderr)
        if len(issues) > args.max_errors:
            print(
                f"ERROR ... {len(issues) - args.max_errors} additional issue(s)",
                file=sys.stderr,
            )
        print(f"{len(issues)} rendered-site issue(s)", file=sys.stderr)
        raise SystemExit(1)

    html_count = sum(1 for _ in Path(args.site_dir).rglob("*.html"))
    print(f"Rendered site is valid: {html_count} HTML pages, all local links resolved.")


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
