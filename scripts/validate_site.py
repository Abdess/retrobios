#!/usr/bin/env python3
"""Validate the built RetroBIOS site as a navigable, accessible data product.

This complements ``mkdocs build --strict`` with checks on the rendered HTML:
metadata, heading structure, image alternatives, duplicate IDs, structured
data, local resources, links and fragments.
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
    lang: str = ""
    descriptions: list[str] = field(default_factory=list)
    canonical: list[str] = field(default_factory=list)
    h1_count: int = 0
    main_count: int = 0
    ids: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    missing_alt: list[str] = field(default_factory=list)
    jsonld: list[str] = field(default_factory=list)


class _PageParser(HTMLParser):
    def __init__(self, path: Path):
        super().__init__(convert_charrefs=True)
        self.page = Page(path)
        self._title_depth = 0
        self._title_parts: list[str] = []
        self._jsonld_depth = 0
        self._jsonld_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        data = dict(attrs)
        if tag == "html":
            self.page.lang = data.get("lang", "")
        elif tag == "title":
            self._title_depth += 1
        elif tag == "meta" and data.get("name", "").lower() == "description":
            self.page.descriptions.append(data.get("content", "").strip())
        elif tag == "h1":
            self.page.h1_count += 1
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
        if tag == "link" and "canonical" in data.get("rel", "").split():
            self.page.canonical.append(data.get("href", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._title_depth -= 1
        elif tag == "script" and self._jsonld_depth:
            self.page.jsonld.append("".join(self._jsonld_parts).strip())
            self._jsonld_depth -= 1
            self._jsonld_parts = []

    def handle_data(self, data: str) -> None:
        if self._title_depth:
            self._title_parts.append(data)
        if self._jsonld_depth:
            self._jsonld_parts.append(data)

    def close(self) -> None:
        super().close()
        self.page.title = "".join(self._title_parts).strip()


def _parse_page(path: Path) -> Page:
    parser = _PageParser(path)
    parser.feed(path.read_text(encoding="utf-8", errors="replace"))
    parser.close()
    return parser.page


def _base_path(config_path: Path) -> str:
    """Read site_url without constructing executable YAML extension tags."""
    config = config_path.read_text(encoding="utf-8")
    match = re.search(
        r"(?m)^site_url:\s*['\"]?([^\s#'\"]+)",
        config,
    )
    site_url = match.group(1) if match else ""
    path = urlsplit(site_url).path or "/"
    return "/" + path.strip("/") + "/" if path.strip("/") else "/"


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


def validate_site(site: Path, config_path: Path) -> list[str]:
    site = site.resolve()
    if not site.is_dir():
        return [f"site directory does not exist: {site}"]

    base_path = _base_path(config_path)
    html_paths = sorted(site.rglob("*.html"))
    if not html_paths:
        return [f"no HTML pages found in {site}"]

    pages = {path.resolve(): _parse_page(path) for path in html_paths}
    issues: list[str] = []
    titles: dict[str, list[Path]] = defaultdict(list)
    descriptions: dict[str, list[Path]] = defaultdict(list)

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

    for label, values in (("title", titles), ("description", descriptions)):
        for value, paths in values.items():
            if len(paths) > 1:
                rendered = ", ".join(str(path.relative_to(site)) for path in paths[:5])
                issues.append(f"duplicate {label} {value!r}: {rendered}")

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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-dir", default="site")
    parser.add_argument("--config", default="mkdocs.yml")
    parser.add_argument("--max-errors", type=int, default=100)
    args = parser.parse_args()

    try:
        issues = validate_site(Path(args.site_dir), Path(args.config))
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
    main()
