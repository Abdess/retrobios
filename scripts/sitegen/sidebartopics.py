"""The navigation as Starlight sidebar topics, one per tab, with the reading order through them."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from core.anchors import toc_slug
from sitegen.config import BASE
from sitegen.starlight import page_url, reads_in_order


# Navigation


def _sidebar_link(rel: str) -> str:
    return page_url(rel)[len(BASE) - 1:]


# Tabs whose groups hold pages by the hundred (every system, every
# emulator): a group that does not hold the current page is drawn as one
# link to its overview, so an emulator page does not carry the links of
# every other emulator.
PRUNED_TABS = ("explore",)

# Reading runs from one tab into the next only here: the last Start here
# page leads to Setups. Every other tab is read on its own.
CHAINED_TABS = (("start-here", "setups"),)


def topic_id(label: str) -> str:
    return re.sub(r"[^a-z]+", "-", label.lower()).strip("-")


_DIGIT_RANGE = re.compile(r"[0-9] to [0-9]")


def by_initial(label: str, children: list[dict]) -> bool:
    """A group that files its pages by the first character of their names
    (A, B, "0 to 9"): a way through a long list, not a place, so it is no
    crumb."""
    if not children or any("items" in child for child in children):
        return False
    firsts = {str(child["label"])[:1].upper() for child in children}
    if len(label) == 1:
        return firsts == {label}
    return bool(_DIGIT_RANGE.fullmatch(label)) and not any("A" <= first <= "Z" for first in firsts)


def sidebar(nav: list, present: set[str], anchors: dict[str, set[str]] | None = None) -> dict:
    """The navigation as Starlight topics, one per tab, with what the route
    middleware (website/src/routeData.ts) reads beside it.

    A page the navigation does not list (the parts of a split page) joins
    the topic that holds most pages of its directory. In a directory the
    navigation lists nothing of (get/), it joins the topic of the pages of
    the same name, and a page with neither joins the first topic: no page
    is left out of every tab.

    A group that files names by their first letter is marked `crumb: false`:
    the breadcrumbs skip it.

    `groups` gives each group, keyed by the labels from its tab down, the
    page that introduces it: its own overview page, or the heading named
    after it on the overview above it (`anchors` lists each page's heading
    ids). A group with neither has no address, never the address of its
    first page, which is a sibling of the page being read. `prune` marks the
    groups drawn as one link when they do not hold the current page.

    `reading` is the order of the previous and next links, one list per run
    of tabs read in sequence.
    """
    walk = _NavWalk(present, anchors or {})
    topics = []
    for tab in nav:
        (label, value), = tab.items()
        topic = topic_id(label)
        children = [child for child in (walk.item(v, topic, (label,), _overview_of(value)) for v in value)
                    if child]
        if children:
            topics.append({"id": topic, "label": label, "link": next(_links(children))["link"],
                           "items": children})
    extra = _unlisted_pages(walk.owner, present, topics)
    return {"topics": topics, "options": {"topics": extra, "exclude": []},
            "groups": walk.groups, "reading": _reading(nav, present)}


def _overview_of(value: list) -> str | None:
    return next((v for v in value if isinstance(v, str)), None)


@dataclass
class _NavWalk:
    """The sidebar items of the navigation, the topic of each page it
    lists, and the entry of each group in `groups`."""
    present: set[str]
    anchors: dict[str, set[str]]
    owner: dict[str, str] = field(default_factory=dict)
    groups: dict[str, dict] = field(default_factory=dict)

    def item(self, entry: str | dict, topic: str, trail: tuple[str, ...],
             parent: str | None) -> dict | None:
        if isinstance(entry, str):
            self.owner[entry] = topic
            return {"label": "Overview", "link": _sidebar_link(entry)} if entry in self.present else None
        (label, value), = entry.items()
        if isinstance(value, str):
            if value.startswith("http"):
                return {"label": label, "link": value}
            self.owner[value] = topic
            return {"label": label, "link": _sidebar_link(value)} if value in self.present else None
        if "/" in label:
            raise ValueError(f"a navigation group label holds a slash: {label!r}")
        own = _overview_of(value)
        here = (*trail, label)
        href = self._group_href(label, own, parent, topic)
        children = [child for child in (self.item(v, topic, here, own or parent) for v in value) if child]
        if not children:
            return None
        self.groups["/".join(here)] = {"href": href, "prune": topic in PRUNED_TABS and href is not None,
                                       "crumb": not by_initial(label, children)}
        return {"label": label, "items": children, "collapsed": True}

    def _group_href(self, label: str, own: str | None, parent: str | None, topic: str) -> str | None:
        if own and own in self.present:
            return page_url(own)
        if parent and parent in self.present:
            anchor = toc_slug(label)
            if anchor in self.anchors.get(parent, set()):
                return f"{page_url(parent)}#{anchor}"
            if topic in PRUNED_TABS:
                # Drawn as a link, it needs an address: the overview it
                # sits under, never one of its own pages.
                return page_url(parent)
        return None


def _unlisted_pages(owner: dict[str, str], present: set[str], topics: list[dict]) -> dict[str, list[str]]:
    """The pages each topic holds beyond the ones the navigation lists."""
    votes: dict[str, dict[str, int]] = {}
    for rel, topic in owner.items():
        tally = votes.setdefault(rel.rpartition("/")[0], {})
        tally[topic] = tally.get(topic, 0) + 1
    # The page a stale link lands on opens on the first tab: its sidebar
    # is the way back in. Excluded from every tab, the theme named the tabs
    # by their position, 0 to 4.
    extra: dict[str, list[str]] = {topics[0]["id"]: ["/404"]} if topics else {}
    # A folder the navigation lists nothing of (get/, one download page per
    # setup) has no vote, and excluded from every tab its pages had the
    # tabs numbered 0 to 4 too. Its pages take the tab of the pages of the
    # same name (get/batocera.md, platforms/batocera.md), and its overview
    # the tab its pages took.
    by_name: dict[str, dict[str, int]] = {}
    for rel, topic in owner.items():
        tally = by_name.setdefault(PurePosixPath(rel).name, {})
        tally[topic] = tally.get(topic, 0) + 1
    unlisted = sorted(present - owner.keys())
    adopted: dict[str, dict[str, int]] = {}
    for rel in unlisted:
        folder, name = rel.rpartition("/")[0], PurePosixPath(rel).name
        if folder in votes or name == "index.md":
            continue
        tally = adopted.setdefault(folder, {})
        for topic, count in by_name.get(name, {}).items():
            tally[topic] = tally.get(topic, 0) + count
    for rel in unlisted:
        folder = rel.rpartition("/")[0]
        chosen = votes.get(folder) or adopted.get(folder)
        if chosen:
            topic = max(chosen, key=chosen.__getitem__)
        elif topics:
            topic = topics[0]["id"]
        else:
            continue
        extra.setdefault(topic, []).append("/" + (_sidebar_link(rel).strip("/") or "index"))
    return extra


def _reading(nav: list, present: set[str]) -> list[list[dict]]:
    """The previous and next links, in runs. An overview is named after the
    group or tab it opens ("Setups", not "Overview")."""
    def walk(value: list, name: str) -> Iterator[dict]:
        for entry in value:
            if isinstance(entry, str):
                if entry in present and reads_in_order(entry):
                    yield {"label": name, "link": page_url(entry)}
                continue
            (label, target), = entry.items()
            if isinstance(target, list):
                yield from walk(target, label)
            elif not target.startswith("http") and target in present and reads_in_order(target):
                yield {"label": label, "link": page_url(target)}

    tabs = {topic_id(label): list(walk(value, label))
            for tab in nav for label, value in tab.items()}
    runs: list[list[dict]] = []
    previous = ""
    for tab, pages in tabs.items():
        if runs and (previous, tab) in CHAINED_TABS:
            runs[-1].extend(pages)
        else:
            runs.append(list(pages))
        previous = tab
    return [run for run in runs if run]


def _links(items: list[dict]) -> Iterator[dict]:
    for entry in items:
        if "link" in entry:
            yield entry
        else:
            yield from _links(entry["items"])
