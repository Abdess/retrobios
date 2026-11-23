"""What a run fetches: the files no copy here gives, those the pack lacks, the data files it brings."""
from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

from installer.datadirs import data_fetch_bytes
from installer.events import EVENTS
from installer.offline import LOCAL
from installer.pack_source import pack_holds_trees, pack_lacks


class FetchPlan(NamedTuple):
    """The files a run fetches, decided once for --check, --dry-run, the
    install and the screen's plan, which reads it from the fetch_plan event."""

    copied: list[dict]
    fetched: list[dict]
    lacking: list[dict]
    data_files: int
    data_bytes: int

    @property
    def coming(self) -> list[dict]:
        """The files fetched that the pack, when one is given, holds."""
        return self.without_lacking(self.fetched)

    def without_lacking(self, entries: list[dict]) -> list[dict]:
        """entries without those the pack lacks: the files a run writes."""
        lacking = {id(entry) for entry in self.lacking}
        return [entry for entry in entries if id(entry) not in lacking]


def fetch_plan(to_download: list[dict], copies: dict,
               data_states: list[tuple[dict, tuple[Path, dict[str, dict], int]]]) -> FetchPlan:
    """The files to install that no copy on this machine gives, those of
    them the pack lacks, and the data files the run brings: all of them
    from the network, from a pack only when it holds the trees. The screen
    counted the data files from a pack that held none, --check left them
    out of a pack that held them all."""
    copied = [entry for entry in to_download if id(entry) in copies]
    fetched = [entry for entry in to_download if id(entry) not in copies]
    trees = LOCAL.pack is None or pack_holds_trees([entry for entry, _state in data_states])
    return FetchPlan(
        copied, fetched, pack_lacks(fetched),
        sum(len(state[1]) for _entry, state in data_states) if trees else 0,
        sum(data_fetch_bytes(entry, state[1]) for entry, state in data_states) if trees else 0,
    )


def emit_fetch_plan(plat: str, plan: FetchPlan) -> None:
    """The plan as the screen reads it: files and bytes from the network or
    the pack, the dests copied from this machine, those the pack lacks."""
    coming = plan.coming
    EVENTS.emit(
        "fetch_plan", platform=plat, files=len(coming),
        bytes=sum(entry.get("size", 0) for entry in coming),
        copied=[entry["dest"] for entry in plan.copied],
        lacking=[entry["dest"] for entry in plan.lacking],
        data_files=plan.data_files, data_bytes=plan.data_bytes,
    )
