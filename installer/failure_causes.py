"""The cause of each failed file and the remedy it calls for, said alike in line mode and on the screen."""
from __future__ import annotations

from collections.abc import Iterable
from typing import NamedTuple

from installer.host_fs import DRIVE_FULL, NOT_WRITABLE, READ_ONLY
from installer.network import OVERRIDE_LINE
from installer.offline import LOCAL
from installer.pack_source import NOT_IN_PACK
from installer.remote import TROUBLESHOOTING_PAGE, active_remote
from installer.safe_replace import NOT_KEPT
from installer.text import _plural


class OfflineReason(str):
    """A file not fetched because the run was told to make no request."""


class NetworkReason(str):
    """A failure the connection caused: cut, timed out, refused by a server
    or a proxy. The summary names the network instead of the folder."""

    url = ""


class HttpReason(str):
    """A file the server answered for with an error of its own (HTTP 404):
    the summary names the address, where "HTTP 404" alone told the user
    neither what failed nor that running again changes nothing."""

    url = ""


# The causes a failure event names (the failures event's kind), each with
# the remedy failure_remedies gives it. other: a cause with no remedy of
# its own, the reason words saying it.
FAILURE_KINDS = ("offline", "network", "http", "not_writable", "drive_full", "read_only",
                 "not_kept", "not_in_pack", "other")


class Failure(NamedTuple):
    """One failed file: where, the reason in words, its cause (FAILURE_KINDS)
    and the address it was asked at, for a server's refusal."""

    dest: str
    reason: str
    kind: str
    url: str = ""


def failure_kind(reason: str) -> str:
    """The cause of a failure, from the type the run gave its reason or the
    words that name it."""
    if isinstance(reason, OfflineReason):
        return "offline"
    if isinstance(reason, HttpReason):
        return "http"
    if isinstance(reason, NetworkReason):
        return "network"
    words = str(reason)
    if words == NOT_WRITABLE:
        return "not_writable"
    if words == DRIVE_FULL:
        return "drive_full"
    if words == READ_ONLY:
        return "read_only"
    if words.startswith(NOT_KEPT):
        return "not_kept"
    if words == NOT_IN_PACK:
        return "not_in_pack"
    return "other"


def failure_records(failures: Iterable[tuple[str, str]]) -> list[Failure]:
    """The run's failures, each with its cause."""
    return [Failure(dest, str(reason), failure_kind(reason), getattr(reason, "url", ""))
            for dest, reason in failures]


def failure_events(failures: Iterable[tuple[str, str]]) -> list[dict]:
    """The failures event's items: what a screen needs to give the same remedies."""
    return [record._asdict() for record in failure_records(failures)]


def event_records(items: Iterable[dict]) -> list[Failure]:
    """The failures event's items read back."""
    return [Failure(str(item.get("dest", "")), str(item.get("reason", "")),
                    str(item.get("kind", "other")), str(item.get("url", "")))
            for item in items]


def split_offline(records: list[Failure]) -> tuple[list[Failure], list[Failure]]:
    """(failed, offline): a file --offline left out is missing, never failed."""
    return ([record for record in records if record.kind != "offline"],
            [record for record in records if record.kind == "offline"])


def _http_failure_lines(records: list[Failure]) -> list[str]:
    """The address the first refused file was asked at, and what chose it:
    a mirror named with RETROBIOS_BASE_URL that holds the lists and not yet
    the files, or a list out of step with the files it names."""
    refused = [record for record in records if record.kind == "http"]
    if not refused:
        return []
    more = f" (and {_plural(len(refused) - 1, 'other file')})" if len(refused) > 1 else ""
    lines = [f"  The server answered {refused[0].reason} for {refused[0].url}{more}."]
    if active_remote().overridden:
        return [*lines, OVERRIDE_LINE]
    return lines + ["  The file list names files the server does not hold, and running "
                    "again changes nothing until the two match.",
                    f"  More help: {TROUBLESHOOTING_PAGE}"]


NETWORK_FAILURE_ADVICE = (
    "  The transfers were cut or refused on the way: check the connection, and "
    "HTTPS_PROXY if this network needs a proxy.\n"
    f"  More help: {TROUBLESHOOTING_PAGE}")


def failure_remedies(records: list[Failure], locations: str) -> list[str]:
    """What to do about each cause but a folder this user cannot write,
    whose remedy each interface words with its own commands. locations
    names the folders the run wrote to."""
    kinds = {record.kind for record in records}
    advice: list[str] = []
    if "drive_full" in kinds:
        advice.append(f"  The drive holding {locations} is full: free up space, or "
                      "install to another drive with --dest, then run again.")
    if "read_only" in kinds:
        advice.append("  Files marked read-only are in the way: clear that attribute "
                      "(or delete them), then run again.")
    advice += _http_failure_lines(records)
    if "network" in kinds:
        advice.append(NETWORK_FAILURE_ADVICE)
        if active_remote().overridden:
            # A mirror that is down read as this machine's connection.
            advice.append(OVERRIDE_LINE)
    if "not_kept" in kinds:
        # The same run fails the same way: "retry only those" sent a phone
        # user round the loop with nothing changed.
        advice.append("  The files in place were left as they were, as no backup folder could "
                      "be made for them. Move them out of the folder, then run again to "
                      "install the new ones.")
    return advice


def retry_words(records: list[Failure]) -> str:
    """What to do when every failure is a file the pack does not hold: a
    second run fails them the same way, and "run it again to retry only
    those" sent people round. "" otherwise."""
    lacking = [record for record in records if record.kind == "not_in_pack"]
    if not lacking or len(lacking) != len(
            [record for record in records if record.kind != "not_kept"]):
        return ""
    name = LOCAL.pack.name if LOCAL.pack is not None else "The pack"
    return (f"{name} does not hold {'it' if len(lacking) == 1 else 'them'}: a newer pack, "
            "or a run without --from-pack, installs "
            f"{'it' if len(lacking) == 1 else 'them'}.")


def retry_helps(records: list[Failure]) -> bool:
    """Whether running again can install what failed: not when every file
    failed for want of a backup folder or of space, which a second run
    meets the same way."""
    return not all(record.kind in ("not_kept", "drive_full") for record in records)


def connection_only(records: list[Failure]) -> bool:
    """Whether every file failed on the way, the folder never the problem."""
    return bool(records) and all(record.kind in ("offline", "network", "http")
                                 for record in records)
