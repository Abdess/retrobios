"""The file lists and board lists a run reads, and why one could not be had."""
from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path
from typing import NamedTuple

from installer.host_fs import _is_file, read_local_json
from installer.manifest import _check_standalone_layouts, _validate_manifest, _validate_targets
from installer.network import _address_lines, _fetch_json, network_words, request_proxy
from installer.offline import LOCAL, _Offline, offline_named, offline_undo, offline_words
from installer.platforms import TARGET_PLATFORMS, display_name
from installer.refusal import Refusal
from installer.remote import (
    DEFAULT_RELEASE_REF,
    MAX_MANIFEST_BYTES,
    MAX_RETRIES,
    MAX_STANDALONE_BYTES,
    MAX_TARGETS_BYTES,
    STANDALONE_DIR,
    TROUBLESHOOTING_PAGE,
    Remote,
    active_remote,
)

NETWORK_ADVICE = ("  Check the connection, and HTTPS_PROXY if this network needs a "
                  "proxy, then run the same command again.\n"
                  f"  More help: {TROUBLESHOOTING_PAGE}")


class ListProblem(NamedTuple):
    """A list that could not be had, classified once: line mode prints it
    and stops, the full screen draws it.

    source is file or pack for a list this run was given (where names it),
    network for one asked at the address where. code is unreadable or
    invalid, http (status), offline, or the network_words code (network,
    clock, no_ca, no_ssl), with words saying it. garbled is an answer that
    is not JSON at all: a Wi-Fi sign-in page or a cut download. fatal is the
    code line mode ends on, 0 when the run carries on without the list.
    proxy names what sent a network request through a proxy (a variable or
    the system settings), empty when it went direct.
    """

    plat: str
    code: str
    words: str
    source: str = "network"
    where: str = ""
    remote: Remote | None = None
    status: int = 0
    attempts: int = MAX_RETRIES
    garbled: bool = False
    fatal: int = 1
    proxy: str = ""

    @property
    def overridden(self) -> bool:
        """Whether RETROBIOS_BASE_URL chose the address that failed."""
        return self.remote is not None and self.remote.overridden

    @property
    def ref(self) -> str:
        return self.remote.ref if self.remote is not None else DEFAULT_RELEASE_REF


class ListFailure(Exception):
    """A list that could not be had, its problem carried to who says it."""

    def __init__(self, problem: ListProblem) -> None:
        super().__init__(problem.words)
        self.problem = problem


def _download_failure(plat: str, url: str, remote: Remote, exc: Exception,
                      fatal: int = 1) -> ListFailure:
    """What a list asked at url gave instead of a valid document."""
    if isinstance(exc, ValueError):
        garbled = isinstance(exc.__cause__, (json.JSONDecodeError, UnicodeDecodeError))
        return ListFailure(ListProblem(plat, "invalid", str(exc), where=url, remote=remote,
                           garbled=garbled, fatal=fatal))
    if isinstance(exc, urllib.error.HTTPError):
        return ListFailure(ListProblem(plat, "http", str(exc), where=url, remote=remote,
                           status=exc.code, fatal=fatal))
    code, words = network_words(exc)
    return ListFailure(ListProblem(plat, code, words, where=url, remote=remote, fatal=fatal,
                       attempts=getattr(exc, "attempts", MAX_RETRIES),
                       proxy=request_proxy(url)))


def missing_list_advice(plat: str, again: str, ref: str) -> str:
    """What to do when the revision asked for has no file list for plat:
    the name was checked before any request, so the revision is the cause."""
    if ref != DEFAULT_RELEASE_REF:
        return (f"RETROBIOS_REF={ref} has no list for {plat}: unset it, or pick a "
                "newer tag from https://github.com/Abdess/retrobios/releases.")
    return f"The repository may be moving its files: {again} in a few minutes."


def load_manifest(plat: str, attempts: int = MAX_RETRIES, timeout: float | None = None) -> dict:
    """The file list of plat: the one this run was given, else downloaded.
    ListFailure when it cannot be had."""
    if LOCAL.manifest is not None:
        path = str(LOCAL.manifest)
        try:
            return _validate_manifest(read_local_json(LOCAL.manifest, MAX_MANIFEST_BYTES), plat)
        except OSError as exc:
            raise ListFailure(ListProblem(plat, "unreadable", str(exc.strerror or exc),
                              source="file", where=path)) from exc
        except ValueError as exc:
            raise ListFailure(ListProblem(plat, "invalid", str(exc), source="file", where=path)) from exc
    if LOCAL.pack is not None:
        try:
            return _validate_manifest(LOCAL.pack.manifest(plat), plat)
        except ValueError as exc:
            raise ListFailure(ListProblem(plat, "invalid", str(exc), source="pack",
                              where=LOCAL.pack.name)) from exc
    remote = active_remote()
    url = remote.manifest_url.format(platform=plat)
    try:
        return _validate_manifest(_fetch_json(url, MAX_MANIFEST_BYTES, "file list",
                                              attempts=attempts, timeout=timeout), plat)
    except (ValueError, OSError) as exc:
        raise _download_failure(plat, url, remote, exc) from exc


def invalid_list_words(failure: ListProblem) -> str:
    """A file list that arrived and is not one, in line mode's words."""
    if failure.garbled:
        # The parser's "Expecting value: line 1 column 1" told no one
        # anything, where the full screen names the usual cause.
        return ("what arrived is not a file list: a Wi-Fi sign-in page or a cut "
                "download looks like this")
    return f"the file list is not valid: {failure.words}"


def _manifest_event(failure: ListProblem) -> tuple[str, str] | None:
    """The reason and message of the error event line mode writes, if any."""
    code, words = failure.code, failure.words
    if failure.source != "network":
        return ("invalid", f"the file list is not valid: {words}") \
            if failure.source == "file" and code == "invalid" else None
    if code == "invalid":
        return code, invalid_list_words(failure)
    if code == "http":
        return ("not_found" if failure.status == 404 else "network",
                f"the file list could not be fetched: HTTP {failure.status}")
    return code, words if code != "network" else f"the file list could not be fetched: {words}"


def _manifest_local_lines(failure: ListProblem) -> list[str]:
    where, words = failure.where, failure.words
    if failure.source == "pack":
        return [f"  The file list in {where} is not valid: {words}"]
    if failure.code == "unreadable":
        return [f"  Cannot read the file list {where}: {words}."]
    return [f"  The file list {where} is not valid for {failure.plat}: {words}"]


def manifest_failure_lines(failure: ListProblem) -> list[str]:
    """What line mode prints of a file list it could not have."""
    if failure.source != "network":
        return _manifest_local_lines(failure)
    plat, code, words = failure.plat, failure.code, failure.words
    address = _address_lines(failure.where, failure.overridden)
    if code == "invalid":
        lines = [f"  For {display_name(plat)}, {invalid_list_words(failure)}."]
        if failure.garbled:
            lines += [*address, "  Check the connection (sign in to the Wi-Fi if it asks), "
                      "then run the same command again."]
        return lines
    if code == "http" and failure.status == 404:
        if failure.overridden:
            return [f"  No file list for {plat} there.", *address]
        # Asked once, a 4xx being final. The name was checked before any
        # request, so the revision is what has no such list.
        return [f"  No file list for {plat} at {failure.ref}.",
                f"  {missing_list_advice(plat, 'run the same command again', failure.ref)}"]
    if code == "http":
        return [f"  Could not fetch the file list for {plat}: HTTP {failure.status}",
                *address, NETWORK_ADVICE]
    if code == "offline":
        return [f"  No file list for {plat}: {offline_words()}. Give --manifest FILE "
                f"(a copy of install/{plat}.json) or --from-pack PACK, or run "
                f"{offline_undo()}."]
    if code != "network":
        return [f"  Could not fetch the file list for {plat}.", f"  {words}."]
    return [f"  Could not fetch the file list for {plat} after {failure.attempts} "
            f"attempts: {words}", *address, NETWORK_ADVICE]


def fetch_manifest(plat: str) -> dict:
    """The file list of plat, or the run stopped on what went wrong, code 1."""
    try:
        return load_manifest(plat)
    except ListFailure as stopped:
        failure = stopped.problem
        lines = manifest_failure_lines(failure)
        # A list given as a file or in a pack that cannot be used ended the
        # run on code 1 with no event: its words are the message.
        reason, message = _manifest_event(failure) or (
            failure.code, " ".join(line.strip() for line in lines))
        raise Refusal("manifest", reason, plat, *lines, code=failure.fatal,
                      message=message) from None


def _say(lines: list[str]) -> None:
    for line in lines:
        print(line, file=sys.stderr)


def _pack_alone(plat: str) -> bool:
    """A pack read without a file list for plat: one built before packs
    carried their install list records the systems of its files only."""
    return (LOCAL.pack is not None and LOCAL.manifest is None
            and (LOCAL.pack.install_list or {}).get("platform") != plat)


def fetch_standalone(plat: str, manifest: dict) -> dict:
    """What each standalone build reads, for --standalone only: the file
    beside --manifest (standalone/<platform>.json, where the repository
    keeps it), else downloaded as the list is. Missing, unreachable or
    invalid, the run stops on one line, code 1."""
    beside = (LOCAL.manifest.parent / STANDALONE_DIR / f"{plat}.json"
              if LOCAL.manifest is not None else None)
    url = active_remote().standalone_url.format(platform=plat)
    where = str(beside) if beside is not None and _is_file(beside) else url
    try:
        if where != url:
            data = read_local_json(Path(where), MAX_STANDALONE_BYTES)
        else:
            data = _fetch_json(url, MAX_STANDALONE_BYTES, "standalone layout")
        return _check_standalone_layouts(data, manifest, plat)
    except urllib.error.HTTPError as exc:
        problem = f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError) as exc:
        problem = (str(exc) if isinstance(exc, _Offline)
                   else exc.strerror or str(exc) if where != url
                   else network_words(exc)[1])
    except ValueError as exc:
        problem = f"not valid: {exc}"
    raise Refusal("manifest", "unavailable", plat,
                  f"Error: --standalone needs {where}, which could not be read ({problem}).",
                  message=f"--standalone needs {where}: {problem}")


def held_targets(plat: str) -> dict | None:
    """The cores per board this run has without the network: the list the
    pack carries, else targets/<platform>.json beside --manifest, where the
    repository keeps it (install/targets/). None when there is neither,
    ListFailure, code 1, when the file beside --manifest cannot be used:
    read as absent, the offline run asked for the file already there."""
    if LOCAL.pack is not None and LOCAL.pack.targets is not None \
            and plat in LOCAL.pack.platforms():
        return LOCAL.pack.targets
    if LOCAL.manifest is None:
        return None
    beside = LOCAL.manifest.parent / "targets" / f"{plat}.json"
    if not _is_file(beside):
        return None
    try:
        return _validate_targets(read_local_json(beside, MAX_TARGETS_BYTES))
    except OSError as exc:
        raise ListFailure(ListProblem(plat, "unreadable", str(exc.strerror or exc), source="file",
                          where=str(beside))) from exc
    except ValueError as exc:
        raise ListFailure(ListProblem(plat, "invalid", str(exc), source="file", where=str(beside))) from exc


def local_targets(plat: str) -> dict | None:
    """held_targets, the run stopped on a file beside --manifest it cannot use."""
    try:
        return held_targets(plat)
    except ListFailure as stopped:
        raise _targets_refusal(stopped.problem) from None


def load_targets(plat: str, attempts: int = MAX_RETRIES,
                 timeout: float | None = None) -> dict:
    """The target core list: the one this run has at hand, else downloaded.

    Empty on 404, where the platform publishes no targets. ListFailure when
    the list could not be read: a timeout says nothing about the platform,
    and answering "no targets" for it sent users to the full pack. A run
    without the network and with no list at hand fails with code 2, before
    any file is written. A list the network did not bring lets the run go
    on (fatal 0).
    """
    held = held_targets(plat)
    if held is not None:
        return held
    if LOCAL.offline and plat not in TARGET_PLATFORMS:
        return {}
    if LOCAL.offline:
        source = (f"{LOCAL.pack.name} carries none" if LOCAL.pack is not None
                  else f"{offline_named()} makes no request")
        raise ListFailure(ListProblem(plat, "offline", source, fatal=2))
    remote = active_remote()
    url = remote.targets_url.format(platform=plat)
    try:
        return _validate_targets(_fetch_json(url, MAX_TARGETS_BYTES, "target list",
                                             attempts=attempts, timeout=timeout))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        raise _download_failure(plat, url, remote, exc, fatal=0) from exc
    except (ValueError, OSError) as exc:
        raise _download_failure(plat, url, remote, exc, fatal=0) from exc


def targets_file_words(failure: ListProblem) -> str:
    """Why the board list beside --manifest cannot be used, in one clause."""
    state = "cannot be read" if failure.code == "unreadable" else "is not valid"
    return f"the target list {failure.where} {state}: {failure.words}"


def targets_failure_lines(failure: ListProblem) -> list[str]:
    """What line mode prints of a board list it could not have."""
    plat, code, words, where = failure.plat, failure.code, failure.words, failure.where
    if failure.source == "file":
        return [f"  Error: {targets_file_words(failure)}"]
    if code == "offline":
        return [f"Error: --target needs the {display_name(plat)} board list ({words}). Put "
                f"install/targets/{plat}.json beside the --manifest file, or go online."]
    if code == "invalid":
        return [f"  Error: the target list for {plat} is not valid: {words}"]
    return [f"  Error: failed to fetch targets for {plat}: {words}",
            *_address_lines(where, failure.overridden), NETWORK_ADVICE]


def _targets_refusal(failure: ListProblem) -> Refusal:
    """A board list the run cannot go on without, as the run's refusal."""
    return Refusal("targets", failure.code, failure.plat, *targets_failure_lines(failure),
                   code=failure.fatal)


def fetch_targets(plat: str, attempts: int = MAX_RETRIES,
                  timeout: float | None = None) -> dict | None:
    """load_targets in line mode: what went wrong said, None when the run
    carries on without the list, the run stopped when it cannot."""
    try:
        return load_targets(plat, attempts, timeout)
    except ListFailure as stopped:
        if stopped.problem.fatal:
            raise _targets_refusal(stopped.problem) from None
        _say(targets_failure_lines(stopped.problem))
        return None
