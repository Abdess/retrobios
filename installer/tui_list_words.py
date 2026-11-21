"""What the full screen says of a file list or board list it could not have."""
from __future__ import annotations

import os

from installer.lists import ListProblem, manifest_failure_lines, missing_list_advice
from installer.offline import offline_named, offline_undo
from installer.platforms import display_name
from installer.tui_rows import TUI_OFFLINE_TITLE

_NETWORK_TITLES = {"clock": "The clock is wrong", "no_ca": "No trusted certificates",
                   "no_ssl": "This Python cannot use HTTPS"}


def _download_lines(failure: ListProblem) -> tuple[str, list[str]]:
    """The title and lines of a file list the network did not bring."""
    plat, code, words = failure.plat, failure.code, failure.words
    if code == "invalid":
        if failure.garbled:
            # The parser's "Expecting value: line 2 column 1" told no one anything.
            return "The file list is not valid", [
                "What arrived is not a file list: a Wi-Fi sign-in page or a cut "
                "download looks like this.", "Check the connection, then choose Try again."]
        return "The file list is not valid", [f"What arrived is not a file list: {words}."]
    if code == "http":
        lines = [f"There is no file list for {display_name(plat)} at this address."
                 if failure.status == 404 else f"The server answered HTTP {failure.status}."]
        if failure.status == 404 and not failure.overridden:
            lines.append(missing_list_advice(plat, "choose Try again", failure.ref))
        return "No file list", lines
    if code != "network":
        # The screen's first row is Try again: "then run again" was a second way.
        return _NETWORK_TITLES.get(code, "No connection"), [
            words[0].upper() + words[1:].replace(", then run again",
                                                  ", then choose Try again") + "."]
    lines = [f"The list of BIOS files could not be downloaded: {words}.",
             "Check the Wi-Fi or the cable, then choose Try again.",
             # A handheld with no Wi-Fi has the pack as its way.
             "Or copy a pack to the card and run the installer with --from-pack "
             "PACK: no network is needed then."]
    proxy = next((name for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY",
                                    "all_proxy") if os.environ.get(name)), "")
    if proxy:
        # Named, never shown: the value can hold a password.
        lines.append(f"{proxy} is set, so the connection goes through a proxy: "
                     "check that it answers.")
    return "No connection", lines


def manifest_failure_screen(failure: ListProblem) -> tuple[str, list[str], int]:
    """The title, lines and exit code the screen shows for a file list it
    could not have, from the failure line mode prints."""
    plat = failure.plat
    if failure.source != "network":
        # A list given on disk or in a pack: line mode's words, as they are.
        return "", manifest_failure_lines(failure), failure.fatal
    if failure.code == "offline":
        # Asked for, not a failure: no Try again, and the two ways a run
        # without the network gets its list.
        return TUI_OFFLINE_TITLE, [
            f"This run makes no network request ({offline_named()}), and the list "
            "of BIOS files comes from the network.",
            "Run the installer again with the list saved as a file "
            f"(--manifest FILE, a copy of install/{plat}.json) or with a pack "
            f"(--from-pack PACK), or {offline_undo()}."], failure.fatal
    title, lines = _download_lines(failure)
    if failure.overridden:
        lines.append(f"RETROBIOS_BASE_URL chose the address: {failure.where}")
    return title, lines, failure.fatal


def targets_failure_words(failure: ListProblem) -> str:
    """The line Device shows for a board list it could not have."""
    code, words, where = failure.code, failure.words, failure.where
    if failure.source == "file":
        state = "cannot be read" if code == "unreadable" else "is not valid"
        cause = f"the list {where} {state}: {words}"
    elif code == "offline":
        cause = words
    elif code == "invalid":
        cause = f"it is not valid: {words}"
    elif code == "http":
        cause = f"the server answered HTTP {failure.status}"
    else:
        cause = words
    return f"The board list could not be read: {cause}."
