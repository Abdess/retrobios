"""The drives the folder screen offers, read when it opens and on Look again."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from installer.cards import _doubt_kinds, share_doubt
from installer.destination import _card_what, blank_cards_of, doubt_cards, mounted_cards_of
from installer.host_fs import _is_dir
from installer.line_folder import (
    _said_with,
    drives_left_out,
    folder_drives,
    share_targets,
    unproven_words,
)
from installer.tui_choice import _tui_card_bound

if TYPE_CHECKING:
    from installer.tui_state import TuiState


class FolderScan(NamedTuple):
    """What the mounted drives said when the folder screen last looked."""

    # (mount, what its own files say) of the cards that run the system.
    cards: tuple = ()
    # (mount, the systems it could be) of the drives two systems fit.
    doubtful: tuple = ()
    # (mount, what it is) of the drives no system claims.
    blank: tuple = ()
    # (row label, bios folder) of each share drive.
    shares: tuple = ()
    # (row label, folder) of each drive, its label saying a missing folder.
    drives: tuple = ()
    # The notes under the rows: drives left out, drives nothing proves.
    notes: tuple = ()


def scan_folder(state: TuiState) -> FolderScan:
    """The mounted drives the folder screen lists, read once: a frame that
    read them moved the rows under the focus when a stick was inserted, and
    Enter acted on a row nobody chose."""
    bound = _tui_card_bound(state)
    if bound:
        mounts = mounted_cards_of(bound[0], state.platform)
        doubtful = [mount for mount in doubt_cards(state.platform) if mount not in mounts]
        taken = [*mounts, *doubtful]
        return FolderScan(
            cards=tuple((mount, _card_what(mount)) for mount in mounts),
            doubtful=tuple((mount, _doubt_kinds(share_doubt(mount)[0])) for mount in doubtful),
            blank=tuple((mount, _card_what(mount))
                        for mount in blank_cards_of(bound[0], state.platform)
                        if mount not in taken))
    if state.folder_kind == "share":
        return FolderScan(shares=tuple(share_targets(state.platform)))
    drives = tuple((label if _is_dir(folder) else _said_with(label, "does not exist yet"),
                    folder)
                   for label, folder in folder_drives(state.os_type, state.platform,
                                                      state.folder_kind == "usual"))
    notes = tuple(note for note in (drives_left_out(state.platform), unproven_words()) if note)
    return FolderScan(drives=drives, notes=notes)


def card_mounts(scan: FolderScan) -> list[Path]:
    """The mounts of the cards found running the system."""
    return [mount for mount, _what in scan.cards]
