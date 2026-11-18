"""The line question that picks a setup among those found."""
from __future__ import annotations

from installer.detect_os import detect_os
from installer.embedded import _SHARE_FOLDERS, _name_key, card_setup, display_name
from installer.offline import LOCAL
from installer.prompt import _ask, _no_widow, _quit
from installer.setups import _SETUP_DEVICES, TuiRow, _setup_devices, android_hint, setup_list
from installer.terminal import terminal_size
from installer.text import _wrap


def _row_name(row: TuiRow) -> str:
    """The name a setup row is typed back with: a platform id, or the name
    of a system that runs from its SD card."""
    value = row.value
    if row.action == "cardsystem" and isinstance(value, tuple):
        return str(value[1])
    return str(value)


def _row_platform(row: TuiRow) -> str:
    """The platform of the system a cardsystem row stands for."""
    value = row.value
    return str(value[0]) if isinstance(value, tuple) else ""


def _line_setups(setups: list | None = None, mounted: set | None = None,
                 os_type: str = "") -> list[tuple[str, str]]:
    """(name typed back, label) of each choice of the line menus, the
    screen's setup list (setup_list) in its order, numbered: Onion was
    reachable only as RetroArch, whose folder on a computer is the
    computer's, and the numbers followed another order than the rows."""
    def devices(names: list[str]) -> str:
        # The devices that run it, three at most: the name its owner knows.
        more = f", +{len(names) - 3}" if len(names) > 3 else ""
        return ", ".join(names[:3]) + more

    choices = []
    for row in setup_list(setups or [], mounted or set(), "", os_type or detect_os(),
                          LOCAL.serves()):
        name = _row_name(row)
        if row.action == "cardsystem":
            listed = list(_SETUP_DEVICES.get(name, ()))
            shown = devices(listed) or f"{display_name(_row_platform(row))} files"
            choices.append((name, f"{row.label} ({shown})"))
        else:
            listed = list(_setup_devices(name, os_type or detect_os())) \
                if card_setup(name, name) else []
            choices.append((name, row.label + (f" ({devices(listed)})" if listed else "")))
    return choices


def _line_matches(choices: list[tuple[str, str]], typed: str, setups: list | None = None,
                  mounted: set | None = None, os_type: str = "") -> list[tuple[int, str]]:
    """(index, label) of the choices a typed device or system name finds,
    with the screen filter's own matcher: "miyoo" was refused, the line
    menu knowing only setup names. The label names what was matched first,
    as the screen's row does on its right: "miyoo mini" listed MinUI with
    RG28XX, RG34XX and RG34XX SP."""
    found = {_row_name(row): row for row in setup_list(
        setups or [], mounted or set(), typed, os_type or detect_os(), LOCAL.serves())}
    matched = []
    for index, (name, label) in enumerate(choices):
        row = found.get(name)
        if row is None:
            continue
        named = row.right.split(", ") if row.right else []
        more = f", +{len(named) - 3}" if len(named) > 3 else ""
        matched.append((index, f"{row.label} ({', '.join(named[:3])}{more})" if named
                        else label))
    return matched


def _choose_platform(title: str, default: str = "", setups: list | None = None,
                     mounted: set | None = None) -> str:
    """One setup from the numbered list, Enter taking the default: a
    platform id, or the name of a system that runs from its SD card, which
    normalize_platform turns into its list.

    A device several systems run lists them all, and Enter after that list
    takes none of them: it took RetroArch, which none of them was. A number
    out of range is said as one, never read as a device name.
    """
    os_type = detect_os()
    choices = _line_setups(setups, mounted, os_type)
    if default and default not in {name for name, _label in choices}:
        # A file list for another setup: Enter takes the first row, where
        # the screen's focus falls (_platform_focus).
        default = choices[0][0] if choices else ""
    print(f"\n{title}")
    # Wrapped at the width between words, its devices under its name: left
    # to the terminal, "Miyoo Flip" was folded inside "Miy" and "oo" below
    # 40 columns.
    cols = terminal_size()[0] - 1
    width = len(str(len(choices)))
    for i, (_name, label) in enumerate(choices, 1):
        number = f"  {i:>{width}}) "
        pieces = _no_widow(_wrap(label, max(cols - len(number), 8), ""),
                           max(cols - len(number), 8))
        print(number + pieces[0])
        for piece in pieces[1:]:
            print(" " * len(number) + piece)
    print("  q) quit")
    print("Type a number, a setup's name, or the device's name (Miyoo Mini, R36S).")
    usage = (f"  Type a number from 1 to {len(choices)}, a setup name or the "
             "device's name, or q to quit.")
    while True:
        prompt = f"> [Enter for {display_name(default)}] " if default else "> "
        choice = _ask(prompt)
        if not choice:
            if default:
                return default
            print(usage)
            continue
        if choice.lower() == "q":
            _quit()
        if choice.isdigit():
            if 1 <= int(choice) <= len(choices):
                return choices[int(choice) - 1][0]
            print(usage)
            continue
        key = _name_key(choice)
        for name, _label in choices:
            if key and key in (_name_key(name), _name_key(display_name(name))):
                return name
        found = _line_matches(choices, choice, setups, mounted, os_type) if key else []
        if len(found) == 1:
            print(f"  {found[0][1]}")
            return choices[found[0][0]][0]
        if found:
            print(f"  {len(found)} setups run on '{choice.strip()}':")
            for index, label in found:
                print(f"  {index + 1}) {label}")
            print("  Type the number of the right one.")
            default = ""
            continue
        hint = android_hint(choice, os_type)
        print(f"  {hint}" if hint else usage)


def drive_example(os_type: str, label: str, below: str = "", plat: str = "") -> str:
    """Where a drive mounted here is, as this system writes it, for the
    example a refusal gives: macOS mounts it at /Volumes/<label>, WSL at
    /mnt/<letter>, Windows names a letter. A Linux path with $USER was
    given on every system, which PowerShell does not expand. plat, a
    system reached over the network, names its network share on Windows."""
    if os_type == "windows":
        if plat in _SHARE_FOLDERS:
            return _SHARE_FOLDERS[plat]
        return "E:\\" + below.replace("/", "\\")
    root = {"darwin": f"/Volumes/{label}", "wsl": "/mnt/e",
            "android": f"/storage/{label}"}.get(os_type, f"/media/$USER/{label}")
    return f"{root}/{below}" if below else root
