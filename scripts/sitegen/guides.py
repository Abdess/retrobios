"""The guide part of the site: where each setup keeps its BIOS files.

A platform page opens on what someone holding the device needs: the folder,
the command, the pack, how to check. The words live in
``platforms/_guides.yml``, one guide per registered platform, beside the
device groups, the terminal tabs and the safety notes every guide shares.
This module loads that file, checks it against the registry and renders the
parts the pages share. The registry keeps the folder the pack unzips into
(``extract_to``) and the group a platform belongs to (``device_group``).
"""

from __future__ import annotations


from sitegen import markup
from model.guides import Guide, terminals, trust_items, install_command


# The title over each command block, by the shell it is written for.
FENCE_TITLES = {"sh": "Terminal", "powershell": "PowerShell"}


def fence(shell: str, command: str, indent: str = "") -> list[str]:
    """A command block with its title, as every command on the site is shown."""
    return [f'{indent}```{shell} title="{FENCE_TITLES[shell]}"', f"{indent}{command}", f"{indent}```"]


# Terminals named by where the command runs, not by the system it runs on.
PLACES = ("device", "server")


def terminal_tabs(
    tabs: tuple[str, ...], args: dict[str, str], indent: str = "", steps: bool = True,
    how: dict[str, str] | None = None,
    under_steps: dict[str, list[str]] | None = None,
    under_command: dict[str, list[str]] | None = None,
) -> list[str]:
    """Content tabs, one per place the command runs, each with how to open
    the terminal there. Tab labels are shared across the site, so the reader's
    choice carries from page to page. *how* replaces the shared text of a tab
    for one setup. *under_steps* and *under_command* add lines to a tab
    after its text and after its command (sitegen.steps.install_box)."""
    items = []
    for key in tabs:
        label, shared, shell = terminals()[key]
        if len(tabs) == 1 and key in PLACES:
            label = ""  # one place, which the text around already names
        text = (how or {}).get(key) or shared
        body = [text, ""] if steps else []
        body += (under_steps or {}).get(key, [])
        items.append((label, body + fence(shell, install_command(shell, args.get(key, "")))
                      + [""] + (under_command or {}).get(key, [])))
    return markup.tabs(items, indent)


def platform_args(name: str, guide: Guide) -> dict[str, str]:
    """The options of the command on a platform page, per tab."""
    args: dict[str, str] = {}
    for key in guide.run:
        if guide.on_card:
            card = "E:\\" if key == "windows" else "/path/to/card"
            args[key] = f"--platform {name} --dest {card}"
        elif guide.dest:
            args[key] = f"--platform {name} --dest {guide.dest}"
        else:
            args[key] = f"--platform {name}"
    return args


def trust_box(prefix: str, indent: str = "") -> list[str]:
    """Is it safe, under every command on a guide page: the trust items."""
    return markup.details("note", "Is it safe?", [
        *(f"- {item}" for item in trust_items()),
        "",
        f"[Read the script first]({prefix}wiki/faq.md#is-piping-the-installer-into-a-shell-safe)",
    ], indent)
