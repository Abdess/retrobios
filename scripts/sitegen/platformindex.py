"""The platforms index and the setup table."""

from __future__ import annotations

from model import releaserecord
from model.guides import DEVICE_GROUPS, GROUP_TILES, GUIDES
from resolve.nativemode import check_label
from sitegen import markup
from sitegen.guidepage import NO_ZIP_FAQ
from sitegen.home import group_members
from sitegen.install import has_release_pack
from sitegen.readme import release_totals


# Platform pages


def generate_platform_index(coverages: dict, registry: dict | None = None) -> str:
    """The Setups tab: every platform by the device it runs on, and one
    line to the table that sets them side by side (setup_table), which is
    reference matter and sits with how each setup checks its files."""
    registry = registry or {}
    lines = [
        "# Setups",
        "",
        "Each setup's page gives the folder and the command.",
        "",
    ]
    for group, (label, _description) in DEVICE_GROUPS.items():
        members = group_members(coverages, registry, group)
        if not members:
            continue
        # The group label names the devices, and each card carries its
        # setup's own sentence. The kinds of device that run a setup
        # follow, as on the home tiles.
        lines += [f"## {label}", ""]
        lines += markup.card_grid([
            *((f"[{coverages[name]['platform']}]({name}.md)", [GUIDES[name].summary])
              for name in members),
            *((f"[{tile.name}](../{tile.link})", [tile.text])
              for tile in GROUP_TILES.get(group, ())),
        ])
    lines += [
        f"Comparing setups? [Every setup side by side](../{SETUP_TABLE_LINK})",
        "",
    ]
    return "\n".join(lines) + "\n"


# Where the side-by-side table of setups is published: with how each setup
# checks its files, the column a reader compares.
SETUP_TABLE_PAGE = "wiki/verification-modes.md"
SETUP_TABLE_ANCHOR = "every-setup-at-a-glance"
SETUP_TABLE_LINK = f"{SETUP_TABLE_PAGE}#{SETUP_TABLE_ANCHOR}"


def setup_table(coverages: dict) -> list[str]:
    """Every setup side by side: the files on its own list, the files in its
    ZIP, and how it checks them. Written under the Reference level, on the
    page that explains each way of checking."""
    lines = [
        f"## Every setup at a glance {{ #{SETUP_TABLE_ANCHOR} }}",
        "",
        "| Setup | Files on its own list | Files in the ZIP | How it checks |",
        "|-------|------:|------:|---------------|",
    ]
    for name, cov in sorted(coverages.items(), key=lambda item: item[1]["platform"].casefold()):
        listed = f"{cov['total']:,}" if cov["total"] else "No list of its own"
        files, _size = release_totals(name, releaserecord.load_advertised())
        zipped = (f"{files:,}" if files
                  else "No ZIP yet" if has_release_pack(name) else "No ZIP")
        lines.append(
            f"| [{cov['platform']}](../platforms/{name}.md) | {listed} | {zipped} | "
            f"{check_label(cov['mode'], cov['config'].get('hash_rule'))} |"
        )
    lines += [
        "",
        "The ZIP adds the files its emulators load to the files on the setup's own list.",
        "",
    ]
    lines += ["No ZIP: the setup is served by the command alone. "
              f"[Why?](../{NO_ZIP_FAQ})", ""]
    return lines


def with_setup_table(page: str, coverages: dict) -> str:
    """The comparison table placed before the Next steps of its page, or at
    its end."""
    table = "\n".join(setup_table(coverages))
    marker = "\n## Next steps"
    if marker in page:
        head, tail = page.split(marker, 1)
        return f"{head.rstrip()}\n\n{table}{marker}{tail}"
    return f"{page.rstrip()}\n\n{table}"
