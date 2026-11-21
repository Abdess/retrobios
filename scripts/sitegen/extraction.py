"""Where each platform's pack extracts, and the packs that carry their own root folder."""

from __future__ import annotations

from model.declarations import declared_root
from model.platforms import load_platform_config
from model.registry import load_platform_registry
from sitegen.install import display_name, platform_display


def extract_targets(platforms_dir: str) -> list[tuple[str, str]]:
    """(display name, folder) per registered platform, where its pack extracts.

    Read from the registry so the README, the site and the pack guide answer
    from one place. Sorted by display name.
    """
    rows = [
        (platform_display(key, platforms_dir), entry["extract_to"])
        for key, entry in load_platform_registry(platforms_dir).items()
        if entry.get("extract_to")
    ]
    return sorted(rows, key=lambda row: row[0].casefold())


def own_root(config: dict) -> str:
    """The folder a pack written from an empty base_destination starts with.

    RetroDECK writes bios/ in front of its files, the MinUI family hands its
    cores folders below Bios/.
    """
    root = declared_root(config)
    if root:
        return root
    tops = {directory.split("/", 1)[0] for directory in config.get("core_system_dirs") or {}}
    return tops.pop() if len(tops) == 1 else "bios"


def extract_notes(platforms_dir: str, released_only: bool = False) -> list[str]:
    """A pack whose entries carry their own root extracts above the BIOS folder.

    *released_only* keeps the platforms a release publishes a pack for.
    """
    folders = dict(extract_targets(platforms_dir))
    registry = load_platform_registry(platforms_dir)
    notes = []
    for key in sorted(registry):
        if released_only and registry[key].get("release_pack") is not True:
            continue
        config = load_platform_config(key, platforms_dir)
        display = display_name(config, key)
        if config.get("base_destination") == "" and display in folders:
            notes.append(
                f"The {display} pack holds its own `{own_root(config)}/` folder."
                f" Unzip it into `{folders[display]}`."
            )
    return notes
