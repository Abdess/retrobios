"""The systems a pack covers, with the titles a person reads."""

from __future__ import annotations

from collections.abc import Iterable


def platform_list_version(config: dict, platform: str) -> str:
    """The version of the list a platform's YAML transcribes: the release
    tag the scraper read, or for a list kept on a branch with no release,
    the date of the commit it pinned. load_platform_config never passes a
    parent's version to a child, Lakka is not RetroArch v1.22.2.

    The installer compares it with the version a machine runs, so a missing
    value is refused rather than written as a stand-in.
    """
    version = str(config.get("version") or "").strip()
    if not version:
        raise ValueError(
            f"{platform}: the platform YAML records no version of its own"
        )
    return version


def system_titles(*entry_lists: Iterable[dict]) -> dict[str, str]:
    """The name a person reads for each system the entries carry.

    Batocera names PlayStation `psx` and the installer showed
    `sony-playstation (psx)`: neither is what a beginner looks for. The
    title is the one the site prints, so a system reads the same on its
    page and in the installer. A system the site cannot name is left out,
    and the installer shows its id: the site build refuses such a system,
    so only a test fixture reaches here with one.
    """
    from model.systemnames import system_name

    ids = {
        sys_id
        for entries in entry_lists for entry in entries
        for sys_id in entry.get("systems") or []
    }
    titles: dict[str, str] = {}
    for sys_id in sorted(ids):
        try:
            titles[sys_id] = system_name(sys_id)
        except KeyError:
            continue
    return titles


def pack_systems(install_manifest: dict, targets: dict | None = None) -> dict:
    """What a pack's manifest.json records of its systems, from the install
    list built with the same choices: each file's systems, by its path in
    the pack, and the names a person reads for them.

    A pack recorded none: the installer refused --system with a pack alone
    ("the file list comes from an older release") and offered no Choose
    systems, the route of a handheld without Wi-Fi.

    The install list itself and the platform's cores per board (targets, as
    install/targets/ publishes them) ride along: with the pack alone, a
    board was never applied and --target was refused, and a Batocera RPi4
    card took 8.9 GB where its board reads 5.8.
    """
    files = install_manifest.get("files", [])
    entries = [*files, *install_manifest.get("omitted_files", [])]
    # What the install list narrows by, the installer's recorded_axes: with
    # the pack alone it names that list as the way to --core and --region
    # only when the list records them. It named install/misterfpga.json for
    # --core, a list that records no core.
    records = {"systems"} if any("systems" in entry for entry in entries) else set()
    if any(copy.get("cores") for entry in files
           for copy in [entry, *entry.get("alternatives", []),
                        *entry.get("slot_choices", [])]):
        records.add("cores")
    if records or any("regions" in entry for entry in entries):
        records.add("regions")
    systems = {
        "files": {entry["dest"]: list(entry.get("systems") or [])
                  for entry in files if "systems" in entry},
        "system_titles": dict(install_manifest.get("system_titles") or {}),
        "system_names": dict(install_manifest.get("system_names") or {}),
        "list_records": sorted(records),
    }
    # The version of the platform's list, which the installer compares with
    # the one the machine runs when it has the pack alone.
    if install_manifest.get("version"):
        systems["list_version"] = install_manifest["version"]
    systems["install_list"] = install_manifest
    if targets is not None:
        systems["targets"] = targets
    return systems


def annotate_pack_systems(manifest: dict, systems: dict | None) -> None:
    """Write pack_systems into a pack's manifest: a systems list on each
    file the install list names, the titles and names beside."""
    if not systems:
        return
    for entry in manifest.get("files", []):
        held = systems["files"].get(entry["path"])
        if held is not None:
            entry["systems"] = held
    for key in ("system_titles", "system_names"):
        if systems.get(key):
            manifest[key] = systems[key]
    for key in ("list_records", "list_version", "install_list", "targets"):
        if key in systems:
            manifest[key] = systems[key]
