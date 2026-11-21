"""Install manifest invariants: counts, destinations and the standalone layouts."""

from __future__ import annotations

import json
from pathlib import Path

import core.paths


def semantic_install_checks(path: Path, manifest: dict) -> list[str]:
    out: list[str] = []
    files = manifest.get("files", [])
    if manifest.get("total_files") != len(files):
        out.append(f"{path.relative_to(core.paths.REPO_ROOT)}: total_files does not equal len(files)")
    if manifest.get("total_size") != sum(entry.get("size", 0) for entry in files):
        out.append(f"{path.relative_to(core.paths.REPO_ROOT)}: total_size does not equal the file-size sum")
    omitted = manifest.get("omitted_files", [])
    if manifest.get("total_omitted") != len(omitted):
        out.append(
            f"{path.relative_to(core.paths.REPO_ROOT)}: total_omitted does not equal "
            "len(omitted_files)"
        )
    # One dest below the BIOS folder and one below the save directory are
    # two places.
    destinations = [(entry.get("root"), entry.get("dest")) for entry in files]
    if len(destinations) != len(set(destinations)):
        out.append(f"{path.relative_to(core.paths.REPO_ROOT)}: duplicate destinations")
    # root: emulator is each core's own folder: mame2015 and mame2016 read
    # 3dobios.zip in two places, one omission each, named by its cores.
    omitted_destinations = [
        (entry.get("root"), entry.get("dest"),
         tuple(entry.get("cores") or ()) if entry.get("root") == "emulator" else ())
        for entry in omitted
    ]
    if len(omitted_destinations) != len(set(omitted_destinations)):
        out.append(f"{path.relative_to(core.paths.REPO_ROOT)}: duplicate omitted destinations")
    overlap = set(destinations) & set(omitted_destinations)
    if overlap:
        out.append(
            f"{path.relative_to(core.paths.REPO_ROOT)}: destinations are both downloadable and omitted"
        )
    saved = [
        entry for entry in [*files, *manifest.get("case_variants", [])]
        if entry.get("root") == "save"
    ]
    layout = manifest.get("save_directory")
    if saved and not layout:
        out.append(
            f"{path.relative_to(core.paths.REPO_ROOT)}: entries read below the save directory "
            "and no save_directory"
        )
    builds = core.paths.REPO_ROOT / "install" / "standalone" / path.name
    if manifest.get("standalone_builds") and path.parent == core.paths.REPO_ROOT / "install" \
            and not builds.is_file():
        out.append(f"{path.relative_to(core.paths.REPO_ROOT)}: standalone_builds and no "
                   f"install/standalone/{path.name}")
    stray = sorted(
        entry["dest"] for entry in [*files, *omitted]
        if entry.get("core_folder") and entry.get("root") != "save"
    )
    if stray:
        out.append(
            f"{path.relative_to(core.paths.REPO_ROOT)}: core_folder outside root: save ({stray[0]})"
        )
    return out


def semantic_standalone_checks(path: Path, layouts: object) -> list[str]:
    """A standalone layout file goes with its platform's list: the list
    names the same builds, and each [dest, sha1] item takes its download
    from a copy of that list."""
    where = path.relative_to(core.paths.REPO_ROOT)
    if not isinstance(layouts, dict):
        return [f"{where}: not an object"]
    plat = layouts.get("platform")
    if path.stem != plat:
        return [f"{where}: platform {plat} in a file named {path.stem}"]
    listed = core.paths.REPO_ROOT / "install" / f"{plat}.json"
    if not listed.is_file():
        return [f"{where}: no install/{plat}.json beside it"]
    manifest = json.loads(listed.read_text(encoding="utf-8"))
    out: list[str] = []
    if sorted(layouts.get("standalone_layouts", {})) != manifest.get("standalone_builds"):
        out.append(f"{where}: its builds differ from standalone_builds in {listed.name}")
    held = {
        copy.get("sha1")
        for entry in [*manifest.get("files", []), *(manifest.get("truth_files") or [])]
        for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]
    }
    missing = sorted({
        item[1] for items in layouts.get("standalone_layouts", {}).values()
        for item in items if isinstance(item, list) and item[1] not in held
    })
    if missing:
        out.append(f"{where}: {len(missing)} sha1 no copy of {listed.name} carries "
                   f"({missing[0]})")
    return out
