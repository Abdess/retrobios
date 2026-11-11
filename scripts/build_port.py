#!/usr/bin/env python3
"""Build the handheld launchers in ports/ into their archives.

    RetroBIOS.zip            the PortMaster port (ports/RetroBIOS)
    RetroBIOS-batocera.zip   Batocera and Knulli, from Ports (ports/batocera)
    RetroBIOS.muxapp         muOS, from Applications (ports/muos)
    RetroBIOS-tools.zip      the Tools menu of ArkOS, dArkOS, ROCKNIX, JELOS
                             and AmberELEC (ports/tools)

Each carries ports/shared (tui.txt, which runs the full-screen interface,
rbevents.py and the controller mapping) beside its own launcher. The
PortMaster archive has the layout PortMaster's own release build gives a port
(PortMaster-New tools/build_release.py): the launch script at the top, and
one folder holding port.json, gameinfo.xml, the README as <name>.md, the
licenses and the port's files. A muOS application archive is extracted into
the applications folder, so its top folder is the application.

install.py is copied from the repository root, and only when it is the
installer the bootstraps pin, so every launcher runs the same bytes as the
one-line command of the same commit. The site builds them at each deploy
and serves them under get/handheld/ (scripts/sitehandheld.py): they are no
release files, and are written to tmp/handheld/ by default, away from the
packs of dist/. Members are written as the packs write
theirs: fixed timestamps, sorted names, the executable bit read from the
source, so the same tree gives the same archives.

Usage:
    python scripts/build_port.py
    python scripts/build_port.py --output-dir tmp/port   # default: tmp/handheld
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import zipfile
from pathlib import Path

from artifacts import ArtifactLockBusy, artifact_lock

REPO_ROOT = Path(__file__).resolve().parent.parent
PORT_DIR = "retrobios"
PORT_SCRIPT = "RetroBIOS.sh"
PORT_ZIP = "RetroBIOS.zip"
BATOCERA_ZIP = "RetroBIOS-batocera.zip"
MUOS_APP = "RetroBIOS.muxapp"
TOOLS_ZIP = "RetroBIOS-tools.zip"
# Every launcher archive the site serves.
ARCHIVES = (PORT_ZIP, BATOCERA_ZIP, MUOS_APP, TOOLS_ZIP)
# Which release pack serves each platform, read by tui.txt offline.
PACKS_TABLE = "packs.txt"
_PIN = re.compile(r'^DEFAULT_INSTALL_SHA256="([0-9a-f]{64})"$', re.MULTILINE)


def pinned_installer_sha256(root: Path = REPO_ROOT) -> str:
    """The SHA-256 install.sh accepts for install.py."""
    found = _PIN.search((root / "install.sh").read_text(encoding="utf-8"))
    if found is None:
        raise ValueError("install.sh pins no installer SHA-256")
    return found.group(1)


def _engine(folder: str, root: Path, mapping: bool = True) -> list[tuple[str, Path | None]]:
    """What every launcher runs: the installer, the interface launcher, the
    event reader, the licenses, and the gptokeyb mapping where one is read."""
    shared = root / "ports" / "shared"
    members = [
        (f"{folder}/install.py", root / "install.py"),
        (f"{folder}/tui.txt", shared / "tui.txt"),
        (f"{folder}/rbevents.py", shared / "rbevents.py"),
        (f"{folder}/licenses/LICENSE-retrobios.txt", root / "LICENSE"),
        (f"{folder}/licenses/NOTICE-retrobios.txt", root / "NOTICE"),
        # Written by build_archive from the registry.
        (f"{folder}/{PACKS_TABLE}", None),
    ]
    if mapping:
        members.append((f"{folder}/retrobios.gptk", shared / "retrobios.gptk"))
    return members


def archive_members(name: str, root: Path = REPO_ROOT) -> list[tuple[str, Path | None]]:
    """(name in the archive, source file) for every member of *name*, sorted.
    The source is None for the packs table build_archive writes."""
    ports = root / "ports"
    if name == PORT_ZIP:
        source = ports / "RetroBIOS"
        members = [
            (PORT_SCRIPT, source / PORT_SCRIPT),
            (f"{PORT_DIR}/port.json", source / "port.json"),
            (f"{PORT_DIR}/gameinfo.xml", source / "gameinfo.xml"),
            (f"{PORT_DIR}/{PORT_DIR}.md", source / "README.md"),
            *_engine(PORT_DIR, root),
        ]
        members += [
            (f"{PORT_DIR}/{path.relative_to(source / PORT_DIR).as_posix()}", path)
            for path in sorted((source / PORT_DIR).rglob("*"))
            if path.is_file() and "__pycache__" not in path.parts
        ]
    elif name == BATOCERA_ZIP:
        source = ports / "batocera"
        members = [
            (PORT_SCRIPT, source / PORT_SCRIPT),
            (f"{PORT_SCRIPT}.keys", source / f"{PORT_SCRIPT}.keys"),
            (f"{PORT_DIR}/README.md", source / "README.md"),
            # evmapy reads RetroBIOS.sh.keys: no gptokeyb there.
            *_engine(PORT_DIR, root, mapping=False),
        ]
    elif name == MUOS_APP:
        source = ports / "muos"
        members = [
            ("RetroBIOS/mux_launch.sh", source / "mux_launch.sh"),
            ("RetroBIOS/README.md", source / "README.md"),
            # muOS draws an application's list glyph from glyph/<ICON>.png
            # in its own folder (apply_app_glyph, frontend common/ui/glyph.c):
            # `# ICON: retrobios` resolved to nothing without it.
            ("RetroBIOS/glyph/retrobios.png", source / "glyph" / "retrobios.png"),
            *_engine("RetroBIOS", root),
        ]
    elif name == TOOLS_ZIP:
        source = ports / "tools"
        members = [
            (PORT_SCRIPT, source / PORT_SCRIPT),
            (f"{PORT_DIR}/README.md", source / "README.md"),
            *_engine(PORT_DIR, root),
        ]
    else:
        raise ValueError(f"no launcher archive is named {name}")
    names = [member for member, _path in members]
    if len(set(names)) != len(names):
        raise ValueError(f"two members of {name} share a name")
    return sorted(members)


def release_pack_labels(root: Path = REPO_ROOT) -> dict[str, str]:
    """Platform -> the platform part of the release pack that serves it.

    Only the platforms the registry marks release_pack have a pack, grouped
    as the release builds them (pipeline.py). install.py
    refuses a pack whose name does not spell the platform, so a platform
    outside these groups has no pack to copy, whatever its file list.
    """
    from common import (  # noqa: PLC0415
        group_identical_platforms,
        list_release_pack_platforms,
        load_platform_config,
    )
    from generate_pack import _name_part, _platform_pack_stem  # noqa: PLC0415

    platforms_dir = str(root / "platforms")
    pool = list_release_pack_platforms(platforms_dir)
    labels: dict[str, str] = {}
    for group, representative in group_identical_platforms(pool, platforms_dir):
        stem = _platform_pack_stem(group, representative, platforms_dir)
        config = load_platform_config(representative, platforms_dir)
        version = config.get("version", config.get("dat_version", ""))
        tag = f"_{_name_part(str(version))}" if version else ""
        label = stem[: -len(tag)] if tag and stem.endswith(tag) else stem
        for platform in group:
            labels[platform] = label
    return dict(sorted(labels.items()))


def _packs_table(root: Path) -> bytes:
    return "".join(f"{platform}\t{label}\n"
                   for platform, label in release_pack_labels(root).items()).encode()


def build_archive(name: str, output: Path, root: Path = REPO_ROOT) -> Path:
    """Write the launcher archive *name* to *output* and return it."""
    pinned = pinned_installer_sha256(root)
    actual = hashlib.sha256((root / "install.py").read_bytes()).hexdigest()
    if actual != pinned:
        raise ValueError(
            f"install.py is {actual[:12]}, install.sh pins {pinned[:12]}: "
            "re-pin the bootstraps before building the launchers"
        )
    # The packs' member writer: imported here, as it loads the whole
    # pack builder, which a caller reading ARCHIVES does not need.
    from generate_pack import _add_pack_member  # noqa: PLC0415

    members = archive_members(name, root)
    output.parent.mkdir(parents=True, exist_ok=True)
    scratch = output.with_name(f".{output.name}.tmp")
    table = output.with_name(f".{output.name}.{PACKS_TABLE}")
    table.write_bytes(_packs_table(root))
    try:
        with zipfile.ZipFile(scratch, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for member, path in members:
                _add_pack_member(zf, str(path or table), member)
    finally:
        table.unlink()
    scratch.replace(output)
    return output


def build_port(output: Path, root: Path = REPO_ROOT) -> Path:
    """Write the PortMaster port archive to *output* and return it."""
    return build_archive(PORT_ZIP, output, root)


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False, description="Build the RetroBIOS handheld launchers"
    )
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "tmp" / "handheld",
                        help="where the archives are written (default: tmp/handheld/)")
    args = parser.parse_args()
    try:
        with artifact_lock(str(args.output_dir)):
            paths = [build_archive(name, args.output_dir / name) for name in ARCHIVES]
    except (ArtifactLockBusy, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"{path} ({path.stat().st_size} bytes, sha256 {digest})")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
