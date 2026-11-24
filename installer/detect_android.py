"""RetroArch builds found on Android, and the app folders Android keeps out of reach."""
from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path

from installer.config_values import _parse_retroarch_system_dir, _retroarch_cfg_value
from installer.host_fs import _SETUP_SEARCH, _exists, _is_dir


# The three RetroArch packages published for Android, newest ABI first.
ANDROID_RETROARCH_PACKAGES = (
    "com.retroarch.aarch64",
    "com.retroarch",
    "com.retroarch.ra32",
)
# Where Android keeps each app's private data.
ANDROID_APP_DATA = Path("/data/data")


def _android_storage_root() -> Path:
    """Shared storage root, the parent RetroArch builds its defaults from."""
    value = os.environ.get("EXTERNAL_STORAGE", "").strip()
    return Path(value) if value else Path("/storage/emulated/0")


# Where each RetroArch package keeps its folders, RetroArch v1.22.2
# (pkg/android/phoenix/build.gradle:46-95). com.retroarch and
# com.retroarch.aarch64 are each published twice under one id: by
# retroarch.com (normal, aarch64) and on Google Play (playStoreNormal,
# playStorePlus). com.retroarch.ra32 has no Google Play flavor. The Google
# Play build hands RetroArch Android/data/<package>/files as the storage its
# defaults are built from, the other builds the shared storage root
# (MainMenuActivity.java:182-183).
_ANDROID_RETROARCH_PLAY_IDS = ("com.retroarch", "com.retroarch.aarch64")
# A Google Play versionCode is the manifest's 1597175267 (AndroidManifest.xml:5)
# plus one per half week since 1609632000 (build.gradle:76, 87, 168-175), so
# it stays below that start time. The other flavors use the build time in
# seconds (build.gradle:42), above it for every build since 2021. The launcher
# writes the code to retroarch.cfg (UserPreferences.java:150), which
# RetroArch keeps (configuration.c:2623).
_ANDROID_PLAY_VERSION_CEILING = 1609632000


@contextlib.contextmanager
def _refusals_expected() -> Iterator[None]:
    """Probes whose refusal is the answer, not a folder to report: another
    app's private data on Android, which any app may test for existence and
    none may enter, has a line of its own (android_unreachable_folders)."""
    outer = getattr(_SETUP_SEARCH, "active", False)
    _SETUP_SEARCH.active = False
    try:
        yield
    finally:
        _SETUP_SEARCH.active = outer


def _android_play_build(package: str, storage: Path, cfgs: tuple[Path, ...]) -> bool | None:
    """True for the Google Play build of this package, False for the
    retroarch.com one, None when nothing it wrote tells them apart.

    The version code in its config decides. Without a readable config, the
    folder each build writes does: the Google Play build never asks for
    shared storage (MainMenuActivity.java:199-202), and only it builds its
    defaults under Android/data/<package>/files/RetroArch.
    """
    if package not in _ANDROID_RETROARCH_PLAY_IDS:
        return False
    for cfg in cfgs:
        code = _retroarch_cfg_value(cfg, "bundle_assets_extract_version_current")
        if code and code.isdigit() and int(code) > 0:
            return int(code) < _ANDROID_PLAY_VERSION_CEILING
    if _is_dir(storage / "Android" / "data" / package / "files" / "RetroArch"):
        return True
    if _is_dir(storage / "RetroArch"):
        return False
    return None


def _android_writable(folder: Path) -> bool:
    """Whether this shell can create folder: its nearest existing parent is
    writable. Android 11 and later keep Android/data/<package> of other apps
    from Termux."""
    for parent in (folder, *folder.parents):
        if _exists(parent):
            return _is_dir(parent) and os.access(parent, os.W_OK)
    return False


def _android_out_of_reach(name: str, folder: Path, what: str) -> str:
    """The line said for an emulator whose BIOS folder this shell cannot write."""
    return (f"{name} is installed, but this shell cannot write its BIOS folder "
            f"{folder} without root: {what} are not copied there.")


@_refusals_expected()
def _android_retroarch_builds() -> list[tuple[Path | None, str]]:
    """Each installed RetroArch build: its system folder when this shell can
    write it, else None and the line that says why.

    RetroArch v1.22.2: the launcher picks retroarch.cfg in the app external
    files directory, else in the internal one
    (pkg/android/phoenix-common/src/com/retroarch/browser/preferences/util/
    UserPreferences.java:36-89), and passes it as CONFIGFILE
    (MainMenuActivity.java:178, read at frontend/drivers/platform_unix.c:
    1428-1444). A system_directory left at default resolves against
    <storage>/RetroArch/system (platform_unix.c:1670-1697), storage being
    what the launcher passes as SDCARD: Android/data/<package>/files for the
    Google Play build, the shared storage root for the others.
    """
    storage = _android_storage_root()
    builds: list[tuple[Path | None, str]] = []
    for package in ANDROID_RETROARCH_PACKAGES:
        external = storage / "Android" / "data" / package / "files"
        if not _exists(ANDROID_APP_DATA / package) and not _exists(external):
            continue
        cfgs = (external / "retroarch.cfg",
                ANDROID_APP_DATA / package / "files" / "retroarch.cfg")
        play = _android_play_build(package, storage, cfgs)
        play_root, shared_root = external / "RetroArch", storage / "RetroArch"
        named = next(filter(None, (_retroarch_cfg_value(cfg, "system_directory")
                                   for cfg in cfgs)), "default")
        if play is None and named == "default":
            builds.append((None,
                f"RetroArch ({package}) is installed, but nothing it has written tells "
                f"which build it is: the Google Play build reads {play_root / 'system'}, "
                f"the retroarch.com build reads {shared_root / 'system'}. "
                "Name the folder with --dest."))
            continue
        root = play_root if play else shared_root
        folder = next(filter(None, (_parse_retroarch_system_dir(cfg, root) for cfg in cfgs)),
                      root / "system")
        private = (storage / "Android" / "data", ANDROID_APP_DATA)
        if any(folder == base or base in folder.parents for base in private) \
                and not _android_writable(folder):
            build = "Google Play build" if play else "retroarch.com build"
            builds.append((None, _android_out_of_reach(
                f"RetroArch ({build}, {package})", folder, "BIOS files")))
            continue
        builds.append((folder, ""))
    return builds


def _detect_android() -> list[tuple[str, Path]]:
    """Find the RetroArch system directory of each installed build on
    Android, as _android_retroarch_builds() resolves it (RetroArch v1.22.2,
    platform_unix.c:1670-1697).

    With no package seen, <shared storage>/RetroArch is the folder of a
    retroarch.com build whose private data this shell cannot see.
    """
    found: list[tuple[str, Path]] = []
    builds = _android_retroarch_builds()
    for folder, _line in builds:
        if folder is not None and ("retroarch", folder) not in found:
            found.append(("retroarch", folder))
    default_root = _android_storage_root() / "RetroArch"
    if not builds and _exists(default_root):
        found.append(("retroarch", default_root / "system"))
    return found


# Android emulators that keep their BIOS outside RetroArch's folder:
# (name, package, folder, files read there). DraStic keeps it in its private
# data (GammaOS Next 14 bb28e71d, gammaos/setup.sh:345-363 extracts it to
# /data/data/com.dsemu.drastic/files/DraStic/system), which no other app
# writes without root. Flycast reads <home>/data/ (flycast a9bd1c74,
# shell/android-studio/flycast/src/main/jni/src/Android.cpp:143-159), its
# home being Android/data/com.flycast.emulator/files, which Android 11 and
# later keep from other apps.
_ANDROID_APP_FOLDERS = (
    ("DraStic", "com.dsemu.drastic", "/data/data/com.dsemu.drastic/files/DraStic/system",
     ("nds_bios_arm7.bin", "nds_bios_arm9.bin", "nds_firmware.bin")),
    ("Flycast", "com.flycast.emulator",
     "$STORAGE/Android/data/com.flycast.emulator/files/data",
     ("dc_boot.bin", "dc_nvmem.bin")),
)


@_refusals_expected()
def android_unreachable_folders() -> list[str]:
    """A line for each Android emulator installed here whose BIOS folder
    this shell cannot write, said instead of skipping it in silence. A
    RetroArch build whose folder is out of reach, or whose build cannot be
    told, is among them.

    An app's private folder can be tested for existence by any app, so the
    emulator is known to be installed even where its folder is out of reach.
    """
    lines = [line for folder, line in _android_retroarch_builds() if folder is None]
    storage = str(_android_storage_root())
    for name, package, folder, files in _ANDROID_APP_FOLDERS:
        target = Path(folder.replace("$STORAGE", storage, 1))
        if folder.startswith("/data/data/"):
            target = ANDROID_APP_DATA / Path(folder).relative_to("/data/data")
        if not _exists(ANDROID_APP_DATA / package) and not _exists(target):
            continue
        if _is_dir(target) and os.access(target, os.W_OK):
            continue
        lines.append(_android_out_of_reach(name, target, ", ".join(files)))
    return lines
