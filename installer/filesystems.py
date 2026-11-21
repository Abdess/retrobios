"""What a destination's file system allows: case, the names FAT refuses, file sizes, media scans."""
from __future__ import annotations

import errno
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from installer.host_fs import _exists, _is_dir
from installer.paths import shown_path
from installer.terminal import _kernel32


def keeps_case(directory: Path) -> bool:
    """Whether names differing only by case are distinct files there.

    Probed on the nearest existing directory, since the filesystem decides,
    not the operating system: an ext4 drive mounted on macOS keeps case and
    a casefolded ext4 directory folds it. Unprobeable: the system's default.
    """
    probe_dir = directory
    while not _is_dir(probe_dir) and probe_dir != probe_dir.parent:
        probe_dir = probe_dir.parent
    try:
        handle, name = tempfile.mkstemp(prefix=".retrobios-case-", dir=str(probe_dir))
    except OSError:
        return sys.platform not in ("win32", "darwin")
    os.close(handle)
    try:
        twin = os.path.join(os.path.dirname(name), os.path.basename(name).upper())
        return not os.path.exists(twin)
    finally:
        os.unlink(name)


def fold_case_twins(files: list[dict]) -> tuple[list[dict], list[str]]:
    """One file per name where the directory folds case, the others named.

    The first in manifest order stays, as the pack's own order places it.
    """
    kept: list[dict] = []
    seen: set[str] = set()
    folded: list[str] = []
    for entry in files:
        key = str(entry.get("dest", "")).casefold()
        if key in seen:
            folded.append(str(entry.get("dest", "")))
            continue
        seen.add(key)
        kept.append(entry)
    return kept, folded


# The characters FAT and exFAT refuse in a name, as Windows does on any drive
# (Linux 7475ea8b, fs/fat/namei_vfat.c:201-207 and fs/exfat/nls.c:396-403;
# "Naming Files, Paths, and Namespaces" in the Win32 documentation). The
# slash, the backslash and the controls never reach a destination
# (_safe_relative_path). RetroDECK names three files zxs:48.rom,
# zxs:if1-2.rom and snes:st018.data.rom (its retroarch component manifest):
# on an exFAT card each write failed, on every run.
FAT_REFUSED = re.compile(r'[<>:"|?*]')
FAT_REFUSED_SHOWN = '< > : " | ? *'


def holds_fat_refused_names(directory: Path) -> bool:
    """Whether a name holding a colon can be created there.

    Probed on the nearest existing directory, as keeps_case is: an ext4
    card on a Steam Deck holds one, an exFAT card refuses it with EINVAL.
    Windows refuses it on every drive. A probe refused for another cause
    (a folder this user cannot write) decides nothing.
    """
    if os.name == "nt":
        return False
    probe_dir = directory
    while not _is_dir(probe_dir) and probe_dir != probe_dir.parent:
        probe_dir = probe_dir.parent
    try:
        handle, name = tempfile.mkstemp(prefix=".retrobios-name-", suffix=":",
                                        dir=str(probe_dir))
    except OSError as exc:
        return exc.errno != errno.EINVAL
    os.close(handle)
    os.unlink(name)
    return True


def split_fat_refused(files: list[dict]) -> tuple[list[dict], list[str]]:
    """The entries whose destination a FAT, exFAT or Windows folder can
    hold, and the destinations it cannot."""
    kept = [entry for entry in files if not FAT_REFUSED.search(str(entry.get("dest", "")))]
    refused = [str(entry.get("dest", "")) for entry in files
               if FAT_REFUSED.search(str(entry.get("dest", "")))]
    return kept, refused


# Android's media scanner marks a folder holding a .nomedia file hidden, and
# every folder below it (MediaProvider a183e2b9, FileUtils.java:1587-1629
# isDirectoryHidden, ModernMediaScanner.java:845-846 and 1017-1020). Without
# one, the samples, overlays and videos of a BIOS folder in shared storage
# showed in the phone's gallery and music apps. RetroArch writes none
# (libretro-common/file/file_path_io.c:194 only skips one).
NOMEDIA = ".nomedia"


def hide_from_media_scanner(folder: Path) -> bool:
    """Leave an empty .nomedia in folder, True when this call wrote it."""
    marker = folder / NOMEDIA
    if not _is_dir(folder) or _exists(marker):
        return False
    try:
        marker.touch()
    except OSError as exc:
        print(f"  {NOMEDIA} not written in {shown_path(folder)}: {exc.strerror}",
              file=sys.stderr)
        return False
    return True


def read_mountinfo() -> str | None:
    """/proc/self/mountinfo, None where it cannot be read."""
    try:
        return Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def mount_point(field: str) -> str:
    """Field 5 of a mountinfo line, its space, tab, newline and backslash
    written as octal escapes (proc(5))."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def mountinfo_types(text: str) -> list[tuple[str, str]]:
    """(mount point, file system type) of each line of /proc/self/mountinfo:
    the point is field 5, its space, tab and backslash written as octal
    escapes, the type the first field after the " - " separator (proc(5))."""
    mounts = []
    for line in text.splitlines():
        head, _sep, tail = line.partition(" - ")
        fields = head.split(" ")
        if len(fields) > 4 and tail:
            point = mount_point(fields[4])
            mounts.append((point, tail.split(" ")[0]))
    return mounts


def mount_list_types(text: str) -> list[tuple[str, str]]:
    """(mount point, file system type) of each line macOS's mount prints:
    "/dev/disk4s1 on /Volumes/CARD (msdos, local, nodev)"."""
    return [(found[1], found[2]) for found in
            (re.match(r".+? on (.+) \(([^,)]+)", line) for line in text.splitlines())
            if found]


def fat_mounted(target: Path, mounts: list[tuple[str, str]]) -> bool:
    """Whether the deepest mount holding target is FAT (vfat on Linux,
    msdos on macOS)."""
    best = ""
    kind = ""
    for point, fstype in mounts:
        mount = Path(point)
        if (target == mount or mount in target.parents) and len(point) >= len(best):
            best, kind = point, fstype
    return kind.lower() in ("vfat", "msdos", "fat")


def fat32_drive(folder: Path) -> bool:
    """Whether folder is on a FAT32 (or FAT16) drive, which holds no file of
    4 GiB: the mount table's type on Linux, the volume's file system on
    Windows, the mount list on macOS. False where the system does not say."""
    probe = folder
    while not _is_dir(probe) and probe != probe.parent:
        probe = probe.parent
    if os.name == "nt":
        try:
            import ctypes
            root = ctypes.create_unicode_buffer(261)
            kind = ctypes.create_unicode_buffer(261)
            kernel = _kernel32()
            if not kernel.GetVolumePathNameW(str(probe), root, 261):
                return False
            if not kernel.GetVolumeInformationW(root, None, 0, None, None, None, kind, 261):
                return False
        except (AttributeError, OSError):
            return False
        return kind.value.upper() in ("FAT32", "FAT")
    try:
        target = probe.resolve()
        if sys.platform == "darwin":
            listing = subprocess.run(["/sbin/mount"], capture_output=True, text=True,
                                     timeout=5, check=False).stdout
            return fat_mounted(target, mount_list_types(listing))
        text = read_mountinfo()
    except (OSError, subprocess.SubprocessError):
        return False
    return text is not None and fat_mounted(target, mountinfo_types(text))
