#!/usr/bin/env python3
"""Universal BIOS installer for retrogaming platforms.

Self-contained script using only Python stdlib. Downloads missing BIOS files
from the retrobios repository and places them in the correct location for
the detected emulator platform.

Usage:
    python install.py
    python install.py --platform retroarch --dest ~/custom/bios
    python install.py --check
    python install.py --list-platforms
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE_URL = os.environ.get(
    "RETROBIOS_BASE_URL",
    "https://raw.githubusercontent.com/Abdess/retrobios/main",
)
MANIFEST_URL = f"{BASE_URL}/install/{{platform}}.json"
TARGETS_URL = f"{BASE_URL}/install/targets/{{platform}}.json"
RAW_FILE_URL = f"{BASE_URL}/{{path}}"
RELEASE_URL = (
    "https://github.com/Abdess/retrobios/releases/download/large-files/{asset}"
)
MAX_RETRIES = 3


def detect_os() -> str:
    """Return normalized OS identifier."""
    system = platform.system().lower()
    if system == "linux":
        proc_version = Path("/proc/version")
        if proc_version.exists():
            try:
                content = proc_version.read_text(encoding="utf-8", errors="replace")
                if "microsoft" in content.lower():
                    return "wsl"
            except OSError:
                pass
        return "linux"
    if system == "darwin":
        return "darwin"
    if system == "windows":
        return "windows"
    return system


def _parse_os_release() -> dict[str, str]:
    """Parse /etc/os-release KEY=value format."""
    result: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return result
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if "=" not in line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            value = value.strip('"').strip("'")
            result[key] = value
    except OSError:
        pass
    return result


def _parse_retroarch_system_dir(cfg_path: Path) -> Path | None:
    """Parse system_directory from retroarch.cfg."""
    if not cfg_path.exists():
        return None
    try:
        for line in cfg_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("system_directory"):
                _, _, value = line.partition("=")
                value = value.strip().strip('"').strip("'")
                if not value or value == "default":
                    return cfg_path.parent / "system"
                value = os.path.expandvars(os.path.expanduser(value))
                return Path(value)
    except OSError:
        pass
    return None


def _parse_bash_var(path: Path, key: str) -> str | None:
    """Extract value of key= from a bash/shell file."""
    if not path.exists():
        return None
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith(f"{key}="):
                _, _, value = line.partition("=")
                return value.strip('"').strip("'")
    except OSError:
        pass
    return None


def _parse_ps1_var(path: Path, key: str) -> str | None:
    """Extract value of $key= or key= from a PowerShell file."""
    if not path.exists():
        return None
    normalized = key.lstrip("$")
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            check = line.lstrip("$")
            if check.startswith(f"{normalized}="):
                _, _, value = check.partition("=")
                return value.strip('"').strip("'")
    except OSError:
        pass
    return None


def _detect_embedded() -> list[tuple[str, Path]]:
    """Check for embedded Linux retrogaming OSes."""
    found: list[tuple[str, Path]] = []
    os_release = _parse_os_release()
    os_id = os_release.get("ID", "").lower()

    if os_id == "rocknix":
        found.append(("retroarch", Path("/storage/roms/bios")))
        return found

    if Path("/etc/knulli-release").exists():
        found.append(("batocera", Path("/userdata/bios")))
        return found

    if os_id == "lakka":
        found.append(("lakka", Path("/storage/system")))
        return found

    if Path("/etc/batocera-version").exists():
        found.append(("batocera", Path("/userdata/bios")))
        return found

    if Path("/usr/bin/recalbox-settings").exists():
        found.append(("recalbox", Path("/recalbox/share/bios")))
        return found

    if Path("/opt/muos").exists() or Path("/mnt/mmc/MUOS/").exists():
        found.append(("retroarch", Path("/mnt/mmc/MUOS/bios")))
        return found

    if Path("/home/ark").exists() and Path("/opt/system").exists():
        found.append(("retroarch", Path("/roms/bios")))
        return found

    if Path("/mnt/vendor/bin/dmenu.bin").exists():
        found.append(("retroarch", Path("/mnt/mmc/bios")))
        return found

    return found


def detect_platforms(os_type: str) -> list[tuple[str, Path]]:
    """Detect installed emulator platforms and their BIOS directories."""
    found: list[tuple[str, Path]] = []

    if os_type in ("linux", "wsl"):
        found.extend(_detect_embedded())

        # EmuDeck (Linux/SteamOS)
        home = Path.home()
        emudeck_settings = home / ".config" / "EmuDeck" / "settings.sh"
        if emudeck_settings.exists():
            emu_path = _parse_bash_var(emudeck_settings, "emulationPath")
            if emu_path:
                bios_dir = Path(emu_path) / "bios"
                found.append(("emudeck", bios_dir))

        # RetroDECK
        retrodeck_cfg = home / ".var" / "app" / "net.retrodeck.retrodeck" / "config" / "retrodeck" / "retrodeck.cfg"
        if retrodeck_cfg.exists():
            bios_path = _parse_bash_var(retrodeck_cfg, "rdhome")
            if bios_path:
                found.append(("retrodeck", Path(bios_path) / "bios"))
            else:
                found.append(("retrodeck", home / "retrodeck" / "bios"))

        # RetroArch Flatpak
        flatpak_cfg = home / ".var" / "app" / "org.libretro.RetroArch" / "config" / "retroarch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(flatpak_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

        # RetroArch Snap
        snap_cfg = home / "snap" / "retroarch" / "current" / ".config" / "retroarch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(snap_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

        # RetroArch native
        native_cfg = home / ".config" / "retroarch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(native_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

    if os_type == "darwin":
        home = Path.home()
        mac_cfg = home / "Library" / "Application Support" / "RetroArch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(mac_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

    if os_type in ("windows", "wsl"):
        # EmuDeck Windows
        home = Path.home()
        emudeck_ps1 = Path(os.environ.get("APPDATA", "")) / "EmuDeck" / "settings.ps1"
        if emudeck_ps1.exists():
            emu_path = _parse_ps1_var(emudeck_ps1, "$emulationPath")
            if emu_path:
                found.append(("emudeck", Path(emu_path) / "bios"))

        # RetroArch Windows
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            win_cfg = Path(appdata) / "RetroArch" / "retroarch.cfg"
            ra_dir = _parse_retroarch_system_dir(win_cfg)
            if ra_dir:
                found.append(("retroarch", ra_dir))

    return found


def fetch_manifest(plat: str) -> dict:
    """Download platform manifest JSON."""
    url = MANIFEST_URL.format(platform=plat)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        print(f"  Failed to fetch manifest for {plat}: {exc}", file=sys.stderr)
        sys.exit(1)


def fetch_targets(plat: str) -> dict:
    """Download target core list. Returns empty dict on 404."""
    url = TARGETS_URL.format(platform=plat)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        print(f"  Warning: failed to fetch targets for {plat}: {exc}", file=sys.stderr)
        return {}
    except (urllib.error.URLError, OSError):
        return {}


def _filter_by_target(
    files: list[dict], target_cores: list[str]
) -> list[dict]:
    """Keep files where cores is None or overlaps with target_cores."""
    result: list[dict] = []
    target_set = set(target_cores)
    for f in files:
        cores = f.get("cores")
        if cores is None or any(c in target_set for c in cores):
            result.append(f)
    return result


def _sha1_file(path: Path) -> str:
    """Compute SHA1 of a file."""
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def check_local(
    files: list[dict], bios_path: Path
) -> tuple[list[dict], list[dict], list[dict]]:
    """Check which files exist locally and have correct hashes.

    Returns (to_download, up_to_date, mismatched).
    """
    to_download: list[dict] = []
    up_to_date: list[dict] = []
    mismatched: list[dict] = []

    for f in files:
        dest = bios_path / f["dest"]
        if not dest.exists():
            to_download.append(f)
            continue
        expected_sha1 = f.get("sha1", "")
        if not expected_sha1:
            up_to_date.append(f)
            continue
        actual = _sha1_file(dest)
        if actual == expected_sha1:
            up_to_date.append(f)
        else:
            mismatched.append(f)

    return to_download, up_to_date, mismatched


def _download_one(
    f: dict, bios_path: Path, verbose: bool = False
) -> tuple[str, bool]:
    """Download a single file. Returns (dest, success)."""
    dest = bios_path / f["dest"]
    dest.parent.mkdir(parents=True, exist_ok=True)

    if f.get("release_asset"):
        url = RELEASE_URL.format(asset=urllib.parse.quote(f["release_asset"], safe="/"))
    else:
        url = RAW_FILE_URL.format(path=urllib.parse.quote(f["repo_path"], safe="/"))

    tmp_path = dest.with_suffix(dest.suffix + ".tmp")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                with open(tmp_path, "wb") as out:
                    shutil.copyfileobj(resp, out)

            expected_sha1 = f.get("sha1", "")
            if expected_sha1:
                actual = _sha1_file(tmp_path)
                if actual != expected_sha1:
                    if verbose:
                        print(f"    SHA1 mismatch on attempt {attempt}", file=sys.stderr)
                    tmp_path.unlink(missing_ok=True)
                    continue

            tmp_path.rename(dest)
            return f["dest"], True

        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            if verbose:
                print(f"    Attempt {attempt} failed: {exc}", file=sys.stderr)
            tmp_path.unlink(missing_ok=True)

    return f["dest"], False


def download_files(
    files: list[dict], bios_path: Path, jobs: int = 8, verbose: bool = False
) -> list[str]:
    """Download files in parallel. Returns list of failed file names."""
    failed: list[str] = []
    total = len(files)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        future_map = {
            pool.submit(_download_one, f, bios_path, verbose): f
            for f in files
        }
        done_count = 0
        for future in concurrent.futures.as_completed(future_map):
            done_count += 1
            dest, success = future.result()
            status = "ok" if success else "FAILED"
            print(f"  [{done_count}/{total}] {dest} {status}")
            if not success:
                failed.append(dest)

    return failed


def do_standalone_copies(
    manifest: dict, bios_path: Path, os_type: str
) -> tuple[int, int]:
    """Copy BIOS files to standalone emulator directories.

    Returns (copied_count, skipped_count).
    """
    copies = manifest.get("standalone_copies", [])
    if not copies:
        return 0, 0

    copied = 0
    skipped = 0

    for entry in copies:
        src = bios_path / entry["file"]
        if not src.exists():
            continue
        targets = entry.get("targets", {}).get(os_type, [])
        for target_dir_str in targets:
            target_dir = Path(os.path.expandvars(os.path.expanduser(target_dir_str)))
            if target_dir.is_dir():
                dest = target_dir / src.name
                try:
                    shutil.copy2(src, dest)
                    copied += 1
                except OSError:
                    skipped += 1
            else:
                skipped += 1

    return copied, skipped


def format_size(n: int) -> str:
    """Human-readable file size."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


def _prompt_platform_choice(
    platforms: list[tuple[str, Path]],
) -> list[tuple[str, Path]]:
    """Prompt user to choose among detected platforms."""
    print("\nInstall for:")
    for i, (name, path) in enumerate(platforms, 1):
        print(f"  {i}) {name.capitalize()} ({path})")
    if len(platforms) > 1:
        print(f"  {len(platforms) + 1}) All")
    print()

    while True:
        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not choice:
            continue
        try:
            idx = int(choice)
        except ValueError:
            continue
        if 1 <= idx <= len(platforms):
            return [platforms[idx - 1]]
        if idx == len(platforms) + 1 and len(platforms) > 1:
            return platforms

    return platforms


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Download missing BIOS files for retrogaming emulators.",
    )
    parser.add_argument(
        "--platform",
        help="target platform (retroarch, batocera, emudeck, ...)",
    )
    parser.add_argument(
        "--dest",
        type=Path,
        help="override BIOS destination directory",
    )
    parser.add_argument(
        "--target",
        help="hardware target for core filtering (switch, rpi4, ...)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="check existing files without downloading",
    )
    parser.add_argument(
        "--list-platforms",
        action="store_true",
        help="list detected platforms and exit",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="list available targets for a platform and exit",
    )
    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=8,
        help="parallel download threads (default: 8)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="verbose output",
    )

    args = parser.parse_args()
    print("RetroBIOS\n")

    os_type = detect_os()

    # Early exit for listing
    if args.list_platforms:
        available = [
            "retroarch", "batocera", "recalbox", "retrobat",
            "emudeck", "lakka", "retrodeck", "romm", "bizhawk",
        ]
        print("Available platforms:")
        for p in available:
            print(f"  {p}")
        detected = detect_platforms(os_type)
        if detected:
            print("\nDetected on this system:")
            for name, path in detected:
                print(f"  {name}: {path}")
        return

    # Platform detection or override
    if args.platform and args.dest:
        platforms = [(args.platform, args.dest)]
    elif args.platform:
        print("Detecting platform...")
        detected = detect_platforms(os_type)
        matched = [(n, p) for n, p in detected if n == args.platform]
        if matched:
            platforms = matched
        else:
            print(f"  Platform '{args.platform}' not detected, using default path.")
            platforms = [(args.platform, Path.home() / "bios")]
    elif args.dest:
        print(f"  Using destination: {args.dest}")
        platforms = [("retroarch", args.dest)]
    else:
        print("Detecting platform...")
        platforms = detect_platforms(os_type)
        if not platforms:
            print("  No supported platform detected.")
            print("  Use --platform and --dest to specify manually.")
            sys.exit(1)
        for name, path in platforms:
            print(f"  Found {name.capitalize()} at {path}")

    if len(platforms) > 1 and not args.list_targets and sys.stdin.isatty():
        platforms = _prompt_platform_choice(platforms)

    total_downloaded = 0
    total_up_to_date = 0
    total_errors = 0

    for plat_name, bios_path in platforms:
        print(f"\nFetching file index for {plat_name}...")
        manifest = fetch_manifest(plat_name)
        files = manifest.get("files", [])

        if args.list_targets:
            targets = fetch_targets(plat_name)
            if not targets:
                print(f"  No targets available for {plat_name}")
            else:
                for t in sorted(targets.keys()):
                    cores = targets[t].get("cores", [])
                    print(f"  {t} ({len(cores)} cores)")
            continue

        # Target filtering
        if args.target:
            targets = fetch_targets(plat_name)
            target_info = targets.get(args.target)
            if not target_info:
                print(f"  Warning: target '{args.target}' not found for {plat_name}")
            else:
                target_cores = target_info.get("cores", [])
                before = len(files)
                files = _filter_by_target(files, target_cores)
                print(f"  Filtered {before} -> {len(files)} files for target {args.target}")

        total_size = sum(f.get("size", 0) for f in files)
        print(f"  {len(files)} files ({format_size(total_size)})")

        print("\nChecking existing files...")
        to_download, up_to_date, mismatched = check_local(files, bios_path)
        present = len(up_to_date) + len(mismatched)
        print(
            f"  {present}/{len(files)} present "
            f"({len(up_to_date)} verified, {len(mismatched)} wrong hash)"
        )

        # Mismatched files need re-download
        to_download.extend(mismatched)

        if args.check:
            if to_download:
                print(f"\n  {len(to_download)} files need downloading.")
            else:
                print("\n  All files up to date.")
            continue

        if to_download:
            dl_size = sum(f.get("size", 0) for f in to_download)
            print(f"\nDownloading {len(to_download)} files ({format_size(dl_size)})...")
            bios_path.mkdir(parents=True, exist_ok=True)
            failed = download_files(
                to_download, bios_path, jobs=args.jobs, verbose=args.verbose
            )
            total_downloaded += len(to_download) - len(failed)
            total_errors += len(failed)
        else:
            print("\n  All files up to date.")

        total_up_to_date += len(up_to_date)

        # Standalone copies
        if manifest.get("standalone_copies") and not args.check:
            print("\nStandalone emulators:")
            copied, skipped = do_standalone_copies(manifest, bios_path, os_type)
            if copied or skipped:
                print(f"  {copied} copied, {skipped} skipped (dir not found)")

    if not args.check and not args.list_targets:
        print(
            f"\nDone. {total_downloaded} downloaded, "
            f"{total_up_to_date} up to date, {total_errors} errors."
        )


if __name__ == "__main__":
    main()
