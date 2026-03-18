#!/usr/bin/env python3
"""Scraper for RetroDECK BIOS requirements.

Source: https://github.com/RetroDECK/components
Format: component_manifest.json committed at <component>/component_manifest.json
Hash:   MD5 primary, SHA256 for some entries (melonDS DSi BIOS)

RetroDECK verification logic:
- MD5 or SHA256 checked against expected value per file
- MD5 may be a list of multiple accepted hashes (xroar ROM variants) — joined
  as comma-separated string per retrobios convention
- Files may declare paths via $bios_path, $saves_path, or $roms_path tokens
- $saves_path entries (GameCube memory card directories) are excluded —
  these are directory placeholders, not BIOS files
- $roms_path entries are included with a roms/ prefix in destination,
  consistent with Batocera's saves/ destination convention
- Entries with no hash are emitted without an md5 field (existence-only),
  which is valid per the platform schema (e.g. pico-8 executables)

Component structure:
  RetroDECK/components (GitHub, main branch)
  ├── <component>/component_manifest.json   <- fetched directly via raw URL
  ├── archive_later/                         <- skipped
  └── archive_old/                           <- skipped

BIOS may appear in three locations within a manifest:
  - top-level 'bios' key  (melonDS, xemu, xroar, pico-8)
  - preset_actions.bios   (duckstation, dolphin, pcsx2, ppsspp)
  - cores.bios            (not yet seen in practice, kept for safety)

ppsspp quirk: preset_actions.bios is a bare dict, not a list.

Adding to watch.yml (maintainer step):
    from scraper.retrodeck_scraper import Scraper as RDS
    config = RDS().generate_platform_yaml()
    with open('platforms/retrodeck.yml', 'w') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f'RetroDECK: {len(config["systems"])} systems, version={config["version"]}')
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

try:
    from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
except ImportError:
    from base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version

PLATFORM_NAME = "retrodeck"

COMPONENTS_REPO   = "RetroDECK/components"
COMPONENTS_BRANCH = "main"
COMPONENTS_API_URL = (
    f"https://api.github.com/repos/{COMPONENTS_REPO}"
    f"/git/trees/{COMPONENTS_BRANCH}?recursive=0"
)
RAW_BASE_URL = (
    f"https://raw.githubusercontent.com/{COMPONENTS_REPO}"
    f"/{COMPONENTS_BRANCH}"
)

# Top-level directories to ignore when enumerating components
SKIP_DIRS = {"archive_later", "archive_old", "automation-tools", ".github"}

# Default local path for --manifests-dir (standard flatpak install)
DEFAULT_LOCAL_MANIFESTS = (
    "/var/lib/flatpak/app/net.retrodeck.retrodeck"
    "/current/active/files/retrodeck/components"
)

# RetroDECK system ID -> retrobios slug.
# IDs absent from this map pass through unchanged (maintainer decides on slug).
# IDs mapped to None are skipped entirely (no retrobios equivalent).
SYSTEM_SLUG_MAP: dict[str, str | None] = {
    # Nintendo
    "nes":           "nintendo-nes",
    "snes":          "nintendo-snes",
    "snesna":        "nintendo-snes",
    "n64":           "nintendo-64",
    "n64dd":         "nintendo-64dd",
    "gc":            "nintendo-gamecube",
    "wii":           "wii",            # no retrobios slug yet — passes through
    "wiiu":          "nintendo-wii-u",
    "switch":        "nintendo-switch",
    "gb":            "nintendo-gb",
    "gbc":           "nintendo-gbc",
    "gba":           "nintendo-gba",
    "nds":           "nintendo-ds",
    "3ds":           "nintendo-3ds",
    "n3ds":          "nintendo-3ds",   # azahar uses n3ds
    "fds":           "nintendo-fds",
    "sgb":           "nintendo-sgb",
    "virtualboy":    "nintendo-virtual-boy",
    # Sony
    "psx":           "sony-playstation",
    "ps2":           "sony-playstation-2",
    "ps3":           "sony-playstation-3",
    "psp":           "sony-psp",
    "psvita":        "sony-psvita",
    # Sega
    "megadrive":     "sega-mega-drive",
    "genesis":       "sega-mega-drive",
    "megacd":        "sega-mega-cd",
    "megacdjp":      "sega-mega-cd",
    "segacd":        "sega-mega-cd",
    "saturn":        "sega-saturn",
    "saturnjp":      "sega-saturn",
    "dreamcast":     "sega-dreamcast",
    "naomi":         "sega-dreamcast-arcade",
    "naomi2":        "sega-dreamcast-arcade",
    "atomiswave":    "sega-dreamcast-arcade",
    "sega32x":       "sega32x",
    "sega32xjp":     "sega32x",
    "sega32xna":     "sega32x",
    "gamegear":      "sega-game-gear",
    "mastersystem":  "sega-master-system",
    # NEC
    "tg16":          "nec-pc-engine",
    "tg-cd":         "nec-pc-engine",
    "pcengine":      "nec-pc-engine",
    "pcenginecd":    "nec-pc-engine",
    "pcfx":          "nec-pc-fx",
    # SNK
    "neogeo":        "snk-neogeo",
    "neogeocd":      "snk-neogeo-cd",
    "neogeocdjp":    "snk-neogeo-cd",
    # Atari
    "atari2600":     "atari2600",      # no retrobios slug yet — passes through
    "atari800":      "atari-400-800",
    "atari5200":     "atari-5200",
    "atari7800":     "atari-7800",
    "atarilynx":     "atari-lynx",
    "atarist":       "atari-st",
    "atarijaguar":   "jaguar",
    # Panasonic / Philips
    "3do":           "panasonic-3do",
    "cdimono1":      "cdi",
    "cdtv":          "amigacdtv",
    # Microsoft
    "xbox":          "xbox",
    # Commodore
    "amiga":         "commodore-amiga",
    "amigacd32":     "amigacd32",
    "c64":           "commodore-c64",
    # Tandy / Dragon
    "coco":          "trs80coco",
    "dragon32":      "dragon32",
    "tanodragon":    "dragon32",       # Tano Dragon is a Dragon 32 clone
    # Other
    "colecovision":  "coleco-colecovision",
    "intellivision": "mattel-intellivision",
    "o2em":          "magnavox-odyssey2",
    "msx":           "microsoft-msx",
    "msx2":          "microsoft-msx",
    "fmtowns":       "fmtowns",
    "scummvm":       "scummvm",
    "dos":           "dos",
    # Explicitly skipped — no retrobios equivalent
    "mess":          None,
}

# Matches all saves_path typo variants seen in the wild:
# $saves_path, $saves_paths_path, $saves_paths_paths_path, etc.
_SAVES_PATH_RE = re.compile(r"^\$saves_\w+/")


def _fetch_bytes(url: str, token: str | None = None) -> bytes:
    headers = {"User-Agent": "retrobios-scraper/1.0"}
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to fetch {url}: {e}") from e


def _fetch_json(url: str, token: str | None = None) -> dict | list:
    return json.loads(_fetch_bytes(url, token).decode("utf-8"))


def _resolve_destination(raw_path: str, filename: str) -> str | None:
    """Resolve a RetroDECK path token to a retrobios destination string.

    Returns None if the entry should be excluded ($saves_path variants).
    $bios_path -> strip prefix; destination is bios-relative.
    $roms_path -> preserve roms/ prefix (Batocera saves/ convention).
    Bare directory paths get filename appended.
    """
    if _SAVES_PATH_RE.match(raw_path):
        return None

    if raw_path.startswith("$bios_path/"):
        remainder = raw_path[len("$bios_path/"):].strip("/")
        if not remainder or remainder == filename:
            return filename
        # Subdirectory path — append filename if path looks like a directory
        if not remainder.endswith(tuple(".bin .rom .zip .img .bin ".split())):
            return remainder.rstrip("/") + "/" + filename
        return remainder

    if raw_path.startswith("$roms_path/"):
        remainder = raw_path[len("$roms_path/"):].strip("/")
        base = ("roms/" + remainder) if remainder else "roms"
        return base.rstrip("/") + "/" + filename

    # No recognised token — treat as bios-relative
    remainder = raw_path.strip("/")
    if not remainder:
        return filename
    return remainder.rstrip("/") + "/" + filename


def _normalise_md5(raw: str | list) -> str:
    """Return a comma-separated MD5 string.

    xroar declares a list of accepted hashes for ROM variants;
    retrobios platform schema accepts comma-separated MD5 strings.
    """
    if isinstance(raw, list):
        return ",".join(str(h).strip().lower() for h in raw if h)
    return str(raw).strip().lower() if raw else ""


def _coerce_bios_to_list(val: object) -> list:
    """Ensure a bios value is always a list of dicts.

    ppsspp declares preset_actions.bios as a bare dict, not a list.
    """
    if isinstance(val, list):
        return val
    if isinstance(val, dict):
        return [val]
    return []


def _parse_required(raw: object) -> bool:
    """Coerce RetroDECK required field to bool.

    Values seen: 'Required', 'Optional', 'At least one BIOS file required',
    'Optional, for boot logo', True, False, absent (None).
    Absent is treated as required.
    """
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return True
    return str(raw).strip().lower() not in ("optional", "false", "no", "0")


def _parse_manifest(data: dict) -> list[BiosRequirement]:
    """Parse one component_manifest.json into BiosRequirement objects."""
    requirements: list[BiosRequirement] = []
    seen: set[tuple[str, str]] = set()

    for _component_key, component_val in data.items():
        if not isinstance(component_val, dict):
            continue

        # Component-level system fallback (may be a list for multi-system components)
        comp_system = component_val.get("system", "")
        if isinstance(comp_system, list):
            comp_system = comp_system[0] if comp_system else ""
        comp_system = str(comp_system).strip().lower()

        # Collect bios entries from all known locations
        bios_sources: list[list] = []

        if "bios" in component_val:
            bios_sources.append(_coerce_bios_to_list(component_val["bios"]))

        pa = component_val.get("preset_actions", {})
        if isinstance(pa, dict) and "bios" in pa:
            bios_sources.append(_coerce_bios_to_list(pa["bios"]))

        cores = component_val.get("cores", {})
        if isinstance(cores, dict) and "bios" in cores:
            bios_sources.append(_coerce_bios_to_list(cores["bios"]))

        if not bios_sources:
            continue

        for bios_list in bios_sources:
            for entry in bios_list:
                if not isinstance(entry, dict):
                    continue

                filename = str(entry.get("filename", "")).strip()
                if not filename:
                    continue

                # System slug — entry-level preferred, component-level fallback
                entry_system = entry.get("system", comp_system)
                if isinstance(entry_system, list):
                    entry_system = entry_system[0] if entry_system else comp_system
                entry_system = str(entry_system).strip().lower()

                if entry_system in SYSTEM_SLUG_MAP:
                    slug = SYSTEM_SLUG_MAP[entry_system]
                    if slug is None:
                        continue  # explicitly skipped (e.g. mess)
                else:
                    slug = entry_system  # unknown — pass through

                # Destination resolution
                paths_raw = entry.get("paths")
                if paths_raw is None:
                    destination = filename
                elif isinstance(paths_raw, list):
                    destination = None
                    for p in paths_raw:
                        resolved = _resolve_destination(str(p), filename)
                        if resolved is not None:
                            destination = resolved
                            break
                    if destination is None:
                        continue  # all paths were saves_path variants — skip
                else:
                    destination = _resolve_destination(str(paths_raw), filename)
                    if destination is None:
                        continue  # saves_path — skip

                # Hash fields
                md5_val: str | None = None
                sha256_val: str | None = None

                raw_md5 = entry.get("md5")
                if raw_md5:
                    md5_val = _normalise_md5(raw_md5) or None

                raw_sha256 = entry.get("sha256")
                if raw_sha256:
                    sha256_val = str(raw_sha256).strip().lower() or None

                required = _parse_required(entry.get("required"))

                dedup_key = (slug, filename.lower())
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                req = BiosRequirement(
                    name=filename,
                    system=slug,
                    md5=md5_val,
                    sha1=None,
                    destination=destination,
                    required=required,
                )
                req._sha256 = sha256_val  # type: ignore[attr-defined]
                requirements.append(req)

    return requirements


class Scraper(BaseScraper):
    """Scraper for RetroDECK component_manifest.json files.

    Two modes:
      remote (default): fetches manifests directly from RetroDECK/components
                        via GitHub raw URLs, enumerating components via the
                        GitHub API tree endpoint
      local:            reads manifests from a directory on disk
                        (--manifests-dir or pass manifests_dir= to __init__)
    """

    def __init__(
        self,
        manifests_dir: str | None = None,
        github_token: str | None = None,
    ):
        super().__init__()
        self.manifests_dir = manifests_dir
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self._release_version: str | None = None

    # ── Remote ───────────────────────────────────────────────────────────────

    def _list_component_dirs(self) -> list[str]:
        """Return top-level component directory names from the GitHub API."""
        tree = _fetch_json(COMPONENTS_API_URL, self.github_token)
        return [
            item["path"]
            for item in tree.get("tree", [])
            if item["type"] == "tree" and item["path"] not in SKIP_DIRS
        ]

    def _fetch_remote_manifests(self) -> list[dict]:
        component_dirs = self._list_component_dirs()
        manifests: list[dict] = []
        for component in sorted(component_dirs):
            url = f"{RAW_BASE_URL}/{component}/component_manifest.json"
            print(f"  Fetching {component}/component_manifest.json ...", file=sys.stderr)
            try:
                raw = _fetch_bytes(url, self.github_token)
                manifests.append(json.loads(raw.decode("utf-8")))
            except ConnectionError:
                pass  # component has no manifest — skip silently
            except json.JSONDecodeError as e:
                print(f"    WARNING: parse error in {component}: {e}", file=sys.stderr)
        return manifests

    # ── Local ─────────────────────────────────────────────────────────────────

    def _fetch_local_manifests(self) -> list[dict]:
        root = Path(self.manifests_dir)
        if not root.is_dir():
            raise FileNotFoundError(f"Manifests directory not found: {root}")
        manifests: list[dict] = []
        # Only scan top-level component directories; skip archive and hidden dirs
        for component_dir in sorted(root.iterdir()):
            if not component_dir.is_dir():
                continue
            if component_dir.name in SKIP_DIRS or component_dir.name.startswith("."):
                continue
            manifest_path = component_dir / "component_manifest.json"
            if not manifest_path.exists():
                continue
            try:
                with open(manifest_path) as f:
                    manifests.append(json.load(f))
            except (json.JSONDecodeError, OSError) as e:
                print(f"  WARNING: Could not parse {manifest_path}: {e}", file=sys.stderr)
        return manifests

    # ── BaseScraper interface ─────────────────────────────────────────────────

    def fetch_requirements(self) -> list[BiosRequirement]:
        manifests = (
            self._fetch_local_manifests()
            if self.manifests_dir
            else self._fetch_remote_manifests()
        )

        requirements: list[BiosRequirement] = []
        seen: set[tuple[str, str]] = set()
        for manifest in manifests:
            for req in _parse_manifest(manifest):
                key = (req.system, req.name.lower())
                if key not in seen:
                    seen.add(key)
                    requirements.append(req)
        return requirements

    def validate_format(self, raw_data: str) -> bool:
        try:
            return isinstance(json.loads(raw_data), dict)
        except json.JSONDecodeError:
            return False

    def generate_platform_yaml(self) -> dict:
        requirements = self.fetch_requirements()

        systems: dict[str, dict] = {}
        for req in requirements:
            systems.setdefault(req.system, {"files": []})
            entry: dict = {
                "name":        req.name,
                "destination": req.destination,
                "required":    req.required,
            }
            if req.md5:
                entry["md5"] = req.md5
            sha256 = getattr(req, "_sha256", None)
            if sha256 and not req.md5:
                entry["sha256"] = sha256
            systems[req.system]["files"].append(entry)

        version = self._release_version or ""
        if not version:
            try:
                version = fetch_github_latest_version(COMPONENTS_REPO) or ""
            except (ConnectionError, OSError):
                pass

        return {
            "platform":          "RetroDECK",
            "version":           version,
            "homepage":          "https://retrodeck.net",
            "source":            f"https://github.com/{COMPONENTS_REPO}",
            "base_destination":  "bios",
            "hash_type":         "md5",
            "verification_mode": "md5",
            "systems":           systems,
        }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Scrape RetroDECK component_manifest.json BIOS requirements"
    )
    parser.add_argument(
        "--manifests-dir", metavar="DIR",
        help=(
            "Read manifests from a local directory instead of fetching from GitHub. "
            f"Live install path: {DEFAULT_LOCAL_MANIFESTS}"
        ),
    )
    parser.add_argument(
        "--token", metavar="TOKEN",
        help="GitHub personal access token (or set GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print per-system summary without generating output",
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write generated platform YAML to FILE",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print platform config as JSON (for debugging)",
    )
    args = parser.parse_args()

    scraper = Scraper(manifests_dir=args.manifests_dir, github_token=args.token)

    try:
        reqs = scraper.fetch_requirements()
    except (ConnectionError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        by_system: dict[str, list] = {}
        for r in reqs:
            by_system.setdefault(r.system, []).append(r)
        for system, files in sorted(by_system.items()):
            req_c = sum(1 for f in files if f.required)
            opt_c = len(files) - req_c
            print(f"  {system}: {req_c} required, {opt_c} optional")
        print(f"\nTotal: {len(reqs)} entries across {len(by_system)} systems")
        return

    config = scraper.generate_platform_yaml()

    if args.json:
        print(json.dumps(config, indent=2))
        return

    if args.output:
        try:
            import yaml
        except ImportError:
            print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
            sys.exit(1)

        def _str_representer(dumper, data):
            if any(c in data for c in "()[]{}:#"):
                return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
            return dumper.represent_scalar("tag:yaml.org,2002:str", data)
        yaml.add_representer(str, _str_representer)

        with open(args.output, "w") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        total = sum(len(s["files"]) for s in config["systems"].values())
        print(
            f"Written {total} entries across "
            f"{len(config['systems'])} systems to {args.output}"
        )
        return

    systems = len(set(r.system for r in reqs))
    print(f"Scraped {len(reqs)} entries across {systems} systems. Use --dry-run, --json, or --output FILE.")


if __name__ == "__main__":
    main()
