"""Scraper for Batocera per-board emulator availability.

Sources (batocera-linux/batocera.linux):
  - configs/batocera-*.board  -- board definitions, each sets BR2_PACKAGE_BATOCERA_TARGET_*
  - package/batocera/core/batocera-system/Config.in -- select PACKAGE if CONDITION lines
  - package/batocera/emulationstation/batocera-es-system/es_systems.yml
    -- emulator requireAnyOf flag mapping
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import yaml

from . import BaseTargetScraper

PLATFORM_NAME = "batocera"

GITHUB_API = "https://api.github.com/repos/batocera-linux/batocera.linux/contents"
RAW_BASE = "https://raw.githubusercontent.com/batocera-linux/batocera.linux/master"

CONFIG_IN_URL = f"{RAW_BASE}/package/batocera/core/batocera-system/Config.in"
ES_SYSTEMS_URL = (
    f"{RAW_BASE}/package/batocera/emulationstation/batocera-es-system/es_systems.yml"
)

_HEADERS = {
    "User-Agent": "retrobios-scraper/1.0",
    "Accept": "application/vnd.github.v3+json",
}

_TARGET_FLAG_RE = re.compile(r'^(BR2_PACKAGE_BATOCERA_TARGET_\w+)=y', re.MULTILINE)

# Matches: select BR2_PACKAGE_FOO  (optional: if CONDITION)
# Condition may span multiple lines (backslash continuation)
_SELECT_RE = re.compile(
    r'^\s+select\s+(BR2_PACKAGE_\w+)'   # package being selected
    r'(?:\s+if\s+((?:[^\n]|\\\n)+?))?'  # optional "if CONDITION" (may continue with \)
    r'(?:\s*#[^\n]*)?$',                # optional trailing comment
    re.MULTILINE,
)

# Meta-flag definition: "if COND\n\tconfig DERIVED_FLAG\n\t...\nendif"
_META_BLOCK_RE = re.compile(
    r'^if\s+((?:[^\n]|\\\n)+?)\n'       # condition (may span lines via \)
    r'(?:.*?\n)*?'                       # optional lines before the config
    r'\s+config\s+(BR2_PACKAGE_\w+)'    # derived flag name
    r'.*?^endif',                        # end of block
    re.MULTILINE | re.DOTALL,
)


def _fetch(url: str, headers: dict | None = None) -> str | None:
    h = headers or {"User-Agent": "retrobios-scraper/1.0"}
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"  skip {url}: {e}", file=sys.stderr)
        return None


def _fetch_json(url: str) -> list | dict | None:
    text = _fetch(url, headers=_HEADERS)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"  json parse error {url}: {e}", file=sys.stderr)
        return None


def _normalise_condition(raw: str) -> str:
    """Strip backslash-continuations and collapse whitespace."""
    return re.sub(r'\\\n\s*', ' ', raw).strip()


def _tokenise(condition: str) -> list[str]:
    """Split a Kconfig condition into tokens: flags, !, &&, ||, (, )."""
    token_re = re.compile(r'&&|\|\||!|\(|\)|BR2_\w+|"[^"]*"')
    return token_re.findall(condition)


def _check_condition(tokens: list[str], pos: int, active: frozenset[str]) -> tuple[bool, int]:
    """Recursive descent check of a Kconfig boolean expression."""
    return _check_or(tokens, pos, active)


def _check_or(tokens: list[str], pos: int, active: frozenset[str]) -> tuple[bool, int]:
    left, pos = _check_and(tokens, pos, active)
    while pos < len(tokens) and tokens[pos] == '||':
        pos += 1
        right, pos = _check_and(tokens, pos, active)
        left = left or right
    return left, pos


def _check_and(tokens: list[str], pos: int, active: frozenset[str]) -> tuple[bool, int]:
    left, pos = _check_not(tokens, pos, active)
    while pos < len(tokens) and tokens[pos] == '&&':
        pos += 1
        right, pos = _check_not(tokens, pos, active)
        left = left and right
    return left, pos


def _check_not(tokens: list[str], pos: int, active: frozenset[str]) -> tuple[bool, int]:
    if pos < len(tokens) and tokens[pos] == '!':
        pos += 1
        val, pos = _check_atom(tokens, pos, active)
        return not val, pos
    return _check_atom(tokens, pos, active)


def _check_atom(tokens: list[str], pos: int, active: frozenset[str]) -> tuple[bool, int]:
    if pos >= len(tokens):
        return True, pos
    tok = tokens[pos]
    if tok == '(':
        pos += 1
        val, pos = _check_or(tokens, pos, active)
        if pos < len(tokens) and tokens[pos] == ')':
            pos += 1
        return val, pos
    if tok.startswith('BR2_'):
        pos += 1
        return tok in active, pos
    if tok.startswith('"'):
        pos += 1
        return True, pos
    # Unknown token — treat as true to avoid false negatives
    pos += 1
    return True, pos


def _condition_holds(condition: str, active: frozenset[str]) -> bool:
    """Return True if a Kconfig boolean condition holds for the given active flags."""
    if not condition:
        return True
    norm = _normalise_condition(condition)
    tokens = _tokenise(norm)
    if not tokens:
        return True
    try:
        result, _ = _check_condition(tokens, 0, active)
        return result
    except Exception:
        return True  # conservative: include on parse failure


def _parse_meta_flags(text: str) -> list[tuple[str, str]]:
    """Return [(derived_flag, condition_str)] from top-level if/endif blocks.

    These define derived flags like BR2_PACKAGE_BATOCERA_TARGET_X86_64_ANY,
    BR2_PACKAGE_BATOCERA_GLES3, etc.
    """
    results: list[tuple[str, str]] = []
    for m in _META_BLOCK_RE.finditer(text):
        cond = _normalise_condition(m.group(1))
        flag = m.group(2)
        results.append((flag, cond))
    return results


def _expand_flags(primary_flag: str, meta_rules: list[tuple[str, str]]) -> frozenset[str]:
    """Given a board's primary flag, expand to all active derived flags.

    Iterates until stable (handles chained derivations like X86_64_ANY -> X86_ANY).
    """
    active: set[str] = {primary_flag}
    changed = True
    while changed:
        changed = False
        for derived, cond in meta_rules:
            if derived not in active and _condition_holds(cond, frozenset(active)):
                active.add(derived)
                changed = True
    return frozenset(active)


def _parse_selects(text: str) -> list[tuple[str, str]]:
    """Parse all 'select PACKAGE [if CONDITION]' lines from Config.in.

    Returns [(package, condition)] where condition is '' if unconditional.
    """
    results: list[tuple[str, str]] = []
    for m in _SELECT_RE.finditer(text):
        pkg = m.group(1)
        cond = _normalise_condition(m.group(2) or '')
        results.append((pkg, cond))
    return results


def _parse_es_systems(text: str) -> dict[str, list[str]]:
    """Parse es_systems.yml: map BR2_PACKAGE_* flag -> list of emulator names.

    The file is a dict keyed by system name. Each system has:
      emulators:
        <emulator_group>:
          <core_name>: {requireAnyOf: [BR2_PACKAGE_FOO]}
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}

    if not isinstance(data, dict):
        return {}

    package_to_emulators: dict[str, list[str]] = {}

    for _system_name, system_data in data.items():
        if not isinstance(system_data, dict):
            continue
        emulators = system_data.get("emulators")
        if not isinstance(emulators, dict):
            continue
        for _group_name, group_data in emulators.items():
            if not isinstance(group_data, dict):
                continue
            for core_name, core_data in group_data.items():
                if not isinstance(core_data, dict):
                    continue
                require = core_data.get("requireAnyOf", [])
                if not isinstance(require, list):
                    continue
                for pkg_flag in require:
                    if isinstance(pkg_flag, str):
                        package_to_emulators.setdefault(pkg_flag, []).append(core_name)

    return package_to_emulators


def _arch_from_flag(flag: str) -> str:
    """Guess architecture from board flag name."""
    low = flag.lower()
    if "x86_64" in low or "zen3" in low:
        return "x86_64"
    if "x86" in low:
        return "x86"
    return "aarch64"


class Scraper(BaseTargetScraper):
    """Cross-references Batocera boards, Config.in, and es_systems to build target lists."""

    def __init__(self, url: str = "https://github.com/batocera-linux/batocera.linux"):
        super().__init__(url=url)

    def _list_boards(self) -> list[str]:
        """List batocera-*.board files from configs/ via GitHub API."""
        data = _fetch_json(f"{GITHUB_API}/configs")
        if not data or not isinstance(data, list):
            return []
        return [
            item["name"] for item in data
            if isinstance(item, dict)
            and item.get("name", "").startswith("batocera-")
            and item.get("name", "").endswith(".board")
        ]

    def _fetch_board_flag(self, board_name: str) -> str | None:
        """Fetch a board file and extract its BR2_PACKAGE_BATOCERA_TARGET_* flag."""
        url = f"{RAW_BASE}/configs/{board_name}"
        text = _fetch(url)
        if text is None:
            return None
        m = _TARGET_FLAG_RE.search(text)
        return m.group(1) if m else None

    def fetch_targets(self) -> dict:
        """Build per-board emulator availability map."""
        print("  fetching board list...", file=sys.stderr)
        boards = self._list_boards()
        if not boards:
            print("  warning: no boards found", file=sys.stderr)

        print("  fetching Config.in...", file=sys.stderr)
        config_in_text = _fetch(CONFIG_IN_URL) or ""

        meta_rules = _parse_meta_flags(config_in_text)
        selects = _parse_selects(config_in_text)
        print(
            f"  parsed {len(meta_rules)} meta-flag rules, {len(selects)} select lines",
            file=sys.stderr,
        )

        print("  fetching es_systems.yml...", file=sys.stderr)
        es_text = _fetch(ES_SYSTEMS_URL) or ""
        package_to_emulators = _parse_es_systems(es_text)
        print(
            f"  parsed {len(package_to_emulators)} package->emulator mappings",
            file=sys.stderr,
        )

        targets: dict[str, dict] = {}
        for board_name in sorted(boards):
            target_key = board_name.removeprefix("batocera-").removesuffix(".board")
            print(f"  processing {target_key}...", file=sys.stderr)
            primary_flag = self._fetch_board_flag(board_name)
            if primary_flag is None:
                print(f"    no target flag found in {board_name}", file=sys.stderr)
                continue

            active = _expand_flags(primary_flag, meta_rules)

            # Determine which packages are selected for this board
            selected_packages: set[str] = set()
            for pkg, cond in selects:
                if _condition_holds(cond, active):
                    selected_packages.add(pkg)

            # Map selected packages to emulator names via es_systems.yml
            emulators: set[str] = set()
            for pkg in selected_packages:
                for emu in package_to_emulators.get(pkg, []):
                    emulators.add(emu)

            arch = _arch_from_flag(primary_flag)
            targets[target_key] = {
                "architecture": arch,
                "cores": sorted(emulators),
            }
            print(
                f"    {len(emulators)} emulators ({len(selected_packages)} packages selected)",
                file=sys.stderr,
            )

        return {
            "platform": "batocera",
            "source": self.url,
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape Batocera per-board emulator targets"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = Scraper()
    data = scraper.fetch_targets()

    if args.dry_run:
        for name, info in data["targets"].items():
            print(f"  {name} ({info['architecture']}): {len(info['cores'])} emulators")
        return

    if args.output:
        scraper.write_output(data, args.output)
        print(f"Written to {args.output}")
        return

    print(yaml.dump(data, default_flow_style=False, sort_keys=False))


if __name__ == "__main__":
    main()
