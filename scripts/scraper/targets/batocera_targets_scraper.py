"""Scraper for Batocera per-board emulator availability.

Sources (batocera-linux/batocera.linux):
  - configs/batocera-*.board  -- board definitions, each sets BR2_PACKAGE_BATOCERA_TARGET_*
  - package/batocera/core/batocera-system/Config.in -- select PACKAGE if CONDITION lines
  - Config.in and every Kconfig file it sources -- the selects a package
    declares itself (advanced_drastic selects drastic)
  - package/batocera/emulationstation/batocera-es-system/es_systems.yml
    -- emulator requireAnyOf flag mapping
Sources (batocera-linux/buildroot, at the submodule commit the tag pins):
  - arch/Config.in, package/mesa3d/Config.in, package/libglvnd/Config.in
    -- the symbols Batocera's conditions test but Buildroot sets
    (BR2_ARCH_IS_64, BR2_PACKAGE_HAS_LIBGL)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

import yaml

from safeparse import yaml_load_upstream

from . import BaseTargetScraper

PLATFORM_NAME = "batocera"

try:
    from ..base_scraper import github_headers
except ImportError:
    from scraper.base_scraper import github_headers

_TARGET_FLAG_RE = re.compile(r"^(BR2_PACKAGE_BATOCERA_TARGET_\w+)=y", re.MULTILINE)

# The images a target flag builds, each a board directory whose last segment
# post-image-script.sh writes to boot/<system>.board on the card
# (batocera-43.1 board/batocera/scripts/post-image-script.sh:50,60, KNULLI
# 20260511 board/scripts/post-image-script.sh:57,66): Config.in lists them
# under BR2_TARGET_<SYSTEM>_IMAGES, one "default" per target flag.
_IMAGES_DEFAULT_RE = re.compile(
    r'^\s*default\s+"([^"]*)"\s+if\s+(BR2_PACKAGE_BATOCERA_TARGET_\w+)\s*$')


def _parse_images(text: str) -> dict[str, list[str]]:
    """Each target flag's image names, in the words a card's board file uses."""
    lines = text.replace("\\\n", " ").splitlines()
    start = next((n for n, line in enumerate(lines)
                  if re.match(r"^\s*config\s+BR2_TARGET_[A-Z]+_IMAGES\s*$", line)), None)
    if start is None:
        return {}
    images: dict[str, list[str]] = {}
    for line in lines[start + 1:]:
        if not line.strip():
            continue
        m = _IMAGES_DEFAULT_RE.match(line)
        if m:
            images.setdefault(m.group(2), []).extend(
                path.rsplit("/", 1)[-1] for path in m.group(1).split())
        elif not re.match(r"^\s*(string|default|help)\b", line):
            break
    return images


_IF_RE = re.compile(r"^if\s+(.*)$")
_DEFAULT_Y_RE = re.compile(r"^\s*default\s+y\s*(?:#.*)?$")


def _fetch(url: str, headers: dict | None = None) -> str:
    h = headers or {"User-Agent": "retrobios-scraper/1.0"}
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        raise RuntimeError(f"cannot fetch {url}: {e}") from e


def _fetch_present(url: str) -> str | None:
    """A file's text, or None when the server answers that it does not exist."""
    try:
        return _fetch(url)
    except RuntimeError as e:
        if isinstance(e.__cause__, urllib.error.HTTPError) and e.__cause__.code == 404:
            return None
        raise


def _fetch_json(url: str) -> list | dict:
    text = _fetch(url, headers=github_headers())
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"cannot parse {url}: {e}") from e


def _normalise_condition(raw: str) -> str:
    """Strip backslash-continuations and collapse whitespace."""
    return re.sub(r"\\\n\s*", " ", raw).strip()


def _tokenise(condition: str) -> list[str]:
    """Split a Kconfig condition into tokens: flags, !, &&, ||, (, )."""
    token_re = re.compile(r'&&|\|\||!|\(|\)|BR2_\w+|"[^"]*"')
    return token_re.findall(condition)


def _check_condition(
    tokens: list[str], pos: int, active: frozenset[str]
) -> tuple[bool, int]:
    """Recursive descent check of a Kconfig boolean expression."""
    return _check_or(tokens, pos, active)


def _check_or(tokens: list[str], pos: int, active: frozenset[str]) -> tuple[bool, int]:
    left, pos = _check_and(tokens, pos, active)
    while pos < len(tokens) and tokens[pos] == "||":
        pos += 1
        right, pos = _check_and(tokens, pos, active)
        left = left or right
    return left, pos


def _check_and(tokens: list[str], pos: int, active: frozenset[str]) -> tuple[bool, int]:
    left, pos = _check_not(tokens, pos, active)
    while pos < len(tokens) and tokens[pos] == "&&":
        pos += 1
        right, pos = _check_not(tokens, pos, active)
        left = left and right
    return left, pos


def _check_not(tokens: list[str], pos: int, active: frozenset[str]) -> tuple[bool, int]:
    if pos < len(tokens) and tokens[pos] == "!":
        pos += 1
        val, pos = _check_atom(tokens, pos, active)
        return not val, pos
    return _check_atom(tokens, pos, active)


def _check_atom(
    tokens: list[str], pos: int, active: frozenset[str]
) -> tuple[bool, int]:
    if pos >= len(tokens):
        return True, pos
    tok = tokens[pos]
    if tok == "(":
        pos += 1
        val, pos = _check_or(tokens, pos, active)
        if pos < len(tokens) and tokens[pos] == ")":
            pos += 1
        return val, pos
    if tok.startswith("BR2_"):
        pos += 1
        return tok in active, pos
    if tok.startswith('"'):
        pos += 1
        return True, pos
    # Unknown token: treat as true to avoid false negatives
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
    except (IndexError, ValueError, TypeError):
        return True  # conservative: include on parse failure


def _parse_meta_flags(text: str) -> list[tuple[str, str]]:
    """Return [(derived_flag, condition_str)] from top-level if/endif blocks.

    These define derived flags like BR2_PACKAGE_BATOCERA_TARGET_X86_64_ANY,
    BR2_PACKAGE_BATOCERA_GLES3, etc.: a config inside `if COND` that
    defaults to y is on exactly when COND holds. Read line by line: a
    condition continued with a backslash keeps its later lines, and a block
    whose config is not a package (KNULLI's BR2_KERNEL_LEGACY_3_10) cannot
    reach into the next one.
    """
    results: list[tuple[str, str]] = []
    condition: str | None = None
    config: str | None = None
    for line in re.sub(r"\\\n", " ", text).splitlines():
        start = _IF_RE.match(line)
        if start:
            condition, config = _normalise_condition(start.group(1)), None
            continue
        if condition is None:
            continue
        if line.startswith("endif"):
            condition = config = None
            continue
        found = _CONFIG_LINE_RE.match(line)
        if found:
            config = found.group(1)
        elif config and _DEFAULT_Y_RE.match(line):
            results.append((config, condition))
    return results


# Buildroot files whose selects decide symbols Batocera's Config.in tests:
# the architecture's 64-bit flag and the OpenGL provider. Without them xroar
# ("select BR2_PACKAGE_XROAR if BR2_PACKAGE_HAS_LIBGL") reached no board.
BUILDROOT_KCONFIG = (
    "arch/Config.in",
    # Each armv7-A CPU selects BR2_ARM_CPU_ARMV7A (cortex_a15_a7 included).
    "arch/Config.in.arm",
    "package/mesa3d/Config.in",
    "package/libglvnd/Config.in",
)

_CONFIG_LINE_RE = re.compile(r"^\s*(?:menu)?config\s+(BR2_\w+)")
_SOURCE_RE = re.compile(r'^\s*source\s+"\$BR2_EXTERNAL_\w+_PATH/([^"]+)"')
_OWNED_SELECT_RE = re.compile(r"^\s+select\s+(BR2_\w+)(?:\s+if\s+([^#]+))?")
_BOARD_FLAG_RE = re.compile(r"^(BR2_\w+)=y\s*$", re.MULTILINE)
_BOARD_INCLUDE_RE = re.compile(r"^(-?)include\s+(\S+)", re.MULTILINE)


def _parse_owned_selects(text: str) -> list[tuple[str, str, str]]:
    """Return [(owner, selected, condition)] for every select in a Kconfig.

    A select fires only when the config it sits under is on: Batocera's
    XORG7 comes from BATOCERA_XORG, which BATOCERA_SYSTEM turns on for x86_64
    alone. Reading every select as unconditional put X11 on the Raspberry Pi.
    """
    rules: list[tuple[str, str, str]] = []
    owner: str | None = None
    for line in re.sub(r"\\\n", " ", text).splitlines():
        config = _CONFIG_LINE_RE.match(line)
        if config:
            owner = config.group(1)
            continue
        if line[:1] not in ("", " ", "\t", "#"):
            owner = None
            continue
        select = _OWNED_SELECT_RE.match(line)
        if select and owner:
            rules.append(
                (owner, select.group(1), _normalise_condition(select.group(2) or ""))
            )
    return rules


def _active_symbols(
    board_flags: set[str],
    meta_rules: list[tuple[str, str]],
    rules: list[tuple[str, str, str]],
) -> frozenset[str]:
    """Every symbol a board ends up with: its own, the derived, the selected.

    Run to a fixed point, as Kconfig does: a select can turn on a config
    whose own selects then fire, and a derived flag can follow from either.
    Each pass rebuilds the set from the board's own flags, so a select
    guarded by a negation (`if !BR2_PACKAGE_BATOCERA_GLES3`) that fired
    before GLES3 was derived is dropped once it is: accumulating kept
    duckstation-legacy on every GLES3 board.
    """
    base = frozenset(board_flags)
    active = base
    for _ in range(64):
        following = base | {
            derived for derived, condition in meta_rules
            if _condition_holds(condition, active)
        } | {
            selected
            for owner, selected, condition in rules
            if owner in active and _condition_holds(condition, active)
        }
        if following == active:
            return active
        active = frozenset(following)
    raise RuntimeError("Kconfig selects do not settle: a negated condition cycles")


def _parse_es_systems(text: str) -> dict[str, list[str]]:
    """Parse es_systems.yml: map BR2_PACKAGE_* flag -> list of emulator names.

    The file is a dict keyed by system name. Each system has:
      emulators:
        <emulator_group>:
          <core_name>: {requireAnyOf: [BR2_PACKAGE_FOO]}
    """
    try:
        data = yaml_load_upstream(text)
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
        for group_name, group_data in emulators.items():
            if not isinstance(group_data, dict):
                continue
            for core_name, core_data in group_data.items():
                if not isinstance(core_data, dict):
                    continue
                require = core_data.get("requireAnyOf", [])
                if not isinstance(require, list):
                    continue
                # A standalone emulator is its own core: amiberry, fsuae and
                # vice list machines under their name, and the package that
                # builds a machine builds the emulator.
                names = [core_name] if group_name == "libretro" else [group_name, core_name]
                for pkg_flag in require:
                    if isinstance(pkg_flag, str):
                        package_to_emulators.setdefault(pkg_flag, []).extend(names)

    return package_to_emulators


# RetroArch's core downloader fetches from DEFAULT_BUILDBOT_SERVER_URL, which
# Linux sets for x86_64, i386 and armv7 hard-float alone, and leaves empty on
# aarch64 (config.def.h:1855-1864 at Batocera's 4b74434 and at v1.22.2).
def buildbot_target(symbols: set[str] | frozenset[str]) -> str | None:
    """The RetroArch targets entry a board's core downloader installs from.

    `symbols` are the board's active symbols. An armv7-A CPU selects
    BR2_ARM_CPU_ARMV7A (arch/Config.in.arm) and is hard-float unless the
    board asks for soft-float (BR2_ARM_EABI): Buildroot picks EABIHF for a
    CPU with a VFP, which every Cortex-A has. armv6 (bcm2835), aarch64 and
    riscv64 get no buildbot URL.
    """
    if "BR2_x86_64" in symbols:
        return "linux-x86_64"
    if "BR2_i386" in symbols:
        return "linux-x86"
    if "BR2_ARM_CPU_ARMV7A" in symbols and "BR2_ARM_EABI" not in symbols:
        return "linux-armhf"
    return None


# configure options and make variables that compile the downloader out.
_NO_DOWNLOADER = ("--disable-update-cores", "--disable-online-updater", "--disable-networking",
                  "HAVE_UPDATE_CORES=0", "HAVE_ONLINE_UPDATER=0", "HAVE_LAKKA=1")
_BLANK_CORES_URL = re.compile(r'^\s*core_updater_buildbot_cores_url\s*=\s*""', re.MULTILINE)


def downloader_disabled(retroarch_mk: str, shipped_cfgs: dict[str, str]) -> str | None:
    """Why RetroArch's core downloader installs nothing, or None.

    Compiled out by its build options, or left without a URL by a shipped
    retroarch.cfg. A config that hides the menu entry alone does not stop
    it: without HAVE_LAKKA, Settings > User Interface offers it back
    (menu_setting.c). A config that blanks the URL for some boards only is
    a case this reader does not split, and an error.
    """
    for option in _NO_DOWNLOADER:
        if option in retroarch_mk:
            return f"retroarch.mk sets {option}"
    blank = sorted(path for path, text in shipped_cfgs.items() if _BLANK_CORES_URL.search(text))
    if blank:
        raise RuntimeError(f"{', '.join(blank)} blank the core downloader URL: split per board")
    return None


# Buildroot's architecture choice, as a board sets it (arch/Config.in).
_ARCH_SYMBOLS = {
    "BR2_aarch64": "aarch64",
    "BR2_arm": "arm",
    "BR2_x86_64": "x86_64",
    "BR2_i386": "x86",
    "BR2_riscv": "riscv64",
}


def _arch_from_flag(flag: str, board_flags: set[str] | frozenset[str] = frozenset()) -> str:
    """The board's Buildroot architecture, else a guess from its target flag.

    KNULLI's R16, RK3128 and ATM7039 images are 32-bit ARM (BR2_arm=y):
    the target flag alone does not say so.
    """
    for symbol, arch in _ARCH_SYMBOLS.items():
        if symbol in board_flags:
            return arch
    low = flag.lower()
    if "x86_64" in low or "zen3" in low:
        return "x86_64"
    if "x86" in low:
        return "x86"
    return "aarch64"


@dataclass(frozen=True)
class BuildSelection:
    """What the boards of a build turn on, read once from its Kconfig.

    `targets` is each board's entry of the targets file, `downloads` naming
    the RetroArch targets entry its core downloader installs from. `emulators` holds
    every es_systems name some board builds and `listed` every name
    es_systems ties to a package, `symbols` every symbol some board ends up
    with, and `packages` the config symbol each package folder of the tree
    defines.
    """

    targets: dict[str, dict]
    emulators: frozenset[str]
    listed: frozenset[str]
    symbols: frozenset[str]
    packages: dict[str, str]


def _sourced(text: str) -> list[str]:
    """The files a Kconfig file sources, relative to the external tree."""
    return [m.group(1) for line in text.splitlines() if (m := _SOURCE_RE.match(line))]


def _package_symbols(files: dict[str, str]) -> dict[str, str]:
    """package folder -> the first config symbol its Config.in defines."""
    found: dict[str, str] = {}
    for path, text in files.items():
        parts = path.split("/")
        if len(parts) < 3 or parts[-1] != "Config.in" or "package" not in parts:
            continue
        config = next((m.group(1) for line in text.splitlines()
                       if (m := _CONFIG_LINE_RE.match(line))), None)
        if config:
            found.setdefault(parts[-2], config)
    return found


class Scraper(BaseTargetScraper):
    """Cross-references Batocera boards, Config.in, and es_systems to build target lists.

    A Buildroot tree built on Batocera's model (KNULLI) overrides the class
    attributes: its repository, board prefix, system Config.in, es_systems
    and the config every image turns on.
    """

    PLATFORM = PLATFORM_NAME
    REPO = "batocera-linux/batocera.linux"
    BOARD_PREFIX = "batocera-"
    CONFIG_IN_PATH = "package/batocera/core/batocera-system/Config.in"
    ES_SYSTEMS_PATH = "package/batocera/emulationstation/batocera-es-system/es_systems.yml"
    SYSTEM_SYMBOL = "BR2_PACKAGE_BATOCERA_SYSTEM"
    BUILDROOT_REPO = "batocera-linux/buildroot"
    # Path prefix -> repository of a submodule the root Config.in sources
    # from: KNULLI reads Batocera's packages as batocera/package/...
    SUBMODULES: dict[str, str] = {}
    RETROARCH_MK = "package/batocera/emulators/retroarch/retroarch/retroarch.mk"

    def __init__(self, url: str = "") -> None:
        super().__init__(url=url or f"https://github.com/{self.REPO}")
        self.tag = ""

    def _raw(self, path: str) -> str:
        return f"https://raw.githubusercontent.com/{self.REPO}/{self.tag}/{path}"

    def _api(self, path: str) -> str:
        return f"https://api.github.com/repos/{self.REPO}/contents/{path}?ref={self.tag}"

    def _list_boards(self) -> list[str]:
        """List <prefix>*.board files from configs/ via GitHub API."""
        data = _fetch_json(self._api("configs"))
        boards = [
            item["name"]
            for item in data
            if isinstance(item, dict)
            and item.get("name", "").startswith(self.BOARD_PREFIX)
            and item.get("name", "").endswith(".board")
        ] if isinstance(data, list) else []
        if not boards:
            raise RuntimeError(
                f"no {self.BOARD_PREFIX}*.board file in configs/ at {self.tag}"
            )
        return boards

    def _fetch_board(self, board_name: str) -> tuple[str | None, set[str]]:
        """A board's target flag and every flag it sets, includes followed.

        <prefix>board.common turns on the system symbol, the config whose
        selects bring in the display stack and every emulator group.
        """
        flags: set[str] = set()
        target: str | None = None
        pending, seen = [(board_name, False)], set()
        while pending:
            name, optional = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            try:
                text = _fetch(self._raw(f"configs/{name}"))
            except RuntimeError:
                if optional:
                    continue
                raise
            flags |= set(_BOARD_FLAG_RE.findall(text))
            if target is None:
                m = _TARGET_FLAG_RE.search(text)
                target = m.group(1) if m else None
            pending += [(inc, bool(dash)) for dash, inc in _BOARD_INCLUDE_RE.findall(text)]
        return target, flags

    def _kconfig_files(self) -> dict[str, str]:
        """The root Config.in and every file it sources, recursively.

        The build reads these and nothing else: a package's own Config.in
        can select another package (advanced_drastic selects drastic), and
        such a select sits in no system Config.in. A sourced file absent at
        the pin defines nothing and is named: KNULLI 20260511 sources
        package/utils/vtree/Config.in, a package its tree gained later.
        """
        bases: list[tuple[str, str]] = []
        for prefix, repo in self.SUBMODULES.items():
            pin = _fetch_json(self._api(prefix.rstrip("/")))
            sha = pin.get("sha") if isinstance(pin, dict) else None
            if not sha:
                raise RuntimeError(f"no {prefix.rstrip('/')} submodule commit at {self.tag}")
            bases.append((prefix, f"https://raw.githubusercontent.com/{repo}/{sha}/"))

        def url(path: str) -> str:
            for prefix, base in bases:
                if path.startswith(prefix):
                    return base + path.removeprefix(prefix)
            return self._raw(path)

        files: dict[str, str] = {}
        absent: list[str] = []
        pending = ["Config.in"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            while pending:
                found = dict(zip(pending, pool.map(lambda path: _fetch_present(url(path)), pending)))
                absent += [path for path, text in found.items() if text is None]
                files.update((path, text or "") for path, text in found.items())
                pending = sorted({src for text in found.values() if text
                                  for src in _sourced(text)} - set(files))
        if "Config.in" in absent or len(files) - len(absent) < 2:
            raise RuntimeError(f"Config.in at {self.tag} sources no readable Kconfig file")
        for path in absent:
            print(f"  sourced but absent at {self.tag}: {path}", file=sys.stderr)
        return files

    def _shipped_retroarch_cfgs(self) -> dict[str, str]:
        """Every retroarch.cfg the tree ships, its submodules included."""
        repos = [("", self.REPO, self.tag)]
        for prefix, repo in self.SUBMODULES.items():
            pin = _fetch_json(self._api(prefix.rstrip("/")))
            repos.append((prefix, repo, pin["sha"]))
        found: dict[str, str] = {}
        for prefix, repo, ref in repos:
            listing = _fetch_json(f"https://api.github.com/repos/{repo}/git/trees/{ref}?recursive=1")
            if not isinstance(listing, dict) or listing.get("truncated"):
                raise RuntimeError(f"{repo} tree at {ref} is unreadable or truncated")
            for entry in listing.get("tree", []):
                if re.search(r"(^|/)retroarch\.cfg$", entry["path"]):
                    raw = f"https://raw.githubusercontent.com/{repo}/{ref}/{entry['path']}"
                    found[prefix + entry["path"]] = _fetch(raw)
        return found

    def _buildroot_rules(self) -> list[tuple[str, str, str]]:
        """Buildroot's selects for the symbols the tree tests, at its pin."""
        pin = _fetch_json(self._api("buildroot"))
        sha = pin.get("sha") if isinstance(pin, dict) else None
        if not sha:
            raise RuntimeError(f"no buildroot submodule commit at {self.tag}")
        raw = f"https://raw.githubusercontent.com/{self.BUILDROOT_REPO}/{sha}"
        rules: list[tuple[str, str, str]] = []
        for path in BUILDROOT_KCONFIG:
            rules += _parse_owned_selects(_fetch(f"{raw}/{path}"))
        return rules

    def build_selection(self, tag: str | None = None) -> BuildSelection:
        """Each board's selection, from the Kconfig the build reads.

        `tag` is the revision to read, by default the one the platform's
        YAML was scraped at: a platform scraper moving to a new release
        passes its own.
        """
        self.tag = tag or self.pinned_revision(self.PLATFORM)
        print("  fetching board list...", file=sys.stderr)
        boards = self._list_boards()

        print("  fetching Kconfig files...", file=sys.stderr)
        files = self._kconfig_files()
        config_in_text = files.get(self.CONFIG_IN_PATH)
        if not config_in_text:
            raise RuntimeError(f"Config.in at {self.tag} does not source {self.CONFIG_IN_PATH}")

        meta_rules = _parse_meta_flags(config_in_text)
        rules = [rule for text in files.values() for rule in _parse_owned_selects(text)]
        print(
            f"  parsed {len(meta_rules)} meta-flag rules, {len(rules)} select lines "
            f"in {len(files)} Kconfig files",
            file=sys.stderr,
        )
        if not _parse_owned_selects(config_in_text):
            raise RuntimeError(f"no 'select BR2_PACKAGE_*' lines parsed from {self.CONFIG_IN_PATH}")
        rules += self._buildroot_rules()

        print("  fetching es_systems.yml...", file=sys.stderr)
        es_systems_url = self._raw(self.ES_SYSTEMS_PATH)
        es_text = _fetch(es_systems_url)
        if not es_text:
            raise RuntimeError(f"empty es_systems.yml from {es_systems_url}")
        package_to_emulators = _parse_es_systems(es_text)
        print(
            f"  parsed {len(package_to_emulators)} package->emulator mappings",
            file=sys.stderr,
        )
        if not package_to_emulators:
            raise RuntimeError(f"no package->emulator mappings parsed from {es_systems_url}")
        images_by_flag = _parse_images(config_in_text)
        if not images_by_flag:
            raise RuntimeError(f"no target image list parsed from {self.CONFIG_IN_PATH}")
        disabled = downloader_disabled(_fetch(self._raw(self.RETROARCH_MK)),
                                       self._shipped_retroarch_cfgs())
        if disabled:
            print(f"  core downloader off: {disabled}", file=sys.stderr)

        targets: dict[str, dict] = {}
        symbols: set[str] = set()
        for board_name in sorted(boards):
            target_key = board_name.removeprefix(self.BOARD_PREFIX).removesuffix(".board")
            print(f"  processing {target_key}...", file=sys.stderr)
            primary_flag, board_flags = self._fetch_board(board_name)
            if primary_flag is None:
                print(f"    no target flag found in {board_name}", file=sys.stderr)
                continue

            selected_packages = _active_symbols(board_flags, meta_rules, rules)
            # x86_wow64 builds the 32-bit Wine package the x86_64 image
            # carries: no batocera-board.common, no system, no target.
            if self.SYSTEM_SYMBOL not in selected_packages:
                print(f"    {board_name} builds no system image", file=sys.stderr)
                continue
            symbols |= selected_packages

            # Map selected packages to emulator names via es_systems.yml
            emulators: set[str] = set()
            for pkg in selected_packages:
                for emu in package_to_emulators.get(pkg, []):
                    emulators.add(emu)

            arch = _arch_from_flag(primary_flag, board_flags)
            targets[target_key] = {
                "architecture": arch,
                "cores": sorted(emulators),
            }
            images = sorted(set(images_by_flag.get(primary_flag, [])))
            if images and images != [target_key]:
                targets[target_key]["images"] = images
            downloads = None if disabled else buildbot_target(selected_packages)
            if downloads:
                targets[target_key]["downloads"] = downloads
            print(
                f"    {len(emulators)} emulators ({len(selected_packages)} packages selected)",
                file=sys.stderr,
            )

        return BuildSelection(
            targets=targets,
            emulators=frozenset(c for entry in targets.values() for c in entry["cores"]),
            listed=frozenset(n for names in package_to_emulators.values() for n in names),
            symbols=frozenset(symbols),
            packages=_package_symbols(files),
        )

    def fetch_targets(self) -> dict:
        """Build per-board emulator availability map."""
        selection = self.build_selection()
        return {
            "platform": self.PLATFORM,
            "source": f"{self.url}/tree/{self.tag}",
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": selection.targets,
        }


def main(scraper_class: type[Scraper] = Scraper) -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=f"Scrape {scraper_class.PLATFORM} per-board emulator targets"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = scraper_class()
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
