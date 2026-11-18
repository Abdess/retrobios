"""Values read from frontends' config files as each frontend reads them."""
from __future__ import annotations

import json
import os
from pathlib import Path

from installer.host_fs import _exists, _host_path, _note_refused


def _expand_retroarch_path(value: str, app_dir: Path, home: Path | None = None) -> Path:
    """Expand the notations RetroArch writes into its config values.

    fill_pathname_expand_special (libretro-common/file/file_path.c) maps a
    leading '~' to the home directory and a leading ':' to the application
    directory, dropping the two leading characters in both cases.
    """
    if value[:1] == "~":
        return (home or Path(str(Path.home()))) / value[2:]
    if value[:1] == ":":
        return app_dir / value[2:]
    return _host_path(os.path.expandvars(os.path.expanduser(value)))


def _retroarch_cfg_dir(
    cfg_path: Path, key: str, app_dir: Path, default: str, home: Path | None = None
) -> Path | None:
    """A directory setting of retroarch.cfg, as RetroArch expands it.

    A value left empty or at `default` is the directory RetroArch falls back
    on, `default` under app_dir. None when the config is unreadable or does
    not set the key. A config this user cannot read is said once, like a
    closed folder: a retroarch.cfg a `sudo retroarch` left to root hid the
    setup without a word.
    """
    try:
        lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        _note_refused(cfg_path, exc)
        return None
    for line in lines:
        line = line.strip()
        name, sep, value = line.partition("=")
        if sep and name.strip() == key:
            value = value.strip().strip('"').strip("'")
            if not value or value == "default":
                return app_dir / default
            return _expand_retroarch_path(value, app_dir, home)
    return None


# System directory -> the retroarch.cfg it was read from and the directory
# ':' expands to there, for finding the cores of the same installation.
_RETROARCH_CONFIGS: dict[Path, tuple[Path, Path]] = {}


def _parse_retroarch_system_dir(
    cfg_path: Path, app_dir: Path | None = None, home: Path | None = None
) -> Path | None:
    """Parse system_directory from retroarch.cfg.

    app_dir is RetroArch's application directory, used to expand ':' values.
    It defaults to the directory holding the config, which is where a portable
    install keeps both. home is what '~' means to that RetroArch, the user's
    home when not given.
    """
    if not _exists(cfg_path):
        return None
    app_dir = app_dir or cfg_path.parent
    system_dir = _retroarch_cfg_dir(cfg_path, "system_directory", app_dir, "system", home)
    if system_dir is not None:
        _RETROARCH_CONFIGS.setdefault(system_dir, (cfg_path, app_dir))
    return system_dir


def _shell_unquote(value: str) -> str:
    """Resolve a shell right-hand side into its effective string value.

    Handles concatenated quoted/unquoted segments the way bash does
    (e.g. "/run/media/deck/EmuSD"/Emulation), expands variables in
    double-quoted and unquoted segments, and stops at unquoted
    whitespace or a comment.
    """
    parts: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if c == '"':
            end = value.find('"', i + 1)
            if end == -1:
                parts.append(os.path.expandvars(value[i + 1:]))
                break
            parts.append(os.path.expandvars(value[i + 1:end]))
            i = end + 1
        elif c == "'":
            end = value.find("'", i + 1)
            if end == -1:
                parts.append(value[i + 1:])
                break
            parts.append(value[i + 1:end])
            i = end + 1
        elif c.isspace() or c == "#":
            break
        else:
            end = i
            while end < n and value[end] not in "\"'#" and not value[end].isspace():
                end += 1
            parts.append(os.path.expandvars(value[i:end]))
            i = end
    return os.path.expanduser("".join(parts))


def _parse_bash_var(path: Path, key: str) -> str | None:
    """Extract the effective value of key= from a bash/shell file."""
    if not _exists(path):
        return None
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith(f"{key}="):
                _, _, value = line.partition("=")
                return _shell_unquote(value)
    except OSError as exc:
        # A settings.sh a sudo EmuDeck run left to root hid the setup.
        _note_refused(path, exc)
    return None


def _parse_json_path(path: Path, *keys: str) -> str | None:
    """Extract a nested string value from a JSON file."""
    if not _exists(path):
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        for key in keys:
            data = data[key]
        return data if isinstance(data, str) and data else None
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None


def _parse_ps1_var(path: Path, key: str) -> str | None:
    """Extract value of $key= or key= from a PowerShell file."""
    if not _exists(path):
        return None
    normalized = key.lstrip("$")
    try:
        raw = path.read_bytes()
        # Windows PowerShell's Out-File writes UTF-16, Set-Content -Encoding
        # UTF8 a byte order mark: EmuDeck's settings.ps1 passes through both.
        encoding = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
        for line in raw.decode(encoding, errors="replace").splitlines():
            line = line.strip()
            check = line.lstrip("$")
            if check.startswith(f"{normalized}="):
                _, _, value = check.partition("=")
                return value.strip('"').strip("'")
    except OSError as exc:
        _note_refused(path, exc)
    return None


def _cfg_true(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def _config_keys(path: Path) -> set[str]:
    """The keys an emulatorLauncher-style key=value file sets, lowercased."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return {
        line.split("=", 1)[0].strip().lower()
        for line in text.splitlines() if "=" in line and line.split("=", 1)[1].strip()
    }
