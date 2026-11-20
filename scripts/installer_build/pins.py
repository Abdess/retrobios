"""The SHA-256 of install.py in the bootstraps that pin it."""

from __future__ import annotations

import re
from pathlib import Path

from core.hashing import file_digest
from core.paths import REPO_ROOT


INSTALLER = "install.py"
# Each bootstrap and its one pin line: the text before the value, the
# value, the text after it.
PINS: dict[str, re.Pattern[str]] = {
    "install.sh": re.compile(r'^(DEFAULT_INSTALL_SHA256=")([0-9a-f]{64})(")', re.M),
    "install.ps1": re.compile(r'^(\s*\$defaultInstallSha256 = ")([0-9a-f]{64})(")', re.M),
}
COMMAND = "python scripts/pin_installer.py"


def installer_sha256(root: Path = REPO_ROOT) -> str:
    return file_digest(root / INSTALLER, "sha256")


def pinned_sha256(name: str, root: Path = REPO_ROOT) -> str:
    """The SHA-256 the bootstrap *name* accepts for install.py. Exactly one
    pin line: sh and PowerShell keep the last assignment, so a second line
    would be the value the bootstrap runs with."""
    found = PINS[name].findall((root / name).read_bytes().decode("utf-8"))
    if len(found) != 1:
        raise ValueError(f"{name}: {len(found)} installer pin lines, expected 1")
    return found[0][1]


def stale_pins(root: Path = REPO_ROOT) -> list[str]:
    """The bootstraps whose pin is not the SHA-256 of install.py."""
    digest = installer_sha256(root)
    return [name for name in PINS if pinned_sha256(name, root) != digest]


def write_pins(root: Path = REPO_ROOT) -> list[str]:
    """Rewrite each stale pin. Returns the bootstraps written."""
    digest = installer_sha256(root)
    written = []
    for name in stale_pins(root):
        path = root / name
        text = path.read_bytes().decode("utf-8")
        new, count = PINS[name].subn(rf"\g<1>{digest}\g<3>", text)
        if count != 1:
            raise ValueError(f"{name}: {count} installer pin lines, expected 1")
        path.write_bytes(new.encode("utf-8"))
        written.append(name)
    return written
