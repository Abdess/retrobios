"""The SHA-256 of install.py in the bootstraps that pin it."""

from __future__ import annotations

import re
from pathlib import Path

from core.hashing import file_digest
from core.paths import REPO_ROOT


INSTALLER = "install.py"
# Each bootstrap and its one pin line, the value between the two groups.
PINS: dict[str, re.Pattern[str]] = {
    "install.sh": re.compile(r'^(DEFAULT_INSTALL_SHA256=")[0-9a-f]{64}(")', re.M),
    "install.ps1": re.compile(r'^(\s*\$defaultInstallSha256 = ")[0-9a-f]{64}(")', re.M),
}
# The value of that pin line, by bootstrap.
PIN: dict[str, re.Pattern[str]] = {
    "install.sh": re.compile(r'^DEFAULT_INSTALL_SHA256="([0-9a-f]{64})"', re.M),
    "install.ps1": re.compile(r'^\s*\$defaultInstallSha256 = "([0-9a-f]{64})"', re.M),
}
COMMAND = "python scripts/pin_installer.py"


def installer_sha256(root: Path = REPO_ROOT) -> str:
    return file_digest(root / INSTALLER, "sha256")


def stale_pins(root: Path = REPO_ROOT) -> list[str]:
    """The bootstraps whose pin is not the SHA-256 of install.py."""
    digest = installer_sha256(root)
    stale = []
    for name, pin in PINS.items():
        found = pin.search((root / name).read_bytes().decode("utf-8"))
        if found is None:
            raise ValueError(f"{name}: no installer pin line")
        if found.group(0) != f"{found.group(1)}{digest}{found.group(2)}":
            stale.append(name)
    return stale


def write_pins(root: Path = REPO_ROOT) -> list[str]:
    """Rewrite each stale pin. Returns the bootstraps written."""
    digest = installer_sha256(root)
    written = []
    for name in stale_pins(root):
        path = root / name
        text = path.read_bytes().decode("utf-8")
        new, count = PINS[name].subn(rf"\g<1>{digest}\g<2>", text)
        if count != 1:
            raise ValueError(f"{name}: {count} installer pin lines, expected 1")
        path.write_bytes(new.encode("utf-8"))
        written.append(name)
    return written
