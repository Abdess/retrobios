"""install.py stays under the size the one-liners accept.

install.sh refuses an installer above MAX_INSTALLER_BYTES and install.ps1
above $maximumInstallerBytes: past them every curl | sh and irm | iex
stops before the first file. This test fails while there is still room,
so the cap is raised, or the installer made smaller, before a release.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The share of the cap install.py may use: 1.9 MiB of 2 MiB. Raising the
# cap in both bootstraps raises the alert with it.
ALERT_SHARE = 0.95

_UNITS = {"": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}


def shell_cap() -> int:
    text = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    return int(re.search(r"^MAX_INSTALLER_BYTES=(\d+)$", text, re.MULTILINE).group(1))


def powershell_cap() -> int:
    text = (REPO_ROOT / "install.ps1").read_text(encoding="utf-8")
    found = re.search(r"\$maximumInstallerBytes\s*=\s*(\d+)\s*(KB|MB|GB)?\b", text)
    return int(found.group(1)) * _UNITS[found.group(2) or ""]


class InstallerFitsTheOneLiners(unittest.TestCase):
    def test_both_bootstraps_accept_the_same_size(self):
        self.assertEqual(shell_cap(), powershell_cap())

    def test_install_py_stays_below_the_alert(self):
        cap = shell_cap()
        size = (REPO_ROOT / "install.py").stat().st_size
        alert = int(cap * ALERT_SHARE)
        self.assertLess(
            size, alert,
            f"install.py is {size} bytes, past {alert} of the {cap} the one-liners "
            "accept: raise MAX_INSTALLER_BYTES in install.sh and $maximumInstallerBytes "
            "in install.ps1, or make the installer smaller")


if __name__ == "__main__":
    unittest.main()
