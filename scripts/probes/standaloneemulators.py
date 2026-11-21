"""The standalone emulators a platform installs, and the settings a run writes."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import core_probe as cp

# This file holds every error string the emulators print: without an oracle
# file, a record names it as its oracle.
PATTERNS_FILE = "scripts/probes/standaloneemulators.py"
PATTERNS_PATH = Path(__file__).resolve()


@dataclass(frozen=True)
class Emulator:
    """A standalone emulator as one platform installs it.

    `asset_*` reproduce the installer's choice: EmuDeck's getReleaseURLGH
    takes the first asset, over GitHub's release list in its own order
    (pre-releases included), whose name contains `asset_contains` and ends
    with `asset_endswith`.
    """

    name: str
    platform: str
    installer_ref: str
    repo: str
    asset_endswith: str
    asset_contains: str
    binary: str
    settings_file: str
    error_patterns: tuple[str, ...]
    settings: dict[str, dict[str, str]] = field(default_factory=dict)
    bios_setting: tuple[str, str] = ("", "")
    args: tuple[str, ...] = ()


EMULATORS: dict[str, Emulator] = {
    "duckstation": Emulator(
        name="duckstation",
        platform="emudeck",
        installer_ref="dragoonDorise/EmuDeck functions/EmuScripts/emuDeckDuckStation.sh "
                      "(getReleaseURLGH \"stenzek/duckstation\" \"AppImage\" \"x64.\")",
        repo="stenzek/duckstation",
        asset_endswith="AppImage",
        asset_contains="x64.",
        binary="usr/bin/duckstation-qt",
        # Core::SetDataRoot (src/core/core.cpp): $XDG_CONFIG_HOME/duckstation on Linux.
        settings_file="data/duckstation/settings.ini",
        bios_setting=("BIOS", "SearchDirectory"),
        settings={
            "Main": {"SetupWizardIncomplete": "false", "ConfirmPowerOff": "false",
                     "StartFullscreen": "true"},
            "AutoUpdater": {"CheckAtStartup": "false"},
            "GPU": {"Renderer": "Software"},
            # No sound device in the sandbox: the null backend, not an error dialog.
            "Audio": {"Backend": "Null"},
            "Logging": {"LogLevel": "Info", "LogToConsole": "true", "LogToFile": "false"},
            "Console": {"Region": "Auto"},
        },
        args=("-batch", "-nogui", "-fullscreen", "--"),
        # Strings of src/core/bios.cpp and src/core/system.cpp, as the
        # release binary carries them.
        error_patterns=("No BIOS image found for", "No BIOS images found",
                        "No BIOS images were found", "Failed to open BIOS"),
    ),
    "pcsx2": Emulator(
        name="pcsx2",
        platform="emudeck",
        installer_ref="dragoonDorise/EmuDeck functions/EmuScripts/emuDeckPCSX2QT.sh "
                      "(getReleaseURLGH \"PCSX2/pcsx2\" \"Qt.AppImage\" \"\")",
        repo="PCSX2/pcsx2",
        asset_endswith="Qt.AppImage",
        asset_contains="",
        binary="usr/bin/pcsx2-qt",
        # EmuFolders::SetDataDirectory (pcsx2/Pcsx2Config.cpp): $XDG_CONFIG_HOME/PCSX2 on Linux,
        # its settings in inis/.
        settings_file="data/PCSX2/inis/PCSX2.ini",
        bios_setting=("Folders", "Bios"),
        settings={
            # SETTINGS_VERSION of pcsx2/VMManager.cpp: another value resets every setting.
            "UI": {"SettingsVersion": "1", "SetupWizardIncomplete": "false", "ConfirmShutdown": "false",
                   "StartFullscreen": "true"},
            "AutoUpdater": {"CheckAtStartup": "false"},
            # GSRendererType::SW
            "EmuCore/GS": {"Renderer": "13"},
            # No sound device in the sandbox: the null backend, not an error dialog
            # over the screen.
            "SPU2/Output": {"Backend": "Null"},
            "Logging": {"EnableSystemConsole": "true", "EnableVerbose": "false"},
        },
        args=("-batch", "-nogui", "-fullscreen", "-earlyconsolelog", "--"),
        error_patterns=("requires a PlayStation 2 BIOS in order to run",
                        "Unable to auto locate a BIOS image", "BIOS image has not been selected",
                        "could not be read (permission denied?)"),
    ),
}


def ini_text(sections: dict[str, dict[str, str]]) -> str:
    out = []
    for section, values in sections.items():
        out.append(f"[{section}]")
        out.extend(f"{key} = {value}" for key, value in values.items())
        out.append("")
    return "\n".join(out)


def emulator_settings(emu: Emulator, bios_dir: Path, overrides: Sequence[tuple[str, str]]
                      ) -> dict[str, dict[str, str]]:
    """The settings written before a run: the emulator's own, the BIOS
    folder, then each SECTION.KEY=VALUE override."""
    sections = {name: dict(values) for name, values in emu.settings.items()}
    section, key = emu.bios_setting
    sections.setdefault(section, {})[key] = str(bios_dir)
    for name, value in overrides:
        sec, _, k = name.rpartition(".")
        if not sec or not k:
            raise cp.ProbeError(f"--setting {name}: SECTION.KEY expected")
        sections.setdefault(sec, {})[k] = value
    return sections
