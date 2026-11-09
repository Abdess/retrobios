"""A profile alias is a name the emulator's own code opens.

Platform launchers pick names of their own: Batocera passes cerbios.bin to
xemu, ROCKNIX and EmuDeck write Complex_4627v1.03.bin into xemu.toml. Those
names live in the platform's ``launchers:`` layer. Copied into a profile as
aliases, they claimed that xemu opens them, and xemu-libretro offers
Complex_4627_v1.03.bin, not Complex_4627v1.03.bin (ui/xemu-libretro.c:115-118).

Three checks read the committed data:

- an alias equal to a name a launcher of the same emulator chooses is kept
  only when the entry's own note or description names it in a sentence that
  speaks of no platform, next to a ``source_ref`` into the emulator's code;
- an entry whose note names its own file only in sentences about a platform
  is a launcher's choice: Mini vMac opens no MinivMacBootv2.dsk, the .cmd
  Recalbox writes names it;
- no entry cites a platform's launcher script as its source.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import unittest
from collections import defaultdict
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = REPO_ROOT / "platforms"
EMULATORS = REPO_ROOT / "emulators"

# Words that name a platform in prose. MiSTer's registry key carries its
# hardware suffix, the prose says MiSTer.
PLATFORM_WORDS = (
    "retroarch", "batocera", "recalbox", "retrobat", "emudeck", "lakka",
    "retrodeck", "romm", "rocknix", "retropie", "bizhawk", "mister",
    "knulli", "amberelec", "emuelec",
)

# Launcher sources: configgen and emulatorLauncher generators, EmuDeck and
# RetroPie scripts, a ref annotated as a launcher.
LAUNCHER_REF = re.compile(
    r"Generator\.(?:py|cs)\b|\bconfiggen\b|\bemulatorLauncher\b|"
    r"\bemuDeck\w*\.sh\b|\bscriptmodules/|\(launcher\)",
)

# Entries whose name is the one a platform's launcher picks, kept because
# the code takes any name and the entry needs one.
NAMED_FOR_A_LAUNCHER = {
    ("pcsx_rearmed_standalone", "SCPH1001.BIN"):
        "the code lists any 512 KiB file (frontend/menu.c:2619-2628)",
}

# Profiles whose entries still rest on a launcher, with the fact that blocks
# reading the emulator itself.
LAUNCHER_SOURCED = {
    "lexaloffle": "PICO-8 is a sold binary, and no copy is held to read",
    "voxatron": "Voxatron is a sold binary, and no copy is held to read",
}

_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(\"'])")


def _profiles() -> dict[str, dict]:
    return {
        path.stem: yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for path in sorted(EMULATORS.glob("*.yml"))
    }


def _launcher_names() -> dict[str, set[tuple[str, str]]]:
    """Folded file name -> (platform, emulator) of each launcher choosing it."""
    names: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for path in sorted(PLATFORMS.glob("*.yml")):
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for record in config.get("launchers") or []:
            for name in record.get("names") or []:
                base = str(name).rsplit("/", 1)[-1].casefold()
                names[base].add((path.stem, str(record.get("emulator", ""))))
    return names


def _text(value: object) -> str:
    if isinstance(value, dict):
        return " ".join(_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_text(v) for v in value)
    return str(value or "")


def _named_without_platform(alias: str, prose: str) -> bool:
    for sentence in _SENTENCE.split(" ".join(prose.split())):
        if alias not in sentence:
            continue
        folded = sentence.casefold()
        if not any(re.search(rf"\b{word}", folded) for word in PLATFORM_WORDS):
            return True
    return False


class ProfileAliasesAreCodeNames(unittest.TestCase):
    def test_alias_a_launcher_chooses_is_named_by_the_code(self) -> None:
        launchers = _launcher_names()
        offenders = []
        for key, profile in _profiles().items():
            emulator_names = {key} | {str(c) for c in profile.get("cores") or []}
            for entry in profile.get("files") or []:
                prose = _text(entry.get("note")) + " " + _text(entry.get("description"))
                for alias in entry.get("aliases") or []:
                    alias = str(alias)
                    chosen_by = {
                        platform
                        for platform, emulator in launchers.get(
                            alias.rsplit("/", 1)[-1].casefold(), ()
                        )
                        if emulator in emulator_names
                    }
                    if not chosen_by:
                        continue
                    if entry.get("source_ref") and _named_without_platform(alias, prose):
                        continue
                    offenders.append(
                        f"{key}: {entry.get('name')} alias {alias} "
                        f"(launchers: {', '.join(sorted(chosen_by))})"
                    )
        self.assertEqual(
            offenders, [],
            "an alias a platform launcher chooses must be named by the emulator's "
            "code, stated in the entry's note with its source_ref, or removed",
        )

    def test_an_entry_named_only_by_a_launcher_is_not_the_emulators(self) -> None:
        launchers = _launcher_names()
        offenders = []
        for key, profile in _profiles().items():
            emulator_names = {key} | {str(c) for c in profile.get("cores") or []}
            for entry in profile.get("files") or []:
                name = str(entry.get("name") or "").rsplit("/", 1)[-1]
                if (key, name) in NAMED_FOR_A_LAUNCHER or not any(
                    emulator in emulator_names
                    for _platform, emulator in launchers.get(name.casefold(), ())
                ):
                    continue
                prose = _text(entry.get("note")) + " " + _text(entry.get("description"))
                if name in prose and not _named_without_platform(name, prose):
                    offenders.append(f"{key}: {name}")
        self.assertEqual(
            offenders, [],
            "an entry whose own note names it only as a platform's choice "
            "belongs to that platform's launchers: layer",
        )

    def test_rosalies_mupen_gui_names_stay_out_of_mupen64plus(self) -> None:
        """RetroBat's mupen64 generator configures Rosalie's Mupen GUI and
        writes IPL_USA.n64 and IPL_DEV.n64 into its config
        (Mupen64.Generator.cs:232-238). Mupen64Plus fixes no IPL name."""
        profiles = _profiles()
        for key in ("mupen64plus", "mupen64plus-ae", "m64plus-fz"):
            aliases = {
                str(a) for entry in profiles[key].get("files") or []
                for a in entry.get("aliases") or []
            }
            self.assertFalse(aliases & {"IPL_USA.n64", "IPL_DEV.n64"}, key)

    def test_check_catches_a_launcher_name(self) -> None:
        self.assertFalse(_named_without_platform(
            "cerbios.bin", "Batocera writes bios/cerbios.bin into flashrom_path.",
        ))
        self.assertTrue(_named_without_platform(
            "cerbios.bin", "The core option offers cerbios.bin. Batocera writes it.",
        ))


class EntriesCiteTheEmulator(unittest.TestCase):
    def test_no_source_ref_is_a_launcher_script(self) -> None:
        offenders = []
        for key, profile in _profiles().items():
            if key in LAUNCHER_SOURCED:
                continue
            for entry in profile.get("files") or []:
                ref = _text(entry.get("source_ref"))
                if LAUNCHER_REF.search(ref):
                    offenders.append(f"{key}: {entry.get('name')}: {ref}")
        self.assertEqual(offenders, [])

    def test_known_exceptions_still_need_it(self) -> None:
        profiles = _profiles()
        for key in LAUNCHER_SOURCED:
            refs = [_text(e.get("source_ref")) for e in profiles[key].get("files") or []]
            self.assertTrue(
                any(LAUNCHER_REF.search(r) for r in refs),
                f"{key} no longer cites a launcher: drop it from LAUNCHER_SOURCED",
            )


if __name__ == "__main__":
    unittest.main()
