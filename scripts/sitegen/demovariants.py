"""The installer demo recordings: their variants, output files, size targets and facts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from core.paths import REPO_ROOT

OUT = REPO_ROOT / "docs_assets" / "demo"
WORK = REPO_ROOT / "tmp" / "demo"
FACTS = OUT / "demo.json"


@dataclass(frozen=True)
class Variant:
    """One recording. *place* is "computer" (the card in a reader, the
    one-line command typed) or "device" (the interface on the card's own
    system). *os_type* is RETROBIOS_OS for the run."""

    name: str
    stem: str
    mount: str
    os_type: str
    place: str
    gif: bool = False

    @property
    def tape(self) -> Path:
        return OUT / f"{self.stem}.tape"

    @property
    def suffix(self) -> str:
        return "" if self.name == "default" else f"-{self.name}"

    @property
    def recorded(self) -> Path:
        """What the tape writes, read back here (relative to REPO_ROOT, the
        tape's working directory)."""
        return WORK / f"recorded{self.suffix}.mp4"

    @property
    def poster_shot(self) -> Path:
        return WORK / f"poster{self.suffix}.png"

    @property
    def outputs(self) -> tuple[str, ...]:
        names = (f"{self.stem}.webm", f"{self.stem}.mp4", f"{self.stem}.png")
        return ((f"{self.stem}.gif",) if self.gif else ()) + names


VARIANTS: dict[str, Variant] = {
    "default": Variant("default", "install", "/media/EASYROMS", "linux", "computer",
                       gif=True),
    "handheld": Variant("handheld", "install-handheld", "/roms", "linux", "device"),
}
# The default variant's paths, as the tests and the README name them.
TAPE = VARIANTS["default"].tape
RECORDED = VARIANTS["default"].recorded
POSTER_SHOT = VARIANTS["default"].poster_shot
MOUNT = VARIANTS["default"].mount

# Size targets of the outputs, in bytes, by extension: the README and the
# site's pages.
LIMITS = {".gif": 1_500_000, ".webm": 1_000_000, ".mp4": 1_000_000, ".png": 150_000}


def limits(variant: Variant) -> dict[str, int]:
    """Each output of a variant and its size target."""
    return {name: LIMITS[Path(name).suffix] for name in variant.outputs}


def check_sizes(out: Path, variant: Variant = VARIANTS["default"]) -> list[str]:
    return [f"{name}: {(out / name).stat().st_size:,} bytes, over {limit:,}"
            for name, limit in limits(variant).items() if (out / name).stat().st_size > limit]


def describe(variant: str, facts: dict) -> str:
    """A recording in words, for a reader who cannot see it: its alt text."""
    plan = (f"plans {facts['files']} BIOS files ({facts['size']}) for them, installs them "
            "and shows the summary.")
    if variant == "handheld":
        return (f"Recording of the full-screen installer on the {facts['width']} by "
                f"{facts['height']} screen of a handheld, started from the Tools menu of "
                f"{facts['setup']}, on a demonstration card. It finds the {facts['games']} games "
                f"on the card, {plan} The A button chooses, and the bottom line names the buttons.")
    return (f"Recording of the one-line command in a terminal, on a demonstration card. The "
            f"installer finds {_article(facts['setup'])} {facts['setup']} SD card with "
            f"{facts['games']} games, {plan}")


def _article(name: str) -> str:
    return "an" if name[:1].lower() in "aeiou" else "a"


def load_facts() -> dict:
    """demo.json, an empty mapping before the first recording."""
    if not FACTS.is_file():
        return {}
    return json.loads(FACTS.read_text(encoding="utf-8"))


def demo_facts(variant: str = "default") -> dict:
    """What an installer demo shows, as make_demo.py measured it: one entry
    per variant (default, handheld)."""
    facts = json.loads(FACTS.read_text(encoding="utf-8"))
    return facts[variant]


def demo_description(facts: dict | None = None) -> str:
    """The demo in words, for a reader who cannot see it: the alt text
    make_demo.py wrote from what it measured."""
    return str((facts or demo_facts())["alt"])


def write_facts(facts: dict) -> None:
    """demo.json, one entry per variant recorded so far, in VARIANTS order."""
    ordered = {name: facts[name] for name in VARIANTS if name in facts}
    FACTS.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")
