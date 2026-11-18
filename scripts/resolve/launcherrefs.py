"""The parts of a launcher record's source_ref that cite a config or feature file."""

from __future__ import annotations

import re


# The files a platform ships as configuration: an emulator reads them, the
# platform's code never runs them. Batocera's .yml lists and an EmuELEC .opt
# only offer the values a menu option takes.
_CONFIG_FILE = re.compile(
    r"\.(?:ini|cfg|conf|rc|rc_\w+|opt|bml|toml|uae|template|yml|yaml)$", re.IGNORECASE
)
_FEATURE_FILE = re.compile(r"(?:^|/)es_features[^/]*$|\.opt$", re.IGNORECASE)


def split_ref(ref: str) -> list[str]:
    """The parts of a source_ref, each "path:lines", a bare line span
    continuing the path before it."""
    parts: list[str] = []
    for part in (p.strip() for p in ref.split(", ")):
        if not part:
            continue
        if re.fullmatch(r"\d+(?:-\d+)?", part) and parts:
            parts[-1] += f", {part}"
        else:
            parts.append(part)
    return parts


def ref_path(part: str) -> str:
    return part.rsplit(":", 1)[0] if re.search(r":\d", part) else part


def config_ref(ref: str) -> list[str]:
    """The parts of a source_ref that cite a config, option or feature file.

    Such a part proves what the file says, never that an emulator reads it:
    melonDS.ini keys are written on ROCKNIX for a build that reads them only
    when another key is set.
    """
    return [part for part in split_ref(ref) if _CONFIG_FILE.search(ref_path(part))]


def is_feature_ref(part: str) -> bool:
    """Whether a source_ref part cites a file that lists a menu option's values."""
    return bool(_FEATURE_FILE.search(ref_path(part)))
