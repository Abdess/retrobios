"""The platform entries whose hash pins an archive's container bytes."""

from __future__ import annotations

from collections.abc import Iterator

from model.platforms import load_platform_config
from model.registry import list_registered_platforms


def container_entries(platforms_dir: str) -> Iterator[tuple[str, dict]]:
    """(platform, entry) for each platform entry whose hash is the container's.

    A ``zipped_file`` entry pins a ROM inside the archive, and a Recalbox
    archive md5 is the composite of its members (``zip_digest: composite``,
    Bios.cpp:64-68): neither pins the container bytes, and no container
    build can ever give them.
    """
    for platform in list_registered_platforms(platforms_dir):
        config = load_platform_config(platform, platforms_dir)
        for system in config.get("systems", {}).values():
            for entry in system.get("files", []) or []:
                if not (entry.get("zipped_file") or entry.get("zip_digest") == "composite"):
                    yield platform, entry
