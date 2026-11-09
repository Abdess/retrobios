"""Scraper for KNULLI per-board emulator availability.

KNULLI is a Buildroot external tree on Batocera's model, read with the
Batocera scraper's Kconfig resolution. Sources (knulli-cfw/knulli-linux, at
the tag platforms/knulli.yml names):
  - configs/knulli-*.board -- board definitions, each sets
    BR2_PACKAGE_BATOCERA_TARGET_* and includes knulli-board.common
  - package/system/knulli-system/Config.in -- the system config, sourced by
    the root Config.in in place of Batocera's batocera-system/Config.in
  - package/emulationstation/knulli-es-system/es_systems.yml
    -- emulator requireAnyOf flag mapping
  - Config.in and what it sources, Batocera's packages read from the
    batocera submodule at the commit the tag pins
Sources (knulli-cfw/buildroot, at the submodule commit the tag pins):
  - arch/Config.in, package/mesa3d/Config.in, package/libglvnd/Config.in

The *_armhf_libs boards include knulli-board.libs, which builds 32-bit
libraries for the matching image and turns no system on: they are no target.
"""

from __future__ import annotations

from .batocera_targets_scraper import Scraper as BatoceraScraper
from .batocera_targets_scraper import main as batocera_main

PLATFORM_NAME = "knulli"


class Scraper(BatoceraScraper):
    PLATFORM = PLATFORM_NAME
    REPO = "knulli-cfw/knulli-linux"
    BOARD_PREFIX = "knulli-"
    CONFIG_IN_PATH = "package/system/knulli-system/Config.in"
    ES_SYSTEMS_PATH = "package/emulationstation/knulli-es-system/es_systems.yml"
    SYSTEM_SYMBOL = "BR2_PACKAGE_KNULLI_SYSTEM"
    BUILDROOT_REPO = "knulli-cfw/buildroot"
    SUBMODULES = {"batocera/": "batocera-linux/batocera.linux"}
    RETROARCH_MK = "package/retroarch/retroarch/retroarch.mk"


def main() -> None:
    batocera_main(Scraper)


if __name__ == "__main__":
    main()
