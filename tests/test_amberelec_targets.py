"""AmberELEC's images differ by device, and only its metapackage says how.

packages/amberelec/package.mk adds LIBRETRO_CORES_EXTRA (melonDS, bsnes,
Mesen, geolith) on RG552, RG353 and RG503 and deletes those cores from
es_systems.cfg everywhere else. With no target list, an RG351P pack carried
the firmware of cores its image never had.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper.targets import amberelec_targets_scraper as scraper  # noqa: E402

MAKEFILE = """RG351P:
\tDEVICE=RG351P ARCH=aarch64 ./scripts/build_distro

RG552:
\tDEVICE=RG552 ARCH=aarch64 ./scripts/build_distro

toolchain-RK3326:
\tDEVICE=RK3326 ARCH=aarch64 ./scripts/build toolchain
"""

PACKAGE_MK = """  LIBRETRO_CORES_EXTRA="bsnes melonds"

  PKG_EMUS="${LIBRETRO_CORES}"

  if [[ "${DEVICE}" == "RG552" || "${DEVICE}" =~ ^(RG353|RG503)$ ]]; then
    PKG_EMUS+=" ${LIBRETRO_CORES_EXTRA}"
  fi

makeinstall_target() {
    for CORE in ${LIBRETRO_CORES_EXTRA}; do
      if [[ $CORE == "melonds" ]]; then
        sed -i -e '/<emulator name/{:a;N;/<\\/emulator>/!ba;/melonds/d}' es_systems.cfg
      fi
      sed -i "s|<core>$CORE</core>||g" es_systems.cfg
    done
}
"""

ES_SYSTEMS = """<systemList>
  <system>
    <name>snes</name>
    <emulators>
      <emulator name="retroarch">
        <cores>
          <core default="true">snes9x</core>
          <core>bsnes</core>
        </cores>
      </emulator>
    </emulators>
  </system>
  <system>
    <name>nds</name>
    <emulators>
      <emulator name="retroarch">
        <cores>
          <core>melonds</core>
        </cores>
      </emulator>
      <emulator name="drastic">
        <cores>
          <core default="true">drastic</core>
        </cores>
      </emulator>
    </emulators>
  </system>
</systemList>
"""


class TheMetapackageDecidesEachDevice(unittest.TestCase):
    def test_devices_are_the_images_the_makefile_builds(self):
        self.assertEqual(scraper.devices(MAKEFILE), {"RG351P": "aarch64", "RG552": "aarch64"})

    def test_the_extra_cores_and_their_devices(self):
        extra, keep = scraper.extra_cores(PACKAGE_MK)
        self.assertEqual(extra, ["bsnes", "melonds"])
        self.assertEqual(keep, {"RG552", "RG353", "RG503"})

    def test_a_device_without_them_loses_their_cores(self):
        extra, _keep = scraper.extra_cores(PACKAGE_MK)
        full = scraper.device_cores(ES_SYSTEMS, extra, True)
        lean = scraper.device_cores(ES_SYSTEMS, extra, False)
        self.assertEqual(set(full) - set(lean), {"bsnes", "melonds"})
        self.assertIn("drastic", lean)

    def test_a_changed_removal_stops_the_scrape(self):
        changed = PACKAGE_MK.replace('sed -i "s|<core>$CORE</core>||g"', "true")
        with self.assertRaises(RuntimeError):
            scraper.extra_cores(changed)


if __name__ == "__main__":
    unittest.main()
