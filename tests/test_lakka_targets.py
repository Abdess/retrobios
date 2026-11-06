"""Lakka's per-device core lists, read from its build files.

Without a target list a Lakka RPi1 pack carried the firmware of cores that
image does not build (beetle_psx, mupen64plus_next), and --target refused the
platform outright.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import unittest

from scripts.scraper.targets import lakka_targets_scraper as lakka

CORES_MK = '''PKG_NAME="libretro_cores"
LIBRETRO_CORES="\\
                2048 \\
                beetle_psx \\
                kronos \\
                lr_moonlight \\
                panda3ds \\
                snes9x \\
               "
EARLY_START_LR_CORES="snes9x"
for core in ${EARLY_START_LR_CORES} ; do
  LIBRETRO_CORES="${LIBRETRO_CORES// ${core} /}"
done
LIBRETRO_CORES="${EARLY_START_LR_CORES} ${LIBRETRO_CORES}"
if [ -n "${CUSTOM_LIBRETRO_CORES}" ]; then
  LIBRETRO_CORES="${CUSTOM_LIBRETRO_CORES}"
fi
if [ "${OPENGLES_SUPPORT}" = "yes" ]; then
  EXCLUDE_LIBRETRO_CORES+=" kronos"
fi
if [ "${PROJECT}" = "Generic" ]; then
  EXCLUDE_LIBRETRO_CORES+=" lr_moonlight"
elif [ "${PROJECT}" = "RPi" ]; then
  EXCLUDE_LIBRETRO_CORES+=" lr_moonlight"
  if [ "${DEVICE}" = "RPi" -o "${DEVICE}" = "RPiZero-GPiCase" ]; then
    EXCLUDE_LIBRETRO_CORES+=" beetle_psx \\
                              snes9x"
  elif [ "${DEVICE}" = "RPi2" ]; then
    EXCLUDE_LIBRETRO_CORES+=" panda3ds"
  fi
fi
'''

GENERIC_OPTIONS = '''  OPENGL="no"
  OPENGLES="mesa"
  if [ "${DISTRO}" = "Lakka" ]; then
    # Use OPENGL instead of OPENGLES
    OPENGL="mesa"
    OPENGLES="no"
  fi
'''


def _env(project: str, device: str, gles: str) -> dict[str, str]:
    return {"DISTRO": "Lakka", "PROJECT": project, "DEVICE": device,
            "ARCH": "arm", "OPENGLES_SUPPORT": gles}


class DeviceCores(unittest.TestCase):
    def test_the_rpi1_list_drops_its_exclusions(self):
        cores = lakka.device_cores(CORES_MK, _env("RPi", "RPi", "yes"))
        self.assertEqual(cores, ["2048", "panda3ds"])

    def test_a_gles_image_drops_kronos_and_a_desktop_one_keeps_it(self):
        self.assertNotIn("kronos", lakka.device_cores(CORES_MK, _env("RPi", "RPi4", "yes")))
        self.assertIn("kronos", lakka.device_cores(CORES_MK, _env("Generic", "Generic", "no")))

    def test_the_prepended_early_start_core_is_kept_once(self):
        cores = lakka.device_cores(CORES_MK, _env("RPi", "RPi4", "yes"))
        self.assertEqual(cores.count("snes9x"), 1)


class OptionsEvaluation(unittest.TestCase):
    def test_lakka_overrides_generic_to_desktop_gl(self):
        env = lakka.evaluate(GENERIC_OPTIONS, {"DISTRO": "Lakka"})
        self.assertEqual(env["OPENGLES"], "no")

    def test_an_unknown_condition_is_harmless_where_nothing_watched_changes(self):
        text = 'if [ "${DEBUG}" = "no" ]; then\n  TARGET_CPU="x"\nfi\n  OPENGLES="mesa"\n'
        self.assertEqual(lakka.evaluate(text, {})["OPENGLES"], "mesa")

    def test_an_unknown_condition_deciding_a_watched_value_stops(self):
        text = 'if [ "${DEBUG}" = "no" ]; then\n  OPENGLES="mesa"\nfi\n'
        with self.assertRaises(lakka.ShellSubsetError):
            lakka.evaluate(text, {})

    def test_a_watched_value_set_in_a_case_stops(self):
        text = 'case $TARGET_ARCH in\n  arm)\n    OPENGLES="mesa"\n    ;;\nesac\n'
        with self.assertRaises(lakka.ShellSubsetError):
            lakka.evaluate(text, {})


class Architecture(unittest.TestCase):
    def test_aarch64_where_listed_else_arm(self):
        self.assertEqual(lakka.device_arch("RPi", "case $TARGET_ARCH in\n  aarch64)\n"), "aarch64")
        self.assertEqual(lakka.device_arch("RPi", "case $TARGET_ARCH in\n  arm)\n"), "arm")
        self.assertEqual(lakka.device_arch("Generic", ""), "x86_64")


if __name__ == "__main__":
    unittest.main()
