"""A target scraper that cannot read its source writes nothing.

The EmuDeck, RetroPie and RetroArch scrapers turned a failed request (an
anonymous API quota, a moved buildbot directory) into an empty core list
and wrote the file anyway: a target vanished, or kept no cores, and the
packs built for it shrank without an error.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.scraper.targets import (  # noqa: E402
    batocera_targets_scraper,
    emudeck_targets_scraper,
    retroarch_targets_scraper,
    retropie_targets_scraper,
)


def _refuse(*_args, **_kwargs):
    raise urllib.error.HTTPError("https://api.github.com/x", 403, "rate limited", {}, None)


class FailedRequestsStopTheScrape(unittest.TestCase):
    def test_every_scraper_raises(self):
        for module in (
            batocera_targets_scraper,
            emudeck_targets_scraper,
            retropie_targets_scraper,
            retroarch_targets_scraper,
        ):
            with self.subTest(scraper=module.__name__), mock.patch.object(
                module.urllib.request, "urlopen", _refuse
            ), self.assertRaises(RuntimeError):
                module.Scraper().fetch_targets()

    def test_an_empty_listing_is_not_a_target(self):
        class _Empty:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"[]"

        for module in (emudeck_targets_scraper, retropie_targets_scraper):
            with self.subTest(scraper=module.__name__), mock.patch.object(
                module.urllib.request, "urlopen", lambda *_a, **_k: _Empty()
            ), self.assertRaises(RuntimeError):
                module.Scraper().fetch_targets()

    def test_batocera_needs_its_boards(self):
        """No board listed, or one board unreadable, used to print a warning
        and write the targets file without those boards."""

        class _Body:
            def __init__(self, body: bytes):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return self.body

        def serve(boards: list[str], refuse_board: bool):
            def urlopen(request, *_a, **_k):
                url = request.full_url
                if "/tags" in url:
                    return _Body(b'[{"name": "batocera-43"}]')
                if "/contents/configs" in url:
                    return _Body(json.dumps([{"name": b} for b in boards]).encode())
                if "/contents/buildroot" in url:
                    return _Body(b'{"sha": "0123abc"}')
                if url.endswith("x86_wow64.board"):
                    # Builds the 32-bit Wine package, not an image.
                    return _Body(b"BR2_PACKAGE_BATOCERA_TARGET_X86=y\n")
                if url.endswith(".board"):
                    if refuse_board:
                        _refuse()
                    return _Body(b"BR2_PACKAGE_BATOCERA_TARGET_X86_64=y\n"
                                 b"BR2_PACKAGE_BATOCERA_SYSTEM=y\n")
                if "/git/trees/" in url:
                    return _Body(b'{"tree": [], "truncated": false}')
                if url.endswith("retroarch.mk"):
                    return _Body(b"RETROARCH_CONF_OPTS = --enable-networking\n")
                if url.startswith("https://raw.githubusercontent.com/") and url.count("/") == 6:
                    return _Body(b'source "$BR2_EXTERNAL_BATOCERA_PATH/'
                                 b'package/batocera/core/batocera-system/Config.in"\n')
                if url.endswith("Config.in"):
                    return _Body(b"config BR2_PACKAGE_BATOCERA_SYSTEM\n"
                                 b"\tselect BR2_PACKAGE_MGBA\n\n"
                                 b"config BR2_TARGET_BATOCERA_IMAGES\n\tstring \"x\"\n"
                                 b"\tdefault \"x86_64\" if BR2_PACKAGE_BATOCERA_TARGET_X86_64\n")
                return _Body(
                    b"gba:\n  emulators:\n    libretro:\n"
                    b"      mgba: {requireAnyOf: [BR2_PACKAGE_MGBA]}\n"
                )

            return urlopen

        for boards, refuse_board in (([], False), (["batocera-x86_64.board"], True)):
            with self.subTest(boards=boards), mock.patch.object(
                batocera_targets_scraper.urllib.request,
                "urlopen",
                serve(boards, refuse_board),
            ), self.assertRaises(RuntimeError):
                batocera_targets_scraper.Scraper().fetch_targets()

        with mock.patch.object(
            batocera_targets_scraper.urllib.request,
            "urlopen",
            serve(["batocera-x86_64.board", "batocera-x86_wow64.board"], False),
        ):
            targets = batocera_targets_scraper.Scraper().fetch_targets()["targets"]
        self.assertEqual(targets["x86_64"]["cores"], ["mgba"])
        self.assertNotIn("x86_wow64", targets)


class BatoceraKconfig(unittest.TestCase):
    """The Batocera target scraper read every select as unconditional and
    never set a symbol Buildroot sets: 171 cores on almost every board, and
    xroar ("if BR2_PACKAGE_HAS_LIBGL") on none, so --target x86_64 dropped
    the CoCo and Dragon systems."""

    CONFIG_IN = (
        "if BR2_PACKAGE_BATOCERA_TARGET_X86_64\n"
        "\tconfig BR2_PACKAGE_BATOCERA_TARGET_X86_64_ANY\n\tdefault y\nendif\n\n"
        "config BR2_PACKAGE_BATOCERA_SYSTEM\n"
        "\tselect BR2_PACKAGE_BATOCERA_XORG\tif BR2_PACKAGE_BATOCERA_TARGET_X86_64_ANY\n"
        "\tselect BR2_PACKAGE_XROAR\t\tif BR2_PACKAGE_HAS_LIBGL # needs OpenGL\n"
        "\tselect BR2_PACKAGE_RUFFLE\tif BR2_PACKAGE_XORG7 && \\\n"
        "\t\t\t\tBR2_ARCH_IS_64\n\n"
        "config BR2_PACKAGE_BATOCERA_XORG\n"
        "\tselect BR2_PACKAGE_XORG7\n"
        "\tselect BR2_PACKAGE_MESA3D_OPENGL_GLX if BR2_PACKAGE_XORG7\n"
        "\tselect BR2_PACKAGE_LIBGLVND if BR2_PACKAGE_XORG7\n\n"
        "config BR2_PACKAGE_BATOCERA_CORES_EXPERIMENTAL\n"
        "\tselect BR2_PACKAGE_APPLEWIN\n"
    )
    BUILDROOT = (
        "config BR2_x86_64\n\tbool \"x86_64\"\n\tselect BR2_ARCH_IS_64\n"
        "config BR2_PACKAGE_MESA3D_OPENGL_GLX\n"
        "\tselect BR2_PACKAGE_HAS_LIBGL if !BR2_PACKAGE_LIBGLVND\n"
        "\tselect BR2_PACKAGE_LIBGLVND_DISPATCH_GL if BR2_PACKAGE_LIBGLVND\n"
        "config BR2_PACKAGE_LIBGLVND_DISPATCH_GL\n\tselect BR2_PACKAGE_HAS_LIBGL\n"
    )

    def active(self, board: set[str]) -> frozenset[str]:
        from scraper.targets.batocera_targets_scraper import (  # noqa: PLC0415
            _active_symbols,
            _parse_meta_flags,
            _parse_owned_selects,
        )

        rules = _parse_owned_selects(self.CONFIG_IN) + _parse_owned_selects(self.BUILDROOT)
        return _active_symbols(board, _parse_meta_flags(self.CONFIG_IN), rules)

    def test_x86_64_gets_opengl_and_its_cores(self):
        active = self.active({"BR2_x86_64", "BR2_PACKAGE_BATOCERA_TARGET_X86_64",
                              "BR2_PACKAGE_BATOCERA_SYSTEM"})
        self.assertIn("BR2_PACKAGE_HAS_LIBGL", active)
        self.assertIn("BR2_PACKAGE_XROAR", active)
        self.assertIn("BR2_PACKAGE_RUFFLE", active)
        self.assertNotIn("BR2_PACKAGE_APPLEWIN", active)

    def test_a_board_without_x11_gets_none_of_it(self):
        active = self.active({"BR2_aarch64", "BR2_PACKAGE_BATOCERA_TARGET_RK3588",
                              "BR2_PACKAGE_BATOCERA_SYSTEM"})
        self.assertFalse({"BR2_PACKAGE_XORG7", "BR2_PACKAGE_XROAR",
                          "BR2_PACKAGE_RUFFLE"} & active)


class BatoceraDerivedFlags(unittest.TestCase):
    """A condition continued with a backslash was cut at its first line:
    "BR2_PACKAGE_BATOCERA_TARGET_X86_ANY ||" held on every board, so GLES3
    did too, and a GLES2 Raspberry Pi got yabasanshiro and eduke32. A block
    whose config is not a package (KNULLI's BR2_KERNEL_LEGACY_3_10) sent
    the regex backtracking without end."""

    CONFIG_IN = (
        "if BR2_PACKAGE_BATOCERA_TARGET_X86_64 || \\\n"
        "   BR2_PACKAGE_BATOCERA_TARGET_H700\n"
        "\tconfig BR2_PACKAGE_BATOCERA_GLES3\n\tbool \"gles3\"\n\tdefault y\nendif\n\n"
        "if BR2_PACKAGE_BATOCERA_TARGET_SUNXI_R16\n"
        "        config BR2_KERNEL_LEGACY_3_10\n        default y\nendif\n\n"
        + "config BR2_PACKAGE_FILLER\n\tbool \"filler\"\n" * 400
        + "config BR2_PACKAGE_BATOCERA_SYSTEM\n"
        "\tselect BR2_PACKAGE_EDUKE32\tif BR2_PACKAGE_BATOCERA_GLES3\n"
        "\tselect BR2_PACKAGE_DUCKSTATION_LEGACY\tif !BR2_PACKAGE_BATOCERA_GLES3\n"
    )

    def active(self, board: set[str]) -> frozenset[str]:
        from scraper.targets.batocera_targets_scraper import (  # noqa: PLC0415
            _active_symbols,
            _parse_meta_flags,
            _parse_owned_selects,
        )

        return _active_symbols(
            board | {"BR2_PACKAGE_BATOCERA_SYSTEM"},
            _parse_meta_flags(self.CONFIG_IN),
            _parse_owned_selects(self.CONFIG_IN),
        )

    def test_a_continued_condition_keeps_its_later_lines(self):
        from scraper.targets.batocera_targets_scraper import (  # noqa: PLC0415
            _parse_meta_flags,
        )

        rules = dict(_parse_meta_flags(self.CONFIG_IN))
        self.assertIn("BR2_PACKAGE_BATOCERA_TARGET_H700", rules["BR2_PACKAGE_BATOCERA_GLES3"])
        self.assertEqual(rules["BR2_KERNEL_LEGACY_3_10"],
                         "BR2_PACKAGE_BATOCERA_TARGET_SUNXI_R16")

    def test_gles3_follows_the_board(self):
        h700 = self.active({"BR2_PACKAGE_BATOCERA_TARGET_H700"})
        self.assertIn("BR2_PACKAGE_EDUKE32", h700)
        r16 = self.active({"BR2_PACKAGE_BATOCERA_TARGET_SUNXI_R16"})
        self.assertNotIn("BR2_PACKAGE_BATOCERA_GLES3", r16)
        self.assertNotIn("BR2_PACKAGE_EDUKE32", r16)

    def test_a_negated_select_drops_once_the_flag_is_derived(self):
        """GLES3 is derived on the first pass, after which `!GLES3` no
        longer holds: accumulating kept duckstation-legacy on every GLES3
        board."""
        h700 = self.active({"BR2_PACKAGE_BATOCERA_TARGET_H700"})
        self.assertNotIn("BR2_PACKAGE_DUCKSTATION_LEGACY", h700)
        r16 = self.active({"BR2_PACKAGE_BATOCERA_TARGET_SUNXI_R16"})
        self.assertIn("BR2_PACKAGE_DUCKSTATION_LEGACY", r16)


class CoreDownloaderReach(unittest.TestCase):
    """Batocera and KNULLI build RetroArch with its core downloader, shown in
    the menu, and its compiled buildbot URL serves Linux x86_64, i386 and
    armv7 hard-float alone (config.def.h:743-749, 1855-1864): a board of
    those runs any core of the buildbot list, an aarch64 one none."""

    def test_each_architecture_reads_its_buildbot_list(self):
        from scraper.targets.batocera_targets_scraper import buildbot_target  # noqa: PLC0415

        self.assertEqual(buildbot_target({"BR2_x86_64"}), "linux-x86_64")
        self.assertEqual(buildbot_target({"BR2_arm", "BR2_ARM_CPU_ARMV7A"}), "linux-armhf")
        self.assertIsNone(buildbot_target({"BR2_arm", "BR2_ARM_CPU_ARMV7A", "BR2_ARM_EABI"}))
        self.assertIsNone(buildbot_target({"BR2_arm", "BR2_arm1176jzf_s"}))
        self.assertIsNone(buildbot_target({"BR2_aarch64"}))

    def test_a_build_or_a_blank_url_turns_it_off(self):
        from scraper.targets.batocera_targets_scraper import downloader_disabled  # noqa: PLC0415

        self.assertIsNone(downloader_disabled("--enable-networking", {
            "a/retroarch.cfg": 'menu_show_core_updater = "false"\n'}))
        self.assertIn("HAVE_LAKKA=1", downloader_disabled("make HAVE_LAKKA=1", {}))
        with self.assertRaises(RuntimeError):
            downloader_disabled("", {"a/retroarch.cfg": 'core_updater_buildbot_cores_url = ""\n'})

    def test_a_board_that_downloads_gets_the_buildbot_list(self):
        from common import load_target_config  # noqa: PLC0415

        root = str(REPO_ROOT / "platforms")
        x86 = set(load_target_config("retroarch", "linux-x86_64", root) or ())
        armhf = set(load_target_config("retroarch", "linux-armhf", root) or ())
        self.assertLessEqual(x86, set(load_target_config("batocera", "x86_64", root) or ()))
        self.assertLessEqual(armhf, set(load_target_config("batocera", "rk3288", root) or ()))
        self.assertFalse(x86 <= set(load_target_config("batocera", "bcm2711", root) or ()))
        self.assertLessEqual(armhf, set(load_target_config("knulli", "r16", root) or ()))

    def test_the_platform_names_what_its_boards_install(self):
        import yaml  # noqa: PLC0415

        from common import load_target_config  # noqa: PLC0415

        root = str(REPO_ROOT / "platforms")
        for platform in ("batocera", "knulli"):
            config = yaml.safe_load((REPO_ROOT / "platforms" / f"{platform}.yml").read_text())
            targets = yaml.safe_load(
                (REPO_ROOT / "platforms" / "targets" / f"{platform}.yml").read_text())["targets"]
            fetched = set()
            for entry in targets.values():
                if entry.get("downloads"):
                    fetched |= load_target_config("retroarch", entry["downloads"], root) or set()
                if entry["architecture"] == "aarch64":
                    self.assertNotIn("downloads", entry)
            with self.subTest(platform=platform):
                self.assertEqual(set(config["installable_cores"]), fetched - set(config["cores"]))


class KnulliPerBoard(unittest.TestCase):
    """KNULLI builds per board on Batocera's model from its own tree:
    configs/knulli-*.board, package/system/knulli-system/Config.in and
    package/emulationstation/knulli-es-system/es_systems.yml, with
    BR2_PACKAGE_KNULLI_SYSTEM as the config every image turns on."""

    FILES = {
        "configs/knulli-board.common": "BR2_PACKAGE_KNULLI_SYSTEM=y\n",
        "configs/knulli-board.libs": "BR2_PACKAGE_BATOCERA_SYSTEM=n\n",
        "configs/knulli-h700.board": (
            "include knulli-board.common\n\nBR2_aarch64=y\n"
            "BR2_PACKAGE_BATOCERA_TARGET_H700=y\n"
        ),
        "configs/knulli-r16.board": (
            "include knulli-board.common\n\nBR2_arm=y\nBR2_cortex_a7=y\n"
            "BR2_PACKAGE_BATOCERA_TARGET_SUNXI_R16=y\n"
        ),
        "configs/knulli-h700_armhf_libs.board": (
            "include knulli-board.libs\ninclude knulli-h700_armhf_libs.packages\n"
            "BR2_arm=y\nBR2_PACKAGE_BATOCERA_TARGET_H700=y\n"
        ),
        "configs/knulli-h700_armhf_libs.packages": "BR2_PACKAGE_SDL2=y\n",
        # The root Config.in sources KNULLI's system and Batocera's packages
        # from the batocera submodule, where a package selects another.
        "Config.in": (
            'source "$BR2_EXTERNAL_KNULLI_PATH/package/system/knulli-system/Config.in"\n'
            'source "$BR2_EXTERNAL_KNULLI_PATH/batocera/package/batocera/emulators/'
            'ppsspp/Config.in"\n'
            '#source "$BR2_EXTERNAL_KNULLI_PATH/package/utils/off/Config.in"\n'
            'source "$BR2_EXTERNAL_KNULLI_PATH/package/utils/vtree/Config.in"\n'
        ),
        "package/system/knulli-system/Config.in": (
            "if BR2_PACKAGE_BATOCERA_TARGET_H700 || \\\n"
            "   BR2_PACKAGE_BATOCERA_TARGET_A133\n"
            "\tconfig BR2_PACKAGE_BATOCERA_GLES3\n\tdefault y\nendif\n\n"
            "config BR2_PACKAGE_KNULLI_SYSTEM\n"
            "\tselect BR2_PACKAGE_LIBRETRO_MGBA\n"
            "\tselect BR2_PACKAGE_PPSSPP\tif BR2_PACKAGE_BATOCERA_GLES3\n\n"
            "config BR2_TARGET_KNULLI_IMAGES_DEFINITIONS\n"
            "\tbool \"target images definitions\"\n"
            "\tconfig BR2_TARGET_KNULLI_IMAGES\n\tstring \"target images\"\n"
            "\tdefault \"allwinner/h700/rg35xx-sp allwinner/h700/rg35xx-plus\" \\\n"
            "\t\tif BR2_PACKAGE_BATOCERA_TARGET_H700\n"
            "\tdefault \"allwinner/r16/miyoo-a30\"\tif BR2_PACKAGE_BATOCERA_TARGET_SUNXI_R16\n\n"
            "\tchoice\n\tprompt \"knulli target\"\n"
        ),
        "package/emulationstation/knulli-es-system/es_systems.yml": (
            "gba:\n  emulators:\n    libretro:\n"
            "      mgba: {requireAnyOf: [BR2_PACKAGE_LIBRETRO_MGBA]}\n"
            "psp:\n  emulators:\n    ppsspp:\n"
            "      ppsspp: {requireAnyOf: [BR2_PACKAGE_PPSSPP]}\n"
            "pspassets:\n  emulators:\n    libretro:\n"
            "      assets: {requireAnyOf: [BR2_PACKAGE_PPSSPP_ASSETS]}\n"
        ),
    }

    def test_each_board_gets_its_own_cores(self):
        from scripts.scraper.targets import knulli_targets_scraper  # noqa: PLC0415

        pin = knulli_targets_scraper.Scraper.pinned_revision("knulli")
        raw = f"https://raw.githubusercontent.com/knulli-cfw/knulli-linux/{pin}/"
        api = "https://api.github.com/repos/knulli-cfw/knulli-linux/contents/"
        seen: list[str] = []

        class _Body:
            def __init__(self, body: str):
                self.body = body.encode()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return self.body

        def urlopen(request, *_a, **_k):
            url = request.full_url
            seen.append(url)
            if url == f"{api}configs?ref={pin}":
                names = [p.removeprefix("configs/") for p in self.FILES if p.startswith("configs/")]
                return _Body(json.dumps([{"name": n} for n in names]))
            if url == f"{api}buildroot?ref={pin}":
                return _Body('{"sha": "c2d7985b"}')
            if url == f"{api}batocera?ref={pin}":
                return _Body('{"sha": "487014d9"}')
            if "/git/trees/" in url:
                # A board config that hides the downloader leaves its URL.
                cfg = "board/r16/retroarch.cfg" if "knulli-linux" in url else "x"
                return _Body(json.dumps({"tree": [{"path": cfg}], "truncated": False}))
            if url == f"{raw}board/r16/retroarch.cfg":
                return _Body('menu_show_core_updater = "false"\n')
            if url == f"{raw}package/retroarch/retroarch/retroarch.mk":
                return _Body("RETROARCH_CONF_OPTS = --enable-networking\n")
            if url == ("https://raw.githubusercontent.com/batocera-linux/batocera.linux/"
                       "487014d9/package/batocera/emulators/ppsspp/Config.in"):
                return _Body("config BR2_PACKAGE_PPSSPP\n\tselect BR2_PACKAGE_PPSSPP_ASSETS\n")
            if url == f"{raw}package/utils/vtree/Config.in":
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            if url.endswith("/c2d7985b/arch/Config.in.arm"):
                return _Body("config BR2_cortex_a7\n\tselect BR2_ARM_CPU_ARMV7A\n")
            if url.startswith("https://raw.githubusercontent.com/knulli-cfw/buildroot/c2d7985b/"):
                return _Body("config BR2_aarch64\n\tselect BR2_ARCH_IS_64\n")
            path = url.removeprefix(raw)
            if path in self.FILES:
                return _Body(self.FILES[path])
            _refuse()

        with mock.patch.object(batocera_targets_scraper.urllib.request, "urlopen", urlopen):
            data = knulli_targets_scraper.Scraper().fetch_targets()

        self.assertEqual(data["platform"], "knulli")
        self.assertEqual(data["source"],
                         f"https://github.com/knulli-cfw/knulli-linux/tree/{pin}")
        self.assertEqual(sorted(data["targets"]), ["h700", "r16"])
        # The images name what a card's boot/knulli.board holds.
        self.assertEqual(data["targets"]["h700"],
                         {"architecture": "aarch64", "cores": ["assets", "mgba", "ppsspp"],
                          "images": ["rg35xx-plus", "rg35xx-sp"]})
        # An armv7 hard-float board's RetroArch installs the armhf buildbot list.
        self.assertEqual(data["targets"]["r16"],
                         {"architecture": "arm", "cores": ["mgba"], "images": ["miyoo-a30"],
                          "downloads": "linux-armhf"})
        self.assertTrue(all(pin in url or "buildroot/c2d7985b" in url
                            or "487014d9" in url for url in seen), seen)


class RocknixPerDevice(unittest.TestCase):
    """ROCKNIX had no target list: an H700 handheld got the PS2, GameCube
    and PS3 firmware of emulators its image does not carry."""

    PACKAGE_MK = (
        'PKG_EMUS="amiberry duckstation-sa hatarisa"\n'
        'EMUS_32BIT=""\n'
        'LIBRETRO_CORES="81-lr beetle-psx-lr \\\n'
        '                neocd_lr idtech-lr"\n'
        'if [ "${ARCH}" = "aarch64" ]; then\n'
        '  LIBRETRO_CORES+=" duckstation-lr"\n'
        'fi\n'
        'case "${DEVICE}" in\n'
        '  H700|RK3326)\n'
        '    [ "${ENABLE_32BIT}" == "true" ] && EMUS_32BIT="box86 gpsp-lr"\n'
        '    PKG_EMUS+=" drastic-sa"\n'
        '    ;;\n'
        '  SM8550)\n'
        '    PKG_EMUS+=" aethersx2-sa dolphin-sa"\n'
        '    ;;\n'
        '  AMD64)\n'
        '    PKG_EMUS+=" dolphin-sa"\n'
        'esac\n'
    )
    IDTECH = (
        'if [ "${OPENGLES_SUPPORT}" = yes ]; then\n'
        '  PKG_DEPENDS_TARGET+=" ecwolf-lr prboom-lr"\n'
        'fi\n'
        'if [ "${TARGET_ARCH}" = "x86_64" ]; then\n'
        '  PKG_DEPENDS_TARGET+=" vitaquake3-lr"\n'
        'fi\n'
    )

    def test_each_device_gets_its_own_cores(self):
        from scraper.targets.rocknix_targets_scraper import parse_device_cores  # noqa: PLC0415

        libretro, standalone = parse_device_cores(self.PACKAGE_MK, "H700", "aarch64", True)
        self.assertTrue({"gpsp-lr", "duckstation-lr", "beetle-psx-lr", "81-lr",
                         "neocd_lr"} <= set(libretro))
        self.assertTrue({"drastic-sa", "hatarisa"} <= set(standalone))
        self.assertFalse({"aethersx2-sa", "dolphin-sa"} & set(standalone))
        libretro, _ = parse_device_cores(self.PACKAGE_MK, "H700", "aarch64", False)
        self.assertNotIn("gpsp-lr", libretro)
        _, standalone = parse_device_cores(self.PACKAGE_MK, "AMD64", "x86_64", False)
        self.assertIn("dolphin-sa", standalone)
        self.assertNotIn("drastic-sa", standalone)

    def test_a_package_names_the_cores_it_installs(self):
        """vice-lr builds ten EMUTYPEs: read as the package name, vice_x64
        and its siblings reached no ROCKNIX device."""
        from scraper.targets.rocknix_targets_scraper import installed_cores  # noqa: PLC0415

        vice = ("makeinstall_target() {\n  mkdir -p ${INSTALL}/usr/lib/libretro\n"
                "    cp -a built/vice_x128_libretro.so ${INSTALL}/usr/lib/libretro\n"
                "    cp -a built/vice_x64_libretro.so ${INSTALL}/usr/lib/libretro\n}\n")
        self.assertEqual(installed_cores(vice, "aarch64", True), ["vice_x128", "vice_x64"])
        renamed = ("makeinstall_target() {\n"
                   "    cp -a mednafen_psx_libretro.so ${INSTALL}/usr/lib/libretro/beetle_psx_libretro.so\n"
                   "    cp -a fake08_libretro.{so,info} $INSTALL/usr/lib/libretro\n}\n")
        self.assertEqual(installed_cores(renamed, "aarch64", True), ["beetle_psx", "fake08"])
        pcsx = ("makeinstall_target() {\n"
                "    case ${TARGET_ARCH} in\n"
                "      aarch64|x86_64) cp -a ../pcsx_rearmed_libretro.so ${INSTALL}/usr/lib/libretro ;;\n"
                "      arm) cp -a ../pcsx_rearmed_libretro.so ${INSTALL}/usr/lib/libretro/pcsx_rearmed32_libretro.so ;;\n"
                "    esac\n"
                '    if [ "${TARGET_ARCH}" = "aarch64" ] && [ "${ENABLE_32BIT}" = "true" ]; then\n'
                "      cp -a x/usr/lib/libretro/pcsx_rearmed32_libretro.so ${INSTALL}/usr/lib/libretro\n"
                "    fi\n}\n")
        self.assertEqual(installed_cores(pcsx, "aarch64", True), ["pcsx_rearmed", "pcsx_rearmed32"])
        self.assertEqual(installed_cores(pcsx, "aarch64", False), ["pcsx_rearmed"])
        self.assertEqual(installed_cores(pcsx, "x86_64", True), ["pcsx_rearmed"])
        with self.assertRaises(RuntimeError):
            installed_cores('makeinstall_target() {\n  if [ "${DEVICE}" = "H700" ]; then\n'
                            "    cp a_libretro.so ${INSTALL}/usr/lib/libretro\n  fi\n}\n",
                            "aarch64", True)
        with self.assertRaises(RuntimeError):
            installed_cores("makeinstall_target() {\n  :\n}\n", "aarch64", True)

    def test_a_standalone_package_keeps_both_spellings(self):
        """vice-standalone answers to vice-sa only, as scummvm-standalone to
        scummvm-sa: stripped to vice, every targeted pack left them out
        while the untargeted one, read from the platform scraper, kept them."""
        from scraper.rocknix_scraper import standalone_emulators  # noqa: PLC0415
        from scraper.targets.rocknix_targets_scraper import parse_device_cores  # noqa: PLC0415

        _, standalone = parse_device_cores(self.PACKAGE_MK, "SM8550", "aarch64", False)
        names = set(standalone_emulators(standalone))
        self.assertTrue({"aethersx2-sa", "aethersx2", "dolphin-sa", "dolphin"} <= names)

    def test_a_metapackage_names_the_cores_it_installs(self):
        from scraper.targets.rocknix_targets_scraper import metapackage_cores  # noqa: PLC0415

        self.assertEqual(metapackage_cores(self.IDTECH, "aarch64"), ["ecwolf-lr", "prboom-lr"])
        self.assertEqual(metapackage_cores(self.IDTECH, "x86_64"),
                         ["ecwolf-lr", "prboom-lr", "vitaquake3-lr"])


class RecalboxPerBoard(unittest.TestCase):
    """Recalbox had no target list: a Raspberry Pi 3 pack carried the
    firmware of emulators only its x86_64 image builds."""

    SYSTEM_INI = (
        "[core.0]\npackage = BR2_PACKAGE_PCSX2\nemulator = \"pcsx2\"\ncore = \"pcsx2\"\n"
        "[core.1]\npackage = BR2_PACKAGE_LIBRETRO_PCSX_REARMED\nemulator = \"libretro\"\n"
        "core = \"pcsx_rearmed\"\npackage.rpi3 = BR2_PACKAGE_LIBRETRO_PCSX_REARMED_NEON\n"
        "[core.2]\npackage = BR2_PACKAGE_LIBRETRO_SWANSTATION\nemulator = \"libretro\"\n"
        "core = \"swanstation\"\n"
        "[core.2.rpi3]\npackage = BR2_PACKAGE_LIBRETRO_DUCKSTATION\nemulator = \"libretro\"\n"
        "core = \"duckstation\"\n"
    )

    def test_a_board_gets_the_cores_its_defconfig_builds(self):
        from scraper.recalbox_scraper import board_cores  # noqa: PLC0415
        from scraper.targets.recalbox_targets_scraper import (  # noqa: PLC0415
            defconfig_arch,
            enabled_packages,
        )

        x86 = enabled_packages("BR2_x86_64=y\nBR2_PACKAGE_PCSX2=y\n"
                               "BR2_PACKAGE_LIBRETRO_PCSX_REARMED=y\n"
                               "BR2_PACKAGE_LIBRETRO_SWANSTATION=y\n# BR2_PACKAGE_X is not set\n")
        self.assertEqual(board_cores(self.SYSTEM_INI, "x86_64", x86),
                         {"pcsx2", "pcsx_rearmed", "swanstation"})
        rpi3 = enabled_packages("BR2_arm=y\nBR2_PACKAGE_LIBRETRO_PCSX_REARMED_NEON=y\n"
                                "BR2_PACKAGE_LIBRETRO_DUCKSTATION=y\n")
        self.assertEqual(board_cores(self.SYSTEM_INI, "rpi3", rpi3),
                         {"pcsx_rearmed", "duckstation"})
        self.assertEqual(defconfig_arch("BR2_arm=y\n"), "armhf")
        self.assertEqual(defconfig_arch("BR2_aarch64=y\n"), "aarch64")

    def test_board_sections_read_key_by_key_as_romfs_does(self):
        from scraper.recalbox_scraper import board_cores  # noqa: PLC0415

        ini = (
            "[core.0]\npackage = BR2_PACKAGE_LIBRETRO_GAMBATTE\nemulator = \"libretro\"\n"
            "core = \"gambatte\"\n"
            "[core.0.x86_64]\npriority = 2\n"
            "[core.5.x86_64]\npackage = BR2_PACKAGE_LIBRETRO_BSNES\nemulator = \"libretro\"\n"
            "core = \"bsnes\"\n"
        )
        enabled = {"BR2_PACKAGE_LIBRETRO_GAMBATTE", "BR2_PACKAGE_LIBRETRO_BSNES"}
        self.assertEqual(board_cores(ini, "x86_64", enabled), {"gambatte", "bsnes"})
        self.assertEqual(board_cores(ini, "rpi3", enabled), {"gambatte"})


class RetroPieModuleFlags(unittest.TestCase):
    """The RetroPie target list read flags as requirements and libretro alone.

    sdl1 and sdl2 are build options, not hardware: read as requirements they
    removed dosbox, atari800 and linapple from every target, and with only
    scriptmodules/libretrocores listed, no standalone package (openmsx,
    xroar, amiberry) reached a targeted pack at all.
    """

    def test_flags_follow_rp_register_module(self):
        available = retropie_targets_scraper._is_available
        cases = {
            ("sdl1 !mali", "rpi4"): True,
            ("!all videocore", "rpi3"): True,
            ("!all videocore", "rpi4"): False,
            ("!armv6 !videocore !:\\$__gcc_version:-lt:9", "rpi3"): False,
            ("!armv6 !videocore !:\\$__gcc_version:-lt:9", "rpi4"): True,
            ("!all x86", "rpi4"): False,
            ("!all x86", "x86_64"): True,
            ("!all arm rpi3 rpi4 rpi5 x86", "rpi1"): True,
        }
        for (flags, platform), expected in cases.items():
            with self.subTest(flags=flags, platform=platform):
                self.assertIs(available(flags, platform), expected)

    def test_standalone_sections_are_listed_and_keep_their_id(self):
        listings = {
            "emulators": [{"name": "dosbox-staging.sh"}, {"name": "dosbox.sh"}],
            "libretrocores": [{"name": "lr-beetle-psx.sh"}, {"name": "lr-dosbox.sh"}],
            "ports": [{"name": "openbor.sh"}],
        }
        modules = {
            "emulators/dosbox-staging.sh": 'rp_module_id="dosbox-staging"\nrp_module_flags="sdl2"',
            "libretrocores/lr-beetle-psx.sh": 'rp_module_id="lr-beetle-psx"',
            "libretrocores/lr-dosbox.sh": 'rp_module_id="lr-dosbox"',
            "emulators/dosbox.sh": 'rp_module_id="dosbox"\nrp_module_flags="sdl1 !mali"',
            "ports/openbor.sh": 'rp_module_id="openbor"\nrp_module_flags="sdl1 !mali !x11"',
        }

        def fake_fetch(url, **_kwargs):
            section = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
            if section in listings:
                return json.dumps(listings[section])
            return modules[url.split("scriptmodules/", 1)[1]]

        with mock.patch.object(retropie_targets_scraper, "_fetch", fake_fetch):
            targets = retropie_targets_scraper.Scraper().fetch_targets()["targets"]
        self.assertEqual(
            targets["rpi4"]["cores"], ["beetle_psx", "dosbox", "dosbox-staging", "openbor"]
        )
        self.assertEqual(targets["x86_64"]["cores"], ["beetle_psx", "dosbox", "dosbox-staging"])



class TargetsReadThePlatformRevision(unittest.TestCase):
    """A target list read on master filtered packages by flags the pinned
    package list does not have: every request names the platform's pin."""

    def _urls(self, module, scraper) -> list[str]:
        seen: list[str] = []

        def record(url, **_kwargs):
            seen.append(url)
            if "contents" in url:
                return json.dumps([{"name": "lr-mgba.sh"}])
            return 'rp_module_id="lr-mgba"'

        with mock.patch.object(module, "_fetch", record):
            scraper.fetch_targets()
        return seen

    def test_retropie_reads_its_codeload_pin(self):
        pin = retropie_targets_scraper.Scraper.pinned_revision("retropie")
        self.assertRegex(pin, r"^[0-9a-f]{40}$")
        urls = self._urls(retropie_targets_scraper, retropie_targets_scraper.Scraper())
        self.assertTrue(urls)
        self.assertTrue(all(pin in url for url in urls), urls)

    def test_emudeck_steamos_reads_its_pin(self):
        pin = emudeck_targets_scraper.Scraper.pinned_revision("emudeck")
        scraper = emudeck_targets_scraper.Scraper()
        with mock.patch.object(scraper, "_load_retroarch_cores", return_value=[]):
            urls = self._urls(emudeck_targets_scraper, scraper)
        steamos = [u for u in urls if "dragoonDorise" in u]
        self.assertTrue(steamos)
        self.assertTrue(all(u.endswith(f"?ref={pin}") for u in steamos), steamos)

    def test_emudeck_platform_lists_its_installers_at_the_pin(self):
        """cores: was read on master while launchers: and the SteamOS target
        were read at the pin: the YAML described two revisions."""
        from scripts.scraper import emudeck_scraper

        pin = "d" * 40
        seen: list[str] = []

        class _Body:
            def __init__(self, url):
                seen.append(url)

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

            def read(self):
                return json.dumps([{"name": "emuDeckRMG.sh"}]).encode()

        with mock.patch("urllib.request.urlopen", lambda req, **_kw: _Body(req.full_url)):
            cores = emudeck_scraper.Scraper(checkbios_url="pinned")._fetch_installed_emulators(pin)
        self.assertEqual(cores, ["mupen64plus_next"])
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0].endswith(f"?ref={pin}"), seen)


class EmuDeckScriptNamesHaveOneRule(unittest.TestCase):
    """The target scraper kept its own copy of the EmuScripts-to-profile
    table: it published emudeck-we's template skeleton as a core, and a
    rename added to one copy only made --target filter that core out."""

    def test_the_target_scraper_names_scripts_as_the_platform_does(self):
        from scripts.scraper.emudeck_launchers import emulator_of_script

        listing = [
            "emuDeckRMG.sh",
            "emuDeckPCSX2QT.ps1",
            "emuDeckTemplate.ps1",
            "emuDeckRetroArch.ps1",
            "RetroArch_maincfg.sh",
            "emuDeckXemu.ps1",
        ]
        scraper = emudeck_targets_scraper.Scraper(revision="0" * 40)
        with mock.patch.object(
            emudeck_targets_scraper, "_list_emuscripts", return_value=listing
        ), mock.patch.object(scraper, "_load_retroarch_cores", return_value=["mgba"]):
            cores = scraper._fetch_cores_for_target("unused", "Windows", "windows-x86_64")
        standalone = {emulator_of_script(name) for name in listing} - {None, "retroarch"}
        self.assertEqual(standalone, {"mupen64plus_next", "pcsx2", "xemu"})
        self.assertEqual(cores, sorted(standalone | {"mgba"}))


class EmuDeckWindowsReadsTheWindowsBuild(unittest.TestCase):
    """The RetroArch list was the first target of the architecture:
    EmuDeck's Windows target carried fsuae, omicron and video_processor,
    which the buildbot publishes for Linux only."""

    def test_each_target_gets_its_own_retroarch_list(self):
        seen: list[str] = []

        def load(target: str) -> list[str]:
            seen.append(target)
            return [target]

        scraper = emudeck_targets_scraper.Scraper(revision="0" * 40)
        with mock.patch.object(
            emudeck_targets_scraper, "_list_emuscripts", return_value=["emuDeckRetroArch.sh"]
        ), mock.patch.object(scraper, "_load_retroarch_cores", side_effect=load):
            data = scraper.fetch_targets()
        self.assertEqual(seen, ["linux-x86_64", "windows-x86_64"])
        self.assertEqual(data["targets"]["windows"]["cores"], ["windows-x86_64"])

    def test_the_list_is_read_by_target_name_from_any_directory(self):
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(Path(__file__).parent)
        load = emudeck_targets_scraper.Scraper._load_retroarch_cores
        windows, linux = load("windows-x86_64"), load("linux-x86_64")
        self.assertNotIn("video_processor", windows)
        self.assertIn("video_processor", linux)


class HashScrapersRefuseAnUnknownVersion(unittest.TestCase):
    """mame_hash_scraper wrote core_version "unknown" after a failed API call
    and cached it for a day, while the pipeline step still read OK."""

    def test_mame_raises(self):
        from scripts.scraper import mame_hash_scraper  # noqa: PLC0415

        with mock.patch.object(mame_hash_scraper.urllib.request, "urlopen", _refuse), \
                self.assertRaises(RuntimeError):
            mame_hash_scraper._get_version()


class RetroArchCoversEveryBuildbotFamily(unittest.TestCase):
    """OpenDingux, RetroFW, MiyooCFW and webOS builds were published on the
    buildbot and absent from the target list: an RG350 or Miyoo user could
    not narrow a pack or an install to the board."""

    def test_the_handheld_and_tv_families_are_listed(self):
        from scraper.targets.retroarch_targets_scraper import TARGETS

        paths = {path.split("/latest")[0] for path, _name, _arch in TARGETS}
        for family in ("dingux/mips32", "dingux/mips32-odbeta", "dingux/rs90-mips32-odbeta",
                       "dingux/retrofw-mips32", "dingux/miyoo-arm32",
                       "webos/armv7a", "webos/aarch64"):
            with self.subTest(family=family):
                self.assertIn(family, paths)


if __name__ == "__main__":
    unittest.main()
