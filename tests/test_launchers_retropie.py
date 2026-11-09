"""RetroPie's launcher layer read from the scriptmodules.

Each fixture copies the lines an extractor reads from RetroPie-Setup
46128cd252cdecae852a4d0bafa2aaf9d03ab563, placed at the line numbers they
have there, so the source_ref a record carries is the one platforms/retropie.yml
cites. A construct that is gone or unknown must stop the scrape.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import dataclasses
import json
import sys
import textwrap
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper import batocera_launchers  # noqa: E402
from scraper import retropie_launchers as rl  # noqa: E402

EMULATORS = "scriptmodules/emulators"
LIBRETRO = "scriptmodules/libretrocores"


def at(first_line: int, text: str) -> str:
    """Text placed so its first line is line `first_line` of the file."""
    return "\n" * (first_line - 1) + textwrap.dedent(text).lstrip("\n")


def header(package: str, repo: str | None = None, repo_line: int = 15) -> str:
    lines = {12: f'rp_module_id="{package}"'}
    if repo is not None:
        lines[repo_line] = f'rp_module_repo="{repo}"'
    return "\n".join(lines.get(n, "") for n in range(1, max(lines) + 1)) + "\n"


def module(package: str, body: str, first_line: int, repo: str | None = None,
           repo_line: int = 15) -> str:
    head = header(package, repo, repo_line)
    padding = first_line - 1 - head.count("\n")
    return head + "\n" * padding + textwrap.dedent(body).lstrip("\n")


def records(files: dict[str, str], package: str | None = None) -> list[dict]:
    found = rl.extract_launchers(files)
    return [r for r in found if package is None or r["package"] == package]


PX68K = module("px68k", """
    function configure_px68k() {
        mkRomDir "x68000"

        moveConfigDir "$home/.keropi" "$md_conf_root/x68000"
        mkUserDir "$biosdir/keropi"

        local bios
        for bios in cgrom.dat iplrom30.dat iplromco.dat iplrom.dat iplromxv.dat; do
            if [[ -f "$biosdir/$bios" ]]; then
                mv "$biosdir/$bios" "$biosdir/keropi/$bios"
            fi
            ln -sf "$biosdir/keropi/$bios" "$md_conf_root/x68000/$bios"
        done

        addEmulator 1 "$md_id" "x68000" "$md_inst/px68k.sdl2 %ROM%"
        addSystem "x68000"
    }
""", 47, repo="git https://github.com/TurtleBazooka/px68k.git master")

REDREAM = module("redream", """
    function configure_redream() {
        mkUserDir "$biosdir/dc"
        ln -sf "$biosdir/dc/dc_boot.bin" "$md_inst/boot.bin"
        ln -sf "$biosdir/dc/dc_flash.bin" "$md_inst/flash.bin"
    }
""", 56)

SDLTRS = module("sdltrs", """
    function configure_sdltrs() {
        local common_args
        mkRomDir "trs-80"

        common_args="-fullscreen -nomousepointer -showled"
        addEmulator 1 "$md_id-model1" "trs-80" "$md_inst/sdl2trs $common_args -m1 -romfile $biosdir/level2.rom -disk0 %ROM%"
        addEmulator 0 "$md_id-model3" "trs-80" "$md_inst/sdl2trs $common_args -m3 -romfile3 $biosdir/level3.rom -disk0 %ROM%"
        addEmulator 0 "$md_id-model4" "trs-80" "$md_inst/sdl2trs $common_args -m4 -romfile3 $biosdir/level4.rom -disk0 %ROM%"
        addEmulator 0 "$md_id-model4p" "trs-80" "$md_inst/sdl2trs $common_args -m4p -romfile4p $biosdir/level4p.rom -disk0 %ROM%"
        addSystem "trs-80"
    }
""", 44)

BASILISK = module("basilisk", """
    function configure_basilisk() {
        addEmulator 1 "$md_id" "macintosh" "$md_inst/bin/BasiliskII --rom $romdir/macintosh/mac.rom --disk $romdir/macintosh/disk.img"
        addSystem "macintosh"
    }
""", 55, repo="git https://github.com/cebix/macemu.git master", repo_line=16)

GNGEOPI = module("gngeopi", """
    function configure_gngeopi() {
        addEmulator 0 "$md_id" "arcade" "$md_inst/bin/gngeo -i $romdir/neogeo -B $md_inst/neogeobios %ROM%"
        addEmulator 0 "$md_id" "neogeo" "$md_inst/bin/gngeo -i $romdir/neogeo -B $md_inst/neogeobios %ROM%"
        addSystem "arcade"
        addSystem "neogeo"
    }
""", 59)

FS_UAE = module("fs-uae", """
    function configure_fs-uae() {
        mkRomDir "amiga"

        addEmulator 1 "$md_id" "amiga" "CON:bash $md_inst/bin/fs-uae.sh %ROM%"
        addSystem "amiga"
    }
""", 76)

FS_UAE_LAUNCHER = at(15, """
    rootdir="/opt/retropie"
    datadir="$HOME/RetroPie"
    romdir="$datadir/roms/amiga"
    biosdir="$datadir/BIOS"
    kickfile="$biosdir/kick13.rom"

    source "$rootdir/lib/archivefuncs.sh"

    if [[ ! -f "$kickfile" ]]; then
        dialog --no-cancel --pause "You need to copy the Amiga kickstart file (kick13.rom) to the folder $biosdir to boot the Amiga emulator." 22 76 15
        exit 1
    fi
""") + "\n" * 14 + 'fs-uae --floppy_drive_0="$rom" --kickstart_file="$kickfile" --floppies_dir="$romdir"\n'

DOSBOX = module("dosbox", """
    function configure_dosbox() {
        local def=0
        mkRomDir "pc"
        addEmulator "$def" "$md_id" "pc" "bash $romdir/pc/launcher %ROM%"
        addSystem "pc"

        cat > "$romdir/pc/launcher" << _EOF_
    function midi_synth() {
        echo start
    }
    _EOF_
    }
""", 64)

DOSBOX_SDL2 = module("dosbox-sdl2", """
    function configure_dosbox-sdl2() {
        configure_dosbox
    }
""", 42, repo="git https://github.com/duganchen/dosbox.git master", repo_line=16)

FBNEO = module("lr-fbneo", """
    function configure_lr-fbneo() {
        local systems=(
            "arcade"
            "neogeo"
            "pcengine"
        )

        local system
        for system in "${systems[@]}"; do
            addSystem "$system"
        done
    }
""", 94)

MAME2003 = module("lr-mame2003", """
    function _get_dir_name_lr-mame2003() {
        echo "mame2003"
    }

    function configure_lr-mame2003() {
        addSystem "arcade"
        local dir_name="$(_get_dir_name_${md_id})"
        cp "$md_inst/metadata/"{hiscore.dat,cheat.dat} "$biosdir/$dir_name/"
        if [[ "$md_id" == "lr-mame2003-plus" ]]; then
            cp "$md_inst/metadata/artwork/"* "$biosdir/$dir_name/artwork/"
        fi
    }
""", 19)

MAME2003_PLUS = module("lr-mame2003-plus", """
    function _get_dir_name_lr-mame2003-plus() {
        echo "mame2003-plus"
    }

    function configure_lr-mame2003-plus() {
        configure_lr-mame2003
    }
""", 19)


class LinksAndCopies(unittest.TestCase):
    def test_px68k_links_only_its_five_names(self):
        found = records({f"{EMULATORS}/px68k.sh": PX68K}, "px68k")
        links = next(r for r in found if r["kind"] == "links")
        self.assertEqual(
            links["names"],
            ["cgrom.dat", "iplrom30.dat", "iplromco.dat", "iplrom.dat", "iplromxv.dat"],
        )
        self.assertNotIn("cgrom30.dat", links["names"])
        self.assertEqual(links["search_dir"], "$biosdir/keropi")
        self.assertEqual(links["passes_to"], "$md_conf_root/x68000/<name>")
        self.assertEqual(links["source_ref"], f"{EMULATORS}/px68k.sh:58")

    def test_px68k_moves_a_root_copy_first(self):
        found = records({f"{EMULATORS}/px68k.sh": PX68K}, "px68k")
        moves = next(r for r in found if r["kind"] == "moves")
        self.assertEqual((moves["search_dir"], moves["passes_to"]), ("$biosdir", "$biosdir/keropi"))
        self.assertEqual(moves["depends_on_option"], '[[ -f "$biosdir/$bios" ]]')
        self.assertEqual(moves["source_ref"], f"{EMULATORS}/px68k.sh:56")

    def test_redream_renames_both_files(self):
        found = records({f"{EMULATORS}/redream.sh": REDREAM}, "redream")
        links = next(r for r in found if r["kind"] == "links")
        self.assertEqual(links["names"], ["dc_boot.bin", "dc_flash.bin"])
        self.assertEqual(links["passes_to"], "$md_inst/boot.bin, $md_inst/flash.bin")
        self.assertEqual(links["source_ref"], f"{EMULATORS}/redream.sh:58-59")

    def test_a_copy_kept_only_for_the_package_the_test_names(self):
        files = {
            f"{LIBRETRO}/lr-mame2003.sh": MAME2003,
            f"{LIBRETRO}/lr-mame2003-plus.sh": MAME2003_PLUS,
        }
        base = [r for r in records(files, "lr-mame2003") if r["kind"] == "copies"]
        plus = [r for r in records(files, "lr-mame2003-plus") if r["kind"] == "copies"]
        self.assertEqual([r["passes_to"] for r in base], ["$biosdir/mame2003"])
        self.assertEqual(
            [r["passes_to"] for r in plus],
            ["$biosdir/mame2003-plus", "$biosdir/mame2003-plus/artwork"],
        )
        self.assertEqual(base[0]["names"], ["hiscore.dat", "cheat.dat"])


class CommandLines(unittest.TestCase):
    def test_sdltrs_passes_one_rom_per_machine(self):
        found = records({f"{EMULATORS}/sdltrs.sh": SDLTRS}, "sdltrs")
        found = [r for r in found if r["kind"] == "fixed_name"]
        self.assertEqual(
            [(r["emulator"], r["names"], r["passes_to"]) for r in found],
            [
                ("sdltrs-model1", ["level2.rom"], "command line -romfile"),
                ("sdltrs-model3", ["level3.rom"], "command line -romfile3"),
                ("sdltrs-model4", ["level4.rom"], "command line -romfile3"),
                ("sdltrs-model4p", ["level4p.rom"], "command line -romfile4p"),
            ],
        )
        self.assertEqual(found[2]["source_ref"], f"{EMULATORS}/sdltrs.sh:51")

    def test_a_bios_read_outside_the_bios_folder(self):
        files = {f"{EMULATORS}/basilisk.sh": BASILISK, f"{EMULATORS}/gngeopi.sh": GNGEOPI}
        rom = next(r for r in records(files, "basilisk") if r["kind"] == "fixed_name")
        self.assertEqual((rom["names"], rom["search_dir"]), (["mac.rom"], "$romdir/macintosh"))
        bios = next(r for r in records(files, "gngeopi") if r["kind"] == "passes_path")
        self.assertEqual(bios["search_dir"], "$md_inst/neogeobios")
        self.assertEqual(bios["source_ref"], f"{EMULATORS}/gngeopi.sh:60-61")

    def test_a_flag_dropped_from_the_command_raises(self):
        files = {
            f"{EMULATORS}/basilisk.sh": BASILISK.replace("--rom ", "--romfile "),
            f"{EMULATORS}/gngeopi.sh": GNGEOPI,
        }
        with self.assertRaises(rl.LauncherPatternMissing):
            rl.extract_launchers(files)


DRASTIC = module("drastic", """
    function configure_drastic() {
        mkRomDir "nds"

        addEmulator 1 "$md_id" "nds" "$md_inst/drastic.sh %ROM%"
        addSystem "nds"

        [[ "$md_mode" == "remove" ]] && return

        isPlatform "kms" && ! isPlatform "x11" && setBackend "$md_id" "x11"

        cat > "$md_inst/drastic.sh" << _EOF_
    #!/bin/bash
    pushd "$md_conf_root/nds/drastic"
    $md_inst/drastic "\\$1"
    popd
    _EOF_
        chmod +x "$md_inst/drastic.sh"
    }
""", 36)


UAE4ALL = module("uae4all", """
    function configure_uae4all() {
        mkRomDir "amiga"

        moveConfigDir "$md_inst/kickstarts" "$biosdir/amiga"

        rm -f "$romdir/amiga/+Start UAE4All.sh"
        if [[ "$md_mode" == "install" ]]; then
            cat > "$romdir/amiga/+Start UAE4All.sh" << _EOF_
    #!/bin/bash
    pushd "$md_inst"
    ./uae4all
    popd
    _EOF_
        fi

        addEmulator 1 "$md_id" "amiga" "bash $romdir/amiga/+Start\\ UAE4All.sh"
        addSystem "amiga"
    }
""", 60)


OPENMSX = module("openmsx", """
    function configure_openmsx() {
        mkUserDir "$home/.openMSX/share/systemroms"
        moveConfigDir "$home/.openMSX" "$configdir/msx/openmsx"
        moveConfigDir "$configdir/msx/openmsx/share/systemroms" "$home/RetroPie/BIOS/openmsx"
        moveConfigDir "$home/.unrelated" "$configdir/msx/other"
    }
""", 74)


XROAR = module("xroar", """
    function build_xroar() {
        ./configure --prefix="$md_inst" "${params[@]}"
    }

    function configure_xroar() {
        mkdir -p "$md_inst/share/xroar"
        ln -snf "$biosdir" "$md_inst/share/xroar/roms"
    }
""", 36)


class ReachingLinks(unittest.TestCase):
    """The directory outside BIOS that a whole-directory link is read from."""

    def test_openmsx_user_directory_holds_the_systemroms_link(self):
        found = records({f"{EMULATORS}/openmsx.sh": OPENMSX}, "openmsx")
        links = [r for r in found if r["kind"] == "links"]
        self.assertEqual(
            [(r["search_dir"], r["passes_to"], r["source_ref"]) for r in links],
            [
                (
                    "$home/RetroPie/BIOS/openmsx",
                    "$configdir/msx/openmsx/share/systemroms is a symlink to it",
                    f"{EMULATORS}/openmsx.sh:77",
                ),
                (
                    "$configdir/msx/openmsx",
                    "$home/.openMSX is a symlink to it",
                    f"{EMULATORS}/openmsx.sh:76",
                ),
            ],
        )

    def test_xroar_install_prefix_holds_the_roms_link(self):
        found = records({f"{EMULATORS}/xroar.sh": XROAR}, "xroar")
        prefix = [r for r in found if r["kind"] == "passes_path"]
        self.assertEqual(
            [(r["search_dir"], r["passes_to"], r["source_ref"]) for r in prefix],
            [("$md_inst", "${prefix} of configure --prefix", f"{EMULATORS}/xroar.sh:37")],
        )


class WorkingDirectory(unittest.TestCase):
    def test_drastic_reads_below_the_folder_its_script_enters(self):
        found = records({f"{EMULATORS}/drastic.sh": DRASTIC}, "drastic")
        entered = [r for r in found if r["kind"] == "passes_path"]
        self.assertEqual(
            [(r["search_dir"], r["passes_to"], r["source_ref"]) for r in entered],
            [(
                "$md_conf_root/nds/drastic",
                "working directory of $md_inst/drastic.sh",
                f"{EMULATORS}/drastic.sh:48",
            )],
        )

    def test_uae4all_runs_from_its_install_directory(self):
        found = records({f"{EMULATORS}/uae4all.sh": UAE4ALL}, "uae4all")
        entered = [r for r in found if r["kind"] == "passes_path"]
        self.assertEqual(
            [(r["search_dir"], r["passes_to"], r["source_ref"]) for r in entered],
            [(
                "$md_inst",
                "working directory of $romdir/amiga/+Start UAE4All.sh",
                f"{EMULATORS}/uae4all.sh:69",
            )],
        )

    def test_a_launch_script_that_no_longer_enters_a_folder_raises(self):
        files = {f"{EMULATORS}/drastic.sh": DRASTIC.replace('pushd "', 'echo "')}
        with self.assertRaises(rl.LauncherPatternMissing):
            rl.extract_launchers(files)


class LaunchScripts(unittest.TestCase):
    def test_fs_uae_refuses_to_start_without_kick13(self):
        files = {f"{EMULATORS}/fs-uae.sh": FS_UAE, f"{EMULATORS}/fs-uae/fs-uae.sh": FS_UAE_LAUNCHER}
        check = next(r for r in records(files, "fs-uae") if r["kind"] == "fixed_name")
        self.assertEqual(check["names"], ["kick13.rom"])
        self.assertEqual(check["search_dir"], "$HOME/RetroPie/BIOS")
        self.assertEqual(check["passes_to"], "command line --kickstart_file")
        message = check["fails_when_missing"]
        self.assertTrue(message.startswith("You need to copy the Amiga kickstart"))
        self.assertEqual(check["source_ref"], f"{EMULATORS}/fs-uae/fs-uae.sh:23-26, 41")

    def test_a_launch_script_without_a_check_raises(self):
        script = FS_UAE_LAUNCHER.replace("exit 1", "true")
        files = {f"{EMULATORS}/fs-uae.sh": FS_UAE, f"{EMULATORS}/fs-uae/fs-uae.sh": script}
        with self.assertRaises(rl.LauncherPatternMissing):
            records(files)


class Packages(unittest.TestCase):
    def test_the_package_names_what_it_builds_and_registers(self):
        found = records({f"{EMULATORS}/px68k.sh": PX68K}, "px68k")
        package = next(r for r in found if r["kind"] == "package")
        self.assertEqual(package["repo"], "git https://github.com/TurtleBazooka/px68k.git master")
        self.assertEqual(package["systems"], ["x68000"])
        self.assertEqual(package["source_ref"], f"{EMULATORS}/px68k.sh:12, 15, 62")

    def test_a_package_inherits_the_systems_of_the_function_it_runs(self):
        files = {f"{EMULATORS}/dosbox.sh": DOSBOX, f"{EMULATORS}/dosbox-sdl2.sh": DOSBOX_SDL2}
        package = next(r for r in records(files, "dosbox-sdl2") if r["kind"] == "package")
        self.assertEqual(package["systems"], ["pc"])
        self.assertIn(f"{EMULATORS}/dosbox.sh:68", package["source_ref"])

    def test_systems_from_a_multi_line_array(self):
        found = records({f"{LIBRETRO}/lr-fbneo.sh": FBNEO}, "lr-fbneo")
        package = next(r for r in found if r["kind"] == "package")
        self.assertEqual(package["systems"], ["arcade", "neogeo", "pcengine"])
        self.assertEqual(package["build"], "libretro")

    def test_a_system_name_left_unresolved_raises(self):
        broken = FBNEO.replace('"${systems[@]}"', '"${others[@]}"')
        with self.assertRaises(rl.LauncherPatternMissing):
            records({f"{LIBRETRO}/lr-fbneo.sh": broken})


class UnknownConstructs(unittest.TestCase):
    def test_an_unclassified_use_of_the_bios_folder_raises(self):
        broken = REDREAM.replace('mkUserDir "$biosdir/dc"', 'rsync -a "$biosdir/dc" "$md_inst"')
        with self.assertRaises(rl.LauncherPatternMissing):
            records({f"{EMULATORS}/redream.sh": broken})

    def test_scripts_without_a_package_raise(self):
        with self.assertRaises(rl.LauncherPatternMissing):
            rl.Scripts({f"{EMULATORS}/redream.sh": "function x() {\n}\n"})


class PlatformRecords(unittest.TestCase):
    """The launchers platforms/retropie.yml carries, as the scraper wrote them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "retropie.yml").read_text())
        cls.schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text())

    def test_one_package_record_per_core(self):
        packages = [r["package"] for r in self.config["launchers"] if r["kind"] == "package"]
        self.assertEqual(len(packages), len(set(packages)))
        from scraper.retropie_scraper import core_name  # noqa: PLC0415

        self.assertEqual({core_name(p) for p in packages}, set(self.config["cores"]))

    def test_every_record_belongs_to_a_package(self):
        packages = {r["package"] for r in self.config["launchers"] if r["kind"] == "package"}
        for record in self.config["launchers"]:
            self.assertIn(record["package"], packages, record)
            self.assertTrue(record["source_ref"].startswith("scriptmodules/"), record)

    def test_the_standalone_builds_name_their_own_project(self):
        repos = {
            r["package"]: r.get("repo") for r in self.config["launchers"] if r["kind"] == "package"
        }
        self.assertEqual(repos["minivmac"], "git https://github.com/minivmac/minivmac.git master")
        self.assertEqual(repos["quasi88"], "git https://github.com/winterheart/quasi88.git master")
        self.assertEqual(repos["px68k"], "git https://github.com/TurtleBazooka/px68k.git master")

    def test_the_schema_describes_every_scraper_field(self):
        fields = {
            f.name for cls in (batocera_launchers.Launcher, rl.Launcher)
            for f in dataclasses.fields(cls)
        } - {"lines"}
        self.assertEqual(fields, set(self.schema["$defs"]["launcher"]["properties"]))


if __name__ == "__main__":
    unittest.main()
