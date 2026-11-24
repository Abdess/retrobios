"""RetroBat's launcher layer: names in launcher order, guarded config writes,
options that replace a path.

Each fixture is a cut-down copy of the construct at emulatorLauncher
48cdc61623c5943bb17647b80a60d32d395c3725, kept to the lines an extractor
reads. The records must carry the names in the launcher's order and point at
the fixture's own lines, and a construct that is gone must stop the scrape.
"""

from __future__ import annotations

import tests

import tempfile
import unittest
from pathlib import Path

from scraper import retrobat_launchers as rl
from scraper import retrobat_generators
from scraper.retrobat_computers import hatari, openmsx, amiberry
from scraper.retrobat_config_files import (
    ares,
    mesen,
)
from scraper.retrobat_generators import GENERATORS, GUARDED_WRITES, guarded_writes_in
from scraper.retrobat_playstation import duckstation, psx_cascades
from scraper.retrobat_render import _option_path_in
from scraper.csharp_source import LauncherPatternMissing, Source, render_concat
from model.sourcerevision import required_revision
from tests.launcherssupport import _sources


ARES = """
    if (system == "laseractive" && core.ToLowerInvariant() == "megald")
    {
        var sys = bml.GetOrCreateContainer("LaserActiveSEGAPAC");
        var firmware = sys.GetOrCreateContainer("Firmware");
        string biosfolderPioneer = Path.Combine(AppConfig.GetFullPath("bios"), "laseractive");

        string bios_japan = Path.Combine(biosfolderPioneer, "[BIOS] LaserActive PAC-S1 (Japan) (v1.05).bin");
        if (!File.Exists(bios_japan))
            bios_japan = Path.Combine(biosfolderPioneer, "[BIOS] LaserActive PAC-S1 (Japan) (v1.02).bin");
        if (!File.Exists(bios_japan))
            bios_japan = Path.Combine(biosfolderPioneer, "[BIOS] LaserActive PAC-S1 (Japan) (v1.01).bin");

        if (File.Exists(bios_japan))
            firmware["BIOS.Japan"] = bios_japan.Replace("\\\\", "/");
    }
"""

MESEN = """
    private void ConfigureColeco(JObject section, string mesenSystem, string system, string path)
    {
        string targetFirmwarePath = Path.Combine(path, "Firmware");
        string targetFirmware1 = Path.Combine(targetFirmwarePath, "bios.col");

        string sourceFirmware1 = Path.Combine(AppConfig.GetFullPath("bios"), "colecovision.rom");

        if (File.Exists(sourceFirmware1) && !File.Exists(targetFirmware1) && Directory.Exists(targetFirmwarePath))
            File.Copy(sourceFirmware1, targetFirmware1);

        if (!File.Exists(targetFirmware1))
            throw new ApplicationException("Colecovision firmware is missing (colecovision.rom)");
    }
"""

AMIBERRY = """
    private static readonly Dictionary<string, AmigaModel> _models = new Dictionary<string, AmigaModel>()
    {
        { "CD32", new AmigaModel {
            Id = "CD32",
            Kickstart = new[] { "kick40060.CD32", "kick40060.CD32.rom" },
            KickstartExt = new[] { "kick40060.CD32.ext", "amiga-os-310-cd32-ext.rom" } } },

        { "CD32FR", new AmigaModel {
            Id = "CD32FR",
            Kickstart = new[] { "kick40060.CD32", "kick40060.CD32.rom" } } },
    };

    void Configure()
    {
        string kickstart = StageKickstart(_model.Kickstart);
        if (kickstart == null)
            SimpleLogger.Instance.Warning("[Amiberry] No Kickstart ROM found for " + _model.Id);
        string kickstartExt = StageKickstart(_model.KickstartExt);
        if (kickstartExt == null)
            SimpleLogger.Instance.Warning("[Amiberry] No extended ROM found for " + _model.Id);
    }

    private string FindBios(string[] candidates)
    {
        var searchDirs = new List<string> { biosPath, Path.Combine(biosPath, "amiga"), Path.Combine(biosPath, "Amiga") };
        return null;
    }

    public override ProcessStartInfo Generate(string system, string emulator, string core, string rom)
    {
        if (!GetEmulatorPathAndExe(emulator, out string path, out string exe, "Amiberry.exe", "amiberry.exe"))
            return null;
    }

    private void SetupAmiberrySettings(string path, string system)
    {
        _amiberryRomsPath = Path.Combine(path, "ROMs");
        FileTools.TryCreateDirectory(_amiberryRomsPath);
        overrides["rom_path"] = _amiberryRomsPath;
        overrides["whdboot_path"] = Path.Combine(path, "WHDBoot");
        MergeConfLines(confFile, overrides);
    }

    private void StageRomKey()
    {
        string source = FindBios(new[] { "rom.key" });
        string dest = Path.Combine(_amiberryRomsPath, "rom.key");
        if (!File.Exists(dest) || new FileInfo(dest).Length != new FileInfo(source).Length)
            File.Copy(source, dest, true);
    }

    private string StageKickstart(string[] candidates)
    {
        string source = FindBios(candidates);
        string dest = Path.Combine(_amiberryRomsPath, candidates[0]);
        if (!dst.Exists || dst.Length != src.Length || dst.LastWriteTimeUtc < src.LastWriteTimeUtc)
            File.Copy(source, dest, true);
        return dest;
    }
"""

MEDNAFEN = """
    if (!SystemConfig.getOptBoolean("mednafen_psx_original_bios"))
    {
        string biosFile = Path.Combine(AppConfig.GetFullPath("bios"), "psxonpsp660.bin");
        if (File.Exists(biosFile))
        {
            cfg["psx.bios_eu"] = "psxonpsp660.bin";
        }
        else if (File.Exists(Path.Combine(AppConfig.GetFullPath("bios"), "ps1_rom.bin")))
        {
            cfg["psx.bios_eu"] = "ps1_rom.bin";
        }
        else
        {
            cfg["psx.bios_eu"] = "scph5502.bin";
            cfg["psx.bios_jp"] = "scph5500.bin";
        }
    }
    else
    {
        cfg["psx.bios_eu"] = "scph5502.bin";
    }
"""

LIBRETRO_PSX = """
    if (core != "mednafen_psx_hw")
        return;
    if (!SystemConfig.getOptBoolean("beetle_psx_original_bios"))
    {
        string biosFile = Path.Combine(AppConfig.GetFullPath("bios"), "psxonpsp660.bin");
        if (File.Exists(biosFile))
            coreSettings["beetle_psx_hw_override_bios"] = "psxonpsp";
        else
            coreSettings["beetle_psx_hw_override_bios"] = "disabled";
    }
    else
        coreSettings["beetle_psx_hw_override_bios"] = "disabled";
"""

OPENMSX = """
    foreach (var c in biosFileRequired)
    {
        if (!systemRomsContent.Contains(c))
            throw new ApplicationException(machine + " machine has missing BIOS file '" + c + "' in 'bios\\\\openmsx\\\\share\\\\systemroms' folder.");
    }

    static readonly Dictionary<string, string[]> biosFiles = new Dictionary<string, string[]>()
    {
        { "Philips_VG_8020", new string[] { "vg8020_basic-bios1.rom" } },
        { "Pioneer_PX-7", new string[] { "px-7_basic-bios1.rom", "px-7_pbasic.rom" } }
    };

    string sharePath = Path.Combine(AppConfig.GetFullPath("bios"), "openmsx");
    ret.EnvironmentVariables["OPENMSX_HOME"] = sharePath;
"""

DUCKSTATION = """
    ini.WriteValue("BIOS", "SearchDirectory", biosPath);

    if (SystemConfig.isOptSet("duck_bios") && !string.IsNullOrEmpty(SystemConfig["duck_bios"]))
    {
        ini.WriteValue("BIOS", "PathNTSCJ", SystemConfig["duck_bios"]);
        ini.WriteValue("BIOS", "PathPAL", SystemConfig["duck_bios"]);
    }
    else
    {
        ini.WriteValue("BIOS", "PathNTSCJ", null);
    }
"""

FEATURES = """
    <features>
      <emulator name="libretro, angle">
        <cores>
          <core name="duckstation">
            <feature value="duck_bios">
              <choice name="WRONG" value="libretro.bin"/>
            </feature>
          </core>
        </cores>
      </emulator>
      <emulator name="duckstation" features="cheevos">
        <feature submenu="EMULATION" name="FORCE BIOS" value="duck_bios" order="102">
          <choice name="PSX ON PSP BIOS" value="psxonpsp660.bin"/>
          <choice name="PS1 US (SCPH5501)" value="scph5501.bin"/>
        </feature>
      </emulator>
    </features>
"""

HATARI = """
    string tosDir = Path.Combine(AppConfig.GetFullPath("bios"), "hatari", "tos");
    string tosfile = Path.Combine(AppConfig.GetFullPath("bios"), "tos.img");
    string emutos = Path.Combine(tosDir, "emutos.img");

    if (SystemConfig.isOptSet("hatari_tos") && SystemConfig["hatari_tos"] != "default")
        tosfile = Path.Combine(tosDir, SystemConfig["hatari_tos"]);
    else if (media.HasHardDiskImage && File.Exists(emutos))
    {
        tosfile = emutos;
    }
    else
    {
        if (!File.Exists(tosfile) && File.Exists(emutos))
            tosfile = emutos;

        if (old)
        {
            string newTos = new string[] { "tos104.img", "tos206.img", "emutos.img" }
                .Select(t => Path.Combine(tosDir, t))
                .FirstOrDefault(t => File.Exists(t));
        }
    }

    if (!File.Exists(tosfile))
        throw new ApplicationException("Missing TOS file " + tosName + " in 'bios' folder.");

    ini.WriteValue("ROM", "szTosImageFileName", tosfile);
"""

HATARI_FEATURES = """
    <emulator name="hatari" features="padtokeyboard">
      <feature name="TOS" value="hatari_tos" order="101">
        <choice name="TOS 2.06" value="tos206.img"/>
        <choice name="TOS 1.02" value="tos102.img"/>
      </feature>
    </emulator>
"""


KEGA = """
    private void SetupConfiguration(string path, string system)
    {
        string iniFile = Path.Combine(path, "Fusion.ini");

        using (var ini = IniFile.FromFile(iniFile))
        {
            string biosPath = AppConfig.GetFullPath("bios");
            if (!Directory.Exists(biosPath)) try { Directory.CreateDirectory(biosPath); }
                catch { }

            ini.WriteValue("", "GenesisBIOS", biosPath);

            // BIOS
            string euBios = Path.Combine(biosPath, "bios_CD_E.bin");
            if (File.Exists(euBios))
                ini.WriteValue("", "SCDEURBIOS", euBios);

            string bios32Xg = Path.Combine(biosPath, "32X_G_BIOS.BIN");
            if (File.Exists(bios32Xg))
                ini.WriteValue("", "32XM68KBIOS", bios32Xg);
        }
    }
"""

JGENESIS = """
    private void SetupTomlConfiguration(string path)
    {
        string settingsFile = Path.Combine(path, "jgenesis-config.toml");
        using (IniFileJGenesis ini = new IniFileJGenesis(settingsFile, IniOptionsJGenesis.UseSpaces))
        {
            ConfigureGenesis(ini, system);
        }
    }

    private void ConfigureGenesis(IniFileJGenesis ini, string system)
    {
        if (system != "genesis" && system != "sega_cd")
            return;

        if (system == "sega_cd")
        {
            string segaCdBios = Path.Combine(AppConfig.GetFullPath("bios"), "bios_CD_U.bin");

            ini.WriteValue("sega_cd", "per_region_bios", "true");

            if (File.Exists(segaCdBios))
                ini.WriteValue("sega_cd", "bios_path", "'" + segaCdBios + "'");
        }
    }
"""

MELONDS = """
    private void SetupConfiguration(string path, string rom)
    {
        string settingsFile = Path.Combine(path, "melonDS.toml");

        using (IniTomlFile ini = IniTomlFile.FromFile(settingsFile, IniTomlOptions.UseSpaces))
        {
            if (SystemConfig.isOptSet("melonds_externalBIOS") && SystemConfig.getOptBoolean("melonds_externalBIOS"))
            {
                string bios7 = Path.Combine(AppConfig.GetFullPath("bios"), "bios7.bin");

                if (File.Exists(bios7))
                    ini.WriteValue("DS", "BIOS7Path", "\\"" + bios7.Replace("\\\\", "/") + "\\"");
            }
        }
    }
"""

# Kronos: the path is replaced by an option before the check, so the name
# checked is not the literal.
REASSIGNED = """
    private void SetupConfiguration(string path)
    {
        string conf = Path.Combine(path, "kronos.ini");
        using (var ini = IniFile.FromFile(conf))
        {
            string bios = Path.Combine(AppConfig.GetFullPath("bios"), "saturn_bios.bin");
            if (SystemConfig.isOptSet("kronos_force_bios"))
                bios = Path.Combine(AppConfig.GetFullPath("bios"), SystemConfig["kronos_force_bios"]);
            if (File.Exists(bios))
                ini.WriteValue("1.0", "General\\\\Bios", bios.Replace("\\\\", "/"));
        }
    }
"""


def _psx_sources() -> dict[str, Source]:
    return _sources(
        **{
            f"{GENERATORS}/Mednafen.Generator.cs": MEDNAFEN,
            f"{GENERATORS}/Bizhawk.Generator.cs": MEDNAFEN.replace("mednafen_psx", "bizhawk_psx"),
            f"{GENERATORS}/LibRetro.CoreOptions.cs": LIBRETRO_PSX,
        }
    )


def revision_of(url: str) -> str:
    return required_revision(url, repo="RetroBat-Official/emulatorlauncher", commit=True)


class NamesInLauncherOrder(unittest.TestCase):
    def test_ares_fallback_chain_keeps_its_order(self):
        [record] = ares(_sources(**{f"{GENERATORS}/Ares.Generator.cs": ARES}))
        self.assertEqual(
            record["names"],
            [
                "[BIOS] LaserActive PAC-S1 (Japan) (v1.05).bin",
                "[BIOS] LaserActive PAC-S1 (Japan) (v1.02).bin",
                "[BIOS] LaserActive PAC-S1 (Japan) (v1.01).bin",
            ],
        )
        self.assertEqual(record["kind"], "names_searched")
        self.assertEqual(record["search_dir"], "bios/laseractive")
        self.assertEqual(
            record["passes_to"], "settings.bml LaserActiveSEGAPAC/Firmware/BIOS.Japan (first found)"
        )
        self.assertEqual(record["source_ref"], f"{GENERATORS}/Ares.Generator.cs:7-14")

    def test_mesen_copy_names_source_and_renamed_target(self):
        [record] = mesen(_sources(**{f"{GENERATORS}/Mesen.Generator.cs": MESEN}))
        self.assertEqual(record["names"], ["colecovision.rom"])
        self.assertEqual(record["kind"], "copies")
        self.assertIn("<mesen>/Firmware/bios.col", record["passes_to"])
        self.assertEqual(
            record["fails_when_missing"],
            "ApplicationException 'Colecovision firmware is missing (colecovision.rom)'",
        )
        self.assertEqual(record["source_ref"], f"{GENERATORS}/Mesen.Generator.cs:1-13")

    def test_amiberry_identical_lists_are_one_record(self):
        records = amiberry(_sources(**{f"{GENERATORS}/Amiberry.Generator.cs": AMIBERRY}))
        records = [r for r in records if r["kind"] == "names_searched"]
        self.assertEqual(
            [r["names"] for r in records],
            [
                ["kick40060.CD32", "kick40060.CD32.rom"],
                ["kick40060.CD32.ext", "amiga-os-310-cd32-ext.rom"],
            ],
        )
        self.assertEqual(records[0]["search_dir"], "bios, bios/amiga, bios/Amiga")
        self.assertEqual(
            records[0]["source_ref"], f"{GENERATORS}/Amiberry.Generator.cs:3-5, 8-10, 15-17, 23-27"
        )
        self.assertEqual(
            records[1]["passes_to"],
            "copied to <amiberry roms>/kick40060.CD32.ext, kickstart_ext_rom_file",
        )

    def test_amiberry_folders_are_below_its_emulator_folder(self):
        records = amiberry(_sources(**{f"{GENERATORS}/Amiberry.Generator.cs": AMIBERRY}))
        folders = [r for r in records if r["kind"] == "passes_path"]
        self.assertEqual(
            [(r["search_dir"], r["passes_to"], r["source_ref"]) for r in folders],
            [
                ('<AppConfig.GetFullPath("amiberry")>/ROMs', "written: rom_path in amiberry.conf",
                 f"{GENERATORS}/Amiberry.Generator.cs:31, 37-41"),
                ('<AppConfig.GetFullPath("amiberry")>/WHDBoot',
                 "written: whdboot_path in amiberry.conf", f"{GENERATORS}/Amiberry.Generator.cs:31, 40-41"),
            ],
        )

    def test_amiberry_copies_each_kickstart_into_its_roms_folder(self):
        records = amiberry(_sources(**{f"{GENERATORS}/Amiberry.Generator.cs": AMIBERRY}))
        copies = [r for r in records if r["kind"] == "copies"]
        self.assertEqual(
            [(r["names"], r["passes_to"], r["depends_on_option"]) for r in copies],
            [
                (["kick40060.CD32", "kick40060.CD32.rom"],
                 '<AppConfig.GetFullPath("amiberry")>/ROMs/kick40060.CD32',
                 "first name found, the target is absent, smaller or older"),
                (["kick40060.CD32.ext", "amiga-os-310-cd32-ext.rom"],
                 '<AppConfig.GetFullPath("amiberry")>/ROMs/kick40060.CD32.ext',
                 "first name found, the target is absent, smaller or older"),
                (["rom.key"], '<AppConfig.GetFullPath("amiberry")>/ROMs/rom.key',
                 "the target is absent or its size differs"),
            ],
        )
        self.assertEqual(copies[0]["search_dir"], "bios, bios/amiga, bios/Amiga")
        self.assertEqual(
            copies[0]["source_ref"],
            f"{GENERATORS}/Amiberry.Generator.cs:3-5, 8-10, 15, 23-27, 31, 37-39, 52-59",
        )

    def test_amiberry_copy_without_its_staleness_test_raises(self):
        broken = AMIBERRY.replace(" || dst.LastWriteTimeUtc < src.LastWriteTimeUtc", "")
        with self.assertRaises(LauncherPatternMissing):
            amiberry(_sources(**{f"{GENERATORS}/Amiberry.Generator.cs": broken}))

    def test_psx_cascade_splits_searched_from_fallback(self):
        records = psx_cascades(_psx_sources())
        searched, fallback = [r for r in records if r["emulator"] == "mednafen"]
        self.assertEqual(searched["names"], ["psxonpsp660.bin", "ps1_rom.bin"])
        self.assertEqual(searched["depends_on_option"], "mednafen_psx_original_bios off")
        self.assertEqual(fallback["names"], ["scph5502.bin", "scph5500.bin"])
        self.assertEqual(fallback["kind"], "fixed_name")
        self.assertEqual(fallback["fails_when_missing"], "names written without an existence check")
        self.assertEqual(searched["source_ref"], f"{GENERATORS}/Mednafen.Generator.cs:1-21")

    def test_libretro_cascade_takes_the_core_from_its_guard(self):
        records = psx_cascades(_psx_sources())
        [beetle] = [r for r in records if r["build"] == "libretro"]
        self.assertEqual(beetle["emulator"], "mednafen_psx_hw")
        self.assertEqual(beetle["names"], ["psxonpsp660.bin"])
        self.assertEqual(beetle["source_ref"], f"{GENERATORS}/LibRetro.CoreOptions.cs:3-12")

    def test_openmsx_one_record_per_machine(self):
        records = openmsx(_sources(**{f"{GENERATORS}/OpenMSX.Generator.cs": OPENMSX}))
        self.assertEqual(
            [(r["passes_to"], r["names"]) for r in records],
            [
                ("-machine Philips_VG_8020", ["vg8020_basic-bios1.rom"]),
                ("-machine Pioneer_PX-7", ["px-7_basic-bios1.rom", "px-7_pbasic.rom"]),
                ("environment OPENMSX_HOME", []),
            ],
        )
        self.assertEqual(records[0]["search_dir"], "bios/openmsx/share/systemroms")
        self.assertFalse(records[0]["case_insensitive"])
        self.assertEqual(records[1]["source_ref"], f"{GENERATORS}/OpenMSX.Generator.cs:1-4, 10")

    def test_openmsx_home_is_handed_as_a_directory(self):
        # OPENMSX_HOME is the user directory openMSX reads share/systemroms below.
        records = openmsx(_sources(**{f"{GENERATORS}/OpenMSX.Generator.cs": OPENMSX}))
        home = records[-1]
        self.assertEqual(home["kind"], "passes_path")
        self.assertEqual(home["search_dir"], "bios/openmsx")
        self.assertEqual(home["source_ref"], f"{GENERATORS}/OpenMSX.Generator.cs:13-14")

    def test_duckstation_reads_the_standalone_feature_not_the_core(self):
        search, option = duckstation(
            _sources(**{f"{GENERATORS}/Duckstation.Generator.cs": DUCKSTATION, retrobat_generators.FEATURES: FEATURES})
        )
        self.assertEqual(search["kind"], "passes_path")
        self.assertEqual(search["names"], [])
        self.assertEqual(option["names"], ["psxonpsp660.bin", "scph5501.bin"])
        self.assertEqual(option["passes_to"], "settings.ini [BIOS] PathNTSCJ = PathPAL = <value>")
        self.assertEqual(
            option["source_ref"], f"{GENERATORS}/Duckstation.Generator.cs:3-7, {retrobat_generators.FEATURES}:12-15"
        )

    def test_hatari_default_and_option(self):
        fixed, option, emutos, newer = hatari(
            _sources(**{f"{GENERATORS}/Hatari.Generator.cs": HATARI, retrobat_generators.FEATURES: HATARI_FEATURES})
        )
        message = "ApplicationException 'Missing TOS file <tosName> in 'bios' folder.'"
        self.assertEqual(fixed["names"], ["tos.img"])
        self.assertEqual(fixed["search_dir"], "bios")
        self.assertEqual(fixed["fails_when_missing"], f"bios/hatari/tos/emutos.img instead, else {message}")
        self.assertEqual(fixed["source_ref"], f"{GENERATORS}/Hatari.Generator.cs:1-3, 13-14, 27")
        self.assertEqual(option["names"], ["tos206.img", "tos102.img"])
        self.assertEqual(option["search_dir"], "bios/hatari/tos")
        self.assertEqual(option["fails_when_missing"], message)
        self.assertEqual(emutos["names"], ["emutos.img"])
        self.assertEqual(emutos["search_dir"], "bios/hatari/tos")
        self.assertEqual(newer["kind"], "names_searched")
        self.assertEqual(newer["names"], ["tos104.img", "tos206.img", "emutos.img"])


def _one(text: str, emulator: str, path: str = f"{GENERATORS}/X.Generator.cs") -> list[dict]:
    return guarded_writes_in(_sources(**{path: text})[path], emulator)


class GuardedConfigWrites(unittest.TestCase):
    def test_kega_fusion_one_record_per_key(self):
        records = _one(KEGA, "kega-fusion")
        fixed = [r for r in records if r["kind"] == "fixed_name"]
        self.assertEqual(
            [(r["names"], r["passes_to"], r["fails_when_missing"]) for r in fixed],
            [
                (["bios_CD_E.bin"], "Fusion.ini SCDEURBIOS, only if the file exists",
                 "SCDEURBIOS not written"),
                (["32X_G_BIOS.BIN"], "Fusion.ini 32XM68KBIOS, only if the file exists",
                 "32XM68KBIOS not written"),
            ],
        )
        self.assertEqual(fixed[0]["source_ref"], f"{GENERATORS}/X.Generator.cs:14-16")
        self.assertTrue(all(r["search_dir"] == "bios" and r["case_insensitive"] for r in fixed))
        self.assertNotIn("depends_on_option", fixed[0])

    def test_kega_fusion_genesis_key_receives_the_folder(self):
        (folder,) = [r for r in _one(KEGA, "kega-fusion") if r["kind"] == "passes_path"]
        self.assertEqual(folder["names"], [])
        self.assertEqual(folder["passes_to"], "Fusion.ini GenesisBIOS = bios")
        self.assertEqual(folder["source_ref"], f"{GENERATORS}/X.Generator.cs:7, 11")

    def test_early_return_and_enclosing_if_are_conditions(self):
        (record,) = _one(JGENESIS, "jgenesis")
        self.assertEqual(
            record["depends_on_option"],
            'system == "genesis" || system == "sega_cd", system == "sega_cd"',
        )
        self.assertEqual(
            record["passes_to"], "jgenesis-config.toml [sega_cd] bios_path, only if the file exists"
        )
        self.assertEqual(record["source_ref"], f"{GENERATORS}/X.Generator.cs:12-13, 17, 21-22")

    def test_option_switch_is_named(self):
        (record,) = _one(MELONDS, "melonds")
        self.assertEqual(record["names"], ["bios7.bin"])
        self.assertEqual(record["depends_on_option"], "melonds_externalBIOS on")
        self.assertEqual(
            record["passes_to"], "melonDS.toml [DS] BIOS7Path, only if the file exists"
        )

    def test_reassigned_path_is_not_a_fixed_name(self):
        with self.assertRaises(LauncherPatternMissing):
            _one(REASSIGNED, "kronos")

    def test_write_inside_a_loop_is_not_read(self):
        looped = KEGA.replace("// BIOS", "foreach (var x in xs)\n            {").replace(
            '"32XM68KBIOS", bios32Xg);', '"32XM68KBIOS", bios32Xg);\n            }'
        )
        with self.assertRaises(LauncherPatternMissing):
            _one(looped, "kega-fusion")

    def test_pinned_kega_fusion_generator_is_read(self):
        self.assertIn(f"{GENERATORS}/KegaFusion.Generator.cs", rl.SOURCE_FILES)
        self.assertEqual(GUARDED_WRITES[f"{GENERATORS}/KegaFusion.Generator.cs"], "kega-fusion")


SATURN_FEATURES = """
    <features>
      <emulator name="kronos">
        <feature name="FORCE BIOS" value="kronos_force_bios" order="103">
          <choice name="Multi-region" value="saturn_bios.bin"/>
          <choice name="JAP" value="sega_101.bin"/>
          <choice name="HLE" value="hle"/>
        </feature>
      </emulator>
      <emulator name="ymir">
        <feature name="FORCE BIOS" value="ymir_force_bios" order="100">
          <choice name="Multi-region" value="saturn_bios.bin"/>
          <choice name="EUR/US" value="mpr-17933.bin"/>
        </feature>
      </emulator>
      <emulator name="ssf">
        <feature name="FORCE BIOS" value="use_external_bios" order="100">
          <choice name="JAP" value="sega_101.bin"/>
          <choice name="HLE" value="hle"/>
        </feature>
      </emulator>
    </features>
"""

KRONOS = """
    private void SetupConfig(string path)
    {
        string iniFile = Path.Combine(path, "kronos.ini");
        using (var ini = new IniFile(iniFile, IniOptions.KeepEmptyValues))
        {
            string bios = Path.Combine(AppConfig.GetFullPath("bios"), "saturn_bios.bin");
            if (SystemConfig.isOptSet("kronos_force_bios") && !string.IsNullOrEmpty(SystemConfig["kronos_force_bios"]))
            {
                if (SystemConfig["kronos_force_bios"] != "hle")
                    bios = Path.Combine(AppConfig.GetFullPath("bios"), SystemConfig["kronos_force_bios"]);
                else
                    hleBios = true;
            }
            if (File.Exists(bios))
                ini.WriteValue("1.0", "General\\\\Bios", bios.Replace("\\\\", "/"));
        }
    }
"""

YMIR = """
    private void SetupConfiguration(string path)
    {
        string iniFile = Path.Combine(path, "Ymir.toml");
        using (var ini = new IniFile(iniFile))
        {
            string saturnBiosPath = Path.Combine(AppConfig.GetFullPath("bios"), "saturn_bios.bin");

            if (SystemConfig.isOptSet("ymir_force_bios") && !string.IsNullOrEmpty(SystemConfig["ymir_force_bios"]))
            {
                saturnBiosPath = Path.Combine(AppConfig.GetFullPath("bios"), SystemConfig["ymir_force_bios"]);
            }

            ini.WriteValue("System.IPL", "Path", "'" + saturnBiosPath + "'");
            string iplPath = AppConfig.GetFullPath("bios");
            ini.WriteValue("General.PathOverrides", "IPLROMImages", "'" + iplPath + "'");
        }
    }
"""

# emulatorLauncher f681f435: the default falls back to the regional BIOS.
KRONOS_FALLBACK = """
    private void SetupConfig(string path)
    {
        string iniFile = Path.Combine(path, "kronos.ini");
        using (var ini = new IniFile(iniFile, IniOptions.KeepEmptyValues))
        {
            bool hleBios = false;
            string bios = Path.Combine(AppConfig.GetFullPath("bios"), "saturn_bios.bin");
            if (SystemConfig.isOptSet("kronos_force_bios") && !string.IsNullOrEmpty(SystemConfig["kronos_force_bios"]))
            {
                if (SystemConfig["kronos_force_bios"] != "hle")
                    bios = Path.Combine(AppConfig.GetFullPath("bios"), SystemConfig["kronos_force_bios"]);
                else
                    hleBios = true;
            }
            if (!hleBios && !File.Exists(bios))
                bios = new[] { "sega_101.bin", "mpr-17933.bin" }.Select(f => Path.Combine(AppConfig.GetFullPath("bios"), f)).FirstOrDefault(File.Exists) ?? bios;

            if (File.Exists(bios))
                ini.WriteValue("1.0", "General\\\\Bios", bios.Replace("\\\\", "/"));
        }
    }
"""

# emulatorLauncher f681f435: a forced BIOS only, written under a flag, and
# a folder below bios for the CD block ROM.
YMIR_OVERRIDE = """
    private void SetupConfiguration(string path)
    {
        string iniFile = Path.Combine(path, "Ymir.toml");
        using (var ini = new IniFile(iniFile))
        {
            string saturnBiosPath = null;
            if (SystemConfig.isOptSet("ymir_force_bios") && !string.IsNullOrEmpty(SystemConfig["ymir_force_bios"]))
                saturnBiosPath = Path.Combine(AppConfig.GetFullPath("bios"), SystemConfig["ymir_force_bios"]);

            bool overrideIpl = saturnBiosPath != null && File.Exists(saturnBiosPath);
            ini.WriteValue("System.IPL", "Override", overrideIpl ? "true" : "false");
            if (overrideIpl)
                ini.WriteValue("System.IPL", "Path", "'" + saturnBiosPath + "'");

            string iplPath = AppConfig.GetFullPath("bios");
            ini.WriteValue("General.PathOverrides", "IPLROMImages", "'" + iplPath + "'");
            string cdbPath = Path.Combine(iplPath, "cdb");
            FileTools.TryCreateDirectory(cdbPath);
            ini.WriteValue("General.PathOverrides", "CDBlockROMImages", "'" + cdbPath + "'");
        }
    }
"""

SSF = """
    private void SetupConfiguration(string path)
    {
        string iniFile = Path.Combine(path, "SSF.ini");
        using (var ini = IniFile.FromFile(iniFile, IniOptions.KeepEmptyValues))
        {
            if (SystemConfig.isOptSet("use_external_bios") && !string.IsNullOrEmpty(SystemConfig["use_external_bios"]))
            {
                string saturnBios = Path.Combine(AppConfig.GetFullPath("bios"), SystemConfig["use_external_bios"]);
                if (File.Exists(saturnBios) && SystemConfig["use_external_bios"] != "hle")
                    ini.WriteValue("Peripheral", "SaturnBIOS", "\\"" + saturnBios + "\\"");
                else
                    ini.WriteValue("Peripheral", "SaturnBIOS", "\\"" + "" + "\\"");
            }
        }
    }
"""


def _feature_sources(path: str, text: str, features: str) -> dict[str, Source]:
    return _sources(**{path: text, retrobat_generators.FEATURES: features})


class OptionReplacesThePath(unittest.TestCase):
    def test_kronos_default_then_option_without_hle(self):
        path = f"{GENERATORS}/Kronos.Generator.cs"
        sources = _feature_sources(path, KRONOS, SATURN_FEATURES)
        fixed, option = _option_path_in(sources[path], sources[retrobat_generators.FEATURES], "kronos")
        self.assertEqual(fixed["names"], ["saturn_bios.bin"])
        self.assertEqual(fixed["depends_on_option"], "kronos_force_bios unset")
        self.assertEqual(
            fixed["passes_to"], "kronos.ini [1.0] General\\Bios, only if the file exists"
        )
        self.assertEqual(fixed["source_ref"], f"{path}:6, 14-15")
        self.assertEqual(option["kind"], "core_option")
        self.assertEqual(option["names"], ["saturn_bios.bin", "sega_101.bin"])
        self.assertEqual(option["source_ref"], f"{path}:7-15, {retrobat_generators.FEATURES}:3-7")

    def test_ymir_writes_without_a_check_and_passes_the_folder(self):
        path = f"{GENERATORS}/Ymir.Generator.cs"
        sources = _feature_sources(path, YMIR, SATURN_FEATURES)
        fixed, option, folder = _option_path_in(sources[path], sources[retrobat_generators.FEATURES], "ymir")
        self.assertEqual(
            fixed["passes_to"], "Ymir.toml [System.IPL] Path, written without an existence check"
        )
        self.assertEqual(option["names"], ["saturn_bios.bin", "mpr-17933.bin"])
        self.assertEqual(folder["kind"], "passes_path")
        self.assertEqual(
            folder["passes_to"], "Ymir.toml [General.PathOverrides] IPLROMImages = bios"
        )

    def test_kronos_falls_back_to_the_regional_bios(self):
        path = f"{GENERATORS}/Kronos.Generator.cs"
        sources = _feature_sources(path, KRONOS_FALLBACK, SATURN_FEATURES)
        fixed, option, fallback = _option_path_in(
            sources[path], sources[retrobat_generators.FEATURES], "kronos"
        )
        self.assertEqual(
            fixed["fails_when_missing"],
            "sega_101.bin, then mpr-17933.bin, instead, else General\\Bios not written",
        )
        self.assertEqual(option["fails_when_missing"], fixed["fails_when_missing"])
        self.assertEqual(fallback["kind"], "names_searched")
        self.assertEqual(fallback["names"], ["sega_101.bin", "mpr-17933.bin"])
        self.assertEqual(
            fallback["passes_to"],
            "kronos.ini [1.0] General\\Bios = <first found>, only if the file exists",
        )
        self.assertEqual(
            fallback["depends_on_option"],
            "saturn_bios.bin absent with kronos_force_bios unset"
            " or the kronos_force_bios file absent, kronos_force_bios not hle",
        )
        self.assertEqual(fallback["source_ref"], f"{path}:15-19")

    def test_ymir_writes_a_forced_bios_under_its_flag(self):
        path = f"{GENERATORS}/Ymir.Generator.cs"
        sources = _feature_sources(path, YMIR_OVERRIDE, SATURN_FEATURES)
        option, ipl, cdb = _option_path_in(sources[path], sources[retrobat_generators.FEATURES], "ymir")
        self.assertEqual(
            option["passes_to"],
            "Ymir.toml [System.IPL] Path = <bios>/<value>, only if the file exists",
        )
        self.assertEqual(option["source_ref"], f"{path}:7-13, {retrobat_generators.FEATURES}:10-13")
        self.assertEqual(ipl["passes_to"], "Ymir.toml [General.PathOverrides] IPLROMImages = bios")
        self.assertEqual(cdb["search_dir"], "bios/cdb")
        self.assertEqual(
            cdb["passes_to"], "Ymir.toml [General.PathOverrides] CDBlockROMImages = bios/cdb"
        )
        self.assertEqual(cdb["source_ref"], f"{path}:15-19")

    def test_ssf_has_no_default_name(self):
        path = f"{GENERATORS}/SSF.Generator.cs"
        sources = _feature_sources(path, SSF, SATURN_FEATURES)
        [option] = _option_path_in(sources[path], sources[retrobat_generators.FEATURES], "ssf")
        self.assertEqual(option["names"], ["sega_101.bin"])
        self.assertEqual(
            option["passes_to"],
            "SSF.ini [Peripheral] SaturnBIOS = <bios>/<value>, only if the file exists",
        )


class AbsentConstructStopsTheScrape(unittest.TestCase):
    def test_each_extractor_raises_on_an_empty_source(self):
        empty = {path: Source(path, "") for path in rl.SOURCE_FILES}
        for extractor in rl.EXTRACTORS:
            with self.subTest(extractor=extractor.__name__), self.assertRaises(LauncherPatternMissing):
                extractor(empty)

    def test_chain_without_fallback_is_not_a_search(self):
        single = ARES.split("        if (!File.Exists(bios_japan))")[0] + "    }\n"
        with self.assertRaises(LauncherPatternMissing):
            ares(_sources(**{f"{GENERATORS}/Ares.Generator.cs": single}))

    def test_missing_source_file_is_named(self):
        with self.assertRaises(LauncherPatternMissing) as caught:
            rl.extract_launchers({})
        self.assertIn(rl.SOURCE_FILES[0], str(caught.exception))

    def test_the_error_is_a_scrape_error(self):
        self.assertTrue(issubclass(LauncherPatternMissing, ValueError))


class Helpers(unittest.TestCase):
    def test_header_keeps_a_string_holding_slashes(self):
        """The header regex cut `"http://x"` at its // as a comment."""
        src = Source("a.cs", 'void F(string s = "http://x") /* note */ // tail\n{\n}')
        self.assertEqual(src.header(src.blocks()[0]), 'void F(string s = "http://x")')

    def test_concatenation_renders_operands(self):
        self.assertEqual(
            render_concat('"BIOS file " + name + " does not exist in \'" + dir + "\'."'),
            "BIOS file <name> does not exist in '<dir>'.",
        )

    def test_braces_inside_strings_do_not_close_blocks(self):
        src = Source("x.cs", 'void f()\n{\n    s = "}";\n}\n')
        self.assertEqual(src.lines(*src.block_at(0)), (2, 4))

    def test_a_rescrape_reads_the_pinned_commit(self):
        from scraper import retrobat_scraper as rs

        pin = "ca486005f598551600d04a33b3156a5d764368d6"
        with tempfile.TemporaryDirectory() as scratch:
            yml = Path(scratch) / "retrobat.yml"
            yml.write_text(
                "source: https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/"
                f"{pin}/batocera-systems/Resources/batocera-systems.json\n",
                encoding="utf-8",
            )
            self.assertEqual(rs.pinned_revision(yml), pin)
        self.assertEqual(rs.resolve_revision(pin), pin)
        self.assertEqual(rs.resolve_revision(None), rs.pinned_revision())

    def test_revision_comes_from_the_pinned_url(self):
        url = (
            "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/"
            "48cdc61623c5943bb17647b80a60d32d395c3725/batocera-systems/Resources/batocera-systems.json"
        )
        self.assertEqual(revision_of(url), "48cdc61623c5943bb17647b80a60d32d395c3725")
        with self.assertRaises(ValueError):
            revision_of("https://example.test/master/batocera-systems.json")


if __name__ == "__main__":
    unittest.main()
