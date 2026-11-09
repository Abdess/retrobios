"""RetroBat's launcher layer read from emulatorLauncher's generators.

Each fixture is a cut-down copy of the construct at emulatorLauncher
48cdc61623c5943bb17647b80a60d32d395c3725, kept to the lines an extractor
reads. The records must carry the names in the launcher's order and point at
the fixture's own lines, and a construct that is gone must stop the scrape.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper import retrobat_launchers as rl  # noqa: E402
from scraper.retrobat_scraper import launcher_revision  # noqa: E402

G = rl.GENERATORS


def _sources(**texts: str) -> dict[str, rl.Source]:
    return {
        path: rl.Source(path, textwrap.dedent(text).lstrip("\n")) for path, text in texts.items()
    }


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


def _psx_sources() -> dict[str, rl.Source]:
    return _sources(
        **{
            f"{G}/Mednafen.Generator.cs": MEDNAFEN,
            f"{G}/Bizhawk.Generator.cs": MEDNAFEN.replace("mednafen_psx", "bizhawk_psx"),
            f"{G}/LibRetro.CoreOptions.cs": LIBRETRO_PSX,
        }
    )


class NamesInLauncherOrder(unittest.TestCase):
    def test_ares_fallback_chain_keeps_its_order(self):
        [record] = rl.ares(_sources(**{f"{G}/Ares.Generator.cs": ARES}))
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
        self.assertEqual(record["source_ref"], f"{G}/Ares.Generator.cs:7-14")

    def test_mesen_copy_names_source_and_renamed_target(self):
        [record] = rl.mesen(_sources(**{f"{G}/Mesen.Generator.cs": MESEN}))
        self.assertEqual(record["names"], ["colecovision.rom"])
        self.assertEqual(record["kind"], "copies")
        self.assertIn("<mesen>/Firmware/bios.col", record["passes_to"])
        self.assertEqual(
            record["fails_when_missing"],
            "ApplicationException 'Colecovision firmware is missing (colecovision.rom)'",
        )
        self.assertEqual(record["source_ref"], f"{G}/Mesen.Generator.cs:1-13")

    def test_amiberry_identical_lists_are_one_record(self):
        records = rl.amiberry(_sources(**{f"{G}/Amiberry.Generator.cs": AMIBERRY}))
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
            records[0]["source_ref"], f"{G}/Amiberry.Generator.cs:3-5, 8-10, 15-17, 23-27"
        )
        self.assertEqual(
            records[1]["passes_to"],
            "copied to <amiberry roms>/kick40060.CD32.ext, kickstart_ext_rom_file",
        )

    def test_amiberry_folders_are_below_its_emulator_folder(self):
        records = rl.amiberry(_sources(**{f"{G}/Amiberry.Generator.cs": AMIBERRY}))
        folders = [r for r in records if r["kind"] == "passes_path"]
        self.assertEqual(
            [(r["search_dir"], r["passes_to"], r["source_ref"]) for r in folders],
            [
                ('<AppConfig.GetFullPath("amiberry")>/ROMs', "written: rom_path in amiberry.conf",
                 f"{G}/Amiberry.Generator.cs:31, 37-41"),
                ('<AppConfig.GetFullPath("amiberry")>/WHDBoot',
                 "written: whdboot_path in amiberry.conf", f"{G}/Amiberry.Generator.cs:31, 40-41"),
            ],
        )

    def test_amiberry_copies_each_kickstart_into_its_roms_folder(self):
        records = rl.amiberry(_sources(**{f"{G}/Amiberry.Generator.cs": AMIBERRY}))
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
            f"{G}/Amiberry.Generator.cs:3-5, 8-10, 15, 23-27, 31, 37-39, 52-59",
        )

    def test_amiberry_copy_without_its_staleness_test_raises(self):
        broken = AMIBERRY.replace(" || dst.LastWriteTimeUtc < src.LastWriteTimeUtc", "")
        with self.assertRaises(rl.LauncherPatternMissing):
            rl.amiberry(_sources(**{f"{G}/Amiberry.Generator.cs": broken}))

    def test_psx_cascade_splits_searched_from_fallback(self):
        records = rl.psx_cascades(_psx_sources())
        searched, fallback = [r for r in records if r["emulator"] == "mednafen"]
        self.assertEqual(searched["names"], ["psxonpsp660.bin", "ps1_rom.bin"])
        self.assertEqual(searched["depends_on_option"], "mednafen_psx_original_bios off")
        self.assertEqual(fallback["names"], ["scph5502.bin", "scph5500.bin"])
        self.assertEqual(fallback["kind"], "fixed_name")
        self.assertEqual(fallback["fails_when_missing"], "names written without an existence check")
        self.assertEqual(searched["source_ref"], f"{G}/Mednafen.Generator.cs:1-21")

    def test_libretro_cascade_takes_the_core_from_its_guard(self):
        records = rl.psx_cascades(_psx_sources())
        [beetle] = [r for r in records if r["build"] == "libretro"]
        self.assertEqual(beetle["emulator"], "mednafen_psx_hw")
        self.assertEqual(beetle["names"], ["psxonpsp660.bin"])
        self.assertEqual(beetle["source_ref"], f"{G}/LibRetro.CoreOptions.cs:3-12")

    def test_openmsx_one_record_per_machine(self):
        records = rl.openmsx(_sources(**{f"{G}/OpenMSX.Generator.cs": OPENMSX}))
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
        self.assertEqual(records[1]["source_ref"], f"{G}/OpenMSX.Generator.cs:1-4, 10")

    def test_openmsx_home_is_handed_as_a_directory(self):
        # OPENMSX_HOME is the user directory openMSX reads share/systemroms below.
        records = rl.openmsx(_sources(**{f"{G}/OpenMSX.Generator.cs": OPENMSX}))
        home = records[-1]
        self.assertEqual(home["kind"], "passes_path")
        self.assertEqual(home["search_dir"], "bios/openmsx")
        self.assertEqual(home["source_ref"], f"{G}/OpenMSX.Generator.cs:13-14")

    def test_duckstation_reads_the_standalone_feature_not_the_core(self):
        search, option = rl.duckstation(
            _sources(**{f"{G}/Duckstation.Generator.cs": DUCKSTATION, rl.FEATURES: FEATURES})
        )
        self.assertEqual(search["kind"], "passes_path")
        self.assertEqual(search["names"], [])
        self.assertEqual(option["names"], ["psxonpsp660.bin", "scph5501.bin"])
        self.assertEqual(option["passes_to"], "settings.ini [BIOS] PathNTSCJ = PathPAL = <value>")
        self.assertEqual(
            option["source_ref"], f"{G}/Duckstation.Generator.cs:3-7, {rl.FEATURES}:12-15"
        )

    def test_hatari_default_and_option(self):
        fixed, option, emutos, newer = rl.hatari(
            _sources(**{f"{G}/Hatari.Generator.cs": HATARI, rl.FEATURES: HATARI_FEATURES})
        )
        message = "ApplicationException 'Missing TOS file <tosName> in 'bios' folder.'"
        self.assertEqual(fixed["names"], ["tos.img"])
        self.assertEqual(fixed["search_dir"], "bios")
        self.assertEqual(fixed["fails_when_missing"], f"bios/hatari/tos/emutos.img instead, else {message}")
        self.assertEqual(fixed["source_ref"], f"{G}/Hatari.Generator.cs:1-3, 13-14, 27")
        self.assertEqual(option["names"], ["tos206.img", "tos102.img"])
        self.assertEqual(option["search_dir"], "bios/hatari/tos")
        self.assertEqual(option["fails_when_missing"], message)
        self.assertEqual(emutos["names"], ["emutos.img"])
        self.assertEqual(emutos["search_dir"], "bios/hatari/tos")
        self.assertEqual(newer["kind"], "names_searched")
        self.assertEqual(newer["names"], ["tos104.img", "tos206.img", "emutos.img"])


def _one(text: str, emulator: str, path: str = f"{G}/X.Generator.cs") -> list[dict]:
    return rl.guarded_writes_in(_sources(**{path: text})[path], emulator)


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
        self.assertEqual(fixed[0]["source_ref"], f"{G}/X.Generator.cs:14-16")
        self.assertTrue(all(r["search_dir"] == "bios" and r["case_insensitive"] for r in fixed))
        self.assertNotIn("depends_on_option", fixed[0])

    def test_kega_fusion_genesis_key_receives_the_folder(self):
        (folder,) = [r for r in _one(KEGA, "kega-fusion") if r["kind"] == "passes_path"]
        self.assertEqual(folder["names"], [])
        self.assertEqual(folder["passes_to"], "Fusion.ini GenesisBIOS = bios")
        self.assertEqual(folder["source_ref"], f"{G}/X.Generator.cs:7, 11")

    def test_early_return_and_enclosing_if_are_conditions(self):
        (record,) = _one(JGENESIS, "jgenesis")
        self.assertEqual(
            record["depends_on_option"],
            'system == "genesis" || system == "sega_cd", system == "sega_cd"',
        )
        self.assertEqual(
            record["passes_to"], "jgenesis-config.toml [sega_cd] bios_path, only if the file exists"
        )
        self.assertEqual(record["source_ref"], f"{G}/X.Generator.cs:12-13, 17, 21-22")

    def test_option_switch_is_named(self):
        (record,) = _one(MELONDS, "melonds")
        self.assertEqual(record["names"], ["bios7.bin"])
        self.assertEqual(record["depends_on_option"], "melonds_externalBIOS on")
        self.assertEqual(
            record["passes_to"], "melonDS.toml [DS] BIOS7Path, only if the file exists"
        )

    def test_reassigned_path_is_not_a_fixed_name(self):
        with self.assertRaises(rl.LauncherPatternMissing):
            _one(REASSIGNED, "kronos")

    def test_write_inside_a_loop_is_not_read(self):
        looped = KEGA.replace("// BIOS", "foreach (var x in xs)\n            {").replace(
            '"32XM68KBIOS", bios32Xg);', '"32XM68KBIOS", bios32Xg);\n            }'
        )
        with self.assertRaises(rl.LauncherPatternMissing):
            _one(looped, "kega-fusion")

    def test_pinned_kega_fusion_generator_is_read(self):
        self.assertIn(f"{G}/KegaFusion.Generator.cs", rl.SOURCE_FILES)
        self.assertEqual(rl.GUARDED_WRITES[f"{G}/KegaFusion.Generator.cs"], "kega-fusion")


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

DESMUME = """
    private void SetupConfiguration(string path, string rom)
    {
        string settingsFile = Path.Combine(path, "desmume.ini");
        using (IniFile ini = IniFile.FromFile(settingsFile, IniOptions.KeepEmptyValues))
        {
            ini.WriteValue("BIOS", "UseExtBIOS", "0");
            if (SystemConfig.isOptSet("desmume_UseExtBIOS") && SystemConfig.getOptBoolean("desmume_UseExtBIOS"))
            {
                string bios7 = Path.Combine(AppConfig.GetFullPath("bios"), "bios7.bin");
                string bios9 = Path.Combine(AppConfig.GetFullPath("bios"), "bios9.bin");

                if (File.Exists(bios7) && File.Exists(bios9))
                {
                    ini.WriteValue("BIOS", "ARM9BIOSFile", bios9);
                    ini.WriteValue("BIOS", "ARM7BIOSFile", bios7);
                    ini.WriteValue("BIOS", "UseExtBIOS", "1");
                }
            }

            if (SystemConfig.isOptSet("desmume_UseExtFirmware") && SystemConfig.getOptBoolean("desmume_UseExtFirmware"))
            {
                string firmware = Path.Combine(AppConfig.GetFullPath("bios"), "firmware.bin");

                if (SystemConfig.isOptSet("desmume_firmwareFile") && !string.IsNullOrEmpty(SystemConfig["desmume_firmwareFile"]))
                {
                    string newFirmware = SystemConfig["desmume_firmwareFile"];
                    if (File.Exists(newFirmware))
                        firmware = newFirmware;
                }

                if (File.Exists(firmware))
                {
                    ini.WriteValue("Firmware", "FirmwareFile", firmware);
                    ini.WriteValue("Firmware", "UseExtFirmware", "1");
                }
            }
        }
    }
"""

MELONDS_DSI = """
    bool bootToDSINand = Path.GetExtension(rom).ToLowerInvariant() == ".bin";

    private void SetupConfiguration(string path, string rom, bool bootToDSINand = false)
    {
        string settingsFile = Path.Combine(path, "melonDS.toml");
        using (IniTomlFile ini = IniTomlFile.FromFile(settingsFile, IniTomlOptions.UseSpaces))
        {
            bool dsi = SystemConfig.isOptSet("melonds_console") && SystemConfig["melonds_console"] == "dsi";

            if (bootToDSINand)
                dsi = true;

            if (dsi)
            {
                string biosPath = AppConfig.GetFullPath("bios");
                string dsibios9 = Path.Combine(biosPath, "dsi_bios9.bin");
                string dsinand = Path.Combine(biosPath, "dsi_nand.bin");

                if (SystemConfig.isOptSet("melonds_nandregion") && !string.IsNullOrEmpty(SystemConfig["melonds_nandregion"]))
                {
                    string region = SystemConfig["melonds_nandregion"];
                    string match = Directory.GetFiles(biosPath, "dsi_nand*.bin")
                        .FirstOrDefault(f => Path.GetFileNameWithoutExtension(f)
                            .IndexOf(region, StringComparison.OrdinalIgnoreCase) >= 0);

                    if (match != null)
                        dsinand = match;
                }

                if (!File.Exists(dsibios9) || !File.Exists(dsinand))
                    throw new ApplicationException("Cannot run dsi system, dsi bios files are missing");

                ini.WriteValue("DSi", "BIOS9Path", "\\"" + dsibios9.Replace("\\\\", "/") + "\\"");
                ini.WriteValue("DSi", "NANDPath", "\\"" + dsinand.Replace("\\\\", "/") + "\\"");
            }
        }
    }
"""

MELONDS_FEATURES = """
    <emulator name="melonds">
      <feature name="DSI NAND REGION" value="melonds_nandregion" order="103">
        <choice name="USA" value="USA"/>
        <choice name="Japan" value="JPN"/>
      </feature>
    </emulator>
"""

JZINTV = """
    public override ProcessStartInfo Generate(string system, string rom)
    {
        string gromPath = Path.Combine(AppConfig.GetFullPath("bios"), "grom.bin");
        string execPath = Path.Combine(AppConfig.GetFullPath("bios"), "exec.bin");

        if (!File.Exists(gromPath) || !File.Exists(execPath))
            throw new ApplicationException("grom.bin or exec.bin not found in bios folder!");

        commandArray.Add("-e");
        commandArray.Add("\\"" + execPath + "\\"");
        commandArray.Add("-g");
        commandArray.Add("\\"" + gromPath + "\\"");

        string commandFile = rom.Replace(Path.GetExtension(rom), ".commands");

        if (!File.Exists(commandFile))
            commandFile = Path.Combine(AppConfig.GetFullPath("roms"),"intellivision", "default.commands");

        if (File.Exists(commandFile))
        {
        }
        else
        {
            if (SystemConfig.getOptBoolean("jzintv_useECS"))
            {
                string ecsPath = Path.Combine(AppConfig.GetFullPath("bios"), "ecs.bin");

                if (File.Exists(ecsPath))
                {
                    commandArray.Add("-E");
                    commandArray.Add("\\"" + ecsPath + "\\"");
                }
                else
                {
                    SimpleLogger.Instance.Warning("[WARN] ecs.bin not found in bios folder!");
                    commandArray.Add("-s0");
                }
            }
        }
    }
"""

BLASTEM = """
    private void SetupConfiguration(string path)
    {
        string targetCfg = Path.Combine(path, "blastem.cfg");
        var sys = cfg.GetOrCreateSection("system");
    }

    private void SetupSystem(BlastemConfigNode sys, string path)
    {
        string bios = AppConfig.GetFullPath("bios");
        SetBiosPath(sys, "scd_bios_us", bios, "bios_CD_U.bin");
        SetBiosPath(sys, "coleco_bios_path", bios, "colecovision.rom");
    }

    private static void SetBiosPath(BlastemConfigNode sys, string key, string biosPath, string fileName)
    {
        string file = Path.Combine(biosPath, fileName);
        if (File.Exists(file))
            sys[key] = file;
        else
            SimpleLogger.Instance.Info("[Generator] BIOS not found, leaving " + key + " alone : " + file);
    }
"""

DOLPHIN = """
    private void SetupGeneralConfig(string path)
    {
        string iniFile = Path.Combine(path, "User", "Config", "Dolphin.ini");
        using (var ini = new IniFile(iniFile, IniOptions.UseSpaces))
        {
            string gbaBiosPath = Path.Combine(AppConfig.GetFullPath("bios"), "gba_bios.bin");
            ini.WriteValue("GBA", "BIOS", gbaBiosPath);

            if (_triforce)
            {
                if (!_crediar)
                    CopySegaBoot(path);
            }
        }
    }

    private void CopySegaBoot(string path)
    {
        string target = Path.Combine(path, "User", "Triforce", "segaboot.gcm");

        string[] candidates = new string[]
        {
            Path.Combine(AppConfig.GetFullPath("bios"), "triforce", "segaboot.gcm"),
            Path.Combine(AppConfig.GetFullPath("bios"), "segaboot.gcm")
        };

        string source = candidates.FirstOrDefault(f => File.Exists(f));
        if (source == null)
        {
            if (!File.Exists(target))
                SimpleLogger.Instance.Warning("[WARNING] segaboot.gcm not found");
            return;
        }

        if (dst.Exists && dst.Length == src.Length && dst.LastWriteTimeUtc >= src.LastWriteTimeUtc)
            return;
    }

    private static bool GetRvzHash(string rvzPath)
    {
        string dolphinTool = Path.Combine(Program.AppConfig.GetFullPath("bios"), "dolphin-emu", "DolphinTool.exe");
    }
"""

DOSBOX = """
    private void SearchAndCopySoundFiles(string path)
    {
        string targetPathFluidSynth = Path.Combine(path, "soundfonts");
        string targetPathmt32 = Path.Combine(path, "mt32-roms");

        try
        {
            string mtcontrolsource = Path.Combine(AppConfig.GetFullPath("bios"), "scummvm", "extra", "MT32_CONTROL.ROM");
            string mtcontroltarget = Path.Combine(targetPathmt32, "MT32_CONTROL.ROM");
            if (!File.Exists(mtcontroltarget) && File.Exists(mtcontrolsource))
                try { File.Copy(mtcontrolsource, mtcontroltarget); } catch { }

            string roland55source = Path.Combine(AppConfig.GetFullPath("bios"), "scummvm", "extra", "Roland_SC-55.sf2");
            string roland55target = Path.Combine(targetPathFluidSynth, "Roland_SC-55.sf2");
            if (!File.Exists(roland55target) && File.Exists(roland55source))
                try { File.Copy(roland55source, roland55target); } catch { }
        }
        catch
        {
        }
    }
"""

TSUGARU = """
    public override ProcessStartInfo Generate(string system, string rom)
    {
        string biosPath = null;

        if (Directory.Exists(Path.Combine(AppConfig.GetFullPath("bios"), "fmtowns")))
            biosPath = Path.Combine(AppConfig.GetFullPath("bios"), "fmtowns");
        if (!File.Exists(Path.Combine(biosPath, "FMT_SYS.ROM")))
            biosPath = Path.Combine(AppConfig.GetFullPath("bios"), "fmtownsux");
        if (!File.Exists(Path.Combine(biosPath, "FMT_SYS.ROM")))
            biosPath = Path.Combine(path, "roms");
        if (!File.Exists(Path.Combine(biosPath, "FMT_SYS.ROM")))
        {
            SimpleLogger.Instance.Info("[TsugaruGenerator] Bios path not found");
            return null;
        }

        commandArray.Add(biosPath);
        commandArray.Add("-CMOS");
        commandArray.Add(Path.Combine(biosPath, "CMOS.DAT"));
    }
"""

EKA2L1 = """
    public override ProcessStartInfo Generate(string system, string rom)
    {
        /*if (rom != null)
        {
            string bios = Path.Combine(AppConfig.GetFullPath("bios"), "N-Gage Installer.sis");
        }*/
    }

    private void SetupConfiguration(string path)
    {
        var yml = YmlFile.Load(Path.Combine(path, "config.yml"));
        string dataFolder = Path.Combine(AppConfig.GetFullPath("bios"), "eka2l1", "data").Replace("\\\\", "/");
        yml["data-storage"] = dataFolder;
    }
"""

BIZHAWK_GB = """
    private void ConfigureGambatte(DynamicJson coreSyncSettings, string core, string system)
    {
        if (core != "Gambatte")
            return;

        var gambatteSync = coreSyncSettings.GetOrCreateContainer("BizHawk.Emulation.Cores.Nintendo.Gameboy.Gameboy");

        string gbBios = Path.Combine(AppConfig.GetFullPath("bios"), "gb_bios.bin");
        if (system == "gbc")
            gbBios = Path.Combine(AppConfig.GetFullPath("bios"), "gbc_bios.bin");
        else if (system == "gba")
            gbBios = Path.Combine(AppConfig.GetFullPath("bios"), "gba_bios.bin");

        if (File.Exists(gbBios) && SystemConfig.getOptBoolean("bizhawk_gb_bios"))
            gambatteSync["EnableBIOS"] = "true";
        else
            gambatteSync["EnableBIOS"] = "false";
    }
"""

BIZHAWK_CONFIG = """
    string configFile = Path.Combine(path, "config.ini");
"""

MESS = """
    public List<string> GetMameCommandLineArguments(string system, string rom, bool standalone = false)
    {
        string bios = AppConfig.GetFullPath("bios");

        commandArray.Add("-rp");
        if (!string.IsNullOrEmpty(AppConfig["bios"]) && Directory.Exists(AppConfig.GetFullPath("bios")))
        {
            if (Directory.Exists(Path.Combine(bios, "mess")))
                commandArray.Add(Path.Combine(bios, "mess") + ";" + bios + ";" + Path.GetDirectoryName(rom));
            else
                commandArray.Add(bios + ";" + Path.GetDirectoryName(rom));
        }

        if (standalone)
        {
            commandArray.Add("-hash");
            commandArray.Add(EnsureDirectoryExists(Path.Combine(bios, "mame", "hash")));
        }
    }
"""

MAME64 = """
    public override ProcessStartInfo Generate(string system, string rom)
    {
        if (messMode == null)
        {
            List<string> commandArray = new List<string>
            {
                "-skip_gameinfo",
                "-rp"
            };
            if (!string.IsNullOrEmpty(AppConfig["bios"]) && Directory.Exists(AppConfig["bios"]))
                commandArray.Add(AppConfig.GetFullPath("bios") + ";" + Path.GetDirectoryName(rom));

            string samplePath = hbmame? Path.Combine(AppConfig.GetFullPath("bios"), "hbmame", "samples") : Path.Combine(AppConfig.GetFullPath("bios"), "mame", "samples");
            commandArray.Add("-sp");
            commandArray.Add(samplePath);
        }
    }
"""

XROAR = """
    public override ProcessStartInfo Generate(string system, string rom)
    {
        commandArray.Add("-rompath");
        string romPath = Path.Combine(AppConfig.GetFullPath("bios"), "dragon");
        if (system == "coco")
            romPath = Path.Combine(AppConfig.GetFullPath("bios"), "coco");
        commandArray.Add("\\"" + romPath + "\\"");
        string setupPath = Path.Combine(path, "xroar.conf");
    }

    private void SetupConfiguration(string setupPath)
    {
        string rompath = "rompath \\".\\\\\\\\..\\\\\\\\..\\\\\\\\bios\\\\\\\\dragon\\"";
        for (int i = 0; i < lines.Count; i++)
        {
            if (lines[i].StartsWith("rompath "))
                lines[i] = rompath;
        }
    }
"""


def _feature_sources(path: str, text: str, features: str) -> dict[str, rl.Source]:
    return _sources(**{path: text, rl.FEATURES: features})


class OptionReplacesThePath(unittest.TestCase):
    def test_kronos_default_then_option_without_hle(self):
        path = f"{G}/Kronos.Generator.cs"
        sources = _feature_sources(path, KRONOS, SATURN_FEATURES)
        fixed, option = rl._option_path_in(sources[path], sources[rl.FEATURES], "kronos")
        self.assertEqual(fixed["names"], ["saturn_bios.bin"])
        self.assertEqual(fixed["depends_on_option"], "kronos_force_bios unset")
        self.assertEqual(
            fixed["passes_to"], "kronos.ini [1.0] General\\Bios, only if the file exists"
        )
        self.assertEqual(fixed["source_ref"], f"{path}:6, 14-15")
        self.assertEqual(option["kind"], "core_option")
        self.assertEqual(option["names"], ["saturn_bios.bin", "sega_101.bin"])
        self.assertEqual(option["source_ref"], f"{path}:7-15, {rl.FEATURES}:3-7")

    def test_ymir_writes_without_a_check_and_passes_the_folder(self):
        path = f"{G}/Ymir.Generator.cs"
        sources = _feature_sources(path, YMIR, SATURN_FEATURES)
        fixed, option, folder = rl._option_path_in(sources[path], sources[rl.FEATURES], "ymir")
        self.assertEqual(
            fixed["passes_to"], "Ymir.toml [System.IPL] Path, written without an existence check"
        )
        self.assertEqual(option["names"], ["saturn_bios.bin", "mpr-17933.bin"])
        self.assertEqual(folder["kind"], "passes_path")
        self.assertEqual(
            folder["passes_to"], "Ymir.toml [General.PathOverrides] IPLROMImages = bios"
        )

    def test_ssf_has_no_default_name(self):
        path = f"{G}/SSF.Generator.cs"
        sources = _feature_sources(path, SSF, SATURN_FEATURES)
        [option] = rl._option_path_in(sources[path], sources[rl.FEATURES], "ssf")
        self.assertEqual(option["names"], ["sega_101.bin"])
        self.assertEqual(
            option["passes_to"],
            "SSF.ini [Peripheral] SaturnBIOS = <bios>/<value>, only if the file exists",
        )


class FilesNeededTogether(unittest.TestCase):
    def test_desmume_pair_and_firmware_override(self):
        pair, firmware = rl.desmume(_sources(**{f"{G}/Desmume.Generator.cs": DESMUME}))
        self.assertEqual(pair["names"], ["bios7.bin", "bios9.bin"])
        self.assertEqual(
            pair["passes_to"],
            "desmume.ini [BIOS] ARM7BIOSFile, ARM9BIOSFile, only if every listed file exists",
        )
        self.assertEqual(pair["fails_when_missing"], "UseExtBIOS left at 0")
        self.assertEqual(pair["depends_on_option"], "desmume_UseExtBIOS on")
        self.assertEqual(firmware["names"], ["firmware.bin"])
        self.assertEqual(
            firmware["depends_on_option"],
            "desmume_UseExtFirmware on, desmume_firmwareFile unset or not an existing file",
        )

    def test_melonds_dsi_files_and_nand_region(self):
        fixed, region = rl.melonds_dsi(
            _sources(**{f"{G}/MelonDS.Generator.cs": MELONDS_DSI, rl.FEATURES: MELONDS_FEATURES})
        )
        self.assertEqual(fixed["names"], ["dsi_bios9.bin", "dsi_nand.bin"])
        self.assertEqual(fixed["passes_to"], "melonDS.toml [DSi] BIOS9Path, NANDPath")
        self.assertEqual(
            fixed["fails_when_missing"],
            "ApplicationException 'Cannot run dsi system, dsi bios files are missing'",
        )
        self.assertEqual(
            fixed["depends_on_option"], 'melonds_console == "dsi" || rom extension ".bin"'
        )
        self.assertEqual(region["kind"], "scans_dir")
        self.assertEqual(region["names"], ["dsi_nand*{region}*.bin"])
        self.assertEqual(region["expands"], {"region": ["USA", "JPN"]})
        self.assertEqual(region["fails_when_missing"], "falls back to dsi_nand.bin")

    def test_jzintv_flags_in_command_line_order(self):
        both, ecs = rl.jzintv(_sources(**{f"{G}/Jzintv.Generator.cs": JZINTV}))
        self.assertEqual(both["names"], ["exec.bin", "grom.bin"])
        self.assertEqual(both["passes_to"], "command line -e <bios>/exec.bin -g <bios>/grom.bin")
        self.assertEqual(ecs["names"], ["ecs.bin"])
        self.assertEqual(
            ecs["depends_on_option"],
            "jzintv_useECS on, no <rom>.commands and no roms/intellivision/default.commands",
        )
        self.assertEqual(
            ecs["fails_when_missing"],
            "warning '[WARN] ecs.bin not found in bios folder!', -s0 passed",
        )


class HelpersAndCopies(unittest.TestCase):
    def test_blastem_one_record_per_helper_call(self):
        records = rl.blastem(_sources(**{f"{G}/Blastem.Generator.cs": BLASTEM}))
        self.assertEqual(
            [(r["names"], r["passes_to"]) for r in records],
            [
                (["bios_CD_U.bin"], "blastem.cfg system.scd_bios_us, only if the file exists"),
                (
                    ["colecovision.rom"],
                    "blastem.cfg system.coleco_bios_path, only if the file exists",
                ),
            ],
        )
        self.assertEqual(records[0]["source_ref"], f"{G}/Blastem.Generator.cs:9-10, 14-21")

    def test_dolphin_unchecked_write_and_segaboot_candidates(self):
        gba, segaboot = rl.dolphin(_sources(**{f"{G}/Dolphin.Generator.cs": DOLPHIN}))
        self.assertEqual(gba["names"], ["gba_bios.bin"])
        self.assertEqual(
            gba["passes_to"],
            "User/Config/Dolphin.ini [GBA] BIOS, written without an existence check",
        )
        self.assertEqual(segaboot["kind"], "copies")
        self.assertEqual(segaboot["names"], ["triforce/segaboot.gcm", "segaboot.gcm"])
        self.assertEqual(
            segaboot["depends_on_option"],
            "_triforce, !_crediar, first name found, the target is absent, smaller or older",
        )

    def test_dosbox_copies_grouped_by_target_folder(self):
        sources = _sources(
            **{f"{G}/DosBoxPure.Generator.cs": DOSBOX, f"{G}/DosBoxStaging.Generator.cs": DOSBOX}
        )
        records = rl.dosbox_copies(sources)
        self.assertEqual(
            [(r["emulator"], r["names"], r["passes_to"]) for r in records[:2]],
            [
                (
                    "dosbox-pure",
                    ["MT32_CONTROL.ROM"],
                    "<emulator>/mt32-roms/<name>",
                ),
                (
                    "dosbox-pure",
                    ["Roland_SC-55.sf2"],
                    "<emulator>/soundfonts/<name>",
                ),
            ],
        )
        self.assertEqual(records[0]["search_dir"], "bios/scummvm/extra")
        self.assertEqual(records[0]["depends_on_option"], "the target does not exist")

    def test_tsugaru_folder_chain(self):
        [record] = rl.tsugaru(_sources(**{f"{G}/Tsugaru.Generator.cs": TSUGARU}))
        self.assertEqual(record["names"], ["FMT_SYS.ROM"])
        self.assertEqual(
            record["search_dir"], "bios/fmtowns, then bios/fmtownsux, then <emulator>/roms"
        )
        self.assertEqual(
            record["fails_when_missing"], "info '[TsugaruGenerator] Bios path not found', no launch"
        )

    def test_commented_code_is_not_read(self):
        [record] = rl.eka2l1(_sources(**{f"{G}/Eka2l1.Generator.cs": EKA2L1}))
        self.assertEqual(record["passes_to"], "config.yml data-storage = bios/eka2l1/data")

    def test_bizhawk_gb_one_slot_per_system(self):
        records = rl.bizhawk_gb(
            _sources(
                **{
                    f"{G}/Bizhawk.CoreOptions.cs": BIZHAWK_GB,
                    f"{G}/Bizhawk.Generator.cs": BIZHAWK_CONFIG,
                }
            )
        )
        self.assertEqual(
            [(r["slot"], r["names"]) for r in records],
            [
                ("other systems", ["gb_bios.bin"]),
                ("gbc", ["gbc_bios.bin"]),
                ("gba", ["gba_bios.bin"]),
            ],
        )
        self.assertEqual(
            records[0]["depends_on_option"],
            'core == "Gambatte", bizhawk_gb_bios on, system != "gbc" && system != "gba"',
        )
        self.assertEqual(records[0]["fails_when_missing"], "EnableBIOS = false")


class FolderArguments(unittest.TestCase):
    def test_mess_folders_shared_with_the_libretro_core(self):
        sources = _sources(**{f"{G}/MessSystem.cs": MESS, f"{G}/Mame64.Generator.cs": MAME64})
        records = rl.mame(sources)
        mess = [r for r in records if r["source_ref"].startswith(f"{G}/MessSystem.cs")]
        self.assertEqual(
            [(r["emulator"], r["passes_to"]) for r in mess],
            [
                ("mame64", "command line -rp bios/mess;bios;<rom directory>"),
                ("mame", "command line -rp bios/mess;bios;<rom directory>"),
                ("mame64", "command line -rp bios;<rom directory>"),
                ("mame", "command line -rp bios;<rom directory>"),
                ("mame64", "command line -hash bios/mame/hash"),
            ],
        )
        self.assertTrue(
            mess[2]["depends_on_option"].endswith('!Directory.Exists(Path.Combine(bios, "mess"))')
        )
        self.assertNotIn("depends_on_option", mess[4])

    def test_mame64_ternary_folder(self):
        sources = _sources(**{f"{G}/MessSystem.cs": MESS, f"{G}/Mame64.Generator.cs": MAME64})
        own = [r for r in rl.mame(sources) if r["source_ref"].startswith(f"{G}/Mame64")]
        self.assertEqual(own[0]["passes_to"], "command line -rp bios;<rom directory>")
        self.assertEqual(
            own[1]["search_dir"], "bios/hbmame/samples when hbmame, else bios/mame/samples"
        )

    def test_xroar_reassigned_folder_and_config_line(self):
        # romPath is bios/dragon, rewritten to bios/coco for the coco system.
        default, coco, config = rl.xroar(_sources(**{
            f"{G}/Xroar.Generator.cs": XROAR, rl.FEATURES: XROAR_FEATURES,
        }))
        self.assertEqual(
            (default["search_dir"], default["passes_to"], default.get("systems")),
            ("bios/dragon", "command line -rompath bios/dragon", None),
        )
        self.assertEqual(
            (coco["search_dir"], coco["passes_to"], coco["systems"]),
            ("bios/coco", "command line -rompath bios/coco", ["coco"]),
        )
        self.assertEqual(coco["machines"], ["coco", "coco3"])
        self.assertNotIn("machines", default)
        self.assertEqual(
            coco["source_ref"], f"{default['source_ref']}, {rl.FEATURES}:3-6"
        )
        self.assertEqual(config["search_dir"], "bios/dragon")
        self.assertEqual(
            config["passes_to"], 'xroar.conf rompath ".\\\\..\\\\..\\\\bios\\\\dragon"'
        )


XROAR_FEATURES = """
    <emulator name="xroar">
      <system name="coco">
        <feature submenu="EMULATION" name="MACHINE" value="xroar_machine" order="100">
          <choice name="TANDY COCO(PAL)" value="coco"/>
          <choice name="TANDY COCO 3(NTSC)" value="coco3"/>
        </feature>
      </system>
      <system name="dragon32,dragon64,dragon">
        <feature submenu="EMULATION" name="MACHINE" value="xroar_machine" order="100">
          <choice name="DRAGON64" value="dragon64"/>
        </feature>
      </system>
    </emulator>
"""


PICO8 = """
    public override System.Diagnostics.ProcessStartInfo Generate(string system, string emulator, string core, string rom, string playersControllers, ScreenResolution resolution)
    {
        string path = AppConfig.GetFullPath("pico8");

        string exe = Path.Combine(path, "pico8.exe");
        if (!File.Exists(exe))
            return null;

        return new ProcessStartInfo()
        {
            FileName = exe,
            WorkingDirectory = path,
            Arguments = args,
        };
    }
"""


class ProgramsRunFromEmulatorFolders(unittest.TestCase):
    def test_pico8_runs_its_binary_from_its_emulator_folder(self):
        (record,) = rl.pico8(_sources(**{f"{G}/Pico8.Generator.cs": PICO8}))
        self.assertEqual(
            (record["emulator"], record["kind"], record["names"], record["search_dir"],
             record["passes_to"], record["source_ref"]),
            ("pico8", "fixed_name", ["pico8.exe"], '<AppConfig.GetFullPath("pico8")>', "exec",
             f"{G}/Pico8.Generator.cs:3-7, 11-12"),
        )


class EveryBiosReferenceIsRead(unittest.TestCase):
    def test_unread_reference_stops_the_scrape(self):
        extra = EKA2L1 + (
            "\n    private void Other()\n    {\n"
            '        string other = Path.Combine(AppConfig.GetFullPath("bios"), "other.bin");\n'
            "    }\n"
        )
        with self.assertRaises(rl.LauncherPatternMissing) as caught:
            rl.eka2l1(_sources(**{f"{G}/Eka2l1.Generator.cs": extra}))
        self.assertIn("bios reference at line", str(caught.exception))

    def test_semicolon_inside_a_string_does_not_end_the_value(self):
        src = rl.Source(
            "x.cs",
            'void f(string rom)\n{\n    string p = AppConfig.GetFullPath("bios") + ";" + Path.GetDirectoryName(rom);\n}\n',
        )
        self.assertEqual(rl._render(src, "p", 0, len(src.text))[0], "bios;<rom directory>")


class AbsentConstructStopsTheScrape(unittest.TestCase):
    def test_each_extractor_raises_on_an_empty_source(self):
        empty = {path: rl.Source(path, "") for path in rl.SOURCE_FILES}
        for extractor in rl.EXTRACTORS:
            with self.subTest(extractor=extractor.__name__):
                with self.assertRaises(rl.LauncherPatternMissing):
                    extractor(empty)

    def test_chain_without_fallback_is_not_a_search(self):
        single = ARES.split("        if (!File.Exists(bios_japan))")[0] + "    }\n"
        with self.assertRaises(rl.LauncherPatternMissing):
            rl.ares(_sources(**{f"{G}/Ares.Generator.cs": single}))

    def test_missing_source_file_is_named(self):
        with self.assertRaises(rl.LauncherPatternMissing) as caught:
            rl.extract_launchers({})
        self.assertIn(rl.SOURCE_FILES[0], str(caught.exception))

    def test_the_error_is_a_scrape_error(self):
        self.assertTrue(issubclass(rl.LauncherPatternMissing, ValueError))


class Helpers(unittest.TestCase):
    def test_concatenation_renders_operands(self):
        self.assertEqual(
            rl.render_concat('"BIOS file " + name + " does not exist in \'" + dir + "\'."'),
            "BIOS file <name> does not exist in '<dir>'.",
        )

    def test_braces_inside_strings_do_not_close_blocks(self):
        src = rl.Source("x.cs", 'void f()\n{\n    s = "}";\n}\n')
        self.assertEqual(src.lines(*src.block_at(0)), (2, 4))

    def test_revision_comes_from_the_pinned_url(self):
        url = (
            "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/"
            "48cdc61623c5943bb17647b80a60d32d395c3725/batocera-systems/Resources/batocera-systems.json"
        )
        self.assertEqual(launcher_revision(url), "48cdc61623c5943bb17647b80a60d32d395c3725")
        with self.assertRaises(ValueError):
            launcher_revision("https://example.test/master/batocera-systems.json")


if __name__ == "__main__":
    unittest.main()
