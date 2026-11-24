"""RetroBat's launcher layer: files the generators copy, write and pass.

Each fixture is a cut-down copy of the construct at emulatorLauncher
48cdc61623c5943bb17647b80a60d32d395c3725, kept to the lines an extractor
reads.
"""

from __future__ import annotations

import tests

import unittest

from scraper import retrobat_generators
from scraper.retrobat_arguments import pico8, xroar, mame
from scraper.retrobat_config_files import (
    bizhawk_gb,
    dolphin,
    blastem,
    jzintv,
    melonds_dsi,
    desmume,
)
from scraper.retrobat_config_folders import eka2l1, tsugaru, dosbox_copies
from scraper.retrobat_render import render
from scraper.retrobat_xbox import CXBX_DATA_FOLDER, cxbx, xemu_saves
from scraper.csharp_source import LauncherPatternMissing, Source
from tests.launchersretrobatsupport import G, _sources


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


class FilesNeededTogether(unittest.TestCase):
    def test_desmume_pair_and_firmware_override(self):
        pair, firmware = desmume(_sources(**{f"{G}/Desmume.Generator.cs": DESMUME}))
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
        fixed, region = melonds_dsi(
            _sources(**{f"{G}/MelonDS.Generator.cs": MELONDS_DSI, retrobat_generators.FEATURES: MELONDS_FEATURES})
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
        both, ecs = jzintv(_sources(**{f"{G}/Jzintv.Generator.cs": JZINTV}))
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


XEMU_SAVES = """
    public override ProcessStartInfo Generate(string system, string emulator, string core, string rom)
    {
        _chihiro = (emulator == "xemu-chihiro" || system == "chihiro");
        if (!string.IsNullOrEmpty(AppConfig["saves"]) && Directory.Exists(AppConfig.GetFullPath("saves")))
        {
            string savePath = Path.Combine(AppConfig.GetFullPath("saves"), system);
            if (!_chihiro)
            {
                if (!File.Exists(Path.Combine(savePath, "eeprom.bin")))
                {
                    File.WriteAllBytes(Path.Combine(savePath, "eeprom.bin"), Properties.Resources.eeprom);
                }
                if (!File.Exists(Path.Combine(savePath, "xbox_hdd.qcow2")))
                {
                    string zipFile = Path.Combine(savePath, "xbox_hdd.qcow2.zip");
                    File.WriteAllBytes(zipFile, Properties.Resources.xbox_hdd_qcow2);
                    Zip.Extract(zipFile, savePath);
                    File.Delete(zipFile);
                }
            }
        }
    }

    private void SetupTOMLConfiguration(string eepromPath, string hddPath)
    {
        if (!string.IsNullOrEmpty(eepromPath))
            ini.WriteValue("sys.files", "eeprom_path", "'" + eepromPath + "'");
        if (!string.IsNullOrEmpty(hddPath))
            ini.WriteValue("sys.files", "hdd_path", "'" + hddPath + "'");
    }

    private void SetupChihiroConfiguration()
    {
        string savePath = Path.Combine(AppConfig.GetFullPath("saves"), "chihiro");
        if (!Directory.Exists(savePath)) try { Directory.CreateDirectory(savePath); } catch { }
        if (Directory.Exists(savePath))
            ini.WriteValue("chihiro.roms", "snapshot_store_path", "'" + Path.Combine(savePath, "chihiro_snapshots.qcow2") + "'");
    }

    private void SetupChihiroEeprom(string path)
    {
        string savePath = Path.Combine(AppConfig.GetFullPath("saves"), "chihiro");
        _chihiroEeprom = Path.Combine(path, "chihiro_eeprom.bin");
        _chihiroEepromSave = Path.Combine(savePath, "chihiro_eeprom.bin");
    }

    private void SaveChihiroEeprom()
    {
        if (File.Exists(_chihiroEeprom))
            File.Copy(_chihiroEeprom, _chihiroEepromSave, true);
    }
"""

CXBX = """
    private string MountIso(string rom)
    {
        if (Path.GetExtension(rom).ToLowerInvariant() != ".iso")
            return rom;
        string xboxIsoVfsPath = Path.Combine(Path.GetDirectoryName(typeof(Installer).Assembly.Location), "xbox-iso-vfs.exe");
        if (!File.Exists(xboxIsoVfsPath))
            throw new ApplicationException("xbox-iso-vfs is required and is not installed");
        string dokan = Environment.GetEnvironmentVariable("DokanLibrary2");
        dokan = Path.Combine(dokan, "dokan2.dll");
        if (!File.Exists(dokan))
        {
            throw new ApplicationException("Dokan 2 is required and is not installed");
        }
    }

    public override ProcessStartInfo Generate(string system, string emulator, string core, string rom)
    {
        string path = null;
        if ((core != null && core == "chihiro") || (emulator != null && emulator == "chihiro"))
        {
            path = AppConfig.GetFullPath("chihiro");
        }
        else if ((core != null && core == "chihiro-gun") || (emulator != null && emulator == "chihiro-gun"))
        {
            path = AppConfig.GetFullPath("chihiro-ds");
        }
        if (string.IsNullOrEmpty(path))
            path = AppConfig.GetFullPath("cxbx-reloaded");
        if (string.IsNullOrEmpty(path))
            path = AppConfig.GetFullPath("cxbx-r");
        using (var ini = IniFile.FromFile(Path.Combine(path, "settings.ini"), IniOptions.KeepEmptyValues))
        {
        }
        if (system == "xbox")
        {
            string eeprom = Path.Combine(AppConfig.GetFullPath("cxbx-reloaded"), "EEPROM.bin");
            if (!File.Exists(eeprom))
                File.WriteAllBytes(eeprom, Properties.Resources.eeprom);

            WriteXboxEEPROM(eeprom);
        }
    }
"""


class XboxFilesTheLauncherWrites(unittest.TestCase):
    def test_xemu_keeps_its_eeprom_and_disk_below_saves(self):
        records = xemu_saves(_sources(**{f"{G}/Xemu.Generator.cs": XEMU_SAVES}))
        self.assertEqual(
            [(r["emulator"], r["kind"], r["names"], r["search_dir"], r["source_ref"])
             for r in records],
            [
                ("xemu", "fixed_name", ["eeprom.bin", "xbox_hdd.qcow2"], "saves/<system>",
                 f"{G}/Xemu.Generator.cs:3-19, 27-29"),
                ("xemu, xemu-chihiro", "copies", ["chihiro_eeprom.bin"], "saves/chihiro",
                 f"{G}/Xemu.Generator.cs:3, 40-51"),
                ("xemu, xemu-chihiro", "fixed_name", ["chihiro_snapshots.qcow2"], "saves/chihiro",
                 f"{G}/Xemu.Generator.cs:3, 34-37"),
            ],
        )
        self.assertIn("eeprom_path, hdd_path", records[0]["passes_to"])
        self.assertIn('not (emulator == "xemu-chihiro" or system == "chihiro")',
                      records[0]["depends_on_option"])

    def test_cxbx_runs_from_its_folder_and_gets_the_eeprom_there(self):
        records = cxbx(_sources(**{f"{G}/Cxbx.Generator.cs": CXBX}))
        self.assertEqual(
            [(r["emulator"], r["kind"], r["names"], r["search_dir"], r["source_ref"])
             for r in records],
            [
                ("chihiro", "passes_path", [], '<AppConfig.GetFullPath("chihiro")>',
                 f"{G}/Cxbx.Generator.cs:19-21, 31"),
                ("chihiro-gun", "passes_path", [], '<AppConfig.GetFullPath("chihiro-ds")>',
                 f"{G}/Cxbx.Generator.cs:23-25, 31"),
                ("cxbx-reloaded", "passes_path", [], '<AppConfig.GetFullPath("cxbx-reloaded")>',
                 f"{G}/Cxbx.Generator.cs:27-31"),
                ("chihiro, chihiro-gun, cxbx-reloaded", "fixed_name", ["xbox-iso-vfs.exe"],
                 "<emulatorLauncher folder>", f"{G}/Cxbx.Generator.cs:3-7"),
                ("chihiro, chihiro-gun, cxbx-reloaded", "fixed_name", ["dokan2.dll"],
                 "%DokanLibrary2%", f"{G}/Cxbx.Generator.cs:3-4, 8-13"),
                ("cxbx-reloaded", "fixed_name", ["EEPROM.bin"],
                 '<AppConfig.GetFullPath("cxbx-reloaded")>', f"{G}/Cxbx.Generator.cs:34-41"),
            ],
        )
        self.assertTrue(all(r["passes_to"].startswith(CXBX_DATA_FOLDER) for r in records[:3]))
        self.assertEqual(records[3]["passes_to"], "exec")
        self.assertEqual(records[5]["depends_on_option"], 'system == "xbox"')


class HelpersAndCopies(unittest.TestCase):
    def test_blastem_one_record_per_helper_call(self):
        records = blastem(_sources(**{f"{G}/Blastem.Generator.cs": BLASTEM}))
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
        gba, segaboot = dolphin(_sources(**{f"{G}/Dolphin.Generator.cs": DOLPHIN}))
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
        records = dosbox_copies(sources)
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
        [record] = tsugaru(_sources(**{f"{G}/Tsugaru.Generator.cs": TSUGARU}))
        self.assertEqual(record["names"], ["FMT_SYS.ROM"])
        self.assertEqual(
            record["search_dir"], "bios/fmtowns, then bios/fmtownsux, then <emulator>/roms"
        )
        self.assertEqual(
            record["fails_when_missing"], "info '[TsugaruGenerator] Bios path not found', no launch"
        )

    def test_commented_code_is_not_read(self):
        [record] = eka2l1(_sources(**{f"{G}/Eka2l1.Generator.cs": EKA2L1}))
        self.assertEqual(record["passes_to"], "config.yml data-storage = bios/eka2l1/data")

    def test_bizhawk_gb_one_slot_per_system(self):
        records = bizhawk_gb(
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
        records = mame(sources)
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
        own = [r for r in mame(sources) if r["source_ref"].startswith(f"{G}/Mame64")]
        self.assertEqual(own[0]["passes_to"], "command line -rp bios;<rom directory>")
        self.assertEqual(
            own[1]["search_dir"], "bios/hbmame/samples when hbmame, else bios/mame/samples"
        )

    def test_xroar_reassigned_folder_and_config_line(self):
        # romPath is bios/dragon, rewritten to bios/coco for the coco system.
        default, coco, config = xroar(_sources(**{
            f"{G}/Xroar.Generator.cs": XROAR, retrobat_generators.FEATURES: XROAR_FEATURES,
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
            coco["source_ref"], f"{default['source_ref']}, {retrobat_generators.FEATURES}:3-6"
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
        (record,) = pico8(_sources(**{f"{G}/Pico8.Generator.cs": PICO8}))
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
        with self.assertRaises(LauncherPatternMissing) as caught:
            eka2l1(_sources(**{f"{G}/Eka2l1.Generator.cs": extra}))
        self.assertIn("bios reference at line", str(caught.exception))

    def test_semicolon_inside_a_string_does_not_end_the_value(self):
        src = Source(
            "x.cs",
            'void f(string rom)\n{\n    string p = AppConfig.GetFullPath("bios") + ";" + Path.GetDirectoryName(rom);\n}\n',
        )
        self.assertEqual(render(src, "p", 0, len(src.text))[0], "bios;<rom directory>")


if __name__ == "__main__":
    unittest.main()
