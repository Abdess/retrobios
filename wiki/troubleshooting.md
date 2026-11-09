---
level: start
order: 40
terms: bios not found, bios missing, firmware missing, bios error, check my bios folder, check bios folder
---

# When a game does not start

Usually a BIOS file is missing or wrong.

## 1. Check my BIOS folder { #checking-what-you-installed }

<span id="game-wont-start-black-screen"></span><span id="my-setup-says-untested"></span>

<!-- Words as emulators print them: snes9x bsx.cpp:1232 "BS: BIOS not found!"
(1bcc369e), puNES src/core/fds.c:312 "bios not found" (b1758ec2), Gearcoleco
platforms/libretro/libretro.cpp:866 "OS-7 BIOS missing" (23d0ec28), RetroArch
intl/msg_hash_us.h:32805 "One or more firmware files are missing" (5333a7c5). -->

Your emulator says **BIOS not found**, **BIOS missing** or **firmware
missing**? Run the command with `--check`. It changes nothing.

<!-- os-tabs -->
```sh
curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --check
```

Read the count line:

```
  0 in place, 108 missing, 1 wrong copy
```

- **`wrong copy`**: another region or model, or damaged.
- **A number before `missing`**: files are missing.
- **A line under a file**, like `still zipped`, says the fix.
- **`0 missing, 0 wrong copies`**: go to step 3.

## 2. Fix the files

Without `--check`, it adds missing files and replaces wrong ones.

## 3. Check the folder and the names

- **Right folder?** [Get your files](../which-pack.md) names it.
- **Exact name?** `scph5501.bin` and `SCPH-5501.BIN` differ.
- **A `bios` folder inside your BIOS folder?** The installer copies those
  files up one level.
- **BIOS setting on a subfolder, like `system/dc`?** Point it at the BIOS
  folder. Emulators add their own, like `dc/` for Flycast.
- **A ZIP in parts, like `Pack.part1of2.zip`?** Unzip all parts into one
  folder.
- **"left out" on an exFAT card?** The card refuses a `:` in a name. An
  ext4 card holds these files.

<!-- Flycast's libretro port appends "dc/" to the system directory:
shell/libretro/libretro.cpp:2252-2253, emulators/flycast.yml. -->

## An arcade game does not start

It needs its BIOS set, like `neogeo.zip`, and a game set for the same emulator
version.

- Another MAME version's game set often fails.
  Details: [the version of each emulator](technical-faq.md#which-mame-version-do-the-arcade-bios-sets-match).
- Run the command once. It installs the BIOS sets.

## The BIOS is fine, the game still fails

- **Another emulator?** Each reads the files listed on its page.
- **A BIOS setting?** Some emulators can skip the BIOS. In PCSX ReARMed, set
  **BIOS Selection** to **Auto**.
- **The screen says "Please insert PlayStation CD-ROM"?** The BIOS works.
  The game did not load, so open its `.cue` or `.m3u` file, not a `.bin`.

## If the command fails { #installation-script-fails }

- **Network error:** try again later.
- **`The clock reads ...`:** set the right date.
- **Permission denied:** do what the message says.
- **`No supported platform detected`:** name the folder. Not sure? Open
  RetroArch's **Settings > Directory > System/BIOS**.

<!-- The folders RetroArch reads by default, as install.py writes them
(_os_default_dests, _macos_retroarch_base) and the RetroArch setup page
cites them. Steam Deck: the Flatpak build. -->

<!-- os-tabs windows: --platform retroarch --dest C:\RetroArch-Win64\system macos: --platform retroarch --dest ~/Documents/RetroArch/system steamdeck: --platform retroarch --dest ~/.var/app/org.libretro.RetroArch/config/retroarch/system -->
```sh
curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --platform retroarch --dest ~/.config/retroarch/system
```

Other messages: [When something goes wrong](installer.md#when-something-goes-wrong).

<span id="hash-mismatch-untested"></span><span id="pack-is-missing-files"></span><span id="verifypy-reports-errors"></span><span id="one-console-only"></span>

## Next steps

- [Get your files](../which-pack.md)
- [Common questions](faq.md)
