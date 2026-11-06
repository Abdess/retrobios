---
level: start
order: 50
terms: ios, iphone, ipad
---

# Common questions

## Do I need BIOS files?

- **Yes** for PlayStation 1 and 2, Saturn and Neo Geo.
- **Better with it** for Dreamcast. Some games need it.
- **Usually not** for NES or Super Nintendo.

[What is a BIOS?](what-are-bios-files.md)

## How do I know which BIOS I need?

`--dry-run` lists them and changes nothing.

<!-- os-tabs -->
```sh
curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --dry-run
```

## Do I need every file of a console?

No. `--region us` keeps only your region's BIOS.

## Does the BIOS set the game's language?

Rarely. It comes from the game. Some follow the console's setting, like Flycast's **Language**
option.

## Zip or unzip? { #zip-or-unzip }

Unzip into the folder your setup's page names. Keep
inner ZIPs zipped, like `neogeo.zip`.

## Does a BIOS work on every setup?

Usually. The command installs each setup's own, like `neogeo.zip`.

## My arcade game fails (which MAME version?) { #my-arcade-game-does-not-start }

Game sets must match the emulator's version:
[the list](technical-faq.md#which-mame-version-do-the-arcade-bios-sets-match).

## Keys, firmware or BIOS?

- **BIOS** or **firmware**: the console's own program, like `scph5501.bin`.
- Newer consoles need a system update, like `PS3UPDAT.PUP`, installed in the
  emulator.
- **Keys** unlock encrypted games, like `prod.keys` for Switch.

## Is the command safe? { #is-piping-the-installer-into-a-shell-safe }

- It stops if the installer does not match its expected fingerprint, and
  checks each file.
- It fills the BIOS folder, some save folders and a games cache.
- It never touches games or saves.
- It keeps each file it replaces in `retrobios-backup`, for `--restore`.

Read them: [install.sh](https://github.com/Abdess/retrobios/blob/main/install.sh),
[install.ps1](https://github.com/Abdess/retrobios/blob/main/install.ps1),
[install.py](https://github.com/Abdess/retrobios/blob/main/install.py).

## Windows or my antivirus blocks the command

Use your setup's ZIP. None? [Pick your consoles](../which-pack.md#only-some-consoles)
and download their files.

## Why is there no ZIP for my setup?

ZIPs are made for the setups most people download. The command installs every
setup's files and checks each one. `--dry-run` shows the list first.

## Fill an SD card from a computer?

The interface finds a muOS, Onion, spruceOS, MinUI, KNULLI, ROCKNIX or MiSTer
card. Else name your setup and its BIOS folder. For RetroArch on a Switch,
with the card in drive `E:`, run:

<!-- os-tabs windows: --platform retroarch --dest E:\retroarch\cores\system -->
```sh
curl -fsSL https://abdess.github.io/retrobios/i \
  | sh -s -- --platform retroarch --dest /path/to/sdcard/retroarch/cores/system
```

## No internet on the device?

Fill it from a computer or point `--from-pack` at your ZIP: [Without a network](installer.md#without-a-network-offline-install).

## Lost or wiped card?

`--from` copies BIOS files from an old card or backup:
[Copy from an old card](installer.md#copy-from-an-old-card).

## My setup is not in the list

- Name your emulator's BIOS folder with `--dest`.
- ES-DE or LaunchBox? It fills their emulators' folders.
- iPhone, iPad (iOS): no terminal.
  [Pick your consoles and copy them to the app](../which-pack.md#iphone-and-ipad).

## Why is a file missing from the ZIP?

Some come with the emulator.

## My game shows a black screen

Often a missing BIOS: [When a game does not start](troubleshooting.md).

## Can I copy my own console's BIOS? { #copy-your-own-bios }

Yes: [PCSX2](https://pcsx2.net/docs/setup/bios/) for PlayStation 2,
[melonDS](https://melonds.kuribo64.net/faq.php) for DS and DSi.

## Is this legal?

[It depends on your country](legal.md).

## Next steps

- [Get your files](../which-pack.md)
- [Words used on this site](glossary.md)
