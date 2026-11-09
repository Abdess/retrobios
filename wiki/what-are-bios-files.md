---
level: start
order: 10
---

# What is a BIOS?

A console has a small program inside it. It starts first, then starts the game.
This program is the **BIOS**, also called **firmware**.

<a class="rb-button rb-button-primary" href="../which-pack.md">Get the files</a>

An **emulator** is an app that acts like a console. For many consoles, it needs
a copy of the BIOS. That copy is a file: a **BIOS file**.

<!-- image: bios-chain -->

## How it works

1. Pick a game in the setup's menu.
2. The setup starts the emulator.
3. The emulator opens the BIOS file in the **BIOS folder**.
4. The game starts.

If step 3 fails, the screen says "BIOS missing" or stays black.

## Which consoles need one? { #do-i-need-one }

- **Yes:** PlayStation 1 and 2, Saturn, Neo Geo, PC Engine CD and many home
  computers.
- **Better with it:** Dreamcast. Some games need it.
- **Usually not:** NES, Super Nintendo, Mega Drive, Game Boy and Game Boy
  Advance.
- **Add-ons need their own:** the Famicom Disk System and the Mega CD.

Details: [Every console, one by one](../systems/index.md)

## The name must match

Most emulators look for one exact name, like `scph5501.bin`. A file with
another name is not found. A few, like DuckStation, read any name and check
what the file holds.

## The version must match

Two files can have the same name and different contents. One may be for Japan,
another for Europe.

Some setups check each file's **hash**, a fingerprint of its contents.
Batocera, Recalbox and EmuDeck report a version they do not expect.

The files here are the versions each setup expects.

## Can a game start without it?

Sometimes. Some emulators carry their own code in place of the BIOS. Some games
then glitch or do not start. The real file works best, so the packs include it.

## Is it legal?

Laws differ by country. [Is it legal?](legal.md)

## Next steps

- [Get the files](../which-pack.md)
- [Words used on this site](glossary.md)

