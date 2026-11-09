# RetroBIOS

Puts the BIOS files your emulators need in the right folder.

It finds your setup and its BIOS folder, downloads only the missing files and
checks each one. It works with RetroArch, Batocera, EmuDeck, RetroBat,
Recalbox, RetroDECK, RomM and more.

Run it:

```bash
uvx retrobios
```

Or `pipx run retrobios`, or `pip install retrobios` and then `retrobios`.
Python 3.8 or newer.

Add `--check` to see what is missing without changing anything, and `--help`
for every option.

Guides, the list of setups and the files each one needs:
https://abdess.github.io/retrobios/
