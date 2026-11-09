## Notes

RetroBIOS runs the RetroBIOS installer (`install.py`, from
[github.com/Abdess/retrobios](https://github.com/Abdess/retrobios)) on the
device, in its full-screen interface. The installer finds the BIOS folder of
the system, checks every file its emulators read against its hash, and
installs the missing ones.

With a network connection the files are downloaded. Without one, copy the
BIOS pack of the system (a `_BIOS_Pack.zip` file from the releases page)
into `ports/retrobios` on the card, and RetroBIOS installs from it.

Python 3.8 or newer: the system's, or PortMaster's `python_3.11` runtime on
aarch64, downloaded on first use.

Under a desktop session with neither foot nor xterm, RetroBIOS opens
PortMaster's own screens instead of the full-screen interface.

## Controls

| Button | Action |
|--|--|
| D-Pad | Move |
| A or Start | Choose |
| B or Select | Back |
| X | Tick or untick a system |
| Y | Options |
| L1 / R1 | Page up / down |
| Start + Select | Quit |
