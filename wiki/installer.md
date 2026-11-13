---
level: setup
order: 100
terms: manifest, events, exit code, schema, packager, pin, reproducible
---

# All installer options

The one-line command finds the setup and its BIOS folder. It downloads only
the files that are missing or wrong, and checks each one against its
fingerprint before writing it. The options below are for anything else: fewer
files (one console, one region, only the cores installed), another folder, an
SD card, a check without download, or a run from a script.

Example: `--platform retroarch --system sony-playstation --region north-america`
installs only the PlayStation files, and the North American version where
there is one per region.

How the command protects the machine is under
[What the bootstrap does](#what-the-bootstrap-does) and
[Trust boundary](#trust-boundary). The BIOS folder of each setup is on
[Get the files](../which-pack.md).

## Options at a glance

Each links to its row in the [Options](#options) table.

## One line

```bash
# Linux / macOS / Steam Deck
curl -fsSL https://abdess.github.io/retrobios/i | sh
```

```powershell
# Windows
irm https://abdess.github.io/retrobios/i.ps1 | iex
```

Always type the `https://`: without it the first request goes out in clear
text, and anyone on the way could answer with another script.

With Python 3.8 or newer, the same installer is a package:

```bash
uvx retrobios
```

`pipx run retrobios` works too, or `pip install retrobios` and then
`retrobios`. Options follow the command: `uvx retrobios --check`.

`i` and `i.ps1` are `install.sh` and `install.ps1` as of the commit the site
was built from, set to download `install.py` from that same commit. The
fingerprint they check and the installer they fetch never come from two
different versions. If the site is down, the repository serves the same
bootstraps:

```bash
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1 | iex
```

From a clone, run the installer itself. Nothing beyond the standard library is
needed, and Python 3.8 is the floor both bootstraps enforce before handing over:

```bash
python install.py
```

### For packagers { #for-packagers }

A package that must not change under its users takes the installer and its
file list from one commit. `install.sh` of that commit pins the SHA-256 of its
`install.py`, and `RETROBIOS_REF` makes the installer download every file from
the same commit:

```bash
commit=<commit>
base=https://raw.githubusercontent.com/Abdess/retrobios/$commit
curl -fsSLO "$base/install.py" -O "$base/install/retroarch.json"
pin=$(curl -fsSL "$base/install.sh" | sed -n 's/^DEFAULT_INSTALL_SHA256="\(.*\)"$/\1/p')
echo "$pin  install.py" | sha256sum --check
RETROBIOS_REF=$commit python3 install.py --manifest retroarch.json
```

What `RETROBIOS_REF` does not pin is listed under
[Environment overrides](#environment-overrides).

## Passing options

The shell bootstrap forwards everything after `-s --`:

```bash
curl -fsSL https://abdess.github.io/retrobios/i \
  | sh -s -- --platform retroarch --dest /path/to/sdcard/retroarch/cores/system
```

`--dest` is the BIOS folder itself: on a card, `retroarch/cores/system` for
RetroArch on Switch, `RetroArch/system` on Android. The root of a handheld's
card works too when the installer knows that card (muOS, Onion, spruceOS,
KNULLI, ROCKNIX and the MinUI family, see
[Platform detection](#platform-detection)): the files go where its system reads.

PowerShell needs another form. `iex` takes the script text as its own argument,
so anything appended to `irm ... | iex` is read as an argument to `iex` and
rejected with `A positional parameter cannot be found`. Building a script block
from the text and calling it passes the arguments through:

```powershell
&([scriptblock]::Create((irm https://abdess.github.io/retrobios/i.ps1))) `
  --platform retroarch --dest D:\bios
```

## Without a network (offline install) { #without-a-network-offline-install }

<span id="without-a-network"></span>

A pack downloaded once installs again with no network, on this machine or on
one that has none:

```bash
python install.py --from-pack ~/Downloads/RetroArch_v1.22.2_BIOS_Pack.zip
python install.py --from-pack ~/Downloads/RetroArch_v1.22.2_BIOS_Pack.part1of3.zip
python install.py --from-pack ~/Downloads --dest /media/card/retroarch/system
```

One part is enough to name a split pack: the others are taken from the same
folder, and a part that is not there is named before anything is written.
The platform is read from the pack's name when `--platform` is not given. The
file list is the one the pack carries (`manifest.json`), with each file's
SHA-1 and size, and every file is checked against it before it takes its
place. A data tree (Dolphin's `Sys/`, PPSSPP's assets) comes from the pack
too, not from its source archive. A pack built since 2026-11 also carries
its platform's install list and the cores of each board (the
`install/targets/<platform>.json` list): `--target` applies with the pack
alone, and so does a board found on the device. An older pack carries
neither, and `--target` is then refused before anything is written. At a
terminal the run
finds a card mounted here, asks the folder when nothing is found, and names
the BIOS folder on its menu before anything is copied.

`--manifest FILE` reads the file list from a copy of `install/<platform>.json`
instead of downloading it. Alone, the files still come from the repository.
With `--from-pack`, the run reads that list and takes every file from the
pack: `--system`, `--core`, `--region` and `--no-game-data` then apply as
they do online, and a file of the list the pack does not hold fails as
`not in the pack`. The list's platform has to be the one installed for.

`--offline` forbids every request, for a device with no Wi-Fi: `--check`
still names the platform and its folder where it finds them, then stops at the
file list unless `--manifest` or `--from-pack` gives it, and counts the files
that need the internet instead of offering to fetch them. A file list or a pack
names its platform, not where that platform is: when it is found nowhere here,
every run without questions stops before reading it, `--check`, `--dry-run`
and `--no-input` included, and names the `--dest` to give. The run installs the copies found
on this machine and downloads nothing. The files left out are missing, not
failed: it ends `Finished with files missing` (code 1), or `Nothing installed`
(code 2) when nothing was installed, at a terminal, without questions and on
the full screen alike. The `summary` event counts them in `pending`, never in
`failed`. The advice that follows names a pack or a run without
`--offline`, and no `--from` folder already read. A command it suggests keeps
`--offline` when `RETROBIOS_INSTALL_OFFLINE` set it, sudo not passing that on.
The `--plain` menu then offers `f) copy from a folder or an old card`, and its
Enter checks the BIOS folder when nothing can be copied.

## The full-screen interface { #the-full-screen-interface }

Run at a terminal, the installer opens a full screen that a keyboard or a
controller drives. With one setup found here, it opens on that setup's plan,
and two presses of A or Enter install everything it reads: the plan, then the
result. **Change where** (or B) goes back to the setups, which open first when
none or several are found. What that screen would have noted (ES-DE found, the
setup's name) is under **Details**, one plan line saying so. After an install, the plan of the same folder opens
on the same choice (**Same choice as on 10 Nov: yes**, the
[install record](#the-install-record)), and **no** takes the whole list, or the
games of the card when it holds some. The plan screen says
what it installs, its size and where, before anything is written. **Details**
(`d`) adds the rest: how many files are in place, the free space, the files
left out and why.

The other choices sit one press away. **Choose systems** ticks the consoles to
keep, with the total to download under the list. It opens on its first system,
every system ticked: A or Enter ticks or unticks the one in focus, and **All** and
**None** (`a` and `n`) sit at the end of the list. B or Esc (**Done**) takes the
choice back to the plan, which counts it before **Install**: the list never installs
by itself, and Done with nothing ticked is refused. **Change** holds every
other option, grouped by what it decides. **What to install**: the preferred
regions, the cores, the emulators and the game data. **Where**: the BIOS
folder, the save directory for a list with files read there, a folder to copy
from, and **From a pack**, a pack ZIP downloaded before
([`--from-pack`](#option-from-pack)), whose own list is then read. **For which
device**: **Device** and the installed cores only. **How**: **Without the
internet** ([`--offline`](#option-offline)) and the parallel downloads.
**See**: the preview and the command line. Up and Down pass the headings. Each
row names the option it sets, and **Show the command line** gives the same
choice as one command for a script. **Preview the file list** shows what would
be downloaded and writes nothing.

**Device** lists the boards of the platform's board list by the names that
list gives them (`bcm2711`, `h700`), each with the devices it runs where the
list names them, then **Every board**. The board read on the device, or named
by the card in the reader (`boot/batocera.board`), comes first, marked
`this device` or `named by the card`, and is already chosen: it is what the
run does with nothing chosen. Another board sets
[`--target`](#option-target), **Every board** sets
[`--every-board`](#option-every-board) where a board was read. **Emulators**
ticks the emulators to install for, each one [`--emulator`](#option-emulator),
and none ticked installs for every emulator. A choice made on either screen
installs the files its option installs. **Copy the BIOS
files from an old card or a folder** opens the folder browser on the first
mounted card, and adds [`--from`](#copy-from-an-old-card): the plan then says how
many files that folder holds and how many are left to download, or that it
holds none of them. After an install
on a muOS, KNULLI or ROCKNIX card, the result offers **Put RetroBIOS on this
card (update from the console later)**, and **Change** has the same row
([On a handheld](#on-a-handheld-the-retrobios-port)). Files the BIOS
folder holds in the wrong place are counted on the plan, and **Show the files
in the wrong place** lists each one with its reason. Back on the plan
after a change of options, the folder is checked again, so its numbers are the
exact ones for the new choice. Ticked systems get their exact count before the
install starts.

| Action | Keyboard | Controller (gptokeyb, evmapy) |
|--------|----------|------------------------------|
| Move | Up and Down, `k` and `j` | D-pad Up and Down |
| Page | PgUp and PgDn | L1 and R1, D-pad Right and Left inside muxterm |
| First, last | Home and End, `g` and `G` | |
| Continue, open, choose | Enter, and Space outside a list of ticks | A, Start |
| Tick, untick | Space, Right, Left | X, D-pad Right and Left (X alone inside muxterm, Y with muxterm's own keys) |
| Back | Esc, Backspace | B, Select (B alone with muxterm's own keys, where Select shows its keyboard) |
| Change | `o`, Tab | Y |
| Details | `d`, and `o` or Tab on the result | the Details row, Y on the result |
| Filter a long list | `/` then type, Enter on a lone match chooses it | muxterm: Select shows a keyboard. Elsewhere none (the setup list puts the SD cards after RetroArch) |
| Keys of the screen | `?`, F1 (F1 alone while typing a filter, where the help lists the keys that do not type) | |
| Stop an install | Esc, `q`, Ctrl+C | B, Select+Start (B alone with muxterm's own keys) |
| Quit | `q`, Ctrl+C | B on the first screen |
| Pause, back with `fg` (Linux, macOS) | Ctrl+Z | |

The buttons of each handheld route, muxterm's and a Miyoo's among them, are
in the [key table of each route](#on-a-handheld-the-retrobios-port).

The bottom line of each screen names what A does on the row under the cursor,
in the names of what is held. On a computer it names the keys (`Enter Install`,
`Esc Back`). Started by a handheld launcher, it names the buttons of that
launcher (`A Install`, `B Back`, see `RETROBIOS_PAD` below), and `?` shows
both the buttons and the keys. Where neither is known, in SteamOS game mode or
on a console no launcher named, it gives both spellings (`A/Enter`, `B/Esc`),
and a narrow screen shortens them to `A`, `B` and `X`. In Termux on Android,
with no launcher named, a narrow screen keeps the keys (`Enter`, `Esc`) instead,
a phone having an Enter key and no A button. On the
regions screen, Left and Right move the region under the cursor up and down the
order of preference. During the download, a stop waits for the files in
progress, and a second one stops at once. Select+Start on a handheld ends the
installer with a signal (SIGTERM), which stops it the same way. Either way the
result says how many files were installed and the next step, and it stays
printed in the terminal once the screen closes. Its **Details** hold the
command that repeats the run, printed in the terminal too once they were
opened. A run that failed keeps its log and names it, and every other run
leaves nothing behind. A path on the result is never split inside a word: one
longer than the window takes a line of its own, which the terminal folds. A command breaks only between its
arguments, an option kept with its value, each line but the last ending with
the continuation its shell reads (a backslash in sh, a backtick in PowerShell), so
the lines copied run as one command. Where an option and its path do not fit
on one line, the path keeps its last folders after `.../`, the line under it
says it was shortened, and the terminal shows it whole after the screen
closes. On Android and on a handheld route the result does not mention Shift,
which neither has. Every path a run names is spelled the way its BIOS
folder was named, the backup folder and the save directory included
(`/sdcard/RetroArch` on Android, not the `/storage/emulated/0` it links to).

It opens only for an install, at a terminal of at least 40 columns and 12 rows
(a smaller window says so, with its size, before the first question:
`The window is 39x12: questions come line by line (40x12 for the full
screen).`) whose `TERM` is set, is not `dumb`
and can draw it: where the terminal's description
(terminfo) has no way to move the cursor, or moves it with other sequences
than the ANSI ones the screen writes (`TERM=vt52`), the questions come line by
line instead, by themselves. A terminal whose description is not found on the
machine gets the screen. A listing, `--check`, `--dry-run`, `--events`,
`--quiet`, `--no-input`, `--yes` and `--restore` keep the plain output. Options
given on the command line fill the screens in advance and are kept as they are.
`--system` is said on the plan (`For 1 of 12 systems (--system)`), and
**Choose systems** reads every system again with those ticked. The `--plain`
menu shows it the same way, Enter keeping what `--system` named and `c`
choosing anew.

Colour is added to words, never put in their place. RetroBIOS in the title, the row in focus
and the key the bottom line names first are magenta, files installed or in place
green, files missing or left out yellow, failures and a refused folder red, and
secondary text dim. Only the 16 basic colours are used, the ones a handheld's
console has. `NO_COLOR` set to any value but an empty one turns colour off, as do
`TERM=dumb` or no `TERM`, a terminal whose description names fewer than 8 colours
and an output that is not a terminal. The text stays the same. `TERM=dumb`, no
`TERM` outside Windows, or a terminal that moves no cursor the ANSI way
(`TERM=vt52`) also replace the live progress line with a line per file. The line-by-line
questions paint the end of a run the same way.

However the screen ends (Enter on the result, `q`, Ctrl+C, Ctrl+D, SIGTERM, a
hangup), the terminal is given back as the screen found it: the cursor shown,
the main screen back, echo and line editing on. Ctrl+Z, or SIGTSTP from
outside, gives it back the same way and stops the run, and `fg` redraws the
screen where it was. Ctrl+Z stops it only when a shell with job control
started it, the one thing that can resume it: started from a terminal app's
`-e`, a desktop entry or a launcher's `sh -c`, the key is ignored and the bar
says why.

A mouse or a touch screen works too, beside the keys and buttons, in a
terminal that reports clicks: those of Linux, macOS, WSL and Termux. A click
or a tap on a box (a system, a core, a region) ticks or unticks it, as Space
does. On any other row it moves the cursor there and adds `click or tap
again` to the row and the bottom line, and a second one on that
row does what Enter does: one row of a terminal is far smaller than a finger,
and the row a screen opens on (**Install** on Confirm) is never chosen by one
tap. The entries of the bottom line press their key, **Exit** on the result
too. One that writes files with no screen after it to look first, **Install**
on the plan and **Put it on the card**, takes two taps: the first adds
`click or tap again` to it in the accent colour (`tap again` where the line
has no room), the second presses it. A first tap on the row it acts on arms
it the same way, on the row and on the bottom line.
**Install** on Confirm, which is that look, Quit, Continue and Close take one,
so installing or quitting never takes more than two. A row of
Preferred regions stays where it is when it is ticked, its number giving the
order, which the list shows sorted the next time it opens. The line that says
which rows are in view shows the next page, and the wheel scrolls a list or a
text without moving the cursor unless it would leave the screen. Nothing
happens until the button or the finger comes up, and only where it went down,
on the screen drawn when it went down. A new screen takes no press for the
first 400 ms after it is on the screen, however long it took to lay out: a double click is two presses at most 400 ms (GNOME) to 500 ms
(Windows, macOS) apart and the new screen is drawn on the first release, so
the second tap of a double tap that changes the screen does nothing on the
new one, and a tap made later acts. The right and middle buttons
do nothing. The help and the bottom line of a list of boxes say how a tap acts.

Clicks are off in the Windows console the PowerShell command runs in, which
reports no click as a key, with `TERM` unset or set to `dumb`, `unknown`,
`linux` or a name starting with `vt`, `cons` or `ansi`, on a handheld route
(`RETROBIOS_PAD`), and with `RETROBIOS_NO_MOUSE` set. The installer gives
them back on every way out, a stop with Ctrl+Z included. On the command line
screen, any screen showing a command and the screen where a path is typed,
the terminal keeps the mouse, so text is selected, copied and pasted as usual.
The result takes taps, so a touch screen can leave it: it is printed again in
the terminal once the screen closes, with its commands when its Details were
opened, and the last line of the Details says so. Elsewhere, and on the
result, hold Shift while selecting. `--plain`
never asks for clicks. Clicks and taps were checked on 2026-10-27 in xterm,
tmux, GNU screen 4.09, Windows Terminal (WSL) and Termux
on Android 17. macOS Terminal and iTerm2 are not checked yet, nor the key
they use to select over the installer.

- `--tui` asks for the full screen, and names the reason when it cannot open
  (code 2).
- `--plain`, `RETROBIOS_PLAIN=1` or `ACCESSIBLE=1` keep the questions line by
  line. This is the mode for a screen reader, which reads a full screen badly.

Behind the screens, the installer runs itself with `--check --events`, then
`--events --yes` and the options chosen: the same
[events](#machine-readable-events) a program driving the installer reads. The
file list is downloaded once and handed to each run.

## What the installer does

1. Detects the host OS and the platforms installed on it.
2. Fetches `install/<platform>.json` from `main`, the newest file list,
   whatever commit the installer itself came from. `RETROBIOS_REF` reads it
   from a tag or a commit instead (see [For packagers](#for-packagers)).
3. Prints the file count and total size, then a `Not installable:` line
   counting the files the collection does not hold and how many of them are
   required. At a terminal, the
   [full-screen interface](#the-full-screen-interface) then offers **Install**
   for everything and **Choose systems** for fewer, and `--plain` asks the
   same as questions (see below).
4. Hashes what is already in the destination and reports how many entries are
   present, verified, or present with the wrong contents.
5. Copies from this machine what it already holds: a file misplaced in the
   BIOS folder, and what a folder named with `--from` has. See
   [Copy from an old card](#copy-from-an-old-card).
6. Downloads what is still missing or wrong, up to 8 files at a time. At a
   terminal one line shows the progress, the speed and the time left, while in a
   log each finished file gets its own line. A data tree's archive gets the
   same line at a terminal, and the bytes and time the run ends on count
   it with the files. In an interactive run, a
   download of 1 GB or more is confirmed first (`--yes` skips the question).
7. Verifies each download against the declared size, SHA-256 and SHA-1 before
   it touches the destination, then moves it into place with `os.replace` so
   a partial file is never visible. A failed attempt is retried up to three
   times, after 1, 2 then 4 seconds or the delay a `Retry-After` header asks.
   A file of 16 MB or more keeps its partial copy (`.<name>.part`) when a
   transfer stops, and the next attempt or the next run requests only the
   rest. A data tree's archive does the same beside the tree
   (`.<ref>.archive.part`), asking with `If-Range` so that a server whose
   archive changed sends it whole. A second run into the same folder finds
   that archive in use and downloads its own copy. A file already there with other contents
   is moved aside first, see [Files already in the folder](#files-you-already-had).
8. Copies into standalone emulator directories, only with `--standalone-copies`.
9. Writes the [install record](#the-install-record): each file it placed, with
   its SHA-1, and the choice it made.

The file list names the version of the platform it was built for (Batocera
43.1, RetroBat 8.3.1). Where the system writes its own version in a file, the
installer reads it, and when the two differ it says so before the install and
again with the result: "This list was built for Batocera 43.1, this machine
runs 41. Batocera's own BIOS check reads the list of the version it runs, and
may show some files as not matching it." The install goes on. The files read are
`/usr/share/batocera/batocera.version` on Batocera, `/recalbox/recalbox.version`
on Recalbox (a release, not a branch build), `system\version.info` beside the
`bios` folder of RetroBat, and `VERSION_ID` in `/etc/os-release` on Lakka and
EmuELEC. Nothing is run to find it, and an unknown version says nothing:
RetroArch writes its version in no file, KNULLI writes a codename, ROCKNIX the
date of the build, and AmberELEC's prerelease tags are not matched to the version
its image writes.

Some cores read their system data below the frontend's save directory, not
below the BIOS folder: Azahar's keys, shared font and NAND files, Citra's
`sysdata`, Dolphin's `User` tree. The file list marks them `root: save`, and
the run writes them below the save directory, which it names before checking
files (`5 files read from RetroArch's save directory go to ...`). For a
RetroArch found by its `retroarch.cfg` (with `--dest` too, when the folder is
the config's `system_directory`, as in the full screen), that is `savefile_directory` as
RetroArch expands it (`:` for its own folder, `~` for the home), `saves/`
beside the config when the value is `default`, empty, or names no folder, and
the core's own folder below it when `sort_savefiles_enable` is on, as it is by
default. Without a config, a BIOS folder at its default name (`system`) puts
the save directory beside it (`saves`, `/storage/savefiles` on Lakka).
`--save-dir PATH` names the save directory itself. When none of these
applies, or when `savefiles_in_content_dir` or
`sort_savefiles_by_content_enable` keeps saves beside each game, those files
are left out and the run says why, like the other entries the list cannot
install. The full screen says so on its plan and its result. RetroPie, ROCKNIX,
AmberELEC, EmuELEC and RomM keep the save directory in no fixed place: their
lists hold none of these files, so `--save-dir` installs none, and the run says
that instead of naming the option.

Batocera, KNULLI, Recalbox, RetroBat and RetroDECK write the save directory at
each launch, one folder per system (`by_system` in the file list). Their lists
already name each system's folder (`gamecube/User/GBA/gba_bios.bin`), and the
run writes below the `saves` folder beside the BIOS folder (`/userdata/saves`,
`/recalbox/share/saves`, `~/retrodeck/saves`), never reading a
`retroarch.cfg` that only holds the last launch. EmuDeck's RetroArch config
names `~/Emulation/saves/retroarch/saves`. RetroPie, ROCKNIX, AmberELEC and
EmuELEC keep saves beside each game, and RomM keeps them in the browser: their
lists record these files as omitted.

<!-- generated: dry-run -->

A RetroArch dry run into an empty folder, with the list of 2026-11-13, printed this:

```
Fetching file index for retroarch...
  106 files read from RetroArch's save directory go to a folder per core under /home/me/.config/retroarch/saves
  15056 files (7.5 GB)
    3367 BIOS files (4.3 GB), 5108 game data files (3.1 GB) and 6581 data files (135.6 MB).
    Game data: files a game or a game engine reads, of no use to the other cores. Data files: the files an emulator reads from a data folder of its own, such as Dolphin's Sys and PPSSPP's assets.
  Not installable: 376 files, 264 of them required. Why: not found (96), read outside the BIOS folder (280).

Checking existing files...
  0 in place, 15056 missing, 0 wrong copies
```
<!-- /generated: dry-run -->

The second line divides the first, and every later count of the run (the
menu, the plan, `--dry-run`, the result) is taken from the same list.

When the manifest leaves entries out (a file the collection cannot supply, or
one that failed its hash check), a `Not installable:` line under the index count
says how many and why. `--check` and the closing report also name the required
ones, grouped by system with the emulators that read them, and point at the
emulator pages. They do not change the exit code of `--check`, since no run of
the installer can fetch them.

## The install record { #the-install-record }

An install that places files writes what it placed in a record beside the BIOS
folder: `retrobios-backup/<folder name>.install.json`, in the same holder as
the [backups](#files-you-already-had). A folder with nothing writable beside it
(a drive's root) keeps it in `retrobios-backup` inside the folder. It is never
loose in the BIOS folder, which DuckStation, SwanStation and Rustation read
whole. On a card it travels with the card.

The record is JSON, one entry per setup:

```json
{"schema": 1, "installer": "48e57b2f26e2",
 "folder": "/home/me/.config/retroarch/system",
 "setups": {"retroarch": {
   "written": "2026-11-10T09:48:36Z",
   "list": {"version": "v1.22.2", "generated": "2026-11-10T01:52:59Z"},
   "choice": ["--system", "nintendo-gba"],
   "files": [{"dest": "gba_bios.bin", "root": "", "sha1": "4176d5fc...",
              "size": 16384, "from": "download"}]}}}
```

`files` holds each file this run and the earlier ones wrote, with the SHA-1
checked before it was moved into place: `root` is empty for the BIOS folder,
`save` for the save directory and `data` for a data tree's member, and `from`
says `download`, `copy` (this machine, `--from`) or `pack`. A file that was
already in place is not added: the record names only what the installer wrote.
`choice` is the options of the run that decided what to install, `--all-files`
for the whole list.

The next run for the same setup and folder takes that choice when nothing on
the command line chose: line mode installs the same systems
(`Installing 1 file (16.0 KB) for RetroArch, same choice as on 10 Nov.`), and
the full screen opens on it (**Same choice as on 10 Nov: yes**). Any option of
the choice (`--system`, `--core`, `--region`, `--for-games`, `--no-game-data`,
`--target`, `--every-board`, `--emulator`, `--installed-cores`, `--declared-only`)
replaces it, `--all-files` installs the whole list, and a run over several
setups or from a file list (`--manifest`) never reads it. `--check` and
`--dry-run` read it too, and say so. To forget it, delete the file.

A record is read only when it is a regular file of at most 16 MiB whose
choice holds nothing but the options above and their values. A games folder
(`--for-games FOLDER`) is kept only under the folder that holds the BIOS
folder, so a record never sends the games scan to another drive or a network
share: any other folder is recorded as `--for-games` alone, the card's own
games. A record that breaks any of this, or cannot be read, is said once and
ignored, and the next install writes a new one, keeping the other setups'
entries that read. One written by a newer installer is left as it is. A
recorded option the list can no longer apply (a region, an emulator, a board,
the installed cores, game data on a list that marks none) is left out in one
line, `Left out of the recorded choice: --target (...)`, and the run goes on:
typed on the command line, the same option is refused as before. A record kept
for a folder of another name (copied or renamed with it) is not applied. With `--events` the record
gives a `record` event, see [Machine-readable events](#machine-readable-events).

## Reading a run { #reading-a-run }

<!-- generated: run-date -->

Each line a first install prints, and what it means. The run below is a
Batocera install into an empty folder, from the list of 2026-11-13.
The figures change with each release.
<!-- /generated: run-date -->

By default a run says five things: what it installs, where, a progress line
at a terminal, the result and the next step. A failure, a wrong copy or a file
an emulator needs that is not available is said too.

<!-- generated: run-default -->

```
Installing 20907 files (11.0 GB) for Batocera.
BIOS folder: /userdata/bios

Done. 20907 files installed.
254 files an emulator needs are not available here (--verbose names them).
Next: start Batocera and play.
```
<!-- /generated: run-default -->

With `--verbose` (`-v`) it says each step, the lists and the reasons too.
The lines below are those of the same run with `--verbose`.

### Before the run

The size depends on the platform and changes with each release. The run prints
it before downloading, and asks first when the download reaches 1 GB. The
installer also measures the free space and refuses before writing anything if
there is not enough. The count holds the BIOS files, every data file still to
come, and the largest source archive, which sits in its tree while it is read.

`curl` or `wget`, and Python 3.8 or newer, are checked by the command itself:
it stops with a message naming what is absent. PowerShell's execution policy
does not block the Windows line. The policy governs script files, and the
command never writes one.

### The first lines

<!-- generated: run-first-lines -->

```
Looking for setups here...
  Found Batocera at /userdata/bios
```
<!-- /generated: run-first-lines -->

A line above them, `RetroBIOS` and a code, identifies the installer: the
code is the start of the SHA-256 the command checked before running it.
`--version` prints it too. The path is the folder it will write to.

### The file index and the download

Two phases follow. The first reads what is already in the folder. It takes a
few minutes on a memory card, because every file is hashed:

<!-- generated: run-index -->

```
Fetching file index for batocera...
  23 files read from Batocera's save directory go to a folder per system under /userdata/saves
  20907 files (11.0 GB)
    5518 BIOS files (6.2 GB), 11561 game data files (4.7 GB) and 3828 data files (88.7 MB).
    Game data: files a game or a game engine reads, of no use to the other cores. Data files: the files an emulator reads from a data folder of its own, such as Dolphin's Sys and PPSSPP's assets.
  Not installable: 807 files, 254 of them required. Why: no system runs the core (83), not found (525), read outside the BIOS folder (199).

Checking existing files...
  0 in place, 20907 missing, 0 wrong copies
```
<!-- /generated: run-index -->

On a first install nothing is in place. On a later run the line counts what
is already there, and only the rest is downloaded. A download of 1 GB or more
is confirmed first, the size and the folder in the question.

The second phase downloads what is missing. At a terminal one progress line
moves with the count and the size. With `--verbose` a pipe or a log gets one
line per file, as the log of the run below:

<!-- generated: run-download -->

```
Downloading 17079 files (10.9 GB)...
  Press Ctrl+C to stop. Running the same command again carries on from here.
  [1/17079] panafz1.bin ok
  [2/17079] panafz10.bin ok
```
<!-- /generated: run-download -->

Ctrl+C is safe at any point. Files already installed stay, and running the
command again picks up where it stopped.

### The end of the run

<!-- generated: run-end -->

```
Done. 20907 files installed.
  Installed: 5518 BIOS files, 11561 game data files and 3828 data files.
BIOS folder: /userdata/bios
807 files were not installed: the collection does not hold them, or its copy fails their check.
  Needed to start an emulator (102 files):
    acclaim-zn1 (mame2010, mame2015): acpsx.zip
      https://abdess.github.io/retrobios/emulators/mame2010/
      https://abdess.github.io/retrobios/emulators/mame2015/
    alg-laserdisc (mame2010, mame2015): alg_bios.zip
      https://abdess.github.io/retrobios/emulators/mame2010/
      https://abdess.github.io/retrobios/emulators/mame2015/
    allied-leisure-pinball (mame2015): allied.zip
      https://abdess.github.io/retrobios/emulators/mame2015/
    arcadia-systems (mame2010, mame2015): ar_bios.zip
      https://abdess.github.io/retrobios/emulators/mame2010/
      https://abdess.github.io/retrobios/emulators/mame2015/
    aristocrat-mk5 (mame2015): aristmk5.zip
      https://abdess.github.io/retrobios/emulators/mame2015/
    aristocrat-mk6 (mame2015): aristmk6.zip, mk6nsw11.zip
      https://abdess.github.io/retrobios/emulators/mame2015/
    atari-system1 (mame2010, mame2015): atarisy1.zip
      https://abdess.github.io/retrobios/emulators/mame2010/
      https://abdess.github.io/retrobios/emulators/mame2015/
    atari-zn1 (mame2010, mame2015): atpsx.zip
      https://abdess.github.io/retrobios/emulators/mame2010/
      https://abdess.github.io/retrobios/emulators/mame2015/
    ... and 58 more systems (--check --verbose lists them all)
  Each emulator's page, linked above, says what these files are.
  Not available here: DARK.GOB, DARKWAR.RTL, DARKWAR.WAD and 76 more, game data their games read. Copy them from an owned copy of the game into /userdata/bios/, /userdata/bios/Source/, /userdata/bios/base/ and 10 more folders.
  Game data: files a game or a game engine reads, of no use to the other cores.
To check this later, run the same command with --check.
```
<!-- /generated: run-end -->

When most of a download of 100 MB or more comes from one system, or from
one core of a single system, the end of a `--verbose` run says so and what
narrowing would save, once that saving is over half.

<!-- generated: bulk-hint -->

RetroArch with `--system sony-playstation`, from the list of 2026-11-13:

```
  duckstation pulls 316.5 MB of this 329.0 MB download for sony-playstation. --core pcsx1 keeps 11.0 MB of it and saves 318.0 MB (96%).
```
<!-- /generated: bulk-hint -->

`--dry-run` prints the same line under its plan.

When some files came from this machine rather than the network, the run says
where each came from: on the `Done` line when all came from one place
(`Done. 22 files copied from /home/me/old.`), on a line under it otherwise
(`2 files copied from /home/me/old, 2 downloaded.`). See
[Copy from an old card](#copy-from-an-old-card).

The word `Done` and the BIOS folder are the confirmation. Any other ending
(`Stopped`, `Finished with errors`, `Nothing was installed`) means something
was left undone, and the run says which case it was.

The lines between `BIOS folder:` and the `--check` hint name the files of the
list that the collection does not hold. `Not available here` names the game
data an engine reads from a copy of the game itself (Dark Forces, Diablo, Doom
3), and the folders to copy them into. `Needed to start an emulator` gives,
for each system, the emulators that read it and the other files they cannot
start without. The rest are optional, counted in the first line only: the
emulators reading them start without them.

### A later check

The same command with `--check` reads the folder and writes nothing:

<!-- generated: run-check -->

```
Checking existing files...
  20907 in place, 0 missing, 0 wrong copies

  Every file on the list is in place.
```
<!-- /generated: run-check -->

`Every file on the list is in place.` is said only when the data folders are complete
too. With the BIOS files in place and data files missing (PPSSPP's assets,
Dolphin's `Sys`), the line counts those instead (`169 data files to fetch`),
and `--check` exits with code 3. The files the collection does not hold are
listed after it again, as long as they are absent from the folder. A number before `wrong copies` means a file is
in place with contents the platform does not accept. Running the install again
replaces it and keeps the old one, see
[Files already in the folder](#files-you-already-had).

### Why a file is refused { #why-a-file-is-refused }

Each file `--check` flags comes with the reason it found and the place each
core reads it. A RetroArch folder holding a copy of each kind, checked
against a list of four files:

<!-- generated: check-refused -->

```
  3 files to download.
  2 of these files are in the BIOS folder in the wrong place: a run without --check copies them where the cores open them, and leaves the copies found as they are.
    wrong copy: scph5501.bin
      another region: the contents of scph5500.bin (japan)
      read by beetle_psx, pcsx_rearmed at /home/me/.config/retroarch/system/scph5501.bin
    missing: gba_bios.bin
      nested folder: it is at system/system/gba_bios.bin, a system folder inside system
      a run without --check copies it into place
      read by mgba at /home/me/.config/retroarch/system/gba_bios.bin
    missing: pcsx/extra.bin
      still zipped: it is inside PSX BIOS.zip
      a run without --check copies it into place
      read by pcsx_rearmed at /home/me/.config/retroarch/system/pcsx/extra.bin
```
<!-- /generated: check-refused -->

| Reason | What the folder holds |
|--------|-----------------------|
| `nested folder` | The file inside a folder named like the BIOS folder itself (`bios/bios/`, `system/system/`) |
| `one folder too deep`, `2 folders too deep` | The file below its place, as a ZIP extracted into a folder of its own leaves it |
| `one folder too high` | The file in the folder above the BIOS folder |
| `wrong folder` | The file under its name in another folder |
| `case of the name` | A name that differs only by capital letters, on a system where that makes two names (`the folder holds SCPH1001.BIN, the cores open scph1001.bin`) |
| `still zipped` | The file inside a ZIP in the folder, a `.7z` or `.rar` of the same name, or a ZIP saved under the file's own name |
| `wrong size` | A file of another size than any copy the list accepts |
| `another region`, `another revision`, `another file` | The contents of another file of the list: another region's BIOS, the copy another core reads, or the one the platform's own list declares |
| `a name no core opens` | The right contents under a name no core of the platform reads |
| `same size, other contents` | Another dump, or a damaged copy |
| `only a Mac's ._ file` | Only the `._name` file a Mac writes beside each file it copies to a FAT or exFAT card: Finder data, not the file |

The reasons are read from the folder and the file list, nothing else. When
three files or more sit too deep in the same folder, a line before the list
names that folder once. A file whose exact contents are somewhere in the BIOS
folder (too deep, in capitals, still in its ZIP, one folder too high) is put
in place by the next install: `--check` says so under the file, with `a run
without --check copies it into place`. Files with a reason are always listed. The plain
missing ones stop at ten unless `--verbose` is given.

A pack published in parts leaves a marker beside the files of each part
(`RetroArch_v1.22.2_BIOS_Pack.part1of3.txt`). `--check` reads them and names
a part that was not extracted, or one extracted into a folder of its own:

```
  RetroArch_v1.22.2_BIOS_Pack.zip comes in 3 parts, all needed.
    missing: part 2, RetroArch_v1.22.2_BIOS_Pack.part2of3.zip (1.9 GB)
    Download it and extract into /home/me/.config/retroarch/system, beside the other parts.
```

## Files already in the folder { #files-you-already-had }

A file in the BIOS folder whose contents differ from the expected one (another
revision, a personal dump) is replaced, but never lost. Just before the
verified copy takes its place, the old file is moved to a dated folder beside
the BIOS folder, under the same path:

```
~/.config/retroarch/system/scph5501.bin                    the verified copy
~/.config/retroarch/retrobios-backup/20261022-153000/system/scph5501.bin   yours
```

A file with the expected contents is never copied, and nothing is kept when
nothing is replaced. The end of the run says how many files were kept, their
size, the folder, and the command that puts them back:

```
Kept 1 file already there (512.0 KB), which the collection's copies replaced, in /home/me/.config/retroarch/retrobios-backup/20261022-153000
  To put them back: python3 install.py --restore /home/me/.config/retroarch/retrobios-backup/20261022-153000
```

`--restore FOLDER` copies every file of that folder back to its place and
leaves the folder as it is, to delete once the emulators start as before. A
file at that place with other contents (a newer one, one put there by hand) is
first moved into a new dated backup, as an install keeps what it replaces, and
the end of the run names that folder. The installer's own copy, as the
install record names it, is replaced without one: the collection gives it
again.
Copying the contents of the dated folder into the folder that holds
`retrobios-backup` does the same by hand. `--dry-run --restore FOLDER` lists
what would go back. `--dry-run` alone counts the files an install would keep.

The folder is beside the BIOS folder, not inside it, because some emulators
find a BIOS by its contents and not by its name. DuckStation, SwanStation and
Rustation read every file of the BIOS folder, and BizHawk walks its firmware
folder with every subfolder: an old copy anywhere inside could be picked
instead of the new one. Only when nothing can be written beside the BIOS folder
(a drive root, a parent folder that refuses writes) does `retrobios-backup` go
inside it, and the same `--restore` puts the files back. A file that cannot be
moved aside is not replaced: it stays, and the run reports it as failed with
`file in place could not be kept aside`.

A BIOS folder can sit on a network share other people write to. So a
`retrobios-backup` that is a link is never written through (the backup goes
inside the BIOS folder instead), and `--restore` only takes a folder the
installer created, marked by a `.retrobios-backup` file, without following
links found inside it.

On one drive the old file is moved, not copied, so keeping it needs no space
beyond what it already used. A link sitting at a file's name is not kept: the
file it points to is never touched. Data trees and `--standalone-copies` keep
their replaced files the same way, beside the folder they were in.

## Removing files { #removing-files }

`--remove` takes out of the BIOS folder what the installer put there, and only
that. The [install record](#the-install-record) says which files these are, so
a folder without one loses nothing:

```
python3 install.py --remove --system nintendo-gba
Remove 2 files from ~/.config/retroarch/system for RetroArch, 12.0 KB freed.
1 file stays: 1 still needed.
  shared.bin: still needed by PlayStation
Remove them for good? [y/N]
```

Without a narrowing option every file of the setup's record goes. `--system`,
`--core` or `--emulator` takes one part, and `--file PATH` one file. The
question comes once, names what goes and the space freed, and only `y` or
`yes` goes on. `--dry-run` lists the files and removes nothing, and `--yes`
answers it for a script. A run without a terminal and without `--yes` stops
with code 2 and names `--yes`.

`--remove --misplaced` takes the other files instead: the copies an install
found in the wrong place and copied where the cores read them. A copy goes
only when the installer's file holds the same bytes at its place, read again
just before, under the same name: beside it in another case (`GBA_BIOS.BIN`
next to `gba_bios.bin`), or at the top of a folder where the list places files
itself (`dc_boot.bin` at the top of RetroArch's `system` for `dc/dc_boot.bin`).
No other folder is read: games, saves and other trees are never looked at. A
renamed copy stays, since a core option, a launcher or a game list may name
it (a PlayStation 2 BIOS picked by its name), and so does a copy of game data,
which a frontend lists as a game of its own. A place any list of the folder
reads or any setup recorded stays, and so do a link and a file with a second
name. Every copy stays when the list of another setup of the folder cannot be
fetched.

The copies are named before the question. The record is not changed, and the
copies are deleted, never moved to a backup: they were never a setup's.

```
python3 install.py --remove --misplaced --dry-run
Remove 2 copies in the wrong place of /sdcard/RetroArch/system for RetroArch,
2.0 MB freed. Each is a file RetroBIOS placed where the cores read it.
  GBA_BIOS.BIN (in place: gba_bios.bin)
  dc_boot.bin (in place: dc/dc_boot.bin)
```

Removal deletes for good. `--backup` moves the files into a new dated folder of
`retrobios-backup` instead, and the end of the run prints the `--restore`
command that puts them back. On one drive a move frees no space until the
backup is deleted.

A file is removed only when all of these hold:

- the record lists it for this setup and this folder
- its bytes are still the SHA-1 the record holds
- it is a regular file, below the BIOS folder, reached through no link
- the setup's current list still serves that SHA-1 at that place, so a later
  install can put it back.

Anything else stays and is named with its reason: a file changed since, a
link, a file outside the BIOS folder (the save directory's included), a file
the list no longer serves (a key the user supplied, a dump of another
release), and a file still needed by what stays. A file two systems share
stays while one of them is still chosen, and a file another setup of the same
folder recorded stays too. Removing everything also counts the files the
record never names, added by hand or by another program, and leaves them.
A record that cannot be read is said in one line, and nothing is removed. So
is a BIOS folder that is not there (a card not mounted), with code 2. Each
file is read and hashed again just before it goes: one edited during the
question stays, as changed since the plan.
On FAT and exFAT cards, which open a name whatever its case, names are
compared without case.

The record is updated only after the yes, and only for what was done: the
files removed leave it, the systems or cores removed leave its choice, a file
that stayed (changed, failed, still needed) keeps its entry, and a setup with
no file left goes from it. `--restore` on a removal's backup gives the files back to the record with
the choice they had. A folder moved since the removal is said, the record
left as it is. On a backup of files an install replaced, the record lets
go of each file put back: it is the user's again.

`--backups` lists the backups of the BIOS folder, newest first, and
`--delete-backup FOLDER` deletes one after a question naming its date and
size. Only a dated folder holding `.retrobios-backup`, inside
`retrobios-backup`, is ever deleted, and no link inside it is followed, a
Windows junction included. On the
full screen, **More** on the plan, shown once the folder has a record or a
backup, holds **Remove files**, **Backups**, **Put back a backup** and
**Delete a backup**. Remove files lists every recorded file or one system,
then the plan of the removal (what goes, the space freed, what stays and why,
the files behind **Details**), **Keep a backup**, and a confirm before
anything is removed.

Exit codes: `0` once done, `1` when a file or the record could not be
written, `2` when nothing was done (no record, nothing to remove, no `--yes`
without a terminal, or no at the question). With `--events` the run writes
`removal_plan`, `removed`, `backup` and `restored` events, see
[Machine-readable events](#machine-readable-events).

## Making a pack { #making-a-pack }

`--pack PATH` downloads the files of the choice into a pack ZIP instead of a
BIOS folder, for another device or an install without the internet. Every
narrowing option applies as for an install (`--system`, `--core`,
`--emulator`, `--region`, `--target`, `--no-game-data`, and `--for-games
FOLDER` with `--required-only`), and `--dry-run` says what the pack would hold,
`--verbose` listing each file:

```
python3 install.py --platform retroarch --system sony-playstation --pack ~/Downloads/ --dry-run
Pack for RetroArch: 108 files (324.0 MB).
Pack: ~/Downloads/RetroArch_Custom_BIOS_Pack.zip
  --verbose lists the files.
```

Without `--dry-run` the run downloads the files, writes the pack and ends on
`Pack made:` with the count and the size of the ZIP.

A folder takes the name `<Platform>_BIOS_Pack.zip`, with `_Custom` when the
choice narrows the list. A file name must end with `_BIOS_Pack.zip`, the
name `--from-pack` and the parts read, and must not name another platform
(`Batocera_BIOS_Pack.zip` for a RetroArch pack is refused). The reader trusts
the platform the pack's own list names over its file name. On the other device,
`--from-pack` on the pack installs the same files at the same places, with no
network and no option: the pack's `manifest.json` carries the list narrowed
to the choice, the cores per board and every file's SHA-1. A file two places
share is stored once, and each data tree sits where the reader looks for it.

Every file is checked against its SHA-1 as it is written into the ZIP, and the
ZIP is read back with its CRCs before it takes its name. The pack is written
beside its final name, so a download that fails, a file that does not match or
a stop leaves no file behind. An earlier pack of the same name, whole or in
parts, is set aside while the new files take their names, and put back if one
of them cannot: the folder holds the old pack or the new one, never a mix of
their parts. The earlier files are then deleted and each one is named. A file
of that name that is not a part of this pack stays and is named too. With one
zlib the bytes depend on the choice alone: members in a fixed order, a fixed
date and mode, deflate level 9 on each member. Another deflate (zlib-ng, which
CPython 3.14 ships on Windows) gives other bytes for the same members. Making
the pack needs room for the files, the ZIP and the largest data tree archive
together on the drive it goes to.

`--split SIZE` (`1900M`, `4G`) writes parts of at most that size, each a whole
ZIP named `<Name>.part1of3.zip`, as release packs are split, with the marker
`--check` reads. On a FAT32 drive, which holds no file of 4 GB or more, a pack
that would pass that is split by itself, and the run says so in one line.
`--from-pack` takes any one of the parts and finds the others beside it.

On the full screen, **More** on the plan holds **Make a pack**. Its plan names
the files, their size, where the pack goes (Downloads, else the home folder,
**Change where** to browse) and how it is written, then **Make the pack**
gives the result. The plan's choice is the pack's, and the options of the
folder of this machine (the save directory, the installed cores, the card's
own games) are left out.

Exit codes: `0` once written, or listed with `--dry-run`, `1` when a file
could not be had or the pack could not be written, `2` when nothing was tried
(an option refused, a choice that keeps no file, a file larger than a part,
too little room). With `--events` the run writes a `pack` event, see
[Machine-readable events](#machine-readable-events).

## Copy from an old card { #copy-from-an-old-card }

The card a handheld came with, a backup of an old BIOS folder, a Downloads
folder: `--from FOLDER` copies the BIOS files it holds instead of downloading
them.

```bash
python install.py --platform muos --dest /media/me/SD1 --from /media/me/STOCK
python install.py --from ~/Downloads --from /media/me/backup
python install.py --check --from /media/me/STOCK
```

The first line names the root of the muOS card, the one holding `MUOS`: the
files go to `MUOS/bios` on it, where muOS reads them, and the run says so.

Every file is recognised by its contents, never by its name:
`PSX BIOS (USA).bin` in a subfolder lands as `scph5501.bin` when it holds those
bytes, and a file of the right name with other bytes (an empty file left by a
CFW, another revision) is not taken. The folder is searched with every
subfolder, and inside each ZIP it holds, for a file the list wants loose and
for an archive it wants whole (`neogeo.zip`). Only files whose size is one the
list expects are hashed, so a large card is read quickly. The `._` files a Mac
writes, the system folders (`System Volume Information`, `.Spotlight-V100`,
`.Trashes`, `$RECYCLE.BIN`) and a link leading out of the folder are skipped.
`--from` also takes a ZIP of an old BIOS folder.

The search stays on one drive: a drive mounted inside the folder is named and
not entered (give it its own `--from`), and so are `/proc`, `/sys`, `/dev` and
Windows junctions. The root of the system (`/`, `C:\`) is refused. A file that
cannot be read, and has the size of a file still missing, is named with the
reason (`E:\bios\a.bin could not be read: Permission denied`), as is a ZIP
member locked by a password.

The folder is only read: each file is copied, checked against the list's
hashes once written, and the original stays where it is. A file in place with
other contents is kept aside first, as a download would replace it (see
[Files already in the folder](#files-you-already-had)). What no folder holds is
downloaded as usual, or taken from the pack with `--from-pack`. Several
`--from` are read in the order given, and the end of the run says where each
file came from. A run of a list of four files, two of them in `old`:

<!-- generated: from-run -->

```
Done. 4 files installed.
  2 files copied from /home/me/old, 2 downloaded.
```
<!-- /generated: from-run -->

`--check --from FOLDER` writes nothing and says how many files the folder
would give (`E:\ holds 38 of these files: a run without --check copies
them.`), with each file's place in it. `--dry-run` counts them apart from the
download.

The BIOS folder itself is read the same way. A file the list wants that sits
misplaced in it, in a `bios/bios/` folder, a pack extracted into a folder of
its own, a name in capitals on a system where case counts, a ZIP never
extracted, or one folder above, is copied where the cores open it, with no
`--from` needed. The misplaced copy is left as it is, and the end of the run
counts them (`3 copied from the wrong place in the BIOS folder`).

## Choosing what to install

By default the installer fetches everything the platform runs. At a terminal,
the plan screen of the [full-screen interface](#the-full-screen-interface)
offers **Install**, **Choose systems** and **Change**. With `--plain`, or where
the full screen cannot open (a terminal smaller than 40x12, `TERM=dumb`), the
same choice comes as questions after detection. A RetroArch run with `--plain`
prints this for the RetroArch list, `g` then pressed (written from install.py
by `scripts/generate_installer_doc.py`):

<!-- generated: line-menu -->

```
RetroArch: 15056 files, 7.5 GB.
  3367 BIOS files (4.3 GB), 5108 game data files (3.1 GB) and 6581 data files (135.6 MB).
  Game data: files a game or a game engine reads, of no use to the other cores. Data files: the files an emulator reads from a data folder of its own, such as Dolphin's Sys and PPSSPP's assets.
  BIOS folder: /home/me/.config/retroarch/system
  Not available here, and needed to start their emulators: 3dobios.zip (Panasonic 3Do), 3dobios.zip (Panasonic 3Do), 3dobios.zip (Panasonic 3Do) and 260 more. An owned copy goes in the BIOS folder.
  Not available here: jazz2/Source/Anims.j2a (Jazz Jackrabbit 2), game data its game reads. Copy it from an owned copy of the game into /home/me/.config/retroarch/system/jazz2/Source/.
  Enter) install everything
  c) choose systems, cores and regions
  f) copy from a folder or an old card
  g) Game data: kept (5108 files, 3.1 GB): leave it out
  q) quit
> g

  Counted again for these choices. Nothing is written before Enter.

RetroArch: 9948 files, 4.4 GB.
  3367 BIOS files (4.3 GB) and 6581 data files (135.6 MB). 5108 game data files left out.
  Game data: files a game or a game engine reads, of no use to the other cores. Data files: the files an emulator reads from a data folder of its own, such as Dolphin's Sys and PPSSPP's assets.
  BIOS folder: /home/me/.config/retroarch/system
  Not available here, and needed to start their emulators: 3dobios.zip (Panasonic 3Do), 3dobios.zip (Panasonic 3Do), 3dobios.zip (Panasonic 3Do) and 260 more. An owned copy goes in the BIOS folder.
  Same choice without questions: python3 install.py --platform retroarch --dest /home/me/.config/retroarch/system --no-game-data
  Enter) install everything
  c) choose systems, cores and regions
  f) copy from a folder or an old card
  g) Game data: left out (5108 files, 3.1 GB): keep it
  q) quit
>
```
<!-- /generated: line-menu -->

A list that marks its game data counts three kinds of file apart, on the plan,
in this menu and on the result (`Installed: 3269 BIOS files, 5089 game data
files and 2636 data files.`), the parts adding up to the total: BIOS files,
game data, and the data files of an emulator's own data folder (Dolphin's
`Sys`, PPSSPP's assets). What the last two are is said once, under the counts.
`g` leaves the game data of the choice out, as `--no-game-data` does, and
counts again (`g` then keeps it). The plan screen has the same choice as a row
of its own, **Game data: kept** with its count, one press toggling it to
**Game data: left out**, and Change keeps its **Game data** row too. Its
count follows the systems chosen, as `g` counts them, and a choice that holds
no game data has no row. Given `--no-game-data`, neither the menu nor the plan
offers the game data back.

An `i` entry, with the count and size of only what the installed cores read,
appears for RetroArch, Lakka and RetroPie when cores are found installed.
It keeps what those cores read and drops the systems none of them emulates,
the rule `--installed-cores` applies.

`c` walks through three numbered lists, each answered with numbers such as
`1,4,7-9`, or Enter to keep everything on that axis. The letter names the
lists it asks (`c) choose systems` with a MiSTer pack), and a list with one
answer is not asked.

- **Systems.** The consoles and computers the platform declares, titled and
  ordered as the full screen's Choose systems lists them, the id `--system`
  takes after each title. A last entry, `Other systems and game engines`,
  holds what cores load for systems the platform does not list, such as game
  engines and extra computers. Choosing systems leaves it out unless it is
  chosen too, as `generate_pack.py --system` does.
- **Cores.** The platform's own BIOS list for the chosen systems is always
  kept. This narrows only the extra files each emulator core loads beyond it.
  Asked only when the chosen systems have such files. Every core is kept
  until numbers name some, and the head then says how many of how many
  (`1 of 2 cores`). The full screen's **Cores** opens with every core
  ticked, as Choose systems does: untick the unused ones, **All**
  and **None** tick or untick them all.
- **Regions.** Asked only when a chosen system has one BIOS per region. The
  numbers give an order of preference: `2,1` keeps the second region where a
  file for it exists, and the first one elsewhere.

Nothing is written yet: the menu comes back counted for the choice, as the
full screen's Confirm does, with the command that makes the same choice
without questions, every other option of the run in it, for instance
`python3 install.py --platform retroarch --dest /home/me/.config/retroarch/system
--system sony-playstation --region north-america`. Enter then installs, and
`c` chooses again.

An option is refused by the axis the list does not record, with what works
instead. The MinUI, NextUI and MyMinUI lists record cores and regions and no
system: `--core` and `--region` narrow them, `--system` is refused with
`Run it without --system, or narrow with --core and --region`. A pack records
the systems of its files and what its platform's list narrows by: with the
pack alone, `--core` or `--region` names that list (`--manifest FILE`, a copy
of `install/minui.json`) only when it records them, and MiSTer FPGA's pack
says its list records no cores. A list from an older release records none of
the three, and the one-line installer fetches the current one.

The same choices on the command line:

```bash
python install.py --platform retroarch --list-systems
python install.py --platform retroarch --system sony-playstation,nintendo-gba
python install.py --platform retroarch --system sony-playstation --core pcsx_rearmed
python install.py --platform recalbox --region us,eu,jp
python install.py --platform emuelec --no-game-data
```

### For the games on this card { #for-the-games-on-this-card }

When the card holds games in its rom folders, the plan opens on **For the
games on this card: yes**, and Install takes only what those games need. One
press on the row installs everything instead. Line mode asks the same: Enter
installs for the games, `e` everything, `r` only what starts. On the command
line it is `--for-games`, and `--for-games FOLDER` reads a games folder on a
computer, one subfolder per system. A run that asks nothing (`--yes`,
`--no-input`, `--events`) takes the same first choice when it finds games on
the card, and says so. `--all-files` installs the whole list instead, as does
a run narrowed by name (`--system`, `--core`, `--region`, `--emulator`).

Per system, the run keeps what the system's default core reads for the games
found. Another core can need more files: **Install everything** covers every
core. One region is kept only where the game's own
content proves it: a cartridge's crc32 found in No-Intro, a disc serial found
in Redump, or a header the core reads. A file name such as `(Europe)` proves
nothing. Where a core forces a region by an option, falls back to another
region, or uses its own disc list, every region stays. An arcade set gets the
BIOS sets of its parent chain (`neogeo.zip` for `mslug.zip`).

A game that is not recognised gets every BIOS of its system, and the run names
it. So does an arcade set the core does not know. **Only what starts**
(`--required-only`) leaves out the files the cores mark optional, and the data
folders every core reading them runs without (FinalBurn Neo's cheats and
samples).

The games are read without hashing whole discs, and a cache keeps what was
read, so a second run over the same card reads only new files. It is a
`retrobios` folder in the system's cache folder (`RETROBIOS_CACHE`, see
[Environment overrides](#environment-overrides)), written by `--dry-run` too. Offline, with
no games index on this machine, the run keeps every file and says so.

### Firmware without game data

Some platform lists name the files a game reads beside the firmware its
emulator needs (the Doom WADs in EmuELEC's list), and the cores' profiles mark
the data files of the games they run `category: game_data`: MAME's software
lists, a game engine's own data. The manifest marks each of these files
`"category": "game_data"`, and firmware carries no category.

`--no-game-data` leaves them out of the install, `--check` and `--dry-run`,
and names what it left out with its category (ten names, `--verbose` for all):

```text
  2912 game data files left out (--no-game-data), 150 of them not installable: ports/CaveStory/Doukutsu.exe, ports/dinothawr/dinothawr.game, ports/doom/doom1.wad, ...
```

It is the cut `generate_pack.py --no-game-data` makes, and a test holds the
two to the same file list. A file list that records no category is refused
rather than read as having no game data.

### Installed cores

`--installed-cores` reads the cores a RetroArch already has and installs what
they need. The cores are the `<name>_libretro.so` (`.dll`, `.dylib`,
`_libretro_android.so`) files in the `libretro_directory` of the
`retroarch.cfg` whose `system_directory` is the BIOS folder, found the same
way with `--dest` or without, `cores/` beside RetroArch when the setting is
unset, a `retroarch.cfg` next to the system directory for a portable install,
and the folders RetroPie (`/opt/retropie/libretrocores`)
and Lakka (`/usr/lib/libretro`, `/storage/cores`, `/tmp/cores`) install into. A core file
is named the buildbot's way (`mednafen_psx`), and the manifest maps each name to
the profile its files are filed under (`beetle_psx`).

What stays is what a pack built for exactly those cores carries, the rule
`--target` follows too: a platform system stays when an installed core
emulates it or reads its files, or when no core of the platform does. A
file a core loads stays when that core is installed. Where two cores read
one path and want different bytes, the copy of the first installed core in
the builder's order is the one installed. The same holds for a file of the
platform's own list: where a core's source contradicts the platform and the
frontend only checks the path, the core's copy is installed while that core
is, and otherwise the platform's answer, read from the first declaring
system that stays.

With `--dest` and no `retroarch.cfg` beside the folder, nothing names the cores
folder: `--cores-dir` names it, and the refusal prints the command with it.

Batocera, Recalbox and the other distributions ship their cores with the
system, so the option is refused there, as it is when no core is found or
when the file list predates the mapping: carrying on would install
everything while the option asked for less.

A name the platform does not have is refused before anything is downloaded,
since carrying on would install something other than what was asked. The
refusal suggests the closest names (`playstation` gives `sony-playstation`) and
the option that lists them all. Names are matched on letters and digits, so
`--platform "MiSTer FPGA"` and `--system "Sony PlayStation"` are read as the
site writes them. A system name that itself contains commas, as Recalbox's
`msx1,msx2,msxturbor` does, is read as one name. The name a platform gives a
system itself is accepted too: on Batocera `--system psx` is
`sony-playstation` and `--system gba` is `nintendo-gba`, the names its
`roms/` folders carry. They come from the platform's own file, and
`--list-systems` prints them beside each system (`nintendo-gba (gba)`).

The region rule is the one `generate_pack.py --region` applies, and a test
holds the two to the same file list. In each group of regional alternatives
the best-ranked match stays. A file declared for every region beats regional
files that match nothing asked. When nothing matches, every regional file
stays, so no system is left without its BIOS. A file the emulator does not
select by region always stays. The manifest records, for each file, the
systems that declare it, and for a regional file, its regions and the groups
it competes in. The installer reads nothing else.

The questions are asked only when standard input is a terminal. Piped,
scripted or run with `--no-input`, the installer asks nothing and installs
what the options name, everything by default.

### One level further { #one-level-further }

Four options sit below the default path, on the Change screen and as flags.
Each gives what the pack builder's option of the same name gives, and
`tests/test_install_expert.py` compares the two, (dest, sha1) for (dest,
sha1), on the real list of every registered platform.

- [`--one-per-slot`](#option-one-per-slot) keeps one BIOS per console and
  region: the one the emulators' own search order ranks first. A slot is a
  system and the regions the code selects the file for, so the Japanese and
  the American PlayStation BIOS never compete. Change offers it as
  **One BIOS per console and region** while no system, emulator or game
  choice narrows the list.
- [`--standalone`](#option-standalone), with `--emulator`, installs the
  emulator's standalone build in place of its core's layout. Change shows
  **Standalone version of it** once an emulator with such a build is ticked.
  The layouts live apart, in `install/standalone/<platform>.json`, read only
  by a run given `--standalone`: beside `--manifest FILE` when a
  `standalone/` folder holds it, else downloaded as the list is. Missing,
  unreachable or invalid, the run stops on one line with code 1.
- [`--source truth`](#option-source) keeps only what the emulator profiles
  prove a core reads, the platform's own declarations aside.
- [`--find HASH`](#option-find) installs the one BIOS with that content.

`--find` with `--json` prints, for each platform, one line:

```json
{"schema": 1, "platform": "retroarch", "hash": "<the hash, lower case>",
 "kind": "sha1", "result": "found",
 "matches": [{"dest": "scph5501.bin", "root": null, "sha1": "...",
              "sha256": "...", "md5": null, "crc32": null, "size": 524288,
              "systems": ["sony-playstation"], "cores": null}]}
```

`kind` is `sha1`, `sha256`, `md5` or `crc32`, read from the length.
`result` is `found` (one content), `ambiguous` (two contents share the
hash), `unknown`, or `unrecorded` when the list records no hash of that
kind. Every match carries every key above, `null` where the list records
none. New keys may come, existing ones keep their meaning. The published
lists carry no md5 and no crc32 yet, so those two kinds answer `unrecorded`
until they do. A `result` other than `found` ends on code 4, with or without
`--json`.

A list published before these options lacks what they read, and the run
stops on it with code 1 rather than install the whole list. None of them is
kept in the [install record](#the-install-record): a later run without the
option takes the recorded choice whole.

## Options

<!-- generated: options -->

| Option | Effect |
|--------|--------|
| <span id="option-platform"></span>`--platform NAME` | Install for this platform instead of the detected one. A system `--list-platforms` names under its own files (`muos`, `arkos`) stands for the file list it gets, and the run says which. ES-DE, LaunchBox and Android, which keep no BIOS folder, are answered with the run that fills each emulator's folder. Unknown names are refused with the closest ones |
| <span id="option-dest"></span>`--dest PATH` | Destination directory, overriding detection. Without `--platform`, the file list is the platform detected here: at a terminal the installer asks, Enter taking the one found, and otherwise it uses the one found, RetroArch's when nothing is found, and refuses when several are. The run prints whose list it is. A folder that does not exist is named with the nearest one that does, then created, except for a system that runs from its SD card, which refuses it. When more than its last level is missing (a mistyped path), a run at a terminal asks first, and the answer defaults to no |
| <span id="option-target"></span>`--target NAME` | Keep only the files the cores of that hardware target need, and the systems they emulate. An unknown target is refused rather than ignored, since carrying on would install everything. On Batocera, Recalbox, ROCKNIX, Lakka, KNULLI, AmberELEC, EmuELEC and RetroPie the board is read from the system (`batocera.arch`, `recalbox.arch`, `HW_DEVICE`, `LIBREELEC_DEVICE` or `LIBREELEC_PROJECT`, `knulli.arch`, `COREELEC_DEVICE`, the Pi model in `/proc/cpuinfo` where `/opt/retropie` exists) and applied when no `--target` is given, from a pack alone too when it carries the core list per board. On a computer, the board a Batocera or KNULLI card names on its boot partition (`boot/batocera.board`, `boot/knulli.board`) is applied the same way, in line mode and on the full screen. The card names its image (`anbernic-rg35xx-plus`, `x86-64-v3`), which the target list maps to its board (`h700`, `zen3`) |
| <span id="option-every-board"></span>`--every-board` | Install the files of every board instead of the one the system names, for a card that moves between devices |
| <span id="option-installed-cores"></span>`--installed-cores` | Keep only what the cores already installed read (RetroArch, Lakka, RetroPie). See [Installed cores](#installed-cores) |
| <span id="option-cores-dir"></span>`--cores-dir PATH` | The folder RetroArch loads its cores from, for `--installed-cores` when it is not found. Implies `--installed-cores`. A folder that does not exist or cannot be opened is refused with the reason (code 1) |
| <span id="option-save-dir"></span>`--save-dir PATH` | The frontend's save directory (RetroArch's `savefile_directory`), for the files some cores read there, when the run cannot find it. The core's own folder is still added below it when the frontend sorts saves by core |
| <span id="option-system"></span>`--system NAMES` | Install only these systems. Comma-separated or repeated. `--list-systems` prints the names, `other` included, and the title a system is printed with is taken too. A short name the platform does not use (`gba`, `psx`) is refused with the ids it may stand for, never taken in their place. So is an id the list files under another one: RetroArch keeps `neogeo.zip` under `arcade`, which `--system snk-neogeo` suggests |
| <span id="option-core"></span>`--core NAMES` | Keep the platform's own list and only the extra files these cores load. `--list-cores` prints the names |
| <span id="option-emulator"></span>`--emulator NAMES` | Install what these emulators read on the detected platform, and nothing else: their own files and the platform's files of the systems they run. Each emulator page on the site gives this command. `--list-emulators` prints the names, buildbot names such as `mednafen_psx` included |
| <span id="option-region"></span>`--region LIST` | Preferred regions, best first (`us,eu,jp`): keep one BIOS per region where a system has several. Accepts the names and aliases of `generate_pack.py --region` |
| <span id="option-for-games"></span>`--for-games FOLDER` | Install only what the games on the card need. See [For the games on this card](#for-the-games-on-this-card) |
| <span id="option-required-only"></span>`--required-only` | With `--for-games`, only the files the games cannot start without |
| <span id="option-all-files"></span>`--all-files` | The whole list, even when the card holds games. A run that asks nothing (`--yes`, `--no-input`, `--events`) otherwise installs what the card's games need, the plan's first choice. See [For the games on this card](#for-the-games-on-this-card) |
| <span id="option-no-game-data"></span>`--no-game-data` | Leave out game data (a game's own files, not firmware) and install the firmware only. What it leaves out is named. See [Firmware without game data](#firmware-without-game-data) |
| <span id="option-declared-only"></span>`--declared-only` | Keep only the files the platform's own list names (`cores: null` in the manifest), not the extra files cores load. With `--check`, the answer is about the list the platform itself checks. Refused with `--core`, the listings it does not change, `--standalone-copies` and `--tui` |
| <span id="option-one-per-slot"></span>`--one-per-slot` | Keep one BIOS per console and region, the one the emulators' own search order (`priority:`, lower first) ranks first, as `generate_pack.py --one-per-slot` does. A slot with an unranked candidate, or a candidate two cores rank apart, keeps all of them. Decided over the whole list, by the board's cores on a board: refused with `--system`, `--emulator`, `--for-games`, `--declared-only` and the listings. See [One level further](#one-level-further) |
| <span id="option-standalone"></span>`--standalone` | With `--emulator`: that emulator's standalone build, at the paths it reads, beside the platform's own BIOS of its systems, as `generate_pack.py --emulator NAME --standalone` packs it. The layouts come from `install/standalone/<platform>.json`, fetched only for this option. An emulator without a standalone build is refused, and so are `--region`, `--one-per-slot`, `--core` and `--system` beside it |
| <span id="option-source"></span>`--source SOURCE` | `truth`: only what the emulator profiles prove a core reads, as `generate_pack.py --source truth` packs it. `full`, the default, is the platform's list and what its cores read. `truth` takes no other choice, opens no full screen, and is refused on a list published before it |
| <span id="option-find"></span>`--find HASH` | Install the one BIOS of the list with this content: a sha1 or sha256 always, an md5 or crc32 where the list records it. A content at several destinations is installed at each. A hash two contents share is named and refused, as is one the list lacks, code 4. The published lists carry no md5 and no crc32 yet: those kinds answer that the list records none. Takes no other choice, and refuses `--pack`, `--add-app`, `--standalone-copies`, `--romm-firmware` and `--from` |
| <span id="option-json"></span>`--json` | With `--find`: print the matches as one JSON object per platform and install nothing. The shape is in [One level further](#one-level-further). Exit code 0 when found, 4 otherwise |
| <span id="option-list-systems"></span>`--list-systems` | Print a platform's systems with the files and size each holds, the files other systems share too counted apart. `--system`, `--core`, `--region`, `--target` and `--installed-cores` narrow it, as they narrow an install. A run prints one list: two listing options are refused |
| <span id="option-list-cores"></span>`--list-cores` | Print the cores whose extra files a platform installs. The options that narrow `--list-systems` narrow it too |
| <span id="option-list-emulators"></span>`--list-emulators` | Print every name `--emulator` accepts, each buildbot name beside the emulator it stands for. `--target` and `--installed-cores` narrow it, and `--system`, `--core`, `--region` and `--emulator` are refused |
| <span id="option-romm-firmware"></span>`--romm-firmware TEMPLATE` | RomM: where each platform's firmware goes in the library, as `filesystem.structure.firmware` in RomM's `config.yml` says (`{platform}/bios` for a library laid out as `{platform}/roms`). Read from `config.yml` beside the library when it is there. See [RomM firmware layout](#romm-firmware-layout) |
| <span id="option-no-input"></span>`--no-input` | Never ask a question, even at a terminal. A run whose output goes to a file or a pipe asks nothing either, and says so on stderr. It finds the setups and the mounted cards the screen finds: one is taken, as Enter takes it, two stop the run with an `error` event (`stage` `detect`, `reason` `conflict`) naming each with its `--platform` and `--dest`, and none stops it too, with `reason` `not_found` when a file list or a pack names the platform |
| <span id="option-check"></span>`--check` | Report and exit without writing |
| <span id="option-dry-run"></span>`--dry-run` | Show what would be downloaded, the totals first, then by system and with sizes, without writing anything. A plan taller than the screen names the ten largest systems, and `--verbose` lists every system and file |
| <span id="option-yes"></span>`--yes`, `-y` | Do not ask before a download of 1 GB or more, nor anything else. Implies `--no-input`, so a run that needs an answer (nothing found here, a file list or a pack naming its platform included, or two setups found) stops on what to name instead. `--platform` names a setup, whose usual folder is then taken |
| <span id="option-quiet"></span>`--quiet`, `-q` | Print only failures and the final summary. Implies `--no-input` |
| <span id="option-events"></span>`--events` | Write the run as JSON events on standard output, one object per line, and the usual text on standard error. Implies `--no-input`. See [Machine-readable events](#machine-readable-events) |
| <span id="option-from"></span>`--from FOLDER` | Copy the BIOS files a folder holds (an old SD card, a backup, a ZIP) instead of downloading them, each one recognised by its hash and copied, never moved. Repeat for several folders. See [Copy from an old card](#copy-from-an-old-card) |
| <span id="option-from-pack"></span>`--from-pack PATH` | Install from a pack already downloaded: its ZIP, one of its parts (the others are found in the same folder), or the folder holding them. Makes no network request and checks every file's hash. See [Without a network](#without-a-network-offline-install) |
| <span id="option-offline"></span>`--offline` | Make no network request. `--check`, `--from`, `--from-pack` and `--manifest` work without one, the file list stops the run at once when none of them gives it, and a file the run would download fails at once. `RETROBIOS_INSTALL_OFFLINE=1` does the same. `--target` and `--list-targets` read the core list per board a pack carries, or `targets/<platform>.json` beside `--manifest`, and are refused when neither gives one |
| <span id="option-manifest"></span>`--manifest FILE` | Read the file list from FILE, a copy of `install/<platform>.json`, instead of downloading it. See [Without a network](#without-a-network-offline-install) |
| <span id="option-restore"></span>`--restore FOLDER` | Put back the files a run replaced or a removal moved and kept in FOLDER, a dated folder inside `retrobios-backup`, and update the install record. Takes no other option but `--dry-run`, `--events`, `--yes`, `--no-input` and `--verbose`. See [Files already in the folder](#files-you-already-had) |
| <span id="option-remove"></span>`--remove` | Remove what the installer placed in the BIOS folder, as its [install record](#the-install-record) proves it: every file, or those of one `--system`, `--core`, `--emulator` or `--file`. Deleted for good unless `--backup` is given. See [Removing files](#removing-files) |
| <span id="option-file"></span>`--file PATH` | With `--remove`, one file of the BIOS folder, by its path there or in full. Repeat for several |
| <span id="option-misplaced"></span>`--misplaced` | With `--remove`, delete the copies left in the wrong place of the BIOS folder, each one whose bytes the installer placed where the cores read them. See [Removing files](#removing-files) |
| <span id="option-backup"></span>`--backup` | With `--remove`, move the files into a dated folder of `retrobios-backup` instead of deleting them, for `--restore` to put back |
| <span id="option-backups"></span>`--backups` | List the backups of the BIOS folder, newest first, with the date, the files and the size of each |
| <span id="option-delete-backup"></span>`--delete-backup FOLDER` | Delete one backup listed by `--backups`, after one question that names its date and size (`--yes` skips it) |
| <span id="option-pack"></span>`--pack PATH` | Download the choice into a pack ZIP at PATH instead of a BIOS folder, for another device or an install without the internet: a folder takes `<Platform>_BIOS_Pack.zip`. The narrowing options apply, `--dry-run` lists what the pack would hold, and `--from-pack` installs from it. See [Making a pack](#making-a-pack) |
| <span id="option-split"></span>`--split SIZE` | With `--pack`, write parts of at most SIZE (`1900M`, `4G`), each a whole ZIP. A pack that would pass 4 GB on a FAT32 drive is split by itself |
| <span id="option-tui"></span>`--tui` | Open the full-screen interface, or stop with the reason it cannot open here (code 2) instead of falling back to the questions. Wins over `RETROBIOS_PLAIN` and `ACCESSIBLE`. See [The full-screen interface](#the-full-screen-interface) |
| <span id="option-plain"></span>`--plain` | Ask the questions line by line instead of the full-screen interface, the mode for a screen reader. See [The full-screen interface](#the-full-screen-interface) |
| <span id="option-version"></span>`--version` | Print the installer's identity, the first 12 hex digits of the SHA-256 the bootstraps pin |
| <span id="option-list-platforms"></span>`--list-platforms` | Print the supported platforms and what was detected here. An option that narrows a list (`--platform`, `--system`, `--core`, `--region`, `--emulator`, `--target`, `--every-board`, `--installed-cores`) is refused |
| <span id="option-list-targets"></span>`--list-targets` | Print the hardware targets a platform publishes, with the core count each carries. `--system`, `--core`, `--region`, `--emulator`, `--target`, `--every-board` and `--installed-cores` are refused |
| <span id="option-jobs"></span>`--jobs N`, `-j N` | Parallel downloads, 1 to 32, default 8 |
| <span id="option-verbose"></span>`--verbose`, `-v` | Print per-attempt failures and hash mismatches |
| <span id="option-standalone-copies"></span>`--standalone-copies` | Also copy into detected standalone emulator directories |
| <span id="option-add-app"></span>`--add-app` | After the install, put the RetroBIOS app on the handheld card the BIOS folder is on (muOS, KNULLI, ROCKNIX), to check and update the BIOS files from the console later. Refused (code 2) for a folder on no such card, and with `--check`, `--dry-run`, a listing, `--from-pack` and `--offline`. See [On a handheld](#on-a-handheld-the-retrobios-port) |
| <span id="option-help"></span>`--help`, `-h` | Print the option list, a few examples in the form the run was started with, and the address of this page |

<!-- /generated: options -->

`--check` exits with code 3 when a file is missing or does not match, 0
when every one does, and 1 when the check itself failed. What it lists is under
[Why a file is refused](#why-a-file-is-refused). An install leaves a file with
the expected hash untouched and replaces any other, the old one kept beside
the BIOS folder. Files the list does not name are never moved or deleted. A file whose size
matches a listed one is read, to find a misplaced copy.

## Platform detection

Detection reads what the system itself writes, never a guess from a directory
name. A machine runs one embedded system, so every rule below is tested. A
system built on another one (KOLOS on JELOS, dArkOS on ArkOS, spruceOS on a
TrimUI) matches both and is the one meant. Two unrelated systems matching
are both named: at a terminal the run asks which one, otherwise it stops and
asks for `--dest`. The run names the system as it names itself, with the file
list it gets when that list is another system's:
`Found JELOS at /storage/roms/bios (RetroArch files)`.
`--list-platforms` lists every system below.

Where a system's RetroArch config is named, its `system_directory` is the
folder, `~` being that system's home for RetroArch. The folder in the last
column is used when no config sets one. ArkOS and dArkOS keep two configs
(64-bit and 32-bit RetroArch), and their "Switch to SD2 for Roms" script
rewrites both to `/roms2/bios`: a second card is followed through them.

| Evidence | System | File list | BIOS directory |
|----------|--------|-----------|----------------|
| `/etc/os-release` `OS_NAME=ROCKNIX` (or `ID=rocknix` on images before 2025) | ROCKNIX | ROCKNIX | `/storage/roms/bios` |
| `/etc/os-release` `OS_NAME=knulli` or `/usr/share/knulli/knulli.version` | KNULLI | KNULLI | `/userdata/bios` |
| `/etc/os-release` `ID=lakka` | Lakka | Lakka | `/storage/system` |
| `/usr/share/batocera/batocera.version` | Batocera | Batocera | `/userdata/bios` |
| `/recalbox/recalbox.version` or `/usr/bin/recalbox-settings` | Recalbox | Recalbox | `/recalbox/share/bios` |
| `/opt/muos` | muOS | RetroArch | `system_directory` of `/opt/muos/share/info/config/retroarch.cfg`, else of the default it is copied from: `/run/muos/storage/bios`, which muOS binds to `MUOS/bios` on the second card when that card holds one, else the first. Cores are read from that config's `libretro_directory` (`/opt/muos/share/core`) |
| `/mnt/mmc/MUOS/` | muOS | RetroArch | `/mnt/mmc/MUOS/bios` |
| `/etc/os-release` `NAME=AmberELEC` (CHAos writes the same) | AmberELEC | AmberELEC | `/storage/roms` (its list names `bios/` and `neogeo/` there) |
| `/usr/bin/batocera-info` naming PAN4ELEC, on AmberELEC | PAN4ELEC | AmberELEC | as AmberELEC |
| `/etc/os-release` `NAME=EmuELEC` | EmuELEC | EmuELEC | `/storage/roms` (its list names `bios/`, `ports/` and `neogeo/` there) |
| `/etc/os-release` `OS_NAME=JELOS` | JELOS | RetroArch | `/storage/.config/retroarch/retroarch.cfg`, else `/storage/roms/bios` |
| `/usr/lib/systemd/system/jelos-ready.service`, on JELOS | KOLOS | RetroArch | as JELOS |
| `/etc/os-release` `OS_NAME=UnofficialOS` | UnofficialOS | RetroArch | as JELOS |
| `/etc/os-release` `OS_NAME=ArchR` | ArchR | RetroArch | as JELOS |
| `/home/ark` and `/opt/system`, or `title=ArkOS` in `/usr/share/plymouth/themes/text.plymouth` | ArkOS | RetroArch | `/home/ark/.config/retroarch/retroarch.cfg` then `retroarch32/retroarch.cfg`, else `/roms/bios` |
| `title=dArkOS` in the same file (the dArkOSRE, dArkOSen and ArkOS4Clone images keep it) | dArkOS | RetroArch | as ArkOS |
| `title=RetroOZ` in the same file, `/opt/.retrooz` or `/etc/retrooz_version` | RetroOZ | RetroArch | `/home/odroid/.config/retroarch/retroarch.cfg` then `retroarch32/retroarch.cfg`, else `/roms/bios` |
| `/mnt/SDCARD/spruce` | spruceOS | RetroArch | `/mnt/SDCARD/Saves/ra-configs/retroarch-*.cfg`, else `/mnt/SDCARD/BIOS` |
| `/mnt/SDCARD/System/usr/trimui/crossmix-version.txt` | CrossMix-OS | RetroArch | `/mnt/SDCARD/RetroArch/retroarch.cfg`, else `/mnt/SDCARD/BIOS` |
| `/mnt/SDCARD/.tmp_update/onionVersion/version.txt` | Onion | RetroArch | `/mnt/SDCARD/RetroArch/.retroarch/retroarch.cfg`, else `/mnt/SDCARD/BIOS` |
| `/mnt/SDCARD/.allium` | Allium | RetroArch | as Onion |
| `/mnt/SDCARD/Koriki/version.txt` | Koriki | RetroArch | as Onion |
| `/etc/main` and `/usr/bin/miyooctl` | MiyooCFW | RetroArch | `/mnt/.retroarch/retroarch.cfg`, else `/mnt/.retroarch/system` |
| `/mnt/plumos-user` | plumOS | RetroArch | `/mnt/plumos-user/bios`, which its launcher appends to every RetroArch run |
| `/etc/os-release` `ID=plumos` without the folder above | plumOS | none | its builds choose a folder per launch: named, not installed to |
| `/usr/trimui` | TrimUI | none | no published source names the stock firmware's folder: named, not installed to |
| `/mnt/SDCARD/.system/res` or `/mnt/sdcard/.system/res` | MinUI, NextUI or MyMinUI, as the first line of the card's `.system/version.txt` names it | MinUI, NextUI or MyMinUI | the card root, below which the list writes `Bios/<tag>/`. Without `version.txt` the three cannot be told apart: named, not installed to, and the message gives `--platform` and `--dest` to use |
| `/mnt/vendor/bin/dmenu.bin` | Anbernic stock firmware | RetroArch | `/mnt/mmc/bios` |

AmberELEC, EmuELEC and KNULLI install the BIOS list they publish themselves. TheRA is not detected: no
image or source of its Odroid Go builds is published, so neither its marker
files nor its folder could be read.

AmberELEC, EmuELEC, Batocera, Recalbox, ROCKNIX, Lakka and KNULLI also name the
board they were built for (AmberELEC and EmuELEC as `COREELEC_DEVICE` in
`/etc/os-release`), RetroPie reads the Pi model as its setup script does (`x86_64` on a PC),
and that board narrows the install unless `--target` or `--every-board` says
otherwise (see the options above). A board with no core list of its own is
named and gets the files of every board. KNULLI writes its board to
`/usr/share/knulli/knulli.arch` under the name of the chip its board file
selects: `rk3568` there is the `rk3566` list.

Some platforms keep their BIOS in a fixed directory, and that directory is the
evidence. They are looked for after the configurations below, for a platform
not already found that way.

| Evidence | Platform | BIOS directory |
|----------|----------|----------------|
| `/media/fat/MiSTer` | MiSTer FPGA | `/media/fat/games` |
| `C:\RetroBat\bios` or `%USERPROFILE%\RetroBat\bios` | RetroBat | the same |
| `~/Emulation/bios` (Linux and macOS) | EmuDeck | the same |
| `~/.var/app/net.retrodeck.retrodeck` | RetroDECK | `~/retrodeck` |
| `/romm/library/bios` | RomM | the same |
| `/romm/config/config.yml` | RomM | `/romm/library/bios`, laid out by its firmware template |
| `~/RetroPie/BIOS` | RetroPie | the same |
| `%USERPROFILE%\BizHawk\Firmware` | BizHawk | the same |
| `EmuHawk.exe` or `EmuHawkMono.sh` in a `BizHawk*` folder of the home folder or one level down (`~/Games/BizHawk-2.11.1`), the newest | BizHawk | `Firmware` beside it |

A `--dest` given without `--platform` is first read as an SD card: the MinUI
family writes the release name as the first line of `.system/version.txt` at
the card root (`MinUI-`, `NextUI-`, `MyMinUI-`), and that line names the file
list.

A card that holds a system's own files is read the same way, without
`--platform` or with the one that names its list, by the rules the table above
gives for the device, below the card's root instead of its mount point:

<!-- generated: card-markers -->

| On the card | System | Files go to |
|-------------|--------|-------------|
| `system/configs/emulationstation/about.info` holding the line `KNULLI` | KNULLI | `bios`, KNULLI's list |
| `system/batocera.conf` holding the line `system.hostname=KNULLI` | KNULLI | `bios`, KNULLI's list |
| `.config/system/configs/system.cfg` holding the line `root.password=rocknix` | ROCKNIX | `roms/bios`, ROCKNIX's list |
| `.config/retroarch/retroarch.cfg` holding the line `system_directory = "/tmp/system"` | Lakka | `system`, Lakka's list |
| `MiSTer`, `menu.rbf` | MiSTer FPGA | `games`, MiSTer FPGA's list |
| `MUOS/` | muOS | `MUOS/bios`, RetroArch's list |
| `spruce/` | spruceOS | `BIOS`, RetroArch's list |
| `System/usr/trimui/crossmix-version.txt` | CrossMix-OS | `BIOS`, RetroArch's list |
| `.tmp_update/onionVersion/version.txt` | Onion | `BIOS`, RetroArch's list |
| `.allium/` | Allium | `BIOS`, RetroArch's list |
| `Koriki/version.txt` | Koriki | `BIOS`, RetroArch's list |
| `bgmusic/` beside `bios/`, on a drive that is not a fixed disk | ArkOS | `bios`, RetroArch's list |
| `launchimages/` beside `bios/`, on a drive that is not a fixed disk | ArkOS | `bios`, RetroArch's list |
| `gamedata/`, `homebrew/` beside `bios/`, on a drive that is not a fixed disk | AmberELEC | `bios`, AmberELEC's list |
| `bezels/default.cfg` beside `bios/`, on a drive that is not a fixed disk | EmuELEC | `bios`, EmuELEC's list |
| `system/batocera.conf` holding `system.hostname=BATOCERA` or no hostname line, and no KNULLI file above | Batocera SHARE drive | `bios`, Batocera's list |
| `system/recalbox.conf` | Recalbox SHARE drive | `bios`, Recalbox's list |
| `system/batocera.conf` with any other hostname, and no KNULLI file above, or the files of two SHARE drives | named by neither: the run says which systems it could be | the folder of the system named with `--platform` |

<!-- /generated: card-markers -->

Each file is one the system writes. KNULLI is read by `about.info` first,
which no menu writes: its HOSTNAME row rewrites `system.hostname`, and a KNULLI
card renamed there was read as a Batocera SHARE drive. ROCKNIX's line changes
with its root password, and a card whose password was changed is named by
nothing, never by another system. A drive whose files fit two systems is named
by neither: the first screen and `--plain` say which systems it could be and
the two commands that name it, and a `--dest` named with one of them takes it
as that system's, with a note. The full screen lists it under each system it
could be ("KNULLI2: if it is a KNULLI card"), and with a file list for one of
them it is that system's card, offered first, never "no card is mounted".
`--plain` numbers it the same way ("Type 1 if it is the KNULLI card").

The full screen lists such a card on its first screen ("muOS SD card (E:\)"),
and a SHARE drive the same way ("Batocera SHARE drive (SHARE)"): its root, typed
or given with `--dest`, stands for its `bios` folder. Two cards of one system
say what their BIOS folder holds ("Onion SD card (OLDONION, 6 BIOS files)"),
the one holding fewer first.
Named by its system (`--platform muos`, `--platform knulli`), a `--dest` that
is another system's card is refused, and so is another system's SHARE drive
for Batocera and Recalbox. One that holds none of the system's
files is refused where the card always carries them. For KNULLI, ROCKNIX and
the systems no file on the card names, it gets the system's folder below it
(`bios`, `roms/bios`), with a note. Named with a file list instead
(`--platform batocera --dest` an Onion card), another system's card takes the
files as named, and a note names the system and its folder.

Desktop installs are read from their own configuration, and several can be
found on one machine.

Under WSL both sides are searched. The Windows one is reached through its
`/mnt/<drive>` mount: a `C:\` path from a rule or a config becomes
`/mnt/c/...`, and the Windows variables the rules use (`USERPROFILE`,
`APPDATA`, `LOCALAPPDATA`, `ProgramFiles`) are read through `cmd.exe` when
WSL does not pass them. When `cmd.exe` or `reg.exe` gives no answer within
10 seconds or cannot run (interop turned off), the run says the Windows side
was not searched, never that nothing is installed there. A forced `--platform retrobat` falls back to
`/mnt/c/RetroBat/bios`. With nothing found, the folder question offers both
usual folders of a setup that has one on each side: RetroArch's in this Linux
(`~/.config/retroarch/system`, under Enter) and the Windows one
(`C:\RetroArch-Win64\system`), each named by its side.

| Evidence | Platform | BIOS directory |
|----------|----------|----------------|
| `HKCU\SOFTWARE\RetroBat` `LatestKnownInstallPath`, which `RetroBat.exe` writes on every start (read through `reg.exe` under WSL) | RetroBat | that folder + `\bios`, before the fixed folders above |
| `~/.config/EmuDeck/settings.sh` (Linux and macOS) | EmuDeck | `emulationPath` + `/bios` |
| `%APPDATA%\EmuDeck\settings.ps1`, else `%USERPROFILE%\EmuDeck\settings.ps1` | EmuDeck | `$emulationPath` + `\bios`, `C:\Emulation\bios` when it names none (a network install: the `$VolName` share + `\Emulation\bios`) |
| `~/.var/app/net.retrodeck.retrodeck/config/retrodeck/retrodeck.json` | RetroDECK | `paths.rd_home_path`, falling back to the pre-migration `retrodeck.cfg` and its `rdhome`. A folder RetroDECK moved on its own is followed: files for `bios/` go to `paths.bios_path`, files for `roms/` to `paths.roms_path`, and the run names the new place |
| `~/.var/app/org.libretro.RetroArch/config/retroarch/retroarch.cfg` | RetroArch (Flatpak) | `system_directory` |
| `~/snap/retroarch/current/.config/retroarch/retroarch.cfg` | RetroArch (Snap) | `system_directory` |
| `~/.config/retroarch/retroarch.cfg` | RetroArch (native) | `system_directory` |
| `<name>.AppImage.home/.config/retroarch/retroarch.cfg` (or `<name>.AppImage.config/retroarch/`) beside an AppImage in `~`, or one or two folders below it | RetroArch (AppImage from the buildbot, whose portable folder becomes its home) | `system_directory`. Without a config, `system` in that `retroarch` folder |
| `~/Library/Application Support/RetroArch/config/retroarch.cfg` | RetroArch (macOS) | `system_directory`. At default, `~/Documents/RetroArch/system` (portable, Steam build included: `Application Support/RetroArch/system`) |
| `retroarch.cfg` beside `retroarch.exe` (`C:\RetroArch-Win64`, `C:\RetroArch`, `Program Files\RetroArch`) | RetroArch (Windows) | `system_directory`. At default or without a config, `system` beside the exe |
| `%APPDATA%\RetroArch\retroarch.cfg` | RetroArch (Windows) | `system_directory`, read when the exe folder has no config |
| `steamapps\common\RetroArch\retroarch.cfg` in every Steam library: the client's folder (`SteamPath` under `HKCU\Software\Valve\Steam`, else `%ProgramFiles(x86)%\Steam`) and the libraries its `libraryfolders.vdf` lists | RetroArch (Steam) | `system_directory` |
| `%LOCALAPPDATA%\Packages\1e4cf179-f3c2-404f-b9f3-cb2070a5aad8_*\LocalState` | RetroArch (UWP/MSIX package) | `system_directory` of the `retroarch.cfg` there, `~` meaning that folder. By default `LocalState\system` |
| LaunchBox `Data\Emulators.xml` | RetroArch (portable) | the system directory that entry points at |
| LaunchBox `Data\Emulators.xml` naming `EmuHawk.exe` | BizHawk (portable) | `Firmware` beside `EmuHawk.exe` |
| `$BIZHAWK_DATA_HOME`, or `$XDG_DATA_HOME/emuhawk-monort-<version>` (Nix package) | BizHawk (Unix) | `Firmware` under it |

`system_directory` is read the way RetroArch expands it: a leading `~` is the
home directory, a leading `:` is the application directory, and `default` means
`system` next to the application. The LaunchBox installation is located through
its Start menu shortcut, the only record of where its installer was pointed.

Android has one frontend with a shared BIOS directory, and the app-private
directories of the standalone emulators are unreachable from outside the app
under scoped storage.

| Evidence | Platform | BIOS directory |
|----------|----------|----------------|
| `<shared storage>/Android/data/<package>/files/retroarch.cfg` | RetroArch (Android) | `system_directory` |
| `/data/data/<package>/files/retroarch.cfg` | RetroArch (Android) | `system_directory` |
| `<shared storage>/Android/data/<package>/files/RetroArch/` | RetroArch (Android, Google Play build) | `<shared storage>/Android/data/<package>/files/RetroArch/system` |
| `<shared storage>/RetroArch/` | RetroArch (Android, retroarch.com build) | `<shared storage>/RetroArch/system` |

The packages are `com.retroarch.aarch64`, `com.retroarch` and
`com.retroarch.ra32`, the flavours the frontend publishes. The first two are
published both on Google Play and on retroarch.com, and the two builds keep
their folders in different places (see [Android](#android)). Both config
paths are unreadable from Termux on Android 11 and later, so the directories
themselves are what answers on current devices.

ES-DE and LaunchBox are reported when present and nothing is written to them:
they reference emulators rather than owning a BIOS directory. ES-DE is looked
up at `$ESDE_APPDATA_DIR` or `~/ES-DE`, the two locations its own
`getAppDataDirectory` resolves.

When no platform is found but standalone emulators are (an ES-DE setup with
DuckStation and PCSX2, for one), the installer fills their own BIOS folders:
the folders of the [standalone copies](#standalone-copies) list that exist on
the machine, with the files that list names, taken from the EmuDeck file list
and then RetroArch's. At a terminal it asks first. `--check` and `--dry-run`
work as for a platform. With `--system`, `--core`, `--emulator`, `--region`,
`--target`, `--installed-cores` or `--declared-only` the run asks for a
platform as before, since those name a platform's lists.

When a platform named with `--platform` is not found on the machine, the
destination falls back to the directory its detection looks for:
`/userdata/bios` for Batocera and KNULLI, `/recalbox/share/bios` for Recalbox,
`/storage/system` for Lakka, `/storage/roms/bios` for ROCKNIX,
`/storage/roms` for AmberELEC and EmuELEC, `~/retrodeck` for RetroDECK, `~/Emulation/bios`
for EmuDeck (`C:\Emulation\bios` on Windows), `/media/fat/games` for MiSTer,
`~/RetroPie/BIOS` for RetroPie, `/romm/library/bios` for RomM,
`C:\RetroBat\bios` for RetroBat, and RetroArch's own default system
directory for RetroArch. BizHawk has no such folder: it reads `Firmware`
beside its executable wherever the archive was extracted, so a forced
`--platform bizhawk` that finds no install stops and asks for `--dest`.

The systems that run from an SD card keep their files there: MinUI, NextUI,
MyMinUI, KNULLI, ROCKNIX, Lakka (its STORAGE partition, which a Linux computer reads, once Lakka has started once), MiSTer FPGA, AmberELEC and EmuELEC (the card's games part, which
they mount as `/storage/roms`), and each system of the
[Linux handhelds](../platforms/linux-handhelds.md) that gets RetroArch's list
(Onion, muOS, spruceOS, ArkOS, UnofficialOS and the others). Run on the
device, the installer finds its folder. From a computer, each has a row of its
own in the setup list (**Onion, SD card**), without the filter, and in the
`--plain` menu, beside the devices that run it (Miyoo Mini, Miyoo Mini Plus).
The filter takes a device name, and so does the `--plain` menu, which lists
the setups it matches by number. With nothing found here, the SD card rows
come right after RetroArch: Onion comes into view after five presses of L1 and R1 at
40x12, where it was row 30 of 34. That row, `--platform onion` and the menu
all ask for the card: one card of that system mounted when the run starts is
taken, otherwise
the screen opens **Where is the SD card?**, which lists only that system's
cards and offers **Look again**, and `--plain` asks `Card root`, listing the
same cards by number and naming the one picked and its folder. The RetroArch
row is this computer's RetroArch.

The card's top folder is read by one function wherever it is chosen, listed,
browsed, typed, numbered or named with `--dest`, and gives the same folder and
the same note on the screen and in `--plain`. A folder that does not exist,
or that is another system's card, is refused for every system, and so is a
folder inside another system's card (ROCKNIX's `roms/bios` named for KNULLI).
A card whose own files name it is that card whatever its name: an Onion card
mounted as `BIOS` gets `BIOS/BIOS`. One without the system's own files is
refused for the MinUI family, Onion, muOS, spruceOS, CrossMix-OS, Allium and
Koriki. KNULLI, ROCKNIX, AmberELEC and EmuELEC fill their card when they first
start (AmberELEC's `gamedata` and `homebrew`, EmuELEC's `bezels/default.cfg`),
and no file on the card names ArkOS, dArkOS, JELOS, KOLOS, UnofficialOS, ArchR,
RetroOZ, plumOS, MiyooCFW or the Anbernic firmware: such a folder
gets the system's folder below it, and a note says so, kept on **Create the
folder?** and the plan. No to creating its folders asks for the card again.
Under WSL a drive letter (`D:`, `D:\`) is that Windows drive, typed or given
to `--dest`, `--from`, `--from-pack`, `--save-dir` and `--cores-dir`, and the
screens write the folder `D:\BIOS`. Without questions (`--no-input`) the
run stops with a `--dest` example. A `--dest` that is a folder inside a MinUI
card (its `Bios/`) is refused with the root to name instead. AmberELEC
and EmuELEC write `bios/` below their games part: their `bios` folder named
with `--dest` stands for the games part, as RetroDECK's for its folder. A refused
`--dest` ends with code 1 and an `error` event (`stage` `detect`). On Android a forced `--platform retroarch` falls back to
`<shared storage>/RetroArch/system` instead, a home directory there belonging
to Termux rather than to the frontend. Pass `--dest` to say where instead of
relying on that. When detection met a folder this user cannot open, under the
home folder or above the default, no default is taken: the frontend's own
configuration there may name another folder, so the run asks for `--dest`.

With nothing detected, the setup screen lists the platforms to choose from,
and `--plain` gives the same list numbered, in the same order, with `--dest`
too. Both find the SD cards mounted here, the screen under **Found on this
machine**. With a setup found, the setup screen lists it with **Another setup
or folder**, and `--plain` asks the same: Enter takes the first, `o` opens the
numbered list and then the folder, `q` quits. A platform named and found
nowhere gets its folder asked, its usual one under Enter, the mounted drives
numbered. A list or a pack read by card setups too (RetroArch's, read by Onion,
muOS, ArkOS and the others) opens the setup list instead, filtered to the
setups that read it, RetroArch first: Enter on it asks RetroArch's folder. At
that question a drive is numbered by the folder its system reads (`ONION:
BIOS`), a drive nothing names by its `bios` folder (`EASYROMS: bios`), never
by its root, which no setup reads. A handheld's card whose own files sit on a
part a computer does not open is told by the folders its system writes beside
`bios` on the games part: `bgmusic` or `launchimages` on ArkOS's `EASYROMS`
(every ArkOS card has one of them from its first images, `themes` only since
an update a full card skipped), `gamedata` and `homebrew` on AmberELEC's
`GAMES`, `bezels/default.cfg` on EmuELEC's `EEROMS`. A disk Windows or Linux
calls fixed is never one. AmberELEC's and EmuELEC's card is found as theirs
(`AmberELEC SD card (GAMES)` under **Found on this machine**), in both modes
and on their own setup's card question, and gets their list. An ArkOS card
reads RetroArch's list: with nothing found here the first screen and line mode
say `A card is in the reader (EASYROMS): choose its system` (two cards: `choose
their systems`), and its `bios` folder comes first at the folder question,
under Enter, before this computer's usual folder. A drive with a `bios` folder
and none of those folders, a data drive or a stick, is numbered with a note
(`DATA has a bios folder but no folder a handheld system writes. Pick it below
if the BIOS files go there.`) and never taken under Enter. Another system's card or SHARE drive, and a
drive two systems fit, are left out, and a line names them: each is reached
through its own setup. A folder typed is read from the current
one when it is not a full path, and named in full after. `q` quits there too
(a folder named `q` is typed `./q`), and Enter with no default says what to
type. On a computer Batocera and Recalbox have no default: the drives are
numbered by their `bios` folder (`SHARE: bios`), as the screen lists them,
and a drive whose files name another system is left out. Without questions
the run stops there with an `error` event and a `--dest` example. A device
several systems run lists them all, and a model finds the systems that list
its family (`RG353V` finds ROCKNIX, which lists `RG353`). Both need a
terminal: piped into a script
with no platform to install for, it prints the manual invocation, in the form
the run was started with (the one-line command for a one-liner user), and
exits 1.

## Standalone copies

Some files are read by a standalone emulator from its own data directory
rather than from the platform's BIOS tree. `--standalone-copies` copies them
there after the install, and only then: without the flag a run writes only to the BIOS
folder, the save folders its list names, `retrobios-backup` and the
installer's cache folder.

The manifest carries the list on the six platforms that declare one
(Batocera, EmuDeck, Recalbox, RetroArch, RetroBat, RetroDECK). It has two
parts. The registry names fifteen entries, Flatpak folders included:

| Files | Copied to |
|-------|-----------|
| `prod.keys` | yuzu, eden, citron, suyu and Ryujinx key directories |
| `title.keys` | yuzu, eden, citron and suyu key directories |
| `Citra/sysdata/aes_keys.txt`, `Citra/sysdata/boot9.bin` | Azahar `sysdata` |
| `scph*.bin` | DuckStation `bios` |
| `ps2-*.bin` | PCSX2 `bios`, native and Flatpak |
| `GC/USA/IPL.bin`, `GC/EUR/IPL.bin`, `GC/JAP/IPL.bin`, `dsp_rom.bin`, `dsp_coef.bin` | Dolphin `GC`, per region for the IPL |
| `PPSSPP/ppge_atlas.zim` | PPSSPP `PSP/SYSTEM` |
| `dc/dc_boot.bin`, `dc/dc_nvmem.bin` | Flycast's data folder, native and Flatpak |

The rest comes from the emulator profiles. A profile that gives the folder its
standalone build reads, per system, has each file with a
`standalone_path` copied to that path under the folder: Cemu's `keys.txt`,
`otp.bin` and `seeprom.bin` to `~/.local/share/Cemu`, xemu's EEPROM, melonDS's
DSi SD image. A copy carries `as` when the emulator reads the file under
another name (`eeprom.bin`, `dsisd.bin`). A folder no run can name (beside an
executable, picked in the app) is not a target, nor is a place the registry
already gives for the same file. A file the emulator finds by its contents in a
folder the user sets (Amiberry's ROMs) is left out.

An entry names one file or a glob, and one entry carries no file at all: when
an RPCS3 configuration directory is present it prints that `PS3UPDAT.PUP` is
installed through RPCS3's own File menu, since that firmware is an installer to
run rather than a file to copy.

Targets are per OS, WSL falling back to the Linux ones. A directory that does
not exist is skipped rather than created, so nothing is copied for an emulator
that is not installed. A destination that is already a symbolic link is
replaced by the file rather than written through: a write through the link
would land outside the folder the user opted into. The summary counts each
copy as copied, skipped (folder absent) or failed, and names every failure.
A run without the flag lists the emulator folders of this list that exist on
the machine, and says nothing when there are none.

## RomM firmware layout

RomM 5.4 places each platform's firmware where `filesystem.structure.firmware`
in its `config.yml` says, relative to the library: `bios/{platform}` by
default, the layout of the pack. A library laid out as `{platform}/roms` makes
RomM stop until `config.yml` declares its templates, and RomM suggests
`firmware: "{platform}/bios"` for it.

The installer reads that value from `config.yml` in the `config` folder beside
the library, `/romm/config/config.yml` inside the container, and places each
file accordingly: with `{platform}/bios`, `psx/scph5501.bin` goes to
`library/psx/bios/scph5501.bin`. `--dest` still names the library's `bios`
folder, whose parent is the library. Run from the host of a container, where
`config.yml` sits elsewhere, `--romm-firmware` gives the same value. A
library laid out as `{platform}/roms` with no template found is refused
rather than filled in the wrong place, and the message gives the command.

RomM's player reads the firmware its library scan has recorded, and RomM
watches the library folder only when `ENABLE_RESCAN_ON_FILESYSTEM_CHANGE` is
set. An install that put files in place ends by saying so: start a scan in
RomM so that the player finds them.

## Android

Android reports itself as Linux, so the runtime is named from its own
variables instead: `ANDROID_ROOT` and `ANDROID_DATA`, which Termux inherits,
with `/system/build.prop` covering a shell started without them.

Detection then looks for each installed RetroArch package. Its
`retroarch.cfg` is read from the app external files directory and then from
the internal one, the order the frontend itself follows (RetroArch v1.22.2,
`UserPreferences.java:36-89`), and a `system_directory` it names is used as
written. Left at `default`, it resolves against `<storage>/RetroArch`
(`platform_unix.c:1670-1697`), where `<storage>` depends on the build
(`MainMenuActivity.java:182-183`):

| Build | Packages | `<storage>` |
|-------|----------|-------------|
| Google Play | `com.retroarch`, `com.retroarch.aarch64` | `<shared storage>/Android/data/<package>/files` |
| retroarch.com | `com.retroarch`, `com.retroarch.aarch64`, `com.retroarch.ra32` | `<shared storage>` |

The two builds share their package ids (`pkg/android/phoenix/build.gradle:46-95`),
so the build is told by what it wrote. The version code the launcher records
in `retroarch.cfg` (`bundle_assets_extract_version_current`) is below
1609632000 for a Google Play build and the build time in seconds for the
others (`build.gradle:42, 168-175`). Without a readable config, a
`RetroArch` folder under `Android/data/<package>/files` is the Google Play
build, and `<shared storage>/RetroArch` is the retroarch.com build, the
Google Play build never asking for shared storage
(`MainMenuActivity.java:199-202`). When nothing tells them apart, the run
names both folders and asks for `--dest`. The Google Play folder sits in
`Android/data`, which Termux cannot write on Android 11 and later: the run
then names it, as it does for Flycast below.

Two Android emulators keep their BIOS elsewhere. DraStic reads
`/data/data/com.dsemu.drastic/files/DraStic/system`, private to the app, and
Flycast reads `Android/data/com.flycast.emulator/files/data` in shared
storage, which Android 11 and later keep from other apps. No app can write
the first without root, and Termux cannot write the second on Android 11 and
later. When either emulator is installed and its folder is out of reach, the
run names it and the files that are not copied. Where the Flycast folder is
writable (Android 10 and earlier), it is a standalone copy target.

Under scoped storage the two RetroArch config paths are unreadable from Termux on
Android 11 and later, so on current devices the folders are what answers.
Running `termux-setup-storage` once is what makes the shared one reachable.
The one-line command runs it when `~/storage` is missing, then waits up to a
minute for the permission Android asks for, as it offers `pkg install python`
when Python is missing:

```bash
curl -fsSL https://abdess.github.io/retrobios/i | sh
```

`EXTERNAL_STORAGE` overrides the storage root for a device that mounts it
elsewhere. A custom BIOS directory is still named directly:

```bash
python install.py --platform retroarch --dest /storage/emulated/0/RetroArch/system
```

An install on Android leaves an empty `.nomedia` in the BIOS folder. Android's
media scanner hides a folder holding one, and every folder below it
(MediaProvider, `FileUtils.java` `isDirectoryHidden`), so the samples,
overlays and videos of the BIOS folder stay out of the gallery and music
apps. RetroArch writes none. A run that finds one already there leaves it,
and `--check` and `--dry-run` write nothing. The RetroArch pack, unzipped on
Android as on other systems, carries the same empty `.nomedia` beside
`README.txt`. A pack built for a target other than Android does not.

## On a handheld { #on-a-handheld-the-retrobios-port }

RetroBIOS also runs on the handheld, with the controller. Download the file
for the system, copy it to the SD card, then start RetroBIOS from the menu.

<!-- generated: handheld-downloads -->

| System | Download | Steps |
|--------|----------|-------|
| muOS | [RetroBIOS.muxapp](../get/handheld/RetroBIOS.muxapp) | [muOS steps](../get/linux-handhelds.md#muos) |
| ArkOS | [RetroBIOS-tools.zip](../get/handheld/RetroBIOS-tools.zip), [RetroBIOS.zip](../get/handheld/RetroBIOS.zip) (PortMaster) | [ArkOS steps](../get/linux-handhelds.md#arkos) |
| dArkOS | [RetroBIOS-tools.zip](../get/handheld/RetroBIOS-tools.zip), [RetroBIOS.zip](../get/handheld/RetroBIOS.zip) (PortMaster) | [dArkOS steps](../get/linux-handhelds.md#darkos) |
| ROCKNIX | [RetroBIOS-tools.zip](../get/handheld/RetroBIOS-tools.zip), [RetroBIOS.zip](../get/handheld/RetroBIOS.zip) (PortMaster) | [ROCKNIX steps](../get/rocknix.md#on-the-handheld) |
| AmberELEC | [RetroBIOS-tools.zip](../get/handheld/RetroBIOS-tools.zip), [RetroBIOS.zip](../get/handheld/RetroBIOS.zip) (PortMaster) | [AmberELEC steps](../get/amberelec.md#on-the-handheld) |
| JELOS | [RetroBIOS-tools.zip](../get/handheld/RetroBIOS-tools.zip), [RetroBIOS.zip](../get/handheld/RetroBIOS.zip) (PortMaster) | [JELOS steps](../get/linux-handhelds.md#jelos) |
| KNULLI | [RetroBIOS-batocera.zip](../get/handheld/RetroBIOS-batocera.zip), [RetroBIOS.zip](../get/handheld/RetroBIOS.zip) (PortMaster) | [KNULLI steps](../get/knulli.md#on-the-handheld) |
| Batocera | [RetroBIOS-batocera.zip](../get/handheld/RetroBIOS-batocera.zip) | [Batocera steps](../get/batocera.md#on-the-handheld) |
<!-- /generated: handheld-downloads -->

### Where each file goes { #where-each-file-goes }

It runs in the [full-screen interface](#the-full-screen-interface).

<!-- generated: handheld -->

| System | File | Copy it to | Start it from |
|--------|------|------------|---------------|
| [muOS](../get/linux-handhelds.md) | `RetroBIOS.muxapp` | `ARCHIVE` at the root of the card, then install it from the Archive Manager | Applications |
| Any other system with [PortMaster](https://portmaster.games/): [ArkOS](../get/linux-handhelds.md), [dArkOS](../get/linux-handhelds.md), [ROCKNIX](../get/rocknix.md), [AmberELEC](../get/amberelec.md), [JELOS](../get/linux-handhelds.md), [KNULLI](../get/knulli.md) | `RetroBIOS.zip` | PortMaster's `autoinstall` folder: `/roms/ports/PortMaster/autoinstall/` on ROCKNIX and AmberELEC, `/roms/tools/PortMaster/autoinstall/` on ArkOS, `/userdata/system/.local/share/PortMaster/autoinstall/` on KNULLI | Ports, after opening PortMaster once |
| [Batocera](../get/batocera.md), [KNULLI](../get/knulli.md) | `RetroBIOS-batocera.zip`, extracted | `roms/ports` on the SHARE partition | Ports, after updating the game list |
| [ArkOS](../get/linux-handhelds.md), [dArkOS](../get/linux-handhelds.md) | `RetroBIOS-tools.zip`, extracted | `tools` on the EASYROMS partition | Options, then Tools |
| [ROCKNIX](../get/rocknix.md), [JELOS](../get/linux-handhelds.md) | `RetroBIOS-tools.zip`, extracted | `/storage/.config/modules`, over the network share or SSH | Tools |
| [AmberELEC](../get/amberelec.md) | `RetroBIOS-tools.zip`, extracted | `/storage/.config/distribution/modules` | Tools |
<!-- /generated: handheld -->

`RetroBIOS.zip` also installs on muOS, from `MUOS/PortMaster/autoinstall/`
on the first card (`/mnt/mmc` on the device). It then shows the interface in
muxterm, as the muOS app does.

### Buttons on a handheld { #buttons-on-a-handheld }

| Button | Action |
|--------|--------|
| D-pad | Move |
| A, Start | Choose, continue |
| B, Select | Back, and quit on the first screen |
| X | Tick or untick a system |
| Y | Change |
| L1, R1 | Page up, page down (not in muxterm, which keeps them for its own scrollback) |
| Hold Select, then Start | Quit at once (PortMaster port, muOS, Tools) |

Start pressed first also chooses the line in focus: hold Select first. A
running install is then stopped the way B stops it, and the last screen says
what it wrote. On muOS without PortMaster, muxterm reads the pad itself: Y
ticks a system, Select shows its keyboard, and Menu quits. L1 and R1 do not
page there: muxterm keeps PgUp and PgDn for its own scrollback, so Left and
Right on the D-pad page a list instead, as they do with gptokeyb in muxterm.

Each launcher also sets `RETROBIOS_IDLE_EXIT` to 300: with no button pressed
for 5 minutes since it opened, and no check or install running, the interface
closes by itself. A pad the system has no mapping for sends nothing, and would
otherwise leave the console stuck on the interface with no way out. It closes
with `RetroBIOS: No button pressed, closing.` and exit status 2, as a quit
before the install. Closed on an error or a result screen, it prints that
screen's words after the line and exits with its code (1 for `No internet:
offline mode`), so the launcher can tell an error from a close with nothing to
report. The time counts from the end of the last check, so a launcher that
names the platform, whose interface moves on to the plan by itself, closes the
same way. Any launcher can set it to another number of seconds.

Each launcher tells the interface which buttons reach it, in
`RETROBIOS_PAD`, so the hints can name them:

<!-- generated: pad-routes -->

| Value | Input | Set by |
|-------|-------|--------|
| `gptokeyb` | gptokeyb or gptokeyb2 with `retrobios.gptk`, the table above | the PortMaster port and the Tools entry |
| `gptokeyb_muxterm` | the same, inside muxterm, which keeps L1 and R1 for its scrollback: Left and Right page | the muOS app with PortMaster |
| `muxterm` | muxterm's own keys: D-pad (Left and Right page), Start as Enter, B as Backspace, Y as Space | the muOS app without PortMaster |
| `evmapy` | `RetroBIOS.sh.keys`, the same buttons as the table | the Batocera and Knulli port |
| `miyoo` | buttons that are already keys: A as Space, Start as Enter, L1 and R1 as E and T, L2 as Tab, R2 as Backspace | no launcher yet |

<!-- /generated: pad-routes -->

A launcher with no mapper at all (a keyboard) leaves it unset.

The help screen (`?`) names the keys of the route in use. A computer gets
the keyboard column, and SteamOS game mode or a console no launcher named
gets the column that names both:

<!-- generated: route-keys -->

| Action | Computer (`keys`) | Unknown (`both`) | `gptokeyb` | `gptokeyb_muxterm` | `muxterm` | `evmapy` | `miyoo` |
|--------|-------------------|------------------|------------|--------------------|-----------|----------|---------|
| Move | Up/Down, k/j | Up/Down, k/j | D-pad, Up/Down | D-pad, Up/Down | D-pad, Up/Down | D-pad, Up/Down | D-pad, Up/Down |
| Page | PgUp/PgDn | PgUp/PgDn, L1/R1 | L1/R1, PgUp/PgDn | D-pad Left/Right | D-pad Left/Right | L1/R1, PgUp/PgDn | L1/R1, PgUp/PgDn |
| Continue, open, choose | Enter | A/Enter, Start | A, Start, Enter | A, Start, Enter | Start, Enter | A, Start, Enter | A, Start, Enter |
| Tick, untick | Space, Right/Left | X, Space, Right/Left | X, Space, Right/Left | X, Space | Y, Space | X, Space, Right/Left | A, Space, Right/Left |
| Change | o, Tab | Y, o, Tab | Y, Tab, o | Y, Tab, o | o, Tab | Y, Tab, o | L2, Tab, o |
| Back, and quit on the first screen | Esc, Backspace | B/Esc, Backspace | B, Select, Esc | B, Select, Esc | B, Esc, Backspace | B, Select, Esc | R2, Esc, Backspace |
| Stop an install | Esc, Ctrl-C | B/Esc, Ctrl-C | B, Esc, Ctrl-C | B, Esc, Ctrl-C | B, Esc, Ctrl-C | B, Esc, Ctrl-C | R2, Esc, Ctrl-C |
| Quit at once | none | Select+Start | Select, then Start | Select, then Start | none | none | none |
| Use the folder typed | Enter | Enter | A, Enter | A, Enter | Start, Enter | A, Enter | Start, Enter |
| Clear a filter, leave the folder typed | Esc | Esc | B, Esc | B, Esc | Esc | B, Esc | Esc |

<!-- /generated: route-keys -->

On a Miyoo, B, X, Y and Select are Left Ctrl, Shift, Alt and Right Ctrl:
pressed alone, a modifier sends nothing to a terminal, so the interface goes
back with R2 instead, and the bottom line says so.

**Without Wi-Fi.** On a computer, download the BIOS pack that serves the
system (every part, for a pack in parts): RetroArch's on muOS, ArkOS,
dArkOS and JELOS, Batocera's on Batocera. Copy it next to RetroBIOS: into
`ports/retrobios` for the PortMaster port and on Batocera, to the root of
either card on muOS, into the `retrobios` folder of the Tools entry. With no
connection, RetroBIOS installs from it, as
[`--from-pack`](#without-a-network-offline-install) does. With no pack there,
it names the pack and the folder. The releases carry no pack for ROCKNIX,
Knulli or AmberELEC: there RetroBIOS needs Wi-Fi, or the computer route.

On a two-card device, RetroBIOS without Wi-Fi first asks to **copy the BIOS
files from the other card**: muOS's `MUOS/bios` on the card the system does
not read, or the other of `/roms/bios` and `/roms2/bios` on ArkOS and dArkOS.
A says yes, as [`--from`](#copy-from-an-old-card) does. The list of files
still comes from the pack, so the pack is needed too.

**What it needs.** Python 3.8 or newer: the system's, else PortMaster's
`python_3.11` runtime on aarch64, which the PortMaster port downloads on
first use and the Tools entry then reuses. That runtime uses the system's
OpenSSL 1.1, so on an image with OpenSSL 3 only it may not download (not
tried on a device). The BIOS folder must be one the installer detects, see
[Platform detection](#platform-detection). On a read-only or full card,
RetroBIOS keeps its log in `retrobios` under `XDG_RUNTIME_DIR` or `/tmp`, and the interface names the
folder it cannot write.

**Where no terminal shows.** The PortMaster port draws on the console, or in
foot or xterm under a desktop session. Where neither can, it opens
PortMaster's own screens instead: the same check, update and choice of
systems, one list at a time. On Batocera and Knulli the visible terminal is
not verified on a device yet: RetroBIOS tries xterm or foot, then console 4,
and stops when console 4 does not come to the front. `retrobios/log.txt`
names each route it tried, and `log.prev.txt` keeps the run before.

**From a computer.** Onion, MinUI, NextUI, Allium, GarlicOS and the Switch
have no Python 3 to run the installer. Put the card in a computer and run
the [one-line command](#one-line) there: it finds a mounted Onion,
spruceOS, MinUI, muOS, Knulli, ROCKNIX or MiSTer card by itself (MiSTer's
files go to `games/` below the card's root, which MiSTer reads as
`/media/fat/games`). For a card it does
not recognise, add `--platform <platform> --dest <BIOS folder on the card>`.
This works for every system above too.

**The app, from a computer.** After an install on a muOS, KNULLI or ROCKNIX
card, the installer can put RetroBIOS on that card too, so the console checks
and updates its BIOS files later. The result screen offers **Put RetroBIOS on
this card (update from the console later)**, **Change** has the same row, the
line questions ask once (`[y/N]`), and a script adds
[`--add-app`](#option-add-app). Nothing is written without that choice.

| System | Written on the card | Then, on the console |
|--------|---------------------|----------------------|
| muOS | `ARCHIVE/RetroBIOS.muxapp`, which the Archive Manager lists | install it from the Archive Manager, start it from Applications |
| KNULLI | `roms/ports/RetroBIOS.sh`, `RetroBIOS.sh.keys` and the `retrobios` folder, on the SHARE partition | update the game list, start it from Ports |
| ROCKNIX | `.config/modules/RetroBIOS.sh`, executable, and the `retrobios` folder, on the STORAGE partition | start it from Tools |

The files are the launchers above, from the same ref as the file lists:
`install/launchers/index.json` lists each one with its size and SHA-256, and
every file is fetched and checked before the first is written. The muOS
archive holds the members of `RetroBIOS.muxapp`, stored rather than
compressed, and is checked against the hash the list records for it. A file
already in place with that content is left alone, so a second run writes
nothing. A different one is moved to `retrobios-backup` first, as a BIOS file
is. Onion, MinUI, NextUI, MyMinUI and Allium have no Python to run it, and the
result says so in one line. spruceOS and CrossMix have no launcher yet. With
`--from-pack` or `--offline` the app is not offered, the launchers coming from
the network.

## Where the files come from

Each manifest entry names either `repo_path`, served from the repository at the
pinned revision, or `release_asset`, served from the `large-files` release for
the files above the size GitHub carries in a tree. Everything else in the entry
(`dest`, `size`, `sha1`, `sha256`, `cores`) describes what must land where and
what it must hash to.

Entries the collection cannot satisfy are not silently dropped: they travel in
`omitted_files` with a reason, and the run prints the count before downloading
anything. `not_found` means no file in the collection matches the entry, which
is what the gap analysis tracks (Reference: [What the packs do not hold](../gaps.md)).

Some cores read a whole tree of data rather than a few files: Dolphin's `Sys/`,
PPSSPP's assets, blueMSX's machines. These are not files of the collection, so
`data_directories` names each tree's source archive (the libretro buildbot, an
upstream release) and the sha1 and size of every file the pack carries. The
installer downloads the archive once, maps its members the way the pack was
built (`strip_components` for a ZIP, `source_path` for a tarball, `exclude`),
and writes a file only when its hash matches the list. A file the source has
changed since is left out and counted, and the pack still holds it. `--check`
counts the data files missing, `--dry-run` names each tree it would fetch, and
the size announced for a tree is its archive's (`archive_size`, recorded when
`refresh_data_dirs.py` last downloaded it): one missing file fetches the whole
archive, and a tarball can be a thousand times its tree. Narrowing with
`--system`, `--core` or `--target` keeps only the trees of the systems that
stay.

## What the bootstrap does

Both wrappers do the same four things before any BIOS file is considered.

They fetch `install.py` over HTTPS only, from `RETROBIOS_INSTALL_URL` or the
pinned raw URL. A URL with any other scheme is refused outright.

They cap the download at 2 MB and require the SHA-256 to equal the 64 hex
characters embedded in the wrapper, `RETROBIOS_INSTALL_SHA256` when set. A
mismatch aborts with "the downloaded installer does not match its expected
fingerprint" and nothing runs. The copies the site serves name the commit's
`install.py`, which never changes, and both downloaders stop on a cut transfer
before the hash is read: there a mismatch is a file changed on its way, by a
proxy or an antivirus, and that is what they say. The raw form reads `main`,
whose two files can come from caches a few minutes apart right after an
update: it says to try again, and that waiting five minutes settles it. The
site build refuses to publish a copy whose pin is not the SHA-256 of the
`install.py` it names, and Deploy Site runs the bootstrap tests before it
deploys, so a failed check keeps the last good pair served. Any change to
`install.py` therefore means recomputing that pin in both wrappers.

They locate a Python 3.8 or newer interpreter (`python3`, `python`, then each
`python3.X` on PATH, newest first, on POSIX, `py -3` then `python3` then `python` on Windows). Without one,
`install.sh` names the command that installs it on the system it runs on
(`pkg install python` in Termux, which it offers to run since Termux installs
without root, `xcode-select --install` on macOS, apt, dnf, pacman, zypper or apk
from `/etc/os-release`), and `install.ps1` at a console offers to run `winget
install Python.Python.3.12`, then reads the new PATH and carries on.
`install.sh` needs `curl` or `wget` (GNU or BusyBox) and `sha256sum` or `shasum`.
Windows PowerShell 5.1 still negotiates SSL 3.0 and TLS 1.0 by default and
GitHub refuses both, so `install.ps1` raises the floor to TLS 1.2 before
downloading, and `install.sh` pins the same floor with `curl --tlsv1.2`.

They delete the temporary installer on the way out, including on interrupt.
Run from a clone, `install.sh` and `install.ps1` reuse the `install.py` sitting
next to them and skip the download entirely. Piped from stdin, `install.sh`
never treats the working directory as a trusted location for it.

Piped from `curl`, the shell's standard input is the script itself, so
`install.sh` hands the installer the terminal (`/dev/tty`) when there is one.
That keeps the installer's questions working when the script is piped from
`curl`.

## Trust boundary

The manifest is fetched over the network and treated as untrusted input. Every
path it carries goes through one validator that refuses an absolute path, a
drive letter, a backslash, a null byte or any other control character, a
doubled separator, a trailing slash and any `..` component, so a destination
cannot climb out of the BIOS directory and no file is named with a terminal
command. Manifest, target list and payloads each have a size cap, the file
list a count cap, and the sum of the declared sizes is checked against the
total the manifest claims.

Every other string from outside is shown, never obeyed: the names a list or
a pack records, a card's label and a folder a configuration names reach the
terminal, line by line or on the screen, and the `--events` stream with a `?`
for each control character. A folder a configuration names with one is not
taken: the run says so and asks for `--dest`, its default being no answer
for a setup that reads another folder.

Symbolic links met under the BIOS root are followed on purpose: they are the
user's own layout, and EmuDeck links `bios/shadps4/sys_modules` into shadPS4's
data directory where the emulator actually reads it. The boundary is lexical,
not a resolved-path comparison, which is what keeps that case working.
Standalone copies are stricter, since they write outside the tree the user
selected: a symlink already sitting at the destination is replaced by the
file rather than followed.

## Changing the installer

`install.py` runs on the user's machine, often an older handheld, so it stays
on Python 3.8 and the standard library alone. The RetroPie 4.8 images
(`retropie-buster-4.8-*.img.gz`) are Debian Buster, whose `python3` is 3.7.3:
there the bootstrap stops before running anything, and the way to install is
the command run on a computer with the Pi's network folder as `--dest`
([first install](first-install.md#error-python-38-or-newer-is-required)).
Tests refuse any 3.9 syntax or API, and one runs the installer end to end under
a real 3.8 interpreter, which CI installs beside 3.12 so the check cannot skip.
The build scripts need 3.9 and are not bound by this.

Every change to `install.py` recomputes the SHA-256 pinned in `install.sh` and
`install.ps1` in the same commit: `python scripts/pin_installer.py` writes both
(`--check` writes nothing and exits 1 on a stale pin). It also runs
`scripts/generate_launcher_index.py`: `install/launchers/index.json` records the
hash of `install.py` that `--add-app` checks before it writes a launcher on a
card. The tests compare the pins and the list with the file and name the command
that fixes each.

The tables of options, events, exit codes, keys and card markers, the line
menu and the run samples on this page sit between `generated` markers and are
written from `install.py` by `scripts/generate_installer_doc.py`: the options
from its parser, the events from `EVENT_KEYS`, the codes from its `sys.exit`
calls, the keys from `TUI_ROUTES`, the card markers from its card rules. The
run samples (a dry run, a first install, a check, the reasons a file is
refused, a copy from an old card) are printed by `install.py` itself, in a
sandbox under `tmp/` served on the loopback from the committed
`install/*.json`. A new list therefore rewrites this page, and `--check`
fails until the script has run. Pipeline step 7 runs it after the README.
The prose cells stay as written. A row the code gains stops the script until
its text is added inside the markers, and `--check`, which a test runs, fails
on a table behind the code. `--page FILE` renders another copy of the page,
which the tests use.

The [handheld](#on-a-handheld-the-retrobios-port) archives each carry
`install.py`, the one the one-line command of the same commit downloads:
`scripts/build_port.py` refuses any other (it compares it with the SHA-256
`install.sh` pins). The file lists come from `main`. The launchers in
`ports/` start it with `--tui`, and read it through
[Machine-readable events](#machine-readable-events) for the rest.

Narrowing by system, core, region or target replays the pack builder's rules
from fields the manifest carries, and a parity test compares an installer
selection with the pack built the same way. Given a manifest without those
fields, the installer refuses to narrow rather than install everything.

## Exit status

<!-- generated: exit-codes -->

| Code | Meaning |
|------|---------|
| `0` | everything asked for is installed or already in place, or removed, put back or deleted |
| `1` | a failure: the one-liner could not download or verify `install.py`, or found no Python 3.8 with its ssl, unicodedata and zlib modules (nothing was run), an unusable base URL, `--installed-cores` with no core found, a manifest that fails validation, a fetch that never succeeded, no platform to install for in a non-interactive run, some files failed or were left out by `--offline` while others installed, a `--from-pack` pack that cannot be read, lacks a part or is for another platform, a `--from` folder that does not exist or cannot be read, a BIOS folder that is a file or lies under one, a `--dest` that is not the card of the system named (another system's card, a folder inside one, a drive with none of its files where its card always has them, or a folder that does not exist), `--restore` could not put a file back, `--remove` or `--delete-backup` could not delete a file or update the install record, `--pack` could not get a file or write the pack (nothing is left behind), or `--add-app` could not put every file of the app on the card |
| `2` | nothing was installed: every file the run tried failed (a BIOS folder that cannot be written, for one), or `--offline` left every file out, the drive has too little free space for the download (checked before any folder is created), or the question about a folder that does not exist, named with `--dest` or typed at the folder question, was answered no. Also an option the installer refused before any download: an unknown option, `--jobs` outside 1 to 32, `--target` with `--every-board`, `--target` with `--from-pack` or `--offline` (or `RETROBIOS_INSTALL_OFFLINE` set) when no core list per board is at hand (the pack carries none and none is beside `--manifest` as `targets/<platform>.json`), or for a platform that publishes none, which is said to have no hardware targets, `--list-targets` with `--offline` and neither, `--add-app` with `--check`, `--dry-run`, a listing, `--from-pack` or `--offline`. The message then starts with `install.py: error:`. Also an unknown platform, target, system, core or emulator, said in an `Error:` or `Unknown platform` line and an `error` event whose `stage` is `option`. Also `--add-app` for a folder on no card that takes the app, said in an `Error:` line and an `app` event before anything is written. With `--restore` or `--delete-backup`, a folder that is not a dated folder inside `retrobios-backup`. With `--pack`, no pack tried: a choice that keeps no file, a file larger than a part of `--split`, too little room, or `--pack` with an option that reads the BIOS folder of this machine. With `--remove`, nothing removed: no install record of the setup, nothing it can remove, no `--yes` without a terminal, or no at its question, and the same for `--delete-backup`. Also a quit chosen before the install, as `gh` ends a cancelled prompt: `q` at a question, `q` or **Quit** on the full screen, which then keeps `RetroBIOS: quit. Nothing was installed.`, and the full screen closed with no button pressed (`RETROBIOS_IDLE_EXIT`). No code but `0` closes a Windows Terminal tab started on the installer itself, so such a tab stays open on a quit |
| `3` | `--check` ran and found files to fetch or wrong copies, nothing having failed. A failure takes `1` as before: a manifest refused, a `--from` folder that does not exist. Until November 2026 this case also ended on `1`, so a script that reads any code but `0` as "not ready" needs no change |
| `4` | `--find` read the hash and the list holds no one file for it: none has it (`unknown`), two contents share it (`ambiguous`), or the list records no hash of that kind (`unrecorded`). With `--json` the `result` key says which, and nothing is installed |
| `130` | stopped with Ctrl+C, or with Ctrl+C or Ctrl+D at a question, the terminal keeping `RetroBIOS: stopped. Nothing was installed.` before an install. Run the same command again to carry on |
| `141` | the output was piped to a reader that closed early (`--list-platforms \| head`) |

<!-- /generated: exit-codes -->

The full screen ended by SIGTERM (Select+Start on a handheld) before any
install exits `143`. During an install it stops the install first, and exits
`130`. Its window or terminal closed (SIGHUP) exits `129`, during an install
too: the install is stopped as Ctrl+C stops it, and the last lines go
nowhere, no one being left to read them.

`install.ps1` passes the installer's code on unchanged: run as a file it exits
with it, run through `irm | iex` it sets `$LASTEXITCODE` (an `exit` there
would close the PowerShell window). It declares no parameter of its own, so
every argument reaches `install.py` as typed, short forms such as `-v`
included. Its body runs in a script block of its own,
so `irm | iex` leaves neither its variables nor its `$ErrorActionPreference`
in the session.

Failures that are per-file, such as a download exhausting its three attempts,
are counted and reported at the end.

`--check` tells missing files (`3`) from a failure (`1`) by its code. The
`check` event of [Machine-readable events](#machine-readable-events) counts what
is left in `missing` and `wrong_hash`.

## Machine-readable events

With `--events`, standard output carries only JSON objects, one per line, and
the text a person reads goes to standard error. A program driving the installer
(the [handheld port](#on-a-handheld-the-retrobios-port) is one) reads the
objects and never parses the text. Every object has an `event` key naming its
kind, and each kind has exactly the keys below, in this order. The schema is
`EVENT_KEYS` in `install.py`, and this table is written from it. The same
keys, with their types, are in `schemas/install-events.schema.json`, written
from `EVENT_KEYS` by `scripts/generate_event_schema.py` and published with the
other schemas under `api/v1/schemas/`.

<!-- generated: events -->

| Kind | Keys | When |
|------|------|------|
| `start` | `schema`, `installer`, `mode` | First line. `schema` is 1, `installer` the identity `--version` prints, `mode` one of `install`, `check`, `dry-run`, `list` (also `--backups`), `remove` (`--remove`, `--delete-backup`), `restore`, `pack` (`--pack`, with `--dry-run` too) |
| `unsearched` | `folder`, `reason`, `message` | Before `detect`, once for each folder the search for setups could not look in, this user being refused it or a read failing there (a failing card, a link that loops), or under WSL the Windows side when Windows did not answer (`folder` is then the drive mount, `/mnt`). What it would hold counts as absent, and the other places are still searched: `detect` then lists what they hold, and an empty `platforms` after an `unsearched` line means nothing was found where the installer could look. `reason` says why in words (`Permission denied`), `message` says it in a sentence |
| `detect` | `os`, `os_name`, `platforms` | Once the platforms are known. `os_name` comes from `/etc/os-release`. `platforms` lists `{platform, name, bios_dir}`, and is empty when nothing supported was found |
| `error` | `stage`, `reason`, `platform`, `message` | The file list could not be read (`stage` is `manifest`): `reason` is `network`, `not_found` or `invalid`, `clock` when the server's certificate was refused and the system clock reads a date before the installer was written, `no_ca` when the machine holds no list of trusted certificates (`SSL_CERT_FILE` names one), `no_ssl` when this Python was built without its `ssl` module and cannot use HTTPS, or `offline` when `--offline` forbids the request. A folder named with `--from` cannot be read (`stage` is `from`, `reason` `not_found`, `not_a_folder` for a file that is no ZIP, `unreadable`, or `system` for the root of the system, `/proc`, `/sys` or `/dev`). The BIOS folder sits under a folder this user cannot open (`stage` is `dest`, `reason` `unreadable`), or is a file or lies under one (`reason` `not_a_folder`), and the run ends with code 1 before anything is written. A platform, target, system, core or emulator named on the command line is unknown or cannot be used here (`stage` is `option`, `reason` `unknown`, `platform` the platform it was checked against or the name typed), refused before any download with code 2. The BIOS folder cannot be created (`stage` is `dest`, `reason` `not_writable`): a `summary` follows with what the run installed before it. Two systems are detected on one machine and no `--dest` names the folder (`stage` is `detect`, `reason` `conflict`). The platform named with `--platform` is found nowhere and no folder can be assumed for it: a card system with no card named, a portable emulator, Batocera or Recalbox named on a computer (their folder is the `bios` folder of their SHARE drive), or no usual folder on this system or one set aside behind a folder this user cannot open (`stage` is `detect`, `reason` `not_found`). So is a platform named by a file list or a pack, in a run without questions where it is found nowhere here. A `--dest` refused as the card of the system named carries the same `stage` and `reason`: another system's card, a folder inside a card, a drive with none of the files its card always has, or a folder that does not exist. `message` says it in words, and is the only thing that tells these cases apart |
| `scanned` | `folder`, `files`, `truncated`, `other_drives` | Each folder named with `--from`, once read and before `detect`. `files` counts the files found, `truncated` is true when the search stopped at 200,000 of them, and `other_drives` lists the folders below it on another drive, which were not entered |
| `version` | `platform`, `list_version`, `installed_version`, `message` | Before `choices`, when the system here runs another version than the one the list was built for: `list_version` is the list's, `installed_version` the one the system's version file states, and `message` says it and what it means. Not written when either version is unknown. The run goes on |
| `board` | `platform`, `board`, `applied`, `message` | Before `choices`, with no `--target` and no `--every-board`, when the system names its board or a Batocera or KNULLI card mounted here does (`boot/batocera.board` or `boot/knulli.board` on its boot partition, `board` then being the board its image maps to): `applied` is true when the run keeps that board's files only, false for a board the platform's list does not name, which keeps every board's files. `message` says it |
| `unknown_core` | `platform`, `core`, `info`, `dests`, `message` | With `--installed-cores`, before `choices`, once for each installed core the list has no profile for. `info` is true when its RetroArch `.info` was found, and `dests` are the `firmware<N>_path` values it declares, kept whatever the narrowing drops. A core without a `.info` keeps nothing it alone reads, and `message` says so |
| `choices` | `platform`, `systems` | Before `checking`: the systems the run's list lets one choose among, sorted by id, `other` last for the files no system names. The run's other options apply (`--core`, `--region`, `--no-game-data`, the files left out for an unknown save directory), `--system` does not: these are the systems a screen lists to choose from, and the count a `--system` is out of |
| `set_aside` | `platform`, `dests` | Right after `choices`: the files of the list the run sets aside before any choice, in list order, those read from a save directory whose place is not known among them. A screen chooses its cores among the rest, the cores `--core` accepts |
| `file` | `platform`, `dest`, `systems`, `size`, `state` | Each file of the list after the check. `state` is `present` (hash verified), `wrong_hash` or `missing` |
| `system` | `platform`, `system`, `name`, `files`, `present`, `missing`, `wrong_hash`, `bytes_needed` | Each system, sorted by id, and with `--system` only the systems named. Files with no system count under `other`. `name` is the platform's own name for it |
| `checking` | `files_done`, `files_total` | While the files already in the folder are read and hashed, at most every half second and once at the end. `files_total` counts the files found in place |
| `games_reading` | `files_done`, `files_total` | With `--for-games`, while the games of the card are read (a cartridge hashed, a disc's header read), at most every half second and once at the end |
| `games` | `platform`, `folder`, `games`, `recognised`, `found`, `fallback`, `not_games`, `required_only` | With `--for-games`, once the games are read, before `choices`. `found` lists per system its `folder`, `games`, `recognised` and the `regions` kept (empty for every region). `fallback` names each game that got every BIOS of its system, with a `reason` (`not_recognised`, `not_read`, `region_unknown`, `unknown_set`, `no_parent`) |
| `games_unavailable` | `platform`, `reason`, `message` | With `--for-games`, what the games need could not be read (`offline`, `network`, `invalid`, `stale`, `no_sets`, `no_folder`): the run keeps every file of the list, except for a `FOLDER` that does not exist, where it stops |
| `check` | `platform`, `name`, `bios_dir`, `files`, `present`, `missing`, `wrong_hash`, `bytes_needed`, `data_missing`, `not_installable` | The platform's totals. `data_missing` counts data-tree files to fetch, `not_installable` the files the collection cannot supply |
| `declared` | `platform`, `files`, `present`, `missing`, `wrong_hash`, `bytes_needed`, `dests` | Right after `check`, the same counts over the files the platform's own list names (`cores: null`), and their `dests` in the order of the `file` events. A setup that checks its own list reads its answer here, with or without `--declared-only` |
| `data` | `platform`, `files`, `bytes` | Right after `declared`: the data-tree files to fetch (the `data_missing` of `check`) and the bytes fetching them costs: each tree's archive, or the files themselves from a pack or a list that records no archive size |
| `found` | `platform`, `dest`, `folder`, `path`, `member`, `reason` | Each file to install that this machine already holds, after `check` and before anything is written, in `--check` and `--dry-run` too. `folder` is the `--from` folder as given, or the `bios_dir` of the check when the BIOS folder holds the file at another place, and then `reason` says where in words (`nested folder: ...` for a misplaced file, `the same file is at ...` for one the list installs there too). `path` is the file, and `member` the ZIP member holding the bytes when `path` is an archive, an empty string otherwise. Its copy is reported by a `downloaded` event |
| `unreadable` | `platform`, `folder`, `path`, `member`, `reason` | Each file in a `--from` folder that could not be read and may be one the run still needs, right after the `found` events: its size is that of a file no copy was found for, or unknown (a folder that could not be listed, a ZIP that would not open). `member` names the ZIP member, or is empty. `reason` says why in words (`Permission denied`, `it is encrypted, a password is needed`) |
| `saves` | `platform`, `files`, `folder` | After `choices` and before `checking`, when the files the run installs (once `--system` and the other choices narrowed the list) hold some read from the frontend's save directory and that directory is known: how many, and the `folder` they go to, where `<system>` and `<core>` stand for one folder per system or per core (the screen and `--plain` say it in words: "a folder per core under /sdcard/RetroArch/saves"). When it is not known, the files are counted in the summary's `skipped` instead (`no_save_directory`) |
| `download` | `platform`, `files`, `bytes` | Before the downloads start. Counts the files copied from this machine too |
| `progress` | `files_done`, `files_total`, `bytes_done`, `bytes_total` | At most every half second while bytes arrive |
| `transfer` | `bytes_local`, `bytes_network` | Right after each `progress` event, and once when the files of a `download` event are done. It splits `bytes_done`: `bytes_local` came from this machine (a copy found by `--from` or in the BIOS folder, the pack, a partial copy resumed), `bytes_network` from the network. A download speed is `bytes_network` over the time elapsed |
| `downloaded` | `dest`, `ok`, `reason`, `size`, `files_done`, `files_total`, `bytes_done`, `bytes_total` | Each finished file, downloaded or copied from where a `found` event named it. `reason` says why one failed, and is empty otherwise |
| `summary` | `mode`, `installed`, `up_to_date`, `pending`, `failed`, `skipped`, `left_out`, `kept`, `interrupted` | The outcome. `pending` counts what a next run would still fetch, `failed` lists `{dest, reason}`, `skipped` lists `{reason, label, files, required}` for the files the collection cannot supply, `left_out` lists `{category, label, files, dests}` for what `--no-game-data` left out, and is empty without it. `kept` lists `{folder, files, bytes}`, one per backup folder, for the files in place the run moved aside before replacing them (with `--dry-run`, would move), and is empty when none. Not written for a listing |
| `app` | `system`, `folder`, `ok`, `reason`, `dests`, `written`, `kept` | After `summary`, with `--add-app` or a yes to its question: the RetroBIOS app on the card of `system` whose root is `folder`. `dests` lists the app's files below that root, `written` the ones this run wrote (empty when each was in place), `kept` the backup folders as in `summary`. `ok` is false, with `reason`, when the card takes no app (before anything is written, code 2), when the install did not finish, or when a file could not be fetched, verified or written (code 1) |
| `record` | `platform`, `folder`, `path`, `status`, `choice`, `date`, `files`, `message` | The [install record](#the-install-record) of `folder`, kept at `path`. `status` is `applied` before `choices` when the run took its choice, nothing on the command line having chosen, `written` before `summary` once an install placed files, `unreadable` when it cannot be read (said once, ignored), or `not_written` when it could not be saved, the install itself unharmed. `choice` is the recorded options as words, `date` when it was written (UTC), `files` how many files it holds for the platform |
| `removal_plan` | `platform`, `folder`, `files`, `bytes`, `systems`, `dests`, `kept`, `gone`, `backup`, `message` | With `--remove`, before anything is removed, and all a `--dry-run` writes: `dests` the files that go in record order, `bytes` the space they free, `systems` those losing a file, `kept` a `{dest, reason}` for each file left (`shared`, `changed`, `link`, `not_a_file`, `outside`, `not_servable`, `unreadable`, `not_recorded`), `gone` the recorded files no longer there, `backup` whether they are moved rather than deleted. With `files` 0 and a `message` when no record says what is the installer's |
| `removed` | `platform`, `dest`, `size`, `ok`, `reason`, `moved_to` | Each file `--remove` took. `ok` is false, with `reason`, for a file that stays. `moved_to` is its place in the backup with `--backup`, empty otherwise |
| `restored` | `folder`, `path`, `size`, `ok`, `reason` | Each file `--restore` put back from the backup `folder` to `path` |
| `backup` | `folder`, `date`, `files`, `bytes`, `source`, `status`, `message` | A backup folder: `status` is `listed` by `--backups`, `made` by `--remove --backup`, `deleted` or `not_deleted` by `--delete-backup`. `date` is when it was made, local time. `source` is `remove` for a removal's backup and `install` for the files an install replaced |
| `pack` | `platform`, `path`, `files`, `bytes`, `size`, `parts`, `status`, `message` | With `--pack`, once: `status` is `planned` with `--dry-run`, `written` once every part is in place, `failed` when no pack was written (`message` says why). `files` and `bytes` count the pack's members, each file stored once, `size` what the written files take on disk (0 unless `written`), `parts` each file written or to be written, the pack alone when it is one ZIP |
| `end` | `code` | Last line, with the exit status the process returns (see [Exit status](#exit-status)) |

<!-- /generated: events -->

Schema 1 can gain a kind (`found` came with `--from`, `declared` with `--declared-only`, `unsearched` with the search that goes on past a closed folder, `app` with `--add-app`, `data` with the size of the data trees, `version` with the list's version, `record` with the install record, `removal_plan`, `removed`, `restored` and `backup` with removal, `pack` with `--pack`), never a key of an
existing kind: a reader skips a kind it does not know. An option refused
before the run starts (`install.py: error:`, code 2) writes
no event at all. A program reads a missing `end` as that case, or as a
crash: an error the installer did not expect ends the process on a Python
traceback, on standard error, without an `end` line.

Five lines of a run of `--check --events --system sony-playstation` on a
RetroArch folder that holds only `scph5501.bin`, in the order written:

```json
{"event": "start", "schema": 1, "installer": "c90676dcc433", "mode": "check"}
{"event": "file", "platform": "retroarch", "dest": "scph5501.bin", "systems": ["sony-playstation"], "size": 524288, "state": "present"}
{"event": "check", "platform": "retroarch", "name": "RetroArch", "bios_dir": "system", "files": 118, "present": 1, "missing": 117, "wrong_hash": 0, "bytes_needed": 344457216, "data_missing": 0, "not_installable": 0}
{"event": "summary", "mode": "check", "installed": 0, "up_to_date": 1, "pending": 117, "failed": [], "skipped": [], "left_out": [], "kept": [], "interrupted": false}
{"event": "end", "code": 3}
```

## Environment overrides

| Variable | Effect |
|----------|--------|
| `RETROBIOS_REF` | Branch or tag the file list and the files committed to the repository are read from. Defaults to `main`. Files the manifest marks `release_asset` always come from the `large-files` release, whatever the ref, and that release replaces an asset in place when it is rebuilt. Each release deletes the previous release tags, so a tag holds a file list until the next release. For contributors: [release process](release-process.md#cutting-a-release) |
| `RETROBIOS_BASE_URL` | Base URL for the manifest and the files it declares. HTTPS only, plain HTTP allowed to loopback for end-to-end tests. Whoever controls this base controls the expected hashes, hence the check. A file list that cannot be fetched names the address, and this variable when it is set |
| `RETROBIOS_INSTALL_OFFLINE` | Set to anything but `0`: no network request, as with `--offline`. The runs the full-screen interface starts inherit it. The words then name the variable (`not fetched (RETROBIOS_INSTALL_OFFLINE=1)`, `run it with RETROBIOS_INSTALL_OFFLINE unset`), and `--offline` where the option was given. `RETROBIOS_OFFLINE` is the build scripts' own and leaves the installer alone |
| `RETROBIOS_OS` | Names the host outright (`linux`, `wsl`, `windows`, `darwin`, `android`) instead of detecting it |
| `EXTERNAL_STORAGE` | Android only, the shared storage root RetroArch builds its default directories from. Defaults to `/storage/emulated/0` |
| `RETROBIOS_INSTALL_URL` | Where the bootstrap fetches `install.py`. HTTPS only |
| `RETROBIOS_INSTALL_SHA256` | The SHA-256 the bootstrap requires of that installer, 64 hex characters. When either of these two is set and the fingerprint does not match, the error names the variable instead of suggesting a retry |
| `RETROBIOS_BOOTSTRAP` | Set by `install.sh` (`sh`) and `install.ps1` (`ps1`) for the temporary installer they run, and by the `retrobios` package (`pypi`), so that its hints give back the command that ran it (the one-liner, `uvx retrobios`, `pipx run retrobios` or `retrobios`) rather than `python3 install.py` |
| `NO_COLOR` | Set to any value but an empty one: no colour, even at a terminal. The full screen then marks the row in focus with `>` as well as reverse video. What else turns colour off is under [The full-screen interface](#the-full-screen-interface) |
| `TERM`, `TERMINFO`, `TERMINFO_DIRS` | Decide whether the full screen opens, as [The full-screen interface](#the-full-screen-interface) says. The terminal's description is read where ncurses reads it: `TERMINFO`, then `~/.terminfo`, then each folder of `TERMINFO_DIRS`, then the system's own |
| `FORCE_COLOR`, `CLICOLOR_FORCE` | Colour even when the output is a pipe or a file, set to any value but `0` or an empty one. `NO_COLOR` wins over both, and the progress line stays one line per file |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | The trusted certificates to check servers with, for a Python that finds none of its own |
| `RETROBIOS_PLAIN`, `ACCESSIBLE` | Set to anything but `0`: the questions come line by line, as with `--plain`, instead of the full-screen interface |
| `RETROBIOS_PAD` | The buttons a handheld launcher's mapper sends to the full screen (`gptokeyb`, `gptokeyb_muxterm`, `muxterm`, `evmapy`, `miyoo`), so its hints name them. See [On a handheld](#on-a-handheld-the-retrobios-port) |
| `RETROBIOS_IDLE_EXIT` | Seconds the full screen waits for a first button, counted while nothing runs. With none pressed, it closes with exit status 2, as a quit, or with the code of the error or result screen it closed on |
| `RETROBIOS_NO_MOUSE` | Set to any value but `0` or an empty one: the full screen never asks the terminal for clicks, and the mouse selects text everywhere as it does outside the installer |
| `RETROBIOS_CACHE` | The folder that keeps the games index and what a run read of the games, for the next run. Defaults to `retrobios` in `$XDG_CACHE_HOME` (else `~/.cache`), `~/Library/Caches` on macOS, `%LOCALAPPDATA%` on Windows. Deleting it loses nothing |
| `RETROBIOS_DEBUG` | Set to anything: says why the games index could not be fetched or a cache file not written |
| `HTTPS_PROXY`, `NO_PROXY` | Honoured for every download through the standard library's default proxy handling: one names the proxy, the other the hosts to reach directly |

## When something goes wrong

The common cases, with the short answer, are on
[When a game does not start](troubleshooting.md). The details follow.

### Network

The installer fetches its manifest, then downloads only the repository or
`large-files` release objects it needs. When a download fails, check that
`https://github.com` opens. Behind a proxy, set `HTTPS_PROXY` in the
environment. A connection that does not open within 4 seconds counts as
none, so a dropped network gives its error in about 15 seconds. Once a
connection is open, a slow transfer keeps the full timeout. The file list
is the exception: a server that takes the connection and then sends nothing
(a Wi-Fi sign-in page, a stuck proxy) gets 15 seconds per wait and two
attempts, about 30 seconds in all. A file that fails three attempts is counted and reported at the
end, and the next run fetches only what is still missing.

The reason is said in words: no internet connection or a name that could not
be looked up, a connection that timed out, was refused or was cut, a
certificate that was rejected. `--verbose` adds the text Python gave. Two
causes are not the network and are not retried:

- `The clock reads 1980-01-01`: a device without a clock battery starts on an
  old date, and every certificate then looks not yet valid. Connect to Wi-Fi
  and let the time sync, or set the date, then run again.
- `This system has no list of trusted certificates`: install the
  `ca-certificates` package, or name a certificate bundle with `SSL_CERT_FILE`.
  When the system keeps one where this Python does not look, the message names
  it. Certificate checks are never turned off.

### Permission denied

The installer needs to write to the BIOS folder. On Linux and macOS, check who
owns it (`ls -la`). On Batocera, Recalbox and ROCKNIX the folder belongs to
root, so the same command with `sudo` in front of it succeeds. On Windows, run
PowerShell as Administrator only for a protected folder.

When a folder above the BIOS folder cannot be opened at all (`/root/...` run
without `sudo`, a card mounted for another user), the run stops before it
starts: `this user cannot open /root (Permission denied), which holds
/root/.config/retroarch/system`. The full-screen interface says the same on
the folder screen and asks for another folder.

A folder the search for setups cannot open (`~/.config/EmuDeck` left to root
by a `sudo` run) is named once, `Could not look for setups: this user cannot
open ...`, and the search goes on everywhere else: a RetroArch whose
`retroarch.cfg` is readable is still found at the folder it reads. The
full-screen interface keeps that line above the list of setups.

A file system mounted read-only refuses root too, so the installer does not
suggest `sudo` for it. Linux remounts a card or drive read-only after an error,
an unclean removal for one: check it (`fsck`, or `chkdsk` on Windows) and
mount it read-write again.

A file already in the BIOS folder with the read-only attribute is replaced
like any other: on Windows the installer clears the attribute first.
`file in place is read-only` appears only when Windows refuses that too, which
a file owned by another account can cause.

### Platform not detected

The installer finds a platform from the config files it knows. When it finds
none, name the platform and its BIOS folder:

```bash
curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --platform retroarch --dest ~/.config/retroarch/system
curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --platform batocera --dest /userdata/bios
```

```powershell
&([scriptblock]::Create((irm https://abdess.github.io/retrobios/i.ps1))) `
  --platform retroarch --dest C:\RetroArch-Win64\system
```

`--list-platforms` lists the platforms the installer knows and the ones it
finds here. `--help` lists the options with examples.

### No file list

The installer reads its file lists from `main`, or from the ref
`RETROBIOS_REF` names. A platform name is checked before anything is
downloaded, so a "No file list" message comes from that ref: a tag that does
not exist, or one older than the platform. Unset it, or pick a tag
from the releases page ([Environment overrides](#environment-overrides)).

### Upper and lower case

Linux file systems tell `Bios.ROM` and `bios.rom` apart. Windows and macOS do
not, by default.

The RetroArch pack is built for every system RetroArch runs on, so it holds
one name per file: `BIOS.col`, never `bios.col` beside it, since unzipping both
on Windows or macOS would overwrite one with the other. On Linux, Mesen-CE
opens `bios.col` and NP2kai opens the lowercase `np2kai/2608_*.wav`, which the
pack only holds as `BIOS.col` and `2608_*.WAV`. The installer checks whether
the BIOS folder keeps case and, when it does, also fetches these names. On
Linux, use the installer rather than unzipping the pack by hand.

The reverse happens on Batocera and Recalbox, whose lists hold both spellings
because their systems keep case: NP2kai reads `np2kai/bios.rom` and
`np2kai/BIOS.ROM` as two files. Written to a folder that folds case (the share
opened from Windows, an exFAT card), one overwrites the other. The installer
checks the folder first, keeps one file per name there and lists the ones it
left out.

FAT, exFAT and every Windows drive also refuse `< > : " | ? *` in a name
(Linux `fs/fat/namei_vfat.c:201-207`, `fs/exfat/nls.c:396-403`). RetroDECK's
list names three files with a colon, like `zxs:48.rom`. Before writing such a
name, the installer creates one in the BIOS folder: on an ext4 card it goes
in, on an exFAT card the installer leaves those files out and names them.

### Packs and their parts

`scripts/download.py --list` and `scripts/download.sh --list` print the packs of
a release. A pack's name lists every platform it serves. Releases up to
v2026.10.10 ship RetroArch and Lakka as one `RetroArch_Lakka` pack. Later
releases publish packs only for the setups most people download, so Lakka,
which runs on Linux where two names that differ by case are two files, is
served by the installer. The download scripts name the installer for a setup without a pack.

Parts named `Pack.part1of2.zip` are ordinary ZIPs: unzip each one into the same
folder, and check that all of them were downloaded. The name says how many
there are, and each part leaves a marker file naming every part, which
`--check` reads to name a part that is missing. `scripts/download.sh` and `scripts/download.py` download every part
and check it against the release's checksums before unzipping. Both stage
inside the destination folder, never in `/tmp`, which is a RAM disk on most of
these systems.
