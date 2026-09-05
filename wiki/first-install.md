# First install

One path, from an empty BIOS folder to files the emulator can read. Every step
shows what the screen looks like when it worked, so there is never a moment of
wondering.

If something on this page does not match what happens, the last section covers
the cases that come up.

## Before starting

Three things, and a few minutes:

- The BIOS folder the emulator reads. The installer finds it by itself on most
  systems; on a handheld, that usually means plugging the SD card into a
  computer.
- `curl` or `wget`, and Python 3.8 or newer. The command below checks for both
  and stops with a message if either is absent.
- Room on the drive. A full RetroArch set is 5.5 GB, Batocera 4.0 GB, MiSTer
  FPGA 24 MB. The installer measures the free space and refuses before writing
  anything if there is not enough.

Nothing is written outside the BIOS folder, and games and saves are never
touched.

## Step 1. Run the command

On Linux, macOS, a Steam Deck, or a handheld running Batocera, Recalbox,
KNULLI, ROCKNIX or Lakka:

```bash
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh
```

On Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1 | iex
```

PowerShell's execution policy does not block that line. The policy governs
script files, and this command never writes one. Changing the policy is not
part of installing anything here.

On Android, from Termux, three commands instead of one:

```bash
pkg install python
termux-setup-storage
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh
```

Before running anything, that first line downloads the installer, compares it
against the SHA-256 written inside the command's own script, and refuses to
continue if the two differ. To read the script first:

```bash
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | less
```

## Step 2. Watch it find the platform

The first lines name what it found and where it will write:

```
RetroBIOS

Detecting platform...
  Found Batocera at /userdata/bios
```

That path is the one thing worth reading twice. If it is not where the emulator
keeps its BIOS files, stop with Ctrl+C and see the last section.

## Step 3. Let it work

Two phases follow. The first reads what is already in the folder, which takes a
few minutes on a memory card because every file is hashed:

```
Fetching file index for misterfpga...
  72 files (24.0 MB)

Checking existing files...
  72/72 present (72 verified, 0 wrong hash)
```

On a first install those numbers are zeros, which is expected, not a fault.

The second phase downloads what is missing, one line per file:

```
Downloading 72 files (24.0 MB)...
  Press Ctrl+C to stop. Running the same command again carries on from here.
  [1/72] AtariLynx/boot.rom ok
  [2/72] Astrocade/boot.rom ok
```

Ctrl+C is safe at any point. Files already installed stay, and running the
command again picks up where it stopped.

## Step 4. Read the last three lines

This is what a finished run looks like:

```
Done. 72 files installed, 0 files already up to date.
Location: /userdata/bios
To check this later, run the same command with --check.
```

The word `Done` and a location are the confirmation. Any other ending means
something was left undone, and the run says which case it was.

## Step 5. Confirm it later

The same command with `--check` reads the folder and writes nothing:

```bash
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh -s -- --check
```

```
Checking existing files...
  72/72 present (72 verified, 0 wrong hash)

  All files up to date.
```

`0 wrong hash` is the line that matters. A number there means a file is present
whose contents the platform will reject, and running the install again replaces
it.

## When the screen says something else

### No supported platform detected.

The command was piped from the internet, so it cannot stop and ask a question.
Name the platform and the folder instead:

```bash
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh \
  | sh -s -- --platform retroarch --dest /path/to/system
```

The accepted names come from `--list-platforms`. For where each platform keeps
its BIOS folder, see [Getting started](getting-started.md).

### Error: Python 3.8 or newer is required.

Python is missing from the machine. The message names the command that installs
it, `sudo apt install python3` on Debian and Ubuntu; on a handheld running Batocera or Recalbox it is already there, so
this message usually means the command ran on the computer rather than on the
console.

### Error: the downloaded installer does not match its expected fingerprint.

Nothing was run and nothing was written. The download did not match the
fingerprint the script carries, which is almost always a transfer cut short.
Running the command again, on another network if possible, is the answer.

### Cannot create ...

The user running the command cannot write there. On Batocera, Recalbox and
ROCKNIX the BIOS folder belongs to root, so the same command with `sudo` in
front of it succeeds.

### Not enough space on the drive holding ...

The run stopped before writing. The message names how much is needed and how
much is free. `--dest` installs to another drive.

### The game still shows a black screen

A file can be in place and still be the wrong one for that game, or the console
may need a file that nobody has dumped yet.
[Troubleshooting](troubleshooting.md) goes through that case.

## What comes next

- [Troubleshooting](troubleshooting.md), when a game does not start
- [FAQ](faq.md), for what the words mean and why a pack is this large
- [Installer](installer.md), for every option, what it detects and what it is
  allowed to write
