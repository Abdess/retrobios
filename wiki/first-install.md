---
level: start
order: 30
---

# First install, step by step

From an empty BIOS folder to games that start.

**You need:** internet and some free space.

## 1. Open a terminal and paste

A **terminal** is a window where you type commands. Paste your system's
line, then press Enter.

<Tabs syncKey="os">
<TabItem label="Windows">

Open the Start menu. Type **PowerShell** and open it.

```powershell title="PowerShell"
irm https://abdess.github.io/retrobios/i.ps1 | iex
```

</TabItem>
<TabItem label="macOS">

Open **Terminal**, in Applications, then Utilities.

```sh title="Terminal"
curl -fsSL https://abdess.github.io/retrobios/i | sh
```

</TabItem>
<TabItem label="Linux">

Open a terminal.

```sh title="Terminal"
curl -fsSL https://abdess.github.io/retrobios/i | sh
```

</TabItem>
<TabItem label="Steam Deck">

Switch to Desktop Mode and open **Konsole**.

```sh title="Terminal"
curl -fsSL https://abdess.github.io/retrobios/i | sh
```

</TabItem>
<TabItem label="Android (Termux)">

Install **Termux**, a terminal app, and run this line. It installs Python
and asks Android for storage access: allow both.

```sh title="Terminal"
curl -fsSL https://abdess.github.io/retrobios/i | sh
```

</TabItem>
</Tabs>

On Batocera, Recalbox and similar setups, see
[Get your files](../which-pack.md).

## 2. Check the setup it found

It opens a menu:

```
 RetroBIOS: Where do you play?
 Found on this machine:
 > <your setup>
   Another setup or folder
 BIOS folder: <its folder>
```

- **Right folder?** Press Enter.
- **Wrong folder, or a handheld's SD card?** Choose
  **Another setup or folder**. Press / and type the device (Miyoo Mini),
  or browse.

Arrows move, Enter chooses, Esc goes back (A and B on a handheld). On a
touch screen, tap a row twice to open it, once to tick a box.

## 3. Install

Press Enter on **Install**. **Choose systems** keeps the consoles you
play.

**Game data** (only a game reads it) has its own row.

**Old card?** In a card reader, choose **Copy the BIOS files from your old
card or a folder**, then the card.

## 4. Wait

Esc or Ctrl+C stops, B on a handheld. Run again to resume.

## 5. Read the result

- **Done**: all files are in place.
- **Finished with errors**: run it again. It retries only those.
- **Finished with files missing**: run it again online.
- **Nothing installed**: the screen says why. See [If it stops](#if-it-stops).

For line-by-line questions (screen readers), add `--plain`.

## What the command does

<!-- image: install-flow -->

## Check it later

Add `--check` to the same command. It changes nothing.

<!-- os-tabs -->
```sh
curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --check
```

All good:

```
  Everything is in place.
```

## Undo

Replaced files go to `retrobios-backup` beside your BIOS folder. The result
says how to restore them.

## If it stops

### Nothing was found here.

Choose your setup, then its folder. Where the screen offers
**Another setup or folder**, choose it first.

### Error: Python 3.8 or newer is required.

Run the command the message shows, then the installer again.

RetroPie 4.8 has Python 3.7.3, and its update finds nothing newer. Run it on
a computer, with RetroPie's `bios` share open, `\\RETROPIE\bios` from Windows:

<!-- RetroPie-Setup scriptmodules/supplementary/samba.sh:49-52 (46128cd2) shares
$home/RetroPie/BIOS as "bios", and RetroPie docs/Transferring-Roms.md:29 names
\\RETROPIE. -->

<!-- os-tabs windows: --platform retropie --dest \\RETROPIE\bios\ -->
```sh
curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --platform retropie --dest <the bios share>
```

### Error: the downloaded installer does not match its expected fingerprint.

Nothing ran, because something changed the file. Try another network.

### Cannot create ...

You cannot write there. Do what the message says.

### The card is full

Nothing was written. Free some space there.

### The game still does not start

See [When a game does not start](troubleshooting.md).

## Next steps

- [Get your files](../which-pack.md)
- [When a game does not start](troubleshooting.md)
- Details: [Reading the installer's output, line by line](installer.md#reading-a-run)
