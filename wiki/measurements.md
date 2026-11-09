---
level: reference
order: 70
group: Data
terms: measurement, proof, tested, core probe, real conditions, method
---

# How emulators are tested

An emulator runs here only when a question needs a real answer. That is an
issue, a fix sent to a project, or a check before a release.

A page that relies on a run says so in a **Proof** line. Every run is on the
[Measurements](../measurements.md) page.

## What a test does

- A script runs the emulator with no window and no sound.
- It starts a game and runs it for a set time.
- A test that compares files runs each case at least twice.
- It compares the screens with ones checked by eye.
- It reads the emulator's log to see which BIOS it ran.

## What a result says

| Result | Meaning |
|--------|---------|
| works | the game reached a screen it shows when it works |
| works on its built-in BIOS | it worked, but the emulator refused the file and ran its own BIOS |
| BIOS error | the emulator said a BIOS is missing or wrong |
| crash | the emulator stopped |
| hang | the screen stayed blank, or the run never ended |
| unknown | none of these could be shown |
| no verdict | an older test that only compared screens |

## What a result does not prove

- It shows the first minutes of one game, not the whole game.
- It sees the files the emulator opened on this path, not every path.
- Some emulators run their own BIOS when the given one is refused. The game still works.
- The app that runs the game may change settings the test left as they were.

## How a file is proven

The game runs with no BIOS and with the BIOS alone. Then it runs with a wrong
file under the BIOS name: zeros, half the file, or another region's BIOS.

- **Required**: no BIOS fails, the BIOS alone works.
- **Built-in stand-in**: no BIOS still works.
- **Checked**: a wrong file is refused.

## Where results are kept

Each result is a full record in the
[`measurements/`](https://github.com/Abdess/retrobios/tree/main/measurements)
folder. It names its method, the computer and the exact build of the emulator.

Records are added. A change to one is a commit of its own.

The results so far ran on these computers:

<!-- measurements-hosts -->
