# Installer - RetroBIOS

Reference for `install.sh`, `install.ps1` and `install.py`: what the one-liner
runs, what it detects, where the bytes come from and what it is allowed to
write. For BIOS directory paths per platform, see
[Getting started](getting-started.md).

## One line

```bash
# Linux / macOS / Steam Deck
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh
```

```powershell
# Windows
irm https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1 | iex
```

From a clone, run the installer itself. Nothing beyond the standard library is
needed, and Python 3.8 is the floor both bootstraps enforce before handing over:

```bash
python install.py
```

## Passing options

The shell bootstrap forwards everything after `-s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh \
  | sh -s -- --platform retroarch --dest /path/to/sdcard
```

PowerShell needs another form. `iex` takes the script text as its own argument,
so anything appended to `irm ... | iex` is read as an argument to `iex` and
rejected with `A positional parameter cannot be found`. Building a script block
from the text and calling it passes the arguments through:

```powershell
&([scriptblock]::Create((irm https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1))) `
  --platform retroarch --dest D:\bios
```

## What the bootstrap does

Both wrappers do the same four things before any BIOS file is considered.

They fetch `install.py` over HTTPS only, from `RETROBIOS_INSTALL_URL` or the
pinned raw URL. A URL with any other scheme is refused outright.

They cap the download at 2 MB and require the SHA-256 to equal the 64 hex
characters embedded in the wrapper, `RETROBIOS_INSTALL_SHA256` when set. A
mismatch aborts with `install.py SHA-256 mismatch` and nothing runs. Any change
to `install.py` therefore means recomputing that pin in both wrappers.

They locate a Python 3.8 or newer interpreter (`python3` then `python` on
POSIX, `py -3` then `python3` then `python` on Windows) and refuse to continue
without one. `install.sh` needs `curl` or `wget` and `sha256sum` or `shasum`.
Windows PowerShell 5.1 still negotiates SSL 3.0 and TLS 1.0 by default and
GitHub refuses both, so `install.ps1` raises the floor to TLS 1.2 before
downloading; `install.sh` pins the same floor with `curl --tlsv1.2`.

They delete the temporary installer on the way out, including on interrupt.
Run from a clone, `install.sh` and `install.ps1` reuse the `install.py` sitting
next to them and skip the download entirely; piped from stdin, `install.sh`
never treats the working directory as a trusted location for it.

## What the installer does

1. Detects the host OS and the platforms installed on it.
2. Fetches `install/<platform>.json` from the same revision the bootstrap
   verified the installer against, so the file list and the code reading it
   always come from one commit.
3. Prints the file count and total size, then a safety notice counting the
   entries the collection cannot serve, how many of those the platform marks
   required, and why.
4. Hashes what is already in the destination and reports how many entries are
   present, verified, or present with the wrong contents.
5. Downloads what is missing or wrong, up to 8 files at a time.
6. Verifies each download against the declared size, SHA-256 and SHA-1 before
   it touches the destination, retrying up to three times, then moves it into
   place with `os.replace` so a partial file is never visible.
7. Copies into standalone emulator directories, only with `--standalone-copies`.

A run looks like this:

```
Fetching file index for retroarch...
  1872 files (5.5 GB)
  Safety notice: 9 unavailable or unsafe entries omitted (1 required; not found: 9).

Checking existing files...
  0/1872 present (0 verified, 0 wrong hash)

  1872 files need downloading.
```

## Options

| Option | Effect |
|--------|--------|
| `--platform NAME` | Install for this platform instead of the detected one. Unknown names are refused with the available list |
| `--dest PATH` | Destination directory, overriding detection. With `--dest` alone the file list is RetroArch's |
| `--target NAME` | Keep only the files the cores of that hardware target need. An unknown target is refused rather than ignored, since carrying on would install everything |
| `--check` | Report and exit without writing |
| `--list-platforms` | Print the supported platforms and what was detected here |
| `--list-targets` | Print the hardware targets a platform publishes, with the core count each carries |
| `--jobs N`, `-j N` | Parallel downloads, 1 to 32, default 8 |
| `--verbose`, `-v` | Print per-attempt failures and hash mismatches |
| `--standalone-copies` | Also copy into detected standalone emulator directories |

`--check` reads the same file list, hashes the destination and exits. Without
it, a file already present with the expected hash is left untouched, and one
whose contents do not match is re-downloaded and replaced by the verified copy.
Files the list does not name are never read, moved or deleted.

## Environment overrides

| Variable | Effect |
|----------|--------|
| `RETROBIOS_REF` | Branch or tag the file list and the payloads are read from. Defaults to `main`; a release tag pins a reproducible file set |
| `RETROBIOS_BASE_URL` | Base URL for the manifest and the files it declares. HTTPS only, plain HTTP allowed to loopback for end-to-end tests. Whoever controls this base controls the expected hashes, hence the check |
| `RETROBIOS_OS` | Names the host outright (`linux`, `wsl`, `windows`, `darwin`) instead of detecting it |
| `RETROBIOS_INSTALL_URL` | Where the bootstrap fetches `install.py`. HTTPS only |
| `RETROBIOS_INSTALL_SHA256` | The SHA-256 the bootstrap requires of that installer, 64 hex characters |
| `HTTPS_PROXY` | Honoured for every download, through the standard library's default proxy handling |

## Platform detection

Detection reads what the platform itself writes, never a guess from a directory
name. The embedded systems are tested in the order below and the first match
wins, since a machine is only one of them.

| Evidence | Platform | BIOS directory |
|----------|----------|----------------|
| `/etc/os-release` `ID=rocknix` | ROCKNIX | `/storage/roms/bios` |
| `/media/fat/MiSTer` | MiSTer FPGA | `/media/fat/games` |
| `/etc/knulli-release` | Batocera | `/userdata/bios` |
| `/etc/os-release` `ID=lakka` | Lakka | `/storage/system` |
| `/etc/batocera-version` | Batocera | `/userdata/bios` |
| `/recalbox/recalbox.version` or `/usr/bin/recalbox-settings` | Recalbox | `/recalbox/share/bios` |
| `/opt/muos` or `/mnt/mmc/MUOS/` | RetroArch | `/mnt/mmc/MUOS/bios` |
| `/home/ark` and `/opt/system` | RetroArch | `/roms/bios` |
| `/mnt/vendor/bin/dmenu.bin` | RetroArch | `/mnt/mmc/bios` |

Desktop installs are read from their own configuration, and several can be
found on one machine.

| Evidence | Platform | BIOS directory |
|----------|----------|----------------|
| `~/.config/EmuDeck/settings.sh` | EmuDeck | `emulationPath` + `/bios` |
| `%APPDATA%\EmuDeck\settings.ps1` | EmuDeck | `$emulationPath` + `\bios` |
| `~/.var/app/net.retrodeck.retrodeck/config/retrodeck/retrodeck.json` | RetroDECK | `paths.rd_home_path`, falling back to the pre-migration `retrodeck.cfg` and its `rdhome` |
| `~/.var/app/org.libretro.RetroArch/config/retroarch/retroarch.cfg` | RetroArch (Flatpak) | `system_directory` |
| `~/snap/retroarch/current/.config/retroarch/retroarch.cfg` | RetroArch (Snap) | `system_directory` |
| `~/.config/retroarch/retroarch.cfg` | RetroArch (native) | `system_directory` |
| `~/Library/Application Support/RetroArch/retroarch.cfg` | RetroArch (macOS) | `system_directory` |
| `%APPDATA%\RetroArch\retroarch.cfg` | RetroArch (Windows) | `system_directory` |
| `%ProgramFiles(x86)%\Steam\steamapps\common\RetroArch\retroarch.cfg` | RetroArch (Steam) | `system_directory` |
| LaunchBox `Data\Emulators.xml` | RetroArch (portable) | the system directory that entry points at |

`system_directory` is read the way RetroArch expands it: a leading `~` is the
home directory, a leading `:` is the application directory, and `default` means
`system` next to the application. The LaunchBox installation is located through
its Start menu shortcut, the only record of where its installer was pointed.

ES-DE and LaunchBox are reported when present and nothing is written to them:
they reference emulators rather than owning a BIOS directory. ES-DE is looked
up at `$ESDE_APPDATA_DIR` or `~/ES-DE`, the two locations its own
`getAppDataDirectory` resolves.

BizHawk, RetroBat, RomM and RetroPie have no detection and are selected with
`--platform`. When a forced platform is not found on the machine, the
destination falls back to `/userdata/bios` for Batocera, `/recalbox/share/bios`
for Recalbox, `/storage/system` for Lakka, `~/retrodeck` for RetroDECK,
`~/Emulation/bios` for EmuDeck, `/storage/roms/bios` for ROCKNIX,
`/media/fat/games` for MiSTer, `~/RetroPie/BIOS` for RetroPie, and `~/bios`
for anything else. Pass `--dest` to say where instead of relying on that.

With nothing detected, the installer lists the platforms and asks. With several
detected, it asks which one. Both prompts need a terminal: piped into a script
with no platform to install for, it prints the manual invocation and exits 1.

## Where the files come from

Each manifest entry names either `repo_path`, served from the repository at the
pinned revision, or `release_asset`, served from the `large-files` release for
the files above the size GitHub carries in a tree. Everything else in the entry
(`dest`, `size`, `sha1`, `sha256`, `cores`) describes what must land where and
what it must hash to.

Entries the collection cannot satisfy are not silently dropped: they travel in
`omitted_files` with a reason, and the run prints the count before downloading
anything. `not_found` means no file in the collection matches the entry, which
is what the [gap analysis](../gaps.md) tracks.

## Trust boundary

The manifest is fetched over the network and treated as untrusted input. Every
path it carries goes through one validator that refuses an absolute path, a
drive letter, a backslash, a null byte, a doubled separator, a trailing slash
and any `..` component, so a destination cannot climb out of the BIOS
directory. Manifest, target list and payloads each have a size cap, the file
list a count cap, and the sum of the declared sizes is checked against the
total the manifest claims.

Symbolic links met under the BIOS root are followed on purpose: they are the
user's own layout, and EmuDeck links `bios/shadps4/sys_modules` into shadPS4's
data directory where the emulator actually reads it. The boundary is lexical,
not a resolved-path comparison, which is what keeps that case working.
Standalone copies are stricter, since they write outside the tree the user
selected: a symlink already sitting at the destination is skipped rather than
followed.

## Exit status

`0` on success, `1` on failure: an unusable base URL, an unknown platform or
target, a manifest that fails validation, a fetch that never succeeded, or no
platform to install for in a non-interactive run.

Failures that are per-file, such as a download exhausting its three attempts,
are counted and reported at the end.

## When something goes wrong

See [Troubleshooting](troubleshooting.md#installation-script-fails) for network,
permission and detection failures.
