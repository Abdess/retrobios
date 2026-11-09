# Security policy

## Scope

- The one-line installer: `install.sh`, `install.ps1` and the `install.py` they download.
- The packs, their manifests under `install/` and the checksums each release publishes.
- The website, its scripts and the data it serves under `api/`.

## Reporting a vulnerability

Report it privately from the repository's **Security** tab, with **Report a vulnerability**. A public issue is the wrong place for it: the details stay private until a fix is out.

A useful report names the file or the page, the steps that show the problem, and what an attacker gains.

## Supported versions

The installer and the site served from `main`, and the latest release. Older releases are removed when a new one is published.

## How downloads are checked

- `install.sh` and `install.ps1` download `install.py` from a fixed commit and refuse it unless its SHA-256 matches the one they carry.
- The installer checks every file against the hash its manifest records before writing it.
- Each release lists the SHA-256 of its files in `SHA256SUMS.txt`, signed with the key in `allowed_signers`: [verifying a release](https://abdess.github.io/retrobios/wiki/release-process/#verifying-a-release).

## Not a security issue

A file with an unexpected hash, a missing file or a takedown request: [open an issue](https://github.com/Abdess/retrobios/issues/new) with the file's path or hash.
