# Contributing to RetroBIOS

## Add a BIOS file

1. Fork this repository
2. Place the file in `bios/Manufacturer/Console/filename`
3. Variants (alternate hashes): `bios/Manufacturer/Console/.variants/`
4. Create a Pull Request - checksums are verified automatically

## File conventions

- Files >50 MB go in GitHub release assets (`large-files` release)
- RPG Maker and ScummVM directories are excluded from deduplication
- See the [documentation site](https://abdess.github.io/retrobios/) for full details
