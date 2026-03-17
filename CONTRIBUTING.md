# Contributing BIOS Files

Thank you for helping expand the BIOS collection!

## How to Contribute

1. **Fork** this repository
2. **Add** your BIOS file to the correct directory under `bios/Manufacturer/Console/`
3. **Create a Pull Request**

## File Placement

Place files in the correct manufacturer/console directory:
```
bios/
├── Sony/
│   └── PlayStation/
│       └── scph5501.bin
├── Nintendo/
│   └── Game Boy Advance/
│       └── gba_bios.bin
└── Sega/
    └── Dreamcast/
        └── dc_boot.bin
```

## Verification

All submitted BIOS files are automatically verified against known checksums:

1. **Hash verification** - SHA1/MD5 checked against known databases
2. **Size verification** - File size matches expected value
3. **Platform reference** - File must be referenced in at least one platform config
4. **Duplicate detection** - Existing files are flagged to avoid duplication

## What We Accept

- **Verified BIOS dumps** with matching checksums from known databases
- **System firmware** required by emulators
- **New variants** of existing BIOS files (different regions, versions)

## What We Don't Accept

- Game ROMs or ISOs
- Modified/patched BIOS files
- Files without verifiable checksums
- Executable files (.exe, .bat, .sh)

## Questions?

Open an [Issue](../../issues) if you're unsure about a file.
