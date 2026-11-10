---
level: reference
order: 45
group: Checking files
terms: recipe, rebuild, archive, zip, romset, exact, canonical
---

# Rebuilding an archive

Arcade emulators read their BIOS files from a ZIP archive.

The collection keeps a **recipe** for each archive. It lists the files
inside, in order, with their fingerprints. The recipe and those files make
the archive again. No copy from elsewhere is needed.

## Rebuild one archive

In a copy of the project:

```bash
python scripts/romset_recipes.py --build neogeo.zip --output-dir rebuilt
```

Each archive of that name is made under `rebuilt/`, in the folders it has in
the collection. It is checked against its recipe before it is kept.

## Exact or canonical

<!-- generated: archive-recipes -->
- **Exact**: the same bytes as the archive in the collection. 1,794 of 2,229 archives.
- **Canonical**: the same files inside, packed another way. 435 of 2,229 archives.
<!-- /generated: archive-recipes -->

An emulator reads the files inside, so both work the same. A setup that
checks the whole archive by its fingerprint needs the exact one.

Every option of the command: [tools](tools.md#archive-recipes).
