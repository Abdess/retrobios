"""A pack limited to some systems carries those systems' core extras.

With --platform and --system, the full source emptied the core extras, so
`--source full` and `--source platform` built the same pack under two
names, while the split packs, built per system, carried them.
"""

from __future__ import annotations

import tests
from tests.sources import script_source

import unittest
from pathlib import Path

from packs.extras import extras_for_systems as _extras_for_systems

REPO_ROOT = Path(__file__).resolve().parents[1]


class SystemExtras(unittest.TestCase):
    def test_extras_follow_their_system(self):
        extras = [
            {"name": "a", "source_system": "sony-playstation"},
            {"name": "b", "source_system": "sega-saturn"},
            {"name": "c", "source_systems": ["sony-playstation", "sony-psp"]},
        ]
        picked = [e["name"] for e in _extras_for_systems(extras, ["sony-playstation"])]
        self.assertEqual(picked, ["a", "c"])

    def test_a_shared_file_follows_every_core_that_reads_it(self):
        """One extra stands per destination and the other cores' claims ride on
        it. Their systems are the file's systems too: narrowed to one of them,
        pack and installer both keep the file the core reads."""
        from packs.manifestselect import SelectionIndex

        extras = [{
            "name": "floppy.wav", "destination": "mame/samples/floppy.wav",
            "source_system": "coco",
            "other_claims": [{"name": "floppy.wav", "source_system": "supracan"}],
        }]
        picked = [e["name"] for e in _extras_for_systems(extras, ["supracan"])]
        self.assertEqual(picked, ["floppy.wav"])
        index = SelectionIndex.build({}, {}, {"coco": {}, "supracan": {}}, extras)
        self.assertEqual(
            index.fields("mame/samples/floppy.wav", "floppy.wav")["systems"],
            ["coco", "supracan"],
        )

    def test_full_source_does_not_empty_them(self):
        source = script_source("generate_pack.py")
        self.assertNotIn('elif system_filter and source != "truth":\n          core_files = []', source)


if __name__ == "__main__":
    unittest.main()
