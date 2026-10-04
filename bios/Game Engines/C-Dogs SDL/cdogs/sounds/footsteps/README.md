Footsteps depend on the following:

- Character class (some override all footstep sounds)
- Tile type
- Map item

The tile type determines footstep sound based on the tile sprite.

Some map items also modify footstep sounds if actors walk over it, like grates.

See `MatGetFootstepSound` for details.

Inspired by the Half-Life materials system - see https://greg-kennedy.com/hl_materials/
