This is a simple guide to making sprites that will fit in the style of C-Dogs. Consistency is the most important thing; it doesn't matter how good an individual sprite looks, if it looks different from the rest it will stick out and make the whole thing look bad!

## Summary

![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/barrel_blue.png)
![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/wall/plasteel/o.png)
![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/plant.png)
![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/box.png)
![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/rocket.png)

C-Dogs sprites are:

  - Pixel art
  - Somewhat limited palette
  - Lit from the top-left, with a secondary light from the bottom-left
  - Some objects, like pickups, cast a 1px full black shadow along its bottom-right

### Colours

Try to use the limited palette that original C-Dogs uses. Not all current sprites are like this (https://github.com/cxong/cdogs-sdl/issues/388).

![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/palette.png)

If you use GIMP, you can also import this palette using
  - Windows > Palettes
  - Right click the list > Import Palette... > find palette.png
  - Open an image you want to palettise
  - Image > Mode > Indexed... > Use custom palette > select the imported C-Dogs palette

### Lighting

The primary light is from the top-left. This means that:

  - Top and left edges are brightest
  - The top surface is brighter than the front surface

Take these examples:

![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/box.png)
![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/wall/plasteel/o.png)

There are up to 7 shades used for the various surfaces and edges. Here they are in an ASCII diagram, from brightest (1) to darkest (7):

    +---+---------+---+
    | 1 |    2    | 3 |
    +---+---------+---+
    |   |         |   |
    | 2 |    3    | 4 |
    |   |         |   |
    +---+---------+---+
    | 3 |    4    | 5 |
    +---+---------+---+
    |   |         |   |
    | 4 |    5    | 6 |
    |   |         |   |
    +---+---------+---+
    | 5 |    6    | 7 |
    +---+---------+---+

For round objects in particular, there is a secondary light from the bottom-left. This is just to make the object look nice, and accentuate the roundness.

![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/barrel_blue.png)
![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/rocket.png)

### Shadows

For tall objects and pickups, there's a drop shadow to the bottom-right, 1px thick (unless the object is taller), pure black.

![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/keys/dungeon/blue.png)
![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/bottle.png)
![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/disk1.png)
