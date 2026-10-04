Door sprites are generated via imagemagick by compositing several base sprites. See `generate.sh` for details.

## Example (blast)

### Copied as-is

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/open_h.png) open_h
- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/open_v.png) open_v
- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/wall.png) wall

### Door sprites

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_h.png) normal_h = ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/open_h.png) open_h + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/h.png) h + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/left.png) left + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/right.png) right

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_left.png)![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_hmid.png)![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_right.png) normal_left + normal_hmid normal_right

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_v.png) normal_v = ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/v.png) v + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/top.png) top + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/bottom.png) bottom

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_top.png) normal_top  
  ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_vmid.png) normal_vmid  
  ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_bottom.png) normal_bottom

### Keyed doors

Colors: ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_h.png) yellow ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/green_h.png) green ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/blue_h.png) blue ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/red_h.png) red

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_h.png) key_h = ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_h.png) normal_h + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/key/yellow_h.png) key_h + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/key/yellow_left.png) key_left + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/key/yellow_right.png) key_right

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_left.png) ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_hmid.png) ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_right.png) key_left + key_hmid + key_right

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_v.png) key_v = ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/normal_v.png) normal_v + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/key/yellow_v.png) key_v + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/key/yellow_top.png) key_top + ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/base/key/yellow_bottom.png) key_bottom

- ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_top.png) key_top  
  ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_vmid.png) key_vmid  
  ![](https://github.com/cxong/cdogs-sdl/blob/master/graphics/door/blast/yellow_bottom.png) key_bottom
