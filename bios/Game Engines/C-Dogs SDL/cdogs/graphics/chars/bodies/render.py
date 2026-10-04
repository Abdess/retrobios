"""
Render animation in 8 rotations
adapted from http://clintbellanger.net/articles/isometric_tiles/

Args:
- layer
- action
- frames
- name
"""
import bpy
import sys
from math import radians

C = bpy.context
D = bpy.data

argv = sys.argv[sys.argv.index("--") + 1:]
collections = argv[0].split(',')
action = argv[1]
frames = int(argv[2])
name = '{}_{}'.format(argv[3], action)

RESOLUTION = 32
FRAME_SKIP = 10

angle = -45
axis = 2 # z-axis
platform = D.objects["armature"]
scene = D.scenes[0]
# Zoom out to show big characters - change RESOLUTION to account for this
scene.camera.data.ortho_scale = RESOLUTION
try:
    platform.animation_data.action = D.actions[action]
except KeyError:
    print(f"action {action} not found")
    sys.exit(1)

for collection in D.collections.keys():
    D.collections[collection].hide_render = collection not in collections

render = scene.render
render.image_settings.file_format = 'PNG'
render.image_settings.color_mode ='RGBA'
render.resolution_x = RESOLUTION
render.resolution_y = RESOLUTION
render.frame_map_new = 100 // FRAME_SKIP
render.engine = 'BLENDER_EEVEE_NEXT'
render.film_transparent = True
scene.frame_end = (frames - 1) // FRAME_SKIP
original_path = 'out/{}##'.format(name)
path = 'out/{}_{}_##'
platform.rotation_euler[axis] = 0
for i in range(0, 8):
    # rotate
    platform.rotation_euler[axis] = radians(angle) * (i + 1)
    # set filename so that up is first
    render.filepath = path.format(name, (i + 6) % 8)
    # render animation
    bpy.ops.render.render(animation=True)

platform.rotation_euler[axis] = 0