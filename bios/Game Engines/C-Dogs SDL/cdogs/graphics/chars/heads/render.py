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

argv = sys.argv[sys.argv.index("--") + 1:]
layers = [int(layer) + 3 for layer in argv[0].split(',')]
action = argv[1]
frames = int(argv[2])
name = '{}_{}'.format(argv[3], action)

RESOLUTION = 12
FRAME_SKIP = 10

angle = -45
axis = 2 # z-axis
platform = bpy.data.objects["armature"]
scene = bpy.data.scenes[0]
scene.objects.active = platform
platform.animation_data.action = bpy.data.actions[action]
for i in range(len(scene.layers)):
    if i < 3:
        scene.layers[i] = True
        continue
    scene.layers[i] = i in layers
render = scene.render
render.image_settings.file_format = 'PNG'
render.image_settings.color_mode ='RGBA'
render.alpha_mode = 'TRANSPARENT'
render.resolution_x = RESOLUTION
render.resolution_y = RESOLUTION
render.frame_map_new = 100 / FRAME_SKIP
scene.frame_end = (frames - 1) / FRAME_SKIP
original_path = 'out/{}##'.format(name)
path = 'out/{}_{}_##'
# C-Dogs heads aren't perfectly diagonal, just slightly
diag_angle = 15
angles = [
    -90, -180+diag_angle, -180, -180-diag_angle,
    -270, -360+diag_angle, 0, -diag_angle
]
for i, angle in zip(range(0, 8), angles):
    # rotate
    temp_rot = platform.rotation_euler
    temp_rot[axis] = radians(angle)
    platform.rotation_euler = temp_rot

    # set filename so that up is first
    render.filepath = path.format(name, (i + 6) % 8)

    # render animation
    bpy.ops.render.render(animation=True)
