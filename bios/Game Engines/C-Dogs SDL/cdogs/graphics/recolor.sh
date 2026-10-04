#!/bin/sh
#
# Recolor sprites based on C-Dogs palette
# TODO: force RGB, don't use grayscale
#
for image in *.png; do
  convert "$image" +depth +dither -remap palette.png "$image"
done
