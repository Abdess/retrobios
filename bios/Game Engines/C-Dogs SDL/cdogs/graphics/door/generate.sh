#!/bin/bash
#
# Generate game-ready door sprites
# TODO: generate spritesheet?
#
if [ "$#" -ne 1 ]; then
    echo "Usage: generate.sh <doorname>"
    exit 1
fi

# Copy simple sprites
for s in open_h open_v wall; do
  cp $1/base/${s}.png $1/${s}.png
done

# Generate door bases
# normal_h = h + left + right
convert "$1/base/h.png" -background none -gravity South -extent 16x21 \
  "$1/base/left.png" -geometry +0+0 -composite \
  "$1/base/right.png" -geometry +0+0 -composite \
  "PNG24:$1/normal_h.png"
convert "$1/base/h.png" -background none -gravity South -extent 16x21 \
  "$1/base/left.png" -geometry +0+0 -composite \
  "PNG24:$1/normal_left.png"
convert "$1/base/h.png" -background none -gravity South -extent 16x21 \
  "PNG24:$1/normal_hmid.png"
convert "$1/base/h.png" -background none -gravity South -extent 16x21 \
  "$1/base/right.png" -geometry +0+0 -composite \
  "PNG24:$1/normal_right.png"
# normal_v = v + top + bottom
convert "$1/base/v.png" \
  "$1/base/top.png" -geometry +0+0 -composite \
  "$1/base/bottom.png" -geometry +0+0 -composite \
  "PNG24:$1/normal_v.png"
convert "$1/base/v.png" \
  "$1/base/top.png" -geometry +0+0 -composite \
  "PNG24:$1/normal_top.png"
cp "$1/base/v.png" "$1/normal_vmid.png"
convert "$1/base/v.png" \
  "$1/base/bottom.png" -geometry +0+0 -composite \
  "PNG24:$1/normal_bottom.png"

# Generate keys
for key in blue green red yellow; do
  # key_h = normal_h + key_h + key_left + key_right
  convert "$1/normal_h.png" \
    "$1/base/key/${key}_h.png" -geometry +0+0 -composite \
    "$1/base/key/${key}_left.png" -geometry +0+0 -composite \
    "$1/base/key/${key}_right.png" -geometry +0+0 -composite \
    "PNG24:$1/${key}_h.png"
  convert "$1/normal_left.png" \
    "$1/base/key/${key}_h.png" -geometry +0+0 -composite \
    "$1/base/key/${key}_left.png" -geometry +0+0 -composite \
    "PNG24:$1/${key}_left.png"
  convert "$1/normal_hmid.png" \
    "$1/base/key/${key}_h.png" -geometry +0+0 -composite \
    "PNG24:$1/${key}_hmid.png"
  convert "$1/normal_right.png" \
    "$1/base/key/${key}_h.png" -geometry +0+0 -composite \
    "$1/base/key/${key}_right.png" -geometry +0+0 -composite \
    "PNG24:$1/${key}_right.png"
  # key_v = normal_v + key_v + key_top + key_bottom
  convert "$1/normal_v.png" \
    "$1/base/key/${key}_v.png" -geometry +0+0 -composite \
    "$1/base/key/${key}_top.png" -geometry +0+0 -composite \
    "$1/base/key/${key}_bottom.png" -geometry +0+0 -composite \
    "PNG24:$1/${key}_v.png"
  convert "$1/normal_top.png" \
    "$1/base/key/${key}_v.png" -geometry +0+0 -composite \
    "$1/base/key/${key}_top.png" -geometry +0+0 -composite \
    "PNG24:$1/${key}_top.png"
  convert "$1/normal_vmid.png" \
    "$1/base/key/${key}_v.png" -geometry +0+0 -composite \
    "PNG24:$1/${key}_vmid.png"
  convert "$1/normal_bottom.png" \
    "$1/base/key/${key}_v.png" -geometry +0+0 -composite \
    "$1/base/key/${key}_bottom.png" -geometry +0+0 -composite \
    "PNG24:$1/${key}_bottom.png"
done
