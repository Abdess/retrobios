#!/bin/bash
#
# Create head spritesheet and join all the rendered images
#
if [ "$#" -ne 1 ]; then
    echo "Usage: make_spritesheet.sh head"
    exit 1
fi

# TODO: linux path
BLENDER=/Applications/blender.app/Contents/MacOS/blender
INFILE=$1.blend
# TODO: layers
parts=(head)
# Render separate actions
actions=(idle firing)
idle_frames=1
firing_frames=1
len_i=${#parts[*]}
for (( i=0; i<len_i; i++ ))
do
    part=${parts[$i]}
    for action in ${actions[@]}
    do
      if [[ $action == *"firing"* ]]
      then
        frames=$firing_frames
      else
        frames=$idle_frames
      fi
      layers=$i
      "$BLENDER" -b "$INFILE" -P render.py -- "$layers" "$action" "$frames" "$part"
      for (( j=0; j<8; j++ ))
      do
        # Face not looking down needs to be shifted down a pixel
        if [ "$j" -ge 3 -a "$j" -le 5 ]
        then
          :
        else
          convert "out/${part}_${action}_${j}_00.png" -page +0+1 -background none -flatten tmpimage
          mv tmpimage "out/${part}_${action}_${j}_00.png"
        fi
      done

      DIMENSIONS=`identify -format "%wx%h" "out/${part}_${action}_0_00.png"`
    done
    OUTFILE=$1_${DIMENSIONS}.png
    rm "$OUTFILE"
    montage -geometry +0+0 -background none -tile 8x "out/${part}_idle_*.png" "out/${part}_firing_*.png" -channel A tmpimage
    convert tmpimage -dither None -colors 32 -level 25%,60% "$OUTFILE"
    rm tmpimage
    chmod 644 "$OUTFILE"
    echo "Created $OUTFILE"
done

rm -rf out/
