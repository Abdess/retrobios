#!/bin/bash
#
# Create character spritesheet and join all the rendered images
# Requires blender and imagemagick
#
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
if [ "$#" -ne 1 ]; then
    echo "Usage: make_spritesheet.sh body"
    exit 1
fi

if [[ "$OSTYPE" == "linux-gnu" ]]; then
  BLENDER=blender
elif [[ "$OSTYPE" == "msys" ]]; then
  BLENDER="/c/Program Files/Blender Foundation/Blender 4.4/blender.exe"
else
  # macOS
  BLENDER=/Applications/blender.app/Contents/MacOS/blender
fi
if [[ "$OSTYPE" == "msys" ]]; then
  BLENDER_OUT="C:/out"
else
  BLENDER_OUT="out"
fi

INFILE=$1/src.blend
# Render separate body parts (in collections)
parts=(legs upper)
# Render separate actions
actions_legs=(idle run)
actions_upper=(idle run idle_handgun run_handgun idle_dualgun run_dualgun idle_rifle run_rifle idle_riflefire run_riflefire)
idle_frames=1
run_frames=80
len_i=${#parts[*]}
for (( i=0; i<len_i; i++ ))
do
    part=${parts[$i]}
    collections=base
    if [[ $part == *"legs"* ]]
    then
      actions=${actions_legs[@]}
      collections=$collections,legs
    else
      actions=${actions_upper[@]}
      collections=$collections,upper
    fi
    for action in $actions
    do
      rm -rf out
      if [[ $action == *"run"* ]]
      then
        frames=$run_frames
      else
        frames=$idle_frames
      fi
      # Include right hand collection if the part is "upper" and action doesn't have guns
      if [[ $part == *"upper"* ]] && [[ $action != *"handgun"* ]] && [[ $action != *"dualgun"* ]] && [[ $action != *"rifle"* ]]
      then
        collections=$collections,hand_right
      fi
      "$BLENDER" -noaudio -b "$INFILE" -P ${SCRIPT_DIR}/render.py -- "$collections" "$action" "$frames" "$part"

      DIMENSIONS=`identify -format "%wx%h" "${BLENDER_OUT}/${part}_${action}_0_00.png"`
      OUTFILE=$1/${part}_${action}_${DIMENSIONS}.png
      rm -f "$OUTFILE"
      montage -geometry +0+0 -background none -tile x8 "${BLENDER_OUT}/${part}_${action}_*.png" -channel A tmpimage
      magick convert tmpimage -dither None -colors 32 -level 25%,60% "$OUTFILE"
      rm tmpimage
      chmod 644 "$OUTFILE"
      echo "Created $OUTFILE"
    done
done

rm -rf out/
