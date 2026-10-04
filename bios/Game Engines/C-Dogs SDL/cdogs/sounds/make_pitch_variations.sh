#!/bin/bash
# Create a bunch of pitch-shifted variations of a sound file
# Requires SoX (http://sox.sourceforge.net/)
# Sounds vary between +/- 2 tones
# Usage: ./make_pitch_variations.sh <sound_file> <num_variations/2>
# Sound file should be named with a zero, e.g. foo0.ogg, so that the variations
# can be called foo1.ogg, foo2.ogg and so on (foo/0.ogg becomes foo/1.ogg etc.)
if [ "$#" -lt 2 ]; then
  echo "Usage: ./make_pitch_variations.sh <sound_file> <num_variations/2>"
  exit 1
fi
SHIFT_RANGE=200
if [ "$#" -eq 3 ]; then
  SHIFT_RANGE=$3
fi
FILENAME_PREFIX=${1%%0.*}
EXTENSION=${1##*.}
for i in $(seq 1 "$2")
do
  FILENAME="${FILENAME_PREFIX}$(((i - 1) * 2 + 1)).${EXTENSION}"
  SHIFT=$((SHIFT_RANGE * i / $2))
  sox -G "$1" "$FILENAME" pitch "$SHIFT"
  FILENAME="${FILENAME_PREFIX}$((i * 2)).${EXTENSION}"
  sox -G "$1" "$FILENAME" pitch "-$SHIFT"
done
