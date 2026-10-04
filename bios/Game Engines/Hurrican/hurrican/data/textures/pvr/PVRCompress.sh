#!/bin/bash

# This script creates PVRTC textures from all of the PNG's.
# It will upscale to POT if needed and convert the image to 32 bit PNG.
# It also creates the list of filename's with scaling in scalefactors.txt
# The resulting TC2 or TC4 files should be copied to data/textures/pvr
# The scalefactors.txt should be copied to data/textures/pvr

powerof2 () {
# Get the original size of the image
  W=`identify ../$f | cut -f 3 -d " " | sed s/x.*//`
  H=`identify ../$f | cut -f 3 -d " " | sed s/.*x//`

  # Determine the next power of 2 greater the original image size
  P2W=`convert ../$f -format "%[fx:2^(ceil(log(w)/log(2)))]" info:`
  P2H=`convert ../$f -format "%[fx:2^(ceil(log(h)/log(2)))]" info:`
  if test $P2W -lt 32; then
    P2W=32
  fi
  if test $P2H -lt 32; then
    P2H=32
  fi

  # Calculate the ratio size increase
  FACTOR_W=$(echo "scale=3; $W/$P2W" | bc -l )
  FACTOR_H=$(echo "scale=3; $H/$P2H" | bc -l )

  # Remove the file extentsion
  FILENAME=${f%.*}

  # Display and write the results to file
  echo Width  ${FILENAME} ${FACTOR_W} ${W} ${P2W}
  echo Height ${FILENAME} ${FACTOR_H} ${H} ${P2W}
  echo ${FILENAME} ${FACTOR_W} ${FACTOR_H} >> scalefactors.txt
} 

rm scalefactors.txt
rm -rf tc2
rm -rf tc4
#rm -rf XRGB1555
rm -rf ../png32

mkdir tc2
mkdir tc4
#mkdir XRGB1555
mkdir ../png32

cd ..

for f in *.png
do
  cd pvr
  echo "Processing $f file..."
 
  powerof2

  convert ../$f -background transparent -extent ${P2W}x${P2H} PNG32:../png32/$f.png

  ./PVRTexTool -fPVRTC2 -i../png32/$f.png -o tc2/$f.pvr
  ./PVRTexTool -fPVRTC4 -i../png32/$f.png -o tc4/$f.pvr
#  ./PVRTexTool -f1555 -i../png32/$f.png -o XRGB1555/$f.pvr
#  mv XRGB1555/$f.pvr XRGB1555/$f.XRGB1555

  cd ..
done
