#!/usr/bin/env bash
# Use this script to generate all the other versions of wall tiles, given a complete "o" tile
# Use "plasteel" as a template
name=$1
m=$2
((w=16-m))
((h=12-m))
((h2=24-m))
# NESW
magick $name/o.png -crop 16x$h+0+0 -colorspace sRGB -gravity North -define distort:viewport=16x12-0-0 -filter point -distort SRT 0 +repage $name/n.png
magick $name/o.png -crop 16x$h2+0+$m -colorspace sRGB -gravity South -define distort:viewport=16x24-0-$m -filter point -distort SRT 0 +repage $name/s.png
magick $name/o.png -crop ${w}x24+$m+0 -colorspace sRGB -gravity East -define distort:viewport=16x24-$m-0 -filter point -distort SRT 0 +repage $name/e.png
magick $name/o.png -crop ${w}x24+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x24-0-0 -filter point -distort SRT 0 +repage $name/w.png
# NW, NE, SW, SE
magick $name/n.png -crop ${w}x12+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x12-0-0 -filter point -distort SRT 0 +repage $name/nw.png
magick $name/n.png -crop ${w}x12+$m+0 -colorspace sRGB -gravity East -define distort:viewport=16x12-$m-0 -filter point -distort SRT 0 +repage $name/ne.png
magick $name/s.png -crop ${w}x24+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x24-0-0 -filter point -distort SRT 0 +repage $name/sw.png
magick $name/s.png -crop ${w}x24+$m+0 -colorspace sRGB -gravity East -define distort:viewport=16x24-$m-0 -filter point -distort SRT 0 +repage $name/se.png
# NT, ET, ST, WT
magick $name/nw.png -crop ${w}x12+$m+0 -colorspace sRGB -gravity East -define distort:viewport=16x12-$m-0 -filter point -distort SRT 0 +repage $name/nt.png
magick $name/ne.png -crop 16x$h+0+$m -colorspace sRGB -gravity South -define distort:viewport=16x12-0-$m -filter point -distort SRT 0 +repage $name/et.png
magick $name/se.png -crop ${w}x24+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x24-0-0 -filter point -distort SRT 0 +repage $name/st.png
magick $name/sw.png -crop 16x$h+0+0 -colorspace sRGB -gravity North -define distort:viewport=16x12-0-0 -filter point -distort SRT 0 +repage $name/wt.png
# VH
magick $name/n.png -crop 16x$h+0+$m -colorspace sRGB -gravity South -define distort:viewport=16x12-0-$m -filter point -distort SRT 0 +repage $name/v.png
magick $name/e.png -crop ${w}x24+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x24-0-0 -filter point -distort SRT 0 +repage $name/h.png
# X
magick $name/et.png -crop ${w}x12+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x12-0-0 -filter point -distort SRT 0 +repage $name/x.png
