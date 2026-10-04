# Use this script to generate all the other versions of wall tiles, given a complete "o" tile
# Use "plasteel" as a template
param (
    [string]$name,
    [int]$m = 1
)
$w = 16 - $m
$h = 12 - $m
$h2 = 24 - $m
# NESW
Invoke-Expression ("magick $name/o.png -crop 16x{0}+0+0 -colorspace sRGB -gravity North -define distort:viewport=16x12-0-0 -filter point -distort SRT 0 +repage $name/n.png" -f $h)
Invoke-Expression ("magick $name/o.png -crop 16x{0}+0+{1} -colorspace sRGB -gravity South -define distort:viewport=16x24-0-{1} -filter point -distort SRT 0 +repage $name/s.png" -f $h2,$m)
Invoke-Expression ("magick $name/o.png -crop {0}x24+{1}+0 -colorspace sRGB -gravity East -define distort:viewport=16x24-{1}-0 -filter point -distort SRT 0 +repage $name/e.png" -f $w,$m)
Invoke-Expression ("magick $name/o.png -crop {0}x24+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x24-0-0 -filter point -distort SRT 0 +repage $name/w.png" -f $w)
# NW, NE, SW, SE
Invoke-Expression ("magick $name/n.png -crop {0}x12+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x12-0-0 -filter point -distort SRT 0 +repage $name/nw.png" -f $w)
Invoke-Expression ("magick $name/n.png -crop {0}x12+{1}+0 -colorspace sRGB -gravity East -define distort:viewport=16x12-{1}-0 -filter point -distort SRT 0 +repage $name/ne.png" -f $w,$m)
Invoke-Expression ("magick $name/s.png -crop {0}x24+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x24-0-0 -filter point -distort SRT 0 +repage $name/sw.png" -f $w)
Invoke-Expression ("magick $name/s.png -crop {0}x24+{1}+0 -colorspace sRGB -gravity East -define distort:viewport=16x24-{1}-0 -filter point -distort SRT 0 +repage $name/se.png" -f $w,$m)
# NT, ET, ST, WT
Invoke-Expression ("magick $name/nw.png -crop {0}x12+{1}+0 -colorspace sRGB -gravity East -define distort:viewport=16x12-{1}-0 -filter point -distort SRT 0 +repage $name/nt.png" -f $w,$m)
Invoke-Expression ("magick $name/ne.png -crop 16x{1}+0+{2} -colorspace sRGB -gravity South -define distort:viewport=16x12-0-{2} -filter point -distort SRT 0 +repage $name/et.png" -f $w,$h,$m)
Invoke-Expression ("magick $name/se.png -crop {0}x24+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x24-0-0 -filter point -distort SRT 0 +repage $name/st.png" -f $w)
Invoke-Expression ("magick $name/sw.png -crop 16x{1}+0+0 -colorspace sRGB -gravity North -define distort:viewport=16x12-0-0 -filter point -distort SRT 0 +repage $name/wt.png" -f $w,$h)
# VH
Invoke-Expression ("magick $name/n.png -crop 16x{1}+0+{2} -colorspace sRGB -gravity South -define distort:viewport=16x12-0-{2} -filter point -distort SRT 0 +repage $name/v.png" -f $w,$h,$m)
Invoke-Expression ("magick $name/e.png -crop {0}x24+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x24-0-0 -filter point -distort SRT 0 +repage $name/h.png" -f $w)
# X
Invoke-Expression ("magick $name/et.png -crop {0}x12+0+0 -colorspace sRGB -gravity West -define distort:viewport=16x12-0-0 -filter point -distort SRT 0 +repage $name/x.png" -f $w)
