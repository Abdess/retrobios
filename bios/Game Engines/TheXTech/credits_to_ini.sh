#/bin/bash

DST=gameinfo.ini

mv $DST gameinfo.tmp

findEnd=false

while IFS= read -r srcLine; do
    if $findEnd; then
        if [[ "$srcLine" == "; credits.txt end" ]]; then
            echo $srcLine >> $DST
            findEnd=false
        fi
    else
        echo $srcLine >> $DST
        if [[ "$srcLine" == "; credits.txt begin" ]]; then
            i=1
            while IFS= read -r line; do
                echo "game-credit-$i=\"$line\"" >> $DST
                i=$(($i+1))
            done < credits.txt
            findEnd=true
        fi
    fi
done < gameinfo.tmp

rm gameinfo.tmp

echo "DONE!"
