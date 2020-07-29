#!/bin/sh

SRC=/mnt/stripe/ExpressoGameBuild-4.25.1-src/
DST=/mnt/stripe/ExpressoGameBuild-4.25.1-dst/
OUT=/mnt/stripe/ExpressoGameBuild-4.25.1-out/
PCH=/mnt/stripe/ExpressoGameBuild-4.25.1-pch/

# normal test
python3 delta-patcher.py generate -s $SRC -d $DST -p $PCH
python3 delta-patcher.py apply -s $SRC -d $OUT -p $PCH
python3 delta-patcher.py validate -s $DST -d $OUT -p $PCH
diff -q -r $DST $OUT

# pre-existing data in output folder
cp -R $SRC $OUT
python3 delta-patcher.py generate -s $SRC -d $DST -p $PCH
python3 delta-patcher.py apply -s $SRC -d $OUT -p $PCH
python3 delta-patcher.py validate -s $DST -d $OUT -p $PCH
diff -q -r $DST $OUT
