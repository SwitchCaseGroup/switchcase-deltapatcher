#!/bin/sh
python3 delta-patcher.py generate -s /mnt/stripe/ExpressoGameBuild-4.25.1-src/ -d /mnt/stripe/ExpressoGameBuild-4.25.1-dst/ -p /mnt/stripe/ExpressoGameBuild-4.25.1-pch/
rm -rf /mnt/stripe/ExpressoGameBuild-4.25.1-out/
cp -R /mnt/stripe/ExpressoGameBuild-4.25.1-src /mnt/stripe/ExpressoGameBuild-4.25.1-out
python3 delta-patcher.py apply -s /mnt/stripe/ExpressoGameBuild-4.25.1-src/ -d /mnt/stripe/ExpressoGameBuild-4.25.1-out/ -p /mnt/stripe/ExpressoGameBuild-4.25.1-pch/
python3 delta-patcher.py validate -s /mnt/stripe/ExpressoGameBuild-4.25.1-dst/ -d /mnt/stripe/ExpressoGameBuild-4.25.1-out/ -p /mnt/stripe/ExpressoGameBuild-4.25.1-pch/
diff /mnt/stripe/ExpressoGameBuild-4.25.1-dst/ /mnt/stripe/ExpressoGameBuild-4.25.1-out
