#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/xpax.ico

convert ../../src/qt/res/icons/xpax-16.png ../../src/qt/res/icons/xpax-32.png ../../src/qt/res/icons/xpax-48.png ${ICON_DST}
