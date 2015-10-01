#!/bin/bash
BUILD_VERSION=4.1.8

BUILD_DATE=`date "+%Y%m%d"`

echo "version: DPI-$BUILD_DATE-$BUILD_VERSION"  > dpi.ver

echo "date:`date "+%Y-%m-%d"`"      >> dpi.ver
#date "+%Y-%m-%d"    >> dpi.ver

./appbuild
if [ $? != 0 ]; then
    exit -1
fi

tar zcvf DPI-${BUILD_DATE}-${BUILD_VERSION}.tmp dpi.dfa dpi.info dpi.ver dpi.pbdl

./a.out DPI-${BUILD_DATE}-${BUILD_VERSION}.tmp DPI-${BUILD_DATE}-${BUILD_VERSION}

rm DPI-${BUILD_DATE}-${BUILD_VERSION}.tmp
rm dpi.xml
rm dpi.info
rm dpi.dfa
