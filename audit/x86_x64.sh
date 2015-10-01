#!/bin/bash

if [ "$1" == "x86" ]; then
    cp libcrypto/libcrypto_x86.a libcrypto/libcrypto.a

    cp libpcap/libpcap_x86.a libpcap/libpcap.a

    cp zlib/libz_x86.a zlib/libz.a
elif [ "$1" == "x64" ]; then
    cp libcrypto/libcrypto_x64.a libcrypto/libcrypto.a

    cp libpcap/libpcap_x64.a libpcap/libpcap.a

    cp zlib/libz_x64.a zlib/libz.a

elif [ "$1" == "mips32" ]; then
    cp zlib/libz_mips32.a zlib/libz.a
else
    echo "unknown target"
fi
