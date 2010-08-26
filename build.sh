#!/bin/bash

autoconf && ./configure && make

if [ "$?" == "0" ]; then
    echo -e '\n\nBuild successful. To install:\n\n$ sudo make install\n'
fi
