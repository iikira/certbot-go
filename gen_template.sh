#!/bin/sh

if [ $1 = "" ]; then
    echo "no such input"
    exit
fi

php templates/$1.php >$1 2>&1
