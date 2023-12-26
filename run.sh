#!/bin/sh

set -xe

clang -g -O0 -o out ./main.c
if [ $? -eq 0 ]; then
    ./out
fi
