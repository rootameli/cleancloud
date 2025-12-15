#!/bin/bash

dos2unix $0 $1 > /dev/null 2>&1
curdir=$(pwd)
for url in $(cat $1 | cut -d'/' -f1,2,3); do
target=$(echo -n "$url/.git/")
output=$(echo -n "$target" | cut -d'/' -f3-)
./GoGitDumper/GoGitDumper -t 40 -u "$target" -o "src/$output"
cd src/$(echo -n "output" | cut -d'/' -f1,2)
git log -p > commit.dump
git checkout .
cd $curdir
done
