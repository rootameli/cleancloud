#!/bin/bash

THRDS=$2
if [[ -z $THRDS ]]; then THRDS=50; fi
cat $1 | httpx -silent -threads $THRDS -path '/.git/config' -match-string '[core]' -o vulns.txt
sed -i 's/\/config$//g' vulns.txt
