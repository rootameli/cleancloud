#!/bin/bash

cat $1 | grep -aoP 'AKIA[A-Z0-9]{16}' > testclefslol.txt
for i in $(cat testclefslol.txt); do akia=$(cat $1 | grep -a -A5 "$i" | grep -aoP '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40,}(?![A-Za-z0-9/+=])' | head -n1 | sed -e 's/^\(KEY\|SECRET\)=//g'); region=$(cat $1 | grep -a -A5 "$i" | grep -aoP '(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-[0-9]' | head -n1); echo "$i:$akia:$(if [[ -z $region ]]; then echo -n 'us-east-1'; else echo -n $region; fi)";done >> comboaws.txt
rm -f testclefslol.txt
sort -uR comboaws.txt -o comboaws.txt
