#!/bin/bash

cat $1 | grep -aoP 'AKIA[A-Z0-9]{16}' | sort -u > tmp/testclefslol.txt
for i in $(cat tmp/testclefslol.txt); do akia=$(cat $1 | grep -a -C5 "$i" | grep -wiaoP '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40,}(?![A-Za-z0-9/+=])' | head -n1); region=$(cat $1 | grep -a -C5 "$i" | grep -aoP 'email-smtp\.(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-[0-9]\.amazonaws.com' | head -n1); echo "$region:587:$i:$akia:testmail@dkfjekz.com";done >> tmp/combo_ses.txt
rm -f tmp/testclefslol.txt
sort -uR tmp/combo_ses.txt -o tmp/combo_ses.txt
