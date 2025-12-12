#!/bin/bash

for dir in $(ls -d */); do
cd $dir; git checkout . && git log -p > commits.dump; cd ..
grep -rnP -C25 "AKIA[A-Z0-9]{16}" --binary-files=text $dir | cut -c -500 >> akia.txt
grep -rniP -C25 "smtp\.sendgrid\.net|smtp\.mailgun\.org|email-smtp\.(us|eu|ap|ca|cn|sa)-(central|(north|south)?(west|east)?)-[0-9]{1}\.amazonaws.com|smtp.sparkpostmail.com|VONAGE_API_KEY|NEXMO_API_KEY|ONESIGNAL_APP_ID|NEXMO_KEY|VONAGE_KEY|nexmo_api_id|vonage_api_id|smtp.socketlabs.com|mail.infomaniak.com|pro.turbo-smtp.com|smtp-pulse.com|in-v3.mailjet.com" --binary-files=text $dir | cut -c -500 >> smtp.txt
for i in $(find $dir -name '*.env*' -type f); do
cat $i >> gigaenv.txt
done
done